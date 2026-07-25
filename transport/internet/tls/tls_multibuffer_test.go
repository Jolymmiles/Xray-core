package tls_test

import (
	"bytes"
	"context"
	gotls "crypto/tls"
	"io"
	stdnet "net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	xraytls "github.com/xtls/xray-core/transport/internet/tls"
)

type writeCountingConn struct {
	stdnet.Conn
	writes atomic.Int64
}

func (c *writeCountingConn) Write(payload []byte) (int, error) {
	c.writes.Add(1)
	return c.Conn.Write(payload)
}

func (c *writeCountingConn) resetWrites() {
	c.writes.Store(0)
}

func TestConnWriteMultiBufferCoalescesTLSRecords(t *testing.T) {
	client, server := newTLSPipe(t)

	const payloadSize = 64 * 1024
	payload := bytes.Repeat([]byte{'x'}, payloadSize)
	multiBuffer := make(buf.MultiBuffer, 0, payloadSize/buf.Size)
	for offset := 0; offset < len(payload); offset += buf.Size {
		buffer := buf.New()
		if _, err := buffer.Write(payload[offset : offset+buf.Size]); err != nil {
			t.Fatal(err)
		}
		multiBuffer = append(multiBuffer, buffer)
	}

	received := make([]byte, len(payload))
	readError := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(server, received)
		readError <- err
	}()

	client.raw.resetWrites()
	if err := client.conn.WriteMultiBuffer(multiBuffer); err != nil {
		t.Fatalf("write TLS multi-buffer: %v", err)
	}
	if err := <-readError; err != nil {
		t.Fatalf("read TLS payload: %v", err)
	}
	if !bytes.Equal(received, payload) {
		t.Fatal("TLS payload changed while coalescing records")
	}
	if writes := client.raw.writes.Load(); writes > payloadSize/(16*1024) {
		t.Fatalf("TLS transport used %d writes for %d bytes, want at most %d", writes, payloadSize, payloadSize/(16*1024))
	}
}

func BenchmarkConnWriteMultiBuffer64K(b *testing.B) {
	for _, benchmark := range []struct {
		name  string
		write func(*xraytls.Conn, buf.MultiBuffer) error
	}{
		{
			name: "legacy-8KiB-records",
			write: func(connection *xraytls.Conn, multiBuffer buf.MultiBuffer) error {
				multiBuffer = buf.Compact(multiBuffer)
				left, err := buf.WriteMultiBuffer(connection, multiBuffer)
				buf.ReleaseMulti(left)
				return err
			},
		},
		{name: "coalesced-16KiB-records", write: (*xraytls.Conn).WriteMultiBuffer},
	} {
		b.Run(benchmark.name, func(b *testing.B) {
			client, server := newTLSPipe(b)
			payload := bytes.Repeat([]byte{'b'}, 64*1024)
			readError := make(chan error, 1)
			go func() {
				_, err := io.CopyN(io.Discard, server, int64(b.N*len(payload)))
				readError <- err
			}()

			b.SetBytes(int64(len(payload)))
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				multiBuffer := make(buf.MultiBuffer, 0, len(payload)/buf.Size)
				for offset := 0; offset < len(payload); offset += buf.Size {
					buffer := buf.New()
					_, _ = buffer.Write(payload[offset : offset+buf.Size])
					multiBuffer = append(multiBuffer, buffer)
				}
				if err := benchmark.write(client.conn, multiBuffer); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			if err := <-readError; err != nil {
				b.Fatal(err)
			}
		})
	}
}

type tlsPipeClient struct {
	conn *xraytls.Conn
	raw  *writeCountingConn
}

func newTLSPipe(t testing.TB) (*tlsPipeClient, *xraytls.Conn) {
	t.Helper()

	generatedCertificate, _ := cert.MustGenerate(
		nil,
		cert.CommonName("localhost"),
		cert.DNSNames("localhost"),
	)
	certificatePEM, privateKeyPEM := generatedCertificate.ToPEM()
	certificate, err := gotls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil {
		t.Fatalf("parse generated TLS certificate: %v", err)
	}

	clientRaw, serverRaw := stdnet.Pipe()
	t.Cleanup(func() {
		clientRaw.Close()
		serverRaw.Close()
	})
	countingClient := &writeCountingConn{Conn: clientRaw}
	client := xraytls.Client(countingClient, &gotls.Config{
		InsecureSkipVerify:          true,
		ServerName:                  "localhost",
		DynamicRecordSizingDisabled: true,
	}).(*xraytls.Conn)
	server := xraytls.Server(serverRaw, &gotls.Config{
		Certificates: []gotls.Certificate{certificate},
	}).(*xraytls.Conn)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	serverHandshake := make(chan error, 1)
	go func() {
		serverHandshake <- server.HandshakeContext(ctx)
	}()
	if err := client.HandshakeContext(ctx); err != nil {
		t.Fatalf("client TLS handshake: %v", err)
	}
	if err := <-serverHandshake; err != nil {
		t.Fatalf("server TLS handshake: %v", err)
	}

	return &tlsPipeClient{conn: client, raw: countingClient}, server
}
