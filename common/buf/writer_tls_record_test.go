package buf_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	. "github.com/xtls/xray-core/common/buf"
)

// recordCountingConn counts the raw writes a tls.Conn makes once the
// handshake is done: each one carries exactly one TLS record.
type recordCountingConn struct {
	net.Conn
	counting atomic.Bool
	mu       sync.Mutex
	records  []int
}

func (c *recordCountingConn) Write(payload []byte) (int, error) {
	if c.counting.Load() {
		c.mu.Lock()
		c.records = append(c.records, len(payload))
		c.mu.Unlock()
	}
	return c.Conn.Write(payload)
}

func (c *recordCountingConn) recordSizes() []int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]int(nil), c.records...)
}

func newTLSRecordTestCertificate(t testing.TB) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		DNSNames:     []string{"example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// newTLSRecordPair returns a handshaken client over loopback TCP whose
// records are counted, and a channel delivering every byte the server
// decrypted once the client closes. Without keep the server discards them.
func newTLSRecordPair(t testing.TB, keep bool) (*tls.Conn, *recordCountingConn, <-chan []byte) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	certificate := newTLSRecordTestCertificate(t)
	received := make(chan []byte, 1)
	go func() {
		raw, err := listener.Accept()
		if err != nil {
			received <- nil
			return
		}
		server := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13})
		defer server.Close()
		if !keep {
			_, _ = io.Copy(io.Discard, server)
			received <- nil
			return
		}
		data, _ := io.ReadAll(server)
		received <- data
	}()

	raw, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	counting := &recordCountingConn{Conn: raw}
	client := tls.Client(counting, &tls.Config{ServerName: "example.com", InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
	t.Cleanup(func() { _ = client.Close() })
	if err := client.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	counting.counting.Store(true)
	return client, counting, received
}

// A VLESS header written as its own TLS record is a fixed-size record right
// after the handshake (61 bytes for a Vision request, 19 for a response)
// that a stock Xray never sends: upstream copies the first payload into the
// header buffer and writes both at once.
func TestHeaderAndFirstPayloadShareOneTLSRecord(t *testing.T) {
	header := bytes.Repeat([]byte{'h'}, 44)
	tests := []struct {
		name   string
		header []byte
		writer func(t *testing.T, underlying Writer, header []byte) Writer
	}{
		{
			name:   "buffered writer flush next",
			header: header,
			writer: func(t *testing.T, underlying Writer, header []byte) Writer {
				writer := NewBufferedWriter(underlying)
				if _, err := writer.Write(header); err != nil {
					t.Fatal(err)
				}
				writer.SetFlushNext()
				return writer
			},
		},
		{
			name:   "buffered writer with prefix",
			header: header,
			writer: func(t *testing.T, underlying Writer, header []byte) Writer {
				writer, err := NewBufferedWriterWithPrefix(underlying, header)
				if err != nil {
					t.Fatal(err)
				}
				return writer
			},
		},
		{
			name:   "prefix writer",
			header: []byte{0, 0},
			writer: func(t *testing.T, underlying Writer, header []byte) Writer {
				writer, err := NewPrefixWriter(underlying, header)
				if err != nil {
					t.Fatal(err)
				}
				return writer
			},
		},
	}
	payloads := map[string][][]byte{
		"one buffer":  {bytes.Repeat([]byte{'a'}, 517)},
		"two buffers": {bytes.Repeat([]byte{'a'}, 300), bytes.Repeat([]byte{'b'}, 217)},
	}
	for _, test := range tests {
		for payloadName, parts := range payloads {
			t.Run(test.name+"/"+payloadName, func(t *testing.T) {
				client, counting, received := newTLSRecordPair(t, true)
				writer := test.writer(t, NewWriter(client), test.header)

				var first MultiBuffer
				want := append([]byte(nil), test.header...)
				for _, part := range parts {
					first = append(first, FromBytes(part))
					want = append(want, part...)
				}
				if err := writer.WriteMultiBuffer(first); err != nil {
					t.Fatal(err)
				}
				if records := counting.recordSizes(); len(records) != 1 {
					t.Fatalf("header and first payload took %d TLS records %v, want 1", len(records), records)
				}

				next := []byte("next")
				if err := writer.WriteMultiBuffer(MultiBuffer{FromBytes(next)}); err != nil {
					t.Fatal(err)
				}
				want = append(want, next...)
				if err := client.Close(); err != nil {
					t.Fatal(err)
				}
				if got := <-received; !bytes.Equal(got, want) {
					t.Fatalf("server received %d bytes %q, want %d bytes", len(got), got, len(want))
				}
			})
		}
	}
}

func TestHeaderWithLargeFirstPayloadKeepsBytesAndLeadsWithPayload(t *testing.T) {
	const tlsRecordOverhead = 5 + 1 + 16 // record header, inner content type, AEAD tag
	header := bytes.Repeat([]byte{'h'}, 44)
	client, counting, received := newTLSRecordPair(t, true)
	writer := NewBufferedWriter(NewWriter(client))
	if _, err := writer.Write(header); err != nil {
		t.Fatal(err)
	}
	writer.SetFlushNext()

	want := append([]byte(nil), header...)
	var first MultiBuffer
	for index, size := range []int{Size, Size, 100} {
		part := bytes.Repeat([]byte{byte('a' + index)}, size)
		first = append(first, FromBytes(part))
		want = append(want, part...)
	}
	if err := writer.WriteMultiBuffer(first); err != nil {
		t.Fatal(err)
	}
	records := counting.recordSizes()
	if len(records) == 0 || records[0] <= len(header)+tlsRecordOverhead {
		t.Fatalf("first TLS record sizes %v: the header went out without payload", records)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if got := <-received; !bytes.Equal(got, want) {
		t.Fatalf("server received %d bytes, want %d", len(got), len(want))
	}
}

// BenchmarkHeaderAndFirstPayloadOverTLS measures what a VLESS connection pays
// to send its header and first payload on an established TLS connection.
func BenchmarkHeaderAndFirstPayloadOverTLS(b *testing.B) {
	for _, test := range []struct {
		name   string
		header []byte
		prefix bool
	}{
		{name: "request", header: bytes.Repeat([]byte{'h'}, 44)},
		{name: "response", header: []byte{0, 0}, prefix: true},
	} {
		b.Run(test.name, func(b *testing.B) {
			client, counting, _ := newTLSRecordPair(b, false)
			counting.counting.Store(false)
			if err := client.SetDeadline(time.Time{}); err != nil {
				b.Fatal(err)
			}
			underlying := NewWriter(client)
			payload := make([]byte, 1400)
			b.SetBytes(int64(len(test.header) + len(payload)))
			b.ReportAllocs()
			for b.Loop() {
				var writer Writer
				if test.prefix {
					prefixWriter, err := NewPrefixWriter(underlying, test.header)
					if err != nil {
						b.Fatal(err)
					}
					writer = prefixWriter
				} else {
					bufferedWriter := NewBufferedWriter(underlying)
					if _, err := bufferedWriter.Write(test.header); err != nil {
						b.Fatal(err)
					}
					bufferedWriter.SetFlushNext()
					writer = bufferedWriter
				}
				if err := writer.WriteMultiBuffer(MultiBuffer{FromBytes(payload)}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
