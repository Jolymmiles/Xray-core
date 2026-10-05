package hysteria

import (
	"context"
	go_errors "errors"
	"io"
	"math/rand"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/proxy/hysteria/account"
	"github.com/xtls/xray-core/transport/internet"
	hysteriatransport "github.com/xtls/xray-core/transport/internet/hysteria"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// upstreamUDPWriter and upstreamUDPReader are the XTLS/Xray-core v26.9.30
// implementations, kept here as the reference for per-packet comparisons.
type upstreamUDPWriter struct {
	writer io.Writer
	addr   string
	buf    [buf.Size]byte
}

func (w *upstreamUDPWriter) sendMessage(msg *UDPMessage) error {
	msgN := msg.Serialize(w.buf[:])
	if msgN < 0 {
		return nil
	}
	_, err := w.writer.Write(w.buf[:msgN])
	return err
}

func (w *upstreamUDPWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	for i, b := range mb {
		addr := w.addr
		if b.UDP != nil {
			addr = b.UDP.NetAddr()
		}
		msg := &UDPMessage{FragCount: 1, Addr: addr, Data: b.Bytes()}
		err := w.sendMessage(msg)
		var errTooLarge *quic.DatagramTooLargeError
		if go_errors.As(err, &errTooLarge) {
			msg.PacketID = uint16(rand.Intn(0xFFFF)) + 1
			for _, fragment := range FragUDPMessage(msg, int(errTooLarge.MaxDatagramPayloadSize)) {
				if err := w.sendMessage(&fragment); err != nil {
					buf.ReleaseMulti(mb[i:])
					return err
				}
			}
		} else if err != nil {
			buf.ReleaseMulti(mb[i:])
			return err
		}
		b.Release()
	}
	return nil
}

type upstreamUDPReader struct {
	reader io.Reader
	df     *Defragger
}

func (r *upstreamUDPReader) ReadFrom(p []byte) (int, *net.Destination, error) {
	for {
		var packet [1500]byte
		n, err := r.reader.Read(packet[:])
		if err != nil {
			return 0, nil, err
		}
		msg, err := ParseUDPMessage(packet[:n])
		if err != nil {
			continue
		}
		dfMsg := r.df.Feed(msg)
		if dfMsg == nil {
			continue
		}
		dest, err := net.ParseDestination("udp:" + dfMsg.Addr)
		if err != nil {
			continue
		}
		if len(p) < len(dfMsg.Data) {
			continue
		}
		return copy(p, dfMsg.Data), &dest, nil
	}
}

func (r *upstreamUDPReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	b := buf.New()
	b.Resize(0, buf.Size)
	n, addr, err := r.ReadFrom(b.Bytes())
	if err != nil {
		b.Release()
		return nil, err
	}
	b.Resize(0, int32(n))
	b.UDP = addr
	return buf.MultiBuffer{b}, nil
}

// repeatingDatagram returns the same Hysteria UDP frame on every Read.
type repeatingDatagram struct{ frame []byte }

func (r *repeatingDatagram) Read(p []byte) (int, error) { return copy(p, r.frame), nil }

func udpFrame(b testing.TB, address string, payloadSize int) []byte {
	b.Helper()
	message := &UDPMessage{FragCount: 1, Addr: address, Data: make([]byte, payloadSize)}
	frame := make([]byte, message.Size())
	if message.Serialize(frame) < 0 {
		b.Fatal("frame does not fit")
	}
	return frame
}

func BenchmarkCompareServerUDPRead(b *testing.B) {
	for _, address := range []string{"1.1.1.1:53", "example.com:443"} {
		frame := udpFrame(b, address, 1100)
		b.Run(address+"/fork", func(b *testing.B) {
			reader := &UDPReader{reader: &repeatingDatagram{frame: frame}}
			b.ReportAllocs()
			for b.Loop() {
				mb, err := reader.ReadMultiBuffer()
				if err != nil {
					b.Fatal(err)
				}
				buf.ReleaseMulti(mb)
			}
		})
		b.Run(address+"/upstream", func(b *testing.B) {
			reader := &upstreamUDPReader{reader: &repeatingDatagram{frame: frame}, df: &Defragger{}}
			b.ReportAllocs()
			for b.Loop() {
				mb, err := reader.ReadMultiBuffer()
				if err != nil {
					b.Fatal(err)
				}
				buf.ReleaseMulti(mb)
			}
		})
	}
}

// BenchmarkCompareServerUDPWrite writes responses as Freedom produces them:
// a pooled buffer whose UDP destination is a heap-allocated value.
func BenchmarkCompareServerUDPWrite(b *testing.B) {
	payload := make([]byte, 1100)
	source := net.UDPDestination(net.IPAddress([]byte{1, 1, 1, 1}), 53)
	newResponse := func() buf.MultiBuffer {
		response := buf.New()
		response.Write(payload)
		response.UDP = &net.Destination{Address: source.Address, Port: source.Port, Network: net.Network_UDP}
		return buf.MultiBuffer{response}
	}
	b.Run("fork", func(b *testing.B) {
		writer := &UDPWriter{writer: io.Discard, addr: "1.1.1.1:53"}
		b.ReportAllocs()
		for b.Loop() {
			if err := writer.WriteMultiBuffer(newResponse()); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("upstream", func(b *testing.B) {
		writer := &upstreamUDPWriter{writer: io.Discard, addr: "1.1.1.1:53"}
		b.ReportAllocs()
		for b.Loop() {
			if err := writer.WriteMultiBuffer(newResponse()); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkCompareServerUDPQUIC sends client datagrams through a real
// Hysteria QUIC connection on loopback and reads them with each server
// reader, so the reader's share of the per-packet cost is visible.
func BenchmarkCompareServerUDPQUIC(b *testing.B) {
	for _, variant := range []string{"fork", "upstream"} {
		b.Run(variant, func(b *testing.B) {
			serverConns := make(chan stat.Connection, 1)
			release := make(chan struct{})
			settings, server := startBenchmarkListener(b, func(conn stat.Connection) {
				serverConns <- conn
				<-release
			})
			b.Cleanup(func() { close(release) })
			client, err := hysteriatransport.Dial(hysteriatransport.ContextWithDatagram(context.Background(), true), server, settings)
			if err != nil {
				b.Fatal(err)
			}
			defer client.Close()
			writer := &UDPWriter{writer: client, addr: "1.1.1.1:53"}
			send := func() {
				packet := buf.New()
				packet.Extend(1100)
				if err := writer.WriteMultiBuffer(buf.MultiBuffer{packet}); err != nil {
					b.Fatal(err)
				}
			}
			send()
			var serverConn stat.Connection
			select {
			case serverConn = <-serverConns:
			case <-time.After(10 * time.Second):
				b.Fatal("server never accepted the UDP session")
			}
			var reader buf.Reader = &UDPReader{reader: serverConn}
			if variant == "upstream" {
				reader = &upstreamUDPReader{reader: serverConn, df: &Defragger{}}
			}
			mb, err := reader.ReadMultiBuffer()
			if err != nil {
				b.Fatal(err)
			}
			buf.ReleaseMulti(mb)

			// The server queue holds 1024 datagrams; send in bounded windows so
			// none are dropped and every send is matched by one read.
			const window = 256
			b.SetBytes(1100)
			b.ReportAllocs()
			b.ResetTimer()
			for sent := 0; sent < b.N; {
				batch := min(window, b.N-sent)
				for range batch {
					send()
				}
				for range batch {
					mb, err := reader.ReadMultiBuffer()
					if err != nil {
						b.Fatal(err)
					}
					buf.ReleaseMulti(mb)
				}
				sent += batch
			}
		})
	}
}

func startBenchmarkListener(b *testing.B, handler func(stat.Connection)) (*internet.MemoryStreamConfig, net.Destination) {
	b.Helper()
	settings := newHysteriaTestSettings()
	port := reserveUDPPort(b)
	listenCtx := hysteriatransport.ContextWithValidator(context.Background(), account.NewValidator())
	listener, err := hysteriatransport.Listen(listenCtx, net.LocalHostIP, port, settings, handler)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = listener.Close() })
	return settings, net.TCPDestination(net.DomainAddress("localhost"), port)
}
