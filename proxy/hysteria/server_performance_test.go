package hysteria

import (
	"bytes"
	"context"
	"io"
	"testing"

	policyapp "github.com/xtls/xray-core/app/policy"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/protocol"
	featurepolicy "github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport"
)

var (
	hysteriaServerLinkSink *transport.Link
	hysteriaPolicySink     featurepolicy.Session
	hysteriaUserSink       *protocol.MemoryUser
)

func TestPooledServerUDPStateCleared(t *testing.T) {
	reader := newPooledUDPReader(bytes.NewReader(nil))
	reader.message = UDPMessage{Addr: "example.com:443", Data: []byte("payload")}
	fragment := UDPMessage{PacketID: 1, FragID: 0, FragCount: 2, Data: []byte("retained")}
	if reader.df.storeClonedFragment(&fragment) {
		t.Fatal("incomplete fragment unexpectedly completed")
	}
	reader.firstBuf = buf.FromBytes([]byte("first"))
	reader.link = transport.Link{Reader: reader, Writer: buf.NewWriter(io.Discard)}
	reader.serverWriter.writer = io.Discard
	reader.serverWriter.addr = "retained.example:443"
	reader.serverWriter.defaultHeaderLength = 17
	reader.serverWriter.managedDomain = "retained.example"
	reader.serverWriter.managedDomainPort = 443
	reader.serverWriter.managedHeaderLength = 18
	reader.serverWriter.managedIPv4 = [4]byte{192, 0, 2, 1}
	reader.serverWriter.managedIPv4Port = 53
	reader.serverWriter.managedIPv4Header = 19
	releasePooledUDPReader(reader)

	reused := newPooledUDPReader(bytes.NewReader(nil))
	defer releasePooledUDPReader(reused)
	if reused.firstBuf != nil || reused.message.Addr != "" || len(reused.message.Data) != 0 || len(reused.df.frags) != 0 || reused.df.storage != nil || reused.df.used != 0 || reused.link.Reader != nil || reused.link.Writer != nil || reused.serverWriter.writer != nil || reused.serverWriter.addr != "" || reused.serverWriter.defaultHeaderLength != 0 || reused.serverWriter.managedDomain != "" || reused.serverWriter.managedHeaderLength != 0 || reused.serverWriter.managedIPv4Header != 0 {
		t.Fatalf("pooled UDP reader retained state: first=%v message=%+v fragments=%d", reused.firstBuf, reused.message, len(reused.df.frags))
	}
}

func TestPooledServerUDPIOAllocationBudget(t *testing.T) {
	source := bytes.NewReader(nil)
	allocations := testing.AllocsPerRun(1000, func() {
		reader := newPooledUDPReader(source)
		writer := &reader.serverWriter
		writer.writer = io.Discard
		writer.addr = "example.com:443"
		reader.link.Reader = reader
		reader.link.Writer = writer
		hysteriaServerLinkSink = &reader.link
		releasePooledUDPReader(reader)
	})
	if allocations > 1 {
		t.Fatalf("pooled Hysteria server UDP I/O allocations = %.0f, want at most one cold-pool allocation", allocations)
	}
}

func BenchmarkServerUDPIOSetup(b *testing.B) {
	source := bytes.NewReader(nil)
	b.Run("current", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			hysteriaServerLinkSink = &transport.Link{
				Reader: &UDPReader{reader: source},
				Writer: &UDPWriter{writer: io.Discard, addr: "example.com:443"},
			}
		}
	})
	b.Run("separate-link", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			reader := newPooledUDPReader(source)
			writer := newPooledUDPWriter(io.Discard, "example.com:443")
			// transport.Link is allocated per connection rather than pooled: it
			// escapes into the outbound handler for the connection's lifetime,
			// so recycling it cannot be shown safe.
			hysteriaServerLinkSink = &transport.Link{Reader: reader, Writer: writer}
			releasePooledUDPWriter(writer)
			releasePooledUDPReader(reader)
		}
	})
	b.Run("pooled", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			reader := newPooledUDPReader(source)
			writer := newPooledUDPWriter(io.Discard, "example.com:443")
			reader.link.Reader = reader
			reader.link.Writer = writer
			hysteriaServerLinkSink = &reader.link
			releasePooledUDPWriter(writer)
			releasePooledUDPReader(reader)
		}
	})
	b.Run("embedded-writer", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			reader := newPooledUDPReader(source)
			reader.serverWriter.writer = io.Discard
			reader.serverWriter.addr = "example.com:443"
			reader.link.Reader = reader
			reader.link.Writer = &reader.serverWriter
			hysteriaServerLinkSink = &reader.link
			releasePooledUDPReader(reader)
		}
	})
}

func BenchmarkAnonymousServerUser(b *testing.B) {
	b.Run("per-connection", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			hysteriaUserSink = new(protocol.MemoryUser)
		}
	})
	b.Run("shared-immutable", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			hysteriaUserSink = anonymousHysteriaUser
		}
	})
}

func TestServerPolicyCachePreservesNonzeroLevels(t *testing.T) {
	manager, err := policyapp.New(context.Background(), &policyapp.Config{})
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{policyManager: manager, sessionPolicy: manager.ForLevel(0)}
	if got, want := server.policyForLevel(0), manager.ForLevel(0); got != want {
		t.Fatalf("level 0 policy = %+v, want %+v", got, want)
	}
	if got, want := server.policyForLevel(7), manager.ForLevel(7); got != want {
		t.Fatalf("level 7 policy = %+v, want %+v", got, want)
	}
}

func BenchmarkServerPolicyForLevelZero(b *testing.B) {
	manager, err := policyapp.New(context.Background(), &policyapp.Config{})
	if err != nil {
		b.Fatal(err)
	}
	server := &Server{policyManager: manager, sessionPolicy: manager.ForLevel(0)}
	b.Run("manager", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			hysteriaPolicySink = manager.ForLevel(0)
		}
	})
	b.Run("cached", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			hysteriaPolicySink = server.policyForLevel(0)
		}
	})
}

func pooledServerTCPIOCycle(readerSource *bytes.Reader, request *serverTCPRequest) error {
	wireWriter := buf.NewPooledWriter(io.Discard)
	if err := writeTCPResponseOK(wireWriter.(io.Writer)); err != nil {
		return err
	}
	reader := buf.NewPooledReader(readerSource)
	request.link.Reader = reader
	request.link.Writer = wireWriter
	hysteriaServerLinkSink = &request.link
	request.link = transport.Link{}
	buf.ReleasePooledReader(reader)
	buf.ReleasePooledWriter(wireWriter)
	return nil
}

func TestPooledServerTCPIOAllocationBudget(t *testing.T) {
	readerSource := bytes.NewReader(nil)
	request := new(serverTCPRequest)
	allocations := testing.AllocsPerRun(1000, func() {
		if err := pooledServerTCPIOCycle(readerSource, request); err != nil {
			panic(err)
		}
	})
	if allocations > 1 {
		t.Fatalf("pooled Hysteria server TCP I/O allocations = %.0f, want at most one cold-pool allocation", allocations)
	}
}

func BenchmarkServerTCPIOSetup(b *testing.B) {
	readerSource := bytes.NewReader(nil)
	b.Run("current", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			writer := buf.NewBufferedWriter(buf.NewWriter(io.Discard))
			if err := writeTCPResponseOK(writer); err != nil {
				b.Fatal(err)
			}
			if err := writer.SetBuffered(false); err != nil {
				b.Fatal(err)
			}
			hysteriaServerLinkSink = &transport.Link{Reader: buf.NewReader(readerSource), Writer: writer}
		}
	})
	b.Run("pooled", func(b *testing.B) {
		request := new(serverTCPRequest)
		b.ReportAllocs()
		for b.Loop() {
			wireWriter := buf.NewPooledWriter(io.Discard)
			if err := writeTCPResponseOK(wireWriter.(io.Writer)); err != nil {
				b.Fatal(err)
			}
			reader := buf.NewPooledReader(readerSource)
			request.link.Reader = reader
			request.link.Writer = wireWriter
			hysteriaServerLinkSink = &request.link
			request.link = transport.Link{}
			buf.ReleasePooledReader(reader)
			buf.ReleasePooledWriter(wireWriter)
		}
	})
}
