package dispatcher

import (
	"context"
	gotls "crypto/tls"
	"errors"
	stdnet "net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/transport/pipe"
)

const (
	// boundPipeLimit is the per-connection pipe limit of the default policy.
	boundPipeLimit = 512 * 1024
	// boundMaxCache is what a sniff may cache at most here: the bytes a
	// sniffer sees, the pipe's limit and one write of the client, with room
	// to spare.
	boundMaxCache = 1 << 20
)

// boundSniffView returns how many bytes of the cache a sniffer sees: the
// capacity of the scratch buffer Cache copies them into.
func boundSniffView() int {
	b := buf.NewWithSize(32767)
	defer b.Release()
	return int(b.Cap())
}

// boundChunkReader hands out its chunks, one per read. After them it hands
// out a fresh buffer of fill bytes per read, for ever, or, with no fill,
// times out like a link that has nothing more to deliver.
type boundChunkReader struct {
	chunks [][]byte
	fill   int32
	reads  int
}

func (r *boundChunkReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	return r.ReadMultiBufferTimeout(0)
}

func (r *boundChunkReader) ReadMultiBufferTimeout(time.Duration) (buf.MultiBuffer, error) {
	r.reads++
	if len(r.chunks) > 0 {
		chunk := r.chunks[0]
		r.chunks = r.chunks[1:]
		return buf.MergeBytes(nil, chunk), nil
	}
	if r.fill == 0 {
		return nil, buf.ErrReadTimeout
	}
	b := buf.New()
	b.Extend(r.fill)
	return buf.MultiBuffer{b}, nil
}

// boundCachedReader returns a cached reader of link that releases what it
// still caches when the test ends.
func boundCachedReader(t *testing.T, link buf.TimeoutReader) *cachedReader {
	t.Helper()
	reader := newCachedReader(link)
	t.Cleanup(func() { buf.ReleaseMulti(reader.readInternal()) })
	return reader
}

// sniffDuringUpload sniffs a link whose client writes first and then keeps
// uploading full buffers until the sniff ends, through a pipe with the
// default per-connection limit. It returns the result and what the sniff
// cached before the flow would be routed.
func sniffDuringUpload(t *testing.T, network net.Network, sniffer Sniffer, first []byte) (SniffResult, error, int32) {
	t.Helper()
	reader, writer := pipe.New(pipe.WithSizeLimit(boundPipeLimit))
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		if len(first) > 0 && writer.WriteMultiBuffer(buf.MergeBytes(nil, first)) != nil {
			return
		}
		for {
			select {
			case <-stop:
				return
			default:
			}
			b := buf.New()
			b.Extend(buf.Size)
			if writer.WriteMultiBuffer(buf.MultiBuffer{b}) != nil {
				return
			}
		}
	}()
	cached := boundCachedReader(t, reader)
	result, err := sniff(snifferContext(), cached, false, network, sniffer)
	cached.Lock()
	size := cached.cache.Len()
	cached.Unlock()
	close(stop)
	reader.Interrupt()
	<-done
	return result, err, size
}

// craftedTLSRecords is a ClientHello of 32000 bytes in records of 16384: it
// is whole only past the bytes a sniffer sees, so the TLS sniffer asks for
// more data for as long as it is asked.
func craftedTLSRecords() []byte {
	const helloLen = 32000
	message := make([]byte, 2*16384)
	message[0], message[1], message[2], message[3] = 0x01, byte(helloLen>>16), byte(helloLen>>8), byte(helloLen&0xff)
	var out []byte
	for i := 0; i < 2; i++ {
		out = append(out, 0x16, 0x03, 0x01, 0x40, 0x00)
		out = append(out, message[i*16384:(i+1)*16384]...)
	}
	return out
}

// needMoreDataSniffer asks for more data until it is shown enough bytes.
func needMoreDataSniffer(network net.Network, enough int) Sniffer {
	sniff := func(_ context.Context, b []byte) (SniffResult, error) {
		if len(b) < enough {
			return nil, protocol.ErrProtoNeedMoreData
		}
		return fixedSniffResult{protocol: "test", domain: "example.com"}, nil
	}
	return Sniffer{sniffer: []protocolSnifferWithMetadata{{protocolSniffer: sniff, network: network}}}
}

// A sniffer that asks for more data than the cache shows it can never be
// answered, so the dispatcher stops reading once the cache holds more than
// the sniffer sees. It used to read, and cache, the client's upload for the
// whole sniff budget, past the pipe's limit: hundreds of megabytes.
func TestSniffStopsCachingOnceTheSnifferSeesNoMore(t *testing.T) {
	cases := []struct {
		name    string
		network net.Network
		sniffer Sniffer
		first   []byte
	}{
		{"TLS records of a ClientHello past the view", net.Network_TCP, newSniffer(snifferContext()), craftedTLSRecords()},
		{"TCP sniffer that always needs more", net.Network_TCP, needMoreDataSniffer(net.Network_TCP, 1<<30), nil},
		{"UDP sniffer that always needs more", net.Network_UDP, needMoreDataSniffer(net.Network_UDP, 1<<30), nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			result, err, size := sniffDuringUpload(t, c.network, c.sniffer, c.first)
			t.Logf("%v, %v, %d bytes cached", result, err, size)
			if !errors.Is(err, errSniffingPastView) {
				t.Errorf("sniff ended with %v, %v; want %v", result, err, errSniffingPastView)
			}
			if size > boundMaxCache {
				t.Errorf("%d bytes cached behind a %d-byte pipe", size, boundPipeLimit)
			}
		})
	}
}

// The sniffer is shown more data, one read at a time, until it sees all the
// cache shows, and no read longer: on a link without a pipe, as DispatchLink
// sniffs an inbound's reader, too.
func TestSniffReadsUntilTheViewIsFull(t *testing.T) {
	view := boundSniffView()
	const chunk = 1024
	for _, network := range []net.Network{net.Network_TCP, net.Network_UDP} {
		t.Run(network.String()+" needs the whole view", func(t *testing.T) {
			link := &boundChunkReader{fill: chunk}
			result, err := sniff(snifferContext(), boundCachedReader(t, link), false, network, needMoreDataSniffer(network, view))
			if err != nil || result.Domain() != "example.com" {
				t.Fatalf("sniffed %v, %v from %d bytes", result, err, view)
			}
			if link.reads != view/chunk {
				t.Fatalf("%d reads, want %d", link.reads, view/chunk)
			}
		})
		t.Run(network.String()+" needs a byte past the view", func(t *testing.T) {
			link := &boundChunkReader{fill: chunk}
			result, err := sniff(snifferContext(), boundCachedReader(t, link), false, network, needMoreDataSniffer(network, view+1))
			if !errors.Is(err, errSniffingPastView) {
				t.Fatalf("sniff ended with %v, %v; want %v", result, err, errSniffingPastView)
			}
			// The read that fills the view, and the one past it.
			if link.reads != view/chunk+1 {
				t.Fatalf("%d reads, want %d", link.reads, view/chunk+1)
			}
		})
	}
}

// boundClientHello captures a genuine ClientHello from the standard library.
func boundClientHello(t *testing.T) []byte {
	t.Helper()
	client, server := stdnet.Pipe()
	captured := make(chan []byte, 1)
	go func() {
		defer server.Close()
		record := make([]byte, 4096)
		n, _ := server.Read(record)
		captured <- record[:n]
	}()
	conn := gotls.Client(client, &gotls.Config{ServerName: "example.com", InsecureSkipVerify: true})
	_ = conn.Handshake()
	_ = client.Close()
	hello := <-captured
	if len(hello) < 5 {
		t.Fatal("no ClientHello captured")
	}
	return hello
}

// A real ClientHello fragmented into small records, one record per read, is
// reassembled from all the reads.
func TestSniffReassemblesAClientHelloAcrossReads(t *testing.T) {
	message := boundClientHello(t)[5:]
	link := &boundChunkReader{}
	for len(message) > 0 {
		n := min(len(message), 64)
		record := append([]byte{0x16, 0x03, 0x01, 0x00, byte(n)}, message[:n]...)
		link.chunks = append(link.chunks, record)
		message = message[n:]
	}
	records := len(link.chunks)
	result, err := sniff(snifferContext(), boundCachedReader(t, link), false, net.Network_TCP, newSniffer(snifferContext()))
	if err != nil || result.Domain() != "example.com" {
		t.Fatalf("sniffed %v, %v", result, err)
	}
	if link.reads != records {
		t.Fatalf("%d reads of %d records", link.reads, records)
	}
}
