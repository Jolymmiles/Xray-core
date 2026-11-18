package dispatcher

import (
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/pipe"
)

// sniffWhileClientUploads sniffs a TCP link whose client keeps writing after
// its first bytes, through a pipe with the default per-connection limit, and
// returns how long the flow waited and what the sniffer cached meanwhile.
func sniffWhileClientUploads(t *testing.T, first []byte) (SniffResult, error, time.Duration, int32) {
	t.Helper()
	reader, writer := pipe.New(pipe.WithSizeLimit(512 * 1024))
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		head := buf.New()
		_, _ = head.Write(first)
		_ = head.Extend(head.Available())
		if writer.WriteMultiBuffer(buf.MultiBuffer{head}) != nil {
			return
		}
		for {
			select {
			case <-stop:
				return
			default:
			}
			b := buf.New()
			_ = b.Extend(buf.Size)
			if writer.WriteMultiBuffer(buf.MultiBuffer{b}) != nil {
				return
			}
		}
	}()
	cached := newCachedReader(reader)
	ctx := snifferContext()
	start := time.Now()
	result, err := sniff(ctx, cached, false, net.Network_TCP, newSniffer(ctx))
	took := time.Since(start)
	size := cached.cache.Len()
	close(stop)
	reader.Interrupt()
	<-done
	buf.ReleaseMulti(cached.readInternal())
	return result, err, took, size
}

// A STUN header that names more than the cache shows a sniffer is turned
// down at once: waiting kept the dispatcher reading, and caching, the
// client's upload for the whole sniff budget, past the pipe's limit (Joly's
// review of #80, item 1).
func TestSniffSTUNHeaderDoesNotHoldTheUpload(t *testing.T) {
	const limit = 4 << 20
	cases := []struct {
		name  string
		first []byte
	}{
		{"STUN header, length 65532", []byte{0x00, 0x01, 0xff, 0xfc, 0x21, 0x12, 0xa4, 0x42}},
		{"STUN header, length 32752", []byte{0x00, 0x01, 0x7f, 0xf0, 0x21, 0x12, 0xa4, 0x42}},
		{"STUN header, length 1024", []byte{0x00, 0x01, 0x04, 0x00, 0x21, 0x12, 0xa4, 0x42}},
		{"no STUN header", []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
	}
	for _, c := range cases {
		result, err, took, size := sniffWhileClientUploads(t, c.first)
		t.Logf("%-26s -> %v, %v after %v, %d bytes cached", c.name, result, err, took.Round(time.Microsecond), size)
		if size > limit {
			t.Errorf("%s: %d bytes cached behind a 512 KiB pipe", c.name, size)
		}
		if took > 100*time.Millisecond {
			t.Errorf("%s: the flow waited %v", c.name, took)
		}
	}
}
