package dispatcher

import (
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
)

// managedBufferTimeoutReader yields pool-managed buffers, so a Release actually
// recycles the storage and a later read of it is observable under -race and
// -d=checkptr rather than touching still-valid heap memory.
type managedBufferTimeoutReader struct {
	payload []byte
	split   bool
}

func (r *managedBufferTimeoutReader) fill() *buf.Buffer {
	b := buf.New()
	b.Write(r.payload)
	return b
}

func (r *managedBufferTimeoutReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if r.split {
		return buf.MultiBuffer{r.fill(), r.fill()}, nil
	}
	return buf.MultiBuffer{r.fill()}, nil
}

func (r *managedBufferTimeoutReader) ReadMultiBufferTimeout(time.Duration) (buf.MultiBuffer, error) {
	return r.ReadMultiBuffer()
}

// TestCachedReaderCacheSurvivesConcurrentInterrupt is the trigger for
// FORK_DEFECTS_REVIEW item B. Interrupt releases the pooled cache and scratch
// buffers after Cache drops its lock, while the caller may still be sniffing.
// Cache must therefore return storage independent of both pooled sources.
//
// Both dispatch paths call Cache and Interrupt from one goroutine in order, so
// this drives the interleaving the review suspected but could not place: a
// caller tearing the link down while sniffing is still reading the payload.
func TestCachedReaderCacheSurvivesConcurrentInterrupt(t *testing.T) {
	for _, split := range []bool{false, true} {
		for range 300 {
			reader := newCachedReader(&managedBufferTimeoutReader{
				payload: []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
				split:   split,
			})

			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				reader.Interrupt()
			}()

			payload, err := reader.Cache(time.Second)
			if err == nil && len(payload) > 0 {
				reader.Lock()
				if len(reader.cache) == 1 && len(reader.cache[0].Bytes()) > 0 &&
					&payload[0] == &reader.cache[0].Bytes()[0] {
					reader.Unlock()
					t.Fatal("Cache returned a view into its pooled single buffer")
				}
				if reader.scratch != nil && len(reader.scratch.Bytes()) > 0 &&
					&payload[0] == &reader.scratch.Bytes()[0] {
					reader.Unlock()
					t.Fatal("Cache returned a view into its pooled scratch buffer")
				}
				reader.Unlock()

				// What sniffer.Sniff does with the borrowed slice.
				sink := make([]byte, len(payload))
				copy(sink, payload)
			}

			wg.Wait()
			buf.ReleaseMulti(reader.readInternal())
		}
	}
}
