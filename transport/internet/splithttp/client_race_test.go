package splithttp

import (
	"bytes"
	"io"
	"sync"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/transport/pipe"
)

type waitReadCloserTestReader struct {
	*bytes.Reader
}

func (*waitReadCloserTestReader) Close() error { return nil }

func TestWaitReadCloserPublishesReaderBeforeConcurrentRead(t *testing.T) {
	for range 1000 {
		waiter := &WaitReadCloser{Wait: make(chan struct{})}
		reader := &waitReadCloserTestReader{Reader: bytes.NewReader([]byte{'x'})}
		start := make(chan struct{})
		var group sync.WaitGroup
		group.Go(func() {
			<-start
			waiter.Set(reader)
		})
		group.Go(func() {
			<-start
			_, _ = waiter.Read(make([]byte, 1))
		})
		close(start)
		group.Wait()
		_ = waiter.Close()
	}
}

func TestUploadWriterStopsReadingBufferAfterOwnershipTransfer(t *testing.T) {
	reader, writer := pipe.New()
	upload := uploadWriter{Writer: writer}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			buffers, err := reader.ReadMultiBuffer()
			if err != nil {
				return
			}
			buf.ReleaseMulti(buffers)
		}
	}()
	payload := bytes.Repeat([]byte{'x'}, 4096)
	for range 1000 {
		if n, err := upload.Write(payload); err != nil || n != len(payload) {
			t.Fatalf("upload.Write() = %d, %v", n, err)
		}
	}
	_ = writer.Close()
	reader.Interrupt()
	<-done
}

var _ io.ReadCloser = (*waitReadCloserTestReader)(nil)
