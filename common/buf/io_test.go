package buf_test

import (
	"crypto/tls"
	"io"
	"runtime"
	"testing"
	"time"

	. "github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/testing/servers/tcp"
)

type immediateReader struct {
	payload MultiBuffer
}

func (r *immediateReader) ReadMultiBuffer() (MultiBuffer, error) {
	return r.payload, nil
}

type controlledReader struct {
	result <-chan MultiBuffer
}

func (r *controlledReader) ReadMultiBuffer() (MultiBuffer, error) {
	return <-r.result, nil
}

func TestTimeoutWrapperReaderReadyReadDoesNotRetainDeadlineWork(t *testing.T) {
	payload := MultiBuffer{FromBytes([]byte("ready"))}
	reader := &TimeoutWrapperReader{Reader: &immediateReader{payload: payload}}

	const reads = 32
	baseline := runtime.NumGoroutine()
	for range reads {
		got, err := reader.ReadMultiBufferTimeout(time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if got.String() != "ready" {
			t.Fatalf("read payload = %q, want ready", got.String())
		}
	}
	runtime.Gosched()

	if retained := runtime.NumGoroutine() - baseline; retained > 4 {
		t.Fatalf("ready reads retained %d background goroutines, want at most 4", retained)
	}
}

func TestTimeoutWrapperReaderTimeoutPreservesPendingRead(t *testing.T) {
	results := make(chan MultiBuffer, 1)
	reader := &TimeoutWrapperReader{Reader: &controlledReader{result: results}}

	got, err := reader.ReadMultiBufferTimeout(time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if !got.IsEmpty() {
		t.Fatalf("timed-out read returned %q, want no payload", got.String())
	}

	results <- MultiBuffer{FromBytes([]byte("after-timeout"))}
	got, err = reader.ReadMultiBufferTimeout(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "after-timeout" {
		t.Fatalf("pending read payload = %q, want after-timeout", got.String())
	}
}

func BenchmarkTimeoutWrapperReaderReady(b *testing.B) {
	payload := MultiBuffer{FromBytes([]byte("ready"))}
	reader := &TimeoutWrapperReader{Reader: &immediateReader{payload: payload}}

	b.ReportAllocs()
	for b.Loop() {
		got, err := reader.ReadMultiBufferTimeout(10 * time.Millisecond)
		if err != nil {
			b.Fatal(err)
		}
		if got.IsEmpty() {
			got, err = reader.ReadMultiBuffer()
			if err != nil {
				b.Fatal(err)
			}
		}
		if got.String() != "ready" {
			b.Fatalf("read payload = %q, want ready", got.String())
		}
	}
}

func TestWriterCreation(t *testing.T) {
	tcpServer := tcp.Server{}
	dest, err := tcpServer.Start()
	if err != nil {
		t.Fatal("failed to start tcp server: ", err)
	}
	defer tcpServer.Close()

	conn, err := net.Dial("tcp", dest.NetAddr())
	if err != nil {
		t.Fatal("failed to dial a TCP connection: ", err)
	}
	defer conn.Close()

	{
		writer := NewWriter(conn)
		if _, ok := writer.(*BufferToBytesWriter); !ok {
			t.Fatal("writer is not a BufferToBytesWriter")
		}

		writer2 := NewWriter(writer.(io.Writer))
		if writer2 != writer {
			t.Fatal("writer is not reused")
		}
	}

	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true,
	})
	defer tlsConn.Close()

	{
		writer := NewWriter(tlsConn)
		if _, ok := writer.(*SequentialWriter); !ok {
			t.Fatal("writer is not a SequentialWriter")
		}
	}
}
