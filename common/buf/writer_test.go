package buf_test

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/xtls/xray-core/common"
	. "github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/transport/pipe"
)

type releasingMultiBufferWriter struct{}

func (releasingMultiBufferWriter) WriteMultiBuffer(mb MultiBuffer) error {
	ReleaseMulti(mb)
	return nil
}

type recordingMultiBufferWriter struct {
	calls []MultiBuffer
}

func (w *recordingMultiBufferWriter) WriteMultiBuffer(mb MultiBuffer) error {
	w.calls = append(w.calls, mb)
	return nil
}

func TestWriter(t *testing.T) {
	lb := New()
	common.Must2(lb.ReadFrom(rand.Reader))

	expectedBytes := append([]byte(nil), lb.Bytes()...)

	writeBuffer := bytes.NewBuffer(make([]byte, 0, 1024*1024))

	writer := NewBufferedWriter(NewWriter(writeBuffer))
	writer.SetBuffered(false)
	common.Must(writer.WriteMultiBuffer(MultiBuffer{lb}))
	common.Must(writer.Flush())

	if r := cmp.Diff(expectedBytes, writeBuffer.Bytes()); r != "" {
		t.Error(r)
	}
}

func TestBytesWriterReadFrom(t *testing.T) {
	const size = 50000
	pReader, pWriter := pipe.New(pipe.WithSizeLimit(size))
	reader := bufio.NewReader(io.LimitReader(rand.Reader, size))
	writer := NewBufferedWriter(pWriter)
	writer.SetBuffered(false)
	nBytes, err := reader.WriteTo(writer)
	if nBytes != size {
		t.Fatal("unexpected size of bytes written: ", nBytes)
	}
	if err != nil {
		t.Fatal("expect success, but actually error: ", err.Error())
	}

	mb, err := pReader.ReadMultiBuffer()
	common.Must(err)
	if mb.Len() != size {
		t.Fatal("unexpected size read: ", mb.Len())
	}
}

func TestDiscardBytes(t *testing.T) {
	b := New()
	common.Must2(b.ReadFullFrom(rand.Reader, Size))

	nBytes, err := io.Copy(DiscardBytes, b)
	common.Must(err)
	if nBytes != Size {
		t.Error("copy size: ", nBytes)
	}
}

func TestDiscardBytesMultiBuffer(t *testing.T) {
	const size = 10240*1024 + 1
	buffer := bytes.NewBuffer(make([]byte, 0, size))
	common.Must2(buffer.ReadFrom(io.LimitReader(rand.Reader, size)))

	r := NewReader(buffer)
	nBytes, err := io.Copy(DiscardBytes, &BufferedReader{Reader: r})
	common.Must(err)
	if nBytes != size {
		t.Error("copy size: ", nBytes)
	}
}

func TestWriterInterface(t *testing.T) {
	{
		var writer interface{} = (*BufferToBytesWriter)(nil)
		switch writer.(type) {
		case Writer, io.Writer, io.ReaderFrom:
		default:
			t.Error("BufferToBytesWriter is not Writer, io.Writer or io.ReaderFrom")
		}
	}

	{
		var writer interface{} = (*BufferedWriter)(nil)
		switch writer.(type) {
		case Writer, io.Writer, io.ReaderFrom, io.ByteWriter:
		default:
			t.Error("BufferedWriter is not Writer, io.Writer, io.ReaderFrom or io.ByteWriter")
		}
	}
}

func TestBufferedWriterFlushNextPreservesFirstPayloadBuffers(t *testing.T) {
	underlying := new(recordingMultiBufferWriter)
	writer := NewBufferedWriter(underlying)
	if _, err := writer.Write([]byte("header")); err != nil {
		t.Fatal(err)
	}
	writer.SetFlushNext()

	payload := FromBytes([]byte("payload"))
	if err := writer.WriteMultiBuffer(MultiBuffer{payload}); err != nil {
		t.Fatal(err)
	}
	if len(underlying.calls) != 1 {
		t.Fatalf("underlying writes = %d, want 1", len(underlying.calls))
	}
	firstWrite := underlying.calls[0]
	defer ReleaseMulti(firstWrite)
	if got := firstWrite.String(); got != "headerpayload" {
		t.Fatalf("wire output = %q, want %q", got, "headerpayload")
	}
	if len(firstWrite) != 2 || firstWrite[1] != payload {
		t.Fatal("first payload buffer was copied instead of transferred")
	}

	next := FromBytes([]byte("next"))
	if err := writer.WriteMultiBuffer(MultiBuffer{next}); err != nil {
		t.Fatal(err)
	}
	if len(underlying.calls) != 2 || len(underlying.calls[1]) != 1 || underlying.calls[1][0] != next {
		t.Fatal("writer did not remain in pass-through mode after flush-next")
	}
	ReleaseMulti(underlying.calls[1])
}

func BenchmarkBufferedWriterHeaderAndFirstPayload(b *testing.B) {
	underlying := releasingMultiBufferWriter{}
	header := []byte("vless-request-header")
	payload := make([]byte, 1400)
	b.SetBytes(int64(len(header) + len(payload)))
	b.ReportAllocs()

	for b.Loop() {
		writer := NewBufferedWriter(underlying)
		if _, err := writer.Write(header); err != nil {
			b.Fatal(err)
		}
		writer.SetFlushNext()
		if err := writer.WriteMultiBuffer(MultiBuffer{FromBytes(payload)}); err != nil {
			b.Fatal(err)
		}
	}
}
