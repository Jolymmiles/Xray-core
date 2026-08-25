package buf_test

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/xtls/xray-core/common"
	. "github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/transport/pipe"
)

type emptyMultiBufferReader struct{}

func (emptyMultiBufferReader) ReadMultiBuffer() (MultiBuffer, error) {
	return nil, nil
}

type payloadEOFReader struct {
	payload []byte
	done    bool
}

func (r *payloadEOFReader) ReadMultiBuffer() (MultiBuffer, error) {
	if r.done {
		return nil, io.EOF
	}
	r.done = true
	buffer := New()
	_, _ = buffer.Write(r.payload)
	return MultiBuffer{buffer}, io.EOF
}

func TestBufferedReaderPreservesPayloadReturnedWithEOF(t *testing.T) {
	reader := &BufferedReader{Reader: &payloadEOFReader{payload: []byte("final")}}
	var got bytes.Buffer
	chunk := make([]byte, 2)
	for {
		count, err := reader.Read(chunk)
		got.Write(chunk[:count])
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if got.String() != "final" {
		t.Fatalf("payload = %q, want final", got.String())
	}
}

func TestBufferedReaderReadByteDefersEOFUntilPayloadDrained(t *testing.T) {
	reader := &BufferedReader{Reader: &payloadEOFReader{payload: []byte("ab")}}
	for index, want := range []byte("ab") {
		got, err := reader.ReadByte()
		if err != nil || got != want {
			t.Fatalf("byte %d = (%q, %v), want (%q, nil)", index, got, err, want)
		}
	}
	if _, err := reader.ReadByte(); err != io.EOF {
		t.Fatalf("terminal error = %v, want EOF", err)
	}
}

func TestBufferedReaderSplitterDefersEOFUntilByteDelivered(t *testing.T) {
	reader := &BufferedReader{Reader: &payloadEOFReader{payload: []byte("x")}, Splitter: SplitFirstBytes}
	value, err := reader.ReadByte()
	if err != nil || value != 'x' {
		t.Fatalf("first byte = (%q, %v), want (x, nil)", value, err)
	}
	if _, err := reader.ReadByte(); err != io.EOF {
		t.Fatalf("terminal error = %v, want EOF", err)
	}
}

func TestBufferedReaderReadAtMostDefersEOFUntilPayloadDrained(t *testing.T) {
	reader := &BufferedReader{Reader: &payloadEOFReader{payload: []byte("final")}}
	first, err := reader.ReadAtMost(2)
	if err != nil || first.String() != "fi" {
		t.Fatalf("first read = (%q, %v), want (fi, nil)", first.String(), err)
	}
	ReleaseMulti(first)
	second, err := reader.ReadAtMost(8)
	if err != nil || second.String() != "nal" {
		t.Fatalf("second read = (%q, %v), want (nal, nil)", second.String(), err)
	}
	ReleaseMulti(second)
	if _, err := reader.ReadAtMost(8); err != io.EOF {
		t.Fatalf("terminal error = %v, want EOF", err)
	}
}

func TestBytesReaderWriteTo(t *testing.T) {
	pReader, pWriter := pipe.New(pipe.WithSizeLimit(1024))
	reader := &BufferedReader{Reader: pReader}
	b1 := New()
	b1.WriteString("abc")
	b2 := New()
	b2.WriteString("efg")
	common.Must(pWriter.WriteMultiBuffer(MultiBuffer{b1, b2}))
	pWriter.Close()

	pReader2, pWriter2 := pipe.New(pipe.WithSizeLimit(1024))
	writer := NewBufferedWriter(pWriter2)
	writer.SetBuffered(false)

	nBytes, err := io.Copy(writer, reader)
	common.Must(err)
	if nBytes != 6 {
		t.Error("copy: ", nBytes)
	}

	mb, err := pReader2.ReadMultiBuffer()
	common.Must(err)
	if s := mb.String(); s != "abcefg" {
		t.Error("content: ", s)
	}
}

func TestBytesReaderMultiBuffer(t *testing.T) {
	pReader, pWriter := pipe.New(pipe.WithSizeLimit(1024))
	reader := &BufferedReader{Reader: pReader}
	b1 := New()
	b1.WriteString("abc")
	b2 := New()
	b2.WriteString("efg")
	common.Must(pWriter.WriteMultiBuffer(MultiBuffer{b1, b2}))
	pWriter.Close()

	mbReader := NewReader(reader)
	mb, err := mbReader.ReadMultiBuffer()
	common.Must(err)
	if s := mb.String(); s != "abcefg" {
		t.Error("content: ", s)
	}
}

func TestBufferedReaderReleasesConsumedBufferBeforeBlockingRead(t *testing.T) {
	consumed := New()
	reader := &BufferedReader{
		Reader: NewReader(strings.NewReader("")),
		Buffer: MultiBuffer{consumed},
	}

	if _, err := reader.ReadMultiBuffer(); err != io.EOF {
		t.Fatalf("read error = %v, want EOF", err)
	}
	if reader.Buffer != nil {
		t.Fatal("consumed buffer remains retained after the reader moved to the underlying connection")
	}
}

func TestReadByte(t *testing.T) {
	sr := strings.NewReader("abcd")
	reader := &BufferedReader{
		Reader: NewReader(sr),
	}
	b, err := reader.ReadByte()
	common.Must(err)
	if b != 'a' {
		t.Error("unexpected byte: ", b, " want a")
	}
	if reader.BufferedBytes() != 3 { // 3 bytes left in buffer
		t.Error("unexpected buffered Bytes: ", reader.BufferedBytes())
	}

	nBytes, err := reader.WriteTo(DiscardBytes)
	common.Must(err)
	if nBytes != 3 {
		t.Error("unexpect bytes written: ", nBytes)
	}
}

func TestReadByteReturnsEOFAfterLastByte(t *testing.T) {
	reader := &BufferedReader{Reader: NewReader(strings.NewReader("a"))}

	value, err := reader.ReadByte()
	if err != nil {
		t.Fatalf("first ReadByte: %v", err)
	}
	if value != 'a' {
		t.Fatalf("first ReadByte = %q, want %q", value, 'a')
	}

	if value, err = reader.ReadByte(); err != io.EOF {
		t.Fatalf("ReadByte after content = (%q, %v), want (0, EOF)", value, err)
	}
}

func TestReadByteRejectsEmptyReadWithoutError(t *testing.T) {
	reader := &BufferedReader{Reader: emptyMultiBufferReader{}}

	if value, err := reader.ReadByte(); value != 0 || err != io.ErrNoProgress {
		t.Fatalf("ReadByte on empty read = (%q, %v), want (0, %v)", value, err, io.ErrNoProgress)
	}
}

func TestReadBuffer(t *testing.T) {
	{
		sr := strings.NewReader("abcd")
		buf, err := ReadBuffer(sr)
		common.Must(err)

		if s := buf.String(); s != "abcd" {
			t.Error("unexpected str: ", s, " want abcd")
		}
		buf.Release()
	}
}

func TestReadAtMost(t *testing.T) {
	sr := strings.NewReader("abcd")
	reader := &BufferedReader{
		Reader: NewReader(sr),
	}

	mb, err := reader.ReadAtMost(3)
	common.Must(err)
	if s := mb.String(); s != "abc" {
		t.Error("unexpected read result: ", s)
	}

	nBytes, err := reader.WriteTo(DiscardBytes)
	common.Must(err)
	if nBytes != 1 {
		t.Error("unexpect bytes written: ", nBytes)
	}
}

func TestPacketReader_ReadMultiBuffer(t *testing.T) {
	const alpha = "abcefg"
	buf := bytes.NewBufferString(alpha)
	reader := &PacketReader{buf}
	mb, err := reader.ReadMultiBuffer()
	common.Must(err)
	if s := mb.String(); s != alpha {
		t.Error("content: ", s)
	}
}

func TestReaderInterface(t *testing.T) {
	_ = io.Reader(new(ReadVReader))
	_ = Reader(new(ReadVReader))

	_ = Reader(new(BufferedReader))
	_ = io.Reader(new(BufferedReader))
	_ = io.ByteReader(new(BufferedReader))
	_ = io.WriterTo(new(BufferedReader))
}

type closeTrackingReader struct {
	closed bool
}

func (*closeTrackingReader) Read([]byte) (int, error) { return 0, io.EOF }

func (r *closeTrackingReader) Close() error {
	r.closed = true
	return nil
}

func TestReaderInterruptReachesUnderlyingCloser(t *testing.T) {
	t.Run("regular", func(t *testing.T) {
		underlying := new(closeTrackingReader)
		reader := NewReader(underlying)

		if err := common.Interrupt(reader); err != nil {
			t.Fatal(err)
		}
		if !underlying.closed {
			t.Fatal("interrupt did not reach the underlying reader")
		}
	})

	t.Run("pooled", func(t *testing.T) {
		underlying := new(closeTrackingReader)
		reader := NewPooledReader(underlying)
		defer ReleasePooledReader(reader)

		if err := common.Interrupt(reader); err != nil {
			t.Fatal(err)
		}
		if !underlying.closed {
			t.Fatal("interrupt did not reach the underlying pooled reader")
		}
	})
}
