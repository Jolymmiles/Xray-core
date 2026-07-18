package buf_test

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	statsapp "github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common"
	. "github.com/xtls/xray-core/common/buf"
	X "github.com/xtls/xray-core/common/net"
	transportstat "github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/pipe"
)

type benchmarkStreamConn struct{}

func (*benchmarkStreamConn) Read([]byte) (int, error)          { return 0, io.EOF }
func (*benchmarkStreamConn) Write(payload []byte) (int, error) { return len(payload), nil }
func (*benchmarkStreamConn) Close() error                      { return nil }
func (*benchmarkStreamConn) LocalAddr() net.Addr               { return nil }
func (*benchmarkStreamConn) RemoteAddr() net.Addr              { return nil }
func (*benchmarkStreamConn) SetDeadline(time.Time) error       { return nil }
func (*benchmarkStreamConn) SetReadDeadline(time.Time) error   { return nil }
func (*benchmarkStreamConn) SetWriteDeadline(time.Time) error  { return nil }

var writerBenchmarkSink Writer

func TestManagedUDPIPv4Metadata(t *testing.T) {
	buffer := New()
	defer buffer.Release()
	if _, _, ok := buffer.ManagedUDPIPv4(); ok {
		t.Fatal("fresh buffer reported managed IPv4 metadata")
	}
	wantIP := [4]byte{192, 0, 2, 1}
	wantPort := X.Port(5353)
	buffer.SetManagedUDPIPv4(wantIP, wantPort)
	gotIP, gotPort, ok := buffer.ManagedUDPIPv4()
	if !ok || gotIP != wantIP || gotPort != wantPort {
		t.Fatalf("managed IPv4 = %v:%d, ok=%v", gotIP, gotPort, ok)
	}
	buffer.SetManagedUDPDestination(X.UDPDestination(X.DomainAddress("example.com"), 53))
	if _, _, ok := buffer.ManagedUDPIPv4(); ok {
		t.Fatal("domain destination retained managed IPv4 metadata")
	}
	buffer.SetManagedUDPDomain("managed.example", 5353)
	if buffer.UDP == nil || buffer.UDP.Address.Domain() != "managed.example" || buffer.UDP.Port != 5353 {
		t.Fatalf("managed domain destination = %v", buffer.UDP)
	}
	if domain, port, ok := buffer.ManagedUDPDomain(); !ok || domain != "managed.example" || port != 5353 {
		t.Fatalf("managed domain metadata = %q:%d, ok=%v", domain, port, ok)
	}
}

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

func TestNewWriterPreservesStreamCounter(t *testing.T) {
	counter := new(statsapp.Counter)
	connection := &transportstat.CounterConnection{
		Connection:   new(benchmarkStreamConn),
		WriteCounter: counter,
	}
	writer := NewWriter(connection)
	if err := writer.WriteMultiBuffer(MultiBuffer{FromBytes([]byte("payload"))}); err != nil {
		t.Fatal(err)
	}
	if got := counter.Value(); got != 7 {
		t.Fatalf("write counter = %d, want 7", got)
	}
}

func TestNewPooledWriterPreservesStreamCounter(t *testing.T) {
	counter := new(statsapp.Counter)
	connection := &transportstat.CounterConnection{
		Connection:   new(benchmarkStreamConn),
		WriteCounter: counter,
	}
	writer := NewPooledWriter(connection)
	if err := writer.WriteMultiBuffer(MultiBuffer{FromBytes([]byte("payload"))}); err != nil {
		t.Fatal(err)
	}
	ReleasePooledWriter(writer)
	if got := counter.Value(); got != 7 {
		t.Fatalf("write counter = %d, want 7", got)
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

func TestBufferedWriterWithPrefixPreservesFirstPayloadBuffers(t *testing.T) {
	underlying := new(recordingMultiBufferWriter)
	writer, err := NewBufferedWriterWithPrefix(underlying, []byte("header"))
	if err != nil {
		t.Fatal(err)
	}
	payload := FromBytes([]byte("payload"))
	if err := writer.WriteMultiBuffer(MultiBuffer{payload}); err != nil {
		t.Fatal(err)
	}
	if len(underlying.calls) != 1 || underlying.calls[0].String() != "headerpayload" {
		t.Fatalf("first write = %v, want headerpayload", underlying.calls)
	}
	if len(underlying.calls[0]) != 2 || underlying.calls[0][1] != payload {
		t.Fatal("first payload buffer was copied instead of transferred")
	}
	ReleaseMulti(underlying.calls[0])
}

func TestSequentialWriterConsumesPrefixAndPayload(t *testing.T) {
	var output bytes.Buffer
	writer, err := NewBufferedWriterWithPrefix(&SequentialWriter{Writer: &output}, []byte("header"))
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteMultiBuffer(MultiBuffer{FromBytes([]byte("payload"))}); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); got != "headerpayload" {
		t.Fatalf("wire output = %q, want headerpayload", got)
	}
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

func BenchmarkBufferedTCPWriterHeaderAndFirstPayload(b *testing.B) {
	header := []byte("vless-response-header")
	payload := make([]byte, 1400)
	b.SetBytes(int64(len(header) + len(payload)))
	b.ReportAllocs()

	for b.Loop() {
		underlying := &BufferToBytesWriter{Writer: io.Discard}
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

func BenchmarkPrefixedBufferedTCPWriterHeaderAndFirstPayload(b *testing.B) {
	header := []byte("vless-response-header")
	payload := make([]byte, 1400)
	b.SetBytes(int64(len(header) + len(payload)))
	b.ReportAllocs()

	for b.Loop() {
		underlying := &BufferToBytesWriter{Writer: io.Discard}
		writer, err := NewBufferedWriterWithPrefix(underlying, header)
		if err != nil {
			b.Fatal(err)
		}
		if err := writer.WriteMultiBuffer(MultiBuffer{FromBytes(payload)}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPrefixedBufferedSequentialWriter(b *testing.B) {
	header := []byte("vless-response-header")
	payload := make([]byte, 1400)
	b.SetBytes(int64(len(header) + len(payload)))
	b.ReportAllocs()

	for b.Loop() {
		underlying := &SequentialWriter{Writer: io.Discard}
		writer, err := NewPooledBufferedWriterWithPrefix(underlying, header)
		if err != nil {
			b.Fatal(err)
		}
		if err := writer.WriteMultiBuffer(MultiBuffer{FromBytes(payload)}); err != nil {
			b.Fatal(err)
		}
		writer.Release()
	}
}

func BenchmarkNewStreamWriter(b *testing.B) {
	connection := new(benchmarkStreamConn)
	b.ReportAllocs()
	for b.Loop() {
		writerBenchmarkSink = NewWriter(connection)
	}
}

func BenchmarkPooledVLESSResponseWriterSetup(b *testing.B) {
	connection := new(benchmarkStreamConn)
	payload := make([]byte, 1400)
	header := []byte{0, 0}
	b.ReportAllocs()
	b.SetBytes(int64(len(header) + len(payload)))
	for b.Loop() {
		underlying := NewPooledWriter(connection)
		writer, err := NewPooledBufferedWriterWithPrefix(underlying, header)
		if err != nil {
			b.Fatal(err)
		}
		if err := writer.WriteMultiBuffer(MultiBuffer{FromBytes(payload)}); err != nil {
			b.Fatal(err)
		}
		writer.Release()
		ReleasePooledWriter(underlying)
	}
}
