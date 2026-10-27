package buf

import (
	"io"
	"net"
	"sync"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/features/stats"
)

// BufferToBytesWriter is a Writer that writes alloc.Buffer into underlying writer.
type BufferToBytesWriter struct {
	io.Writer

	counter stats.Counter
	inline  [2][]byte
	cache   [][]byte
}

// WriteMultiBuffer implements Writer. This method takes ownership of the given buffer.
func (w *BufferToBytesWriter) WriteMultiBuffer(mb MultiBuffer) error {
	defer ReleaseMulti(mb)

	size := mb.Len()
	if size == 0 {
		return nil
	}

	if len(mb) == 1 {
		return WriteAllBytes(w.Writer, mb[0].Bytes(), w.counter)
	}

	bufferCount := len(mb)
	var bs [][]byte
	if bufferCount <= len(w.inline) {
		bs = w.inline[:0]
	} else {
		if cap(w.cache) < bufferCount {
			w.cache = make([][]byte, 0, bufferCount)
		}
		bs = w.cache
	}
	for _, b := range mb {
		bs = append(bs, b.Bytes())
	}

	defer func() {
		for idx := range bs {
			bs[idx] = nil
		}
	}()

	nb := net.Buffers(bs)
	wc := int64(0)
	defer func() {
		if w.counter != nil {
			w.counter.Add(wc)
		}
	}()
	for size > 0 {
		n, err := nb.WriteTo(w.Writer)
		wc += n
		if err != nil {
			return err
		}
		size -= int32(n)
	}

	return nil
}

// ReadFrom implements io.ReaderFrom.
func (w *BufferToBytesWriter) ReadFrom(reader io.Reader) (int64, error) {
	var sc SizeCounter
	err := Copy(NewReader(reader), w, CountSize(&sc))
	return sc.Size, err
}

// BufferedWriter is a Writer with internal buffer.
type BufferedWriter struct {
	sync.Mutex
	writer    Writer
	buffer    *Buffer
	buffered  bool
	flushNext bool
}

// PrefixWriter keeps a short prefix inline until the first payload arrives,
// then enters synchronized pass-through mode.
type PrefixWriter struct {
	sync.Mutex
	writer    Writer
	prefix    [8]byte
	prefixLen uint8
}

// NewPrefixWriter creates a writer for protocol prefixes that do not need a
// full payload buffer while the connection is idle.
func NewPrefixWriter(writer Writer, prefix []byte) (*PrefixWriter, error) {
	if len(prefix) > len(PrefixWriter{}.prefix) {
		return nil, ErrBufferFull
	}
	prefixWriter := &PrefixWriter{writer: writer, prefixLen: uint8(len(prefix))}
	copy(prefixWriter.prefix[:], prefix)
	return prefixWriter, nil
}

// WriteMultiBuffer flushes the inline prefix with the first non-empty payload
// and takes ownership of every supplied buffer.
func (w *PrefixWriter) WriteMultiBuffer(multiBuffer MultiBuffer) error {
	if multiBuffer.IsEmpty() {
		return nil
	}
	w.Lock()
	defer w.Unlock()
	if w.prefixLen == 0 {
		return w.writer.WriteMultiBuffer(multiBuffer)
	}
	head := New()
	_, _ = head.Write(w.prefix[:w.prefixLen])
	w.prefixLen = 0
	clear(w.prefix[:])
	return writeWithHead(w.writer, head, multiBuffer)
}

// writeWithHead copies payload behind the bytes already in head, as upstream's
// BufferedWriter does with a buffered header, and hands the result to writer
// in one call. It takes ownership of head and payload.
//
// A header written in a slice of its own leaves a TLS or REALITY connection
// as a record of its own: a fixed size right after the handshake that stock
// Xray never sends. Here it shares the first record with the payload.
func writeWithHead(writer Writer, head *Buffer, payload MultiBuffer) error {
	out := MultiBuffer{head}
	for _, b := range payload {
		if b == nil {
			continue
		}
		data := b.Bytes()
		for len(data) > 0 {
			if head.IsFull() {
				head = New()
				out = append(out, head)
			}
			n, _ := head.Write(data)
			data = data[n:]
		}
		b.Release()
	}
	return writer.WriteMultiBuffer(out)
}

var _ Writer = (*PrefixWriter)(nil)

// NewBufferedWriter creates a new BufferedWriter.
func NewBufferedWriter(writer Writer) *BufferedWriter {
	return &BufferedWriter{
		writer:   writer,
		buffer:   New(),
		buffered: true,
	}
}

// NewBufferedWriterWithPrefix initializes a writer before it is shared with
// consumers. The first MultiBuffer write flushes the prefix and enters the
// regular synchronized pass-through mode.
func NewBufferedWriterWithPrefix(writer Writer, prefix []byte) (*BufferedWriter, error) {
	buffer := New()
	if _, err := buffer.Write(prefix); err != nil {
		buffer.Release()
		return nil, err
	}
	return &BufferedWriter{
		writer:    writer,
		buffer:    buffer,
		buffered:  true,
		flushNext: true,
	}, nil
}

// WriteByte implements io.ByteWriter.
func (w *BufferedWriter) WriteByte(c byte) error {
	return common.Error2(w.Write([]byte{c}))
}

// Write implements io.Writer.
func (w *BufferedWriter) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}

	w.Lock()
	defer w.Unlock()

	if !w.buffered {
		if writer, ok := w.writer.(io.Writer); ok {
			return writer.Write(b)
		}
	}

	totalBytes := 0
	for len(b) > 0 {
		if w.buffer == nil {
			w.buffer = New()
		}

		nBytes, err := w.buffer.Write(b)
		totalBytes += nBytes

		// ErrBufferFull means a partial write, so flush below and continue
		if err != nil && err != ErrBufferFull {
			return totalBytes, err
		}
		if !w.buffered || w.buffer.IsFull() {
			if err := w.flushInternal(); err != nil {
				return totalBytes, err
			}
		}
		b = b[nBytes:]
	}

	return totalBytes, nil
}

// WriteMultiBuffer implements Writer. It takes ownership of the given MultiBuffer.
func (w *BufferedWriter) WriteMultiBuffer(b MultiBuffer) error {
	if b.IsEmpty() {
		return nil
	}

	w.Lock()
	defer w.Unlock()

	if !w.buffered {
		return w.writer.WriteMultiBuffer(b)
	}
	if w.flushNext {
		w.buffered = false
		w.flushNext = false
		if w.buffer == nil || w.buffer.IsEmpty() {
			if w.buffer != nil {
				w.buffer.Release()
				w.buffer = nil
			}
			return w.writer.WriteMultiBuffer(b)
		}
		head := w.buffer
		w.buffer = nil
		return writeWithHead(w.writer, head, b)
	}

	reader := MultiBufferContainer{
		MultiBuffer: b,
	}
	defer reader.Close()

	for !reader.MultiBuffer.IsEmpty() {
		if w.buffer == nil {
			w.buffer = New()
		}
		common.Must2(w.buffer.ReadFrom(&reader))
		if w.buffer.IsFull() {
			if err := w.flushInternal(); err != nil {
				return err
			}
		}
	}

	return nil
}

// Flush flushes buffered content into underlying writer.
func (w *BufferedWriter) Flush() error {
	w.Lock()
	defer w.Unlock()

	return w.flushInternal()
}

func (w *BufferedWriter) flushInternal() error {
	if w.buffer.IsEmpty() {
		return nil
	}

	b := w.buffer
	w.buffer = nil

	if writer, ok := w.writer.(io.Writer); ok {
		err := WriteAllBytes(writer, b.Bytes(), nil)
		b.Release()
		return err
	}

	return w.writer.WriteMultiBuffer(MultiBuffer{b})
}

// SetBuffered sets whether the internal buffer is used. If set to false, Flush() will be called to clear the buffer.
func (w *BufferedWriter) SetBuffered(f bool) error {
	w.Lock()
	defer w.Unlock()

	w.buffered = f
	if !f {
		return w.flushInternal()
	}
	return nil
}

// SetFlushNext will wait the next WriteMultiBuffer to flush and set buffered = false
func (w *BufferedWriter) SetFlushNext() {
	w.Lock()
	defer w.Unlock()
	w.flushNext = true
}

// ReadFrom implements io.ReaderFrom.
func (w *BufferedWriter) ReadFrom(reader io.Reader) (int64, error) {
	if err := w.SetBuffered(false); err != nil {
		return 0, err
	}

	var sc SizeCounter
	err := Copy(NewReader(reader), w, CountSize(&sc))
	return sc.Size, err
}

// Close implements io.Closable.
func (w *BufferedWriter) Close() error {
	if err := w.Flush(); err != nil {
		return err
	}
	return common.Close(w.writer)
}

// SequentialWriter is a Writer that writes MultiBuffer sequentially into the underlying io.Writer.
type SequentialWriter struct {
	io.Writer
}

// WriteMultiBuffer implements Writer.
func (w *SequentialWriter) WriteMultiBuffer(mb MultiBuffer) error {
	mb, err := WriteMultiBuffer(w.Writer, mb)
	ReleaseMulti(mb)
	return err
}

type noOpWriter byte

func (noOpWriter) WriteMultiBuffer(b MultiBuffer) error {
	ReleaseMulti(b)
	return nil
}

func (noOpWriter) Write(b []byte) (int, error) {
	return len(b), nil
}

func (noOpWriter) ReadFrom(reader io.Reader) (int64, error) {
	b := New()
	defer b.Release()

	totalBytes := int64(0)
	for {
		b.Clear()
		_, err := b.ReadFrom(reader)
		totalBytes += int64(b.Len())
		if err != nil {
			if errors.Cause(err) == io.EOF {
				return totalBytes, nil
			}
			return totalBytes, err
		}
	}
}

var (
	// Discard is a Writer that swallows all contents written in.
	Discard Writer = noOpWriter(0)

	// DiscardBytes is an io.Writer that swallows all contents written in.
	DiscardBytes io.Writer = noOpWriter(0)
)
