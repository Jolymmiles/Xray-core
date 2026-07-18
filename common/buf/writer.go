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
	return w.writeMultiBuffer(nil, mb)
}

// WriteMultiBufferWithPrefix writes an owned prefix and MultiBuffer without
// first allocating a combined MultiBuffer slice.
func (w *BufferToBytesWriter) WriteMultiBufferWithPrefix(prefix *Buffer, mb MultiBuffer) error {
	defer prefix.Release()
	defer ReleaseMulti(mb)
	return w.writeMultiBuffer(prefix, mb)
}

func (w *BufferToBytesWriter) writeMultiBuffer(prefix *Buffer, mb MultiBuffer) error {
	size := mb.Len()
	if prefix != nil {
		size += prefix.Len()
	}
	if size == 0 {
		return nil
	}

	if prefix == nil && len(mb) == 1 {
		return WriteAllBytes(w.Writer, mb[0].Bytes(), w.counter)
	}
	if prefix != nil && len(mb) == 0 {
		return WriteAllBytes(w.Writer, prefix.Bytes(), w.counter)
	}

	bufferCount := len(mb)
	if prefix != nil {
		bufferCount++
	}
	var bs [][]byte
	if bufferCount <= len(w.inline) {
		bs = w.inline[:0]
	} else {
		if cap(w.cache) < bufferCount {
			w.cache = make([][]byte, 0, bufferCount)
		}
		bs = w.cache
	}
	if prefix != nil {
		bs = append(bs, prefix.Bytes())
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
	pooled    bool
}

var bufferedWriterPool sync.Pool

type prefixMultiBufferWriter interface {
	WriteMultiBufferWithPrefix(prefix *Buffer, mb MultiBuffer) error
}

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

// NewPooledBufferedWriterWithPrefix returns a writer whose lifetime must end
// with Release after all consumers have stopped using it.
func NewPooledBufferedWriterWithPrefix(writer Writer, prefix []byte) (*BufferedWriter, error) {
	buffer := New()
	if _, err := buffer.Write(prefix); err != nil {
		buffer.Release()
		return nil, err
	}
	bufferedWriter, _ := bufferedWriterPool.Get().(*BufferedWriter)
	if bufferedWriter == nil {
		bufferedWriter = new(BufferedWriter)
	}
	bufferedWriter.writer = writer
	bufferedWriter.buffer = buffer
	bufferedWriter.buffered = true
	bufferedWriter.flushNext = true
	bufferedWriter.pooled = true
	return bufferedWriter, nil
}

// Release discards any unflushed prefix, clears connection references, and
// returns a pooled writer for reuse. It is a no-op for non-pooled writers.
func (w *BufferedWriter) Release() {
	if w == nil || !w.pooled {
		return
	}
	w.Lock()
	if w.buffer != nil {
		w.buffer.Release()
	}
	w.writer = nil
	w.buffer = nil
	w.buffered = false
	w.flushNext = false
	w.pooled = false
	w.Unlock()
	bufferedWriterPool.Put(w)
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
		if err != nil {
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
		if writer, ok := w.writer.(prefixMultiBufferWriter); ok {
			prefix := w.buffer
			w.buffer = nil
			return writer.WriteMultiBufferWithPrefix(prefix, b)
		}

		combined := make(MultiBuffer, len(b)+1)
		combined[0] = w.buffer
		copy(combined[1:], b)
		w.buffer = nil
		return w.writer.WriteMultiBuffer(combined)
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

// WriteMultiBufferWithPrefix writes the owned prefix before the owned payload
// without allocating a temporary combined MultiBuffer slice.
func (w *SequentialWriter) WriteMultiBufferWithPrefix(prefix *Buffer, mb MultiBuffer) error {
	if err := WriteAllBytes(w.Writer, prefix.Bytes(), nil); err != nil {
		prefix.Release()
		ReleaseMulti(mb)
		return err
	}
	prefix.Release()
	return w.WriteMultiBuffer(mb)
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
