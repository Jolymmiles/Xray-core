package proxy

import (
	"bytes"
	"reflect"
	"runtime"
	"sync"
	"unsafe"

	"github.com/xtls/xray-core/common/buf"
)

type visionBufferOffsets struct {
	input           uintptr
	rawInput        uintptr
	rawInputPointer bool
	valid           bool
}

var visionBufferOffsetsByType sync.Map

var (
	visionInputType          = reflect.TypeOf(bytes.Reader{})
	visionRawInputType       = reflect.TypeOf(bytes.Buffer{})
	visionPooledRawInputType = reflect.TypeOf((*bytes.Buffer)(nil))
)

// VisionRawInput locates a TLS connection's buffered raw input. Older TLS
// layouts embed the buffer in the connection. Layouts synced from newer
// crypto/tls (REALITY) keep a pooled buffer pointer that is nil while idle and
// is swapped while the connection reads, so that field is only dereferenced
// when Vision drains it.
type VisionRawInput struct {
	embedded *bytes.Buffer
	pooled   **bytes.Buffer
}

// Drain moves the buffered raw input out of the connection and releases the
// connection's buffer. Vision calls it once, when it stops reading through the
// TLS connection.
func (r VisionRawInput) Drain() (buf.MultiBuffer, error) {
	buffer := r.embedded
	if r.pooled != nil {
		buffer = *r.pooled
	}
	if buffer == nil {
		return nil, nil
	}
	drained, err := buf.ReadFrom(buffer)
	if r.pooled != nil {
		// The connection takes a fresh buffer if it ever reads again.
		*r.pooled = nil
	} else {
		*buffer = bytes.Buffer{} // release memory
	}
	return drained, err
}

// VisionBuffers returns the TLS input buffers used by Vision's direct-copy
// transition. The concrete TLS implementations keep these fields private, so
// their checked offsets are resolved once per concrete pointer type.
func VisionBuffers(connection any) (*bytes.Reader, VisionRawInput, bool) {
	value := reflect.ValueOf(connection)
	if !value.IsValid() || value.Kind() != reflect.Pointer || value.IsNil() || value.Type().Elem().Kind() != reflect.Struct {
		return nil, VisionRawInput{}, false
	}

	offsets := loadVisionBufferOffsets(value.Type())
	if !offsets.valid {
		return nil, VisionRawInput{}, false
	}
	base := value.UnsafePointer()
	input := (*bytes.Reader)(unsafe.Add(base, offsets.input))
	var rawInput VisionRawInput
	if offsets.rawInputPointer {
		rawInput.pooled = (**bytes.Buffer)(unsafe.Add(base, offsets.rawInput))
	} else {
		rawInput.embedded = (*bytes.Buffer)(unsafe.Add(base, offsets.rawInput))
	}
	runtime.KeepAlive(connection)
	return input, rawInput, true
}

func loadVisionBufferOffsets(pointerType reflect.Type) visionBufferOffsets {
	if cached, ok := visionBufferOffsetsByType.Load(pointerType); ok {
		return cached.(visionBufferOffsets)
	}

	structType := pointerType.Elem()
	input, inputFound := structType.FieldByName("input")
	rawInput, rawInputFound := structType.FieldByName("rawInput")
	rawInputPointer := rawInputFound && rawInput.Type == visionPooledRawInputType
	offsets := visionBufferOffsets{
		rawInputPointer: rawInputPointer,
		valid: inputFound && rawInputFound &&
			len(input.Index) == 1 && len(rawInput.Index) == 1 &&
			input.Type == visionInputType &&
			(rawInput.Type == visionRawInputType || rawInputPointer),
	}
	if offsets.valid {
		offsets.input = input.Offset
		offsets.rawInput = rawInput.Offset
	}
	actual, _ := visionBufferOffsetsByType.LoadOrStore(pointerType, offsets)
	return actual.(visionBufferOffsets)
}
