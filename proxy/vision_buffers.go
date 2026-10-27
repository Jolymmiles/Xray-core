package proxy

import (
	"bytes"
	"reflect"
	"runtime"
	"sync"
	"unsafe"
)

type visionBufferOffsets struct {
	input    uintptr
	rawInput uintptr
	// rawInputPointer is true where the connection holds a pointer to its raw
	// input buffer rather than the buffer itself.
	rawInputPointer bool
	valid           bool
}

var (
	visionBufferOffsetsByType sync.Map

	visionInputType           = reflect.TypeFor[bytes.Reader]()
	visionRawInputType        = reflect.TypeFor[bytes.Buffer]()
	visionRawInputPointerType = reflect.TypeFor[*bytes.Buffer]()
)

// VisionBuffers returns the TLS input buffers used by Vision's direct-copy
// transition. The concrete TLS implementations keep these fields private, so
// their checked offsets are resolved once per concrete pointer type.
//
// rawInput points at what the connection holds as its raw input buffer when
// Vision reads it. crypto/tls up to Go 1.27 and uTLS hold the buffer itself;
// the REALITY server, like crypto/tls after Go 1.27, holds a pointer to it,
// nil while no input is buffered and replaced as the connection takes buffers
// from its pool, so rawInput then points at that field.
func VisionBuffers(connection any) (*bytes.Reader, **bytes.Buffer, bool) {
	value := reflect.ValueOf(connection)
	if !value.IsValid() || value.Kind() != reflect.Pointer || value.IsNil() || value.Type().Elem().Kind() != reflect.Struct {
		return nil, nil, false
	}

	offsets := loadVisionBufferOffsets(value.Type())
	if !offsets.valid {
		return nil, nil, false
	}
	base := value.UnsafePointer()
	input := (*bytes.Reader)(unsafe.Add(base, offsets.input))
	var rawInput **bytes.Buffer
	if offsets.rawInputPointer {
		rawInput = (**bytes.Buffer)(unsafe.Add(base, offsets.rawInput))
	} else {
		buffer := (*bytes.Buffer)(unsafe.Add(base, offsets.rawInput))
		rawInput = &buffer
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
	offsets := visionBufferOffsets{
		valid: inputFound && rawInputFound &&
			len(input.Index) == 1 && len(rawInput.Index) == 1 &&
			input.Type == visionInputType &&
			(rawInput.Type == visionRawInputType || rawInput.Type == visionRawInputPointerType),
	}
	if offsets.valid {
		offsets.input = input.Offset
		offsets.rawInput = rawInput.Offset
		offsets.rawInputPointer = rawInput.Type == visionRawInputPointerType
	}
	actual, _ := visionBufferOffsetsByType.LoadOrStore(pointerType, offsets)
	return actual.(visionBufferOffsets)
}
