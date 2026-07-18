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
	valid    bool
}

var visionBufferOffsetsByType sync.Map

// VisionBuffers returns the TLS input buffers used by Vision's direct-copy
// transition. The concrete TLS implementations keep these fields private, so
// their checked offsets are resolved once per concrete pointer type.
func VisionBuffers(connection any) (*bytes.Reader, *bytes.Buffer, bool) {
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
	rawInput := (*bytes.Buffer)(unsafe.Add(base, offsets.rawInput))
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
			input.Type == reflect.TypeOf(bytes.Reader{}) &&
			rawInput.Type == reflect.TypeOf(bytes.Buffer{}),
	}
	if offsets.valid {
		offsets.input = input.Offset
		offsets.rawInput = rawInput.Offset
	}
	actual, _ := visionBufferOffsetsByType.LoadOrStore(pointerType, offsets)
	return actual.(visionBufferOffsets)
}
