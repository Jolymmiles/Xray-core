package proxy

import (
	"bytes"
	"reflect"
	"testing"
	"unsafe"
)

// visionBufferFixture has the layout of crypto/tls up to Go 1.27 and of uTLS:
// the connection holds its raw input buffer.
type visionBufferFixture struct {
	prefix   uint64
	rawInput bytes.Buffer
	input    bytes.Reader
}

// visionPointerBufferFixture has the layout of the REALITY server and of
// crypto/tls after Go 1.27: the connection holds a pointer to its raw input
// buffer, nil while nothing is buffered, and replaces it as it takes buffers
// from its pool.
type visionPointerBufferFixture struct {
	prefix   uint64
	rawInput *bytes.Buffer
	input    bytes.Reader
}

var (
	visionInputBenchmarkSink    *bytes.Reader
	visionRawInputBenchmarkSink **bytes.Buffer
)

func TestVisionBuffers(t *testing.T) {
	fixture := new(visionBufferFixture)
	input, rawInput, ok := VisionBuffers(fixture)
	if !ok {
		t.Fatal("matching connection layout was rejected")
	}
	if rawInput == nil {
		t.Fatal("raw input pointer is nil")
	}
	if input != &fixture.input || *rawInput != &fixture.rawInput {
		t.Fatalf("buffers = (%p, %p), want (%p, %p)", input, *rawInput, &fixture.input, &fixture.rawInput)
	}

	inputAgain, rawInputAgain, ok := VisionBuffers(fixture)
	if !ok || inputAgain != input || *rawInputAgain != *rawInput {
		t.Fatal("cached lookup changed the returned fields")
	}
}

func TestVisionBuffersFollowsRawInputPointer(t *testing.T) {
	fixture := new(visionPointerBufferFixture)
	input, rawInput, ok := VisionBuffers(fixture)
	if !ok {
		t.Fatal("connection layout with a raw input pointer was rejected")
	}
	if input != &fixture.input || rawInput != &fixture.rawInput {
		t.Fatalf("buffers = (%p, %p), want (%p, %p)", input, rawInput, &fixture.input, &fixture.rawInput)
	}
	if *rawInput != nil {
		t.Fatal("raw input of a connection without buffered input is not nil")
	}

	// Vision takes the buffers when the request arrives and reads them when it
	// switches to direct copy; in between the connection may replace the
	// buffer, so Vision has to see the one the connection holds by then.
	buffered := bytes.NewBufferString("record")
	fixture.rawInput = buffered
	if *rawInput != buffered {
		t.Fatal("raw input does not follow the buffer the connection holds")
	}

	_, rawInputAgain, ok := VisionBuffers(fixture)
	if !ok || rawInputAgain != rawInput {
		t.Fatal("cached lookup changed the returned fields")
	}
}

func TestVisionBuffersRejectsInvalidLayouts(t *testing.T) {
	for name, value := range map[string]any{
		"nil":         (*visionBufferFixture)(nil),
		"not-pointer": visionBufferFixture{},
		"missing":     new(struct{}),
		"wrong-input": new(struct{ input bytes.Buffer }),
		"promoted": new(struct {
			visionBufferFixture
		}),
		"promoted-pointer": new(struct {
			visionPointerBufferFixture
		}),
		"wrong-rawInput": new(struct {
			input    bytes.Reader
			rawInput bytes.Reader
		}),
		"wrong-rawInput-pointer": new(struct {
			input    bytes.Reader
			rawInput *bytes.Reader
		}),
		"rawInput-pointer-to-pointer": new(struct {
			input    bytes.Reader
			rawInput **bytes.Buffer
		}),
		"input-pointer": new(struct {
			input    *bytes.Reader
			rawInput *bytes.Buffer
		}),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, ok := VisionBuffers(value); ok {
				t.Fatal("invalid connection layout was accepted")
			}
		})
	}
}

func BenchmarkVisionBuffers(b *testing.B) {
	fixture := new(visionBufferFixture)
	b.Run("reflection", func(b *testing.B) {
		for b.Loop() {
			valueType := reflect.TypeOf(fixture).Elem()
			pointer := unsafe.Pointer(fixture)
			inputField, _ := valueType.FieldByName("input")
			rawInputField, _ := valueType.FieldByName("rawInput")
			visionInputBenchmarkSink = (*bytes.Reader)(unsafe.Add(pointer, inputField.Offset))
			rawInput := (*bytes.Buffer)(unsafe.Add(pointer, rawInputField.Offset))
			visionRawInputBenchmarkSink = &rawInput
		}
	})
	b.Run("cached", func(b *testing.B) {
		for b.Loop() {
			visionInputBenchmarkSink, visionRawInputBenchmarkSink, _ = VisionBuffers(fixture)
		}
	})
	pointerFixture := new(visionPointerBufferFixture)
	b.Run("cached-pointer", func(b *testing.B) {
		for b.Loop() {
			visionInputBenchmarkSink, visionRawInputBenchmarkSink, _ = VisionBuffers(pointerFixture)
		}
	})
}
