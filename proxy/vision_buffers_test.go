package proxy

import (
	"bytes"
	"reflect"
	"testing"
	"unsafe"
)

type visionBufferFixture struct {
	prefix   uint64
	rawInput bytes.Buffer
	input    bytes.Reader
}

var (
	visionInputBenchmarkSink    *bytes.Reader
	visionRawInputBenchmarkSink *bytes.Buffer
)

func TestVisionBuffers(t *testing.T) {
	fixture := new(visionBufferFixture)
	input, rawInput, ok := VisionBuffers(fixture)
	if !ok {
		t.Fatal("matching connection layout was rejected")
	}
	if input != &fixture.input || rawInput != &fixture.rawInput {
		t.Fatalf("buffers = (%p, %p), want (%p, %p)", input, rawInput, &fixture.input, &fixture.rawInput)
	}

	inputAgain, rawInputAgain, ok := VisionBuffers(fixture)
	if !ok || inputAgain != input || rawInputAgain != rawInput {
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
		"wrong-rawInput": new(struct {
			input    bytes.Reader
			rawInput bytes.Reader
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
			visionRawInputBenchmarkSink = (*bytes.Buffer)(unsafe.Add(pointer, rawInputField.Offset))
		}
	})
	b.Run("cached", func(b *testing.B) {
		for b.Loop() {
			visionInputBenchmarkSink, visionRawInputBenchmarkSink, _ = VisionBuffers(fixture)
		}
	})
}
