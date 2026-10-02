package proxy

import (
	"bytes"
	"reflect"
	"testing"
	"unsafe"

	"github.com/xtls/xray-core/common/buf"
)

type visionBufferFixture struct {
	prefix   uint64
	rawInput bytes.Buffer
	input    bytes.Reader
}

// visionPooledBufferFixture mirrors TLS layouts synced from newer crypto/tls
// (REALITY): rawInput is a pooled buffer pointer that is nil while idle and is
// swapped while the connection reads.
type visionPooledBufferFixture struct {
	prefix     uint64
	rawInput   *bytes.Buffer
	smallInput *bytes.Buffer
	input      bytes.Reader
}

var (
	visionInputBenchmarkSink    *bytes.Reader
	visionRawInputBenchmarkSink VisionRawInput
)

func TestVisionBuffers(t *testing.T) {
	fixture := new(visionBufferFixture)
	input, rawInput, ok := VisionBuffers(fixture)
	if !ok {
		t.Fatal("matching connection layout was rejected")
	}
	if input != &fixture.input || rawInput.embedded != &fixture.rawInput || rawInput.pooled != nil {
		t.Fatalf("buffers = (%p, %+v), want (%p, embedded %p)", input, rawInput, &fixture.input, &fixture.rawInput)
	}

	inputAgain, rawInputAgain, ok := VisionBuffers(fixture)
	if !ok || inputAgain != input || rawInputAgain != rawInput {
		t.Fatal("cached lookup changed the returned fields")
	}
}

func TestVisionRawInputDrainsEmbeddedBuffer(t *testing.T) {
	fixture := new(visionBufferFixture)
	fixture.rawInput.WriteString("embedded record")
	_, rawInput, ok := VisionBuffers(fixture)
	if !ok {
		t.Fatal("matching connection layout was rejected")
	}

	drained, err := rawInput.Drain()
	if err != nil {
		t.Fatal(err)
	}
	if got := drained.String(); got != "embedded record" {
		t.Fatalf("drained %q, want the buffered record", got)
	}
	buf.ReleaseMulti(drained)
	if fixture.rawInput.Cap() != 0 {
		t.Fatalf("embedded buffer keeps %d bytes of capacity after drain", fixture.rawInput.Cap())
	}
}

func TestVisionRawInputResolvesPooledBufferWhenDrained(t *testing.T) {
	fixture := new(visionPooledBufferFixture)
	input, rawInput, ok := VisionBuffers(fixture)
	if !ok {
		t.Fatal("pooled rawInput layout was rejected")
	}
	if input != &fixture.input || rawInput.pooled != &fixture.rawInput || rawInput.embedded != nil {
		t.Fatalf("buffers = (%p, %+v), want (%p, pooled %p)", input, rawInput, &fixture.input, &fixture.rawInput)
	}

	// An idle connection has returned its buffer to the pool.
	if drained, err := rawInput.Drain(); err != nil || !drained.IsEmpty() {
		t.Fatalf("idle drain = (%v, %v), want nothing", drained, err)
	}

	// Reading swaps buffers after Vision captured the field, so the drain must
	// use the buffer the connection holds at switch time.
	fixture.smallInput = bytes.NewBufferString("stale header")
	fixture.rawInput = fixture.smallInput
	current := bytes.NewBufferString("current record")
	fixture.rawInput = current

	drained, err := rawInput.Drain()
	if err != nil {
		t.Fatal(err)
	}
	if got := drained.String(); got != "current record" {
		t.Fatalf("drained %q, want the buffer held at switch time", got)
	}
	buf.ReleaseMulti(drained)
	if fixture.rawInput != nil {
		t.Fatal("pooled buffer is still attached to the connection after drain")
	}
	if current.Len() != 0 {
		t.Fatalf("drained buffer still holds %d bytes", current.Len())
	}
}

func TestVisionRawInputZeroValueDrainsNothing(t *testing.T) {
	if drained, err := (VisionRawInput{}).Drain(); err != nil || !drained.IsEmpty() {
		t.Fatalf("zero VisionRawInput drain = (%v, %v), want nothing", drained, err)
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
		"wrong-rawInput-pointer": new(struct {
			input    bytes.Reader
			rawInput *bytes.Reader
		}),
		"double-rawInput-pointer": new(struct {
			input    bytes.Reader
			rawInput **bytes.Buffer
		}),
		"pointer-input": new(struct {
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
			visionRawInputBenchmarkSink = VisionRawInput{embedded: (*bytes.Buffer)(unsafe.Add(pointer, rawInputField.Offset))}
		}
	})
	b.Run("cached", func(b *testing.B) {
		for b.Loop() {
			visionInputBenchmarkSink, visionRawInputBenchmarkSink, _ = VisionBuffers(fixture)
		}
	})
}
