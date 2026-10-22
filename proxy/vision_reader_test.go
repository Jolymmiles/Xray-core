package proxy

import (
	"bytes"
	"context"
	"io"
	stdnet "net"
	"testing"

	"github.com/xtls/xray-core/common/buf"
)

// visionFrameReader returns one multi-buffer, then io.EOF.
type visionFrameReader struct {
	mb buf.MultiBuffer
}

func (r *visionFrameReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if r.mb == nil {
		return nil, io.EOF
	}
	mb := r.mb
	r.mb = nil
	return mb, nil
}

// readVisionSwitch reads one Vision block that tells the reader to switch to
// direct copy and returns what the reader delivered.
func readVisionSwitch(t *testing.T, input *bytes.Reader, rawInput **bytes.Buffer) string {
	t.Helper()
	userUUID := []byte("0123456789abcdef")
	payload := buf.New()
	payload.WriteString("payload ")
	writeOnceUUID := append([]byte(nil), userUUID...)
	frame := XtlsPadding(payload, CommandPaddingDirect, &writeOnceUUID, false, context.Background(), []uint32{900, 500, 900, 256})

	connection, peer := stdnet.Pipe()
	t.Cleanup(func() {
		_ = connection.Close()
		_ = peer.Close()
	})
	trafficState := NewTrafficState(userUUID)
	reader := NewVisionReader(&visionFrameReader{mb: buf.MultiBuffer{frame}}, trafficState, true, context.Background(), connection, input, rawInput, nil)
	mb, err := reader.ReadMultiBuffer()
	if err != nil {
		t.Fatal(err)
	}
	defer buf.ReleaseMulti(mb)
	if !trafficState.Inbound.UplinkReaderDirectCopy {
		t.Fatal("Vision did not switch to direct copy")
	}
	return mb.String()
}

func TestVisionReaderSwitchTakesBufferedTLSInput(t *testing.T) {
	t.Run("buffer", func(t *testing.T) {
		connection := new(visionBufferFixture)
		input, rawInput, ok := VisionBuffers(connection)
		if !ok {
			t.Fatal("connection layout was rejected")
		}
		connection.input.Reset([]byte("input "))
		connection.rawInput.WriteString("raw")

		if got := readVisionSwitch(t, input, rawInput); got != "payload input raw" {
			t.Fatalf("delivered %q, want %q", got, "payload input raw")
		}
		if connection.rawInput.Len() != 0 {
			t.Fatalf("%d raw input bytes were left in the connection", connection.rawInput.Len())
		}
	})

	t.Run("pointer", func(t *testing.T) {
		connection := new(visionPointerBufferFixture)
		input, rawInput, ok := VisionBuffers(connection)
		if !ok {
			t.Fatal("connection layout was rejected")
		}
		// The connection takes its buffer after Vision took the buffers, as a
		// connection does when it takes one from its pool for the next record.
		connection.input.Reset([]byte("input "))
		buffered := bytes.NewBufferString("raw")
		connection.rawInput = buffered

		if got := readVisionSwitch(t, input, rawInput); got != "payload input raw" {
			t.Fatalf("delivered %q, want %q", got, "payload input raw")
		}
		if connection.rawInput != buffered {
			t.Fatal("Vision replaced the raw input buffer of the connection")
		}
		if buffered.Len() != 0 {
			t.Fatalf("%d raw input bytes were left in the connection", buffered.Len())
		}
	})

	t.Run("pointer-nothing-buffered", func(t *testing.T) {
		connection := new(visionPointerBufferFixture)
		input, rawInput, ok := VisionBuffers(connection)
		if !ok {
			t.Fatal("connection layout was rejected")
		}
		connection.input.Reset([]byte("input"))

		if got := readVisionSwitch(t, input, rawInput); got != "payload input" {
			t.Fatalf("delivered %q, want %q", got, "payload input")
		}
		if connection.rawInput != nil {
			t.Fatal("Vision gave the connection a raw input buffer")
		}
	})
}
