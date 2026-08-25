package cnc

import (
	"io"
	"strings"
	"testing"
)

type closeTrackingWriter struct{ closed bool }

func (*closeTrackingWriter) Write(payload []byte) (int, error) { return len(payload), nil }
func (w *closeTrackingWriter) Close() error                    { w.closed = true; return nil }

func TestConnectionCloseWritePreservesReadSide(t *testing.T) {
	writer := &closeTrackingWriter{}
	connection := NewConnection(ConnectionInput(writer), ConnectionOutput(strings.NewReader("response")))
	defer connection.Close()
	closeWriter, ok := connection.(interface{ CloseWrite() error })
	if !ok {
		t.Fatalf("connection type %T does not support CloseWrite", connection)
	}
	if err := closeWriter.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if !writer.closed {
		t.Fatal("underlying writer was not closed")
	}
	response, err := io.ReadAll(connection)
	if err != nil || string(response) != "response" {
		t.Fatalf("response=(%q,%v)", response, err)
	}
}
