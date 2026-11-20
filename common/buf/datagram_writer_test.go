//go:build unix || windows

package buf_test

import (
	"bytes"
	"errors"
	stdnet "net"
	"os"
	"syscall"
	"testing"

	. "github.com/xtls/xray-core/common/buf"
)

// refusingWriter stands for a UDP socket: it refuses each datagram whose first
// byte has an error in refuse, and records the first byte of the others.
type refusingWriter struct {
	refuse map[byte]error
	sent   []byte
}

func (w *refusingWriter) Write(p []byte) (int, error) {
	if err := w.refuse[p[0]]; err != nil {
		return 0, err
	}
	w.sent = append(w.sent, p[0])
	return len(p), nil
}

// DatagramWriter drops a datagram the socket refuses as too long and writes
// the rest of the MultiBuffer; any other error ends the write.
func TestDatagramWriterDropsDatagramsTheSocketRefusesAsTooLong(t *testing.T) {
	tooLong := &stdnet.OpError{Op: "write", Net: "udp", Err: os.NewSyscallError("sendto", syscall.EMSGSIZE)}
	socket := &refusingWriter{refuse: map[byte]error{2: tooLong, 4: stdnet.ErrClosed}}
	writer := &DatagramWriter{Writer: socket}
	datagrams := func(ids ...byte) MultiBuffer {
		mb := make(MultiBuffer, len(ids))
		for i, id := range ids {
			mb[i] = FromBytes([]byte{id, 0, 0})
		}
		return mb
	}
	if err := writer.WriteMultiBuffer(datagrams(1, 2, 3)); err != nil {
		t.Fatalf("WriteMultiBuffer() = %v, want the refused datagram dropped", err)
	}
	if !bytes.Equal(socket.sent, []byte{1, 3}) {
		t.Fatalf("the socket sent datagrams %v, want 1 and 3", socket.sent)
	}
	if err := writer.WriteMultiBuffer(datagrams(4, 5)); !errors.Is(err, stdnet.ErrClosed) {
		t.Fatalf("WriteMultiBuffer() = %v, want the error of the closed socket", err)
	}
	if !bytes.Equal(socket.sent, []byte{1, 3}) {
		t.Fatalf("the socket sent datagrams %v after its error, want none", socket.sent[2:])
	}
}
