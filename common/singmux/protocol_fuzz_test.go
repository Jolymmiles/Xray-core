package singmux

import (
	"bytes"
	"io"
	"testing"
)

func FuzzProtocolDecoders(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{carrierVersionPlain, protocolSMUX})
	f.Add([]byte{carrierVersionPadded, protocolSMUX, 1, 0, 3, 1, 2, 3})
	f.Add([]byte{0, 0, addressDomain, 3, 'a', '.', 'b', 0, 80})
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = readCarrierRequest(bytes.NewReader(input))
		_, _, _ = readStreamRequest(bytes.NewReader(input))
		_ = readStreamResponse(bytes.NewReader(input))
		_, _ = readDestination(bytes.NewReader(input))
		_, _, _ = readPacket(bytes.NewReader(input))
		_, _ = readUvarint(bytes.NewReader(input))
	})
}

func FuzzPaddingDecoder(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 3, 0, 1, 'a', 'b', 'c', 0})
	f.Add([]byte{0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, input []byte) {
		underlying := &memoryConn{}
		_, _ = underlying.Write(input)
		conn := newPaddingConnWithGenerator(underlying, func() int { return 0 })
		_, _ = io.Copy(io.Discard, conn)
	})
}
