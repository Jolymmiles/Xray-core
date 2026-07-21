//go:build !race

package singmux

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

func TestPaddingReadAllocationBudget(t *testing.T) {
	const payloadSize = 8 * 1024
	payload := bytes.Repeat([]byte{0x5a}, payloadSize)
	padding := bytes.Repeat([]byte{0xa5}, 32)
	encoded := make([]byte, 0, paddingFrameCount*(4+payloadSize+len(padding))+1)
	for range paddingFrameCount {
		encoded = binary.BigEndian.AppendUint16(encoded, payloadSize)
		encoded = binary.BigEndian.AppendUint16(encoded, uint16(len(padding)))
		encoded = append(encoded, payload...)
		encoded = append(encoded, padding...)
	}
	encoded = append(encoded, 0x7f)
	received := make([]byte, paddingFrameCount*payloadSize+1)

	var operationErr error
	allocations := testing.AllocsPerRun(100, func() {
		if operationErr != nil {
			return
		}
		underlying := &memoryConn{Buffer: *bytes.NewBuffer(encoded)}
		connection := newPaddingConnWithGenerator(underlying, func() int { return 0 })
		_, operationErr = io.ReadFull(connection, received)
	})
	if operationErr != nil {
		t.Fatal(operationErr)
	}
	if allocations > 2 {
		t.Fatalf("16-frame padding read allocations = %.1f, budget is 2", allocations)
	}
}
