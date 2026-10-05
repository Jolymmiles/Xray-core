package mtproxy

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func FuzzReadFakeTLSClientHello(f *testing.F) {
	payload := make([]byte, 38)
	payload[0] = 0x01
	payload[3] = 34
	payload[4], payload[5] = 0x03, 0x03
	valid := []byte{0x16, 0x03, 0x01, 0, 0}
	binary.BigEndian.PutUint16(valid[3:5], uint16(len(payload)))
	valid = append(valid, payload...)
	f.Add(valid)
	f.Add(fragmentClientHello(valid, []int{3, 1, 7, 9}))
	f.Add([]byte{0x16, 0x03, 0x01, 0, 1, 0x01})

	f.Fuzz(func(t *testing.T, wire []byte) {
		if len(wire) < 5 {
			return
		}
		var prefix [5]byte
		copy(prefix[:], wire[:5])
		_, _ = readFakeTLSClientHello(bytes.NewReader(wire[5:]), prefix)
	})
}
