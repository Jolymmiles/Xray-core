// SPDX-License-Identifier: MPL-2.0

package singmux

import (
	"io"
	"sync"

	"github.com/xtls/xray-core/common/buf"
	X "github.com/xtls/xray-core/common/net"
)

type packetReader struct {
	stream io.Reader
}

func (r *packetReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	destination, payload, err := readPacket(r.stream)
	if err != nil {
		return nil, err
	}
	buffer := buf.FromBytes(payload)
	buffer.UDP = &destination
	return buf.MultiBuffer{buffer}, nil
}

type packetWriter struct {
	stream      io.Writer
	destination X.Destination
	mu          sync.Mutex
}

func (w *packetWriter) WriteMultiBuffer(buffers buf.MultiBuffer) error {
	defer buf.ReleaseMulti(buffers)
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, buffer := range buffers {
		destination := w.destination
		if buffer.UDP != nil {
			destination = *buffer.UDP
		}
		destination.Network = X.Network_UDP
		if err := writePacket(w.stream, destination, buffer.Bytes()); err != nil {
			return err
		}
	}
	return nil
}

var _ buf.Reader = (*packetReader)(nil)
var _ buf.Writer = (*packetWriter)(nil)
