package mux

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal/done"
)

// Session represents a client connection in a Mux connection.
type Session struct {
	input         buf.Reader
	output        buf.Writer
	ID            uint16
	transferType  protocol.TransferType
	done          *done.Instance
	ownerToken    uint64
	presenceLease session.PresenceLease
	cancel        context.CancelFunc
	ownerClose    func(uint16, uint64)
	release       func()
	managedClose  sync.Once
	terminated    atomic.Bool
}

// Close closes all resources associated with this session.
func (s *Session) Close(locked bool) error {
	if s.ownerClose != nil {
		s.ownerClose(s.ID, s.ownerToken)
		return nil
	}
	s.releaseManaged()
	return nil
}

func (s *Session) releaseManaged() {
	s.managedClose.Do(func() {
		s.terminated.Store(true)
		if s.cancel != nil {
			s.cancel()
		}
		if s.release != nil {
			s.release()
		} else {
			if s.input != nil {
				common.Interrupt(s.input)
			}
			if s.output != nil {
				common.Close(s.output)
			}
		}
		if s.done != nil {
			_ = s.done.Close()
		}
		if s.presenceLease != nil {
			s.presenceLease.Close()
		}
	})
}

// NewReader creates a buf.Reader based on the transfer type of this Session.
func (s *Session) NewReader(reader *buf.BufferedReader, dest *net.Destination) buf.Reader {
	if s.transferType == protocol.TransferTypeStream {
		return NewStreamReader(reader)
	}
	return NewPacketReader(reader, dest)
}
