package mux

import (
	"context"
	"io"
	"runtime"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal/done"
	"github.com/xtls/xray-core/transport/pipe"
)

// Session represents a client connection in a Mux connection.
type Session struct {
	input         buf.Reader
	output        buf.Writer
	ID            uint16
	transferType  protocol.TransferType
	closed        bool
	done          *done.Instance
	XUDP          *XUDP
	ownerToken    uint64
	presenceLease session.PresenceLease
	cancel        context.CancelFunc
	ownerClose    func(uint16, uint64)
	managedClose  sync.Once
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
		if s.cancel != nil {
			s.cancel()
		}
		if s.XUDP == nil {
			if s.input != nil {
				common.Interrupt(s.input)
			}
			if s.output != nil {
				common.Close(s.output)
			}
		} else {
			// Preserve cached backend reuse until the XUDP runtime migration.
			s.input.(*pipe.Reader).ReturnAnError(io.EOF)
			runtime.Gosched()
			s.input.(*pipe.Reader).Recover()
			XUDPManager.Lock()
			if s.XUDP.Status == Active {
				s.XUDP.Expire = time.Now().Add(time.Minute)
				s.XUDP.Status = Expiring
				errors.LogDebug(context.Background(), "XUDP put ", s.XUDP.GlobalID)
			}
			XUDPManager.Unlock()
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

const (
	Initializing = 0
	Active       = 1
	Expiring     = 2
)

type XUDP struct {
	GlobalID [8]byte
	Status   uint64
	Expire   time.Time
	Mux      *Session
}

func (x *XUDP) Interrupt() {
	common.Interrupt(x.Mux.input)
	common.Close(x.Mux.output)
}

var XUDPManager struct {
	sync.Mutex
	Map map[[8]byte]*XUDP
}

func init() {
	XUDPManager.Map = make(map[[8]byte]*XUDP)
	go func() {
		for {
			time.Sleep(time.Minute)
			now := time.Now()
			XUDPManager.Lock()
			for id, x := range XUDPManager.Map {
				if x.Status == Expiring && now.After(x.Expire) {
					x.Interrupt()
					delete(XUDPManager.Map, id)
					errors.LogDebug(context.Background(), "XUDP del ", id)
				}
			}
			XUDPManager.Unlock()
		}
	}()
}
