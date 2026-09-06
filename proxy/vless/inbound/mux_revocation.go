package inbound

import (
	"context"
	stderrors "errors"
	"io"
	"net"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy/vless"
)

type authenticatedMuxCarrier struct {
	connection net.Conn
	cancel     context.CancelFunc
}

// registerMuxCarrier linearizes carrier admission against user removal/re-add.
// The validator retains the exact MemoryUser obtained by authentication; AddUser
// publishes a new pointer for each incarnation without retaining tombstones.
func (h *Handler) registerMuxCarrier(ctx context.Context, user *protocol.MemoryUser, connection net.Conn) (context.Context, func(), error) {
	h.userMu.Lock()
	defer h.userMu.Unlock()
	if h.usersClosed {
		return nil, nil, errors.New("VLESS inbound is closing")
	}
	var current *protocol.MemoryUser
	if user.Email == "" {
		// Static empty-email accounts are intentionally absent from the email map.
		current = h.validator.Get(user.Account.(*vless.MemoryAccount).ID.UUID())
	} else {
		current = h.validator.GetByEmail(user.Email)
	}
	if current != user {
		return nil, nil, errors.New("VLESS MUX account was removed")
	}
	ctx, cancel := context.WithCancel(ctx)
	carrier := &authenticatedMuxCarrier{connection: connection, cancel: cancel}
	if h.muxCarriers == nil {
		h.muxCarriers = make(map[*protocol.MemoryUser]map[*authenticatedMuxCarrier]struct{})
	}
	if h.muxCarriers[user] == nil {
		h.muxCarriers[user] = make(map[*authenticatedMuxCarrier]struct{})
	}
	h.muxCarriers[user][carrier] = struct{}{}
	return ctx, func() {
		cancel()
		h.userMu.Lock()
		defer h.userMu.Unlock()
		delete(h.muxCarriers[user], carrier)
		if len(h.muxCarriers[user]) == 0 {
			delete(h.muxCarriers, user)
		}
	}, nil
}

// stopMuxCarriers owns a detached set. Cancel every context before any physical
// close; a close can block while downstream work responds to cancellation.
func stopMuxCarriers(carriers map[*authenticatedMuxCarrier]struct{}) error {
	for carrier := range carriers {
		carrier.cancel()
	}
	var closeErrors []error
	for carrier := range carriers {
		if err := carrier.connection.Close(); err != nil && !stderrors.Is(err, net.ErrClosed) && !stderrors.Is(err, io.ErrClosedPipe) {
			closeErrors = append(closeErrors, err)
		}
	}
	return errors.Combine(closeErrors...)
}

func (h *Handler) closeMuxCarriers() error {
	h.userMu.Lock()
	h.usersClosed = true
	carriers := h.muxCarriers
	h.muxCarriers = nil
	h.userMu.Unlock()
	var closeErrors []error
	for _, userCarriers := range carriers {
		closeErrors = append(closeErrors, stopMuxCarriers(userCarriers))
	}
	return errors.Combine(closeErrors...)
}
