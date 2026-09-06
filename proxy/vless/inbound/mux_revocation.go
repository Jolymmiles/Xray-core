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

// beginUserOperation serializes control-plane mutation through cleanup completion.
// The single live channel is completion ownership, not a retained user tombstone.
// Carrier registration/unregistration only needs userMu and remains independent.
func (h *Handler) beginUserOperation() func() {
	for {
		h.userMu.Lock()
		pending := h.userOperation
		if pending == nil {
			done := make(chan struct{})
			h.userOperation = done
			h.userMu.Unlock()
			return func() {
				h.userMu.Lock()
				h.userOperation = nil
				close(done)
				h.userMu.Unlock()
			}
		}
		h.userMu.Unlock()
		<-pending
	}
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
		if err := filterMuxCloseError(carrier.connection.Close()); err != nil {
			closeErrors = append(closeErrors, err)
		}
	}
	return stderrors.Join(closeErrors...)
}

// Preserve wrapper diagnostics while exposing only abnormal children to Is/As.
type filteredMuxCloseError struct {
	error
	cause error
}

func (e filteredMuxCloseError) Unwrap() error { return e.cause }

func filterMuxCloseError(err error) error {
	if err == nil {
		return nil
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		var abnormal []error
		for _, child := range joined.Unwrap() {
			if child = filterMuxCloseError(child); child != nil {
				abnormal = append(abnormal, child)
			}
		}
		return stderrors.Join(abnormal...)
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		// An Xray Error with no inner error is still an abnormal leaf.
		if child := wrapped.Unwrap(); child != nil {
			filtered := filterMuxCloseError(child)
			if filtered == nil {
				return nil
			}
			return filteredMuxCloseError{error: err, cause: filtered}
		}
	}
	if stderrors.Is(err, net.ErrClosed) || stderrors.Is(err, io.ErrClosedPipe) {
		return nil
	}
	return err
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
	return stderrors.Join(closeErrors...)
}
