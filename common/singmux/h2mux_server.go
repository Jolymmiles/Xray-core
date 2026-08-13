// SPDX-License-Identifier: MPL-2.0

package singmux

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/session"
	"golang.org/x/net/http2"
)

func (c *serviceCarrier) wrapH2MuxHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if !c.beginHandler() {
			writer.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		defer c.finishHandler()
		next.ServeHTTP(writer, request)
	})
}

func (s *Service) serveH2Mux(ctx context.Context, carrier net.Conn, owner *serviceCarrier, brutal *serverBrutalController, presence session.PresenceScope) error {
	server := &http2.Server{}
	server.ServeConn(carrier, &http2.ServeConnOpts{
		Context: ctx,
		Handler: owner.wrapH2MuxHandler(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			s.handleH2MuxStream(writer, request, carrier, brutal, presence)
		})),
	})
	if err := ctx.Err(); err != nil {
		return err
	}
	return net.ErrClosed
}

func (s *Service) handleH2MuxStream(writer http.ResponseWriter, request *http.Request, carrier net.Conn, brutal *serverBrutalController, presence session.PresenceScope) {
	if request.Method != http.MethodConnect {
		http.Error(writer, "CONNECT required", http.StatusMethodNotAllowed)
		return
	}

	handshakeSlots := s.pendingHandshakeSlots()
	select {
	case handshakeSlots <- struct{}{}:
	case <-request.Context().Done():
		return
	default:
		http.Error(writer, "too many pending handshakes", http.StatusServiceUnavailable)
		return
	}

	controller := http.NewResponseController(writer)
	_ = controller.SetWriteDeadline(s.streamDeadline(request.Context()))
	writer.WriteHeader(http.StatusOK)
	if err := controller.Flush(); err != nil {
		_ = controller.SetWriteDeadline(time.Time{})
		<-handshakeSlots
		return
	}
	_ = controller.SetWriteDeadline(time.Time{})
	stream := &h2MuxServerStream{
		body:       request.Body,
		writer:     writer,
		controller: controller,
		ctx:        request.Context(),
		localAddr:  carrier.LocalAddr(),
		remoteAddr: carrier.RemoteAddr(),
	}
	s.handleStream(request.Context(), stream, handshakeSlots, brutal, presence)
}

type h2MuxServerStream struct {
	body       io.ReadCloser
	writer     http.ResponseWriter
	controller *http.ResponseController
	ctx        context.Context
	localAddr  net.Addr
	remoteAddr net.Addr
	writeMu    sync.Mutex
	closeOnce  sync.Once
}

func (s *h2MuxServerStream) Read(payload []byte) (int, error) {
	select {
	case <-s.ctx.Done():
		return 0, s.ctx.Err()
	default:
		return s.body.Read(payload)
	}
}

func (s *h2MuxServerStream) Write(payload []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	select {
	case <-s.ctx.Done():
		return 0, s.ctx.Err()
	default:
	}
	n, err := s.writer.Write(payload)
	if err != nil {
		return n, err
	}
	return n, s.controller.Flush()
}

func (s *h2MuxServerStream) Close() error {
	var err error
	s.closeOnce.Do(func() { err = s.body.Close() })
	return err
}

func (s *h2MuxServerStream) LocalAddr() net.Addr  { return s.localAddr }
func (s *h2MuxServerStream) RemoteAddr() net.Addr { return s.remoteAddr }

func (s *h2MuxServerStream) SetDeadline(deadline time.Time) error {
	return errors.Join(s.SetReadDeadline(deadline), s.SetWriteDeadline(deadline))
}

func (s *h2MuxServerStream) SetReadDeadline(deadline time.Time) error {
	return s.controller.SetReadDeadline(deadline)
}

func (s *h2MuxServerStream) SetWriteDeadline(deadline time.Time) error {
	return s.controller.SetWriteDeadline(deadline)
}
