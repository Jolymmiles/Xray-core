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

const (
	// H2MuxFrameSizeMin and H2MuxFrameSizeMax bound the HTTP/2
	// SETTINGS_MAX_FRAME_SIZE range defined by RFC 9113 section 6.5.2.
	H2MuxFrameSizeMin uint32 = 1 << 14
	H2MuxFrameSizeMax uint32 = 1<<24 - 1
)

// H2MuxOptions controls the per-inbound H2MUX carrier settings.
type H2MuxOptions struct {
	// MaxReadFrameSize is advertised as SETTINGS_MAX_FRAME_SIZE, which sizes
	// the per-stream upload buffer of Go clients. Zero keeps the
	// golang.org/x/net/http2 default of 1 MiB.
	MaxReadFrameSize uint32
}

type serverH2MuxOptionsKey struct{}

// ContextWithServerH2MuxOptions attaches immutable per-inbound H2MUX settings
// to an accepted carrier context. SMUX carriers are unaffected by them.
func ContextWithServerH2MuxOptions(ctx context.Context, options H2MuxOptions) context.Context {
	return context.WithValue(ctx, serverH2MuxOptionsKey{}, options)
}

// serverH2MuxOptions reads the carrier options, dropping a frame size outside
// the protocol range so that a carrier keeps the library default instead of
// letting http2 clamp a value config validation should already have rejected.
func serverH2MuxOptions(ctx context.Context) H2MuxOptions {
	options, _ := ctx.Value(serverH2MuxOptionsKey{}).(H2MuxOptions)
	if options.MaxReadFrameSize != 0 &&
		(options.MaxReadFrameSize < H2MuxFrameSizeMin || options.MaxReadFrameSize > H2MuxFrameSizeMax) {
		options.MaxReadFrameSize = 0
	}
	return options
}

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
	server := &http2.Server{
		MaxReadFrameSize: serverH2MuxOptions(ctx).MaxReadFrameSize,
	}
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
	closed     bool
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
	if s.closed {
		return 0, net.ErrClosed
	}
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
	s.closeOnce.Do(func() {
		s.writeMu.Lock()
		s.closed = true
		s.writeMu.Unlock()
		err = s.body.Close()
	})
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
