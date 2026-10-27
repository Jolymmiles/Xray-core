package outbound

import (
	"bytes"
	"context"
	gotls "crypto/tls"
	"encoding/binary"
	"io"
	stdnet "net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
	xraytls "github.com/xtls/xray-core/transport/internet/tls"
)

// heldReader is a plain buf.Reader, as the SOCKS, HTTP and dokodemo inbounds
// hand to an outbound when the dispatcher adds no timeout: each read returns
// what the test sends, and io.EOF once the test closes it.
type heldReader struct {
	payloads chan buf.MultiBuffer
	closed   chan struct{}
	once     sync.Once
}

func newHeldReader() *heldReader {
	return &heldReader{payloads: make(chan buf.MultiBuffer), closed: make(chan struct{})}
}

func (r *heldReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	select {
	case mb := <-r.payloads:
		return mb, nil
	case <-r.closed:
		return nil, io.EOF
	}
}

func (r *heldReader) send(payload []byte) {
	r.payloads <- buf.MultiBuffer{buf.FromBytes(append([]byte(nil), payload...))}
}

func (r *heldReader) close() { r.once.Do(func() { close(r.closed) }) }

// peer is the server end of the connection the outbound dials: it collects
// every byte the outbound writes, decrypted when the carrier is TLS.
type peer struct {
	mu       sync.Mutex
	received []byte
	done     chan struct{}
}

func (p *peer) bytes() []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]byte(nil), p.received...)
}

func startPeer(conn stdnet.Conn) *peer {
	p := &peer{done: make(chan struct{})}
	go func() {
		defer close(p.done)
		chunk := make([]byte, 32*1024)
		for {
			n, err := conn.Read(chunk)
			p.mu.Lock()
			p.received = append(p.received, chunk[:n]...)
			p.mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	return p
}

type pipeDialer struct{ conn stat.Connection }

func (d pipeDialer) Dial(context.Context, net.Destination) (stat.Connection, error) {
	return d.conn, nil
}

func (pipeDialer) DestIpAddress() net.IP { return nil }

func (pipeDialer) SetOutboundGateway(context.Context, *session.Outbound) {}

func newFlowHandler(t *testing.T, v *core.Instance, id uuid.UUID, flow string) *Handler {
	t.Helper()
	ctx := context.WithValue(context.Background(), core.XrayKey(1), v)
	ctx = context.WithValue(ctx, "cone", true)
	h, err := New(ctx, &Config{Vnext: &protocol.ServerEndpoint{
		Address: net.NewIPOrDomain(net.LocalHostIP),
		Port:    443,
		User: &protocol.User{Account: serial.ToTypedMessage(&vless.Account{
			Id:   id.String(),
			Flow: flow,
		})},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

type firstPayloadFixture struct {
	reader    *heldReader
	peer      *peer
	processed chan error
	closeConn func()
}

// startFirstPayloadRequest runs one TCP request through the VLESS outbound
// over a pipe. With tlsCarrier the outbound dials TLS 1.3, which Vision
// requires, and the peer reads the plaintext.
// The instance comes from outside the bubble, as in the testpre tests.
func startFirstPayloadRequest(t *testing.T, v *core.Instance, flow string, tlsCarrier bool, wrap func(buf.Reader) buf.Reader) (*firstPayloadFixture, uuid.UUID) {
	t.Helper()
	id := uuid.New()
	h := newFlowHandler(t, v, id, flow)

	clientEnd, serverEnd := stdnet.Pipe()
	var outboundConn stat.Connection = clientEnd
	var peerConn stdnet.Conn = serverEnd
	if tlsCarrier {
		generated, _ := cert.MustGenerate(nil, cert.DNSNames("example.com"))
		certificate, err := gotls.X509KeyPair(generated.ToPEM())
		if err != nil {
			t.Fatal(err)
		}
		outboundConn = xraytls.Client(clientEnd, &gotls.Config{ServerName: "example.com", InsecureSkipVerify: true})
		peerConn = gotls.Server(serverEnd, &gotls.Config{Certificates: []gotls.Certificate{certificate}})
	}

	reader := newHeldReader()
	f := &firstPayloadFixture{
		reader:    reader,
		peer:      startPeer(peerConn),
		processed: make(chan error, 1),
		closeConn: func() { _ = serverEnd.Close(); _ = clientEnd.Close() },
	}
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
		Target: net.TCPDestination(net.DomainAddress("example.com"), 443),
	}})
	link := &transport.Link{Reader: wrap(reader), Writer: buf.Discard}
	go func() { f.processed <- h.Process(ctx, link, pipeDialer{conn: outboundConn}) }()
	return f, id
}

// finish ends the request and waits for Process and the peer to return.
func (f *firstPayloadFixture) finish(t *testing.T) {
	t.Helper()
	f.reader.close()
	f.closeConn()
	<-f.processed
	<-f.peer.done
}

func plainReader(r buf.Reader) buf.Reader { return r }

func wrappedReader(r buf.Reader) buf.Reader { return &buf.TimeoutWrapperReader{Reader: r} }

// The VLESS header waits for the first payload even when the link reader has
// no timeout, so that the two leave in one write, as they do when sniffing
// gives the reader one.
func TestHeaderWaitsForFirstPayloadWithoutTimeoutReader(t *testing.T) {
	v := newTestpreInstance(t)
	synctest.Test(t, func(t *testing.T) {
		f, _ := startFirstPayloadRequest(t, v, "", false, plainReader)
		defer f.finish(t)

		synctest.Wait()
		if got := f.peer.bytes(); len(got) != 0 {
			t.Fatalf("the outbound sent %d header bytes before the first payload and before 500 ms", len(got))
		}

		payload := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
		f.reader.send(payload)
		synctest.Wait()
		got := f.peer.bytes()
		if len(got) <= len(payload) || !bytes.HasSuffix(got, payload) {
			t.Fatalf("the peer got %d bytes %x, want the header followed by the %d-byte payload", len(got), got, len(payload))
		}
	})
}

// A first payload that comes after the 500 ms wait is read through the
// reader that waited for it, so no byte is lost.
func TestFirstPayloadAfterWaitArrives(t *testing.T) {
	for _, test := range []struct {
		name string
		wrap func(buf.Reader) buf.Reader
	}{
		{name: "plain reader", wrap: plainReader},
		{name: "timeout reader", wrap: wrappedReader},
	} {
		t.Run(test.name, func(t *testing.T) {
			v := newTestpreInstance(t)
			synctest.Test(t, func(t *testing.T) {
				f, _ := startFirstPayloadRequest(t, v, "", false, test.wrap)
				defer f.finish(t)

				time.Sleep(time.Second)
				synctest.Wait()
				header := f.peer.bytes()
				if len(header) == 0 {
					t.Fatal("the outbound did not send the header after the 500 ms wait")
				}

				payload := []byte("late first payload")
				f.reader.send(payload)
				synctest.Wait()
				want := append(header, payload...)
				if got := f.peer.bytes(); !bytes.Equal(got, want) {
					t.Fatalf("the peer got %x, want the header and then the payload %x", got, want)
				}
			})
		})
	}
}

// When no first payload comes within 500 ms, Vision follows the header with
// a padding block, whatever reader the dispatcher handed over.
func TestVisionPadsHeaderWithoutFirstPayload(t *testing.T) {
	for _, test := range []struct {
		name string
		wrap func(buf.Reader) buf.Reader
	}{
		{name: "plain reader", wrap: plainReader},
		{name: "timeout reader", wrap: wrappedReader},
	} {
		t.Run(test.name, func(t *testing.T) {
			v := newTestpreInstance(t)
			synctest.Test(t, func(t *testing.T) {
				f, id := startFirstPayloadRequest(t, v, vless.XRV, true, test.wrap)
				defer f.finish(t)

				time.Sleep(time.Second)
				synctest.Wait()
				got := f.peer.bytes()
				// The header carries the UUID at offset 1; the first Vision
				// padding block starts with it as well.
				userID := id.Bytes()
				if len(got) < 17 || !bytes.Equal(got[1:17], userID) {
					t.Fatalf("the peer got %x, want a VLESS header", got)
				}
				block := bytes.Index(got[17:], userID)
				if block < 0 {
					t.Fatalf("the peer got the %d-byte header and no Vision padding block", len(got))
				}
				block += 17
				if len(got) < block+21 {
					t.Fatalf("the Vision padding block is cut short: %x", got[block:])
				}
				command := got[block+16]
				contentLength := binary.BigEndian.Uint16(got[block+17:])
				paddingLength := binary.BigEndian.Uint16(got[block+19:])
				if command != proxy.CommandPaddingContinue || contentLength != 0 || paddingLength == 0 {
					t.Fatalf("Vision block command %d, content %d, padding %d; want an empty padding-only block", command, contentLength, paddingLength)
				}
				if want := block + 21 + int(paddingLength); len(got) != want {
					t.Fatalf("the peer got %d bytes, want %d: header, then one padding block", len(got), want)
				}
			})
		})
	}
}

// A client that half-closes right after CONNECT still gets its request sent:
// the header goes out, and the response direction stays open.
func TestHeaderSentWhenClientEndsBeforeFirstPayload(t *testing.T) {
	for _, test := range []struct {
		name string
		wrap func(buf.Reader) buf.Reader
	}{
		{name: "plain reader", wrap: plainReader},
		{name: "timeout reader", wrap: wrappedReader},
	} {
		t.Run(test.name, func(t *testing.T) {
			v := newTestpreInstance(t)
			synctest.Test(t, func(t *testing.T) {
				f, id := startFirstPayloadRequest(t, v, "", false, test.wrap)
				defer f.finish(t)

				f.reader.close()
				synctest.Wait()
				select {
				case err := <-f.processed:
					f.processed <- err
					t.Fatalf("Process returned %v before the response, want it to wait for one", err)
				default:
				}
				got := f.peer.bytes()
				if len(got) < 17 || !bytes.Equal(got[1:17], id.Bytes()) {
					t.Fatalf("the peer got %x, want the VLESS header", got)
				}
			})
		})
	}
}

// lastPayloadReader returns its payload together with io.EOF, as a reader
// does that meets the end of the request in the same read.
type lastPayloadReader struct{ payload []byte }

func (r *lastPayloadReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if r.payload == nil {
		return nil, io.EOF
	}
	mb := buf.MultiBuffer{buf.FromBytes(r.payload)}
	r.payload = nil
	return mb, io.EOF
}

// A first payload that comes with io.EOF is sent after the header.
func TestFirstPayloadWithEOFArrives(t *testing.T) {
	payload := []byte("payload and the end of the request")
	for _, test := range []struct {
		name string
		wrap func(buf.Reader) buf.Reader
	}{
		{name: "plain reader", wrap: func(buf.Reader) buf.Reader {
			return &lastPayloadReader{payload: append([]byte(nil), payload...)}
		}},
		{name: "timeout reader", wrap: func(buf.Reader) buf.Reader {
			return wrappedReader(&lastPayloadReader{payload: append([]byte(nil), payload...)})
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			v := newTestpreInstance(t)
			synctest.Test(t, func(t *testing.T) {
				f, id := startFirstPayloadRequest(t, v, "", false, test.wrap)
				defer f.finish(t)

				synctest.Wait()
				got := f.peer.bytes()
				if len(got) < 17 || !bytes.Equal(got[1:17], id.Bytes()) || !bytes.HasSuffix(got, payload) {
					t.Fatalf("the peer got %x, want the VLESS header followed by %x", got, payload)
				}
			})
		})
	}
}
