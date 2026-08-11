package singmux

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"
	"unicode/utf8"

	X "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func TestServerBrutalNegotiatesBoundedRate(t *testing.T) {
	physicalClient, physicalServer := net.Pipe()
	defer physicalClient.Close()
	defer physicalServer.Close()
	applied := make(chan struct {
		conn net.Conn
		rate uint64
	}, 1)
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{Conn: physicalServer})
	ctx = ContextWithServerBrutalOptions(ctx, BrutalOptions{
		Enabled: true, SendBPS: 100_000_000, ReceiveBPS: 125_000_000,
	})
	controller := newServerBrutalController(ctx, func(conn net.Conn, rate uint64) error {
		applied <- struct {
			conn net.Conn
			rate uint64
		}{conn: conn, rate: rate}
		return nil
	})

	client, server := net.Pipe()
	defer client.Close()
	result := make(chan struct {
		closeCarrier bool
		err          error
	}, 1)
	go func() {
		closeCarrier, err := controller.handle(ctx, server, time.Now().Add(time.Second))
		result <- struct {
			closeCarrier bool
			err          error
		}{closeCarrier: closeCarrier, err: err}
	}()
	if err := writeBrutalRequest(client, 80_000_000); err != nil {
		t.Fatal(err)
	}
	gotReceive, err := readBrutalResponse(client)
	if err != nil {
		t.Fatal(err)
	}
	if gotReceive != 125_000_000 {
		t.Fatalf("server receive = %d, want 125000000", gotReceive)
	}
	gotApplied := <-applied
	if gotApplied.conn != physicalServer {
		t.Fatalf("physical connection = %T, want server pipe", gotApplied.conn)
	}
	if gotApplied.rate != 80_000_000 {
		t.Fatalf("applied rate = %d, want 80000000", gotApplied.rate)
	}
	gotResult := <-result
	if gotResult.closeCarrier || gotResult.err != nil {
		t.Fatalf("handle result = close %v, error %v", gotResult.closeCarrier, gotResult.err)
	}
}

func TestServerBrutalRejectsBeforeSocketControl(t *testing.T) {
	tests := []struct {
		name          string
		options       BrutalOptions
		clientReceive uint64
		withPhysical  bool
	}{
		{
			name:          "disabled",
			clientReceive: 80_000_000,
			withPhysical:  true,
		},
		{
			name:          "client receive below minimum",
			options:       BrutalOptions{Enabled: true, SendBPS: 100_000_000, ReceiveBPS: 125_000_000},
			clientReceive: BrutalMinSpeedBPS - 1,
			withPhysical:  true,
		},
		{
			name:          "missing physical connection",
			options:       BrutalOptions{Enabled: true, SendBPS: 100_000_000, ReceiveBPS: 125_000_000},
			clientReceive: 80_000_000,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			if test.withPhysical {
				physicalClient, physicalServer := net.Pipe()
				defer physicalClient.Close()
				defer physicalServer.Close()
				ctx = session.ContextWithInbound(ctx, &session.Inbound{Conn: physicalServer})
			}
			ctx = ContextWithServerBrutalOptions(ctx, test.options)
			called := make(chan struct{}, 1)
			controller := newServerBrutalController(ctx, func(net.Conn, uint64) error {
				called <- struct{}{}
				return nil
			})
			client, server := net.Pipe()
			defer client.Close()
			result := make(chan bool, 1)
			go func() {
				closeCarrier, _ := controller.handle(ctx, server, time.Now().Add(time.Second))
				result <- closeCarrier
			}()
			if err := writeBrutalRequest(client, test.clientReceive); err != nil {
				t.Fatal(err)
			}
			if _, err := readBrutalResponse(client); err == nil {
				t.Fatal("expected a negative Brutal response")
			}
			if <-result {
				t.Fatal("carrier must remain open before socket control")
			}
			select {
			case <-called:
				t.Fatal("socket control was called")
			default:
			}
		})
	}
}

func TestServerBrutalRejectsDuplicate(t *testing.T) {
	physicalClient, physicalServer := net.Pipe()
	defer physicalClient.Close()
	defer physicalServer.Close()
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{Conn: physicalServer})
	ctx = ContextWithServerBrutalOptions(ctx, BrutalOptions{
		Enabled: true, SendBPS: 100_000_000, ReceiveBPS: 125_000_000,
	})
	called := 0
	controller := newServerBrutalController(ctx, func(net.Conn, uint64) error {
		called++
		return nil
	})
	for attempt := 0; attempt < 2; attempt++ {
		client, server := net.Pipe()
		result := make(chan bool, 1)
		go func() {
			closeCarrier, _ := controller.handle(ctx, server, time.Now().Add(time.Second))
			result <- closeCarrier
		}()
		if err := writeBrutalRequest(client, 80_000_000); err != nil {
			t.Fatal(err)
		}
		_, err := readBrutalResponse(client)
		if attempt == 0 && err != nil {
			t.Fatalf("first exchange failed: %v", err)
		}
		if attempt == 1 && err == nil {
			t.Fatal("duplicate exchange succeeded")
		}
		if <-result {
			t.Fatal("duplicate exchange must not close carrier")
		}
		_ = client.Close()
	}
	if called != 1 {
		t.Fatalf("socket control calls = %d, want 1", called)
	}
}

func TestServerBrutalClosesCarrierAfterSocketControlFailure(t *testing.T) {
	physicalClient, physicalServer := net.Pipe()
	defer physicalClient.Close()
	defer physicalServer.Close()
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{Conn: physicalServer})
	ctx = ContextWithServerBrutalOptions(ctx, BrutalOptions{
		Enabled: true, SendBPS: 100_000_000, ReceiveBPS: 125_000_000,
	})
	controller := newServerBrutalController(ctx, func(net.Conn, uint64) error {
		return errors.New("socket control failed")
	})
	client, server := net.Pipe()
	result := make(chan bool, 1)
	go func() {
		closeCarrier, _ := controller.handle(ctx, server, time.Now().Add(time.Second))
		result <- closeCarrier
	}()
	if err := writeBrutalRequest(client, 80_000_000); err != nil {
		t.Fatal(err)
	}
	if _, err := readBrutalResponse(client); err == nil {
		t.Fatal("expected socket control failure response")
	}
	if !<-result {
		t.Fatal("socket control failure must close carrier")
	}
}

func TestServerBrutalClosesCarrierWhenSuccessResponseFails(t *testing.T) {
	physicalClient, physicalServer := net.Pipe()
	defer physicalClient.Close()
	defer physicalServer.Close()
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{Conn: physicalServer})
	ctx = ContextWithServerBrutalOptions(ctx, BrutalOptions{
		Enabled: true, SendBPS: 100_000_000, ReceiveBPS: 125_000_000,
	})
	controller := newServerBrutalController(ctx, func(net.Conn, uint64) error { return nil })
	client, server := net.Pipe()
	result := make(chan bool, 1)
	go func() {
		closeCarrier, _ := controller.handle(ctx, server, time.Now().Add(time.Second))
		result <- closeCarrier
	}()
	if err := writeBrutalRequest(client, 80_000_000); err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	if !<-result {
		t.Fatal("success response failure must close carrier")
	}
}

func TestServerBrutalDestinationIsReservedCaseInsensitively(t *testing.T) {
	tests := []struct {
		name        string
		destination X.Destination
		want        bool
	}{
		{name: "tcp control", destination: X.TCPDestination(X.DomainAddress(brutalExchangeDomain), 0), want: true},
		{name: "mixed case", destination: X.TCPDestination(X.DomainAddress("_bRuTaLbWeXcHaNgE"), 0), want: true},
		{name: "udp is reserved", destination: X.UDPDestination(X.DomainAddress(brutalExchangeDomain), 0), want: true},
		{name: "nonzero port is reserved", destination: X.TCPDestination(X.DomainAddress(brutalExchangeDomain), 1), want: true},
		{name: "other domain", destination: X.TCPDestination(X.DomainAddress("example.com"), 0)},
		{name: "ip", destination: X.TCPDestination(X.LocalHostIP, 0)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := isBrutalDestination(test.destination); got != test.want {
				t.Fatalf("isBrutalDestination() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestBrutalRequestRoundTripFragmented(t *testing.T) {
	var encoded bytes.Buffer
	const want uint64 = 123456789
	if err := writeBrutalRequest(&encoded, want); err != nil {
		t.Fatal(err)
	}
	if got := encoded.Bytes(); !bytes.Equal(got, []byte{0, 0, 0, 0, 7, 91, 205, 21}) {
		t.Fatalf("request bytes = %x", got)
	}
	value, err := readBrutalRequest(&fragmentedReader{data: encoded.Bytes(), max: 1})
	if err != nil {
		t.Fatal(err)
	}
	if value != want {
		t.Fatalf("request value = %d, want %d", value, want)
	}
}

func TestBrutalCodecRejectsShortData(t *testing.T) {
	if _, err := readBrutalRequest(bytes.NewReader(make([]byte, 7))); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("short request error = %v", err)
	}
	if _, err := readBrutalResponse(bytes.NewReader([]byte{1})); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("short response error = %v", err)
	}
}

func TestBrutalResponseRoundTripAndDiagnosticLimit(t *testing.T) {
	var success bytes.Buffer
	if err := writeBrutalResponse(&success, 987654321, true, ""); err != nil {
		t.Fatal(err)
	}
	if got, err := readBrutalResponse(&fragmentedReader{data: success.Bytes(), max: 2}); err != nil || got != 987654321 {
		t.Fatalf("success response = %d, %v", got, err)
	}

	message := bytes.Repeat([]byte("x"), maxDiagnosticBytes+1)
	var failure bytes.Buffer
	if err := writeBrutalResponse(&failure, 0, false, string(message)); err != nil {
		t.Fatal(err)
	}
	var encodedLength []byte
	encodedLength = binary.AppendUvarint(encodedLength, maxDiagnosticBytes)
	if failure.Len() != 1+len(encodedLength)+maxDiagnosticBytes {
		t.Fatalf("encoded diagnostic length = %d, want %d", failure.Len(), 1+len(encodedLength)+maxDiagnosticBytes)
	}
	if _, err := readBrutalResponse(bytes.NewReader(append([]byte{0}, append([]byte{0x80, 0x80, 0x04}, make([]byte, 0)...)...))); err == nil {
		t.Fatal("oversized diagnostic must be rejected")
	}
}

func TestBrutalSuccessResponseGolden(t *testing.T) {
	var encoded bytes.Buffer
	if err := writeBrutalResponse(&encoded, 0x0102030405060708, true, ""); err != nil {
		t.Fatal(err)
	}
	want := []byte{1, 1, 2, 3, 4, 5, 6, 7, 8}
	if !bytes.Equal(encoded.Bytes(), want) {
		t.Fatalf("response bytes = %x, want %x", encoded.Bytes(), want)
	}
}

func TestBrutalResponseRejectsInvalidUTF8(t *testing.T) {
	encoded := []byte{0, 1, 0xff}
	if _, err := readBrutalResponse(bytes.NewReader(encoded)); err == nil || !strings.Contains(err.Error(), "UTF-8") {
		t.Fatalf("invalid diagnostic error = %v", err)
	}
}

func TestBrutalResponseWriterSanitizesAndTruncatesRunes(t *testing.T) {
	var sanitized bytes.Buffer
	if err := writeBrutalResponse(&sanitized, 0, false, string([]byte{0xff})); err != nil {
		t.Fatal(err)
	}
	if _, err := readBrutalResponse(bytes.NewReader(sanitized.Bytes())); err == nil {
		t.Fatal("sanitized diagnostic should be encoded as a valid error response")
	}
	length, err := readUvarint(bytes.NewReader(sanitized.Bytes()[1:]))
	if err != nil {
		t.Fatal(err)
	}
	if length != uint64(len([]byte("�"))) {
		t.Fatalf("sanitized length = %d", length)
	}

	message := strings.Repeat("a", maxDiagnosticBytes-2) + "€"
	var truncated bytes.Buffer
	if err := writeBrutalResponse(&truncated, 0, false, message); err != nil {
		t.Fatal(err)
	}
	encoded := truncated.Bytes()
	length, err = readUvarint(bytes.NewReader(encoded[1:]))
	if err != nil {
		t.Fatal(err)
	}
	if length > maxDiagnosticBytes {
		t.Fatalf("diagnostic length = %d, exceeds limit", length)
	}
	var offset int
	for offset < len(encoded[1:]) && encoded[1+offset]&0x80 != 0 {
		offset++
	}
	offset++
	payload := encoded[1+offset:]
	if len(payload) != maxDiagnosticBytes-2 || !utf8.Valid(payload) {
		t.Fatalf("truncated payload length/UTF-8 = %d/%v", len(payload), utf8.Valid(payload))
	}
}

func TestUnwrapBrutalConnThroughKnownWrappers(t *testing.T) {
	base := &brutalSyscallConn{}
	wrapped := &brutalRawWrapper{Conn: &brutalNetWrapper{Conn: &stat.CounterConnection{Connection: base}}}
	got, err := unwrapBrutalConn(wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if got != base {
		t.Fatalf("unwrapped conn = %T, want base", got)
	}
}

func TestUnwrapBrutalConnStopsAtBound(t *testing.T) {
	conn := net.Conn(&brutalNetWrapper{})
	for i := 0; i < maxBrutalUnwrapDepth+1; i++ {
		conn = &brutalNetWrapper{Conn: conn}
	}
	if _, err := unwrapBrutalConn(conn); err == nil {
		t.Fatal("unwrap must stop at the bounded depth")
	}
}

type fragmentedReader struct {
	data []byte
	max  int
}

func (r *fragmentedReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	if len(p) > r.max {
		p = p[:r.max]
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

type brutalNetWrapper struct{ net.Conn }

func (c *brutalNetWrapper) NetConn() net.Conn { return c.Conn }

type brutalRawWrapper struct{ net.Conn }

func (c *brutalRawWrapper) RawConn() net.Conn { return c.Conn }

type brutalSyscallConn struct{}

func (c *brutalSyscallConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *brutalSyscallConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *brutalSyscallConn) Close() error                     { return nil }
func (c *brutalSyscallConn) LocalAddr() net.Addr              { return nil }
func (c *brutalSyscallConn) RemoteAddr() net.Addr             { return nil }
func (c *brutalSyscallConn) SetDeadline(time.Time) error      { return nil }
func (c *brutalSyscallConn) SetReadDeadline(time.Time) error  { return nil }
func (c *brutalSyscallConn) SetWriteDeadline(time.Time) error { return nil }
func (c *brutalSyscallConn) SyscallConn() (syscall.RawConn, error) {
	return nil, errors.New("not used")
}
