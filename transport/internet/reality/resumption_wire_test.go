package reality

import (
	"context"
	gotls "crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	gonet "net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/xtls/reality"
	"github.com/xtls/xray-core/common/net"
)

// wireRecord is a TLS record as an observer sees it.
type wireRecord struct {
	typ  byte
	body []byte
}

// readRecords reads what peer sends until it stops for wait or closes. Any
// other read error, or a record cut short, fails the test.
func readRecords(t *testing.T, peer gonet.Conn, wait time.Duration) []wireRecord {
	t.Helper()
	var in []byte
	buf := make([]byte, 16<<10)
	for {
		if err := peer.SetReadDeadline(time.Now().Add(wait)); err != nil {
			t.Fatal(err)
		}
		n, err := peer.Read(buf)
		in = append(in, buf[:n]...)
		if err == nil {
			continue
		}
		var timeout gonet.Error
		if !errors.Is(err, io.EOF) && (!errors.As(err, &timeout) || !timeout.Timeout()) {
			t.Fatalf("reading the answer: %v", err)
		}
		break
	}
	var records []wireRecord
	for len(in) >= 5 {
		n := 5 + int(binary.BigEndian.Uint16(in[3:5]))
		if n > len(in) {
			break
		}
		records = append(records, wireRecord{typ: in[0], body: in[5:n]})
		in = in[n:]
	}
	if len(in) != 0 {
		t.Fatalf("the answer ends with %d bytes of an incomplete record", len(in))
	}
	return records
}

// serverHelloExtensions returns the extension types of a ServerHello record.
func serverHelloExtensions(t *testing.T, record wireRecord) []uint16 {
	t.Helper()
	b := record.body
	if record.typ != 22 || len(b) < 4+2+32+1 || b[0] != 2 {
		t.Fatalf("not a ServerHello: type %d, % x", record.typ, b[:min(len(b), 8)])
	}
	p := 4 + 2 + 32
	p += 1 + int(b[p]) + 2 + 1 // session id, cipher suite, compression
	if p+2 > len(b) {
		t.Fatalf("short ServerHello: % x", b)
	}
	end := p + 2 + int(binary.BigEndian.Uint16(b[p:]))
	if end != len(b) {
		t.Fatalf("ServerHello extensions end at %d of %d bytes", end, len(b))
	}
	var types []uint16
	for p += 2; p < end; {
		if p+4 > end || p+4+int(binary.BigEndian.Uint16(b[p+2:])) > end {
			t.Fatalf("malformed ServerHello extension at %d: % x", p, b)
		}
		types = append(types, binary.BigEndian.Uint16(b[p:]))
		p += 4 + int(binary.BigEndian.Uint16(b[p+2:]))
	}
	return types
}

// answer sends hello to addr and returns the records that come back.
func answer(t *testing.T, addr string, hello []byte) []wireRecord {
	t.Helper()
	conn, err := gonet.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write(hello); err != nil {
		t.Fatal(err)
	}
	return readRecords(t, conn, time.Second)
}

// dialResumedHello resumes a REALITY connection and returns the ClientHello
// record it sent.
func dialResumedHello(t *testing.T, server *realityServer) []byte {
	t.Helper()
	dialReality(t, server, "auto")
	raw, err := gonet.Dial("tcp", server.addr)
	if err != nil {
		t.Fatal(err)
	}
	capture := &recordCapture{Conn: raw}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := UClient(capture, &Config{
		Fingerprint: "chrome", ServerName: testServerName, PublicKey: server.public,
		ShortId: make([]byte, 8), SpiderY: make([]int64, 10), Browser: "auto",
	}, ctx, serverDestination(server))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if !conn.(*UConn).ConnectionState().DidResume {
		t.Fatal("the connection did not resume")
	}
	sent := capture.sent()
	return sent[:5+int(binary.BigEndian.Uint16(sent[3:5]))]
}

func serverDestination(server *realityServer) net.Destination {
	host, portStr, _ := gonet.SplitHostPort(server.addr)
	port, _ := strconv.Atoi(portStr)
	return net.TCPDestination(net.ParseAddress(host), net.Port(port))
}

// A censor that replays a resumed ClientHello it saw gets what the target
// answers to those bytes, a full handshake, and not a second resumption.
func TestReplayedResumedHelloReachesTheTarget(t *testing.T) {
	target := goTarget(t)
	server := startRealityServer(t, target)
	hello := dialResumedHello(t, server)

	replayed, direct := answer(t, server.addr, hello), answer(t, target, hello)
	if len(replayed) == 0 || len(direct) == 0 {
		t.Fatalf("no answer: replayed %d records, target %d", len(replayed), len(direct))
	}
	got, want := serverHelloExtensions(t, replayed[0]), serverHelloExtensions(t, direct[0])
	if slices.Contains(got, 41) || !slices.Equal(got, want) {
		t.Fatalf("replayed hello: ServerHello extensions %v, the target's %v", got, want)
	}
	if len(replayed) != len(direct) {
		t.Fatalf("replayed hello: %d records, the target's %d", len(replayed), len(direct))
	}
}

// unsentTicketHello returns the ClientHello record a client offering one of
// server's tickets builds, without the server seeing it: a hello this
// process never authenticated, as a censor's recorded copy is until the
// censor sends it. The failed dial puts no ticket aside.
func unsentTicketHello(t *testing.T, server *realityServer) []byte {
	t.Helper()
	client, peer := gonet.Pipe()
	sent := make(chan []byte, 1)
	go func() {
		defer peer.Close()
		header := make([]byte, 5)
		if _, err := io.ReadFull(peer, header); err != nil {
			sent <- nil
			return
		}
		body := make([]byte, binary.BigEndian.Uint16(header[3:]))
		if _, err := io.ReadFull(peer, body); err != nil {
			sent <- nil
			return
		}
		sent <- slices.Concat(header, body)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := UClient(client, &Config{
		Fingerprint: "chrome", ServerName: testServerName, PublicKey: server.public,
		ShortId: make([]byte, 8), SpiderY: make([]int64, 10), Browser: "auto",
	}, ctx, serverDestination(server)); err == nil {
		t.Fatal("a handshake with no server succeeded")
	}
	tickets.Lock()
	delete(tickets.failed, testTicketKey(server))
	tickets.Unlock()
	hello := <-sent
	if len(hello) == 0 {
		t.Fatal("the client sent no ClientHello")
	}
	return hello
}

// The target's ticket profile can stop placing a ticket this process
// issued: the profile is probed or unknown for the hello's key, as here,
// or a new probe found a new prefix. The tickets are this process's, as
// ticket keys are per process, so the test covers tickets issued and
// offered within one process, not tickets from before a restart. A
// censor's copy of a resumed ClientHello with a spoiled binder must not
// authenticate then either: it goes to the target, as when the target's
// refusal is not measured, and gets the target's own answer. A hello with
// a valid binder still authenticates, once, and a client's own ticket
// still works.
func TestSpoiledBinderReachesTheTargetWhileTheProfileIsProbed(t *testing.T) {
	target := goTarget(t)
	results := make(chan error, 8)
	server := startRealityServer(t, target, func(conn gonet.Conn, config *reality.Config) (*reality.Conn, error) {
		client, err := reality.Server(context.Background(), conn, config)
		results <- err
		return client, err
	})
	// Three tickets: for the spoiled hello, for the replayed valid one, and
	// for the client after them.
	key := testTicketKey(server)
	var held []*utls.ClientSessionState
	for range 3 {
		dialReality(t, server, "auto")
		if err := <-results; err != nil {
			t.Fatalf("an honest connection failed: %v", err)
		}
		session := tickets.pop(key)
		if session == nil {
			t.Fatal("the target's tickets were not issued")
		}
		held = append(held, session)
	}
	record := func(session *utls.ClientSessionState) []byte {
		t.Helper()
		tickets.push(key, session)
		hello := unsentTicketHello(t, server)
		if !slices.Contains((&recordCapture{out: hello}).helloExtensions(), 41) {
			t.Fatal("the recorded hello offers no ticket, so the test shows nothing")
		}
		return hello
	}
	spoiled, valid := record(held[0]), record(held[1])
	spoiled[len(spoiled)-1] ^= 1
	served := func(hello []byte) ([]wireRecord, error) {
		t.Helper()
		records := answer(t, server.addr, hello)
		select {
		case err := <-results:
			return records, err
		case <-time.After(10 * time.Second):
			t.Fatal("the server did not finish with the recorded hello")
			return nil, nil
		}
	}
	const refused = "authentication failed or validation criteria not met"

	profile := target + " " + testServerName + " 2"
	original, _ := reality.GlobalTicketShapes.Load(profile)
	reality.GlobalTicketShapes.Store(profile, false) // a probe is running: no profile places the ticket
	t.Cleanup(func() { reality.GlobalTicketShapes.Store(profile, original) })

	records, err := served(spoiled)
	if err == nil || !strings.Contains(err.Error(), refused) {
		t.Fatalf("a spoiled binder was authenticated while the profile is probed (%d records): %v", len(records), err)
	}
	direct := answer(t, target, spoiled)
	if len(records) == 0 || len(direct) == 0 {
		t.Fatalf("no answer: REALITY %d records, the target %d", len(records), len(direct))
	}
	got, want := serverHelloExtensions(t, records[0]), serverHelloExtensions(t, direct[0])
	if len(records) != len(direct) || !slices.Equal(got, want) {
		t.Fatalf("the spoiled hello got %d records with ServerHello extensions %v, the target answers %d with %v",
			len(records), got, len(direct), want)
	}

	// The valid binder authenticates and reserves the hello: its copy goes
	// to the target.
	if _, err := served(valid); err != nil && strings.Contains(err.Error(), refused) {
		t.Fatalf("a valid binder was not authenticated while the profile is probed: %v", err)
	}
	if _, err := served(valid); err == nil || !strings.Contains(err.Error(), refused) {
		t.Fatalf("a copy of a hello with a valid binder was authenticated again: %v", err)
	}

	tickets.push(key, held[2])
	c := dialReality(t, server, "auto")
	if !slices.Contains(c.hello, 41) {
		t.Fatal("the client offered no ticket, so the test shows nothing")
	}
	if err := <-results; err != nil {
		t.Fatalf("a client's own ticket did not authenticate while the profile is probed: %v", err)
	}
}

// A target whose resumed ServerHello grows by more than pre_shared_key has
// a resumed handshake REALITY cannot reproduce: it answers with a full one.
func TestNoResumptionWhenTheServerHelloDeltaIsUnknown(t *testing.T) {
	target := goTarget(t)
	server := startRealityServer(t, target)
	key := target + " " + testServerName + " 2"
	original := reality.LoadTicketShape(key)
	if original == nil || !original.Resumes || original.HelloDelta != 6 {
		t.Fatalf("unexpected target profile %+v", original)
	}
	dialReality(t, server, "auto")
	shape := *original
	shape.HelloDelta = 10
	reality.GlobalTicketShapes.Store(key, &shape)
	t.Cleanup(func() { reality.GlobalTicketShapes.Store(key, original) })
	c := dialReality(t, server, "auto")
	if !slices.Contains(c.hello, 41) {
		t.Fatal("the client offered no ticket, so the test shows nothing")
	}
	if c.conn.ConnectionState().DidResume {
		t.Fatalf("resumed with a ServerHello delta of %d: records %v", shape.HelloDelta, c.records)
	}
}

// crypto/tls sends its ticket with a full flight. A target that sends none
// after a resumed handshake gets no ticket record in REALITY's resumed flight.
func TestResumedFlightDropsTheFullFlightTicket(t *testing.T) {
	target := goTarget(t)
	server := startRealityServer(t, target)
	key := target + " " + testServerName + " 2"
	original := reality.LoadTicketShape(key)
	if original == nil || !original.Resumes || original.ResTickets != 1 || len(original.ResRecords) != 3 {
		t.Fatalf("unexpected target profile %+v", original)
	}
	dialReality(t, server, "auto")
	shape := *original
	shape.ResTickets, shape.ResRecords = 0, original.ResRecords[:2]
	reality.GlobalTicketShapes.Store(key, &shape)
	t.Cleanup(func() { reality.GlobalTicketShapes.Store(key, original) })
	c := dialReality(t, server, "auto")
	if !c.conn.ConnectionState().DidResume {
		t.Fatal("the connection did not resume")
	}
	// ServerHello, ChangeCipherSpec, EncryptedExtensions, Finished, echo.
	if len(c.records) != 5 || c.records[3] != shape.ResRecords[1] {
		t.Fatalf("resumed records %v, want the flight %v without a ticket", c.records, shape.ResRecords)
	}
}

// h2Target is a crypto/tls site that speaks HTTP/2.
func h2Target(t *testing.T) string {
	t.Helper()
	certPEM, keyPEM := testCertificate(t)
	cert, err := gotls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	target.EnableHTTP2 = true
	target.TLS = &gotls.Config{Certificates: []gotls.Certificate{cert}}
	target.StartTLS()
	t.Cleanup(target.Close)
	return target.Listener.Addr().String()
}

// While the ticket profile is unknown REALITY writes the target's legacy
// records after the handshake, so XHTTP must not shape the HTTP/2 startup
// on top of them.
func TestNoH2StartupWithoutTicketProfile(t *testing.T) {
	target := h2Target(t)
	startup := make(chan []reality.H2StartupRecord, 1)
	server := startRealityServer(t, target, func(conn gonet.Conn, config *reality.Config) (*reality.Conn, error) {
		client, err := reality.Server(context.Background(), conn, config)
		if err == nil {
			startup <- client.H2StartupRecords()
		}
		return client, err
	})
	server.config.AppRecords = true
	key := target + " " + testServerName + " 2"
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(200 * time.Millisecond) {
		dialReality(t, server, "auto")
		if len(<-startup) != 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the target's HTTP/2 startup was not measured")
		}
	}
	original, _ := reality.GlobalTicketShapes.Load(key)
	reality.GlobalTicketShapes.Store(key, false) // a probe is running
	t.Cleanup(func() { reality.GlobalTicketShapes.Store(key, original) })
	dialReality(t, server, "auto")
	if records := <-startup; len(records) != 0 {
		t.Fatalf("HTTP/2 startup %+v shaped with the legacy records", records)
	}
}

// nginxLikeH2Target serves TLS with HTTP/2's greeting grouped as nginx groups
// it: one record of SETTINGS, WINDOW_UPDATE and the ACK when the client's
// preface already waits after the handshake, else SETTINGS and
// WINDOW_UPDATE first and the ACK once the preface comes.
func nginxLikeH2Target(t *testing.T) string {
	t.Helper()
	certPEM, keyPEM := testCertificate(t)
	cert, err := gotls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := gotls.Listen("tcp", "127.0.0.1:0", &gotls.Config{
		Certificates: []gotls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	settings := []byte{0, 0, 12, 4, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 128, 0, 4, 0, 1, 0, 0}
	window := []byte{0, 0, 4, 8, 0, 0, 0, 0, 0, 0, 0xef, 0, 1}
	ack := []byte{0, 0, 0, 4, 1, 0, 0, 0, 0}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				tlsConn := conn.(*gotls.Conn)
				tlsConn.SetDeadline(time.Now().Add(10 * time.Second))
				if err := tlsConn.Handshake(); err != nil || tlsConn.ConnectionState().NegotiatedProtocol != "h2" {
					io.Copy(io.Discard, tlsConn)
					return
				}
				buf := make([]byte, 16<<10)
				tlsConn.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
				if n, _ := tlsConn.Read(buf); n > 0 {
					tlsConn.Write(slices.Concat(settings, window, ack))
				} else {
					tlsConn.Write(slices.Concat(settings, window))
					tlsConn.SetReadDeadline(time.Now().Add(5 * time.Second))
					if n, _ := tlsConn.Read(buf); n == 0 {
						return
					}
					tlsConn.Write(ack)
				}
				tlsConn.SetReadDeadline(time.Now().Add(5 * time.Second))
				io.Copy(io.Discard, tlsConn)
			}()
		}
	}()
	return ln.Addr().String()
}

// heldWrites holds everything written after the ClientHello until flush,
// so the client's Finished and first data reach the server in one write.
type heldWrites struct {
	gonet.Conn
	mu     sync.Mutex
	writes int
	held   []byte
}

func (c *heldWrites) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes++
	if c.writes == 1 {
		return c.Conn.Write(b)
	}
	c.held = append(c.held, b...)
	return len(b), nil
}

func (c *heldWrites) flush() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, err := c.Conn.Write(c.held)
	c.held = nil
	return err
}

// A full Chromium handshake gets the grouping the target gives the same
// arrival: with the client's first data in the write of its Finished the
// combined record, after a pause SETTINGS first.
func TestH2StartupFollowsTheClientsArrival(t *testing.T) {
	target := nginxLikeH2Target(t)
	startup := make(chan []reality.H2StartupRecord, 1)
	server := startRealityServer(t, target, func(conn gonet.Conn, config *reality.Config) (*reality.Conn, error) {
		client, err := reality.Server(context.Background(), conn, config)
		if err == nil {
			startup <- client.H2StartupRecords()
		}
		return client, err
	})
	server.config.AppRecords = true
	ticketsKey := testTicketKey(server)
	dial := func(pipelined bool) []reality.H2StartupRecord {
		t.Helper()
		tickets.clear(ticketsKey) // a full handshake
		raw, err := gonet.Dial("tcp", server.addr)
		if err != nil {
			t.Fatal(err)
		}
		held := &heldWrites{Conn: raw}
		var conn gonet.Conn = raw
		if pipelined {
			conn = held
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		client, err := UClient(conn, &Config{
			Fingerprint: "chrome", ServerName: testServerName, PublicKey: server.public,
			ShortId: make([]byte, 8), SpiderY: make([]int64, 10), Browser: "auto",
		}, ctx, serverDestination(server))
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		if !pipelined {
			time.Sleep(100 * time.Millisecond)
		}
		if _, err := client.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")); err != nil {
			t.Fatal(err)
		}
		if pipelined {
			if err := held.flush(); err != nil {
				t.Fatal(err)
			}
		}
		select {
		case records := <-startup:
			return records
		case <-time.After(10 * time.Second):
			t.Fatal("the server did not finish the handshake")
			return nil
		}
	}
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(200 * time.Millisecond) {
		if records := dial(false); len(records) == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the target's HTTP/2 startup was not measured")
		}
	}
	if records := dial(true); len(records) != 1 || len(records[0].Frames) != 3 {
		t.Fatalf("client data waiting: startup %+v, want the combined record", records)
	}
	if records := dial(false); len(records) != 2 || len(records[0].Frames) != 2 {
		t.Fatalf("nothing waiting: startup %+v, want SETTINGS first", records)
	}
}

// writeTimes records when each write reached the socket.
type writeTimes struct {
	gonet.Conn
	mu    sync.Mutex
	times []time.Time
}

func (c *writeTimes) Write(b []byte) (int, error) {
	c.mu.Lock()
	c.times = append(c.times, time.Now())
	c.mu.Unlock()
	return c.Conn.Write(b)
}

// In browser mode Chrome's first application data trails its Finished by
// at least 250 µs; without browser mode nothing waits.
func TestFirstDataGapOnTheWire(t *testing.T) {
	server := startRealityServer(t, goTarget(t))
	gap := func(browser string) (time.Duration, *UConn) {
		t.Helper()
		raw, err := gonet.Dial("tcp", server.addr)
		if err != nil {
			t.Fatal(err)
		}
		times := &writeTimes{Conn: raw}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := UClient(times, &Config{
			Fingerprint: "chrome", ServerName: testServerName, PublicKey: server.public,
			ShortId: make([]byte, 8), SpiderY: make([]int64, 10), Browser: browser,
		}, ctx, serverDestination(server))
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		times.mu.Lock()
		handshakeWrites := len(times.times)
		times.mu.Unlock()
		if _, err := conn.Write([]byte("ping")); err != nil {
			t.Fatal(err)
		}
		times.mu.Lock()
		defer times.mu.Unlock()
		if len(times.times) != handshakeWrites+1 {
			t.Fatalf("%d writes, want the handshake's %d and one", len(times.times), handshakeWrites)
		}
		return times.times[handshakeWrites].Sub(times.times[handshakeWrites-1]), conn.(*UConn)
	}
	for range 3 {
		if d, _ := gap("auto"); d < 250*time.Microsecond {
			t.Fatalf("browser mode: first data %v after Finished, want at least 250µs", d)
		}
	}
	// Without browser mode nothing waits; the gap is the scheduler's alone
	// and has no bound worth checking.
	d, conn := gap("")
	if !conn.firstData.IsZero() {
		t.Fatalf("without browser mode the first data was scheduled, %v after Finished", d)
	}
	t.Logf("without browser mode the first data went %v after Finished", d)
}
