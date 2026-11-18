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
	"testing"
	"time"

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
