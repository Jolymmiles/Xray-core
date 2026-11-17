package reality

import (
	"bytes"
	"context"
	gotls "crypto/tls"
	"io"
	"net"
	"reflect"
	"testing"
	"time"
)

func h2ProbeListener(t *testing.T) net.Listener {
	t.Helper()
	certPEM, keyPEM := testCertificate(t, "example.com")
	cert, err := gotls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := gotls.Listen("tcp", "127.0.0.1:0", &gotls.Config{
		Certificates: []gotls.Certificate{cert},
		NextProtos:   []string{"h2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	return listener
}

func TestProbeH2ReadsStartupAfterClientPreface(t *testing.T) {
	listener := h2ProbeListener(t)
	serverErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		const preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
		request := make([]byte, len(preface)+9)
		if _, err := io.ReadFull(conn, request); err != nil {
			serverErr <- err
			return
		}
		if !bytes.Equal(request[:len(preface)], []byte(preface)) || request[len(preface)+3] != 4 {
			serverErr <- io.ErrUnexpectedEOF
			return
		}
		// As in the HAProxy capture, SETTINGS and its acknowledgement
		// share one TLS record, after the target sees the client's preface.
		settings := []byte{0, 0, 18, 4, 0, 0, 0, 0, 0,
			0, 8, 0, 0, 0, 1, 0, 4, 0, 1, 0, 0, 0, 3, 0, 0, 0, 100}
		ack := []byte{0, 0, 0, 4, 1, 0, 0, 0, 0}
		_, err = conn.Write(append(settings, ack...))
		serverErr <- err
	}()
	records := probeH2Startup(&Config{Type: "tcp", Dest: listener.Addr().String()}, "example.com", 0, nil, nil).records
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
	want := []H2StartupRecord{{Length: 58, Frames: []H2StartupFrame{H2Settings, H2SettingsAck}}}
	if !reflect.DeepEqual(records, want) {
		t.Fatalf("startup records %+v, want %+v", records, want)
	}
}

func TestMeasureH2StartupProbesResumedConnections(t *testing.T) {
	listener := h2ProbeListener(t)
	serverErr := make(chan error, 4)
	settings := []byte{0, 0, 0, 4, 0, 0, 0, 0, 0}
	ack := []byte{0, 0, 0, 4, 1, 0, 0, 0, 0}
	go func() {
		for range 4 {
			conn, err := listener.Accept()
			if err != nil {
				serverErr <- err
				return
			}
			go func(conn *gotls.Conn) {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				var preface [33]byte
				if _, err := io.ReadFull(conn, preface[:]); err != nil {
					serverErr <- err
					return
				}
				if conn.ConnectionState().DidResume {
					_, err := conn.Write(append(bytes.Clone(settings), ack...))
					serverErr <- err
					return
				}
				if _, err := conn.Write(settings); err != nil {
					serverErr <- err
					return
				}
				_, err := conn.Write(ack)
				serverErr <- err
			}(conn.(*gotls.Conn))
		}
	}()
	profiles := measureH2Startup(&Config{Type: "tcp", Dest: listener.Addr().String()}, "")
	wantFull := []H2StartupRecord{
		{Length: 31, Frames: []H2StartupFrame{H2Settings}},
		{Length: 31, Frames: []H2StartupFrame{H2SettingsAck}},
	}
	wantResumed := []H2StartupRecord{{Length: 40, Frames: []H2StartupFrame{H2Settings, H2SettingsAck}}}
	if !reflect.DeepEqual(profiles.records(false, false), wantFull) || !reflect.DeepEqual(profiles.records(true, false), wantResumed) {
		t.Fatalf("startup profiles %+v, want full %+v and resumed %+v", profiles, wantFull, wantResumed)
	}
	for range 4 {
		select {
		case err := <-serverErr:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("the probe did not make both full and both resumed connections")
		}
	}
}

func TestFirefoxUsesDelayedStartupWhenResumed(t *testing.T) {
	fast := []H2StartupRecord{{Length: 71}}
	delayed := []H2StartupRecord{{Length: 62}, {Length: 31}}
	profiles := h2StartupProfiles{full: delayed, resumed: fast, resumedDelayed: delayed}
	firefox := &clientHelloMsg{extensions: []uint16{28, 34}}
	chrome := &clientHelloMsg{ticketSupported: true}
	if got := profiles.records(true, hasFirefoxH2Fingerprint(firefox)); !reflect.DeepEqual(got, delayed) {
		t.Fatalf("Firefox got %v, want %v", got, delayed)
	}
	if got := profiles.records(true, hasFirefoxH2Fingerprint(chrome)); !reflect.DeepEqual(got, fast) {
		t.Fatalf("Chrome got %v, want %v", got, fast)
	}
}

func TestFullBrowserH2ProfilesCanMixReplyAfterDifferentFrames(t *testing.T) {
	chromium := []H2StartupRecord{{Length: 62}, {Length: 146, ResponseBytes: 115}}
	firefox := []H2StartupRecord{{Length: 186, ResponseBytes: 115}}
	profiles := h2StartupProfiles{fullDelayedReply: chromium, firefoxFull: firefox}
	if got := profiles.records(false, false); !reflect.DeepEqual(got, chromium) {
		t.Errorf("Chromium got %v, want %v", got, chromium)
	}
	if got := profiles.records(false, true); !reflect.DeepEqual(got, firefox) {
		t.Errorf("Firefox got %v, want %v", got, firefox)
	}
}

func TestProbeH2MeasuresReplyInStartupRecord(t *testing.T) {
	listener := h2ProbeListener(t)
	serverErr := make(chan error, 1)
	request := h2StartupRequest("example.com")
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		wantPreface := []byte(h2ClientPreface + h2BrowserSettings)
		preface := make([]byte, len(wantPreface)+len(request))
		if _, err := io.ReadFull(conn, preface); err != nil {
			serverErr <- err
			return
		}
		if !bytes.Equal(preface, append(wantPreface, request...)) {
			serverErr <- io.ErrUnexpectedEOF
			return
		}
		settings := []byte{0, 0, 0, 4, 0, 0, 0, 0, 0}
		ack := []byte{0, 0, 0, 4, 1, 0, 0, 0, 0}
		headers := []byte{0, 0, 1, 1, 5, 0, 0, 0, 1, 0x88}
		_, err = conn.Write(bytes.Join([][]byte{settings, ack, headers}, nil))
		serverErr <- err
	}()
	got := probeH2Startup(&Config{Type: "tcp", Dest: listener.Addr().String()}, "example.com", 0, nil, request)
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
	want := []H2StartupRecord{{Length: 50, Frames: []H2StartupFrame{H2Settings, H2SettingsAck}, ResponseBytes: 10}}
	if !reflect.DeepEqual(got.records, want) {
		t.Fatalf("startup records %+v, want %+v", got.records, want)
	}
}

func TestH2StartupRefreshKeepsLastProfileOnFailure(t *testing.T) {
	key := t.Name()
	t.Cleanup(func() { h2StartupRecords.Delete(key) })
	full := []H2StartupRecord{{Length: 31, Frames: []H2StartupFrame{H2Settings}}}
	old := &h2StartupSnapshot{
		profiles: h2StartupProfiles{full: full},
		probed:   time.Now().Add(-2 * ticketShapeRefresh),
	}
	h2StartupRecords.Store(key, old)
	config := &Config{DialContext: func(context.Context, string, string) (net.Conn, error) {
		return nil, net.ErrClosed
	}}
	if got := detectH2Startup(config, key, "example.com").full; !reflect.DeepEqual(got, full) {
		t.Fatalf("refresh returned %v, want %v", got, full)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		value, _ := h2StartupRecords.Load(key)
		snapshot := value.(*h2StartupSnapshot)
		if !snapshot.running {
			if snapshot.probed.After(old.probed) && reflect.DeepEqual(snapshot.profiles.full, full) {
				return
			}
			t.Fatalf("refresh replaced the existing profile: %+v", snapshot)
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("refresh did not finish")
}

type writtenRecords struct {
	net.Conn
	buffer bytes.Buffer
}

func (c *writtenRecords) Write(b []byte) (int, error) {
	return c.buffer.Write(b)
}

func TestWritePaddedAppRecordIsOneRecord(t *testing.T) {
	wire := &writtenRecords{}
	conn := &Conn{conn: wire, config: &Config{}, vers: VersionTLS13}
	conn.isHandshakeComplete.Store(true)
	suite := cipherSuiteTLS13ByID(TLS_AES_128_GCM_SHA256)
	secret := make([]byte, suite.hash.Size())
	conn.out.version = VersionTLS13
	conn.out.setTrafficSecret(suite, QUICEncryptionLevelApplication, secret)
	// Larger than the first dynamically-sized record, so the explicit
	// length must override the normal splitting of application writes.
	payload := bytes.Repeat([]byte{1}, 1500)
	const length = 1600
	if n, err := conn.WritePaddedAppRecord(payload, length); err != nil || n != len(payload) {
		t.Fatalf("write returned %d, %v", n, err)
	}
	if _, err := conn.Write([]byte{2}); err != nil {
		t.Fatal(err)
	}
	records := splitRecords(wire.buffer.Bytes())
	if len(records) != 2 || records[0].len() != length || records[1].len() != 23 {
		t.Fatalf("wire length %d in %d records, want %d in 2 records", wire.buffer.Len(), len(records), length+23)
	}
	var peer halfConn
	peer.version = VersionTLS13
	peer.setTrafficSecret(suite, QUICEncryptionLevelApplication, secret)
	got, kind, err := peer.decrypt(wire.buffer.Bytes()[:length])
	if err != nil || kind != recordTypeApplicationData || !bytes.Equal(got, payload) {
		t.Fatalf("decrypt returned %d bytes of type %d, %v", len(got), kind, err)
	}
}
