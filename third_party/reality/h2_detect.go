package reality

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/pires/go-proxyproto"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2/hpack"
)

// H2StartupFrame identifies an HTTP/2 connection startup frame.
type H2StartupFrame uint8

const (
	H2Settings H2StartupFrame = iota + 1
	H2SettingsAck
	H2WindowUpdate
)

// H2StartupRecord describes one TLS record carrying the target's HTTP/2
// connection settings, their acknowledgement, or connection window credit.
type H2StartupRecord struct {
	Length        int
	Frames        []H2StartupFrame
	ResponseBytes int // bytes from the first response HEADERS to the end of this record
}

var h2StartupRecords sync.Map

type h2StartupProfiles struct {
	full             []H2StartupRecord
	resumed          []H2StartupRecord
	resumedDelayed   []H2StartupRecord
	firefoxFull      []H2StartupRecord
	fullDelayedReply []H2StartupRecord
	resumedWithReply []H2StartupRecord
}

func (p h2StartupProfiles) records(resumed, firefox bool) []H2StartupRecord {
	if firefox {
		if resumed && len(p.resumedWithReply) != 0 {
			return p.resumedWithReply
		}
		if !resumed && len(p.firefoxFull) != 0 {
			return p.firefoxFull
		}
	}
	if !resumed && !firefox && len(p.fullDelayedReply) != 0 {
		return p.fullDelayedReply
	}
	if resumed && firefox && len(p.resumedDelayed) != 0 {
		return p.resumedDelayed
	}
	if resumed && len(p.resumed) != 0 {
		return p.resumed
	}
	return p.full
}

// Firefox advertises record_size_limit and delegated credentials.
func hasFirefoxH2Fingerprint(hello *clientHelloMsg) bool {
	const recordSizeLimit, delegatedCredentials = 28, 34
	return slices.Contains(hello.extensions, recordSizeLimit) && slices.Contains(hello.extensions, delegatedCredentials)
}

type h2StartupSample struct {
	records []H2StartupRecord
	ticket  *utls.ClientSessionState
	resumed bool
}

type h2StartupSnapshot struct {
	profiles h2StartupProfiles
	probed   time.Time
	running  bool
}

// The peer may send SETTINGS before seeing the client preface. With an
// immediate preface it can pack SETTINGS and the ACK into one record.
const h2PrefaceDelay = 60 * time.Millisecond

// detectH2Startup returns the latest usable profile and refreshes it in the
// background. An unreachable target does not erase the last measurement.
func detectH2Startup(config *Config, key, sni string) h2StartupProfiles {
	pending := &h2StartupSnapshot{probed: time.Now(), running: true}
	if value, loaded := h2StartupRecords.LoadOrStore(key, pending); loaded {
		previous := value.(*h2StartupSnapshot)
		interval := ticketShapeRefresh
		if len(previous.profiles.full) == 0 && len(previous.profiles.resumed) == 0 {
			interval = time.Minute
		}
		if previous.running || time.Since(previous.probed) < interval {
			return previous.profiles
		}
		pending.profiles = previous.profiles
		if !h2StartupRecords.CompareAndSwap(key, previous, pending) {
			return previous.profiles
		}
	}
	go func() {
		profiles := measureH2Startup(config, sni)
		if len(profiles.full) == 0 && len(profiles.resumed) == 0 {
			profiles = pending.profiles
		}
		h2StartupRecords.Store(key, &h2StartupSnapshot{profiles: profiles, probed: time.Now()})
	}()
	return pending.profiles
}

func measureH2Startup(config *Config, sni string) h2StartupProfiles {
	type pair struct {
		full, resumed []H2StartupRecord
	}
	probePair := func(delay time.Duration, request []byte) pair {
		full := probeH2Startup(config, sni, delay, nil, request)
		result := pair{full: full.records}
		if full.ticket != nil {
			resumed := probeH2Startup(config, sni, delay, full.ticket, request)
			if resumed.resumed {
				result.resumed = resumed.records
			}
		}
		return result
	}
	immediate := make(chan pair, 1)
	go func() { immediate <- probePair(0, nil) }()
	var pipelined chan pair
	var delayedReply chan []H2StartupRecord
	if request := h2StartupRequest(sni); len(request) != 0 {
		pipelined = make(chan pair, 1)
		delayedReply = make(chan []H2StartupRecord, 1)
		go func() { pipelined <- probePair(0, request) }()
		// Chromium can receive SETTINGS first, then the ACK and response
		// together after it sends the preface and request.
		go func() {
			delayedReply <- probeH2Startup(config, sni, h2PrefaceDelay, nil, request).records
		}()
	}
	delayed := probePair(h2PrefaceDelay, nil)
	fast := <-immediate
	var withReply pair
	var withDelayedReply []H2StartupRecord
	if pipelined != nil {
		withReply = <-pipelined
		withDelayedReply = <-delayedReply
	}
	// A Go target can flush WINDOW_UPDATE and ACK separately even when
	// the preface is already available. Look for a pipelined sample with
	// fewer records, using a freshly issued ticket each time.
	if len(fast.resumed) > 1 && len(fast.resumed) == len(delayed.resumed) {
		for range 2 {
			sample := probePair(0, nil).resumed
			if len(sample) > 0 && len(sample) < len(fast.resumed) {
				fast.resumed = sample
				break
			}
		}
	}
	if config.Show {
		fmt.Printf("REALITY dest %s SNI %s h2 startup: immediate full %v resumed %v, delayed full %v resumed %v\n",
			config.Dest, sni, fast.full, fast.resumed, delayed.full, delayed.resumed)
		fmt.Printf("REALITY dest %s SNI %s h2 startup with request: full %v resumed %v\n",
			config.Dest, sni, withReply.full, withReply.resumed)
	}
	// Prefer the separate greeting seen in full browser handshakes, and
	// the pipelined preface path on a successfully resumed handshake.
	profiles := h2StartupProfiles{full: delayed.full, resumed: fast.resumed, resumedDelayed: delayed.resumed}
	// Firefox can pipeline its request with the preface. Use the sample
	// when the target sends the greeting together, with or without the reply.
	// When control frames arrive separately, use the control-only profile.
	if len(withReply.full) == 1 {
		profiles.firefoxFull = withReply.full
	} else if len(fast.full) == 1 {
		profiles.firefoxFull = fast.full
	}
	if len(withDelayedReply) == 2 && slices.Contains(withDelayedReply[0].Frames, H2WindowUpdate) &&
		endsWithH2Reply(withDelayedReply) {
		profiles.fullDelayedReply = withDelayedReply
	}
	if len(withReply.resumed) == 1 && endsWithH2Reply(withReply.resumed) {
		profiles.resumedWithReply = withReply.resumed
	}
	if len(profiles.full) == 0 {
		profiles.full = fast.full
	}
	if len(profiles.resumed) == 0 {
		profiles.resumed = delayed.resumed
	}
	return profiles
}

func endsWithH2Reply(records []H2StartupRecord) bool {
	return len(records) != 0 && records[len(records)-1].ResponseBytes != 0
}

// Send a GET to the configured target to measure the record that a real
// navigation can share with startup controls. The probe stops at the ACK.
func h2StartupRequest(sni string) []byte {
	if sni == "" || len(sni) > 253 {
		return nil
	}
	var headers bytes.Buffer
	encoder := hpack.NewEncoder(&headers)
	for _, field := range []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: sni},
		{Name: ":path", Value: "/"},
	} {
		if err := encoder.WriteField(field); err != nil {
			return nil
		}
	}
	length := headers.Len()
	frame := []byte{byte(length >> 16), byte(length >> 8), byte(length), 1, 5, 0, 0, 0, 1}
	return append(frame, headers.Bytes()...)
}

const h2ClientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
const h2EmptySettings = "\x00\x00\x00\x04\x00\x00\x00\x00\x00"

// Chrome and Firefox advertise a 64 KiB HPACK table. Some targets emit a
// table size update in their first response only after seeing this setting.
const h2BrowserSettings = "\x00\x00\x06\x04\x00\x00\x00\x00\x00\x00\x01\x00\x01\x00\x00"

// recordReader prevents TLS from reading ahead into the next record, so
// the size of each decrypted application record can be measured separately.
type recordReader struct {
	net.Conn
	header    [recordHeaderLen]byte
	remaining int
	length    int
}

func (c *recordReader) Read(b []byte) (int, error) {
	if c.remaining == 0 {
		if len(b) < len(c.header) {
			return 0, io.ErrShortBuffer
		}
		if _, err := io.ReadFull(c.Conn, c.header[:]); err != nil {
			return 0, err
		}
		c.remaining = int(binary.BigEndian.Uint16(c.header[3:]))
		c.length = len(c.header) + c.remaining
		return copy(b, c.header[:]), nil
	}
	n, err := c.Conn.Read(b[:min(len(b), c.remaining)])
	c.remaining -= n
	return n, err
}

func probeH2Startup(config *Config, sni string, prefaceDelay time.Duration, replay *utls.ClientSessionState, request []byte) (sample h2StartupSample) {
	ctx, cancel := context.WithTimeout(context.Background(), ticketProbeTimeout)
	defer cancel()
	dial := config.DialContext
	if dial == nil {
		dial = new(net.Dialer).DialContext
	}
	target, err := dial(ctx, config.Type, config.Dest)
	if err != nil {
		return sample
	}
	defer target.Close()
	deadline, _ := ctx.Deadline()
	target.SetDeadline(deadline)
	if config.Xver == 1 || config.Xver == 2 {
		if _, err := proxyproto.HeaderProxyFromAddrs(config.Xver, target.LocalAddr(), target.RemoteAddr()).WriteTo(target); err != nil {
			return sample
		}
	}

	wire := &recordReader{Conn: target}
	recorder := &ticketRecorder{replay: replay}
	conn, err := probeClient(wire, &utls.Config{
		ServerName: sni, InsecureSkipVerify: true, ClientSessionCache: recorder,
	}, 2, replay != nil)
	if err != nil || conn.HandshakeContext(ctx) != nil {
		return sample
	}
	state := conn.ConnectionState()
	if state.Version != VersionTLS13 || state.NegotiatedProtocol != "h2" {
		return sample
	}
	sample.resumed = state.DidResume
	defer func() {
		if tickets := recorder.take(); len(tickets) > 0 {
			sample.ticket = tickets[0]
		}
	}()
	if prefaceDelay > 0 {
		timer := time.NewTimer(prefaceDelay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			return sample
		}
	}
	settings := h2EmptySettings
	if len(request) != 0 {
		settings = h2BrowserSettings
	}
	// Some servers wait for the client preface before sending application data.
	if _, err := conn.Write(append([]byte(h2ClientPreface+settings), request...)); err != nil {
		return sample
	}
	readDeadline := time.Now().Add(ticketProbeWait)
	if deadline.Before(readDeadline) {
		readDeadline = deadline
	}
	if err := target.SetReadDeadline(readDeadline); err != nil {
		return sample
	}

	var records []H2StartupRecord
	buf := make([]byte, maxPlaintext)
	seen := [4]bool{}
	for range len(seen) - 1 {
		n, err := conn.Read(buf)
		if n == 0 || err != nil || wire.length > maxPlaintext+recordHeaderLen+1+16 {
			break
		}
		frames, responseBytes := parseH2Startup(buf[:n])
		if len(frames) == 0 || (len(records) == 0 && frames[0] != H2Settings) {
			return sample
		}
		for _, frame := range frames {
			if seen[frame] {
				return sample
			}
			seen[frame] = true
		}
		records = append(records, H2StartupRecord{Length: wire.length, Frames: frames, ResponseBytes: responseBytes})
		if seen[H2SettingsAck] {
			sample.records = records
			return sample
		}
		if responseBytes != 0 {
			return sample
		}
	}
	return sample
}

func parseH2Startup(data []byte) ([]H2StartupFrame, int) {
	var frames []H2StartupFrame
	for len(data) >= 9 {
		n := int(data[0])<<16 | int(data[1])<<8 | int(data[2])
		stream := binary.BigEndian.Uint32(data[5:9]) & 0x7fffffff
		if data[3] == 1 && stream == 1 {
			return frames, len(data)
		}
		if n > len(data)-9 || stream != 0 {
			return nil, 0
		}
		switch {
		case data[3] == 4 && data[4] == 0 && n%6 == 0:
			frames = append(frames, H2Settings)
		case data[3] == 4 && data[4] == 1 && n == 0:
			frames = append(frames, H2SettingsAck)
		case data[3] == 8 && data[4] == 0 && n == 4:
			frames = append(frames, H2WindowUpdate)
		default:
			return nil, 0
		}
		data = data[9+n:]
	}
	if len(data) != 0 {
		return nil, 0
	}
	return frames, 0
}

// H2StartupRecords returns the target's measured HTTP/2 startup records.
func (c *Conn) H2StartupRecords() []H2StartupRecord {
	records := slices.Clone(c.h2Startup)
	for i := range records {
		records[i].Frames = slices.Clone(records[i].Frames)
	}
	return records
}
