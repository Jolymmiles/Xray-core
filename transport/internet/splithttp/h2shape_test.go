package splithttp

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"net"
	"slices"
	"testing"
	"time"

	reality "github.com/xtls/reality"
)

type writesConn struct {
	net.Conn
	writes [][]byte
}

func (c *writesConn) Write(b []byte) (int, error) {
	c.writes = append(c.writes, bytes.Clone(b))
	return len(b), nil
}

func frame(typ, flags byte, stream uint32, payload []byte) []byte {
	b := []byte{byte(len(payload) >> 16), byte(len(payload) >> 8), byte(len(payload)), typ, flags, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(b[5:], stream)
	return append(b, payload...)
}

func settings(ids ...uint16) []byte {
	var p []byte
	for _, id := range ids {
		p = binary.BigEndian.AppendUint16(p, id)
		p = binary.BigEndian.AppendUint32(p, 1<<16)
	}
	return frame(frameSettings, 0, 0, p)
}

// Go's server writes SETTINGS of six parameters, then WINDOW_UPDATE with
// the acknowledgement; nginx writes SETTINGS of three with WINDOW_UPDATE,
// then the acknowledgement.
func TestShapeConnWritesTheFramesAsNginx(t *testing.T) {
	c, under := nginxShapeForTest(62)
	bw := bufio.NewWriter(c)
	goSettings := settings(0x5, 0x3, 0x6, 0x1, 0x4, 0x8)
	wu := frame(frameWindowUpd, 0, 0, []byte{0, 0x0f, 0, 0x01})
	ack := frame(frameSettings, 0x1, 0, nil)
	bw.Write(goSettings)
	if err := bw.Flush(); err != nil {
		t.Fatal(err)
	}
	if len(under.writes) != 0 {
		t.Fatal("SETTINGS waits for the WINDOW_UPDATE")
	}
	bw.Write(append(append([]byte(nil), wu...), ack...))
	if err := bw.Flush(); err != nil {
		t.Fatal(err)
	}
	want := [][]byte{append(settings(0x5, 0x3, 0x4), wu...), ack}
	if len(under.writes) != 2 || !bytes.Equal(under.writes[0], want[0]) || !bytes.Equal(under.writes[1], want[1]) {
		t.Fatalf("writes %x, want %x", under.writes, want)
	}
	if len(under.writes[0]) != 40 {
		t.Fatalf("SETTINGS and WINDOW_UPDATE take %d bytes, nginx's 40", len(under.writes[0]))
	}
	c.Write([]byte("data"))
	if len(under.writes) != 3 {
		t.Fatal("then everything passes")
	}
}

type startupWritesConn struct {
	writesConn
	profile []reality.H2StartupRecord
	lengths []int
}

func nginxShapeForTest(length int) (*shapeConn, *startupWritesConn) {
	under := &startupWritesConn{}
	return &shapeConn{Conn: under, writer: under, profile: []reality.H2StartupRecord{
		{Length: length, Frames: []reality.H2StartupFrame{reality.H2Settings, reality.H2WindowUpdate}},
		{Length: 31, Frames: []reality.H2StartupFrame{reality.H2SettingsAck}},
	}}, under
}

func (c *startupWritesConn) H2StartupRecords() []reality.H2StartupRecord { return c.profile }

func (c *startupWritesConn) WritePaddedAppRecord(b []byte, length int) (int, error) {
	c.lengths = append(c.lengths, length)
	return c.Write(b)
}

func TestShapeConnUsesTargetStartupRecords(t *testing.T) {
	goSettings := settings(0x5, 0x3, 0x6, 0x1, 0x4, 0x8)
	shortSettings := settings(0x5, 0x3, 0x4)
	window := frame(frameWindowUpd, 0, 0, []byte{0, 0x0f, 0, 1})
	ack := frame(frameSettings, 1, 0, nil)
	for _, test := range []struct {
		name    string
		profile []reality.H2StartupRecord
		want    [][]byte
	}{
		{"nginx", []reality.H2StartupRecord{
			{Length: 62, Frames: []reality.H2StartupFrame{reality.H2Settings, reality.H2WindowUpdate}},
			{Length: 31, Frames: []reality.H2StartupFrame{reality.H2SettingsAck}},
		}, [][]byte{append(bytes.Clone(shortSettings), window...), ack}},
		{"caddy", []reality.H2StartupRecord{
			{Length: 67, Frames: []reality.H2StartupFrame{reality.H2Settings}},
			{Length: 35, Frames: []reality.H2StartupFrame{reality.H2WindowUpdate}},
			{Length: 31, Frames: []reality.H2StartupFrame{reality.H2SettingsAck}},
		}, [][]byte{goSettings, window, ack}},
		{"haproxy", []reality.H2StartupRecord{
			{Length: 58, Frames: []reality.H2StartupFrame{reality.H2Settings, reality.H2SettingsAck}},
		}, [][]byte{append(bytes.Clone(shortSettings), ack...)}},
	} {
		t.Run(test.name, func(t *testing.T) {
			under := &startupWritesConn{profile: test.profile}
			conn := &shapeConn{Conn: under, writer: under, profile: test.profile}
			if conn.omitsStartupWindow() {
				conn.startupGrant = 0x0f0001
			}
			bw := bufio.NewWriter(conn)
			for _, data := range [][]byte{goSettings, window, ack} {
				bw.Write(data)
				if err := bw.Flush(); err != nil {
					t.Fatal(err)
				}
			}
			if len(under.lengths) != len(test.profile) {
				t.Fatalf("padded records %v, profile %+v", under.lengths, test.profile)
			}
			for i, length := range under.lengths {
				if length != test.profile[i].Length || len(under.writes[i])+recordOverhead > length {
					t.Fatalf("record %d takes %d bytes, padded to %d", i, len(under.writes[i])+recordOverhead, length)
				}
			}
			if !slices.EqualFunc(under.writes, test.want, bytes.Equal) {
				t.Fatalf("writes %x, want %x", under.writes, test.want)
			}
			if test.name == "haproxy" {
				// A later stream update stays intact. The retained credit
				// rides on the first update returned for the connection.
				streamUpdate := frame(frameWindowUpd, 0, 1, []byte{0, 0, 0x10, 0})
				update := frame(frameWindowUpd, 0, 0, []byte{0, 0, 0x10, 0})
				conn.Write(streamUpdate)
				conn.Write(update[:3])
				conn.Write(update[3:])
				want := frame(frameWindowUpd, 0, 0, []byte{0, 0x0f, 0x10, 1})
				if !slices.EqualFunc(under.writes[1:], [][]byte{streamUpdate, want}, bytes.Equal) {
					t.Fatalf("updates %x, want %x then %x", under.writes[1:], streamUpdate, want)
				}
			}
		})
	}
}

func TestShapedFlowTagsTheFirstResponse(t *testing.T) {
	server := newFlowConn(&writesConn{}, flowDefault, flowDefault)
	server.shapeStartup, server.pingReady, server.settingsSent = true, true, true
	writer := (*flowWriter)(server)
	if ping := writer.boundary(nil); len(ping) != 0 {
		t.Fatalf("unexpected probe in the greeting: %x", ping)
	}
	writer.frame(h2Frame{typ: h2Headers, stream: 1})
	ping := writer.boundary(nil)
	if len(ping) != 17 || ping[3] != h2Ping {
		t.Fatalf("first response should carry a tagged PING, got %x", ping)
	}

	client := newFlowClientConn(&writesConn{})
	client.shapeStartup, client.serverReplied = true, true
	(*flowWriter)(client).control(h2Frame{typ: h2Ping, length: 8}, ping[:9], ping[9:], nil)
	if !client.peerGoverned {
		t.Fatal("client did not recognize the deferred flow probe")
	}
}

func TestShapeConnSharesStartupRecordWithReply(t *testing.T) {
	settings := settings(settingMaxConc, settingInitWin, settingMaxFrame)
	ack := frame(frameSettings, 1, 0, nil)
	reply := frame(h2Headers, h2FlagEndHeaders, 1, []byte{0x88, 0x0f, 0x08, 0x01, 'x'})
	const replyPrefix = 10
	control := append(bytes.Clone(settings), ack...)
	length := recordOverhead + len(control)
	profile := []reality.H2StartupRecord{{
		Length: length + replyPrefix, Frames: []reality.H2StartupFrame{reality.H2Settings, reality.H2SettingsAck},
		ResponseBytes: replyPrefix,
	}}
	for _, test := range []struct {
		name      string
		sendReply bool
	}{
		{"same record", true},
		{"no response yet", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			under := &startupWritesConn{}
			conn := &shapeConn{Conn: under, writer: under, profile: profile}
			if _, err := conn.Write(settings); err != nil {
				t.Fatal(err)
			}
			if _, err := conn.Write(ack); err != nil {
				t.Fatal(err)
			}
			wantLength := length
			want := [][]byte{control}
			if test.sendReply {
				if _, err := conn.Write(reply); err != nil {
					t.Fatal(err)
				}
				wantLength += replyPrefix
				want = [][]byte{append(bytes.Clone(control), reply[:replyPrefix]...), reply[replyPrefix:]}
			} else {
				conn.mu.Lock()
				err := conn.writeStartup(nil, true)
				conn.mu.Unlock()
				if err != nil {
					t.Fatal(err)
				}
			}
			if !slices.Equal(under.lengths, []int{wantLength}) || !slices.EqualFunc(under.writes, want, bytes.Equal) {
				t.Fatalf("lengths %v writes %x, want %d and %x", under.lengths, under.writes, wantLength, want)
			}
		})
	}
}

func TestShapeConnSendsSettingsAlone(t *testing.T) {
	c, under := nginxShapeForTest(62)
	c.Write(settings(0x5, 0x3, 0x4))
	time.Sleep(2 * shapeWait)
	c.mu.Lock()
	n := len(under.writes)
	c.mu.Unlock()
	if n != 1 {
		t.Fatal("SETTINGS goes alone when nothing follows")
	}
}

func TestShapeConnPassesOtherProtocols(t *testing.T) {
	under := &writesConn{}
	c := &shapeConn{Conn: under}
	c.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
	if len(under.writes) != 1 {
		t.Fatal("HTTP/1.1 passes")
	}
}

func TestShapeConnCloseStopsStartupTimer(t *testing.T) {
	local, remote := net.Pipe()
	defer remote.Close()
	c := &shapeConn{Conn: local, state: 1, timer: time.NewTimer(time.Hour)}
	defer c.timer.Stop()
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if c.state != 2 || c.timer.Stop() {
		t.Fatal("closing a connection must stop its startup timer")
	}
}

func TestAckConnWritesTheAcknowledgementAlone(t *testing.T) {
	under := &writesConn{}
	c := &ackConn{Conn: under}
	wu := frame(frameWindowUpd, 0, 0, []byte{0, 0x0f, 0, 0x01})
	ack := frame(frameSettings, 0x1, 0, nil)
	if n, err := c.Write(append(append([]byte(nil), ack...), wu...)); n != len(ack)+len(wu) || err != nil {
		t.Fatal(n, err)
	}
	if len(under.writes) != 2 || !bytes.Equal(under.writes[0], ack) || !bytes.Equal(under.writes[1], wu) {
		t.Fatalf("writes %x", under.writes)
	}
	later := append(bytes.Clone(ack), wu...)
	if _, err := c.Write(later); err != nil || len(under.writes) != 3 || !bytes.Equal(under.writes[2], later) {
		t.Fatal("writes after the initial ACK pass without splitting", err)
	}
}

func TestAckConnHandlesFragmentedPrefaceAndFrameHeaders(t *testing.T) {
	under := &writesConn{}
	c := &ackConn{Conn: under, prefaceLeft: len(h2Preface)}
	badStream := frame(frameSettings, 1, 1, nil)
	badLength := frame(frameSettings, 1, 0, make([]byte, 6))
	ack := frame(frameSettings, 1, 0, nil)
	wu := frame(frameWindowUpd, 0, 0, []byte{0, 0, 0, 1})
	initial := append(append([]byte(h2Preface), badStream...), badLength...)
	for _, chunk := range [][]byte{initial[:4], initial[4 : len(initial)-2], initial[len(initial)-2:]} {
		if n, err := c.Write(chunk); n != len(chunk) || err != nil {
			t.Fatalf("initial write %d, %v", n, err)
		}
	}
	if c.done || len(under.writes) != 3 {
		t.Fatalf("invalid ACK split the stream: %x", under.writes)
	}
	if _, err := c.Write(ack[:4]); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(append(bytes.Clone(ack[4:]), wu...)); err != nil {
		t.Fatal(err)
	}
	// A header split across writes is held until it can be classified, so
	// the acknowledgement still goes in one write of its own.
	if len(under.writes) != 5 || !bytes.Equal(under.writes[3], ack) || !bytes.Equal(under.writes[4], wu) {
		t.Fatalf("writes %x", under.writes)
	}
}

// Go may write the acknowledgement before the connection's WINDOW_UPDATE.
func TestShapeConnMovesTheWindowUpdate(t *testing.T) {
	c, under := nginxShapeForTest(62)
	wu := frame(frameWindowUpd, 0, 0, []byte{0, 0x0f, 0, 0x01})
	ack := frame(frameSettings, 0x1, 0, nil)
	c.Write(settings(0x5, 0x3, 0x4, 0x6))
	c.Write(append(append([]byte(nil), ack...), wu...))
	if len(under.writes) != 2 || !bytes.Equal(under.writes[0], append(settings(0x5, 0x3, 0x4), wu...)) || !bytes.Equal(under.writes[1], ack) {
		t.Fatalf("writes %x", under.writes)
	}
}

func TestShapeConnPassesUnknownTargets(t *testing.T) {
	goSettings := settings(0x5, 0x3, 0x6, 0x1, 0x4, 0x8)
	under := &writesConn{}
	c := &shapeConn{Conn: under}
	c.Write(goSettings)
	if len(under.writes) != 1 || !bytes.Equal(under.writes[0], goSettings) {
		t.Fatal("SETTINGS goes as Go writes it")
	}
}

// Yandex's first record holds 39 bytes: two parameters and the
// WINDOW_UPDATE fit, padded by REALITY.
func TestShapeConnFitsTheTargetsRecord(t *testing.T) {
	c, under := nginxShapeForTest(61)
	wu := frame(frameWindowUpd, 0, 0, []byte{0, 0x0f, 0, 0x01})
	c.Write(settings(0x5, 0x3, 0x6, 0x1, 0x4, 0x8))
	c.Write(append(frame(frameSettings, 0x1, 0, nil), wu...))
	if got := len(under.writes[0]); got+recordOverhead > 61 {
		t.Fatalf("the first write takes %d bytes, more than the target's record holds", got)
	}
	if !bytes.Equal(under.writes[0], append(settings(0x3, 0x4), wu...)) {
		t.Fatalf("first write %x: INITIAL_WINDOW_SIZE and MAX_CONCURRENT_STREAMS stay", under.writes[0])
	}
}

// A decoder table smaller than the default must be announced: a peer that
// assumes 4096 bytes would encode headers the server cannot decode.
func TestFitSettingsKeepsASmallHeaderTable(t *testing.T) {
	var p []byte
	for _, id := range []uint16{0x5, 0x3, 0x6, 0x1, 0x4, 0x8} {
		value := uint32(1 << 16)
		if id == 0x1 {
			value = 1024
		}
		p = binary.BigEndian.AppendUint16(p, id)
		p = binary.BigEndian.AppendUint32(p, value)
	}
	goSettings := frame(frameSettings, 0, 0, p)
	fitted := fitSettings(goSettings, frameHeaderLen+3*6)
	found := false
	for q := frameHeaderLen; fitted != nil && q+6 <= len(fitted); q += 6 {
		if binary.BigEndian.Uint16(fitted[q:]) == 0x1 {
			found = binary.BigEndian.Uint32(fitted[q+2:]) == 1024
		}
	}
	if !found {
		t.Fatalf("fitted SETTINGS %x dropped HEADER_TABLE_SIZE 1024", fitted)
	}
	if fitted := fitSettings(goSettings, frameHeaderLen+2*6); fitted != nil {
		t.Fatalf("SETTINGS %x cannot carry the table size and must not be shaped", fitted)
	}
	// A default or larger table may go: the peer then assumes 4096.
	if fitted := fitSettings(settings(0x5, 0x3, 0x6, 0x1, 0x4, 0x8), frameHeaderLen+2*6); fitted == nil {
		t.Fatal("a 64 KiB table does not need announcing")
	}
}

type failingStartupConn struct {
	startupWritesConn
	closed chan struct{}
}

func (c *failingStartupConn) WritePaddedAppRecord([]byte, int) (int, error) {
	return 0, net.ErrClosed
}

func (c *failingStartupConn) Write([]byte) (int, error) { return 0, net.ErrClosed }

func (c *failingStartupConn) Close() error {
	close(c.closed)
	return nil
}

// When the deferred flush of SETTINGS fails, nothing else may write: the
// connection must close rather than leave the peer waiting.
func TestShapeConnClosesWhenTheDeferredFlushFails(t *testing.T) {
	under := &failingStartupConn{closed: make(chan struct{})}
	c := &shapeConn{Conn: under, writer: under, profile: []reality.H2StartupRecord{
		{Length: 62, Frames: []reality.H2StartupFrame{reality.H2Settings, reality.H2WindowUpdate}},
		{Length: 31, Frames: []reality.H2StartupFrame{reality.H2SettingsAck}},
	}}
	// SETTINGS waits for its WINDOW_UPDATE, which never comes.
	if _, err := c.Write(settings(0x5, 0x3, 0x4)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-under.closed:
	case <-time.After(10 * shapeWait):
		t.Fatal("the connection stayed open after the deferred flush failed")
	}
}
