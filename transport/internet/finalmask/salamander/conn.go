package salamander

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

type salamanderConn struct {
	net.PacketConn
	obfs *SalamanderObfuscator
}

func NewSalamanderConnClient(c *Config, raw net.PacketConn) (net.PacketConn, error) {
	ob, err := NewSalamanderObfuscator([]byte(c.Password))
	if err != nil {
		return nil, err
	}
	return &salamanderConn{
		PacketConn: raw,
		obfs:       ob,
	}, nil
}

func NewSalamanderConnServer(c *Config, raw net.PacketConn) (net.PacketConn, error) {
	return NewSalamanderConnClient(c, raw)
}

func (c *salamanderConn) Size() int {
	return smSaltLen
}

func (c *salamanderConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	c.obfs.Deobfuscate(p, p[smSaltLen:])
	return len(p) - smSaltLen, nil, nil
}

func (c *salamanderConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	c.obfs.Obfuscate(p[smSaltLen:], p)
	return len(p), nil
}

const (
	geckoReassemblyTTL = 8 * time.Second
	geckoMaxReassembly = 4096
	geckoMaxPerSource  = 8

	geckoBufferSize = 2048

	geckoDefaultMinPacket = 512
	geckoDefaultMaxPacket = 1200
)

type reassemblyKey struct {
	addr  string
	msgID uint8
}

type reassemblyEntry struct {
	chunks   [][]byte
	received int
	total    uint8
	// poisoned marks an ID that received chunks of two messages: it drops
	// every chunk until its deadline instead of delivering a splice.
	poisoned bool
	deadline time.Time
}

type geckoConn struct {
	net.PacketConn
	obfs           *SalamanderObfuscator
	minPkt, maxPkt int

	msgID atomic.Uint32

	mu         sync.Mutex
	reassembly map[reassemblyKey]*reassemblyEntry
	perSource  map[string]int

	closeCh   chan struct{}
	closeOnce sync.Once
}

func NewGeckoConnClient(c *GeckoConfig, raw net.PacketConn) (net.PacketConn, error) {
	ob, err := NewSalamanderObfuscator([]byte(c.Password))
	if err != nil {
		return nil, err
	}
	minPkt, maxPkt := c.MinPacketSize, c.MaxPacketSize
	if minPkt == 0 {
		minPkt = geckoDefaultMinPacket
	}
	if maxPkt == 0 {
		maxPkt = geckoDefaultMaxPacket
	}
	if minPkt <= 0 || minPkt > maxPkt || maxPkt > geckoBufferSize {
		return nil, errors.New("gecko: invalid min/max packet size")
	}
	g := &geckoConn{
		PacketConn: raw,
		obfs:       ob,
		minPkt:     int(minPkt),
		maxPkt:     int(maxPkt),
		reassembly: make(map[reassemblyKey]*reassemblyEntry),
		perSource:  make(map[string]int),
		closeCh:    make(chan struct{}),
	}
	go g.gcLoop()
	return g, nil
}

func NewGeckoConnServer(c *GeckoConfig, raw net.PacketConn) (net.PacketConn, error) {
	return NewGeckoConnClient(c, raw)
}

func (c *geckoConn) readObfs(p []byte) (n int, addr net.Addr, err error) {
	for {
		n, addr, err = c.PacketConn.ReadFrom(p)
		if err != nil {
			return n, addr, err
		}
		if n < smSaltLen {
			continue
		}
		c.obfs.Deobfuscate(p[:n], p)
		return n - smSaltLen, addr, nil
	}
}

func (c *geckoConn) writeObfs(p []byte, addr net.Addr) (n int, err error) {
	b := buf.New()
	b.Resize(0, int32(len(p)+smSaltLen))
	defer b.Release()
	c.obfs.Obfuscate(p, b.Bytes())
	return c.PacketConn.WriteTo(b.Bytes(), addr)
}

func (g *geckoConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if p[0]&0x80 != 0 {
		// QUIC long header, do fragmentation.
		return g.writeFragmented(p, addr)
	}
	// QUIC short header (data), pass through.
	return g.writeObfs(p, addr)
}

func (g *geckoConn) writeFragmented(p []byte, addr net.Addr) (int, error) {
	chunks := randomFragmentChunks()
	chunkSize := len(p) / chunks
	msgID := uint8(g.msgID.Add(1))
	for i := range chunks {
		start := i * chunkSize
		end := len(p)
		if i < chunks-1 {
			end = start + chunkSize
		}
		chunk := p[start:end]
		padLen := g.randomPadLen(len(chunk))
		buf := make([]byte, geckoHeaderSize+int(padLen)+len(chunk))
		n, err := encodeFrame(frameHeader{
			padLen:      padLen,
			msgID:       msgID,
			chunkIdx:    uint8(i),
			totalChunks: uint8(chunks),
		}, chunk, buf)
		if err != nil {
			return 0, err
		}
		if _, err := g.writeObfs(buf[:n], addr); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

func (g *geckoConn) randomPadLen(chunkLen int) uint16 {
	base := smSaltLen + geckoHeaderSize + chunkLen
	lo := max(g.minPkt, base)
	if lo > g.maxPkt {
		return 0
	}
	return uint16(lo - base + randIntn(g.maxPkt-lo+1))
}

func randomFragmentChunks() int {
	return geckoMinFragmentChunks + randIntn(geckoMaxFragmentChunks-geckoMinFragmentChunks+1)
}

func randIntn(n int) int {
	if n <= 1 {
		return 0
	}
	var b [4]byte
	_, _ = rand.Read(b[:])
	return int(binary.BigEndian.Uint32(b[:]) % uint32(n))
}

func (g *geckoConn) ReadFrom(p []byte) (int, net.Addr, error) {
	b := buf.New()
	b.Resize(0, finalmask.UDPSize)
	buf := b.Bytes()
	defer b.Release()
	for {
		n, addr, err := g.readObfs(buf)
		if err != nil {
			return 0, addr, err
		}
		if n <= 0 {
			continue
		}
		// Top bit set → Gecko fragment frame; clear → short-header packet
		// or garbage, passed through for QUIC to handle.
		if buf[0]&0x80 == 0 {
			return copy(p, buf[:n]), addr, nil
		}
		h, payload, decErr := decodeFrame(buf[:n])
		if decErr != nil {
			// Malformed frame; drop silently.
			continue
		}
		out, ready := g.acceptChunk(addr, h, payload)
		if !ready {
			continue
		}
		return copy(p, out), addr, nil
	}
}

func (g *geckoConn) acceptChunk(addr net.Addr, h frameHeader, payload []byte) ([]byte, bool) {
	return g.acceptChunkAt(addr, h, payload, time.Now())
}

// acceptChunkAt reassembles Gecko messages. The one-byte message ID repeats
// every 256 fragmented messages and no field ties a chunk to its message, so
// after a lost chunk a later message can arrive under the ID of an
// incomplete one. A chunk that cannot belong to the message an entry holds
// proves such a mix; the entry is then quarantined, because arrival order
// does not tell which message is newer and restarting from the conflicting
// chunk would let the other message's delayed chunks complete it. A mix that
// stays consistent until it completes cannot be told from a reordered
// message and is still delivered; QUIC's packet protection rejects it.
func (g *geckoConn) acceptChunkAt(addr net.Addr, h frameHeader, payload []byte, now time.Time) ([]byte, bool) {
	key := reassemblyKey{addr: addr.String(), msgID: h.msgID}

	g.mu.Lock()
	defer g.mu.Unlock()

	e, exists := g.reassembly[key]
	if exists && now.After(e.deadline) {
		// Expired but not collected yet: it must not absorb a new message.
		g.dropEntryLocked(key)
		exists = false
	}
	if !exists {
		// Per-source cap.
		if g.perSource[key.addr] >= geckoMaxPerSource {
			return nil, false
		}
		// Global cap with eviction.
		if len(g.reassembly) >= geckoMaxReassembly {
			g.evictOldestLocked()
		}
		e = &reassemblyEntry{
			chunks:   make([][]byte, h.totalChunks),
			total:    h.totalChunks,
			deadline: now.Add(geckoReassemblyTTL),
		}
		g.reassembly[key] = e
		g.perSource[key.addr]++
	}
	switch {
	case e.poisoned:
		return nil, false
	case int(h.chunkIdx) >= int(h.totalChunks):
		// Bad index; drop.
		return nil, false
	case e.total != h.totalChunks || !geckoChunkFits(e, h.chunkIdx, payload):
		// Keep the original deadline: the quarantine must end.
		e.poisoned = true
		e.chunks = nil
		e.received = 0
		return nil, false
	case e.chunks[h.chunkIdx] != nil:
		// Identical duplicate; drop.
		return nil, false
	}
	cp := make([]byte, len(payload))
	copy(cp, payload)
	e.chunks[h.chunkIdx] = cp
	e.received++
	if e.received < int(e.total) {
		return nil, false
	}

	total := 0
	for _, c := range e.chunks {
		total += len(c)
	}
	out := make([]byte, total)
	off := 0
	for _, c := range e.chunks {
		off += copy(out[off:], c)
	}
	g.dropEntryLocked(key)
	return out, true
}

// geckoChunkFits reports whether a chunk can belong to the message whose
// chunks e holds. Every Gecko sender (Xray, Hysteria, sing-quic) splits an
// n-byte message into chunks of n/chunks bytes and gives the remainder to the
// last one, so the other chunks share one length s and the last one has s to
// s+chunks-1 bytes. A repeated index must carry the same bytes; padding is
// already stripped.
func geckoChunkFits(e *reassemblyEntry, idx uint8, payload []byte) bool {
	if stored := e.chunks[idx]; stored != nil {
		return bytes.Equal(stored, payload)
	}
	last := len(e.chunks) - 1
	base, lastLen := -1, -1
	if int(idx) == last {
		lastLen = len(payload)
	} else {
		base = len(payload)
	}
	for i, chunk := range e.chunks {
		switch {
		case chunk == nil:
		case i == last:
			lastLen = len(chunk)
		case base < 0:
			base = len(chunk)
		case len(chunk) != base:
			return false
		}
	}
	return base < 0 || lastLen < 0 || lastLen >= base && lastLen <= base+last
}

func (g *geckoConn) gcLoop() {
	t := time.NewTicker(geckoReassemblyTTL / 2)
	defer t.Stop()
	for {
		select {
		case <-g.closeCh:
			return
		case now := <-t.C:
			g.gcExpired(now)
		}
	}
}

func (g *geckoConn) gcExpired(now time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for k, e := range g.reassembly {
		if now.After(e.deadline) {
			g.dropEntryLocked(k)
		}
	}
}

func (g *geckoConn) dropEntryLocked(k reassemblyKey) {
	if _, ok := g.reassembly[k]; !ok {
		return
	}
	delete(g.reassembly, k)
	g.perSource[k.addr]--
	if g.perSource[k.addr] <= 0 {
		delete(g.perSource, k.addr)
	}
}

func (g *geckoConn) evictOldestLocked() {
	var oldestKey reassemblyKey
	var oldestDeadline time.Time
	first := true
	for k, e := range g.reassembly {
		if first || e.deadline.Before(oldestDeadline) {
			oldestKey = k
			oldestDeadline = e.deadline
			first = false
		}
	}
	if !first {
		g.dropEntryLocked(oldestKey)
	}
}

func (g *geckoConn) Close() error {
	g.closeOnce.Do(func() { close(g.closeCh) })
	return g.PacketConn.Close()
}
