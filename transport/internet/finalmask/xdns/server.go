package xdns

import (
	"bytes"
	"context"
	"encoding/binary"
	go_errors "errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

const (
	responseTTL = 60
)

// Vars so tests can tighten them; treat as constants in production.
var (
	idleTimeout      = 10 * time.Second
	maxResponseDelay = 1 * time.Second

	// Vars so tests can tighten them; treat as constants in production.
	queueClientCap = 512
	queueStashCap  = 1

	recvErrBackoffBase = 10 * time.Millisecond
	recvErrBackoffMax  = time.Second
	// maxQueues bounds writeQueueMap cardinality. Keys are attacker-chosen
	// clientIDs decoded from query labels, so the table must be capped;
	// otherwise a unique-ID flood pins unbounded memory on a pre-auth
	// surface. Over-limit clients are refused until entries idle out.
	maxQueues = 256
)

var errQueueLimitReached = go_errors.New("xdns per-client queue limit reached")

// maxUDPPayload bounds the on-wire response; the per-type encoded payload
// ceilings live behind the lazily evaluated limitsOnce in record_transport.go.
var maxUDPPayload = 1280 - 40 - 8

// recvErrorBackoff spaces out consecutive transient UDP read failures on the
// receive loops exponentially, capped, so a flapping interface cannot spin a
// core at 100%%.
func recvErrorBackoff(consecutive int) time.Duration {
	if consecutive <= 0 {
		return 0
	}
	d := recvErrBackoffBase
	for ; consecutive > 1; consecutive-- {
		d *= 2
		if d >= recvErrBackoffMax {
			return recvErrBackoffMax
		}
	}
	return d
}

func clientIDToAddr(clientID [8]byte) *net.UDPAddr {
	ip := make(net.IP, 16)

	copy(ip, []byte{0xfd, 0x00, 0, 0, 0, 0, 0, 0})
	copy(ip[8:], clientID[:])

	return &net.UDPAddr{
		IP: ip,
	}
}

type record struct {
	Resp *Message
	Addr net.Addr
	// ClientID [8]byte
	ClientAddr net.Addr
}

type queue struct {
	last time.Time
	// dead is set before the channels are closed so consumers can tell a
	// pruned queue from an expired batch timer.
	dead   atomic.Bool
	rrType uint16
	queue  chan []byte
	stash  chan []byte
}

type xdnsConnServer struct {
	net.PacketConn

	domains []domainSpec

	ch            chan *record
	readQueue     chan *packet
	writeQueueMap map[string]*queue

	closed atomic.Bool
	mutex  sync.Mutex
}

func NewConnServer(c *Config, raw net.PacketConn) (net.PacketConn, error) {
	if len(c.Domains) == 0 {
		return nil, errors.New("empty domains")
	}
	domains := make([]domainSpec, 0, len(c.Domains))
	for _, domain := range c.Domains {
		domain, err := parseDomainSpec(domain, "")
		if err != nil {
			return nil, err
		}
		domains = append(domains, domain)
	}

	conn := &xdnsConnServer{
		PacketConn: raw,

		domains: domains,

		ch:            make(chan *record, 500),
		readQueue:     make(chan *packet, 512),
		writeQueueMap: make(map[string]*queue),
	}

	go conn.clean()
	go conn.recvLoop()
	go conn.sendLoop()

	return conn, nil
}

func (c *xdnsConnServer) clean() {
	f := func() bool {
		c.mutex.Lock()
		defer c.mutex.Unlock()

		if c.closed.Load() {
			return true
		}

		now := time.Now()

		for key, q := range c.writeQueueMap {
			if now.Sub(q.last) >= idleTimeout {
				closeQueueLocked(q)
				delete(c.writeQueueMap, key)
			}
		}

		return false
	}

	for {
		time.Sleep(idleTimeout / 2)
		if f() {
			return
		}
	}
}

// lookupOrCreateQueue returns the per-client write queue, creating it on
// demand. When the table is full it reports refused=true; closed-shutdown is
// reported as q==nil with refused=false, matching the historical contract.
func (c *xdnsConnServer) lookupOrCreateQueue(addr net.Addr) (*queue, bool) {
	if c.closed.Load() {
		return nil, false
	}

	key := addr.String()
	q, ok := c.writeQueueMap[key]
	if !ok {
		if len(c.writeQueueMap) >= maxQueues {
			return nil, true
		}
		q = &queue{
			queue: make(chan []byte, queueClientCap),
			stash: make(chan []byte, queueStashCap),
		}
		c.writeQueueMap[key] = q
	}
	q.last = time.Now()

	return q, false
}

// closeQueueLocked retires a per-client queue. Callers hold c.mutex.
func closeQueueLocked(q *queue) {
	q.dead.Store(true)
	close(q.queue)
	close(q.stash)
}

func (c *xdnsConnServer) stash(queue *queue, p []byte) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.closed.Load() || queue.dead.Load() {
		return
	}

	select {
	case queue.stash <- p:
	default:
	}
}

func (c *xdnsConnServer) recvLoop() {
	var buf [finalmask.UDPSize]byte

	consecFails := 0
	for {
		if c.closed.Load() {
			break
		}

		n, addr, err := c.PacketConn.ReadFrom(buf[:])
		if err != nil {
			if go_errors.Is(err, net.ErrClosed) {
				break
			}
			consecFails++
			time.Sleep(recvErrorBackoff(consecFails))
			continue
		}
		consecFails = 0

		query, err := MessageFromWireFormat(buf[:n])
		if err != nil {
			errors.LogDebug(context.Background(), addr, " xdns from wireformat err ", err)
			continue
		}

		resp, payload := responseFor(&query, c.domains)

		var clientID [8]byte
		n = copy(clientID[:], payload)
		payload = payload[n:]
		if n == len(clientID) {
			r := bytes.NewReader(payload)
			for {
				p, err := nextPacketServer(r)
				if err != nil {
					break
				}

				buf := make([]byte, len(p))
				copy(buf, p)
				select {
				case c.readQueue <- &packet{
					p:    buf,
					addr: clientIDToAddr(clientID),
				}:
				default:
					errors.LogDebug(context.Background(), addr, " ", clientID, " mask read err queue full")
				}
			}
		} else {
			if resp != nil && resp.Rcode() == RcodeNoError {
				resp.Flags |= RcodeNameError
			}
		}

		if resp != nil {
			select {
			case c.ch <- &record{resp, addr, clientIDToAddr(clientID)}:
			default:
				errors.LogDebug(context.Background(), addr, " ", clientID, " mask read err record queue full")
			}
		}
	}

	errors.LogDebug(context.Background(), "xdns closed")

	close(c.ch)
	close(c.readQueue)

	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.closed.Store(true)
	for key, q := range c.writeQueueMap {
		closeQueueLocked(q)
		delete(c.writeQueueMap, key)
	}
}

type groupAction int

const (
	groupEmit groupAction = iota // answers prepared on rec; send it
	groupDrop                    // skip this record without a response
	groupStop                    // connection closing; terminate the loop
)

// payloadChunkPrefix is the two-byte little-endian length header in front of
// every queued chunk.
const payloadChunkPrefix = 2

// groupRecord batches queued chunks for rec into a single answer set,
// preserving the original receive ladder. The batch window is armed once and
// left to expire naturally so stale timers cannot collapse mid-batch
// collection.
func (c *xdnsConnServer) groupRecord(rec *record) (pending *record, action groupAction) {
	payload := &bytes.Buffer{}
	limit := maxEncodedPayloadForType(rec.Resp.Question[0].Type)
	timer := time.NewTimer(maxResponseDelay)
	defer timer.Stop()

	dropped, gotAny := false, false
	for {
		c.mutex.Lock()
		q, refused := c.lookupOrCreateQueue(rec.ClientAddr)
		if q == nil {
			c.mutex.Unlock()
			if refused {
				errors.LogDebug(context.Background(), rec.Addr, " ", rec.ClientAddr, " xdns queue limit reached, dropping response")
				return nil, groupDrop
			}
			return nil, groupStop
		}
		q.rrType = rec.Resp.Question[0].Type
		c.mutex.Unlock()

		var p []byte
		select {
		case p = <-q.stash:
		default:
			select {
			case p = <-q.stash:
			case p = <-q.queue:
			default:
				select {
				case p = <-q.stash:
				case p = <-q.queue:
				case <-timer.C:
				case pending = <-c.ch:
				}
			}
		}

		if q.dead.Load() {
			// Queue was idle-pruned mid-batch; anything built from reads on
			// closed channels would be an empty artifact answer.
			errors.LogDebug(context.Background(), rec.Addr, " ", rec.ClientAddr, " xdns queue pruned mid-batch, dropping response")
			dropped = true
			break
		}

		if len(p) == 0 {
			break
		}

		limit -= payloadChunkPrefix + len(p)
		if limit < 0 {
			if payload.Len() == 0 {
				errors.LogDebug(context.Background(), rec.Addr, " ", rec.ClientAddr, " xdns payload too large for rrtype ", rec.Resp.Question[0].Type, " ", len(p))
			} else {
				c.stash(q, p)
			}
			break
		}

		_ = binary.Write(payload, binary.BigEndian, uint16(len(p)))
		payload.Write(p)
		gotAny = true
	}

	if dropped || !gotAny {
		// Suppress empty-answer artifacts: pruned or drained queues must not
		// yield NOERROR records with zero chunks.
		return pending, groupDrop
	}

	answer, err := answersForPayload(rec.Resp.Question[0], responseTTL, payload.Bytes())
	if err != nil {
		errors.LogDebug(context.Background(), rec.Addr, " ", rec.ClientAddr, " xdns encode err ", err)
		return pending, groupDrop
	}
	rec.Resp.Answer = answer
	return pending, groupEmit
}

func (c *xdnsConnServer) sendLoop() {
	var nextRec *record
	for {
		var err error
		rec := nextRec
		nextRec = nil

		if rec == nil {
			var ok bool
			rec, ok = <-c.ch
			if !ok {
				break
			}
		}

		if rec.Resp.Rcode() == RcodeNoError && len(rec.Resp.Question) == 1 {
			prefetched, act := c.groupRecord(rec)
			nextRec = prefetched
			switch act {
			case groupStop:
				return
			case groupDrop:
				continue
			}
		}

		buf, err := rec.Resp.WireFormat()
		if err != nil {
			errors.LogDebug(context.Background(), rec.Addr, " ", rec.ClientAddr, " xdns wireformat err ", err)
			continue
		}

		if len(buf) > maxUDPPayload {
			errors.LogDebug(context.Background(), rec.Addr, " ", rec.ClientAddr, " xdns truncate ", len(buf))
			buf = buf[:maxUDPPayload]
			buf[2] |= 0x02
		}

		if c.closed.Load() {
			return
		}

		_, err = c.PacketConn.WriteTo(buf, rec.Addr)
		if go_errors.Is(err, net.ErrClosed) {
			c.closed.Store(true)
			break
		}
	}
}

func (c *xdnsConnServer) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	packet, ok := <-c.readQueue
	if !ok {
		return 0, nil, net.ErrClosed
	}
	if len(p) < len(packet.p) {
		errors.LogDebug(context.Background(), packet.addr, " mask read err short buffer ", len(p), " ", len(packet.p))
		return 0, packet.addr, nil
	}
	copy(p, packet.p)
	return len(packet.p), packet.addr, nil
}

func (c *xdnsConnServer) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	q, refused := c.lookupOrCreateQueue(addr)
	if q == nil {
		if refused {
			return 0, errQueueLimitReached
		}
		return 0, io.ErrClosedPipe
	}
	limit := maxEncodedPayloadForType(q.rrType)
	if q.rrType == 0 {
		limit = maxEncodedPayloadForType(RRTypeTXT)
	}
	if len(p)+2 > limit {
		errors.LogDebug(context.Background(), addr, " mask write err short write ", len(p), "+2 > ", limit)
		return 0, errPayloadTooBig
	}

	buf := make([]byte, len(p))
	copy(buf, p)

	// Bounded block mirrors the client side: never drop silently.
	timer := time.NewTimer(enqueueBlockWindow)
	defer timer.Stop()
	select {
	case q.queue <- buf:
		return len(p), nil
	case <-timer.C:
		errors.LogDebug(context.Background(), addr, " mask write err queue full")
		return 0, errQueueFull
	}
}

func (c *xdnsConnServer) Close() error {
	c.closed.Store(true)
	return c.PacketConn.Close()
}

func nextPacketServer(r *bytes.Reader) ([]byte, error) {
	eof := func(err error) error {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return err
	}

	for {
		prefix, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		if prefix >= 224 {
			paddingLen := prefix - 224
			_, err := io.CopyN(io.Discard, r, int64(paddingLen))
			if err != nil {
				return nil, eof(err)
			}
		} else {
			p := make([]byte, int(prefix))
			_, err = io.ReadFull(r, p)
			return p, eof(err)
		}
	}
}

func responseFor(query *Message, domains []domainSpec) (*Message, []byte) {
	resp := &Message{
		ID:       query.ID,
		Flags:    0x8000,
		Question: query.Question,
	}

	if query.Flags&0x8000 != 0 {
		return nil, nil
	}

	payloadSize := 0
	for _, rr := range query.Additional {
		if rr.Type != RRTypeOPT {
			continue
		}
		if len(resp.Additional) != 0 {
			resp.Flags |= RcodeFormatError
			return resp, nil
		}
		resp.Additional = append(resp.Additional, RR{
			Name:  Name{},
			Type:  RRTypeOPT,
			Class: 4096,
			TTL:   0,
			Data:  []byte{},
		})
		additional := &resp.Additional[0]

		version := (rr.TTL >> 16) & 0xff
		if version != 0 {
			resp.Flags |= ExtendedRcodeBadVers & 0xf
			additional.TTL = (ExtendedRcodeBadVers >> 4) << 24
			return resp, nil
		}

		payloadSize = int(rr.Class)
	}
	if payloadSize < 512 {
		payloadSize = 512
	}

	if len(query.Question) != 1 {
		resp.Flags |= RcodeFormatError
		return resp, nil
	}
	question := query.Question[0]

	var (
		prefix Name
		ok     bool
		match  domainSpec
	)
	for _, domain := range domains {
		prefix, ok = question.Name.TrimSuffix(domain.name)
		if ok {
			match = domain
			break
		}
	}
	if !ok {
		resp.Flags |= RcodeNameError
		return resp, nil
	}
	resp.Flags |= 0x0400

	if query.Opcode() != 0 {
		resp.Flags |= RcodeNotImplemented
		return resp, nil
	}

	switch question.Type {
	case RRTypeTXT, RRTypeA, RRTypeAAAA:
	default:
		resp.Flags |= RcodeNameError
		return resp, nil
	}
	if match.rrType != 0 && question.Type != match.rrType {
		resp.Flags |= RcodeNameError
		return resp, nil
	}

	encoded := bytes.ToUpper(bytes.Join(prefix, nil))
	payload := make([]byte, base32Encoding.DecodedLen(len(encoded)))
	n, err := base32Encoding.Decode(payload, encoded)
	if err != nil {
		resp.Flags |= RcodeNameError
		return resp, nil
	}
	payload = payload[:n]

	if payloadSize < maxUDPPayload {
		resp.Flags |= RcodeFormatError
		return resp, nil
	}

	return resp, payload
}
