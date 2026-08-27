package xdns

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/binary"
	go_errors "errors"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/transport/internet/finalmask"
)

const (
	numPadding          = 3
	numPaddingForPoll   = 8
	initPollDelay       = 500 * time.Millisecond
	maxPollDelay        = 10 * time.Second
	pollDelayMultiplier = 2.0
	pollLimit           = 16
)

var (
	// Vars so tests can tighten them; treat as constants in production.
	queueWriteCap      = 256
	enqueueBlockWindow = 20 * time.Millisecond

	errQueueFull     = go_errors.New("xdns write queue full")
	errShortBuffer   = go_errors.New("xdns read buffer too small")
	errPayloadTooBig = go_errors.New("xdns payload exceeds encoder limit")
)

var base32Encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

type packet struct {
	p    []byte
	addr net.Addr
}

type xdnsConnClient struct {
	net.PacketConn

	resolverAddrs []*net.UDPAddr
	resolverTypes []uint16
	// resolverIdx selects the next outbound resolver; written only by
	// sendLoop, read by WriteTo callers.
	resolverIdx atomic.Uint32
	// maxPayload[i] is the largest payload encodable for resolver i.
	maxPayload   []int
	resolverSend map[string]*atomic.Uint32

	clientID []byte
	domains  []Name

	pollChan   chan struct{}
	readQueue  chan *packet
	writeQueue chan *packet

	closed atomic.Bool
	mutex  sync.Mutex
}

func NewConnClient(c *Config, raw net.PacketConn) (net.PacketConn, error) {
	if len(c.Resolvers) == 0 {
		return nil, errors.New("empty resolvers")
	}

	var domains []Name
	var servers []string
	var resolverTypes []uint16
	for _, rs := range c.Resolvers {
		domain, server, resolverType, err := parseResolver(rs)
		if err != nil {
			return nil, errors.New("invalid resolvers").Base(err)
		}
		domains = append(domains, domain)
		servers = append(servers, server)
		resolverTypes = append(resolverTypes, resolverType)
	}

	var resolverAddrs []*net.UDPAddr
	resolverSend := make(map[string]*atomic.Uint32)
	for _, rs := range servers {
		h, p, err := net.SplitHostPort(rs)
		if err != nil {
			return nil, err
		}
		ip := net.ParseIP(h)
		if ip == nil {
			return nil, errors.New("invalid ip address")
		}
		port, err := strconv.Atoi(p)
		if err != nil {
			return nil, errors.New("invalid port").Base(err)
		}
		addr := &net.UDPAddr{IP: ip, Port: port}
		resolverAddrs = append(resolverAddrs, addr)
		resolverSend[addr.String()] = &atomic.Uint32{}
	}

	conn := &xdnsConnClient{
		PacketConn: raw,

		resolverAddrs: resolverAddrs,
		resolverTypes: resolverTypes,
		resolverSend:  resolverSend,
		maxPayload:    make([]int, len(resolverTypes)),

		clientID: make([]byte, 8),
		domains:  domains,

		pollChan:   make(chan struct{}, pollLimit),
		readQueue:  make(chan *packet, queueWriteCap),
		writeQueue: make(chan *packet, queueWriteCap),
	}

	common.Must2(rand.Read(conn.clientID))

	// Measure the largest payload the encoder accepts per resolver suffix so
	// oversize frames are rejected up front with a typed error instead of
	// surfacing as a generic name-length failure mid-encode.
	for i, dom := range conn.domains {
		conn.maxPayload[i] = maxPayloadForDomain(dom, conn.clientID)
	}

	go conn.recvLoop()
	go conn.sendLoop()

	return conn, nil
}

func (c *xdnsConnClient) recvLoop() {
	var buf [finalmask.UDPSize]byte

	for {
		if c.closed.Load() {
			break
		}

		n, addr, err := c.PacketConn.ReadFrom(buf[:])
		if err != nil {
			if go_errors.Is(err, net.ErrClosed) {
				break
			}
			continue
		}

		if addr == nil {
			continue
		}

		send := c.resolverSend[addr.String()]
		if send == nil {
			continue
		}

		resp, err := MessageFromWireFormat(buf[:n])
		if err != nil {
			errors.LogDebug(context.Background(), addr, " xdns from wireformat err ", err)
			continue
		}

		payload := dnsResponsePayload(&resp, c.domains)

		r := bytes.NewReader(payload)
		anyPacket := false
		for {
			p, err := nextPacket(r)
			if err != nil {
				break
			}
			anyPacket = true

			buf := make([]byte, len(p))
			copy(buf, p)
			select {
			case c.readQueue <- &packet{
				p:    buf,
				addr: addr,
			}:
			default:
				errors.LogDebug(context.Background(), addr, " mask read err queue full")
			}
		}

		if anyPacket {
			send.Store(0)
			select {
			case c.pollChan <- struct{}{}:
			default:
			}
		}
	}

	errors.LogDebug(context.Background(), "xdns closed")

	close(c.pollChan)
	close(c.readQueue)

	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.closed.Store(true)
	close(c.writeQueue)
}

func (c *xdnsConnClient) sendLoop() {
	pollDelay := initPollDelay
	pollTimer := time.NewTimer(pollDelay)
	for {
		var p *packet
		pollTimerExpired := false

		select {
		case p = <-c.writeQueue:
		default:
			select {
			case p = <-c.writeQueue:
			case <-c.pollChan:
			case <-pollTimer.C:
				pollTimerExpired = true
			}
		}

		if p != nil {
			select {
			case <-c.pollChan:
			default:
			}
		} else {
			idx := c.resolverIdx.Load()
			encoded, _ := encode(nil, c.clientID, c.domains[idx], c.resolverTypes[idx])
			p = &packet{
				p: encoded,
			}
		}

		if pollTimerExpired {
			pollDelay = time.Duration(float64(pollDelay) * pollDelayMultiplier)
			if pollDelay > maxPollDelay {
				pollDelay = maxPollDelay
			}
		} else {
			if !pollTimer.Stop() {
				<-pollTimer.C
			}
			pollDelay = initPollDelay
		}
		pollTimer.Reset(pollDelay)

		if c.closed.Load() {
			return
		}

		// Single writer: cursor advances locally and is published once, so
		// concurrent WriteTo readers always observe a consistent slot.
		cur := c.resolverIdx.Load()
		curSend := c.resolverSend[c.resolverAddrs[cur].String()].Add(1)
		_, _ = c.PacketConn.WriteTo(p.p, c.resolverAddrs[cur])
		next := cur
		for {
			cand := (next + 1) % uint32(len(c.resolverAddrs))
			if cand == cur {
				break
			}
			if c.resolverSend[c.resolverAddrs[cand].String()].Load() < curSend {
				next = cand
				break
			}
		}
		c.resolverIdx.Store(next)
	}
}

func (c *xdnsConnClient) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	packet, ok := <-c.readQueue
	if !ok {
		return 0, nil, net.ErrClosed
	}
	if len(p) < len(packet.p) {
		errors.LogDebug(context.Background(), packet.addr, " mask read err short buffer ", len(p), " ", len(packet.p))
		return 0, packet.addr, errShortBuffer
	}
	copy(p, packet.p)
	return len(packet.p), packet.addr, nil
}

func (c *xdnsConnClient) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.closed.Load() {
		return 0, io.ErrClosedPipe
	}

	idx := c.resolverIdx.Load() % uint32(len(c.resolverAddrs))
	if len(p) > c.maxPayload[idx] {
		errors.LogDebug(context.Background(), addr, " xdns payload too large ", len(p), " > ", c.maxPayload[idx])
		return 0, errPayloadTooBig
	}
	encoded, err := encode(p, c.clientID, c.domains[idx], c.resolverTypes[idx])
	if err != nil {
		errors.LogDebug(context.Background(), addr, " xdns wireformat err ", err, " ", len(p))
		return 0, err
	}

	// Bounded block: give the pipeline a short window to drain instead of
	// dropping silently, then report the loss to the caller.
	timer := time.NewTimer(enqueueBlockWindow)
	defer timer.Stop()
	select {
	case c.writeQueue <- &packet{
		p:    encoded,
		addr: addr,
	}:
		return len(p), nil
	case <-timer.C:
		errors.LogDebug(context.Background(), addr, " mask write err queue full")
		return 0, errQueueFull
	}
}

func (c *xdnsConnClient) Close() error {
	c.closed.Store(true)
	return c.PacketConn.Close()
}

func encode(p []byte, clientID []byte, domain Name, qtype uint16) ([]byte, error) {
	var decoded []byte
	{
		// Payload size is bounded by the measured per-resolver limit checked
		// in WriteTo; oversized input fails inside NewName below.
		var buf bytes.Buffer
		buf.Write(clientID[:])
		n := numPadding
		if len(p) == 0 {
			n = numPaddingForPoll
		}
		buf.WriteByte(byte(224 + n))
		_, _ = io.CopyN(&buf, rand.Reader, int64(n))
		if len(p) > 0 {
			buf.WriteByte(byte(len(p)))
			buf.Write(p)
		}
		decoded = buf.Bytes()
	}

	encoded := make([]byte, base32Encoding.EncodedLen(len(decoded)))
	base32Encoding.Encode(encoded, decoded)
	encoded = bytes.ToLower(encoded)
	labels := chunks(encoded, 63)
	labels = append(labels, domain...)
	name, err := NewName(labels)
	if err != nil {
		return nil, err
	}

	var id uint16
	_ = binary.Read(rand.Reader, binary.BigEndian, &id)
	query := &Message{
		ID:    id,
		Flags: 0x0100,
		Question: []Question{
			{
				Name:  name,
				Type:  qtype,
				Class: ClassIN,
			},
		},
		Additional: []RR{
			{
				Name:  Name{},
				Type:  RRTypeOPT,
				Class: 4096,
				TTL:   0,
				Data:  []byte{},
			},
		},
	}

	buf, err := query.WireFormat()
	if err != nil {
		return nil, err
	}

	return buf, nil
}

// maxPayloadForDomain measures the largest payload the encoder accepts for a
// resolver suffix, so oversize frames are rejected with a typed error instead
// of failing inside NewName.
func maxPayloadForDomain(domain Name, clientID []byte) int {
	lo, hi := 0, 4096
	for lo+1 < hi {
		mid := (lo + hi) / 2
		if _, err := encode(make([]byte, mid), clientID, domain, RRTypeTXT); err == nil {
			lo = mid
		} else {
			hi = mid
		}
	}
	return lo
}

func chunks(p []byte, n int) [][]byte {
	var result [][]byte
	for len(p) > 0 {
		sz := len(p)
		if sz > n {
			sz = n
		}
		result = append(result, p[:sz])
		p = p[sz:]
	}
	return result
}

func nextPacket(r *bytes.Reader) ([]byte, error) {
	var n uint16
	err := binary.Read(r, binary.BigEndian, &n)
	if err != nil {
		return nil, err
	}
	p := make([]byte, n)
	_, err = io.ReadFull(r, p)
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return p, err
}

func dnsResponsePayload(resp *Message, domains []Name) []byte {
	if resp.Flags&0x8000 != 0x8000 {
		return nil
	}
	if resp.Flags&0x000f != RcodeNoError {
		return nil
	}

	if len(resp.Answer) == 0 {
		return nil
	}

	for _, answer := range resp.Answer {
		var ok bool
		for _, domain := range domains {
			_, ok = answer.Name.TrimSuffix(domain)
			if ok {
				break
			}
		}
		if !ok {
			return nil
		}
	}

	return decodeResponsePayload(resp.Answer)
}
