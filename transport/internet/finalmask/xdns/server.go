package xdns

import (
	"context"
	goerrors "errors"
	"io"
	stdnet "net"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"golang.org/x/net/dns/dnsmessage"
)

const (
	maxResponseDelay = time.Second

	recvBackoffMin = 10 * time.Millisecond
	recvBackoffMax = time.Second

	// rcodeBadVersion is BADVERS, whose upper bits travel in the OPT record
	// (RFC 6891).
	rcodeBadVersion dnsmessage.RCode = 16
)

type resp struct {
	msg  dnsmessage.Message
	addr net.Addr
	// limit is the length of the query; the reply must not outgrow it.
	limit int
}

type Rec struct {
	resp     *Resp
	clientID ClientID
	addr     net.Addr
}

type xdnsServer struct {
	net.PacketConn

	domains     []*Domain
	fragManager *FragManager
	sendManager *SendManager

	readCh  chan packet
	recCh   chan *Rec
	drCh    chan resp
	closeCh chan struct{}
	wg      sync.WaitGroup
	mu      sync.RWMutex
}

func NewServer(c *Config, raw net.PacketConn) (net.PacketConn, error) {
	if len(c.Domains) == 0 {
		return nil, errors.New("empty domains")
	}
	domains := make([]*Domain, 0, len(c.Domains))
	for i := range c.Domains {
		types := make([]uint16, 0, len(c.Domains[i].Types))
		for j := range c.Domains[i].Types {
			types = append(types, uint16(c.Domains[i].Types[j]))
		}
		if len(types) == 0 {
			types = []uint16{1, 5, 16, 28}
		}
		domain, err := NewDomain(c.Domains[i].Name, int(c.Domains[i].LenLimit), int(c.Domains[i].LabelLimit), types, uint16(c.Domains[i].Edns0))
		if err != nil {
			return nil, err
		}
		domains = append(domains, domain)
	}
	server := &xdnsServer{
		PacketConn: raw,

		domains:     domains,
		fragManager: NewFragManager(),
		sendManager: NewSendManager(),

		readCh: make(chan packet),
		recCh:  make(chan *Rec, 255),
		// queueReply never blocks the receive loop; buffer error replies so a
		// busy writer drops them only when this bounded queue is full.
		drCh:    make(chan resp, 128),
		closeCh: make(chan struct{}),
	}
	go server.run()
	return server, nil
}

func (c *xdnsServer) closed() bool {
	select {
	case <-c.closeCh:
		return true
	default:
		return false
	}
}

// queueReply queues the reply to a query the server answers without tunnel data.
// The reply carries only the header, the single question and, when the query
// used EDNS, an OPT record of the server's, which holds the upper bits of
// rcode: echoing the query's other records would let a spoofed query draw a
// reply larger than itself. It is not a full authoritative answer: there is
// no SOA in the authority section, and the OPT payload size mirrors the
// query's. queueReply never blocks the receive loop, so the reply is dropped when
// the reply queue is full.
func (c *xdnsServer) queueReply(query *dnsmessage.Message, rcode dnsmessage.RCode, authoritative bool, limit int, addr net.Addr) {
	reply := dnsmessage.Message{Header: dnsmessage.Header{
		ID:               query.Header.ID,
		Response:         true,
		OpCode:           query.Header.OpCode,
		Authoritative:    authoritative,
		RecursionDesired: query.Header.RecursionDesired,
		CheckingDisabled: query.Header.CheckingDisabled,
		RCode:            rcode & 0xF,
	}}
	if len(query.Questions) == 1 {
		reply.Questions = query.Questions
	}
	for i := range query.Additionals {
		if query.Additionals[i].Header.Type != dnsmessage.TypeOPT {
			continue
		}
		var opt dnsmessage.ResourceHeader
		size := min(max(int(query.Additionals[i].Header.Class), 512), 4096)
		if err := opt.SetEDNS0(size, rcode, query.Additionals[i].Header.DNSSECAllowed()); err == nil {
			reply.Additionals = []dnsmessage.Resource{{Header: opt, Body: &dnsmessage.OPTResource{}}}
		}
		break
	}
	select {
	case c.drCh <- resp{msg: reply, addr: addr, limit: limit}:
	default:
	}
}

func (c *xdnsServer) read(buf []byte, addr net.Addr) {
	msg := dnsmessage.Message{}
	if err := msg.Unpack(buf); err != nil {
		return
	}
	if msg.Header.Response {
		return
	}
	answer := func(rcode dnsmessage.RCode, authoritative bool) {
		c.queueReply(&msg, rcode, authoritative, len(buf), addr)
	}

	if msg.Header.OpCode != 0 {
		answer(dnsmessage.RCodeNotImplemented, false)
		return
	}

	if len(msg.Questions) != 1 {
		answer(dnsmessage.RCodeFormatError, false)
		return
	}

	opt := false
	edns0 := uint16(0)
	for i := range msg.Additionals {
		if msg.Additionals[i].Header.Type == dnsmessage.TypeOPT {
			if opt {
				answer(dnsmessage.RCodeFormatError, false)
				return
			}
			opt = true
			edns0 = uint16(msg.Additionals[i].Header.Class)
			if ver := (msg.Additionals[i].Header.TTL >> 16) & 0xFF; ver != 0 {
				answer(rcodeBadVersion, false)
				return
			}
		}
	}
	if opt {
		if edns0 < 512 {
			edns0 = 512
		}
		if edns0 > 4096 {
			edns0 = 4096
		}
	}
	errors.LogDebug(context.Background(), addr, " edns0 ", edns0, " buf ", len(buf), " ", msg.Questions[0].Type)

	var domain *Domain
	for i := range c.domains {
		if c.domains[i].IsDomain(msg.Questions[0].Name) {
			domain = c.domains[i]
			break
		}
	}
	if domain == nil {
		for i := range c.domains {
			if c.domains[i].IsApex(msg.Questions[0].Name) {
				// The apex exists like every name in the zone; NXDOMAIN
				// would deny the whole zone below it (RFC 8020).
				answer(dnsmessage.RCodeSuccess, true)
				return
			}
		}
		answer(dnsmessage.RCodeNameError, false)
		return
	}
	if !domain.HasType(uint16(msg.Questions[0].Type)) {
		answer(dnsmessage.RCodeSuccess, true)
		return
	}

	var decoded [255]byte
	n := domain.Decode(&decoded, msg.Questions[0].Name)
	if n < 9 {
		answer(dnsmessage.RCodeSuccess, true)
		return
	}
	if TypeMap_[decoded[0]&3] != uint16(msg.Questions[0].Type) || (decoded[8]&0x3F != 3 && decoded[8]&0x3F != 8) || (decoded[8]&0x3F == 3 && n < 9+3+1) || (decoded[8]&0xC0 == 0xC0 && n < 9+3+3+1) || (decoded[8]&0x3F == 8 && n != 9+8) {
		answer(dnsmessage.RCodeSuccess, true)
		return
	}
	clientID := ClientIDFromRaw([8]byte(decoded[:8]))

	r := NewResp(msg, domain, edns0)
	if r == nil {
		answer(dnsmessage.RCodeSuccess, true)
		return
	}
	select {
	case c.recCh <- &Rec{resp: r, clientID: clientID, addr: addr}:
	default:
		answer(dnsmessage.RCodeSuccess, true)
	}

	if decoded[8]&0x3F == 8 {
		return
	}
	p := pool4K.Get().([]byte)
	p = p[:0]
	if decoded[8]&0xC0 == 0xC0 {
		out := pool4K.Get().([]byte)
		n := c.fragManager.Feed(out, FragKey{clientID: clientID, fragID: decoded[12]}, decoded[13], decoded[14], decoded[15:n])
		pool4K.Put(p[:cap(p)])
		if n > 0 {
			p = out[:n]
		} else {
			pool4K.Put(out[:cap(out)])
			return
		}
	} else {
		p = append(p, decoded[12:n]...)
	}
	select {
	case <-c.closeCh:
		pool4K.Put(p[:cap(p)])
		return
	case c.readCh <- packet{p: p, addr: clientID.Addr()}:
		return
	}
}

func (c *xdnsServer) run() {
	c.wg.Add(1)
	go c.recv()

	c.wg.Add(1)
	go c.send()

	c.wg.Add(1)
	go c.dr()

	c.wg.Wait()
	close(c.readCh)
	close(c.recCh)
	close(c.drCh)
	c.fragManager.Close()
	c.sendManager.Close()
}

func (c *xdnsServer) recv() {
	defer c.wg.Done()

	var buf [512]byte
	backoff := time.Duration(0)
	for {
		n, addr, err := c.PacketConn.ReadFrom(buf[:])
		if err != nil {
			if c.closed() || goerrors.Is(err, stdnet.ErrClosed) {
				return
			}
			// One failed read must not stop the server; back off so a
			// persistent error cannot spin a core.
			backoff = min(max(2*backoff, recvBackoffMin), recvBackoffMax)
			errors.LogWarningInner(context.Background(), err, "recv err, retrying in ", backoff)
			select {
			case <-c.closeCh:
				return
			case <-time.After(backoff):
			}
			continue
		}
		backoff = 0
		c.read(buf[:n], addr)
	}
}

func (c *xdnsServer) send() {
	defer c.wg.Done()

	timer := time.NewTimer(maxResponseDelay)
	timer.Stop()
	var buf [4096]byte
	var data [4096]byte
	var nextRec *Rec
	for {
		rec := nextRec
		nextRec = nil

		if rec == nil {
			select {
			case rec = <-c.recCh:
			case <-c.closeCh:
				return
			}
		}

		ch, stash, ok := c.sendManager.Pop(rec.clientID)
		if !ok {
			// The queues are closed: answer at once without data.
			_, _ = c.PacketConn.WriteTo(rec.resp.Encode(buf[:0], nil), rec.addr)
			continue
		}
		left := rec.resp.cap
		timer.Reset(maxResponseDelay)
		var ps [][]byte
		for {
			var p []byte
			select {
			case p = <-stash:
			default:
				select {
				case p = <-stash:
				case p = <-ch:
				default:
					select {
					case p = <-stash:
					case p = <-ch:
					case <-timer.C:
					case nextRec = <-c.recCh:
					}
				}
			}
			if len(p) == 0 {
				break
			}
			timer.Reset(0)
			left -= 2 + len(p)
			if left < 0 {
				if len(ps) == 0 {
					errors.LogError(context.Background(), "err size ", len(p))
					break
				}
				c.sendManager.Stash(rec.clientID, p)
				break
			}
			ps = append(ps, p)
		}
		timer.Stop()

		d := data[:0]
		for i := range ps {
			l := len(ps[i])
			if i == len(ps)-1 {
				l |= 0xC000
			}
			d = append(d, []byte{byte(l >> 8), byte(l)}...)
			d = append(d, ps[i]...)
		}
		_, _ = c.PacketConn.WriteTo(rec.resp.Encode(buf[:0], d), rec.addr)
	}
}

func (c *xdnsServer) dr() {
	defer c.wg.Done()

	var buf [512]byte
	for {
		select {
		case <-c.closeCh:
			return
		case r := <-c.drCh:
			b, err := r.msg.AppendPack(buf[:0])
			if err != nil || len(b) > r.limit {
				errors.LogDebug(context.Background(), r.addr, " reply dropped: ", len(b), " bytes for a ", r.limit, "-byte query, err ", err)
				continue
			}
			_, _ = c.PacketConn.WriteTo(b, r.addr)
		}
	}
}

func (c *xdnsServer) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	packet, ok := <-c.readCh
	if ok {
		n = copy(p, packet.p)
		pool4K.Put(packet.p[:cap(packet.p)])
		return n, packet.addr, nil
	}
	return 0, nil, io.ErrClosedPipe
}

func (c *xdnsServer) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if c.closed() {
		return 0, io.ErrClosedPipe
	}
	if len(p) == 0 || len(p) > 4096 {
		errors.LogError(context.Background(), "err size ", len(p))
		return 0, errors.New("err size")
	}
	c.sendManager.Push(ClientIDFromAddr(addr.(*net.UDPAddr)), p)
	return len(p), nil
}

func (c *xdnsServer) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed() {
		return nil
	}
	close(c.closeCh)
	_ = c.PacketConn.Close()
	return nil
}

func (c *xdnsServer) SetDeadline(t time.Time) error { return errors.New("not support") }

func (c *xdnsServer) SetReadDeadline(t time.Time) error { return errors.New("not support") }

func (c *xdnsServer) SetWriteDeadline(t time.Time) error { return errors.New("not support") }
