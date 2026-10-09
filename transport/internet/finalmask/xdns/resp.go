package xdns

import (
	"container/list"
	"sort"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"golang.org/x/net/dns/dnsmessage"
)

const (
	sendTTL = 4 * time.Second
	// sendClientCount caps the per-client queues, whose keys come from
	// unauthenticated queries.
	sendClientCount = 4096
)

type Resp struct {
	msg    dnsmessage.Message
	domain *Domain
	edns0  uint16

	cap int
}

func NewResp(msg dnsmessage.Message, domain *Domain, edns0 uint16) *Resp {
	if msg.Header.Response {
		return &Resp{
			msg:    msg,
			domain: domain,
		}
	}

	size := min(max(int(edns0), 512), max(int(domain.edns0), 512))

	left := size - 12 - int(msg.Questions[0].Name.Length) - 1 - 2 - 2
	if edns0 > 0 {
		left -= 1 + 2 + 2 + 4 + 2 + 0
	}
	cap := 0
	switch msg.Questions[0].Type {
	case dnsmessage.TypeA:
		single := 2 + 2 + 2 + 4 + 2 + 4
		n := left / single
		if n > 255 {
			n = 255
		}
		cap = 4*n - n - 1
	case dnsmessage.TypeCNAME:
		single := 2 + 2 + 2 + 4 + 2 + domain.lenMax
		n := left / single
		if n > 255 {
			n = 255
		}
		cap = domain.cap*n - n - 1
	case dnsmessage.TypeTXT:
		left -= 2 + 2 + 2 + 4 + 2
		single := 255
		n := left / single
		m := left % single
		cap = 255*n - n
		if m > 1 {
			cap += m - 1
		}
	case dnsmessage.TypeAAAA:
		single := 2 + 2 + 2 + 4 + 2 + 16
		n := left / single
		if n > 255 {
			n = 255
		}
		cap = 16*n - n - 1
	}

	return &Resp{
		msg:    msg,
		domain: domain,
		edns0:  edns0,

		cap: cap,
	}
}

func (r *Resp) Encode(encoded []byte, data []byte) []byte {
	msg := r.msg
	msg.Header = dnsmessage.Header{
		ID:            msg.Header.ID,
		Response:      true,
		Authoritative: true,
		RCode:         dnsmessage.RCodeSuccess,
	}
	msg.Answers = nil
	msg.Authorities = nil
	msg.Additionals = nil
	switch msg.Questions[0].Type {
	case dnsmessage.TypeA:
		fragN := 0
		if len(data) > 0 {
			fragN = 1
		}
		if (len(data) - (4 - 2)) > 0 {
			fragN += (len(data) - (4 - 2)) / (4 - 1)
			if (len(data)-(4-2))%(4-1) > 0 {
				fragN++
			}
		}

		for i := range fragN {
			A := [4]byte{byte(i)}
			if i == 0 {
				A[1] = byte(fragN)
				n := copy(A[2:], data)
				data = data[n:]
			} else {
				n := copy(A[1:], data)
				data = data[n:]
			}
			msg.Answers = append(msg.Answers, dnsmessage.Resource{
				Header: dnsmessage.ResourceHeader{
					Name:  msg.Questions[0].Name,
					Type:  msg.Questions[0].Type,
					Class: dnsmessage.ClassINET,
					TTL:   60,
				},
				Body: &dnsmessage.AResource{A: A},
			})
		}
	case dnsmessage.TypeCNAME:
		fragN := 0
		if len(data) > 0 {
			fragN = 1
		}
		if (len(data) - (r.domain.cap - 2)) > 0 {
			fragN += (len(data) - (r.domain.cap - 2)) / (r.domain.cap - 1)
			if (len(data)-(r.domain.cap-2))%(r.domain.cap-1) > 0 {
				fragN++
			}
		}

		DATA := make([]byte, r.domain.cap)
		for i := range fragN {
			DATA[0] = byte(i)
			if i == 0 {
				DATA[1] = byte(fragN)
				n := copy(DATA[2:], data)
				data = data[n:]
				msg.Answers = append(msg.Answers, dnsmessage.Resource{
					Header: dnsmessage.ResourceHeader{
						Name:  msg.Questions[0].Name,
						Type:  msg.Questions[0].Type,
						Class: dnsmessage.ClassINET,
						TTL:   60,
					},
					Body: &dnsmessage.CNAMEResource{CNAME: r.domain.Encode(DATA[:2+n])},
				})
			} else {
				n := copy(DATA[1:], data)
				data = data[n:]
				msg.Answers = append(msg.Answers, dnsmessage.Resource{
					Header: dnsmessage.ResourceHeader{
						Name:  msg.Questions[0].Name,
						Type:  msg.Questions[0].Type,
						Class: dnsmessage.ClassINET,
						TTL:   60,
					},
					Body: &dnsmessage.CNAMEResource{CNAME: r.domain.Encode(DATA[:1+n])},
				})
			}
		}
	case dnsmessage.TypeTXT:
		var txt []string
		for len(data) > 0 {
			size := min(len(data), 255)
			txt = append(txt, string(data[:size]))
			data = data[size:]
		}
		msg.Answers = append(msg.Answers, dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{
				Name:  msg.Questions[0].Name,
				Type:  msg.Questions[0].Type,
				Class: dnsmessage.ClassINET,
				TTL:   60,
			},
			Body: &dnsmessage.TXTResource{TXT: txt},
		})
	case dnsmessage.TypeAAAA:
		fragN := 0
		if len(data) > 0 {
			fragN = 1
		}
		if (len(data) - (16 - 2)) > 0 {
			fragN += (len(data) - (16 - 2)) / (16 - 1)
			if (len(data)-(16-2))%(16-1) > 0 {
				fragN++
			}
		}

		for i := range fragN {
			AAAA := [16]byte{byte(i)}
			if i == 0 {
				AAAA[1] = byte(fragN)
				n := copy(AAAA[2:], data)
				data = data[n:]
			} else {
				n := copy(AAAA[1:], data)
				data = data[n:]
			}
			msg.Answers = append(msg.Answers, dnsmessage.Resource{
				Header: dnsmessage.ResourceHeader{
					Name:  msg.Questions[0].Name,
					Type:  msg.Questions[0].Type,
					Class: dnsmessage.ClassINET,
					TTL:   60,
				},
				Body: &dnsmessage.AAAAResource{AAAA: AAAA},
			})
		}
	}
	if r.edns0 > 0 {
		msg.Additionals = append(msg.Additionals, dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{
				Name:  dnsmessage.MustNewName("."),
				Type:  dnsmessage.TypeOPT,
				Class: dnsmessage.Class(r.edns0),
				TTL:   0,
			},
			Body: &dnsmessage.OPTResource{},
		})
	}
	return common.Must2(msg.AppendPack(encoded[:0]))
}

// Decode writes the payload carried by the answers into decoded and returns
// its length. The caller reslices its buffer with the result, so a payload
// that does not fit len(decoded) is rejected instead of growing past it.
func (r *Resp) Decode(decoded []byte) int {
	limit := len(decoded)
	decoded = decoded[:0]
	fits := func(n int) bool {
		return len(decoded)+n <= limit
	}
	msg := r.msg
	if msg.Questions[0].Type == dnsmessage.TypeTXT {
		if len(msg.Answers) == 1 && r.domain.IsDomain(msg.Answers[0].Header.Name) && msg.Answers[0].Header.Type == dnsmessage.TypeTXT {
			for i := range msg.Answers[0].Body.(*dnsmessage.TXTResource).TXT {
				txt := msg.Answers[0].Body.(*dnsmessage.TXTResource).TXT[i]
				if !fits(len(txt)) {
					return 0
				}
				decoded = append(decoded, txt...)
			}
		}
		return len(decoded)
	} else {
		var frags [][]byte
		for i := range msg.Answers {
			if !r.domain.IsDomain(msg.Answers[i].Header.Name) || msg.Answers[i].Header.Type != msg.Questions[0].Type {
				continue
			}
			switch msg.Questions[0].Type {
			case dnsmessage.TypeA:
				frags = append(frags, msg.Answers[i].Body.(*dnsmessage.AResource).A[:])
			case dnsmessage.TypeCNAME:
				var decoded [255]byte
				n := r.domain.Decode(&decoded, msg.Answers[i].Body.(*dnsmessage.CNAMEResource).CNAME)
				if n == 0 {
					continue
				}
				frags = append(frags, decoded[:n])
			case dnsmessage.TypeAAAA:
				frags = append(frags, msg.Answers[i].Body.(*dnsmessage.AAAAResource).AAAA[:])
			}
		}
		sort.Slice(frags, func(i, j int) bool {
			return frags[i][0] < frags[j][0]
		})
		if len(frags) < 1 || len(frags[0]) < 2 || int(frags[0][1]) > len(frags) {
			return 0
		}
		if !fits(len(frags[0]) - 2) {
			return 0
		}
		decoded = append(decoded, frags[0][2:]...)
		for i := range frags {
			if i > 0 {
				if frags[i][0] == frags[i-1][0] || !fits(len(frags[i])-1) {
					return 0
				}
				decoded = append(decoded, frags[i][1:]...)
			}
		}
		return len(decoded)
	}
}

type SendInfo struct {
	stash    chan []byte
	ch       chan []byte
	deadline time.Time
	// elem is the client's place in SendManager.lru.
	elem *list.Element
}

type SendManager struct {
	m map[ClientID]*SendInfo
	// lru orders the tracked clients from most to least recently used.
	lru *list.List
	ch  chan struct{}
	mu  sync.Mutex
}

func NewSendManager() *SendManager {
	m := &SendManager{
		m:   make(map[ClientID]*SendInfo),
		lru: list.New(),
		ch:  make(chan struct{}),
	}
	go m.gc()
	return m
}

func (m *SendManager) closed() bool {
	select {
	case <-m.ch:
		return true
	default:
		return false
	}
}

func (m *SendManager) gc() {
	ticker := time.NewTicker(sendTTL)
	defer ticker.Stop()
	for {
		select {
		case <-m.ch:
			return
		case now := <-ticker.C:
			m.mu.Lock()
			for key, info := range m.m {
				if now.After(info.deadline) {
					m.remove(key, info)
				}
			}
			m.mu.Unlock()
			ticker.Reset(sendTTL)
		}
	}
}

// remove closes the queues of clientID and stops tracking it. m.mu must be
// held.
func (m *SendManager) remove(clientID ClientID, info *SendInfo) {
	close(info.stash)
	close(info.ch)
	m.lru.Remove(info.elem)
	delete(m.m, clientID)
}

// entry returns the queues of clientID, creating them if needed, and marks
// it the most recently used client. The keys come from unauthenticated
// queries, so a new client beyond sendClientCount evicts the least recently
// used one: a flood can churn the table but never lock new clients out. The
// cost is that sendClientCount IDs brought in between two polls of a client
// evict it, dropping up to 128 downlink packets queued for it; the table no
// longer grows without bound instead. entry returns nil once the manager is
// closed. m.mu must be held.
func (m *SendManager) entry(clientID ClientID) *SendInfo {
	if info := m.m[clientID]; info != nil {
		m.lru.MoveToFront(info.elem)
		return info
	}
	if m.closed() {
		return nil
	}
	if len(m.m) >= sendClientCount {
		oldest := m.lru.Back().Value.(ClientID)
		m.remove(oldest, m.m[oldest])
	}
	info := &SendInfo{
		stash:    make(chan []byte, 1),
		ch:       make(chan []byte, 128),
		deadline: time.Now().Add(sendTTL),
	}
	info.elem = m.lru.PushFront(clientID)
	m.m[clientID] = info
	return info
}

func (m *SendManager) Push(clientID ClientID, p []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	info := m.entry(clientID)
	if info == nil {
		return
	}
	b := make([]byte, len(p))
	copy(b, p)
	select {
	case info.ch <- b:
	default:
	}
}

func (m *SendManager) Stash(clientID ClientID, p []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	info := m.m[clientID]
	if info == nil {
		return
	}
	m.lru.MoveToFront(info.elem)
	info.deadline = time.Now().Add(sendTTL)
	select {
	case info.stash <- p:
	default:
	}
}

// Pop returns the queues of clientID and refreshes their deadline. ok is
// false once the manager is closed.
func (m *SendManager) Pop(clientID ClientID) (ch chan []byte, stash chan []byte, ok bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	info := m.entry(clientID)
	if info == nil {
		return nil, nil, false
	}
	info.deadline = time.Now().Add(sendTTL)
	return info.ch, info.stash, true
}

func (m *SendManager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed() {
		return
	}
	close(m.ch)
	for key, info := range m.m {
		m.remove(key, info)
	}
}
