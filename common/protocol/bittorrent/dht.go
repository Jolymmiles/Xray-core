package bittorrent

import (
	"github.com/xtls/xray-core/common"
)

// SniffDHT detects Mainline DHT (BEP 5) KRPC messages. One bencoded
// dictionary is sent per datagram with a one-character string y selecting
// the message kind and a short non-empty string t carrying the transaction
// id, matching the shape libtorrent's kademlia implementation both sends
// and accepts:
//
//	q  query    with a query name from the deployed set and dict a
//	r  response with dict r containing a 20-byte node id
//	e  error    with list e of [code int, message string]
//
// Trailing bytes after the dictionary are tolerated because the dispatcher
// may hand the sniffer more than one coalesced datagram.
func SniffDHT(b []byte) (*SniffHeader, error) {
	if len(b) == 0 {
		return nil, common.ErrNoClue
	}
	if b[0] != 'd' {
		return nil, errNotBittorrent
	}

	var m dhtMessage
	if !m.parseDict(b, 1) {
		return nil, errNotBittorrent
	}

	switch m.y {
	case 'q':
		if !m.hasTransactionID || !m.hasQueryName || !m.hasArguments || !m.validQueryArguments() {
			return nil, errNotBittorrent
		}
	case 'r':
		if !m.hasTransactionID || !m.hasResultWithID {
			return nil, errNotBittorrent
		}
	case 'e':
		if !m.hasTransactionID || !m.hasErrorList {
			return nil, errNotBittorrent
		}
	default:
		return nil, errNotBittorrent
	}

	return &SniffHeader{}, nil
}

// dhtMaxDepth bounds nesting. The deepest legal structure is a BEP 44 put
// value: argument dict wrapping a mutable value dict wrapping lists.
const dhtMaxDepth = 8

type dhtMessage struct {
	y                byte
	hasTransactionID bool
	hasQueryName     bool
	hasArguments     bool
	hasResultWithID  bool
	hasErrorList     bool
	queryName        string
	queryArguments   dhtQueryArguments
}

type dhtQueryArguments struct {
	hasNodeID      bool
	hasTarget      bool
	hasInfoHash    bool
	hasToken       bool
	hasPort        bool
	hasImpliedPort bool
	hasValue       bool
}

// parseDict parses the top-level dictionary, recording which KRPC fields
// are present and valid. Values that carry no routing meaning are only
// structurally validated by parseValue.
func (m *dhtMessage) parseDict(b []byte, pos int) bool {
	for pos < len(b) && b[pos] != 'e' {
		key, next, ok := parseString(b, pos)
		if !ok {
			return false
		}
		pos = next
		if pos >= len(b) {
			return false
		}

		switch string(key) {
		case "y":
			value, next, ok := parseString(b, pos)
			if !ok || len(value) != 1 {
				return false
			}
			m.y = value[0]
			pos = next
		case "t":
			value, next, ok := parseString(b, pos)
			if !ok || len(value) == 0 || len(value) > 16 {
				return false
			}
			m.hasTransactionID = true
			pos = next
		case "q":
			value, next, ok := parseString(b, pos)
			if !ok || !isKnownDHTQuery(value) {
				return false
			}
			m.queryName = string(value)
			m.hasQueryName = true
			pos = next
		case "a":
			if pos >= len(b) || b[pos] != 'd' {
				return false
			}
			next, ok := m.queryArguments.parseDict(b, pos+1)
			if !ok {
				return false
			}
			m.hasArguments = true
			pos = next
		case "r":
			if pos >= len(b) || b[pos] != 'd' {
				return false
			}
			if !m.parseResultDict(b, pos+1) {
				return false
			}
			next, ok := parseValue(b, pos, 1)
			if !ok {
				return false
			}
			m.hasResultWithID = true
			pos = next
		case "e":
			if pos >= len(b) || b[pos] != 'l' {
				return false
			}
			if !m.parseErrorList(b, pos+1) {
				return false
			}
			next, ok := parseValue(b, pos, 1)
			if !ok {
				return false
			}
			m.hasErrorList = true
			pos = next
		default:
			next, ok := parseValue(b, pos, 1)
			if !ok {
				return false
			}
			pos = next
		}
	}
	return pos < len(b) && b[pos] == 'e'
}

func (a *dhtQueryArguments) parseDict(b []byte, pos int) (int, bool) {
	for pos < len(b) && b[pos] != 'e' {
		key, next, ok := parseString(b, pos)
		if !ok {
			return 0, false
		}
		pos = next

		switch string(key) {
		case "id":
			value, next, ok := parseString(b, pos)
			if !ok || len(value) != 20 {
				return 0, false
			}
			a.hasNodeID = true
			pos = next
		case "target":
			value, next, ok := parseString(b, pos)
			if !ok || len(value) != 20 {
				return 0, false
			}
			a.hasTarget = true
			pos = next
		case "info_hash":
			value, next, ok := parseString(b, pos)
			if !ok || len(value) != 20 {
				return 0, false
			}
			a.hasInfoHash = true
			pos = next
		case "token":
			value, next, ok := parseString(b, pos)
			if !ok || len(value) == 0 {
				return 0, false
			}
			a.hasToken = true
			pos = next
		case "port":
			value, next, ok := parsePositiveInt(b, pos, 65535)
			if !ok {
				return 0, false
			}
			a.hasPort = value != 0
			pos = next
		case "implied_port":
			value, next, ok := parsePositiveInt(b, pos, 1)
			if !ok {
				return 0, false
			}
			a.hasImpliedPort = value == 1
			pos = next
		case "v":
			next, ok := parseValue(b, pos, 2)
			if !ok {
				return 0, false
			}
			a.hasValue = true
			pos = next
		default:
			next, ok := parseValue(b, pos, 2)
			if !ok {
				return 0, false
			}
			pos = next
		}
	}
	if pos >= len(b) || b[pos] != 'e' {
		return 0, false
	}
	return pos + 1, true
}

func (m *dhtMessage) validQueryArguments() bool {
	if !m.queryArguments.hasNodeID {
		return false
	}

	switch m.queryName {
	case "ping":
		return true
	case "find_node", "get", "sample_infohashes":
		return m.queryArguments.hasTarget
	case "get_peers":
		return m.queryArguments.hasInfoHash
	case "announce_peer":
		return m.queryArguments.hasInfoHash && m.queryArguments.hasToken &&
			(m.queryArguments.hasPort || m.queryArguments.hasImpliedPort)
	case "put":
		return m.queryArguments.hasToken && m.queryArguments.hasValue
	default:
		return false
	}
}

// parseResultDict checks that a response result dictionary contains the
// 20-byte node id every KRPC response carries. Other values may be of any
// bencode type, e.g. the values list of a get_peers response.
func (m *dhtMessage) parseResultDict(b []byte, pos int) bool {
	foundID := false
	for pos < len(b) && b[pos] != 'e' {
		key, next, ok := parseString(b, pos)
		if !ok {
			return false
		}
		pos = next
		if string(key) == "id" {
			value, next, ok := parseString(b, pos)
			if !ok || len(value) != 20 {
				return false
			}
			foundID = true
			pos = next
			continue
		}
		next, ok = parseValue(b, pos, 1)
		if !ok {
			return false
		}
		pos = next
	}
	return foundID
}

// parseErrorList checks the [code, message] shape of an error value. The
// list may carry extra elements; libtorrent logs but accepts them.
func (m *dhtMessage) parseErrorList(b []byte, pos int) bool {
	items := 0
	for pos < len(b) && b[pos] != 'e' {
		if items == 0 {
			next, ok := parseInt(b, pos)
			if !ok {
				return false
			}
			pos = next
		} else if items == 1 {
			_, next, ok := parseString(b, pos)
			if !ok {
				return false
			}
			pos = next
		} else {
			next, ok := parseValue(b, pos, 2)
			if !ok {
				return false
			}
			pos = next
		}
		items++
	}
	return pos < len(b) && b[pos] == 'e' && items >= 2
}

// isKnownDHTQuery reports whether name is a query libtorrent dispatches.
func isKnownDHTQuery(name []byte) bool {
	switch string(name) {
	case "ping", "find_node", "get_peers", "announce_peer", "get", "put", "sample_infohashes":
		return true
	}
	return false
}

// parseValue validates any bencode value starting at pos and returns the
// position just past it.
func parseValue(b []byte, pos, depth int) (int, bool) {
	if depth > dhtMaxDepth || pos >= len(b) {
		return 0, false
	}
	switch b[pos] {
	case 'i':
		return parseInt(b, pos)
	case 'l':
		pos++
		for pos < len(b) && b[pos] != 'e' {
			next, ok := parseValue(b, pos, depth+1)
			if !ok {
				return 0, false
			}
			pos = next
		}
		if pos >= len(b) {
			return 0, false
		}
		return pos + 1, true
	case 'd':
		pos++
		for pos < len(b) && b[pos] != 'e' {
			_, next, ok := parseString(b, pos)
			if !ok {
				return 0, false
			}
			next, ok = parseValue(b, next, depth+1)
			if !ok {
				return 0, false
			}
			pos = next
		}
		if pos >= len(b) {
			return 0, false
		}
		return pos + 1, true
	default:
		_, next, ok := parseString(b, pos)
		if !ok {
			return 0, false
		}
		return next, true
	}
}

// parseInt validates an iNNNe integer and returns the position just past it.
func parseInt(b []byte, pos int) (int, bool) {
	if pos >= len(b) || b[pos] != 'i' {
		return 0, false
	}
	pos++
	if pos < len(b) && b[pos] == '-' {
		pos++
	}
	start := pos
	for pos < len(b) && b[pos] >= '0' && b[pos] <= '9' {
		pos++
	}
	// bencode integers fit in 64 bits; more digits are malformed.
	if pos == start || pos-start > 19 || pos >= len(b) || b[pos] != 'e' {
		return 0, false
	}
	return pos + 1, true
}

func parsePositiveInt(b []byte, pos, maxValue int) (value int, next int, ok bool) {
	if pos >= len(b) || b[pos] != 'i' {
		return 0, 0, false
	}
	pos++
	start := pos
	for pos < len(b) && b[pos] >= '0' && b[pos] <= '9' {
		value = value*10 + int(b[pos]-'0')
		if value > maxValue {
			return 0, 0, false
		}
		pos++
	}
	if pos == start || pos >= len(b) || b[pos] != 'e' {
		return 0, 0, false
	}
	return value, pos + 1, true
}

// parseString validates a length-prefixed byte string and returns the value
// and the position just past it.
func parseString(b []byte, pos int) (value []byte, next int, ok bool) {
	start := pos
	for pos < len(b) && b[pos] >= '0' && b[pos] <= '9' {
		pos++
	}
	// String lengths in DHT datagrams stay far below five digits.
	if pos == start || pos-start > 4 || pos >= len(b) || b[pos] != ':' {
		return nil, 0, false
	}
	length := 0
	for _, c := range b[start:pos] {
		length = length*10 + int(c-'0')
	}
	pos++
	if length < 0 || pos+length > len(b) {
		return nil, 0, false
	}
	return b[pos : pos+length], pos + length, true
}
