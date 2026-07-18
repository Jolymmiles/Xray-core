package http

import (
	"bytes"
	"context"
	"errors"
	"strings"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
)

type version byte

const (
	HTTP1 version = iota
	HTTP2
)

type SniffHeader struct {
	version version
	host    string
}

const inlineSniffAttributes = 16

type sniffAttribute struct {
	key   string
	value []byte
	start int
}

type sniffAttributeCollector struct {
	inline   [inlineSniffAttributes]sniffAttribute
	overflow []sniffAttribute
	count    int
	total    int
}

func (c *sniffAttributeCollector) add(key string, value []byte) {
	attribute := sniffAttribute{key: key, value: value}
	if c.count < len(c.inline) {
		c.inline[c.count] = attribute
	} else {
		c.overflow = append(c.overflow, attribute)
	}
	c.count++
	c.total += len(value)
}

func (c *sniffAttributeCollector) apply(content *session.Content) {
	if c.count == 0 {
		return
	}
	var values strings.Builder
	values.Grow(c.total)
	for index := range min(c.count, len(c.inline)) {
		attribute := &c.inline[index]
		attribute.start = values.Len()
		values.Write(attribute.value)
	}
	for index := range c.overflow {
		attribute := &c.overflow[index]
		attribute.start = values.Len()
		values.Write(attribute.value)
	}
	ownedValues := values.String()
	for index := range min(c.count, len(c.inline)) {
		attribute := &c.inline[index]
		content.SetAttribute(attribute.key, ownedValues[attribute.start:attribute.start+len(attribute.value)])
	}
	for index := range c.overflow {
		attribute := &c.overflow[index]
		content.SetAttribute(attribute.key, ownedValues[attribute.start:attribute.start+len(attribute.value)])
	}
}

func (h *SniffHeader) Protocol() string {
	switch h.version {
	case HTTP1:
		return "http1"
	case HTTP2:
		return "http2"
	default:
		return "unknown"
	}
}

func (h *SniffHeader) Domain() string {
	return h.host
}

// DomainNormalized reports that HTTP host sniffing already returns a
// lowercase domain suitable for case-insensitive matcher lookup.
func (*SniffHeader) DomainNormalized() bool { return true }

func (h *SniffHeader) NormalizedProtocolDomain() (string, string) {
	return h.Protocol(), h.host
}

var (
	methods = [...]string{"get", "post", "head", "put", "delete", "options", "connect"}

	errNotHTTPMethod = errors.New("not an HTTP method")
)

func beginWithHTTPMethod(b []byte) error {
	for _, m := range &methods {
		if len(b) >= len(m) && equalFoldASCII(b[:len(m)], m) {
			return nil
		}

		if len(b) < len(m) {
			return common.ErrNoClue
		}
	}

	return errNotHTTPMethod
}

func equalFoldASCII(value []byte, lower string) bool {
	if len(value) != len(lower) {
		return false
	}
	for index, character := range value {
		if character >= 'A' && character <= 'Z' {
			character += 'a' - 'A'
		}
		if character != lower[index] {
			return false
		}
	}
	return true
}

func SniffHTTP(b []byte, c context.Context) (*SniffHeader, error) {
	if err := beginWithHTTPMethod(b); err != nil {
		return nil, err
	}
	content := session.ContentFromContext(c)
	ShouldSniffAttr := true
	// If content.Attributes have information, that means it comes from HTTP inbound PlainHTTP mode.
	// It will set attributes, so skip it.
	if content == nil || content.SkipSniffingAttributes || len(content.Attributes) != 0 {
		ShouldSniffAttr = false
	}
	requestLineEnd := bytes.IndexByte(b, '\n')
	if requestLineEnd < 0 {
		requestLineEnd = len(b)
	}
	if ShouldSniffAttr {
		return sniffHTTPAttributes(b, content, requestLineEnd)
	}
	return sniffHTTPHost(b, requestLineEnd)
}

func sniffHTTPHost(b []byte, requestLineEnd int) (*SniffHeader, error) {
	for offset := requestLineEnd; offset < len(b); {
		offset++
		lineEnd := bytes.IndexByte(b[offset:], '\n')
		var header []byte
		if lineEnd < 0 {
			header = b[offset:]
		} else {
			header = b[offset : offset+lineEnd]
		}
		if len(header) == 0 {
			break
		}
		colon := bytes.IndexByte(header, ':')
		if colon >= 0 {
			keyBytes := header[:colon]
			valueBytes := bytes.TrimSpace(header[colon+1:])
			if isHostHeader(keyBytes) {
				host, err := parseSniffHost(lowerASCIIBytes(valueBytes))
				if err != nil {
					return nil, err
				}
				if host != "" {
					return &SniffHeader{version: HTTP1, host: host}, nil
				}
			}
		}
		if lineEnd < 0 {
			break
		}
		offset += lineEnd
	}
	return nil, common.ErrNoClue
}

func sniffHTTPAttributes(b []byte, content *session.Content, requestLineEnd int) (*SniffHeader, error) {
	var attributes sniffAttributeCollector
	for offset := requestLineEnd; offset < len(b); {
		offset++
		lineEnd := bytes.IndexByte(b[offset:], '\n')
		var header []byte
		if lineEnd < 0 {
			header = b[offset:]
		} else {
			header = b[offset : offset+lineEnd]
		}
		if len(header) == 0 {
			break
		}
		colon := bytes.IndexByte(header, ':')
		if colon >= 0 {
			keyBytes := header[:colon]
			key, commonKey := commonAttributeKey(keyBytes)
			if !commonKey {
				key = lowerASCIIBytes(keyBytes)
			}
			attributes.add(key, bytes.TrimSpace(header[colon+1:]))
		}
		if lineEnd < 0 {
			break
		}
		offset += lineEnd
	}
	// Parse request line
	// Request line is like this
	// "GET /homo/114514 HTTP/1.1"
	requestLine := b[:requestLineEnd]
	firstSpace := bytes.IndexByte(requestLine, ' ')
	if firstSpace >= 0 {
		secondOffset := bytes.IndexByte(requestLine[firstSpace+1:], ' ')
		if secondOffset >= 0 {
			secondSpace := firstSpace + 1 + secondOffset
			if bytes.IndexByte(requestLine[secondSpace+1:], ' ') < 0 {
				attributes.add(":method", requestLine[:firstSpace])
				attributes.add(":path", requestLine[firstSpace+1:secondSpace])
			}
		}
	}
	attributes.apply(content)
	host, err := parseSniffHost(strings.ToLower(content.Attributes["host"]))
	if err != nil {
		return nil, err
	}
	if host != "" {
		return &SniffHeader{version: HTTP1, host: host}, nil
	}
	return nil, common.ErrNoClue
}

func parseSniffHost(headerHost string) (string, error) {
	if headerHost == "" {
		return "", nil
	}
	if isDomainWithoutPort(headerHost) {
		return headerHost, nil
	}
	destination, err := ParseHost(headerHost, net.Port(80))
	if err != nil {
		return "", err
	}
	return destination.Address.String(), nil
}

func lowerASCIIBytes(value []byte) string {
	hasUpper := false
	for _, character := range value {
		if character >= 0x80 {
			return strings.ToLower(string(value))
		}
		if character >= 'A' && character <= 'Z' {
			hasUpper = true
		}
	}
	if !hasUpper {
		return string(value)
	}
	var lower strings.Builder
	lower.Grow(len(value))
	for _, character := range value {
		if character >= 'A' && character <= 'Z' {
			character += 'a' - 'A'
		}
		lower.WriteByte(character)
	}
	return lower.String()
}

func isHostHeader(key []byte) bool {
	return len(key) == 4 &&
		key[0]|0x20 == 'h' && key[1]|0x20 == 'o' &&
		key[2]|0x20 == 's' && key[3]|0x20 == 't'
}

func commonAttributeKey(key []byte) (string, bool) {
	switch len(key) {
	case len("host"):
		if isHostHeader(key) {
			return "host", true
		}
	case len("accept"):
		if equalFoldASCII(key, "accept") {
			return "accept", true
		}
	case len("user-agent"):
		if equalFoldASCII(key, "user-agent") {
			return "user-agent", true
		}
	}
	return "", false
}
