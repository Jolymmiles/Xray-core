package tls

import (
	"encoding/binary"
	"errors"
	"strings"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/protocol"
)

type SniffHeader struct {
	domain string
}

func (h *SniffHeader) Protocol() string {
	return "tls"
}

func (h *SniffHeader) Domain() string {
	return h.domain
}

func (h *SniffHeader) DomainNormalized() bool {
	return true
}

func (h *SniffHeader) NormalizedProtocolDomain() (string, string) {
	return "tls", h.domain
}

var (
	errNotTLS         = errors.New("not TLS header")
	errNotClientHello = errors.New("not client hello")
)

func IsValidTLSVersion(major, minor byte) bool {
	return major == 3
}

// ReadClientHello returns server name (if any) from TLS client hello message.
// https://github.com/golang/go/blob/master/src/crypto/tls/handshake_messages.go#L300
func ReadClientHello(data []byte, h *SniffHeader) error {
	domain, err := readClientHelloServerName(data)
	if err == nil {
		h.domain = domain
	}
	return err
}

func readClientHelloServerName(data []byte) (string, error) {
	if len(data) < 42 {
		return "", common.ErrNoClue
	}
	sessionIDLen := int(data[38])
	if sessionIDLen > 32 || len(data) < 39+sessionIDLen {
		return "", common.ErrNoClue
	}
	data = data[39+sessionIDLen:]
	if len(data) < 2 {
		return "", common.ErrNoClue
	}
	// cipherSuiteLen is the number of bytes of cipher suite numbers. Since
	// they are uint16s, the number must be even.
	cipherSuiteLen := int(data[0])<<8 | int(data[1])
	if cipherSuiteLen%2 == 1 || len(data) < 2+cipherSuiteLen {
		return "", errNotClientHello
	}
	data = data[2+cipherSuiteLen:]
	if len(data) < 1 {
		return "", common.ErrNoClue
	}
	compressionMethodsLen := int(data[0])
	if len(data) < 1+compressionMethodsLen {
		return "", common.ErrNoClue
	}
	data = data[1+compressionMethodsLen:]

	if len(data) < 2 {
		return "", errNotClientHello
	}

	extensionsLength := int(data[0])<<8 | int(data[1])
	data = data[2:]
	if extensionsLength != len(data) {
		return "", errNotClientHello
	}

	for len(data) != 0 {
		if len(data) < 4 {
			return "", errNotClientHello
		}
		extension := uint16(data[0])<<8 | uint16(data[1])
		length := int(data[2])<<8 | int(data[3])
		data = data[4:]
		if len(data) < length {
			return "", errNotClientHello
		}

		if extension == 0x00 { /* extensionServerName */
			d := data[:length]
			if len(d) < 2 {
				return "", errNotClientHello
			}
			namesLen := int(d[0])<<8 | int(d[1])
			d = d[2:]
			if len(d) != namesLen {
				return "", errNotClientHello
			}
			for len(d) > 0 {
				if len(d) < 3 {
					return "", errNotClientHello
				}
				nameType := d[0]
				nameLen := int(d[1])<<8 | int(d[2])
				d = d[3:]
				if len(d) < nameLen {
					return "", errNotClientHello
				}
				if nameType == 0 {
					// QUIC separated across packets
					// May cause the serverName to be incomplete
					normalized := true
					b := byte(0)
					for _, b = range d[:nameLen] {
						if b <= ' ' {
							return "", protocol.ErrProtoNeedMoreData
						}
						if b-'A' <= 'Z'-'A' || b >= 0x80 {
							normalized = false
						}
					}
					// An SNI value may not include a
					// trailing dot. See
					// https://tools.ietf.org/html/rfc6066#section-3.
					if b == '.' {
						return "", errNotClientHello
					}
					var serverName string
					if normalized {
						serverName = string(d[:nameLen])
					} else {
						serverName = normalizeServerName(d[:nameLen])
					}
					return serverName, nil
				}
				d = d[nameLen:]
			}
		}
		data = data[length:]
	}

	return "", errNotTLS
}

func normalizeServerName(value []byte) string {
	for _, character := range value {
		if character >= 0x80 {
			return strings.ToLower(string(value))
		}
	}
	var normalized strings.Builder
	normalized.Grow(len(value))
	for _, character := range value {
		if character >= 'A' && character <= 'Z' {
			character += 'a' - 'A'
		}
		normalized.WriteByte(character)
	}
	return normalized.String()
}

func SniffTLS(b []byte) (*SniffHeader, error) {
	if len(b) < 5 {
		return nil, common.ErrNoClue
	}

	if b[0] != 0x16 /* TLS Handshake */ {
		return nil, errNotTLS
	}
	if !IsValidTLSVersion(b[1], b[2]) {
		return nil, errNotTLS
	}
	headerLen := int(binary.BigEndian.Uint16(b[3:5]))
	if 5+headerLen > len(b) {
		return nil, common.ErrNoClue
	}

	domain, err := readClientHelloServerName(b[5 : 5+headerLen])
	if err == nil {
		return &SniffHeader{domain: domain}, nil
	}
	return nil, err
}
