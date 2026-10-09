package header

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/xtls/xray-core/common/dice"
	"golang.org/x/net/idna"
)

type dns struct {
	header []byte
}

func (h *dns) Size() int {
	return len(h.header)
}

func (h *dns) Serialize(b []byte) {
	copy(b, h.header)
	binary.BigEndian.PutUint16(b[0:], dice.RollUint16())
}

// NewHeaderDNS builds the query that prefixes every packet. The peer strips
// it by its length without parsing it, so the domain is packed as written: a
// domain that would not pack into a well-formed question for itself is
// rejected, because rewriting it would change the length the peer expects.
func NewHeaderDNS(domain string) (*dns, error) {
	if err := checkDomainName(domain); err != nil {
		return nil, fmt.Errorf("invalid domain %q: %w", domain, err)
	}
	var header []byte
	header = binary.BigEndian.AppendUint16(header, 0x0000) // Transaction ID
	header = binary.BigEndian.AppendUint16(header, 0x0100) // Flags: Standard query
	header = binary.BigEndian.AppendUint16(header, 0x0001) // Questions
	header = binary.BigEndian.AppendUint16(header, 0x0000) // Answer RRs
	header = binary.BigEndian.AppendUint16(header, 0x0000) // Authority RRs
	header = binary.BigEndian.AppendUint16(header, 0x0000) // Additional RRs
	for _, label := range strings.Split(domain, ".") {
		header = append(header, byte(len(label)))
		header = append(header, label...)
	}
	header = append(header, 0)                             // Root label
	header = binary.BigEndian.AppendUint16(header, 0x0001) // Type: A
	header = binary.BigEndian.AppendUint16(header, 0x0001) // Class: IN
	return &dns{header: header}, nil
}

// checkDomainName reports why domain would not pack into a question for
// itself made of ASCII labels of 1 to 63 bytes, at most 255 bytes on the wire.
func checkDomainName(domain string) error {
	for i := 0; i < len(domain); i++ {
		if domain[i] >= utf8.RuneSelf {
			return nonASCIIError(domain)
		}
	}
	return checkASCIIName(domain)
}

// nonASCIIError suggests the punycode form that IDNA lookups put on the wire.
func nonASCIIError(domain string) error {
	ascii, err := idna.Lookup.ToASCII(strings.TrimSuffix(domain, "."))
	if err != nil || checkASCIIName(ascii) != nil {
		return errors.New("non-ASCII name; write its punycode form")
	}
	return fmt.Errorf("non-ASCII name; write its punycode form %q", ascii)
}

func checkASCIIName(domain string) error {
	if strings.Contains(domain, `\`) {
		return errors.New("backslash escapes are not supported")
	}
	name := strings.TrimSuffix(domain, ".")
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 {
			return errors.New("empty label")
		}
		if len(label) > 63 {
			return fmt.Errorf("label %q is longer than 63 bytes", label)
		}
	}
	if wire := len(name) + 2; wire > 255 {
		return fmt.Errorf("name of %d bytes on the wire is longer than 255 bytes", wire)
	}
	if name != domain {
		return fmt.Errorf("trailing dot; write %q", name)
	}
	return nil
}
