package xdns

import (
	"encoding/base32"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/idna"
)

func Lower(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}

func ToUpper(b []byte) {
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - 'a' + 'A'
		}
	}
}

func ToLower(b []byte) {
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c - 'A' + 'a'
		}
	}
}

func NewTable() ([256]int, [256]int) {
	var t, t_ [256]int
	for i := range t {
		t[i] = base32Encoding.DecodedLen(i)
	}
	for i := range t_ {
		t_[i] = base32Encoding.EncodedLen(i)
	}
	return t, t_
}

const (
	TypeA     uint16 = 1
	TypeCNAME uint16 = 5
	TypeTXT   uint16 = 16
	TypeAAAA  uint16 = 28
)

var (
	base32Encoding = base32.StdEncoding.WithPadding(base32.NoPadding)
	table, table_  = NewTable()
	TypeMap        = map[uint16]byte{
		TypeA:     0,
		TypeCNAME: 1,
		TypeTXT:   2,
		TypeAAAA:  3,
	}
	TypeMap_ = map[byte]uint16{
		0: TypeA,
		1: TypeCNAME,
		2: TypeTXT,
		3: TypeAAAA,
	}
)

type Domain struct {
	name       dnsmessage.Name
	lenLimit   int
	labelLimit int
	types      []uint16
	edns0      uint16

	cap    int
	lenMax int
}

// absoluteASCIIName converts a configured domain, with or without a trailing
// dot and possibly internationalised, into the absolute ASCII name that is
// packed into queries. Every label must be non-empty and fit a DNS label, or
// the client could not pack its first poll.
func absoluteASCIIName(domain string) (dnsmessage.Name, error) {
	ascii, err := idna.ToASCII(strings.TrimSuffix(domain, "."))
	if err != nil {
		return dnsmessage.Name{}, err
	}
	for _, label := range strings.Split(ascii, ".") {
		if len(label) == 0 || len(label) > 63 {
			return dnsmessage.Name{}, errors.New("invalid domain")
		}
	}
	return dnsmessage.NewName(ascii + ".")
}

func NewDomain(domain string, lenLimit int, labelLimit int, types []uint16, edns0 uint16) (*Domain, error) {
	if lenLimit < 0 || lenLimit > 255 {
		return nil, errors.New("lenLimit < 0 || lenLimit > 255")
	}
	if labelLimit < 0 || labelLimit > 63 {
		return nil, errors.New("labelLimit < 0 || labelLimit > 63")
	}
	if len(types) == 0 {
		return nil, errors.New("empty types")
	}
	for i := range types {
		switch types[i] {
		case uint16(dnsmessage.TypeA), uint16(dnsmessage.TypeCNAME), uint16(dnsmessage.TypeTXT), uint16(dnsmessage.TypeAAAA):
		default:
			return nil, errors.New("unknown types")
		}
	}
	if edns0 != 0 && (edns0 < 512 || edns0 > 4096) {
		return nil, errors.New("edns0 != 0 && (edns0 < 512 || edns0 > 4096)")
	}

	name, err := absoluteASCIIName(domain)
	if err != nil {
		return nil, err
	}

	if lenLimit < int(name.Length)+1 {
		return nil, errors.New("lenLimit < int(name.Length)+1")
	}
	n := (lenLimit - int(name.Length) - 1) / (labelLimit + 1)
	left := (lenLimit - int(name.Length) - 1) % (labelLimit + 1)
	total := n * labelLimit
	if left > 1 {
		total += left - 1
	}
	cap := table[total]
	if cap < 17 {
		return nil, errors.New("cap < 17")
	}
	total = table_[cap]
	lenMax := int(name.Length) + 1 + total + total/labelLimit
	if total%labelLimit > 0 {
		lenMax += 1
	}
	return &Domain{
		name:       name,
		lenLimit:   lenLimit,
		labelLimit: labelLimit,
		types:      types,
		edns0:      edns0,

		cap:    cap,
		lenMax: lenMax,
	}, nil
}

func (d *Domain) Show() string {
	return fmt.Sprint(d.name, d.cap)
}

// IsDomain reports whether name is a strict subdomain of d: d must end name
// at a label boundary, so siblings sharing a suffix do not match.
func (d *Domain) IsDomain(name dnsmessage.Name) bool {
	if d.name.Length >= name.Length || name.Data[name.Length-d.name.Length-1] != '.' {
		return false
	}
	return d.endsName(name)
}

// IsApex reports whether name is d itself, the apex of the zone the server
// answers for. The apex carries no tunnel data, so IsDomain excludes it.
func (d *Domain) IsApex(name dnsmessage.Name) bool {
	return d.name.Length == name.Length && d.endsName(name)
}

// endsName reports whether name ends with d's name, ignoring ASCII case. name
// must be at least as long as d's name.
func (d *Domain) endsName(name dnsmessage.Name) bool {
	offset := name.Length - d.name.Length
	for i := range d.name.Length {
		if Lower(d.name.Data[i]) != Lower(name.Data[offset+i]) {
			return false
		}
	}
	return true
}

func (d *Domain) HasType(qtype uint16) bool {
	for i := range d.types {
		if d.types[i] == qtype {
			return true
		}
	}
	return false
}

func (d *Domain) Encode(data []byte) dnsmessage.Name {
	var name dnsmessage.Name
	var encoded [255]byte
	base32Encoding.Encode(encoded[:], data)
	ToLower(encoded[:table_[len(data)]])
	b1 := name.Data[:0]
	b2 := encoded[:table_[len(data)]]
	for len(b2) > 0 {
		size := min(len(b2), d.labelLimit)
		b1 = append(b1, b2[:size]...)
		b1 = append(b1, '.')
		b2 = b2[size:]
	}
	b1 = append(b1, d.name.Data[:d.name.Length]...)
	if len(b1) > 254 {
		panic("len(b1) > 254")
	}
	name.Length = byte(len(b1))
	return name
}

func (d *Domain) Decode(decoded *[255]byte, name dnsmessage.Name) int {
	if !d.IsDomain(name) {
		return 0
	}
	var encoded [255]byte
	b1 := encoded[:0]
	b2 := name.Data[:name.Length-d.name.Length]
	for i := range b2 {
		if b2[i] != '.' {
			b1 = append(b1, b2[i])
		}
	}
	ToUpper(b1)
	n, err := base32Encoding.Decode(decoded[:], b1)
	if err != nil {
		return 0
	}
	return n
}
