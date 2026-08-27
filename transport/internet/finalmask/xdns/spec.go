package xdns

import (
	"net"
	"strconv"
	"strings"

	"github.com/xtls/xray-core/common/errors"
)

type domainSpec struct {
	name   Name
	rrType uint16
}

func rrTypeFromMethod(method string) (uint16, error) {
	switch strings.ToLower(method) {
	case "", "txt":
		return RRTypeTXT, nil
	case "a":
		return RRTypeA, nil
	case "aaaa":
		return RRTypeAAAA, nil
	default:
		return 0, errors.New("unsupported method")
	}
}

func parseDomainSpec(s string, defaultMethod string) (domainSpec, error) {
	domainPart := s
	method := ""
	hasMethod := false

	if i := strings.LastIndex(s, ":"); i >= 0 {
		domainPart = s[:i]
		method = s[i+1:]
		hasMethod = true
	} else if defaultMethod != "" {
		method = defaultMethod
		hasMethod = true
	}

	if domainPart == "" {
		return domainSpec{}, errors.New("empty domain")
	}

	name, err := ParseName(domainPart)
	if err != nil {
		return domainSpec{}, err
	}

	rrType := uint16(0)
	if hasMethod {
		var err error
		rrType, err = rrTypeFromMethod(method)
		if err != nil {
			return domainSpec{}, err
		}
	}

	return domainSpec{
		name:   name,
		rrType: rrType,
	}, nil
}

func parseResolver(s string) (Name, string, uint16, error) {
	head, server, ok := strings.Cut(s, "+udp://")
	if !ok {
		return nil, "", 0, errors.New("invalid resolver scheme")
	}
	if server == "" {
		return nil, "", 0, errors.New("empty resolver server")
	}
	host, portStr, err := net.SplitHostPort(server)
	if err != nil {
		return nil, "", 0, errors.New("resolver server needs host:port").Base(err)
	}
	if net.ParseIP(host) == nil {
		return nil, "", 0, errors.New("resolver server host is not an IP")
	}
	if _, err := strconv.Atoi(portStr); err != nil {
		return nil, "", 0, errors.New("resolver server port invalid").Base(err)
	}

	spec, err := parseDomainSpec(head, "txt")
	if err != nil {
		return nil, "", 0, err
	}

	return spec.name, server, spec.rrType, nil
}

// ValidateResolver reports whether s is a fully formed client resolver
// endpoint ("domain+udp://host:port"). The conf layer reuses it so invalid
// entries fail at config-build time under the single authoritative parser.
func ValidateResolver(s string) error {
	_, _, _, err := parseResolver(s)
	return err
}

// ValidateDomainSpec reports whether s parses as a server domain spec with an
// optional method suffix ("example.com[:txt|a|aaaa]").
func ValidateDomainSpec(s string) error {
	_, err := parseDomainSpec(s, "")
	return err
}
