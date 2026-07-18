package http

import (
	"context"
	"net/http"
	stdnetip "net/netip"
	"strconv"
	"strings"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
)

// ApplyTrustedXForwardedFor returns remoteAddr overridden by X-Forwarded-For only when a configured trusted header is present.
func ApplyTrustedXForwardedFor(header http.Header, trusted []string, remoteAddr net.Addr) net.Addr {
	value := header.Get("X-Forwarded-For")
	if value == "" {
		return remoteAddr
	}
	for _, t := range trusted {
		if len(header.Values(t)) > 0 {
			if idx := strings.IndexByte(value, ','); idx >= 0 {
				value = value[:idx]
			}
			if addr := net.ParseAddress(value); addr.Family().IsIP() {
				return &net.TCPAddr{
					IP:   addr.IP(),
					Port: 0,
				}
			}
			return remoteAddr
		}
	}
	if len(trusted) == 0 {
		errors.LogWarning(context.Background(), `received "X-Forwarded-For" from `, remoteAddr, ` but "sockopt.trustedXForwardedFor" is not configured; ignoring it and using the real remote address`)
	} else {
		errors.LogError(context.Background(), `ignored potentially forged "X-Forwarded-For" from `, remoteAddr, `: `, value)
	}
	return remoteAddr
}

// RemoveHopByHopHeaders removes hop by hop headers in http header list.
func RemoveHopByHopHeaders(header http.Header) {
	// Strip hop-by-hop header based on RFC:
	// http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html#sec13.5.1
	// https://www.mnot.net/blog/2011/07/11/what_proxies_must_do

	header.Del("Proxy-Connection")
	header.Del("Proxy-Authenticate")
	header.Del("Proxy-Authorization")
	header.Del("TE")
	header.Del("Trailers")
	header.Del("Transfer-Encoding")
	header.Del("Upgrade")

	connections := header.Get("Connection")
	header.Del("Connection")
	if connections == "" {
		return
	}
	for _, h := range strings.Split(connections, ",") {
		header.Del(strings.TrimSpace(h))
	}
}

// ParseHost splits host and port from a raw string. Default port is used when raw string doesn't contain port.
func ParseHost(rawHost string, defaultPort net.Port) (net.Destination, error) {
	port := defaultPort
	host := rawHost
	colon := -1
	multipleColons := false
	for index := range len(rawHost) {
		if rawHost[index] != ':' {
			continue
		}
		if colon < 0 {
			colon = index
		} else {
			multipleColons = true
			break
		}
	}
	if colon >= 0 && !multipleColons && rawHost[0] != '[' {
		host = rawHost[:colon]
		if rawPort := rawHost[colon+1:]; len(rawPort) > 0 {
			intPort, err := strconv.Atoi(rawPort)
			if err != nil {
				return net.Destination{}, err
			}
			port = net.Port(intPort)
		}
	} else if colon >= 0 && !(len(rawHost) >= 2 && rawHost[0] == '[' && rawHost[len(rawHost)-1] == ']') {
		var rawPort string
		var err error
		host, rawPort, err = net.SplitHostPort(rawHost)
		if err != nil {
			if addrError, ok := err.(*net.AddrError); !ok || !strings.Contains(addrError.Err, "missing port") {
				return net.Destination{}, err
			}
			host = rawHost
		} else if len(rawPort) > 0 {
			intPort, err := strconv.Atoi(rawPort)
			if err != nil {
				return net.Destination{}, err
			}
			port = net.Port(intPort)
		}
	}

	return net.TCPDestination(parseHostAddress(host), port), nil
}

func parseHostAddress(host string) net.Address {
	if len(host) > 0 && (host[0] == ' ' || host[0] == '\t' || host[len(host)-1] == ' ' || host[len(host)-1] == '\t') {
		host = strings.TrimSpace(host)
	}
	if isDomainWithoutPort(host) {
		return net.DomainAddress(host)
	}
	candidate := host
	if len(candidate) >= 2 && candidate[0] == '[' && candidate[len(candidate)-1] == ']' {
		candidate = candidate[1 : len(candidate)-1]
	}
	address, err := stdnetip.ParseAddr(candidate)
	if err != nil || address.Zone() != "" {
		return net.DomainAddress(candidate)
	}
	if address.Is4() {
		bytes := address.As4()
		return net.IPAddress(bytes[:])
	}
	bytes := address.As16()
	return net.IPAddress(bytes[:])
}

func isDomainWithoutPort(host string) bool {
	if strings.IndexByte(host, ':') >= 0 {
		return false
	}
	for index := range len(host) {
		value := host[index]
		if (value < '0' || value > '9') && value != '.' {
			return true
		}
	}
	return false
}
