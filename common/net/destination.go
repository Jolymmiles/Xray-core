package net

import (
	"net"
	"net/netip"
	"strings"
	"sync"
)

type connectionIPAddress struct {
	bytes  [16]byte
	family AddressFamily
}

func (a *connectionIPAddress) IP() net.IP {
	if a.family.IsIPv4() {
		return a.bytes[:4]
	}
	return a.bytes[:]
}

func (*connectionIPAddress) Domain() string          { panic("Calling Domain() on an IPAddress.") }
func (a *connectionIPAddress) Family() AddressFamily { return a.family }
func (a *connectionIPAddress) String() string {
	ip := a.NetIPAddr()
	if ip.Is6() {
		return "[" + ip.String() + "]"
	}
	return ip.String()
}

func (a *connectionIPAddress) NetIPAddr() netip.Addr {
	if a.family.IsIPv4() {
		return netip.AddrFrom4([4]byte(a.bytes[:4]))
	}
	return netip.AddrFrom16(a.bytes)
}

// TCPConnectionAddresses owns allocation-free Source and Local destinations
// for the lifetime of one synchronously processed inbound connection.
type TCPConnectionAddresses struct {
	source     connectionIPAddress
	local      connectionIPAddress
	sourcePort Port
	localPort  Port
}

var tcpConnectionAddressesPool sync.Pool

func setConnectionIPAddress(destination *connectionIPAddress, address *net.TCPAddr) bool {
	if address.Zone != "" {
		return false
	}
	ip := address.IP
	switch len(ip) {
	case net.IPv4len:
		copy(destination.bytes[:4], ip)
		destination.family = AddressFamilyIPv4
		return true
	case net.IPv6len:
		if ip[0]|ip[1]|ip[2]|ip[3]|ip[4]|ip[5]|ip[6]|ip[7]|ip[8]|ip[9] == 0 && ip[10] == 0xff && ip[11] == 0xff {
			copy(destination.bytes[:4], ip[12:])
			destination.family = AddressFamilyIPv4
			return true
		}
		copy(destination.bytes[:], ip)
		destination.family = AddressFamilyIPv6
		return true
	default:
		return false
	}
}

// AcquireTCPConnectionAddresses returns nil unless both addresses are usable
// TCP endpoints; callers then retain their existing generic fallback.
func AcquireTCPConnectionAddresses(source, local net.Addr) *TCPConnectionAddresses {
	sourceTCP, sourceOK := source.(*net.TCPAddr)
	localTCP, localOK := local.(*net.TCPAddr)
	if !sourceOK || !localOK {
		return nil
	}
	addresses, _ := tcpConnectionAddressesPool.Get().(*TCPConnectionAddresses)
	if addresses == nil {
		addresses = new(TCPConnectionAddresses)
	}
	if !setConnectionIPAddress(&addresses.source, sourceTCP) || !setConnectionIPAddress(&addresses.local, localTCP) {
		tcpConnectionAddressesPool.Put(addresses)
		return nil
	}
	addresses.sourcePort = Port(sourceTCP.Port)
	addresses.localPort = Port(localTCP.Port)
	return addresses
}

func (a *TCPConnectionAddresses) Source() Destination {
	return TCPDestination(&a.source, a.sourcePort)
}

func (a *TCPConnectionAddresses) Local() Destination {
	return TCPDestination(&a.local, a.localPort)
}

func (a *TCPConnectionAddresses) Release() {
	if a != nil {
		tcpConnectionAddressesPool.Put(a)
	}
}

// Destination represents a network destination including address and protocol (tcp / udp).
type Destination struct {
	Address Address
	Port    Port
	Network Network
}

// DestinationFromAddr generates a Destination from a net address.
func DestinationFromAddr(addr net.Addr) Destination {
	switch addr := addr.(type) {
	case *net.TCPAddr:
		ip := addr.AddrPort().Addr().Unmap()
		if !ip.IsValid() {
			return TCPDestination(nil, Port(addr.Port))
		}
		if ip.Is4() {
			return TCPDestination(IPv4Address(ip.As4()), Port(addr.Port))
		}
		return TCPDestination(IPv6Address(ip.As16()), Port(addr.Port))
	case *net.UDPAddr:
		return UDPDestination(IPAddress(addr.IP), Port(addr.Port))
	case *net.UnixAddr:
		return UnixDestination(DomainAddress(addr.Name))
	default:
		panic("Net: Unknown address type.")
	}
}

// ParseDestination converts a destination from its string presentation.
func ParseDestination(dest string) (Destination, error) {
	d := Destination{
		Address: AnyIP,
		Port:    Port(0),
	}
	if strings.HasPrefix(dest, "tcp:") {
		d.Network = Network_TCP
		dest = dest[4:]
	} else if strings.HasPrefix(dest, "udp:") {
		d.Network = Network_UDP
		dest = dest[4:]
	} else if strings.HasPrefix(dest, "unix:") {
		d = UnixDestination(DomainAddress(dest[5:]))
		return d, nil
	}

	hstr, pstr, err := SplitHostPort(dest)
	if err != nil {
		return d, err
	}
	if len(hstr) > 0 {
		d.Address = ParseAddress(hstr)
	}
	if len(pstr) > 0 {
		port, err := PortFromString(pstr)
		if err != nil {
			return d, err
		}
		d.Port = port
	}
	return d, nil
}

// TCPDestination creates a TCP destination with given address
func TCPDestination(address Address, port Port) Destination {
	return Destination{
		Network: Network_TCP,
		Address: address,
		Port:    port,
	}
}

// UDPDestination creates a UDP destination with given address
func UDPDestination(address Address, port Port) Destination {
	return Destination{
		Network: Network_UDP,
		Address: address,
		Port:    port,
	}
}

// UnixDestination creates a Unix destination with given address
func UnixDestination(address Address) Destination {
	return Destination{
		Network: Network_UNIX,
		Address: address,
	}
}

// NetAddr returns the network address in this Destination in string form.
func (d Destination) NetAddr() string {
	var storage [272]byte
	return string(d.appendNetAddr(storage[:0]))
}

func (d Destination) appendNetAddr(address []byte) []byte {
	if d.Network == Network_TCP || d.Network == Network_UDP {
		switch destinationAddress := d.Address.(type) {
		case ipv4Address:
			return AppendIPv4Port(address, [4]byte(destinationAddress), d.Port)
		case ipv6Address:
			address = append(address, '[')
			address = netip.AddrFrom16([16]byte(destinationAddress)).AppendTo(address)
			address = append(address, ']')
		case domainAddress:
			address = append(address, string(destinationAddress)...)
		default:
			if provider, ok := destinationAddress.(interface{ RawIPv4() [4]byte }); ok {
				return AppendIPv4Port(address, provider.RawIPv4(), d.Port)
			} else if ip, ok := AddressToNetIPAddr(destinationAddress); ok {
				if ip.Is6() {
					address = append(address, '[')
				}
				address = ip.AppendTo(address)
				if ip.Is6() {
					address = append(address, ']')
				}
			} else if destinationAddress.Family().IsDomain() {
				address = append(address, destinationAddress.Domain()...)
			} else {
				address = append(address, destinationAddress.String()...)
			}
		}
		address = append(address, ':')
		return appendPort(address, d.Port)
	}
	if d.Network == Network_UNIX {
		return append(address, d.Address.String()...)
	}
	return address
}

// AppendIPv4Port appends an IPv4 host:port pair without an intermediate
// netip value or generic integer formatter.
func AppendIPv4Port(destination []byte, ip [4]byte, port Port) []byte {
	destination = appendIPv4Octet(destination, ip[0])
	destination = append(destination, '.')
	destination = appendIPv4Octet(destination, ip[1])
	destination = append(destination, '.')
	destination = appendIPv4Octet(destination, ip[2])
	destination = append(destination, '.')
	destination = appendIPv4Octet(destination, ip[3])
	destination = append(destination, ':')
	return appendPort(destination, port)
}

func appendPort(destination []byte, port Port) []byte {
	value := uint16(port)
	switch {
	case value >= 10000:
		return append(destination,
			'0'+byte(value/10000),
			'0'+byte(value/1000%10),
			'0'+byte(value/100%10),
			'0'+byte(value/10%10),
			'0'+byte(value%10))
	case value >= 1000:
		return append(destination,
			'0'+byte(value/1000),
			'0'+byte(value/100%10),
			'0'+byte(value/10%10),
			'0'+byte(value%10))
	case value >= 100:
		return append(destination,
			'0'+byte(value/100),
			'0'+byte(value/10%10),
			'0'+byte(value%10))
	case value >= 10:
		return append(destination,
			'0'+byte(value/10),
			'0'+byte(value%10))
	default:
		return append(destination, '0'+byte(value))
	}
}

const decimalDigitPairs = "00010203040506070809" +
	"10111213141516171819" +
	"20212223242526272829" +
	"30313233343536373839" +
	"40414243444546474849" +
	"50515253545556575859" +
	"60616263646566676869" +
	"70717273747576777879" +
	"80818283848586878889" +
	"90919293949596979899"

func appendIPv4Octet(destination []byte, value byte) []byte {
	if value >= 100 {
		destination = append(destination, '0'+value/100)
		pair := int(value%100) * 2
		return append(destination, decimalDigitPairs[pair], decimalDigitPairs[pair+1])
	}
	if value >= 10 {
		pair := int(value) * 2
		return append(destination, decimalDigitPairs[pair], decimalDigitPairs[pair+1])
	}
	return append(destination, '0'+value)
}

// AppendNetAddrTo appends the host:port representation without allocating an
// intermediate string.
func (d Destination) AppendNetAddrTo(destination []byte) []byte {
	return d.appendNetAddr(destination)
}

// RawNetAddr converts a net.Addr from its Destination presentation.
func (d Destination) RawNetAddr() net.Addr {
	var addr net.Addr
	switch d.Network {
	case Network_TCP:
		if d.Address.Family().IsIP() {
			addr = &net.TCPAddr{
				IP:   d.Address.IP(),
				Port: int(d.Port),
			}
		}
	case Network_UDP:
		if d.Address.Family().IsIP() {
			addr = &net.UDPAddr{
				IP:   d.Address.IP(),
				Port: int(d.Port),
			}
		}
	case Network_UNIX:
		if d.Address.Family().IsDomain() {
			addr = &net.UnixAddr{
				Name: d.Address.String(),
				Net:  d.Network.SystemString(),
			}
		}
	}
	return addr
}

// String returns the strings form of this Destination.
func (d Destination) String() string {
	var storage [280]byte
	destination := storage[:0]
	switch d.Network {
	case Network_TCP:
		destination = append(destination, "tcp:"...)
	case Network_UDP:
		destination = append(destination, "udp:"...)
	case Network_UNIX:
		destination = append(destination, "unix:"...)
	default:
		destination = append(destination, "unknown:"...)
	}
	return string(d.appendNetAddr(destination))
}

// FormatAccessEndpoints formats the VLESS access-log source and target into
// one owned allocation and returns stable slices for both fields.
func FormatAccessEndpoints(source, target Destination) (from, to string) {
	var storage [552]byte
	if sourceIP, sourceIsIPv4 := source.Address.(ipv4Address); sourceIsIPv4 &&
		(source.Network == Network_TCP || source.Network == Network_UDP) {
		if targetDomain, targetIsDomain := target.Address.(domainAddress); targetIsDomain &&
			(target.Network == Network_TCP || target.Network == Network_UDP) {
			formatted := AppendIPv4Port(storage[:0], [4]byte(sourceIP), source.Port)
			split := len(formatted)
			if target.Network == Network_TCP {
				formatted = append(formatted, "tcp:"...)
			} else {
				formatted = append(formatted, "udp:"...)
			}
			formatted = append(formatted, string(targetDomain)...)
			formatted = append(formatted, ':')
			formatted = appendPort(formatted, target.Port)
			owned := string(formatted)
			return owned[:split], owned[split:]
		}
	}
	if sourceIP, sourceIsIPv6 := source.Address.(ipv6Address); sourceIsIPv6 &&
		(source.Network == Network_TCP || source.Network == Network_UDP) {
		if targetDomain, targetIsDomain := target.Address.(domainAddress); targetIsDomain &&
			(target.Network == Network_TCP || target.Network == Network_UDP) {
			formatted := append(storage[:0], '[')
			formatted = netip.AddrFrom16([16]byte(sourceIP)).AppendTo(formatted)
			formatted = append(formatted, ']', ':')
			formatted = appendPort(formatted, source.Port)
			split := len(formatted)
			if target.Network == Network_TCP {
				formatted = append(formatted, "tcp:"...)
			} else {
				formatted = append(formatted, "udp:"...)
			}
			formatted = append(formatted, string(targetDomain)...)
			formatted = append(formatted, ':')
			formatted = appendPort(formatted, target.Port)
			owned := string(formatted)
			return owned[:split], owned[split:]
		}
	}
	if sourceIPv4, sourceIsIPv4 := source.Address.(*connectionIPAddress); sourceIsIPv4 &&
		sourceIPv4.family.IsIPv4() && (source.Network == Network_TCP || source.Network == Network_UDP) {
		if targetDomain, targetIsDomain := target.Address.(domainAddress); targetIsDomain &&
			(target.Network == Network_TCP || target.Network == Network_UDP) {
			formatted := AppendIPv4Port(storage[:0], [4]byte(sourceIPv4.bytes[:4]), source.Port)
			split := len(formatted)
			if target.Network == Network_TCP {
				formatted = append(formatted, "tcp:"...)
			} else {
				formatted = append(formatted, "udp:"...)
			}
			formatted = append(formatted, string(targetDomain)...)
			formatted = append(formatted, ':')
			formatted = appendPort(formatted, target.Port)
			owned := string(formatted)
			return owned[:split], owned[split:]
		}
	}
	if sourceIPv6, sourceIsIPv6 := source.Address.(*connectionIPAddress); sourceIsIPv6 &&
		sourceIPv6.family.IsIPv6() && (source.Network == Network_TCP || source.Network == Network_UDP) {
		if targetDomain, targetIsDomain := target.Address.(domainAddress); targetIsDomain &&
			(target.Network == Network_TCP || target.Network == Network_UDP) {
			formatted := append(storage[:0], '[')
			formatted = netip.AddrFrom16(sourceIPv6.bytes).AppendTo(formatted)
			formatted = append(formatted, ']', ':')
			formatted = appendPort(formatted, source.Port)
			split := len(formatted)
			if target.Network == Network_TCP {
				formatted = append(formatted, "tcp:"...)
			} else {
				formatted = append(formatted, "udp:"...)
			}
			formatted = append(formatted, string(targetDomain)...)
			formatted = append(formatted, ':')
			formatted = appendPort(formatted, target.Port)
			owned := string(formatted)
			return owned[:split], owned[split:]
		}
	}
	formatted := source.appendNetAddr(storage[:0])
	split := len(formatted)
	switch target.Network {
	case Network_TCP:
		formatted = append(formatted, "tcp:"...)
	case Network_UDP:
		formatted = append(formatted, "udp:"...)
	case Network_UNIX:
		formatted = append(formatted, "unix:"...)
	default:
		formatted = append(formatted, "unknown:"...)
	}
	formatted = target.appendNetAddr(formatted)
	owned := string(formatted)
	return owned[:split], owned[split:]
}

// FormatAccessEndpointsFromAddr formats a socket peer and target without
// allocating an intermediate Destination for built-in TCP and UDP addresses.
func FormatAccessEndpointsFromAddr(source net.Addr, target Destination) (from, to string) {
	var sourceAddr netip.Addr
	var sourcePort Port
	switch source := source.(type) {
	case *net.TCPAddr:
		sourceAddr = source.AddrPort().Addr().Unmap()
		sourcePort = Port(source.Port)
	case *net.UDPAddr:
		sourceAddr = source.AddrPort().Addr().Unmap()
		sourcePort = Port(source.Port)
	default:
		return FormatAccessEndpoints(DestinationFromAddr(source), target)
	}
	if !sourceAddr.IsValid() {
		return FormatAccessEndpoints(DestinationFromAddr(source), target)
	}

	var storage [552]byte
	formatted := storage[:0]
	if sourceAddr.Is4() {
		formatted = AppendIPv4Port(formatted, sourceAddr.As4(), sourcePort)
	} else {
		formatted = append(formatted, '[')
		formatted = sourceAddr.WithZone("").AppendTo(formatted)
		formatted = append(formatted, ']', ':')
		formatted = appendPort(formatted, sourcePort)
	}
	split := len(formatted)
	switch target.Network {
	case Network_TCP:
		formatted = append(formatted, "tcp:"...)
	case Network_UDP:
		formatted = append(formatted, "udp:"...)
	case Network_UNIX:
		formatted = append(formatted, "unix:"...)
	default:
		formatted = append(formatted, "unknown:"...)
	}
	if targetDomain, ok := target.Address.(domainAddress); ok &&
		(target.Network == Network_TCP || target.Network == Network_UDP) {
		formatted = append(formatted, string(targetDomain)...)
		formatted = append(formatted, ':')
		formatted = appendPort(formatted, target.Port)
		owned := string(formatted)
		return owned[:split], owned[split:]
	}
	formatted = target.appendNetAddr(formatted)
	owned := string(formatted)
	return owned[:split], owned[split:]
}

// IsValid returns true if this Destination is valid.
func (d Destination) IsValid() bool {
	return d.Network != Network_Unknown
}

// AsDestination converts current Endpoint into Destination.
func (p *Endpoint) AsDestination() Destination {
	return Destination{
		Network: p.Network,
		Address: p.Address.AsAddress(),
		Port:    Port(p.Port),
	}
}
