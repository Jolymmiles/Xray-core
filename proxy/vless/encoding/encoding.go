package encoding

import (
	"context"
	"io"
	stdnet "net"
	"net/netip"
	"sync"
	"unsafe"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/vless"
)

const (
	Version = byte(0)
)

var plainV0ResponseHeader = [2]byte{Version, 0}

var (
	requestHeaderPool sync.Pool
	domainRequestPool sync.Pool
	ipv4RequestPool   sync.Pool
	ipv6RequestPool   sync.Pool
)

const pooledDomainCapacity = 63

type pooledDomainRequest struct {
	header  protocol.RequestHeader
	address pooledDomainAddress
}

type pooledDomainAddress struct {
	owner  *pooledDomainRequest
	length byte
	bytes  [pooledDomainCapacity]byte
	long   string
}

type pooledIPv4Request struct {
	header  protocol.RequestHeader
	address pooledIPv4Address
}

type pooledIPv4Address struct {
	owner *pooledIPv4Request
	bytes [4]byte
}

type pooledIPv6Request struct {
	header  protocol.RequestHeader
	address pooledIPv6Address
}

type pooledIPv6Address struct {
	owner *pooledIPv6Request
	bytes [16]byte
}

func (a *pooledIPv4Address) IP() stdnet.IP {
	return a.bytes[:]
}

func (*pooledIPv4Address) Domain() string {
	panic("Calling Domain() on an IPv4Address.")
}

func (*pooledIPv4Address) Family() net.AddressFamily {
	return net.AddressFamilyIPv4
}

func (a *pooledIPv4Address) String() string {
	return stdnet.IP(a.bytes[:]).String()
}

func (a *pooledIPv4Address) NetIPAddr() netip.Addr {
	return netip.AddrFrom4(a.bytes)
}

func (a *pooledIPv4Address) releaseRequest() {
	request := a.owner
	request.header = protocol.RequestHeader{}
	ipv4RequestPool.Put(request)
}

func (a *pooledIPv6Address) IP() stdnet.IP {
	return a.bytes[:]
}

func (*pooledIPv6Address) Domain() string {
	panic("Calling Domain() on an IPv6Address.")
}

func (*pooledIPv6Address) Family() net.AddressFamily {
	return net.AddressFamilyIPv6
}

func (a *pooledIPv6Address) String() string {
	return "[" + stdnet.IP(a.bytes[:]).String() + "]"
}

func (a *pooledIPv6Address) NetIPAddr() netip.Addr {
	return netip.AddrFrom16(a.bytes)
}

func (a *pooledIPv6Address) releaseRequest() {
	request := a.owner
	request.header = protocol.RequestHeader{}
	ipv6RequestPool.Put(request)
}

func (*pooledDomainAddress) IP() stdnet.IP {
	panic("Calling IP() on a DomainAddress.")
}

func (a *pooledDomainAddress) Domain() string {
	if a.long != "" {
		return a.long
	}
	return unsafe.String(&a.bytes[0], a.length)
}

func (*pooledDomainAddress) Family() net.AddressFamily {
	return net.AddressFamilyDomain
}

func (a *pooledDomainAddress) String() string {
	if a.long != "" {
		return a.long
	}
	return unsafe.String(&a.bytes[0], a.length)
}

func (a *pooledDomainAddress) releaseRequest() {
	request := a.owner
	a.length = 0
	a.long = ""
	request.header = protocol.RequestHeader{}
	domainRequestPool.Put(request)
}

func newPooledDomainRequest(domain []byte) *protocol.RequestHeader {
	request, _ := domainRequestPool.Get().(*pooledDomainRequest)
	if request == nil {
		request = new(pooledDomainRequest)
		request.address.owner = request
	}
	address := &request.address
	if len(domain) <= len(address.bytes) {
		address.length = byte(copy(address.bytes[:], domain))
		address.long = ""
	} else {
		address.length = 0
		address.long = string(domain)
	}
	request.header.Address = address
	return &request.header
}

func newPooledIPv4Request(ip []byte) *protocol.RequestHeader {
	request, _ := ipv4RequestPool.Get().(*pooledIPv4Request)
	if request == nil {
		request = new(pooledIPv4Request)
		request.address.owner = request
	}
	copy(request.address.bytes[:], ip)
	request.header.Address = &request.address
	return &request.header
}

func newPooledIPv6Request(ip []byte) *protocol.RequestHeader {
	request, _ := ipv6RequestPool.Get().(*pooledIPv6Request)
	if request == nil {
		request = new(pooledIPv6Request)
		request.address.owner = request
	}
	copy(request.address.bytes[:], ip)
	request.header.Address = &request.address
	return &request.header
}

func newRequestHeader() *protocol.RequestHeader {
	request, _ := requestHeaderPool.Get().(*protocol.RequestHeader)
	if request == nil {
		request = new(protocol.RequestHeader)
	}
	return request
}

// ReleaseRequestHeader clears authentication and destination references before
// returning a connection-scoped decoded request for reuse.
func ReleaseRequestHeader(request *protocol.RequestHeader) {
	if request == nil {
		return
	}
	if address, ok := request.Address.(interface{ releaseRequest() }); ok {
		address.releaseRequest()
		return
	}
	*request = protocol.RequestHeader{}
	requestHeaderPool.Put(request)
}

var plainDomainByte = func() [256]bool {
	var allowed [256]bool
	for c := byte('0'); c <= '9'; c++ {
		allowed[c] = true
	}
	for c := byte('a'); c <= 'z'; c++ {
		allowed[c] = true
	}
	for c := byte('A'); c <= 'Z'; c++ {
		allowed[c] = true
	}
	allowed['-'] = true
	allowed['.'] = true
	allowed['_'] = true
	return allowed
}()

var plainDomainPair = func() [1 << 16]bool {
	var allowed [1 << 16]bool
	for first := 0; first < 256; first++ {
		if !plainDomainByte[first] {
			continue
		}
		for second := 0; second < 256; second++ {
			allowed[first<<8|second] = plainDomainByte[second]
		}
	}
	return allowed
}()

var addrParser = protocol.NewAddressParser(
	protocol.AddressFamilyByte(byte(protocol.AddressTypeIPv4), net.AddressFamilyIPv4),
	protocol.AddressFamilyByte(byte(protocol.AddressTypeDomain), net.AddressFamilyDomain),
	protocol.AddressFamilyByte(byte(protocol.AddressTypeIPv6), net.AddressFamilyIPv6),
	protocol.PortThenAddress(),
)

// EncodeRequestHeader writes encoded request header into the given writer.
func EncodeRequestHeader(writer io.Writer, request *protocol.RequestHeader, requestAddons *Addons) error {
	if requestAddons.Flow == "" {
		return encodePlainRequestHeader(writer, request)
	}
	return encodeRequestHeaderBuffered(writer, request, requestAddons)
}

func encodePlainRequestHeader(writer io.Writer, request *protocol.RequestHeader) error {
	length := 19 // version + UUID + addons length + command
	var family net.AddressFamily
	var domain string
	if request.Command != protocol.RequestCommandMux && request.Command != protocol.RequestCommandRvs {
		length += 3 // port + address type
		family = request.Address.Family()
		switch family {
		case net.AddressFamilyIPv4:
			length += 4
		case net.AddressFamilyIPv6:
			length += 16
		case net.AddressFamilyDomain:
			domain = request.Address.Domain()
			if len(domain) > 255 {
				return encodeRequestHeaderBuffered(writer, request, &Addons{})
			}
			length += 1 + len(domain)
		default:
			return encodeRequestHeaderBuffered(writer, request, &Addons{})
		}
	}

	header := make([]byte, length)
	header[0] = request.Version
	copy(header[1:17], request.User.Account.(*vless.MemoryAccount).ID.Bytes())
	header[17] = 0
	header[18] = byte(request.Command)
	offset := 19

	if request.Command != protocol.RequestCommandMux && request.Command != protocol.RequestCommandRvs {
		header[offset] = byte(request.Port >> 8)
		header[offset+1] = byte(request.Port)
		offset += 2

		switch family {
		case net.AddressFamilyIPv4:
			header[offset] = byte(protocol.AddressTypeIPv4)
			offset++
			copy(header[offset:], request.Address.IP())
		case net.AddressFamilyIPv6:
			header[offset] = byte(protocol.AddressTypeIPv6)
			offset++
			copy(header[offset:], request.Address.IP())
		case net.AddressFamilyDomain:
			header[offset] = byte(protocol.AddressTypeDomain)
			header[offset+1] = byte(len(domain))
			copy(header[offset+2:], domain)
		}
	}

	if _, err := writer.Write(header); err != nil {
		return errors.New("failed to write request header").Base(err)
	}
	return nil
}

func encodeRequestHeaderBuffered(writer io.Writer, request *protocol.RequestHeader, requestAddons *Addons) error {
	buffer := buf.StackNew()
	defer buffer.Release()

	if err := buffer.WriteByte(request.Version); err != nil {
		return errors.New("failed to write request version").Base(err)
	}

	if _, err := buffer.Write(request.User.Account.(*vless.MemoryAccount).ID.Bytes()); err != nil {
		return errors.New("failed to write request user id").Base(err)
	}

	if err := EncodeHeaderAddons(&buffer, requestAddons); err != nil {
		return errors.New("failed to encode request header addons").Base(err)
	}

	if err := buffer.WriteByte(byte(request.Command)); err != nil {
		return errors.New("failed to write request command").Base(err)
	}

	if request.Command != protocol.RequestCommandMux && request.Command != protocol.RequestCommandRvs {
		if err := addrParser.WriteAddressPort(&buffer, request.Address, request.Port); err != nil {
			return errors.New("failed to write request address and port").Base(err)
		}
	}

	if _, err := writer.Write(buffer.Bytes()); err != nil {
		return errors.New("failed to write request header").Base(err)
	}

	return nil
}

// DecodeRequestHeader decodes and returns (if successful) a RequestHeader from an input stream.
func DecodeRequestHeader(isfb bool, first *buf.Buffer, reader io.Reader, validator vless.Validator) ([]byte, *protocol.RequestHeader, *Addons, bool, error) {
	id, request, addons, fallback, err := decodeRequestHeader(isfb, first, reader, validator, true)
	if err != nil {
		return nil, request, nil, fallback, err
	}
	return id[:], request, &Addons{Flow: addons.Flow, Seed: addons.Seed}, fallback, nil
}

func decodeRequestHeader(isfb bool, first *buf.Buffer, reader io.Reader, validator vless.Validator, probePlain bool) ([16]byte, *protocol.RequestHeader, HeaderAddons, bool, error) {
	if probePlain && isfb {
		if id, request, addons, fallback, err, handled := decodePlainRequestHeaderFromFirst(first, validator); handled {
			return id, request, addons, fallback, err
		}
	}

	buffer := buf.New()

	var version byte
	if isfb {
		version = first.Byte(0)
	} else {
		if _, err := buffer.ReadFullFrom(reader, 1); err != nil {
			buffer.Release()
			return [16]byte{}, nil, HeaderAddons{}, false, errors.New("failed to read request version").Base(err)
		}
		version = buffer.Byte(0)
	}

	switch version {
	case 0:

		var id [16]byte

		if isfb {
			copy(id[:], first.BytesRange(1, 17))
		} else {
			buffer.Clear()
			if _, err := buffer.ReadFullFrom(reader, 16); err != nil {
				buffer.Release()
				return [16]byte{}, nil, HeaderAddons{}, false, errors.New("failed to read request user id").Base(err)
			}
			copy(id[:], buffer.Bytes())
		}

		user := validator.Get(id)
		if user == nil {
			u := uuid.UUID(id)
			buffer.Release()
			return [16]byte{}, nil, HeaderAddons{}, isfb, errors.New("invalid request user id: ", &u)
		}

		if isfb {
			first.Advance(17)
		}

		requestAddons, err := decodeHeaderAddonsValue(buffer, reader)
		if err != nil {
			buffer.Release()
			return [16]byte{}, nil, HeaderAddons{}, false, errors.New("failed to decode request header addons").Base(err)
		}

		var commandByte byte
		if byteReader, ok := reader.(io.ByteReader); ok {
			value, err := byteReader.ReadByte()
			if err != nil {
				buffer.Release()
				return [16]byte{}, nil, HeaderAddons{}, false, errors.New("failed to read request command").Base(err)
			}
			commandByte = value
		} else {
			buffer.Clear()
			if _, err := buffer.ReadFullFrom(reader, 1); err != nil {
				buffer.Release()
				return [16]byte{}, nil, HeaderAddons{}, false, errors.New("failed to read request command").Base(err)
			}
			commandByte = buffer.Byte(0)
		}

		command := protocol.RequestCommand(commandByte)
		var request *protocol.RequestHeader
		switch command {
		case protocol.RequestCommandMux:
			request = newRequestHeader()
			request.Address = net.DomainAddress("v1.mux.cool")
		case protocol.RequestCommandRvs:
			request = newRequestHeader()
			request.Address = net.DomainAddress("v1.rvs.cool")
		case protocol.RequestCommandTCP, protocol.RequestCommandUDP:
			request = readPooledRequestAddress(buffer, reader)
		}
		if request == nil {
			buffer.Release()
			return [16]byte{}, nil, HeaderAddons{}, false, errors.New("invalid request address")
		}
		request.Version = version
		request.User = user
		request.Command = command
		buffer.Release()
		return id, request, requestAddons, false, nil
	default:
		buffer.Release()
		return [16]byte{}, nil, HeaderAddons{}, isfb, errors.New("invalid request version")
	}
}

// DecodeRequestHeaderFromFirst uses an already-buffered VLESS prefix when it
// contains the complete user ID. allowFallback controls only error routing;
// disabling it never turns an invalid UUID or version into a fallback request.
func DecodeRequestHeaderFromFirst(first *buf.Buffer, reader io.Reader, validator vless.Validator, allowFallback bool) ([16]byte, *protocol.RequestHeader, HeaderAddons, bool, error) {
	useFirst := first != nil && first.Len() >= 17
	if useFirst {
		if id, request, addons, fallback, err, handled := decodePlainRequestHeaderFromFirst(first, validator); handled {
			if !allowFallback {
				fallback = false
			}
			return id, request, addons, fallback, err
		}
	}
	id, request, addons, fallback, err := decodeRequestHeader(useFirst, first, reader, validator, false)
	if !allowFallback {
		fallback = false
	}
	return id, request, addons, fallback, err
}

func decodePlainRequestHeaderFromFirst(first *buf.Buffer, validator vless.Validator) ([16]byte, *protocol.RequestHeader, HeaderAddons, bool, error, bool) {
	data := first.Bytes()
	if len(data) < 19 || data[0] != Version || data[17] != 0 {
		return [16]byte{}, nil, HeaderAddons{}, false, nil, false
	}

	var id [16]byte
	copy(id[:], data[1:17])
	user := validator.Get(id)
	if user == nil {
		u := uuid.UUID(id)
		return [16]byte{}, nil, HeaderAddons{}, true, errors.New("invalid request user id: ", &u), true
	}

	command := protocol.RequestCommand(data[18])
	var request *protocol.RequestHeader
	var port net.Port
	headerLength := 19

	switch command {
	case protocol.RequestCommandMux:
		request = newRequestHeader()
		request.Address = net.DomainAddress("v1.mux.cool")
	case protocol.RequestCommandRvs:
		request = newRequestHeader()
		request.Address = net.DomainAddress("v1.rvs.cool")
	case protocol.RequestCommandTCP, protocol.RequestCommandUDP:
		if len(data) < 22 {
			return [16]byte{}, nil, HeaderAddons{}, false, nil, false
		}
		port = net.PortFromBytes(data[19:21])
		switch protocol.AddressType(data[21]) {
		case protocol.AddressTypeIPv4:
			headerLength = 26
			if len(data) < headerLength {
				return [16]byte{}, nil, HeaderAddons{}, false, nil, false
			}
			request = newPooledIPv4Request(data[22:headerLength])
		case protocol.AddressTypeIPv6:
			headerLength = 38
			if len(data) < headerLength {
				return [16]byte{}, nil, HeaderAddons{}, false, nil, false
			}
			request = newPooledIPv6Request(data[22:headerLength])
		case protocol.AddressTypeDomain:
			if len(data) < 23 {
				return [16]byte{}, nil, HeaderAddons{}, false, nil, false
			}
			domainLength := int(data[22])
			headerLength = 23 + domainLength
			if domainLength == 0 || len(data) < headerLength {
				return [16]byte{}, nil, HeaderAddons{}, false, nil, false
			}
			domainBytes := data[23:headerLength]
			domain := unsafe.String(&domainBytes[0], len(domainBytes))
			if domain[0] == '[' || domain[0] >= '0' && domain[0] <= '9' {
				address := net.ParseAddress(domain)
				if address.Family().IsIP() {
					request = newRequestHeader()
					request.Address = address
					break
				}
			}
			if !isPlainDomain(domain) {
				return [16]byte{}, nil, HeaderAddons{}, false, nil, false
			}
			request = newPooledDomainRequest(domainBytes)
		default:
			return [16]byte{}, nil, HeaderAddons{}, false, nil, false
		}
	default:
		return [16]byte{}, nil, HeaderAddons{}, false, nil, false
	}

	first.Advance(int32(headerLength))
	request.Version = Version
	request.User = user
	request.Command = command
	request.Port = port
	return id, request, HeaderAddons{}, false, nil, true
}

func readPooledRequestAddress(buffer *buf.Buffer, reader io.Reader) *protocol.RequestHeader {
	buffer.Clear()
	if _, err := buffer.ReadFullFrom(reader, 3); err != nil {
		return nil
	}
	data := buffer.Bytes()
	port := net.PortFromBytes(data[:2])
	var request *protocol.RequestHeader
	switch protocol.AddressType(data[2]) {
	case protocol.AddressTypeIPv4:
		pooled, _ := ipv4RequestPool.Get().(*pooledIPv4Request)
		if pooled == nil {
			pooled = new(pooledIPv4Request)
			pooled.address.owner = pooled
		}
		if _, err := io.ReadFull(reader, pooled.address.bytes[:]); err != nil {
			pooled.address.releaseRequest()
			return nil
		}
		pooled.header.Address = &pooled.address
		request = &pooled.header
	case protocol.AddressTypeIPv6:
		pooled, _ := ipv6RequestPool.Get().(*pooledIPv6Request)
		if pooled == nil {
			pooled = new(pooledIPv6Request)
			pooled.address.owner = pooled
		}
		if _, err := io.ReadFull(reader, pooled.address.bytes[:]); err != nil {
			pooled.address.releaseRequest()
			return nil
		}
		pooled.header.Address = &pooled.address
		request = &pooled.header
	case protocol.AddressTypeDomain:
		var domainLength byte
		domainStart := int32(3)
		if byteReader, ok := reader.(io.ByteReader); ok {
			value, err := byteReader.ReadByte()
			if err != nil {
				return nil
			}
			domainLength = value
		} else {
			if _, err := buffer.ReadFullFrom(reader, 1); err != nil {
				return nil
			}
			domainLength = buffer.Byte(3)
			domainStart = 4
		}
		if domainLength == 0 {
			return nil
		}
		var pooledDomain *pooledDomainRequest
		var domainBytes []byte
		if int(domainLength) <= pooledDomainCapacity {
			pooledDomain, _ = domainRequestPool.Get().(*pooledDomainRequest)
			if pooledDomain == nil {
				pooledDomain = new(pooledDomainRequest)
				pooledDomain.address.owner = pooledDomain
			}
			domainBytes = pooledDomain.address.bytes[:domainLength]
			if _, err := io.ReadFull(reader, domainBytes); err != nil {
				pooledDomain.address.releaseRequest()
				return nil
			}
		} else {
			if _, err := buffer.ReadFullFrom(reader, int32(domainLength)); err != nil {
				return nil
			}
			domainBytes = buffer.BytesRange(domainStart, domainStart+int32(domainLength))
		}
		domain := unsafe.String(&domainBytes[0], len(domainBytes))
		if domain[0] == '[' || domain[0] >= '0' && domain[0] <= '9' {
			candidate := domain
			if len(candidate) > 1 && candidate[0] == '[' && candidate[len(candidate)-1] == ']' {
				candidate = candidate[1 : len(candidate)-1]
			}
			if ip, err := netip.ParseAddr(candidate); err == nil && ip.Zone() == "" {
				ip = ip.Unmap()
				if ip.Is4() {
					value := ip.As4()
					request = newPooledIPv4Request(value[:])
				} else {
					value := ip.As16()
					request = newPooledIPv6Request(value[:])
				}
				if pooledDomain != nil {
					pooledDomain.address.releaseRequest()
				}
				break
			}
		}
		if !isPlainDomain(domain) {
			if pooledDomain != nil {
				pooledDomain.address.releaseRequest()
			}
			return nil
		}
		if pooledDomain != nil {
			pooledDomain.address.length = domainLength
			pooledDomain.address.long = ""
			pooledDomain.header.Address = &pooledDomain.address
			request = &pooledDomain.header
		} else {
			request = newPooledDomainRequest(domainBytes)
		}
	default:
		return nil
	}
	request.Port = port
	return request
}

func isPlainDomain(domain string) bool {
	i := 0
	for ; i+4 <= len(domain); i += 4 {
		if !plainDomainPair[uint16(domain[i])<<8|uint16(domain[i+1])] ||
			!plainDomainPair[uint16(domain[i+2])<<8|uint16(domain[i+3])] {
			return false
		}
	}
	for ; i < len(domain); i++ {
		if !plainDomainByte[domain[i]] {
			return false
		}
	}
	return true
}

// EncodeResponseHeader writes encoded response header into the given writer.
func EncodeResponseHeader(writer io.Writer, request *protocol.RequestHeader, responseAddons *Addons) error {
	if responseAddons == nil || responseAddons.Flow == "" {
		header := plainV0ResponseHeader[:]
		if request.Version != Version {
			header = []byte{request.Version, 0}
		}
		if _, err := writer.Write(header); err != nil {
			return errors.New("failed to write response header").Base(err)
		}
		return nil
	}

	buffer := buf.StackNew()
	defer buffer.Release()

	if err := buffer.WriteByte(request.Version); err != nil {
		return errors.New("failed to write response version").Base(err)
	}

	if err := EncodeHeaderAddons(&buffer, responseAddons); err != nil {
		return errors.New("failed to encode response header addons").Base(err)
	}

	if _, err := writer.Write(buffer.Bytes()); err != nil {
		return errors.New("failed to write response header").Base(err)
	}

	return nil
}

// DecodeResponseHeader decodes and returns (if successful) a ResponseHeader from an input stream.
func DecodeResponseHeader(reader io.Reader, request *protocol.RequestHeader) (*Addons, error) {
	buffer := buf.StackNew()
	defer buffer.Release()

	if _, err := buffer.ReadFullFrom(reader, 1); err != nil {
		return nil, errors.New("failed to read response version").Base(err)
	}

	if buffer.Byte(0) != request.Version {
		return nil, errors.New("unexpected response version. Expecting ", int(request.Version), " but actually ", int(buffer.Byte(0)))
	}

	responseAddons, err := DecodeHeaderAddons(&buffer, reader)
	if err != nil {
		return nil, errors.New("failed to decode response header addons").Base(err)
	}

	return responseAddons, nil
}

// XtlsRead can switch to splice copy
func XtlsRead(reader buf.Reader, writer buf.Writer, timer *signal.ActivityTimer, conn net.Conn, trafficState *proxy.TrafficState, isUplink bool, ctx context.Context) error {
	err := func() error {
		for {
			if isUplink && trafficState.Inbound.UplinkReaderDirectCopy || !isUplink && trafficState.Outbound.DownlinkReaderDirectCopy {
				var writerConn net.Conn
				var inTimer *signal.ActivityTimer
				if inbound := session.InboundFromContext(ctx); inbound != nil && inbound.Conn != nil {
					writerConn = inbound.Conn
					inTimer = inbound.Timer
				}
				return proxy.CopyRawConnIfExist(ctx, conn, writerConn, writer, timer, inTimer)
			}
			buffer, err := reader.ReadMultiBuffer()
			if !buffer.IsEmpty() {
				timer.Update()
				if werr := writer.WriteMultiBuffer(buffer); werr != nil {
					return werr
				}
			}
			if err != nil {
				return err
			}
		}
	}()
	if err != nil && errors.Cause(err) != io.EOF {
		return err
	}
	return nil
}
