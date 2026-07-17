package encoding

import (
	"context"
	"io"

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
	if isfb {
		if id, request, addons, fallback, err, handled := decodePlainRequestHeaderFromFirst(first, validator); handled {
			return id, request, addons, fallback, err
		}
	}

	buffer := buf.StackNew()
	defer buffer.Release()

	request := new(protocol.RequestHeader)

	if isfb {
		request.Version = first.Byte(0)
	} else {
		if _, err := buffer.ReadFullFrom(reader, 1); err != nil {
			return nil, nil, nil, false, errors.New("failed to read request version").Base(err)
		}
		request.Version = buffer.Byte(0)
	}

	switch request.Version {
	case 0:

		var id [16]byte

		if isfb {
			copy(id[:], first.BytesRange(1, 17))
		} else {
			buffer.Clear()
			if _, err := buffer.ReadFullFrom(reader, 16); err != nil {
				return nil, nil, nil, false, errors.New("failed to read request user id").Base(err)
			}
			copy(id[:], buffer.Bytes())
		}

		if request.User = validator.Get(id); request.User == nil {
			u := uuid.UUID(id)
			return nil, nil, nil, isfb, errors.New("invalid request user id: " + u.String())
		}

		if isfb {
			first.Advance(17)
		}

		requestAddons, err := DecodeHeaderAddons(&buffer, reader)
		if err != nil {
			return nil, nil, nil, false, errors.New("failed to decode request header addons").Base(err)
		}

		buffer.Clear()
		if _, err := buffer.ReadFullFrom(reader, 1); err != nil {
			return nil, nil, nil, false, errors.New("failed to read request command").Base(err)
		}

		request.Command = protocol.RequestCommand(buffer.Byte(0))
		switch request.Command {
		case protocol.RequestCommandMux:
			request.Address = net.DomainAddress("v1.mux.cool")
		case protocol.RequestCommandRvs:
			request.Address = net.DomainAddress("v1.rvs.cool")
		case protocol.RequestCommandTCP, protocol.RequestCommandUDP:
			if addr, port, err := addrParser.ReadAddressPort(&buffer, reader); err == nil {
				request.Address = addr
				request.Port = port
			}
		}
		if request.Address == nil {
			return nil, nil, nil, false, errors.New("invalid request address")
		}
		return id[:], request, requestAddons, false, nil
	default:
		return nil, nil, nil, isfb, errors.New("invalid request version")
	}
}

func decodePlainRequestHeaderFromFirst(first *buf.Buffer, validator vless.Validator) ([]byte, *protocol.RequestHeader, *Addons, bool, error, bool) {
	data := first.Bytes()
	if len(data) < 19 || data[0] != Version || data[17] != 0 {
		return nil, nil, nil, false, nil, false
	}

	var id [16]byte
	copy(id[:], data[1:17])
	user := validator.Get(id)
	if user == nil {
		u := uuid.UUID(id)
		return nil, nil, nil, true, errors.New("invalid request user id: " + u.String()), true
	}

	request := &protocol.RequestHeader{
		Version: Version,
		User:    user,
		Command: protocol.RequestCommand(data[18]),
	}
	headerLength := 19

	switch request.Command {
	case protocol.RequestCommandMux:
		request.Address = net.DomainAddress("v1.mux.cool")
	case protocol.RequestCommandRvs:
		request.Address = net.DomainAddress("v1.rvs.cool")
	case protocol.RequestCommandTCP, protocol.RequestCommandUDP:
		if len(data) < 22 {
			return nil, nil, nil, false, nil, false
		}
		request.Port = net.PortFromBytes(data[19:21])
		switch protocol.AddressType(data[21]) {
		case protocol.AddressTypeIPv4:
			headerLength = 26
			if len(data) < headerLength {
				return nil, nil, nil, false, nil, false
			}
			request.Address = net.IPAddress(data[22:headerLength])
		case protocol.AddressTypeIPv6:
			headerLength = 38
			if len(data) < headerLength {
				return nil, nil, nil, false, nil, false
			}
			request.Address = net.IPAddress(data[22:headerLength])
		case protocol.AddressTypeDomain:
			if len(data) < 23 {
				return nil, nil, nil, false, nil, false
			}
			domainLength := int(data[22])
			headerLength = 23 + domainLength
			if domainLength == 0 || len(data) < headerLength {
				return nil, nil, nil, false, nil, false
			}
			domain := string(data[23:headerLength])
			if domain[0] == '[' || domain[0] >= '0' && domain[0] <= '9' {
				address := net.ParseAddress(domain)
				if address.Family().IsIP() {
					request.Address = address
					break
				}
			}
			if !isPlainDomain(domain) {
				return nil, nil, nil, false, nil, false
			}
			request.Address = net.DomainAddress(domain)
		default:
			return nil, nil, nil, false, nil, false
		}
	default:
		return nil, nil, nil, false, nil, false
	}

	first.Advance(int32(headerLength))
	return id[:], request, &Addons{}, false, nil, true
}

func isPlainDomain(domain string) bool {
	for i := 0; i < len(domain); i++ {
		c := domain[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '-' || c == '.' || c == '_') {
			return false
		}
	}
	return true
}

// EncodeResponseHeader writes encoded response header into the given writer.
func EncodeResponseHeader(writer io.Writer, request *protocol.RequestHeader, responseAddons *Addons) error {
	if responseAddons.Flow == "" {
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
