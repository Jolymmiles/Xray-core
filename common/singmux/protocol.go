// SPDX-License-Identifier: MPL-2.0

package singmux

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	X "github.com/xtls/xray-core/common/net"
)

const (
	carrierVersionPlain  byte = 0
	carrierVersionPadded byte = 1
	protocolSMUX         byte = 0
	protocolH2MUX        byte = 2

	streamFlagUDP        uint16 = 1 << 0
	streamFlagPacketAddr uint16 = 1 << 1
	streamFlagsKnown            = streamFlagUDP | streamFlagPacketAddr

	streamStatusSuccess byte = 0
	streamStatusError   byte = 1

	addressIPv4   byte = 1
	addressDomain byte = 3
	addressIPv6   byte = 4

	maxWirePayload     = 65535
	maxDiagnosticBytes = 65535
)

type carrierRequest struct {
	Version  byte
	Protocol byte
	Padding  []byte
}

func writeFull(writer io.Writer, payload []byte) error {
	for len(payload) != 0 {
		n, err := writer.Write(payload)
		if n > 0 {
			payload = payload[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func writeCarrierRequest(writer io.Writer, protocol byte, padding []byte) error {
	if protocol != protocolSMUX && protocol != protocolH2MUX {
		return fmt.Errorf("unsupported mux protocol %d", protocol)
	}
	if len(padding) > maxWirePayload {
		return errors.New("carrier padding is too large")
	}
	if padding == nil {
		return writeFull(writer, []byte{carrierVersionPlain, protocol})
	}
	header := []byte{carrierVersionPadded, protocol, 0, 0, 0}
	if len(padding) != 0 {
		header[2] = 1
		binary.BigEndian.PutUint16(header[3:], uint16(len(padding)))
	}
	if err := writeFull(writer, header); err != nil {
		return err
	}
	return writeFull(writer, padding)
}

func readCarrierRequest(reader io.Reader) (carrierRequest, error) {
	var initial [2]byte
	if _, err := io.ReadFull(reader, initial[:]); err != nil {
		return carrierRequest{}, err
	}
	request := carrierRequest{Version: initial[0], Protocol: initial[1]}
	if request.Protocol != protocolSMUX && request.Protocol != protocolH2MUX {
		return carrierRequest{}, fmt.Errorf("unsupported mux protocol %d", request.Protocol)
	}
	switch request.Version {
	case carrierVersionPlain:
		return request, nil
	case carrierVersionPadded:
		var option [1]byte
		if _, err := io.ReadFull(reader, option[:]); err != nil {
			return carrierRequest{}, err
		}
		switch option[0] {
		case 0:
			return request, nil
		case 1:
			var length [2]byte
			if _, err := io.ReadFull(reader, length[:]); err != nil {
				return carrierRequest{}, err
			}
			request.Padding = make([]byte, int(binary.BigEndian.Uint16(length[:])))
			if _, err := io.ReadFull(reader, request.Padding); err != nil {
				return carrierRequest{}, err
			}
			return request, nil
		default:
			return carrierRequest{}, fmt.Errorf("unsupported padding option %d", option[0])
		}
	default:
		return carrierRequest{}, fmt.Errorf("unsupported carrier version %d", request.Version)
	}
}

func writeStreamRequest(writer io.Writer, flags uint16, destination X.Destination) error {
	if flags&^streamFlagsKnown != 0 || flags&streamFlagPacketAddr != 0 && flags&streamFlagUDP == 0 {
		return errors.New("invalid stream flags")
	}
	var header [2]byte
	binary.BigEndian.PutUint16(header[:], flags)
	if err := writeFull(writer, header[:]); err != nil {
		return err
	}
	return writeDestination(writer, destination)
}

func readStreamRequest(reader io.Reader) (uint16, X.Destination, error) {
	var header [2]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return 0, X.Destination{}, err
	}
	flags := binary.BigEndian.Uint16(header[:])
	if flags&^streamFlagsKnown != 0 || flags&streamFlagPacketAddr != 0 && flags&streamFlagUDP == 0 {
		return 0, X.Destination{}, errors.New("invalid stream flags")
	}
	destination, err := readDestination(reader)
	if err != nil {
		return 0, X.Destination{}, err
	}
	if flags&streamFlagUDP != 0 {
		destination.Network = X.Network_UDP
	} else {
		destination.Network = X.Network_TCP
	}
	return flags, destination, nil
}

func writeDestination(writer io.Writer, destination X.Destination) error {
	if destination.Address == nil {
		return errors.New("destination address is required")
	}
	var encoded []byte
	switch destination.Address.Family() {
	case X.AddressFamilyIPv4:
		ip := destination.Address.IP().To4()
		if ip == nil {
			return errors.New("invalid IPv4 destination")
		}
		encoded = append(encoded, addressIPv4)
		encoded = append(encoded, ip...)
	case X.AddressFamilyIPv6:
		ip := destination.Address.IP().To16()
		if ip == nil || destination.Address.IP().To4() != nil {
			return errors.New("invalid IPv6 destination")
		}
		encoded = append(encoded, addressIPv6)
		encoded = append(encoded, ip...)
	case X.AddressFamilyDomain:
		domain := destination.Address.Domain()
		if len(domain) == 0 || len(domain) > 255 {
			return errors.New("domain length is outside 1..255")
		}
		encoded = append(encoded, addressDomain, byte(len(domain)))
		encoded = append(encoded, domain...)
	default:
		return errors.New("unknown destination address family")
	}
	encoded = binary.BigEndian.AppendUint16(encoded, uint16(destination.Port))
	return writeFull(writer, encoded)
}

func readDestination(reader io.Reader) (X.Destination, error) {
	var family [1]byte
	if _, err := io.ReadFull(reader, family[:]); err != nil {
		return X.Destination{}, err
	}
	var address X.Address
	switch family[0] {
	case addressIPv4:
		var ip [4]byte
		if _, err := io.ReadFull(reader, ip[:]); err != nil {
			return X.Destination{}, err
		}
		address = X.IPAddress(ip[:])
	case addressIPv6:
		var ip [16]byte
		if _, err := io.ReadFull(reader, ip[:]); err != nil {
			return X.Destination{}, err
		}
		address = X.IPAddress(ip[:])
	case addressDomain:
		var length [1]byte
		if _, err := io.ReadFull(reader, length[:]); err != nil {
			return X.Destination{}, err
		}
		if length[0] == 0 {
			return X.Destination{}, errors.New("empty domain")
		}
		domain := make([]byte, int(length[0]))
		if _, err := io.ReadFull(reader, domain); err != nil {
			return X.Destination{}, err
		}
		address = X.DomainAddress(string(domain))
	default:
		return X.Destination{}, fmt.Errorf("unsupported address family %d", family[0])
	}
	var port [2]byte
	if _, err := io.ReadFull(reader, port[:]); err != nil {
		return X.Destination{}, err
	}
	return X.TCPDestination(address, X.Port(binary.BigEndian.Uint16(port[:]))), nil
}

func writePacket(writer io.Writer, destination X.Destination, payload []byte) error {
	if len(payload) > maxWirePayload {
		return errors.New("UDP payload is too large")
	}
	if err := writeDestination(writer, destination); err != nil {
		return err
	}
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(payload)))
	if err := writeFull(writer, length[:]); err != nil {
		return err
	}
	return writeFull(writer, payload)
}

func readPacket(reader io.Reader) (X.Destination, []byte, error) {
	destination, err := readDestination(reader)
	if err != nil {
		return X.Destination{}, nil, err
	}
	destination.Network = X.Network_UDP
	var encodedLength [2]byte
	if _, err := io.ReadFull(reader, encodedLength[:]); err != nil {
		return X.Destination{}, nil, err
	}
	payload := make([]byte, int(binary.BigEndian.Uint16(encodedLength[:])))
	if _, err := io.ReadFull(reader, payload); err != nil {
		return X.Destination{}, nil, err
	}
	return destination, payload, nil
}

func writeStreamResponse(writer io.Writer, responseErr error) error {
	if responseErr == nil {
		return writeFull(writer, []byte{streamStatusSuccess})
	}
	message := []byte(responseErr.Error())
	if len(message) > maxDiagnosticBytes {
		message = message[:maxDiagnosticBytes]
	}
	encoded := []byte{streamStatusError}
	encoded = binary.AppendUvarint(encoded, uint64(len(message)))
	encoded = append(encoded, message...)
	return writeFull(writer, encoded)
}

func readStreamResponse(reader io.Reader) error {
	var status [1]byte
	if _, err := io.ReadFull(reader, status[:]); err != nil {
		return err
	}
	switch status[0] {
	case streamStatusSuccess:
		return nil
	case streamStatusError:
		length, err := readUvarint(reader)
		if err != nil {
			return err
		}
		if length > maxDiagnosticBytes {
			return errors.New("stream diagnostic is too large")
		}
		message := make([]byte, int(length))
		if _, err := io.ReadFull(reader, message); err != nil {
			return err
		}
		return &streamResponseError{message: string(message)}
	default:
		return &streamResponseError{message: fmt.Sprintf("unknown stream response status %d", status[0])}
	}
}

func readUvarint(reader io.Reader) (uint64, error) {
	var value uint64
	for shift := uint(0); shift < 70; shift += 7 {
		var encoded [1]byte
		if _, err := io.ReadFull(reader, encoded[:]); err != nil {
			return 0, err
		}
		if encoded[0] < 0x80 {
			if shift == 63 && encoded[0] > 1 {
				return 0, errors.New("varint overflow")
			}
			return value | uint64(encoded[0])<<shift, nil
		}
		value |= uint64(encoded[0]&0x7f) << shift
	}
	return 0, errors.New("varint overflow")
}
