package mtproxy

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
)

const (
	rpcProxyRequest    uint32 = 0x36cef1ee
	rpcProxyAnswer     uint32 = 0x4403da0d
	rpcCloseConnection uint32 = 0x1fcf425d
	rpcCloseExternal   uint32 = 0x5eb634a2
	rpcSimpleAck       uint32 = 0x3bac409b
	tlProxyTag         uint32 = 0xdb1e26ae
)

var ErrInvalidMiddleRPC = errors.New("mtproxy: invalid Middle-End RPC message")

type MiddleRPCFrame struct {
	Sequence uint32
	Payload  []byte
}

func EncodeMiddleRPCFrame(sequence uint32, payload []byte) ([]byte, error) {
	if len(payload) < 4 || len(payload)&3 != 0 {
		return nil, fmt.Errorf("%w: unaligned payload length %d", ErrInvalidMiddleRPC, len(payload))
	}
	frame := make([]byte, len(payload)+12)
	binary.LittleEndian.PutUint32(frame[0:4], uint32(len(frame)))
	binary.LittleEndian.PutUint32(frame[4:8], sequence)
	copy(frame[8:], payload)
	binary.LittleEndian.PutUint32(frame[len(frame)-4:], crc32.ChecksumIEEE(frame[:len(frame)-4]))
	return frame, nil
}

func ReadMiddleRPCFrame(reader io.Reader, maxPayload int) (MiddleRPCFrame, error) {
	var result MiddleRPCFrame
	if reader == nil || maxPayload < 4 {
		return result, fmt.Errorf("%w: invalid frame limit", ErrInvalidMiddleRPC)
	}
	var lengthBytes [4]byte
	if _, err := io.ReadFull(reader, lengthBytes[:]); err != nil {
		return result, err
	}
	frameLength := int(binary.LittleEndian.Uint32(lengthBytes[:]))
	if frameLength < 16 || frameLength&3 != 0 || frameLength-12 > maxPayload {
		return result, fmt.Errorf("%w: frame length %d", ErrInvalidMiddleRPC, frameLength)
	}
	frame := make([]byte, frameLength)
	copy(frame[:4], lengthBytes[:])
	if _, err := io.ReadFull(reader, frame[4:]); err != nil {
		return result, err
	}
	expectedCRC := binary.LittleEndian.Uint32(frame[frameLength-4:])
	if actualCRC := crc32.ChecksumIEEE(frame[:frameLength-4]); actualCRC != expectedCRC {
		return result, fmt.Errorf("%w: CRC mismatch", ErrInvalidMiddleRPC)
	}
	result.Sequence = binary.LittleEndian.Uint32(frame[4:8])
	result.Payload = append([]byte(nil), frame[8:frameLength-4]...)
	return result, nil
}

type ProxyRequest struct {
	Flags        uint32
	ConnectionID uint64
	RemoteIP     [16]byte
	RemotePort   uint16
	LocalIP      [16]byte
	LocalPort    uint16
	ProxyTag     *[16]byte
	Payload      []byte
}

type ProxyAnswer struct {
	Flags        uint32
	ConnectionID uint64
	Payload      []byte
}

type SimpleAck struct {
	ConnectionID uint64
	Confirm      uint32
}

type CloseConnection struct{ ConnectionID uint64 }
type CloseExternal struct{ ConnectionID uint64 }

func EncodeProxyRequest(request ProxyRequest) ([]byte, error) {
	if len(request.Payload) < 4 || len(request.Payload)&3 != 0 {
		return nil, fmt.Errorf("%w: proxy request payload length", ErrInvalidMiddleRPC)
	}
	flags := request.Flags
	extraLength := 0
	if request.ProxyTag != nil {
		flags |= 8
		extraLength = 24
	}
	size := 56 + len(request.Payload)
	if extraLength != 0 {
		size += 4 + extraLength
	}
	encoded := make([]byte, 0, size)
	encoded = appendUint32(encoded, rpcProxyRequest)
	encoded = appendUint32(encoded, flags)
	encoded = appendUint64(encoded, request.ConnectionID)
	encoded = append(encoded, request.RemoteIP[:]...)
	encoded = appendUint32(encoded, uint32(request.RemotePort))
	encoded = append(encoded, request.LocalIP[:]...)
	encoded = appendUint32(encoded, uint32(request.LocalPort))
	if request.ProxyTag != nil {
		encoded = appendUint32(encoded, uint32(extraLength))
		encoded = appendUint32(encoded, tlProxyTag)
		encoded = append(encoded, 16)
		encoded = append(encoded, request.ProxyTag[:]...)
		encoded = append(encoded, 0, 0, 0)
	}
	encoded = append(encoded, request.Payload...)
	return encoded, nil
}

func DecodeProxyRequest(encoded []byte, maxPayload int) (ProxyRequest, error) {
	var request ProxyRequest
	if len(encoded) < 60 || len(encoded)&3 != 0 || binary.LittleEndian.Uint32(encoded[:4]) != rpcProxyRequest {
		return request, ErrInvalidMiddleRPC
	}
	request.Flags = binary.LittleEndian.Uint32(encoded[4:8])
	request.ConnectionID = binary.LittleEndian.Uint64(encoded[8:16])
	copy(request.RemoteIP[:], encoded[16:32])
	remotePort := binary.LittleEndian.Uint32(encoded[32:36])
	copy(request.LocalIP[:], encoded[36:52])
	localPort := binary.LittleEndian.Uint32(encoded[52:56])
	if remotePort > 65535 || localPort > 65535 {
		return request, fmt.Errorf("%w: proxy request port", ErrInvalidMiddleRPC)
	}
	request.RemotePort, request.LocalPort = uint16(remotePort), uint16(localPort)
	position := 56
	if request.Flags&12 != 0 {
		if position+4 > len(encoded) {
			return request, ErrInvalidMiddleRPC
		}
		extraLength := int(binary.LittleEndian.Uint32(encoded[position : position+4]))
		position += 4
		if extraLength < 0 || position+extraLength > len(encoded) || extraLength&3 != 0 {
			return request, fmt.Errorf("%w: proxy request extra length", ErrInvalidMiddleRPC)
		}
		if request.Flags&8 != 0 {
			if extraLength < 24 || binary.LittleEndian.Uint32(encoded[position:position+4]) != tlProxyTag || encoded[position+4] != 16 {
				return request, fmt.Errorf("%w: proxy tag", ErrInvalidMiddleRPC)
			}
			var tag [16]byte
			copy(tag[:], encoded[position+5:position+21])
			request.ProxyTag = &tag
		}
		position += extraLength
	}
	if len(encoded)-position < 4 || len(encoded)-position > maxPayload || (len(encoded)-position)&3 != 0 {
		return request, fmt.Errorf("%w: proxy request payload", ErrInvalidMiddleRPC)
	}
	request.Payload = append([]byte(nil), encoded[position:]...)
	return request, nil
}

func EncodeProxyAnswer(answer ProxyAnswer) []byte {
	encoded := make([]byte, 0, 16+len(answer.Payload))
	encoded = appendUint32(encoded, rpcProxyAnswer)
	encoded = appendUint32(encoded, answer.Flags)
	encoded = appendUint64(encoded, answer.ConnectionID)
	return append(encoded, answer.Payload...)
}

func EncodeSimpleAck(ack SimpleAck) []byte {
	encoded := make([]byte, 0, 16)
	encoded = appendUint32(encoded, rpcSimpleAck)
	encoded = appendUint64(encoded, ack.ConnectionID)
	return appendUint32(encoded, ack.Confirm)
}

func EncodeCloseConnection(closeMessage CloseConnection) []byte {
	encoded := appendUint32(nil, rpcCloseConnection)
	return appendUint64(encoded, closeMessage.ConnectionID)
}

func EncodeCloseExternal(closeMessage CloseExternal) []byte {
	encoded := appendUint32(nil, rpcCloseExternal)
	return appendUint64(encoded, closeMessage.ConnectionID)
}

func DecodeMiddleMessage(encoded []byte, maxPayload int) (any, error) {
	if len(encoded) < 4 || len(encoded)&3 != 0 {
		return nil, ErrInvalidMiddleRPC
	}
	switch binary.LittleEndian.Uint32(encoded[:4]) {
	case rpcProxyRequest:
		return DecodeProxyRequest(encoded, maxPayload)
	case rpcProxyAnswer:
		if len(encoded) < 16 || len(encoded)-16 > maxPayload {
			return nil, ErrInvalidMiddleRPC
		}
		return ProxyAnswer{
			Flags:        binary.LittleEndian.Uint32(encoded[4:8]),
			ConnectionID: binary.LittleEndian.Uint64(encoded[8:16]),
			Payload:      append([]byte(nil), encoded[16:]...),
		}, nil
	case rpcSimpleAck:
		if len(encoded) != 16 {
			return nil, ErrInvalidMiddleRPC
		}
		return SimpleAck{ConnectionID: binary.LittleEndian.Uint64(encoded[4:12]), Confirm: binary.LittleEndian.Uint32(encoded[12:16])}, nil
	case rpcCloseConnection:
		if len(encoded) != 12 {
			return nil, ErrInvalidMiddleRPC
		}
		return CloseConnection{ConnectionID: binary.LittleEndian.Uint64(encoded[4:12])}, nil
	case rpcCloseExternal:
		if len(encoded) != 12 {
			return nil, ErrInvalidMiddleRPC
		}
		return CloseExternal{ConnectionID: binary.LittleEndian.Uint64(encoded[4:12])}, nil
	default:
		return nil, fmt.Errorf("%w: unknown operation", ErrInvalidMiddleRPC)
	}
}

func appendUint32(destination []byte, value uint32) []byte {
	var encoded [4]byte
	binary.LittleEndian.PutUint32(encoded[:], value)
	return append(destination, encoded[:]...)
}

func appendUint64(destination []byte, value uint64) []byte {
	var encoded [8]byte
	binary.LittleEndian.PutUint64(encoded[:], value)
	return append(destination, encoded[:]...)
}
