// SPDX-License-Identifier: MPL-2.0

package mplsmux

import "encoding/binary"

const frameHeaderSize = 8

type frameCommand byte

const (
	frameOpen frameCommand = iota
	frameClose
	frameData
	frameKeepalive
)

type frameHeader struct {
	command  frameCommand
	streamID uint32
	length   uint16
}

func encodeFrameHeader(header *[frameHeaderSize]byte, command frameCommand, streamID uint32, length int) {
	header[0] = protocolVersion
	header[1] = byte(command)
	binary.LittleEndian.PutUint16(header[2:4], uint16(length))
	binary.LittleEndian.PutUint32(header[4:8], streamID)
}

func decodeFrameHeader(header *[frameHeaderSize]byte) (frameHeader, error) {
	decoded := frameHeader{
		command:  frameCommand(header[1]),
		length:   binary.LittleEndian.Uint16(header[2:4]),
		streamID: binary.LittleEndian.Uint32(header[4:8]),
	}
	if header[0] != protocolVersion || decoded.command > frameKeepalive {
		return frameHeader{}, ErrInvalidProtocol
	}
	if decoded.command != frameData && decoded.length != 0 {
		return frameHeader{}, ErrInvalidProtocol
	}
	return decoded, nil
}
