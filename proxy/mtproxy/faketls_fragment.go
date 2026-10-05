package mtproxy

import (
	"encoding/binary"
	"fmt"
	"io"
)

const maxFakeTLSHelloRecords = 10

type fakeTLSClientHelloRead struct {
	Canonical []byte
	Wire      []byte
}

// readFakeTLSClientHello reassembles a ClientHello handshake split across TLS
// handshake records. Canonical contains the single-record representation used
// by Telegram's Fake TLS HMAC; Wire preserves every received byte for fallback.
func readFakeTLSClientHello(reader io.Reader, firstHeader [5]byte) (*fakeTLSClientHelloRead, error) {
	if reader == nil || firstHeader[0] != 0x16 || firstHeader[1] != 0x03 || firstHeader[2] < 0x01 || firstHeader[2] > 0x03 {
		return nil, fmt.Errorf("%w: ClientHello record header", ErrInvalidFakeTLS)
	}
	firstLength := int(binary.BigEndian.Uint16(firstHeader[3:5]))
	if firstLength <= 0 || firstLength+5 > fakeTLSMaxClientHello {
		return nil, fmt.Errorf("%w: ClientHello record length", ErrInvalidFakeTLS)
	}

	wire := make([]byte, 5+firstLength)
	copy(wire, firstHeader[:])
	if _, err := io.ReadFull(reader, wire[5:]); err != nil {
		return nil, err
	}
	handshake := append([]byte(nil), wire[5:]...)
	records := 1

	for len(handshake) < 4 {
		if records >= maxFakeTLSHelloRecords {
			return nil, fmt.Errorf("%w: too many ClientHello records", ErrInvalidFakeTLS)
		}
		fragment, raw, err := readFakeTLSHelloFragment(reader, firstHeader[1:3])
		if err != nil {
			return nil, err
		}
		handshake = append(handshake, fragment...)
		wire = append(wire, raw...)
		records++
	}
	if handshake[0] != 0x01 {
		return nil, fmt.Errorf("%w: not a ClientHello handshake", ErrInvalidFakeTLS)
	}
	handshakeLength := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
	totalLength := 4 + handshakeLength
	if totalLength < fakeTLSClientRandomOffset-5+32 || totalLength+5 > fakeTLSMaxClientHello {
		return nil, fmt.Errorf("%w: ClientHello handshake length", ErrInvalidFakeTLS)
	}
	if len(handshake) > totalLength {
		return nil, fmt.Errorf("%w: trailing ClientHello handshake data", ErrInvalidFakeTLS)
	}
	for len(handshake) < totalLength {
		if records >= maxFakeTLSHelloRecords {
			return nil, fmt.Errorf("%w: too many ClientHello records", ErrInvalidFakeTLS)
		}
		fragment, raw, err := readFakeTLSHelloFragment(reader, firstHeader[1:3])
		if err != nil {
			return nil, err
		}
		if len(handshake)+len(fragment) > totalLength {
			return nil, fmt.Errorf("%w: trailing ClientHello fragment data", ErrInvalidFakeTLS)
		}
		handshake = append(handshake, fragment...)
		wire = append(wire, raw...)
		records++
	}

	canonical := make([]byte, 5+len(handshake))
	canonical[0] = 0x16
	canonical[1], canonical[2] = firstHeader[1], firstHeader[2]
	binary.BigEndian.PutUint16(canonical[3:5], uint16(len(handshake)))
	copy(canonical[5:], handshake)
	return &fakeTLSClientHelloRead{Canonical: canonical, Wire: wire}, nil
}

func readFakeTLSHelloFragment(reader io.Reader, expectedVersion []byte) ([]byte, []byte, error) {
	var header [5]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, nil, err
	}
	if header[0] != 0x16 || header[1] != expectedVersion[0] || header[2] != expectedVersion[1] {
		return nil, nil, fmt.Errorf("%w: fragmented ClientHello record header", ErrInvalidFakeTLS)
	}
	length := int(binary.BigEndian.Uint16(header[3:5]))
	if length <= 0 || length+5 > fakeTLSMaxClientHello {
		return nil, nil, fmt.Errorf("%w: fragmented ClientHello record length", ErrInvalidFakeTLS)
	}
	raw := make([]byte, 5+length)
	copy(raw, header[:])
	if _, err := io.ReadFull(reader, raw[5:]); err != nil {
		return nil, nil, err
	}
	return raw[5:], raw, nil
}
