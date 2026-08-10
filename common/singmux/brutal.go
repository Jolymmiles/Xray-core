// SPDX-License-Identifier: MPL-2.0

package singmux

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
	"unicode/utf8"

	"github.com/xtls/xray-core/transport/internet/stat"
)

const (
	BrutalMinSpeedBPS    uint64 = 65536
	maxBrutalUnwrapDepth        = 8
	brutalExchangeDomain        = "_BrutalBwExchange"
)

// BrutalOptions controls the opt-in SMUX bandwidth exchange.
type BrutalOptions struct {
	Enabled    bool
	SendBPS    uint64
	ReceiveBPS uint64
}

func writeBrutalRequest(writer io.Writer, receiveBPS uint64) error {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], receiveBPS)
	return writeFull(writer, encoded[:])
}

func readBrutalRequest(reader io.Reader) (uint64, error) {
	var encoded [8]byte
	if _, err := io.ReadFull(reader, encoded[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(encoded[:]), nil
}

func writeBrutalResponse(writer io.Writer, receiveBPS uint64, ok bool, diagnostic string) error {
	if ok {
		if err := writeFull(writer, []byte{1}); err != nil {
			return err
		}
		var encoded [8]byte
		binary.BigEndian.PutUint64(encoded[:], receiveBPS)
		return writeFull(writer, encoded[:])
	}

	message := []byte(diagnostic)
	if !utf8.Valid(message) {
		message = []byte(string([]rune(string(message))))
	}
	if len(message) > maxDiagnosticBytes {
		message = message[:maxDiagnosticBytes]
		for len(message) > 0 && !utf8.Valid(message) {
			message = message[:len(message)-1]
		}
	}
	encoded := []byte{0}
	encoded = binary.AppendUvarint(encoded, uint64(len(message)))
	encoded = append(encoded, message...)
	return writeFull(writer, encoded)
}

func readBrutalResponse(reader io.Reader) (uint64, error) {
	var status [1]byte
	if _, err := io.ReadFull(reader, status[:]); err != nil {
		return 0, err
	}
	switch status[0] {
	case 1:
		var encoded [8]byte
		if _, err := io.ReadFull(reader, encoded[:]); err != nil {
			if err == io.EOF {
				return 0, io.ErrUnexpectedEOF
			}
			return 0, err
		}
		return binary.BigEndian.Uint64(encoded[:]), nil
	case 0:
		length, err := readUvarint(reader)
		if err != nil {
			return 0, err
		}
		if length > maxDiagnosticBytes {
			return 0, errors.New("brutal diagnostic is too large")
		}
		message := make([]byte, int(length))
		if _, err := io.ReadFull(reader, message); err != nil {
			if err == io.EOF {
				return 0, io.ErrUnexpectedEOF
			}
			return 0, err
		}
		if !utf8.Valid(message) {
			return 0, errors.New("brutal diagnostic is not valid UTF-8")
		}
		return 0, errors.New(string(message))
	default:
		return 0, fmt.Errorf("unknown brutal response status %d", status[0])
	}
}

// SetBrutalOptions applies the Linux carrier settings used by Brutal.
func SetBrutalOptions(conn net.Conn, rate uint64) error {
	if conn == nil {
		return errors.New("brutal connection is nil")
	}
	if rate < BrutalMinSpeedBPS {
		return fmt.Errorf("brutal rate %d is below minimum %d", rate, BrutalMinSpeedBPS)
	}
	return setBrutalOptions(conn, rate)
}

func unwrapBrutalConn(conn net.Conn) (syscall.Conn, error) {
	for depth := 0; depth < maxBrutalUnwrapDepth; depth++ {
		switch wrapped := conn.(type) {
		case *stat.CounterConnection:
			conn = wrapped.Connection
			if conn == nil {
				return nil, errors.New("brutal counter connection is nil")
			}
			continue
		case interface{ NetConn() net.Conn }:
			conn = wrapped.NetConn()
			if conn == nil {
				return nil, errors.New("brutal NetConn wrapper returned nil")
			}
			continue
		case interface{ RawConn() net.Conn }:
			conn = wrapped.RawConn()
			if conn == nil {
				return nil, errors.New("brutal RawConn wrapper returned nil")
			}
			continue
		case syscall.Conn:
			return wrapped, nil
		default:
			return nil, fmt.Errorf("brutal connection does not expose syscall.Conn: %T", conn)
		}
	}
	return nil, errors.New("brutal connection wrapper depth exceeded")
}
