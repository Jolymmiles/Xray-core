// SPDX-License-Identifier: MPL-2.0

//go:build linux

package singmux

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

const brutalSocketOption = 23301

type brutalSocketOptions struct {
	Rate     uint64
	CwndGain uint32
}

//go:linkname brutalSetsockopt syscall.setsockopt
func brutalSetsockopt(fd int, level int, option int, value unsafe.Pointer, length uintptr) error

//go:linkname brutalGetsockopt syscall.getsockopt
func brutalGetsockopt(fd int, level int, option int, value unsafe.Pointer, length *uint32) error

var (
	brutalSetCongestion = syscall.SetsockoptString
	brutalSetRate       = setBrutalRate
	brutalGetCongestion = getBrutalCongestion
)

func getBrutalCongestion(fd, level, option int) (string, error) {
	// Linux TCP_CA_NAME_MAX is 16, including the terminating NUL.
	var name [16]byte
	length := uint32(len(name))
	if err := brutalGetsockopt(fd, level, option, unsafe.Pointer(&name[0]), &length); err != nil {
		return "", err
	}
	return brutalCongestionName(name, length)
}

func brutalCongestionName(name [16]byte, length uint32) (string, error) {
	if length == 0 || length > uint32(len(name)) {
		return "", fmt.Errorf("invalid TCP_CONGESTION length %d", length)
	}
	end := bytes.IndexByte(name[:length], 0)
	if end <= 0 {
		return "", errors.New("invalid TCP_CONGESTION name")
	}
	return string(name[:end]), nil
}

func setBrutalRate(fd int, options brutalSocketOptions) error {
	if err := brutalSetsockopt(fd, syscall.IPPROTO_TCP, brutalSocketOption, unsafe.Pointer(&options), unsafe.Sizeof(options)); err != nil {
		return fmt.Errorf("set TCP_BRUTAL_RATE: %w", err)
	}
	return nil
}

func setBrutalOptions(conn net.Conn, rate uint64) error {
	raw, err := unwrapBrutalConn(conn)
	if err != nil {
		return err
	}
	syscallConn, err := raw.SyscallConn()
	if err != nil {
		return fmt.Errorf("brutal syscall connection: %w", err)
	}
	var optionErr error
	if err := syscallConn.Control(func(fd uintptr) {
		if err := brutalSetCongestion(int(fd), syscall.IPPROTO_TCP, syscall.TCP_CONGESTION, "brutal"); err != nil {
			optionErr = fmt.Errorf("set TCP_CONGESTION=brutal: %w", err)
		} else {
			options := brutalSocketOptions{Rate: rate, CwndGain: 20}
			optionErr = brutalSetRate(int(fd), options)
		}
		if !errors.Is(optionErr, syscall.EPERM) {
			return
		}
		// TCP Brutal v2 destination rules can lock both the algorithm and rate.
		// Honor that policy only after verifying Brutal is already active.
		congestion, err := brutalGetCongestion(int(fd), syscall.IPPROTO_TCP, syscall.TCP_CONGESTION)
		if err != nil {
			optionErr = errors.Join(optionErr, fmt.Errorf("get TCP_CONGESTION after EPERM: %w", err))
			return
		}
		if congestion == "brutal" {
			optionErr = nil
		}
	}); err != nil {
		return fmt.Errorf("control brutal socket: %w", err)
	}
	if optionErr != nil {
		return optionErr
	}
	return nil
}
