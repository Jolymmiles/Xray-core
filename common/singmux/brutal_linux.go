// SPDX-License-Identifier: MPL-2.0

//go:build linux

package singmux

import (
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

var (
	brutalSetCongestion = syscall.SetsockoptString
	brutalSetRate       = setBrutalRate
)

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
			return
		}
		options := brutalSocketOptions{Rate: rate, CwndGain: 20}
		if err := brutalSetRate(int(fd), options); err != nil {
			optionErr = err
		}
	}); err != nil {
		return fmt.Errorf("control brutal socket: %w", err)
	}
	if optionErr != nil {
		return optionErr
	}
	return nil
}
