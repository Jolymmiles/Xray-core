// SPDX-License-Identifier: MPL-2.0

//go:build !linux

package singmux

import (
	"errors"
	"net"
)

func setBrutalOptions(net.Conn, uint64) error {
	return errors.New("brutal socket options are only supported on Linux")
}
