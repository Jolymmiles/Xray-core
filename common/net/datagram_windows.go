//go:build windows

package net

import (
	"errors"
	"syscall"

	"golang.org/x/sys/windows"
)

// IsMessageTooLong reports whether err is the error with which a UDP socket
// refuses a datagram as too long for it. Windows reports WSAEMSGSIZE, which Go
// does not map to syscall.EMSGSIZE, and fails with it a read that cut a
// datagram short as well. syscall.EMSGSIZE counts too.
func IsMessageTooLong(err error) bool {
	return errors.Is(err, windows.WSAEMSGSIZE) || errors.Is(err, syscall.EMSGSIZE)
}

// IsTruncated reports whether the flags of a read of a UDP socket, as
// ReadMsgUDP returns them, mark a datagram that the read cut short because it
// was longer than the buffer (MSG_TRUNC). Windows fails such a read with
// WSAEMSGSIZE as well.
func IsTruncated(flags int) bool {
	return flags&windows.MSG_TRUNC != 0
}
