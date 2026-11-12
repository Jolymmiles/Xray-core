//go:build unix

package net

import (
	"errors"

	"golang.org/x/sys/unix"
)

// IsMessageTooLong reports whether err is the error with which a UDP socket
// refuses a datagram as too long for it (EMSGSIZE). A connected socket on
// Linux also reports so, on its next read or write, a router's "fragmentation
// needed" for an earlier datagram.
func IsMessageTooLong(err error) bool {
	return errors.Is(err, unix.EMSGSIZE)
}

// IsTruncated reports whether the flags of a read of a UDP socket, as
// ReadMsgUDP returns them, mark a datagram that the read cut short because it
// was longer than the buffer (MSG_TRUNC).
func IsTruncated(flags int) bool {
	return flags&unix.MSG_TRUNC != 0
}
