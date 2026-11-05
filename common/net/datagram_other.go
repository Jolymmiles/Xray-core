//go:build !unix && !windows

package net

// IsMessageTooLong reports whether err is the error with which a UDP socket
// refuses a datagram as too long for it; this system reports none.
func IsMessageTooLong(err error) bool {
	return false
}

// IsTruncated reports whether the flags of a read of a UDP socket mark a
// datagram that the read cut short; this system marks none.
func IsTruncated(flags int) bool {
	return false
}
