// SPDX-License-Identifier: MPL-2.0

//go:build linux

package singmux

import (
	"errors"
	"io"
	"net"
	"reflect"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

func TestBrutalSocketABI(t *testing.T) {
	if brutalSocketOption != 23301 {
		t.Fatalf("socket option = %d, want 23301", brutalSocketOption)
	}
	if got := unsafe.Sizeof(brutalSocketOptions{}); got != 16 {
		t.Fatalf("socket option size = %d, want 16", got)
	}
	if got := unsafe.Offsetof(brutalSocketOptions{}.Rate); got != 0 {
		t.Fatalf("Rate offset = %d, want 0", got)
	}
	if got := unsafe.Offsetof(brutalSocketOptions{}.CwndGain); got != 8 {
		t.Fatalf("CwndGain offset = %d, want 8", got)
	}
}

func TestSetBrutalOptionsUsesExpectedOrderAndValues(t *testing.T) {
	const fd = uintptr(41)
	var calls []string
	var gotFD int
	var gotOptions brutalSocketOptions
	restore := installBrutalSocketHooks(
		func(fd, level, option int, value string) error {
			calls = append(calls, "congestion")
			gotFD = fd
			if level != syscall.IPPROTO_TCP || option != syscall.TCP_CONGESTION || value != "brutal" {
				t.Fatalf("congestion call = (%d, %d, %q)", level, option, value)
			}
			return nil
		},
		func(fd int, options brutalSocketOptions) error {
			calls = append(calls, "rate")
			gotFD = fd
			gotOptions = options
			return nil
		},
	)
	t.Cleanup(restore)
	if err := setBrutalOptions(&linuxBrutalConn{raw: &linuxRawConn{fd: fd}}, 987654321); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(calls, []string{"congestion", "rate"}) {
		t.Fatalf("socket option order = %v", calls)
	}
	if gotFD != int(fd) {
		t.Fatalf("socket fd = %d, want %d", gotFD, fd)
	}
	if gotOptions != (brutalSocketOptions{Rate: 987654321, CwndGain: 20}) {
		t.Fatalf("socket options = %+v", gotOptions)
	}
}

func TestSetBrutalOptionsPropagatesSocketErrors(t *testing.T) {
	congestionErr := errors.New("congestion failed")
	rateErr := errors.New("rate failed")
	controlErr := errors.New("control failed")

	t.Run("congestion", func(t *testing.T) {
		restore := installBrutalSocketHooks(
			func(int, int, int, string) error { return congestionErr },
			func(int, brutalSocketOptions) error {
				t.Fatal("rate setter called after congestion failure")
				return nil
			},
		)
		t.Cleanup(restore)
		err := setBrutalOptions(&linuxBrutalConn{raw: &linuxRawConn{fd: 1}}, BrutalMinSpeedBPS)
		if !errors.Is(err, congestionErr) {
			t.Fatalf("error = %v, want %v", err, congestionErr)
		}
	})

	t.Run("rate", func(t *testing.T) {
		restore := installBrutalSocketHooks(
			func(int, int, int, string) error { return nil },
			func(int, brutalSocketOptions) error { return rateErr },
		)
		t.Cleanup(restore)
		err := setBrutalOptions(&linuxBrutalConn{raw: &linuxRawConn{fd: 1}}, BrutalMinSpeedBPS)
		if !errors.Is(err, rateErr) {
			t.Fatalf("error = %v, want %v", err, rateErr)
		}
	})

	t.Run("control", func(t *testing.T) {
		restore := installBrutalSocketHooks(nil, nil)
		t.Cleanup(restore)
		err := setBrutalOptions(&linuxBrutalConn{raw: &linuxRawConn{fd: 1, controlErr: controlErr}}, BrutalMinSpeedBPS)
		if !errors.Is(err, controlErr) {
			t.Fatalf("error = %v, want %v", err, controlErr)
		}
	})
}

func TestBrutalSetRatePropagatesSyscallError(t *testing.T) {
	if err := setBrutalRate(-1, brutalSocketOptions{Rate: BrutalMinSpeedBPS, CwndGain: 20}); err == nil {
		t.Fatal("invalid socket descriptor must fail")
	}
}

func installBrutalSocketHooks(
	congestion func(int, int, int, string) error,
	rate func(int, brutalSocketOptions) error,
) func() {
	previousCongestion, previousRate := brutalSetCongestion, brutalSetRate
	if congestion != nil {
		brutalSetCongestion = congestion
	}
	if rate != nil {
		brutalSetRate = rate
	}
	return func() {
		brutalSetCongestion, brutalSetRate = previousCongestion, previousRate
	}
}

type linuxBrutalConn struct{ raw syscall.RawConn }

func (c *linuxBrutalConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *linuxBrutalConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *linuxBrutalConn) Close() error                     { return nil }
func (c *linuxBrutalConn) LocalAddr() net.Addr              { return nil }
func (c *linuxBrutalConn) RemoteAddr() net.Addr             { return nil }
func (c *linuxBrutalConn) SetDeadline(time.Time) error      { return nil }
func (c *linuxBrutalConn) SetReadDeadline(time.Time) error  { return nil }
func (c *linuxBrutalConn) SetWriteDeadline(time.Time) error { return nil }
func (c *linuxBrutalConn) SyscallConn() (syscall.RawConn, error) {
	return c.raw, nil
}

type linuxRawConn struct {
	fd         uintptr
	controlErr error
}

func (c *linuxRawConn) Control(fn func(uintptr)) error {
	if c.controlErr != nil {
		return c.controlErr
	}
	fn(c.fd)
	return nil
}

func (*linuxRawConn) Read(func(uintptr) bool) error  { return nil }
func (*linuxRawConn) Write(func(uintptr) bool) error { return nil }
