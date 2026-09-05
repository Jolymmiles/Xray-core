// SPDX-License-Identifier: MPL-2.0

//go:build linux

package singmux

import (
	"errors"
	"fmt"
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

func TestSetBrutalOptionsPreservesLockedCongestion(t *testing.T) {
	const systemRate = uint64(25_000_000)
	rate := systemRate
	restore := installBrutalSocketHooks(
		func(int, int, int, string) error { return syscall.EPERM },
		func(_ int, options brutalSocketOptions) error {
			rate = options.Rate
			return nil
		},
	)
	t.Cleanup(restore)
	previousGet := brutalGetCongestion
	t.Cleanup(func() { brutalGetCongestion = previousGet })
	brutalGetCongestion = func(int, int, int) (string, error) { return "brutal", nil }

	if err := SetBrutalOptions(&linuxBrutalConn{raw: &linuxRawConn{fd: 41}}, 1_000_000); err != nil {
		t.Fatalf("system-managed Brutal must remain usable: %v", err)
	}
	if rate != systemRate {
		t.Fatalf("system rate = %d, want %d", rate, systemRate)
	}
}

func TestSetBrutalOptionsAcceptsLockedRate(t *testing.T) {
	restore := installBrutalSocketHooks(
		func(int, int, int, string) error { return nil },
		func(int, brutalSocketOptions) error {
			return fmt.Errorf("set TCP_BRUTAL_RATE: %w", syscall.EPERM)
		},
	)
	t.Cleanup(restore)
	previousGet := brutalGetCongestion
	t.Cleanup(func() { brutalGetCongestion = previousGet })
	brutalGetCongestion = func(fd, level, option int) (string, error) {
		if fd != 41 || level != syscall.IPPROTO_TCP || option != syscall.TCP_CONGESTION {
			return "", syscall.EINVAL
		}
		return "brutal", nil
	}

	if err := SetBrutalOptions(&linuxBrutalConn{raw: &linuxRawConn{fd: 41}}, 1_000_000); err != nil {
		t.Fatalf("system-managed Brutal rate must remain usable: %v", err)
	}
}

func TestSetBrutalOptionsRejectsUnverifiedPermissionErrors(t *testing.T) {
	for _, stage := range []string{"congestion", "rate"} {
		for _, test := range []struct {
			name      string
			algorithm string
			setErr    error
			getErr    error
		}{
			{name: "different algorithm", algorithm: "cubic", setErr: syscall.EPERM},
			{name: "empty algorithm", setErr: syscall.EPERM},
			{name: "read failed", algorithm: "brutal", setErr: syscall.EPERM, getErr: syscall.EBADF},
			{name: "other denial", algorithm: "brutal", setErr: syscall.EACCES},
		} {
			t.Run(stage+"/"+test.name, func(t *testing.T) {
				restore := installBrutalSocketHooks(
					func(int, int, int, string) error {
						if stage == "congestion" {
							return test.setErr
						}
						return nil
					},
					func(int, brutalSocketOptions) error { return test.setErr },
				)
				t.Cleanup(restore)
				previousGet := brutalGetCongestion
				t.Cleanup(func() { brutalGetCongestion = previousGet })
				brutalGetCongestion = func(int, int, int) (string, error) {
					return test.algorithm, test.getErr
				}

				err := SetBrutalOptions(&linuxBrutalConn{raw: &linuxRawConn{fd: 41}}, 1_000_000)
				if !errors.Is(err, test.setErr) {
					t.Fatalf("error = %v, want original denial %v", err, test.setErr)
				}
				if test.getErr != nil && !errors.Is(err, test.getErr) {
					t.Fatalf("error = %v, want socket read failure %v", err, test.getErr)
				}
			})
		}
	}
}

func TestBrutalCongestionReadFromSocket(t *testing.T) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, syscall.IPPROTO_TCP)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := syscall.Close(fd); err != nil {
			t.Error(err)
		}
	})
	if err := syscall.SetsockoptString(fd, syscall.IPPROTO_TCP, syscall.TCP_CONGESTION, "reno"); err != nil {
		t.Fatal(err)
	}
	name, err := getBrutalCongestion(fd, syscall.IPPROTO_TCP, syscall.TCP_CONGESTION)
	if err != nil || name != "reno" {
		t.Fatalf("TCP_CONGESTION = %q, %v, want reno", name, err)
	}
	if _, err := getBrutalCongestion(-1, syscall.IPPROTO_TCP, syscall.TCP_CONGESTION); !errors.Is(err, syscall.EBADF) {
		t.Fatalf("invalid fd error = %v, want EBADF", err)
	}
}

func TestBrutalCongestionNameRejectsInvalidLayout(t *testing.T) {
	for _, test := range []struct {
		name   string
		value  string
		length uint32
	}{
		{name: "zero length", length: 0},
		{name: "oversized length", value: "brutal", length: 17},
		{name: "empty name", length: 16},
		{name: "missing terminator", value: "abcdefghijklmnop", length: 16},
		{name: "truncated name", value: "brutal", length: 6},
	} {
		t.Run(test.name, func(t *testing.T) {
			var value [16]byte
			copy(value[:], test.value)
			if name, err := brutalCongestionName(value, test.length); err == nil {
				t.Fatalf("invalid socket response accepted as %q", name)
			}
		})
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
