//go:build !wasm && !openbsd

package buf_test

import (
	"bytes"
	"io"
	"net"
	"runtime"
	"syscall"
	"testing"
	"time"

	. "github.com/xtls/xray-core/common/buf"
	transportstat "github.com/xtls/xray-core/transport/internet/stat"
)

type stubRawConn struct{}

func (stubRawConn) Control(f func(uintptr)) error    { f(0); return nil }
func (stubRawConn) Read(f func(uintptr) bool) error  { f(0); return nil }
func (stubRawConn) Write(f func(uintptr) bool) error { f(0); return nil }

type syscallStreamConn struct{}

func (*syscallStreamConn) Read([]byte) (int, error)              { return 0, io.EOF }
func (*syscallStreamConn) Write(payload []byte) (int, error)     { return len(payload), nil }
func (*syscallStreamConn) Close() error                          { return nil }
func (*syscallStreamConn) LocalAddr() net.Addr                   { return nil }
func (*syscallStreamConn) RemoteAddr() net.Addr                  { return nil }
func (*syscallStreamConn) SetDeadline(time.Time) error           { return nil }
func (*syscallStreamConn) SetReadDeadline(time.Time) error       { return nil }
func (*syscallStreamConn) SetWriteDeadline(time.Time) error      { return nil }
func (*syscallStreamConn) SyscallConn() (syscall.RawConn, error) { return stubRawConn{}, nil }

func TestNewReaderUnwrapsStatsSyscallConnection(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("stats readv fast path is Linux-specific")
	}
	connection := &transportstat.CounterConnection{Connection: new(syscallStreamConn)}
	if _, ok := NewReader(connection).(*ReadVReader); !ok {
		t.Fatalf("NewReader(stats connection) did not select readv")
	}
}

func BenchmarkStatsTCPReader(b *testing.B) {
	for _, benchmark := range []struct {
		name string
		new  func(*transportstat.CounterConnection) Reader
	}{
		{name: "single", new: func(connection *transportstat.CounterConnection) Reader {
			return &SingleReader{Reader: connection}
		}},
		{name: "readv", new: func(connection *transportstat.CounterConnection) Reader {
			return NewReader(connection)
		}},
	} {
		b.Run(benchmark.name, func(b *testing.B) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				b.Fatal(err)
			}
			defer listener.Close()
			client, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				b.Fatal(err)
			}
			defer client.Close()
			server, err := listener.Accept()
			if err != nil {
				b.Fatal(err)
			}
			defer server.Close()

			const transferSize = 64 * 1024
			payload := bytes.Repeat([]byte{'x'}, transferSize)
			writeError := make(chan error, 1)
			go func() {
				for range b.N {
					if _, err := io.Copy(client, bytes.NewReader(payload)); err != nil {
						writeError <- err
						return
					}
				}
				writeError <- nil
			}()

			reader := benchmark.new(&transportstat.CounterConnection{Connection: server})
			b.SetBytes(transferSize)
			b.ReportAllocs()
			b.ResetTimer()
			var read int64
			for read < int64(b.N)*transferSize {
				mb, err := reader.ReadMultiBuffer()
				if err != nil {
					b.Fatal(err)
				}
				read += int64(mb.Len())
				ReleaseMulti(mb)
			}
			b.StopTimer()
			if err := <-writeError; err != nil {
				b.Fatal(err)
			}
		})
	}
}
