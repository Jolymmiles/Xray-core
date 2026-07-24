package log

import (
	"bufio"
	"errors"
	"io"
	"net"
	"os"
	"sync/atomic"
	"time"
)

const defaultFileBufferSize = 64 * 1024

type unixDialer func(string, string, time.Duration) (net.Conn, error)

// Output writes already encoded records. A logging worker owns an Output and
// calls its methods serially.
type Output interface {
	WriteBatch(records [][]byte) error
	Flush() error
	Close() error
}

// ConsoleOutput writes complete records to a process-owned stream. Close does
// not close the underlying writer.
type ConsoleOutput struct {
	writer io.Writer
}

// NewConsoleOutput creates a console output for stdout, stderr, or another
// process-owned writer.
func NewConsoleOutput(writer io.Writer) *ConsoleOutput {
	return &ConsoleOutput{writer: writer}
}

// IsTerminal reports whether the console writer is a character device.
func (o *ConsoleOutput) IsTerminal() bool {
	file, ok := o.writer.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func (o *ConsoleOutput) WriteBatch(records [][]byte) error {
	for _, record := range records {
		if err := writeFull(o.writer, record); err != nil {
			return err
		}
	}
	return nil
}

func (o *ConsoleOutput) Flush() error {
	if flusher, ok := o.writer.(interface{ Flush() error }); ok {
		return flusher.Flush()
	}
	return nil
}

func (*ConsoleOutput) Close() error { return nil }

// FileOutput owns one append-only file and its userspace buffer.
type FileOutput struct {
	file   *os.File
	writer *bufio.Writer
	closed bool
}

// NewFileOutput opens path once and creates it with mode 0600 when absent.
func NewFileOutput(path string, bufferSize int) (*FileOutput, error) {
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if bufferSize <= 0 {
		bufferSize = defaultFileBufferSize
	}
	return &FileOutput{file: file, writer: bufio.NewWriterSize(file, bufferSize)}, nil
}

func (o *FileOutput) WriteBatch(records [][]byte) error {
	if o.closed {
		return os.ErrClosed
	}
	for _, record := range records {
		if err := writeFull(o.writer, record); err != nil {
			return err
		}
	}
	return nil
}

func (o *FileOutput) Flush() error {
	if o.closed {
		return os.ErrClosed
	}
	return o.writer.Flush()
}

func (o *FileOutput) Close() error {
	if o.closed {
		return nil
	}
	o.closed = true
	return errors.Join(o.writer.Flush(), o.file.Close())
}

// UnixOutput owns one connection to a local Unix stream collector.
type UnixOutput struct {
	path       string
	connection net.Conn
	timeout    time.Duration
	dial       unixDialer
	closed     bool
	reconnects atomic.Uint64
}

// NewUnixOutput connects to an existing Unix stream listener.
func NewUnixOutput(path string, timeout time.Duration) (*UnixOutput, error) {
	return newUnixOutput(path, timeout, net.DialTimeout)
}

func newUnixOutput(path string, timeout time.Duration, dial unixDialer) (*UnixOutput, error) {
	output := &UnixOutput{path: path, timeout: timeout, dial: dial}
	if err := output.connect(false); err != nil {
		return nil, err
	}
	return output, nil
}

func (o *UnixOutput) WriteBatch(records [][]byte) error {
	if o.closed {
		return net.ErrClosed
	}
	if o.connection == nil {
		if err := o.connect(true); err != nil {
			return err
		}
	}
	if o.timeout > 0 {
		if err := o.connection.SetWriteDeadline(time.Now().Add(o.timeout)); err != nil {
			o.breakConnection()
			return err
		}
	}
	for _, record := range records {
		if err := writeFull(o.connection, record); err != nil {
			o.breakConnection()
			return err
		}
	}
	if o.timeout > 0 {
		if err := o.connection.SetWriteDeadline(time.Time{}); err != nil {
			o.breakConnection()
			return err
		}
	}
	return nil
}

func (*UnixOutput) Flush() error { return nil }

func (o *UnixOutput) Close() error {
	if o.closed {
		return nil
	}
	o.closed = true
	if o.connection == nil {
		return nil
	}
	return o.connection.Close()
}

// Reconnects returns the number of successful connections established after
// the initial connection.
func (o *UnixOutput) Reconnects() uint64 { return o.reconnects.Load() }

func (o *UnixOutput) connect(reconnect bool) error {
	connection, err := o.dial("unix", o.path, o.timeout)
	if err != nil {
		return err
	}
	o.connection = connection
	if reconnect {
		o.reconnects.Add(1)
	}
	return nil
}

func (o *UnixOutput) breakConnection() {
	if o.connection == nil {
		return
	}
	_ = o.connection.Close()
	o.connection = nil
}

func writeFull(writer io.Writer, contents []byte) error {
	for len(contents) > 0 {
		written, err := writer.Write(contents)
		if err != nil {
			return err
		}
		if written <= 0 || written > len(contents) {
			return io.ErrShortWrite
		}
		contents = contents[written:]
	}
	return nil
}
