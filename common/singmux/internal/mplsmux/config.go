// SPDX-License-Identifier: MPL-2.0

package mplsmux

import (
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	protocolVersion = 1
	maxFramePayload = 65535
)

type Config struct {
	Version            int
	KeepAliveDisabled  bool
	KeepAliveInterval  time.Duration
	KeepAliveTimeout   time.Duration
	MaxFrameSize       int
	MaxReceiveBuffer   int
	MaxStreamBuffer    int
	StreamStallTimeout time.Duration
}

func DefaultConfig() *Config {
	return &Config{
		Version:            protocolVersion,
		KeepAliveInterval:  10 * time.Second,
		KeepAliveTimeout:   30 * time.Second,
		MaxFrameSize:       32 * 1024,
		MaxReceiveBuffer:   4 * 1024 * 1024,
		MaxStreamBuffer:    64 * 1024,
		StreamStallTimeout: 30 * time.Second,
	}
}

func validateConfig(config *Config) error {
	if config.Version != protocolVersion {
		return fmt.Errorf("unsupported SMUX protocol version %d", config.Version)
	}
	if config.MaxFrameSize <= 0 || config.MaxFrameSize > maxFramePayload {
		return fmt.Errorf("SMUX frame size %d is outside 1..%d", config.MaxFrameSize, maxFramePayload)
	}
	if config.MaxReceiveBuffer < config.MaxFrameSize {
		return errors.New("SMUX receive buffer must hold at least one maximum-size frame")
	}
	if config.MaxStreamBuffer < config.MaxFrameSize || config.MaxStreamBuffer > config.MaxReceiveBuffer {
		return errors.New("SMUX stream buffer must hold at least one maximum-size frame and not exceed the receive buffer")
	}
	if config.StreamStallTimeout <= 0 {
		return errors.New("SMUX stream stall timeout must be positive")
	}
	if !config.KeepAliveDisabled && (config.KeepAliveInterval <= 0 || config.KeepAliveTimeout < config.KeepAliveInterval) {
		return errors.New("SMUX keepalive timeout must be at least its interval")
	}
	return nil
}

func Client(conn io.ReadWriteCloser, config *Config) (*Session, error) {
	return newSession(conn, config, true)
}

func Server(conn io.ReadWriteCloser, config *Config) (*Session, error) {
	return newSession(conn, config, false)
}

type timeoutError struct{}

func (*timeoutError) Error() string   { return "SMUX operation timed out" }
func (*timeoutError) Timeout() bool   { return true }
func (*timeoutError) Temporary() bool { return true }

var (
	ErrTimeout          net.Error = &timeoutError{}
	ErrInvalidProtocol            = errors.New("invalid SMUX protocol frame")
	ErrControlQueueFull           = errors.New("SMUX control frame queue is full")
)
