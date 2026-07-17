// SPDX-License-Identifier: MPL-2.0

package mplsmux

import (
	"bytes"
	"io"
	"net"
	"testing"
)

func BenchmarkStreamRoundTrip32KiB(b *testing.B) {
	clientConn, serverConn := net.Pipe()
	config := DefaultConfig()
	config.KeepAliveDisabled = true
	client, err := Client(clientConn, config)
	if err != nil {
		b.Fatal(err)
	}
	server, err := Server(serverConn, config)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	clientStream, err := client.OpenStream()
	if err != nil {
		b.Fatal(err)
	}
	serverStream, err := server.AcceptStream()
	if err != nil {
		b.Fatal(err)
	}
	payload := bytes.Repeat([]byte{0x5a}, 32*1024)
	go func() {
		buffer := make([]byte, len(payload))
		for {
			if _, err := io.ReadFull(serverStream, buffer); err != nil {
				return
			}
			if _, err := serverStream.Write(buffer); err != nil {
				return
			}
		}
	}()
	received := make([]byte, len(payload))
	b.ReportAllocs()
	b.SetBytes(int64(len(payload) * 2))
	b.ResetTimer()
	for range b.N {
		if _, err := clientStream.Write(payload); err != nil {
			b.Fatal(err)
		}
		if _, err := io.ReadFull(clientStream, received); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkConcurrentStreamsRoundTrip32KiB(b *testing.B) {
	clientConn, serverConn := net.Pipe()
	config := DefaultConfig()
	config.KeepAliveDisabled = true
	client, err := Client(clientConn, config)
	if err != nil {
		b.Fatal(err)
	}
	server, err := Server(serverConn, config)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	payload := bytes.Repeat([]byte{0x5a}, 32*1024)
	go func() {
		for {
			serverStream, err := server.AcceptStream()
			if err != nil {
				return
			}
			go func() {
				buffer := make([]byte, len(payload))
				for {
					if _, err := io.ReadFull(serverStream, buffer); err != nil {
						return
					}
					if _, err := serverStream.Write(buffer); err != nil {
						return
					}
				}
			}()
		}
	}()
	b.ReportAllocs()
	b.SetBytes(int64(len(payload) * 2))
	b.RunParallel(func(parallel *testing.PB) {
		clientStream, err := client.OpenStream()
		if err != nil {
			b.Error(err)
			return
		}
		defer clientStream.Close()
		received := make([]byte, len(payload))
		for parallel.Next() {
			if _, err := clientStream.Write(payload); err != nil {
				b.Error(err)
				return
			}
			if _, err := io.ReadFull(clientStream, received); err != nil {
				b.Error(err)
				return
			}
		}
	})
}

func BenchmarkSessionPair(b *testing.B) {
	config := DefaultConfig()
	config.KeepAliveDisabled = true
	b.ReportAllocs()
	for range b.N {
		clientConn, serverConn := net.Pipe()
		client, err := Client(clientConn, config)
		if err != nil {
			b.Fatal(err)
		}
		server, err := Server(serverConn, config)
		if err != nil {
			b.Fatal(err)
		}
		_ = client.Close()
		_ = server.Close()
	}
}

func BenchmarkStreamLifecycle(b *testing.B) {
	clientConn, serverConn := net.Pipe()
	config := DefaultConfig()
	config.KeepAliveDisabled = true
	client, err := Client(clientConn, config)
	if err != nil {
		b.Fatal(err)
	}
	server, err := Server(serverConn, config)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	b.ReportAllocs()
	for range b.N {
		clientStream, err := client.OpenStream()
		if err != nil {
			b.Fatal(err)
		}
		serverStream, err := server.AcceptStream()
		if err != nil {
			b.Fatal(err)
		}
		if err := clientStream.Close(); err != nil {
			b.Fatal(err)
		}
		if err := serverStream.Close(); err != nil && err != io.EOF {
			b.Fatal(err)
		}
	}
}
