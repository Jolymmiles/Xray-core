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
