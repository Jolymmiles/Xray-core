//go:build !race

// SPDX-License-Identifier: MPL-2.0

package mplsmux

import (
	"bytes"
	"errors"
	"io"
	"net"
	"runtime/debug"
	"strings"
	"testing"
)

func TestStreamLifecycleAllocationBudget(t *testing.T) {
	if checkptrInstrumented() {
		t.Skip("checkptr instrumentation changes allocation counts")
	}
	client, server := testSessionPair(t, nil)
	var operationErr error
	allocations := testing.AllocsPerRun(100, func() {
		if operationErr != nil {
			return
		}
		clientStream, err := client.OpenStream()
		if err != nil {
			operationErr = err
			return
		}
		serverStream, err := server.AcceptStream()
		if err != nil {
			operationErr = err
			return
		}
		if err := clientStream.Close(); err != nil {
			operationErr = err
			return
		}
		if err := serverStream.Close(); err != nil && err != io.EOF && !errors.Is(err, net.ErrClosed) {
			operationErr = err
		}
	})
	if operationErr != nil {
		t.Fatal(operationErr)
	}
	if allocations > 28 {
		t.Fatalf("stream lifecycle allocations = %.1f, budget is 28", allocations)
	}
}

func checkptrInstrumented() bool {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return false
	}
	for _, setting := range info.Settings {
		if setting.Key == "-gcflags" && strings.Contains(setting.Value, "checkptr") {
			return true
		}
	}
	return false
}

func TestStreamRoundTripAllocationBudget(t *testing.T) {
	if checkptrInstrumented() {
		t.Skip("checkptr instrumentation changes allocation counts")
	}
	client, server := testSessionPair(t, nil)
	clientStream, err := client.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	serverStream, err := server.AcceptStream()
	if err != nil {
		t.Fatal(err)
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
	var operationErr error
	allocations := testing.AllocsPerRun(100, func() {
		if operationErr != nil {
			return
		}
		if _, operationErr = clientStream.Write(payload); operationErr != nil {
			return
		}
		_, operationErr = io.ReadFull(clientStream, received)
	})
	if operationErr != nil {
		t.Fatal(operationErr)
	}
	if allocations != 0 {
		t.Fatalf("32 KiB round-trip allocations = %.1f, budget is zero", allocations)
	}
}
