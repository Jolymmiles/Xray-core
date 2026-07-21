package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"
)

func TestPercentile(t *testing.T) {
	values := []time.Duration{9 * time.Millisecond, time.Millisecond, 5 * time.Millisecond, 3 * time.Millisecond}
	if got := percentile(values, 0.5); got != 4*time.Millisecond {
		t.Fatalf("median = %s, want 4ms", got)
	}
	if got := percentile(values, 0.95); got != 9*time.Millisecond {
		t.Fatalf("p95 = %s, want 9ms", got)
	}
	if got := percentile(nil, 0.95); got != 0 {
		t.Fatalf("empty percentile = %s, want 0", got)
	}
}

func TestClientConfigValidation(t *testing.T) {
	valid := clientConfig{
		Target:    "127.0.0.1:9000",
		Mode:      modeDownload,
		Parallel:  1,
		Duration:  time.Second,
		Rounds:    1,
		BlockSize: 32 * 1024,
		Timeout:   5 * time.Second,
	}
	if err := valid.validate(); err != nil {
		t.Fatalf("valid config: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*clientConfig)
	}{
		{name: "target", mutate: func(config *clientConfig) { config.Target = "" }},
		{name: "malformed target", mutate: func(config *clientConfig) { config.Target = "missing-port" }},
		{name: "malformed proxy", mutate: func(config *clientConfig) { config.Proxy = "missing-port" }},
		{name: "mode", mutate: func(config *clientConfig) { config.Mode = 0 }},
		{name: "parallel", mutate: func(config *clientConfig) { config.Parallel = 0 }},
		{name: "duration", mutate: func(config *clientConfig) { config.Duration = 0 }},
		{name: "warmup", mutate: func(config *clientConfig) { config.Warmup = -1 }},
		{name: "rounds", mutate: func(config *clientConfig) { config.Rounds = 0 }},
		{name: "small block", mutate: func(config *clientConfig) { config.BlockSize = 255 }},
		{name: "large block", mutate: func(config *clientConfig) { config.BlockSize = maxBlockSize + 1 }},
		{name: "timeout", mutate: func(config *clientConfig) { config.Timeout = 0 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := valid
			test.mutate(&config)
			if err := config.validate(); err == nil {
				t.Fatal("invalid config was accepted")
			}
		})
	}
}

func TestRunClientAndEncodeReport(t *testing.T) {
	listener, stopServer := startTestBenchmarkServer(t)
	defer stopServer()
	config := clientConfig{
		Target:    listener.Addr().String(),
		Mode:      modeDownload,
		Parallel:  1,
		Duration:  50 * time.Millisecond,
		Warmup:    25 * time.Millisecond,
		Rounds:    2,
		BlockSize: 8 * 1024,
		Timeout:   2 * time.Second,
	}
	report, err := runClient(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Rounds) != 2 || report.Rounds[0].DownloadBytes == 0 {
		t.Fatalf("unexpected report: %+v", report)
	}
	var encoded bytes.Buffer
	if err := encodeReport(&encoded, report); err != nil {
		t.Fatal(err)
	}
	var decoded benchmarkReport
	if err := json.Unmarshal(encoded.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Mode != "download" || decoded.SchemaVersion != 1 {
		t.Fatalf("decoded report = %+v", decoded)
	}
}

func TestRunRoundThroughSOCKS5(t *testing.T) {
	listener, stopServer := startTestBenchmarkServer(t)
	defer stopServer()
	proxyAddress, stopProxy := startTestSOCKS5Proxy(t)
	defer stopProxy()
	config := clientConfig{
		Target:    listener.Addr().String(),
		Proxy:     proxyAddress,
		Mode:      modeDownload,
		Parallel:  2,
		Duration:  50 * time.Millisecond,
		Rounds:    1,
		BlockSize: 8 * 1024,
		Timeout:   2 * time.Second,
	}
	result, err := runRound(context.Background(), config, 1)
	if err != nil {
		t.Fatal(err)
	}
	if result.DownloadBytes == 0 || len(result.Errors) != 0 {
		t.Fatalf("SOCKS5 result = %+v", result)
	}
}

func TestRunRoundDirect(t *testing.T) {
	listener, stopServer := startTestBenchmarkServer(t)
	defer stopServer()

	for _, mode := range []benchmarkMode{modeDownload, modeUpload, modeBidirectional} {
		t.Run(mode.String(), func(t *testing.T) {
			config := clientConfig{
				Target:    listener.Addr().String(),
				Mode:      mode,
				Parallel:  2,
				Duration:  100 * time.Millisecond,
				Rounds:    1,
				BlockSize: 32 * 1024,
				Timeout:   2 * time.Second,
			}
			result, err := runRound(context.Background(), config, 1)
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Errors) != 0 {
				t.Fatalf("stream errors: %v", result.Errors)
			}
			if result.AggregateMbps <= 0 {
				t.Fatalf("aggregate throughput = %f", result.AggregateMbps)
			}
			if mode != modeUpload && result.DownloadBytes == 0 {
				t.Fatal("download transferred no bytes")
			}
			if mode != modeDownload && result.UploadBytes == 0 {
				t.Fatal("upload transferred no bytes")
			}
		})
	}
}

func startTestBenchmarkServer(t *testing.T) (net.Listener, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serve(ctx, listener, 32*1024) }()
	var once sync.Once
	return listener, func() {
		once.Do(func() {
			cancel()
			_ = listener.Close()
			if err := <-done; err != nil {
				t.Errorf("benchmark server: %v", err)
			}
		})
	}
}

func startTestSOCKS5Proxy(t *testing.T) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go serveTestSOCKS5(connection)
		}
	}()
	var once sync.Once
	return listener.Addr().String(), func() {
		once.Do(func() {
			_ = listener.Close()
			<-done
		})
	}
}

func serveTestSOCKS5(client net.Conn) {
	defer client.Close()
	var greeting [2]byte
	if _, err := io.ReadFull(client, greeting[:]); err != nil || greeting[0] != 5 {
		return
	}
	methods := make([]byte, int(greeting[1]))
	if _, err := io.ReadFull(client, methods); err != nil {
		return
	}
	if _, err := client.Write([]byte{5, 0}); err != nil {
		return
	}
	var request [4]byte
	if _, err := io.ReadFull(client, request[:]); err != nil || request[0] != 5 || request[1] != 1 {
		return
	}
	var host string
	switch request[3] {
	case 1:
		address := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(client, address); err != nil {
			return
		}
		host = net.IP(address).String()
	case 3:
		var length [1]byte
		if _, err := io.ReadFull(client, length[:]); err != nil {
			return
		}
		address := make([]byte, int(length[0]))
		if _, err := io.ReadFull(client, address); err != nil {
			return
		}
		host = string(address)
	case 4:
		address := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(client, address); err != nil {
			return
		}
		host = net.IP(address).String()
	default:
		return
	}
	var portBytes [2]byte
	if _, err := io.ReadFull(client, portBytes[:]); err != nil {
		return
	}
	address := net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(portBytes[:]))))
	upstream, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		_, _ = client.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer upstream.Close()
	if _, err := client.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	copyDone := make(chan struct{}, 1)
	go func() {
		_, _ = io.Copy(upstream, client)
		_ = upstream.Close()
		copyDone <- struct{}{}
	}()
	_, _ = io.Copy(client, upstream)
	_ = client.Close()
	<-copyDone
}
