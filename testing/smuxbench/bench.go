package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"sort"
	"sync"
	"time"

	xproxy "golang.org/x/net/proxy"
)

const (
	minBlockSize = 256
	maxBlockSize = 1024 * 1024
	serverAck    = byte(0)
)

type clientConfig struct {
	Target    string
	Proxy     string
	Mode      benchmarkMode
	Parallel  int
	Duration  time.Duration
	Warmup    time.Duration
	Rounds    int
	BlockSize int
	Timeout   time.Duration
}

func (c clientConfig) validate() error {
	if c.Target == "" {
		return errors.New("target is required")
	}
	if _, _, err := net.SplitHostPort(c.Target); err != nil {
		return fmt.Errorf("invalid target %q: %w", c.Target, err)
	}
	if c.Proxy != "" {
		if _, _, err := net.SplitHostPort(c.Proxy); err != nil {
			return fmt.Errorf("invalid SOCKS5 proxy %q: %w", c.Proxy, err)
		}
	}
	if !c.Mode.valid() {
		return errors.New("benchmark mode is required")
	}
	if c.Parallel <= 0 {
		return errors.New("parallel stream count must be positive")
	}
	if c.Duration <= 0 {
		return errors.New("duration must be positive")
	}
	if c.Warmup < 0 {
		return errors.New("warmup must not be negative")
	}
	if c.Rounds <= 0 {
		return errors.New("round count must be positive")
	}
	if c.BlockSize < minBlockSize || c.BlockSize > maxBlockSize {
		return fmt.Errorf("block size must be between %d and %d bytes", minBlockSize, maxBlockSize)
	}
	if c.Timeout <= 0 {
		return errors.New("connect timeout must be positive")
	}
	return nil
}

type latencySummary struct {
	Minimum float64 `json:"min"`
	Median  float64 `json:"median"`
	P95     float64 `json:"p95"`
	Maximum float64 `json:"max"`
}

type roundResult struct {
	Index          int            `json:"index"`
	Duration       float64        `json:"duration_seconds"`
	UploadBytes    int64          `json:"upload_bytes"`
	DownloadBytes  int64          `json:"download_bytes"`
	UploadMbps     float64        `json:"upload_mbps"`
	DownloadMbps   float64        `json:"download_mbps"`
	AggregateMbps  float64        `json:"aggregate_mbps"`
	ConnectLatency latencySummary `json:"connect_ms"`
	Errors         []string       `json:"errors"`
}

type benchmarkReport struct {
	SchemaVersion int           `json:"schema_version"`
	GeneratedAt   string        `json:"generated_at"`
	Target        string        `json:"target"`
	Proxy         string        `json:"proxy,omitempty"`
	Mode          string        `json:"mode"`
	Parallel      int           `json:"parallel"`
	Duration      float64       `json:"duration_seconds"`
	Warmup        float64       `json:"warmup_seconds"`
	BlockSize     int           `json:"block_size"`
	Rounds        []roundResult `json:"rounds"`
}

type preparedConnection struct {
	connection net.Conn
	latency    time.Duration
}

type streamResult struct {
	uploadBytes   int64
	downloadBytes int64
	err           error
}

type contextDialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

func newDialer(config clientConfig) (contextDialer, error) {
	direct := &net.Dialer{Timeout: config.Timeout, KeepAlive: 30 * time.Second}
	if config.Proxy == "" {
		return direct, nil
	}
	dialer, err := xproxy.SOCKS5("tcp", config.Proxy, nil, direct)
	if err != nil {
		return nil, fmt.Errorf("create SOCKS5 dialer: %w", err)
	}
	contextual, ok := dialer.(contextDialer)
	if !ok {
		return nil, errors.New("SOCKS5 dialer does not support context cancellation")
	}
	return contextual, nil
}

func prepareConnection(ctx context.Context, dialer contextDialer, config clientConfig) (preparedConnection, error) {
	started := time.Now()
	connection, err := dialer.DialContext(ctx, "tcp", config.Target)
	if err != nil {
		return preparedConnection{}, err
	}
	success := false
	defer func() {
		if !success {
			_ = connection.Close()
		}
	}()
	if err := connection.SetDeadline(time.Now().Add(config.Timeout)); err != nil {
		return preparedConnection{}, err
	}
	if err := writeRequest(connection, benchmarkRequest{Mode: config.Mode}); err != nil {
		return preparedConnection{}, fmt.Errorf("send benchmark request: %w", err)
	}
	var ack [1]byte
	if _, err := io.ReadFull(connection, ack[:]); err != nil {
		return preparedConnection{}, fmt.Errorf("read benchmark acknowledgement: %w", err)
	}
	if ack[0] != serverAck {
		return preparedConnection{}, fmt.Errorf("server rejected benchmark request with status %d", ack[0])
	}
	if err := connection.SetDeadline(time.Time{}); err != nil {
		return preparedConnection{}, err
	}
	success = true
	return preparedConnection{connection: connection, latency: time.Since(started)}, nil
}

func prepareConnections(ctx context.Context, config clientConfig) ([]preparedConnection, error) {
	dialer, err := newDialer(config)
	if err != nil {
		return nil, err
	}
	connections := make([]preparedConnection, config.Parallel)
	errorsByIndex := make([]error, config.Parallel)
	var wait sync.WaitGroup
	for index := range connections {
		wait.Add(1)
		go func() {
			defer wait.Done()
			connections[index], errorsByIndex[index] = prepareConnection(ctx, dialer, config)
		}()
	}
	wait.Wait()
	for index, err := range errorsByIndex {
		if err != nil {
			for _, prepared := range connections {
				if prepared.connection != nil {
					_ = prepared.connection.Close()
				}
			}
			return nil, fmt.Errorf("prepare stream %d: %w", index+1, err)
		}
	}
	return connections, nil
}

func runRound(ctx context.Context, config clientConfig, index int) (roundResult, error) {
	if err := config.validate(); err != nil {
		return roundResult{}, err
	}
	connections, err := prepareConnections(ctx, config)
	if err != nil {
		return roundResult{}, err
	}
	for _, prepared := range connections {
		defer prepared.connection.Close()
	}

	start := make(chan struct{})
	results := make(chan streamResult, len(connections))
	deadline := time.Now().Add(config.Duration)
	for _, prepared := range connections {
		go func() {
			<-start
			results <- transfer(prepared.connection, config.Mode, config.BlockSize, deadline)
		}()
	}
	close(start)

	result := roundResult{Index: index, Duration: config.Duration.Seconds()}
	latencies := make([]time.Duration, 0, len(connections))
	for _, prepared := range connections {
		latencies = append(latencies, prepared.latency)
	}
	result.ConnectLatency = summarizeLatency(latencies)
	for range connections {
		stream := <-results
		result.UploadBytes += stream.uploadBytes
		result.DownloadBytes += stream.downloadBytes
		if stream.err != nil {
			result.Errors = append(result.Errors, stream.err.Error())
		}
	}
	seconds := config.Duration.Seconds()
	result.UploadMbps = float64(result.UploadBytes*8) / seconds / 1_000_000
	result.DownloadMbps = float64(result.DownloadBytes*8) / seconds / 1_000_000
	result.AggregateMbps = result.UploadMbps + result.DownloadMbps
	return result, nil
}

func transfer(connection net.Conn, mode benchmarkMode, blockSize int, deadline time.Time) streamResult {
	if err := connection.SetDeadline(deadline); err != nil {
		return streamResult{err: err}
	}
	block := make([]byte, blockSize)
	for index := range block {
		block[index] = byte(index)
	}
	switch mode {
	case modeDownload:
		downloaded, err := copyUntilDeadline(io.Discard, connection, block)
		return streamResult{downloadBytes: downloaded, err: normalizeTransferError(err)}
	case modeUpload:
		uploaded, err := writeUntilDeadline(connection, block)
		return streamResult{uploadBytes: uploaded, err: normalizeTransferError(err)}
	case modeBidirectional:
		type directionResult struct {
			bytes int64
			err   error
		}
		upload := make(chan directionResult, 1)
		go func() {
			count, err := writeUntilDeadline(connection, block)
			upload <- directionResult{bytes: count, err: normalizeTransferError(err)}
		}()
		downloaded, downloadErr := copyUntilDeadline(io.Discard, connection, make([]byte, blockSize))
		uploadResult := <-upload
		return streamResult{
			uploadBytes:   uploadResult.bytes,
			downloadBytes: downloaded,
			err:           errors.Join(uploadResult.err, normalizeTransferError(downloadErr)),
		}
	default:
		return streamResult{err: fmt.Errorf("unsupported mode %d", mode)}
	}
}

func copyUntilDeadline(writer io.Writer, reader io.Reader, buffer []byte) (int64, error) {
	return io.CopyBuffer(writer, reader, buffer)
}

func writeUntilDeadline(writer io.Writer, block []byte) (int64, error) {
	var total int64
	for {
		written, err := writer.Write(block)
		total += int64(written)
		if err != nil {
			return total, err
		}
		if written != len(block) {
			return total, io.ErrShortWrite
		}
	}
}

func normalizeTransferError(err error) error {
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	var netError net.Error
	if errors.As(err, &netError) && netError.Timeout() {
		return nil
	}
	return err
}

func summarizeLatency(values []time.Duration) latencySummary {
	if len(values) == 0 {
		return latencySummary{}
	}
	ordered := append([]time.Duration(nil), values...)
	sort.Slice(ordered, func(left, right int) bool { return ordered[left] < ordered[right] })
	return latencySummary{
		Minimum: durationMilliseconds(ordered[0]),
		Median:  durationMilliseconds(percentile(ordered, 0.5)),
		P95:     durationMilliseconds(percentile(ordered, 0.95)),
		Maximum: durationMilliseconds(ordered[len(ordered)-1]),
	}
}

func percentile(values []time.Duration, quantile float64) time.Duration {
	if len(values) == 0 {
		return 0
	}
	ordered := append([]time.Duration(nil), values...)
	sort.Slice(ordered, func(left, right int) bool { return ordered[left] < ordered[right] })
	if quantile == 0.5 && len(ordered)%2 == 0 {
		middle := len(ordered) / 2
		return (ordered[middle-1] + ordered[middle]) / 2
	}
	index := int(math.Ceil(quantile*float64(len(ordered)))) - 1
	if index < 0 {
		index = 0
	}
	if index >= len(ordered) {
		index = len(ordered) - 1
	}
	return ordered[index]
}

func durationMilliseconds(value time.Duration) float64 {
	return float64(value) / float64(time.Millisecond)
}

func runClient(ctx context.Context, config clientConfig) (benchmarkReport, error) {
	if err := config.validate(); err != nil {
		return benchmarkReport{}, err
	}
	if config.Warmup > 0 {
		warmup := config
		warmup.Duration = config.Warmup
		warmup.Rounds = 1
		if _, err := runRound(ctx, warmup, 0); err != nil {
			return benchmarkReport{}, fmt.Errorf("warmup: %w", err)
		}
	}
	report := benchmarkReport{
		SchemaVersion: 1,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339Nano),
		Target:        config.Target,
		Proxy:         config.Proxy,
		Mode:          config.Mode.String(),
		Parallel:      config.Parallel,
		Duration:      config.Duration.Seconds(),
		Warmup:        config.Warmup.Seconds(),
		BlockSize:     config.BlockSize,
		Rounds:        make([]roundResult, 0, config.Rounds),
	}
	for round := 1; round <= config.Rounds; round++ {
		result, err := runRound(ctx, config, round)
		if err != nil {
			return benchmarkReport{}, fmt.Errorf("round %d: %w", round, err)
		}
		report.Rounds = append(report.Rounds, result)
	}
	return report, nil
}

func encodeReport(writer io.Writer, report benchmarkReport) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

func serve(ctx context.Context, listener net.Listener, blockSize int) error {
	if blockSize < minBlockSize || blockSize > maxBlockSize {
		return fmt.Errorf("server block size must be between %d and %d bytes", minBlockSize, maxBlockSize)
	}
	stopClose := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stopClose()
	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go handleConnection(ctx, connection, blockSize)
	}
}

func handleConnection(ctx context.Context, connection net.Conn, blockSize int) {
	defer connection.Close()
	stopClose := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stopClose()
	_ = connection.SetDeadline(time.Now().Add(10 * time.Second))
	request, err := readRequest(connection)
	if err != nil {
		return
	}
	if err := writeFull(connection, []byte{serverAck}); err != nil {
		return
	}
	if err := connection.SetDeadline(time.Time{}); err != nil {
		return
	}
	block := make([]byte, blockSize)
	for index := range block {
		block[index] = byte(index)
	}
	switch request.Mode {
	case modeDownload:
		_, _ = writeUntilDeadline(connection, block)
	case modeUpload:
		_, _ = io.CopyBuffer(io.Discard, connection, block)
	case modeBidirectional:
		writeDone := make(chan struct{})
		go func() {
			_, _ = writeUntilDeadline(connection, block)
			close(writeDone)
		}()
		_, _ = io.CopyBuffer(io.Discard, connection, make([]byte, blockSize))
		_ = connection.Close()
		<-writeDone
	}
}
