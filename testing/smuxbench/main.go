package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(arguments []string, stdout, stderr io.Writer) int {
	if len(arguments) == 0 {
		printUsage(stderr)
		return 2
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	switch arguments[0] {
	case "server":
		return runServerCommand(ctx, arguments[1:], stdout, stderr)
	case "client":
		return runClientCommand(ctx, arguments[1:], stdout, stderr)
	case "help", "-h", "--help":
		printUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n", arguments[0])
		printUsage(stderr)
		return 2
	}
}

func runServerCommand(ctx context.Context, arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("server", flag.ContinueOnError)
	flags.SetOutput(stderr)
	listenAddress := flags.String("listen", "0.0.0.0:5201", "TCP listen address")
	blockSize := flags.Int("block-size", 32*1024, "I/O block size in bytes")
	if err := flags.Parse(arguments); err != nil {
		return 2
	}
	listener, err := net.Listen("tcp", *listenAddress)
	if err != nil {
		fmt.Fprintf(stderr, "listen: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "smuxbench server listening on %s\n", listener.Addr())
	if err := serve(ctx, listener, *blockSize); err != nil {
		fmt.Fprintf(stderr, "server: %v\n", err)
		return 1
	}
	return 0
}

func runClientCommand(ctx context.Context, arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("client", flag.ContinueOnError)
	flags.SetOutput(stderr)
	target := flags.String("target", "", "benchmark server address")
	proxyAddress := flags.String("proxy", "", "optional SOCKS5 proxy address")
	modeValue := flags.String("mode", "download", "download, upload, or bidirectional")
	parallel := flags.Int("parallel", 4, "parallel logical TCP streams")
	duration := flags.Duration("duration", 10*time.Second, "measured duration per round")
	warmup := flags.Duration("warmup", 2*time.Second, "unmeasured warmup duration")
	rounds := flags.Int("rounds", 5, "number of measured rounds")
	blockSize := flags.Int("block-size", 32*1024, "I/O block size in bytes")
	timeout := flags.Duration("timeout", 10*time.Second, "connect and handshake timeout")
	if err := flags.Parse(arguments); err != nil {
		return 2
	}
	mode, err := parseMode(*modeValue)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	config := clientConfig{
		Target:    *target,
		Proxy:     *proxyAddress,
		Mode:      mode,
		Parallel:  *parallel,
		Duration:  *duration,
		Warmup:    *warmup,
		Rounds:    *rounds,
		BlockSize: *blockSize,
		Timeout:   *timeout,
	}
	report, err := runClient(ctx, config)
	if err != nil {
		fmt.Fprintf(stderr, "client: %v\n", err)
		return 1
	}
	if err := encodeReport(stdout, report); err != nil {
		fmt.Fprintf(stderr, "encode report: %v\n", err)
		return 1
	}
	return 0
}

func printUsage(writer io.Writer) {
	fmt.Fprintln(writer, "usage: smuxbench <server|client> [options]")
	fmt.Fprintln(writer, "  server: run on the destination host or VPS")
	fmt.Fprintln(writer, "  client: measure direct or SOCKS5-proxied TCP throughput")
}
