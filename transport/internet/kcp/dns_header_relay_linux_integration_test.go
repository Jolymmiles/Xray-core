//go:build integration && linux

package kcp_test

import (
	"net"
	"strings"
	"testing"
	"time"
)

// A datagram the relay cannot forward is reported as a problem, so a failed
// traffic check names the send error rather than only a SOCKS timeout.
func TestMKCPDNSHeaderRelayReportsSendErrors(t *testing.T) {
	// Linux rejects a send to port 0 with EINVAL.
	server := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	relay := startMKCPDNSHeaderRelay(t, server, "t.example.")
	client, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: relay.port()})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	query := []byte{0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 't', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0, 0, 1, 0, 1}
	if _, err := client.Write(query); err != nil {
		t.Fatal(err)
	}
	select {
	case <-relay.problemc:
	case <-time.After(5 * time.Second):
		t.Fatal("relay did not report the datagram it failed to forward to port 0")
	}
	problems := relay.takeProblems()
	if len(problems) != 1 || !strings.HasPrefix(problems[0], "forward a datagram from") || !strings.Contains(problems[0], "invalid argument") {
		t.Fatalf("relay problems = %q, want one failed forward to port 0", problems)
	}
}
