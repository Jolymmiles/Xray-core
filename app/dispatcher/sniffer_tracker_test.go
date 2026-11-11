package dispatcher

import (
	"bytes"
	"context"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	routing_session "github.com/xtls/xray-core/features/routing/session"
)

// An HTTP tracker request is routed as bittorrent and keeps the HTTP Host as
// its domain, which destOverride ["http"] still applies, so domain rules see
// the tracker even for an IP destination.
func TestSniffHTTPTrackerKeepsItsDomain(t *testing.T) {
	ctx := snifferContext()
	payload := []byte("GET /announce?info_hash=x&peer_id=y HTTP/1.1\r\nHost: tracker.example.com\r\n\r\n")
	result, err := NewSniffer(ctx).Sniff(ctx, payload, net.Network_TCP)
	if err != nil {
		t.Fatal(err)
	}
	if result.Protocol() != "bittorrent" {
		t.Fatalf("protocol = %q, want bittorrent", result.Protocol())
	}
	dest := net.TCPDestination(net.IPAddress([]byte{192, 0, 2, 1}), 80)
	request := session.SniffingRequest{OverrideDestinationForProtocol: []string{"http", "tls"}, RouteOnly: true}
	domain, override := new(DefaultDispatcher).shouldOverride(context.Background(), result, request, dest)
	ob := &session.Outbound{Target: dest}
	if override {
		ob.RouteTarget = dest
		ob.RouteTarget.Address = net.ParseAddress(domain)
	}
	if got := (&routing_session.Context{Outbound: ob}).GetTargetDomain(); got != "tracker.example.com" {
		t.Fatalf("routing domain = %q (shouldOverride %q, %v), want tracker.example.com", got, domain, override)
	}
}

// Requests that only mention the parameter names stay HTTP.
func TestSniffOrdinaryHTTPPathsStayHTTP(t *testing.T) {
	for _, path := range []string{
		"/docs/info_hash=x/peer_id=y",
		"/api?previous_info_hash=abc&last_peer_id=def",
		"/search?info_hash=abc&q=/scrape?",
	} {
		ctx := snifferContext()
		result, err := NewSniffer(ctx).Sniff(ctx, []byte("GET "+path+" HTTP/1.1\r\nHost: example.com\r\n\r\n"), net.Network_TCP)
		if err != nil {
			t.Fatal(err)
		}
		if result.Protocol() != "http1" || result.Domain() != "example.com" {
			t.Errorf("%s: protocol %q domain %q, want http1 for example.com", path, result.Protocol(), result.Domain())
		}
	}
}

// A short datagram that does not open like LSD is turned down at once: the
// LSD sniffer does not hold ordinary UDP for a second read.
func TestSniffShortUDPReadsOnce(t *testing.T) {
	for _, size := range []int{20, 21} {
		ctx := snifferContext()
		link := &countingReader{datagramReader: datagramReader{datagrams: [][]byte{make([]byte, size)}}}
		reader := newTestCachedReader(t, link)
		_, err := sniff(ctx, reader, false, net.Network_UDP, newSniffer(ctx))
		if link.reads != 1 {
			t.Errorf("%d-byte datagram: %d reads (%v), want 1", size, link.reads, err)
		}
	}
}

// uTP is sniffed on the first datagram: two SYNs read at once are still a
// SYN, and an ST_DATA header followed by a datagram holding the peer
// handshake is no handshake carried in uTP.
func TestSniffUTPKeepsDatagramBoundaries(t *testing.T) {
	ctx := snifferContext()
	syns := [][]byte{vUTPSYN(), vUTPSYN()}
	result, err := NewSniffer(ctx).SniffDatagrams(ctx, bytes.Join(syns, nil), syns, net.Network_UDP)
	if err != nil || result.Protocol() != "bittorrent" {
		t.Errorf("two SYN datagrams: %v, %v; want bittorrent", result, err)
	}

	header := make([]byte, 20)
	header[0] = 0x01 // ST_DATA, version 1
	split := [][]byte{header, vPeerHandshake()}
	result, err = NewSniffer(ctx).SniffDatagrams(ctx, bytes.Join(split, nil), split, net.Network_UDP)
	if err == nil && result.Protocol() == "bittorrent" {
		t.Error("uTP handshake assembled from two datagrams")
	}
}
