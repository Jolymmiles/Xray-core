package dns_test

import (
	"context"
	"encoding/binary"
	"io"
	stdnet "net"
	"net/url"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/miekg/dns"
	. "github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/common/net"
	dns_feature "github.com/xtls/xray-core/features/dns"
)

func TestTCPLocalNameServer(t *testing.T) {
	dnsURL := localTCPDNSServer(t)
	s, err := NewTCPLocalNameServer(dnsURL, false, false, 0, net.IP(nil))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	ips, _, err := s.QueryIP(ctx, "google.com", dns_feature.IPOption{
		IPv4Enable: true,
		IPv6Enable: true,
	})
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) == 0 {
		t.Error("expect some ips, but got 0")
	}
}

func TestTCPLocalNameServerWithCache(t *testing.T) {
	dnsURL := localTCPDNSServer(t)
	s, err := NewTCPLocalNameServer(dnsURL, false, false, 0, net.IP(nil))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	ips, _, err := s.QueryIP(ctx, "google.com", dns_feature.IPOption{
		IPv4Enable: true,
		IPv6Enable: true,
	})
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) == 0 {
		t.Error("expect some ips, but got 0")
	}

	ctx2, cancel := context.WithTimeout(context.Background(), time.Second*5)
	ips2, _, err := s.QueryIP(ctx2, "google.com", dns_feature.IPOption{
		IPv4Enable: true,
		IPv6Enable: true,
	})
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	if r := cmp.Diff(ips2, ips); r != "" {
		t.Fatal(r)
	}
}

func TestTCPLocalNameServerWithIPv4Override(t *testing.T) {
	dnsURL := localTCPDNSServer(t)
	s, err := NewTCPLocalNameServer(dnsURL, false, false, 0, net.IP(nil))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	ips, _, err := s.QueryIP(ctx, "google.com", dns_feature.IPOption{
		IPv4Enable: true,
		IPv6Enable: false,
	})
	cancel()
	if err != nil {
		t.Fatal(err)
	}

	if len(ips) == 0 {
		t.Error("expect some ips, but got 0")
	}

	for _, ip := range ips {
		if len(ip) != net.IPv4len {
			t.Error("expect only IPv4 response from DNS query")
		}
	}
}

func TestTCPLocalNameServerWithIPv6Override(t *testing.T) {
	dnsURL := localTCPDNSServer(t)
	s, err := NewTCPLocalNameServer(dnsURL, false, false, 0, net.IP(nil))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	ips, _, err := s.QueryIP(ctx, "google.com", dns_feature.IPOption{
		IPv4Enable: false,
		IPv6Enable: true,
	})
	cancel()
	if err != nil {
		t.Fatal(err)
	}

	if len(ips) == 0 {
		t.Error("expect some ips, but got 0")
	}

	for _, ip := range ips {
		if len(ip) != net.IPv6len {
			t.Error("expect only IPv6 response from DNS query")
		}
	}
}

func localTCPDNSServer(t *testing.T) *url.URL {
	t.Helper()
	listener, err := stdnet.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go serveTCPDNSConnection(connection)
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		<-acceptDone
	})

	dnsURL, err := url.Parse("tcp+local://" + listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return dnsURL
}

func serveTCPDNSConnection(connection stdnet.Conn) {
	defer connection.Close()
	var length uint16
	if err := binary.Read(connection, binary.BigEndian, &length); err != nil {
		return
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(connection, payload); err != nil {
		return
	}
	query := new(dns.Msg)
	if err := query.Unpack(payload); err != nil {
		return
	}
	response := new(dns.Msg)
	response.SetReply(query)
	for _, question := range query.Question {
		header := dns.RR_Header{Name: question.Name, Class: dns.ClassINET, Ttl: 60}
		switch question.Qtype {
		case dns.TypeA:
			header.Rrtype = dns.TypeA
			response.Answer = append(response.Answer, &dns.A{Hdr: header, A: stdnet.IPv4(8, 8, 8, 8)})
		case dns.TypeAAAA:
			header.Rrtype = dns.TypeAAAA
			response.Answer = append(response.Answer, &dns.AAAA{Hdr: header, AAAA: stdnet.ParseIP("2001:4860:4860::8888")})
		}
	}
	encoded, err := response.Pack()
	if err != nil || len(encoded) > 65535 {
		return
	}
	if err := binary.Write(connection, binary.BigEndian, uint16(len(encoded))); err != nil {
		return
	}
	_, _ = connection.Write(encoded)
}
