package dns_test

import (
	"context"
	"io"
	stdnet "net"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/miekg/dns"
	. "github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/common/net"
	dns_feature "github.com/xtls/xray-core/features/dns"
	"golang.org/x/net/http2"
)

func TestDOHNameServer(t *testing.T) {
	dohURL := localDoHServer(t)
	s := NewDoHNameServer(dohURL, nil, true, false, false, 0, net.IP(nil))
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

func TestDOHNameServerWithCache(t *testing.T) {
	dohURL := localDoHServer(t)
	s := NewDoHNameServer(dohURL, nil, true, false, false, 0, net.IP(nil))
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

func TestDOHNameServerWithIPv4Override(t *testing.T) {
	dohURL := localDoHServer(t)
	s := NewDoHNameServer(dohURL, nil, true, false, false, 0, net.IP(nil))
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

func TestDOHNameServerWithIPv6Override(t *testing.T) {
	dohURL := localDoHServer(t)
	s := NewDoHNameServer(dohURL, nil, true, false, false, 0, net.IP(nil))
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

func localDoHServer(t *testing.T) *url.URL {
	t.Helper()
	listener, err := stdnet.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.Header.Get("Content-Type") != "application/dns-message" {
			http.Error(writer, "invalid DoH request", http.StatusBadRequest)
			return
		}
		payload, err := io.ReadAll(request.Body)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		query := new(dns.Msg)
		if err := query.Unpack(payload); err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
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
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
		writer.Header().Set("Content-Type", "application/dns-message")
		_, _ = writer.Write(encoded)
	})

	var connections sync.Map
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			connections.Store(connection, struct{}{})
			go func() {
				defer connections.Delete(connection)
				defer connection.Close()
				(&http2.Server{}).ServeConn(connection, &http2.ServeConnOpts{Handler: handler})
			}()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		connections.Range(func(connection, _ any) bool {
			_ = connection.(stdnet.Conn).Close()
			return true
		})
		<-acceptDone
	})

	dohURL, err := url.Parse("https+local://" + listener.Addr().String() + "/dns-query")
	if err != nil {
		t.Fatal(err)
	}
	return dohURL
}
