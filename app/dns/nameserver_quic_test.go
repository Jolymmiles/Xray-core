package dns

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	stdnet "net"
	"net/url"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/google/go-cmp/cmp"
	"github.com/miekg/dns"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol/tls/cert"
	dns_feature "github.com/xtls/xray-core/features/dns"
)

func TestQUICNameServer(t *testing.T) {
	doqURL, roots := localDoQServer(t)
	s, err := NewQUICNameServer(doqURL, false, false, 0, net.IP(nil))
	if s != nil {
		s.tlsRootCAs = roots
	}
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

func TestQUICNameServerWithIPv4Override(t *testing.T) {
	doqURL, roots := localDoQServer(t)
	s, err := NewQUICNameServer(doqURL, false, false, 0, net.IP(nil))
	if s != nil {
		s.tlsRootCAs = roots
	}
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

func TestQUICNameServerWithIPv6Override(t *testing.T) {
	doqURL, roots := localDoQServer(t)
	s, err := NewQUICNameServer(doqURL, false, false, 0, net.IP(nil))
	if s != nil {
		s.tlsRootCAs = roots
	}
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

func localDoQServer(t *testing.T) (*url.URL, *x509.CertPool) {
	t.Helper()
	certificate, _ := cert.MustGenerate(nil, cert.IPAddresses(stdnet.IPv4(127, 0, 0, 1)))
	certificatePEM, keyPEM := certificate.ToPEM()
	tlsCertificate, err := tls.X509KeyPair(certificatePEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{tlsCertificate},
		NextProtos:   []string{NextProtoDQ},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	serverContext, cancelServer := context.WithCancel(context.Background())
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			connection, err := listener.Accept(serverContext)
			if err != nil {
				return
			}
			go serveDoQConnection(serverContext, connection)
		}
	}()
	t.Cleanup(func() {
		cancelServer()
		_ = listener.Close()
		<-acceptDone
	})

	doqURL, err := url.Parse("quic://" + listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certificatePEM) {
		t.Fatal("failed to trust local DoQ certificate")
	}
	return doqURL, roots
}

func serveDoQConnection(ctx context.Context, connection *quic.Conn) {
	defer connection.CloseWithError(0, "")
	for {
		stream, err := connection.AcceptStream(ctx)
		if err != nil {
			return
		}
		go func() {
			defer stream.Close()
			var length uint16
			if err := binary.Read(stream, binary.BigEndian, &length); err != nil {
				return
			}
			payload := make([]byte, length)
			if _, err := io.ReadFull(stream, payload); err != nil {
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
			if err := binary.Write(stream, binary.BigEndian, uint16(len(encoded))); err != nil {
				return
			}
			_, _ = stream.Write(encoded)
		}()
	}
}
