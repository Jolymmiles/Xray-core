package dns_test

import (
	"context"
	gonet "net"
	"slices"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	dns_proxy "github.com/xtls/xray-core/proxy/dns"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

// packedQuery returns an A query for domain with id, padded with zeros to
// size bytes when size is longer than the query.
func packedQuery(t *testing.T, id uint16, domain string, size int) *buf.Buffer {
	t.Helper()
	query := new(dns.Msg)
	query.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	query.Id = id
	packed, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	b := buf.NewWithSize(int32(max(size, len(packed))))
	b.Write(packed)
	b.Extend(int32(max(size-len(packed), 0)))
	return b
}

// The inbounds hand the DNS outbound a UDP query whole, up to 65535 bytes,
// but the socket to the upstream refuses one longer than an IP packet holds
// with EMSGSIZE, which ended the DNS session. The outbound drops that query
// and passes on the next, both for the DNS module's own queries and for
// queries it sends on directly.
func TestDNSOutboundDropsQueriesTheSocketRefusesAsTooLong(t *testing.T) {
	for _, path := range []struct {
		name       string
		inboundTag string
	}{
		{"own link", timeoutOnlyInboundTag},
		{"direct rule", "socks-in"},
	} {
		t.Run(path.name, func(t *testing.T) {
			upstream := startUpstreamDNS(t)
			handler := new(dns_proxy.Handler)
			if err := handler.Init(directAll(), &ownLinkClient{}, &timeoutOnlyPolicy{idle: time.Minute}); err != nil {
				t.Fatal(err)
			}
			ctx := session.ContextWithInbound(context.Background(), &session.Inbound{
				Tag:    path.inboundTag,
				Source: net.UDPDestination(net.LocalHostIP, 5353),
			})
			ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{Target: upstream}})

			uplinkReader, uplinkWriter := pipe.New(pipe.WithoutSizeLimit())
			downlinkReader, downlinkWriter := pipe.New(pipe.WithoutSizeLimit())
			done := make(chan error, 1)
			go func() {
				done <- handler.Process(ctx, &transport.Link{Reader: uplinkReader, Writer: downlinkWriter}, &recordingDialer{})
			}()
			t.Cleanup(func() {
				uplinkWriter.Close()
				uplinkReader.Interrupt()
				downlinkWriter.Close()
				downlinkReader.Interrupt()
				select {
				case <-done:
				case <-time.After(10 * time.Second):
					t.Error("DNS outbound did not stop within 10s after its link closed")
				}
			})

			queries := buf.MultiBuffer{
				packedQuery(t, 1, "example.com", 0),
				packedQuery(t, 2, "example.com", 65508),
				packedQuery(t, 3, "example.com", 0),
			}
			if err := uplinkWriter.WriteMultiBuffer(queries); err != nil {
				t.Fatal(err)
			}
			var answers []uint16
			for len(answers) < 2 {
				mb, err := downlinkReader.ReadMultiBufferTimeout(10 * time.Second)
				if err != nil {
					t.Fatalf("answers %v within 10s, want 1 and 3: %v", answers, err)
				}
				for _, b := range mb {
					answer := new(dns.Msg)
					if err := answer.Unpack(b.Bytes()); err != nil {
						t.Fatalf("unpack answer: %v", err)
					}
					if !answeredByUpstream(answer) {
						t.Fatalf("answer %d = %v, want the upstream's", answer.Id, answer)
					}
					answers = append(answers, answer.Id)
				}
				buf.ReleaseMulti(mb)
			}
			// the upstream may answer the two queries in either order
			slices.Sort(answers)
			if !slices.Equal(answers, []uint16{1, 3}) {
				t.Fatalf("answers %v, want 1 and 3", answers)
			}
		})
	}
}

// startRawUpstream answers each query in turn, in order: with a reply padded
// to 9000 bytes for the query of id 2, and with upstreamAnswer for the others.
func startRawUpstream(t *testing.T) net.Destination {
	t.Helper()
	conn, err := gonet.ListenUDP("udp", &gonet.UDPAddr{IP: gonet.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		packet := make([]byte, 65536)
		for {
			n, from, err := conn.ReadFromUDP(packet)
			if err != nil {
				return
			}
			query := new(dns.Msg)
			if err := query.Unpack(packet[:n]); err != nil {
				continue
			}
			answer := new(dns.Msg)
			answer.SetReply(query)
			rr, err := dns.NewRR(query.Question[0].Name + " IN A " + upstreamAnswer)
			if err != nil {
				panic(err)
			}
			answer.Answer = append(answer.Answer, rr)
			reply, err := answer.Pack()
			if err != nil {
				panic(err)
			}
			if query.Id == 2 {
				reply = append(reply, make([]byte, 9000-len(reply))...)
			}
			_, _ = conn.WriteToUDP(reply, from)
		}
	}()
	return net.DestinationFromAddr(conn.LocalAddr())
}

// The DNS outbound read the upstream's replies into buffers of 8192 bytes,
// which cut a longer one without a sign, and passed its start on as a whole
// reply. It drops such a reply and passes on the next.
func TestDNSOutboundDropsRepliesLongerThanARead(t *testing.T) {
	upstream := startRawUpstream(t)
	handler := new(dns_proxy.Handler)
	if err := handler.Init(directAll(), &ownLinkClient{}, &timeoutOnlyPolicy{idle: time.Minute}); err != nil {
		t.Fatal(err)
	}
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{Tag: "socks-in", Source: net.UDPDestination(net.LocalHostIP, 5353)})
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{Target: upstream}})
	uplinkReader, uplinkWriter := pipe.New(pipe.WithoutSizeLimit())
	downlinkReader, downlinkWriter := pipe.New(pipe.WithoutSizeLimit())
	done := make(chan error, 1)
	go func() {
		done <- handler.Process(ctx, &transport.Link{Reader: uplinkReader, Writer: downlinkWriter}, &recordingDialer{})
	}()
	t.Cleanup(func() {
		uplinkWriter.Close()
		uplinkReader.Interrupt()
		downlinkWriter.Close()
		downlinkReader.Interrupt()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("DNS outbound did not stop within 10s after its link closed")
		}
	})
	// the upstream answers in order, so the reply to query 2 comes before 3
	for _, id := range []uint16{1, 2, 3} {
		if err := uplinkWriter.WriteMultiBuffer(buf.MultiBuffer{packedQuery(t, id, "example.com", 0)}); err != nil {
			t.Fatal(err)
		}
	}
	var answers []uint16
	for !slices.Contains(answers, 3) {
		mb, err := downlinkReader.ReadMultiBufferTimeout(10 * time.Second)
		if err != nil {
			t.Fatalf("answers %v within 10s, want 1 and 3: %v", answers, err)
		}
		for _, b := range mb {
			answer := new(dns.Msg)
			if err := answer.Unpack(b.Bytes()); err != nil {
				t.Fatalf("a reply of %d bytes does not unpack: %v", b.Len(), err)
			}
			answers = append(answers, answer.Id)
		}
		buf.ReleaseMulti(mb)
	}
	if !slices.Equal(answers, []uint16{1, 3}) {
		t.Fatalf("answers %v, want 1 and 3", answers)
	}
}
