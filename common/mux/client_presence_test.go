package mux

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	X "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

func TestRVSClientWorkerOwnsOnlyDataSessions(t *testing.T) {
	tracker := newXUDPPresenceTracker()
	scope := session.NewPresenceScope(session.PresenceSubject{Email: "alice@example.com", IP: netip.MustParseAddr("192.0.2.44")}, tracker)
	carrier, _ := muxPresenceLinkPair()
	worker, err := NewClientWorkerWithPresence(*carrier, ClientStrategy{}, scope)
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close()

	controlReader, controlWriter := pipe.New(pipe.WithoutSizeLimit())
	_, controlResponse := pipe.New(pipe.WithoutSizeLimit())
	controlCtx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: X.UDPDestination(X.DomainAddress("reverse.internal"), 0)}})
	if !worker.Dispatch(controlCtx, &transport.Link{Reader: controlReader, Writer: controlResponse}) {
		t.Fatal("control session was rejected")
	}
	waitXUDPIPs(t, tracker)

	dataReader, dataWriter := pipe.New(pipe.WithoutSizeLimit())
	_, dataResponse := pipe.New(pipe.WithoutSizeLimit())
	dataCtx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: X.TCPDestination(X.DomainAddress("public.example"), 443)}})
	if !worker.DispatchRVS(dataCtx, &transport.Link{Reader: dataReader, Writer: dataResponse}) {
		t.Fatal("RVS data session was rejected")
	}
	waitXUDPIPs(t, tracker, "192.0.2.44")
	_ = dataWriter.Close()
	waitXUDPIPs(t, tracker)
	_ = controlWriter.Close()
}

func TestRVSClientWorkersUseSelectedCarrierScope(t *testing.T) {
	tracker := newXUDPPresenceTracker()
	newWorker := func(ip string) *ClientWorker {
		carrier, _ := muxPresenceLinkPair()
		scope := session.NewPresenceScope(session.PresenceSubject{Email: "alice@example.com", IP: netip.MustParseAddr(ip)}, tracker)
		worker, err := NewClientWorkerWithPresence(*carrier, ClientStrategy{}, scope)
		if err != nil {
			t.Fatal(err)
		}
		return worker
	}
	first := newWorker("192.0.2.10")
	defer first.Close()
	second := newWorker("198.51.100.20")
	defer second.Close()
	reader, writer := pipe.New(pipe.WithoutSizeLimit())
	_, response := pipe.New(pipe.WithoutSizeLimit())
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: X.TCPDestination(X.DomainAddress("public.example"), 443)}})
	ctx = session.ContextWithInbound(ctx, &session.Inbound{
		Source:       X.TCPDestination(X.ParseAddress("203.0.113.99"), 12345),
		PhysicalPeer: netip.MustParseAddr("203.0.113.99"),
	})
	if !second.DispatchRVS(ctx, &transport.Link{Reader: reader, Writer: response}) {
		t.Fatal("selected carrier rejected data session")
	}
	waitXUDPIPs(t, tracker, "198.51.100.20")
	_ = writer.Close()
	waitXUDPIPs(t, tracker)
}

func TestRVSClientWorkerThousandSlotsEndAtZero(t *testing.T) {
	tracker := newXUDPPresenceTracker()
	scope := session.NewPresenceScope(session.PresenceSubject{Email: "alice@example.com", IP: netip.MustParseAddr("192.0.2.44")}, tracker)
	carrier, _ := muxPresenceLinkPair()
	worker, err := NewClientWorkerWithPresence(*carrier, ClientStrategy{}, scope)
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close()
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Target: X.TCPDestination(X.DomainAddress("public.example"), 443)}})
	for index := range 1000 {
		reader, writer := pipe.New(pipe.WithoutSizeLimit())
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		if !worker.DispatchRVS(ctx, &transport.Link{Reader: reader, Writer: buf.Discard}) {
			t.Fatalf("slot %d was rejected", index)
		}
		deadline := time.Now().Add(time.Second)
		for time.Now().Before(deadline) && worker.ActiveConnections() != 0 {
			time.Sleep(time.Millisecond)
		}
		if worker.ActiveConnections() != 0 {
			t.Fatalf("slot %d did not close", index)
		}
	}
	waitXUDPIPs(t, tracker)
}
