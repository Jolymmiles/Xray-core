package mux

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"

	appstats "github.com/xtls/xray-core/app/stats"
	statscommand "github.com/xtls/xray-core/app/stats/command"
	"github.com/xtls/xray-core/common/session"
	featurestats "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

type clientPresenceTracker struct {
	active atomic.Int32
	closed chan struct{}
	online featurestats.OnlineMap
}

func (t *clientPresenceTracker) Prepare(subject session.PresenceSubject) session.PresenceReservation {
	return clientPresenceReservation{tracker: t, ip: subject.IP.String()}
}

type clientPresenceReservation struct {
	tracker *clientPresenceTracker
	ip      string
}

func (r clientPresenceReservation) Activate() session.PresenceLease {
	r.tracker.active.Add(1)
	if r.tracker.online != nil {
		r.tracker.online.AddIP(r.ip)
	}
	return &clientPresenceLease{tracker: r.tracker, ip: r.ip}
}
func (r clientPresenceReservation) Handoff(previous session.PresenceLease) session.PresenceLease {
	if previous != nil {
		previous.Close()
	}
	return r.Activate()
}
func (clientPresenceReservation) Abort() {}

type clientPresenceLease struct {
	tracker *clientPresenceTracker
	ip      string
	once    sync.Once
}

func (l *clientPresenceLease) Close() {
	l.once.Do(func() {
		l.tracker.active.Add(-1)
		if l.tracker.online != nil {
			l.tracker.online.RemoveIP(l.ip)
		}
		close(l.tracker.closed)
	})
}

type clientPresenceProvider struct{ tracker *clientPresenceTracker }

func (p clientPresenceProvider) SnapshotPresence(context.Context) session.PresenceScope {
	return session.PresenceScope{
		Subject: session.PresenceSubject{Email: "user@example.com", IP: netip.MustParseAddr("192.0.2.1")},
		Tracker: p.tracker,
	}
}

func TestRVSClientTracksDataSessionButNotControl(t *testing.T) {
	carrierReader, carrierWriter := pipe.New(pipe.WithoutSizeLimit())
	manager, err := appstats.NewManager(context.Background(), &appstats.Config{})
	if err != nil {
		t.Fatal(err)
	}
	statsName := "user>>>user@example.com>>>online"
	online, err := manager.GetOrRegisterOnlineMap(statsName)
	if err != nil {
		t.Fatal(err)
	}
	statsServer := statscommand.NewStatsServer(manager)
	tracker := &clientPresenceTracker{closed: make(chan struct{}), online: online}
	client, err := NewClientWorkerWithOptions(context.Background(), transport.Link{Reader: carrierReader, Writer: carrierWriter}, ClientStrategy{}, ClientWorkerOptions{
		PresenceProvider: clientPresenceProvider{tracker: tracker},
		PresenceMode:     session.PresenceModeStructural,
	})
	if err != nil {
		t.Fatal(err)
	}

	controlReader, controlWriter := pipe.New(pipe.WithoutSizeLimit())
	controlCtx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{}})
	if !client.Dispatch(controlCtx, &transport.Link{Reader: controlReader, Writer: controlWriter}) {
		t.Fatal("control dispatch failed")
	}
	if tracker.active.Load() != 0 {
		t.Fatal("RVS control session acquired a presence lease")
	}
	assertClientRPCOnline(t, statsServer, statsName, 0)

	dataReader, dataWriter := pipe.New(pipe.WithoutSizeLimit())
	dataCtx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{}})
	dataCtx = session.ContextWithIsReverseMux(dataCtx, true)
	if !client.Dispatch(dataCtx, &transport.Link{Reader: dataReader, Writer: dataWriter}) {
		t.Fatal("RVS data dispatch failed")
	}
	if tracker.active.Load() != 1 {
		t.Fatalf("RVS data leases = %d; want 1", tracker.active.Load())
	}
	assertClientRPCOnline(t, statsServer, statsName, 1)
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	<-tracker.closed
	if tracker.active.Load() != 0 {
		t.Fatal("RVS data lease remained after carrier shutdown")
	}
	assertClientRPCOnline(t, statsServer, statsName, 0)
}

func assertClientRPCOnline(t *testing.T, server statscommand.StatsServiceServer, name string, want int64) {
	t.Helper()
	response, err := server.GetStatsOnline(context.Background(), &statscommand.GetStatsRequest{Name: name})
	if err != nil {
		t.Fatal(err)
	}
	if got := response.Stat.Value; got != want {
		t.Fatalf("StatsService online value = %d; want %d", got, want)
	}
}
