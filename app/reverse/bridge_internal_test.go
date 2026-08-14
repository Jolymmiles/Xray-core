package reverse

import (
	"context"
	"errors"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
)

type blockingBridgeDispatcher struct {
	started chan struct{}
	release chan struct{}
}

func (*blockingBridgeDispatcher) Type() interface{} { return routing.DispatcherType() }
func (*blockingBridgeDispatcher) Start() error      { return nil }
func (*blockingBridgeDispatcher) Close() error      { return nil }

func (d *blockingBridgeDispatcher) Dispatch(context.Context, net.Destination) (*transport.Link, error) {
	close(d.started)
	<-d.release
	return nil, errors.New("construction canceled")
}

func (*blockingBridgeDispatcher) DispatchLink(context.Context, net.Destination, *transport.Link) error {
	return errors.New("unexpected DispatchLink")
}

func TestBridgeCloseWaitsForPeriodicWorkerConstruction(t *testing.T) {
	dispatcher := &blockingBridgeDispatcher{started: make(chan struct{}), release: make(chan struct{})}
	bridge, err := NewBridge(&BridgeConfig{Tag: "reverse", Domain: "reverse.example"}, dispatcher)
	if err != nil {
		t.Fatal(err)
	}
	monitorDone := make(chan error, 1)
	go func() { monitorDone <- bridge.monitor() }()
	<-dispatcher.started

	closeDone := make(chan error, 1)
	go func() { closeDone <- bridge.Close() }()
	<-bridge.closing
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
		t.Fatal("bridge close returned while periodic worker construction was in flight")
	default:
	}
	close(dispatcher.release)
	if err := <-monitorDone; err != nil {
		t.Fatal(err)
	}
	if err := <-closeDone; err != nil {
		t.Fatal(err)
	}
}

func TestBridgeCloseWaitsForWorkerConstruction(t *testing.T) {
	dispatcher := &blockingBridgeDispatcher{started: make(chan struct{}), release: make(chan struct{})}
	bridge, err := NewBridge(&BridgeConfig{Tag: "reverse", Domain: "reverse.example"}, dispatcher)
	if err != nil {
		t.Fatal(err)
	}
	startDone := make(chan error, 1)
	go func() { startDone <- bridge.Start() }()
	<-dispatcher.started

	closeDone := make(chan error, 1)
	go func() { closeDone <- bridge.Close() }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
		t.Fatal("bridge close returned while worker construction was in flight")
	default:
	}
	close(dispatcher.release)
	if err := <-startDone; err != nil {
		t.Fatal(err)
	}
	if err := <-closeDone; err != nil {
		t.Fatal(err)
	}
}

func TestBridgeStartRejectsAfterClose(t *testing.T) {
	bridge, err := NewBridge(&BridgeConfig{Tag: "reverse", Domain: "reverse.example"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := bridge.Close(); err != nil {
		t.Fatal(err)
	}
	if err := bridge.Start(); err == nil {
		t.Fatal("closed bridge restarted its monitor")
	}
}
