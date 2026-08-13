package reverse

import (
	"testing"

	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

func TestPortalCloseWaitsForAdmittedHandler(t *testing.T) {
	portal := &Portal{state: portalOpen}
	if !portal.beginHandle() {
		t.Fatal("open portal rejected handler admission")
	}
	closed := make(chan struct{})
	go func() {
		_ = portal.Close()
		close(closed)
	}()
	select {
	case <-closed:
		t.Fatal("portal close completed before admitted handler returned")
	default:
	}
	portal.endHandle()
	<-closed
	if portal.beginHandle() {
		t.Fatal("closed portal admitted a new handler")
	}
}

func TestStaticMuxPickerClosingRejectsDrainingFallback(t *testing.T) {
	reader, writer := pipe.New(pipe.WithoutSizeLimit())
	client, err := mux.NewClientWorker(transport.Link{Reader: reader, Writer: writer}, mux.ClientStrategy{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	picker := &StaticMuxPicker{workers: []*PortalWorker{{client: client, draining: true}}, closed: true}
	if got, err := picker.PickAvailable(); err == nil || got != nil {
		t.Fatalf("closing picker selected draining fallback: worker=%v err=%v", got, err)
	}
}

func TestStaticMuxPickerFallsBackToDrainingCarrier(t *testing.T) {
	reader, writer := pipe.New(pipe.WithoutSizeLimit())
	client, err := mux.NewClientWorker(transport.Link{Reader: reader, Writer: writer}, mux.ClientStrategy{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	picker := &StaticMuxPicker{workers: []*PortalWorker{{client: client, draining: true}}}
	got, err := picker.PickAvailable()
	if err != nil {
		t.Fatalf("draining carrier must remain available until its replacement arrives: %v", err)
	}
	if got != client {
		t.Fatal("picker returned a different carrier")
	}
}
