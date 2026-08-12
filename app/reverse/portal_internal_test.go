package reverse

import (
	"testing"

	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

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
