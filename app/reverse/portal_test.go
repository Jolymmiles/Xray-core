package reverse_test

import (
	"testing"
	"time"

	"github.com/xtls/xray-core/app/reverse"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

func TestStaticPickerEmpty(t *testing.T) {
	picker, err := reverse.NewStaticMuxPicker()
	common.Must(err)
	worker, err := picker.PickAvailable()
	if err == nil {
		t.Error("expected error, but nil")
	}
	if worker != nil {
		t.Error("expected nil worker, but not nil")
	}
}

func TestStaticPickerCloseDrainsWorkers(t *testing.T) {
	picker, err := reverse.NewStaticMuxPicker()
	common.Must(err)
	reader, writer := pipe.New(pipe.WithoutSizeLimit())
	client, err := mux.NewClientWorker(transport.Link{Reader: reader, Writer: writer}, mux.ClientStrategy{})
	common.Must(err)
	worker, err := reverse.NewPortalWorker(client)
	common.Must(err)
	picker.AddWorker(worker)
	if err := picker.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-client.WaitClosed():
	case <-time.After(time.Second):
		t.Fatal("picker close did not drain portal worker")
	}
	if err := picker.Close(); err != nil {
		t.Fatal(err)
	}
}
