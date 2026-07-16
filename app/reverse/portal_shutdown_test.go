package reverse

import (
	"testing"

	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

func TestStaticMuxPickerRejectsAndDrainsWorkerAfterClose(t *testing.T) {
	picker, err := NewStaticMuxPicker()
	if err != nil {
		t.Fatal(err)
	}
	if err := picker.Close(); err != nil {
		t.Fatal(err)
	}
	reader, writer := pipe.New(pipe.WithoutSizeLimit())
	client, err := mux.NewClientWorker(transport.Link{Reader: reader, Writer: writer}, mux.ClientStrategy{})
	if err != nil {
		t.Fatal(err)
	}
	worker := &PortalWorker{client: client}
	if picker.AddWorker(worker) {
		t.Fatal("closed picker accepted a new worker")
	}
	<-client.WaitClosed()
	if !client.Closed() {
		t.Fatal("rejected worker was not drained")
	}
}
