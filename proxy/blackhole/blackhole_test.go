package blackhole_test

import (
	"context"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/proxy/blackhole"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

func TestBlackholeHTTPResponse(t *testing.T) {
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{}})
	handler, err := blackhole.New(ctx, &blackhole.Config{
		Response: serial.ToTypedMessage(&blackhole.HTTPResponse{}),
	})
	common.Must(err)

	reader, writer := pipe.New(pipe.WithoutSizeLimit())

	type readResult struct {
		buffer buf.MultiBuffer
		err    error
	}
	result := make(chan readResult, 1)
	go func() {
		buffer, err := reader.ReadMultiBuffer()
		result <- readResult{buffer: buffer, err: err}
	}()

	link := transport.Link{
		Reader: reader,
		Writer: writer,
	}
	common.Must(handler.Process(ctx, &link, nil))

	select {
	case read := <-result:
		common.Must(read.err)
		if read.buffer.IsEmpty() {
			t.Error("expect http response, but nothing")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for HTTP response")
	}
}
