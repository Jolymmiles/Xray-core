package blackhole_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"net/http"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/proxy/blackhole"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

func TestBlackholeHTTPResponse(t *testing.T) {
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{}})
	handler, err := blackhole.New(ctx, &blackhole.Config{
		Response: &blackhole.Response{Type: "http"},
	})
	common.Must(err)

	reader, writer := pipe.New(pipe.WithoutSizeLimit())

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

	read := awaitRead(t, result)
	data := make([]byte, read.Len())
	read.Copy(data)
	resp := common.Must2(http.ReadResponse(bufio.NewReader(bytes.NewBuffer(data)), nil))
	if resp.StatusCode != 403 {
		t.Errorf("expected 403 response, got %d", resp.StatusCode)
	}
}

func TestBlackholeCustomResponse(t *testing.T) {
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{}})
	// slightly bigger than a buffer
	expected := make([]byte, buf.Size+1000)
	if _, err := rand.Read(expected); err != nil {
		t.Fatal(err)
	}
	handler, err := blackhole.New(ctx, &blackhole.Config{
		Response: &blackhole.Response{
			Type:               "custom",
			CustomResponseData: expected,
		},
	})
	common.Must(err)

	reader, writer := pipe.New(pipe.WithoutSizeLimit())
	result := make(chan readResult, 1)
	go func() {
		buffer, err := reader.ReadMultiBuffer()
		result <- readResult{buffer: buffer, err: err}
	}()

	link := transport.Link{Reader: reader, Writer: writer}
	common.Must(handler.Process(ctx, &link, nil))

	if actual := awaitRead(t, result); actual.String() != string(expected) {
		t.Errorf("custom response mismatch")
	}
}

type readResult struct {
	buffer buf.MultiBuffer
	err    error
}

func awaitRead(t *testing.T, result <-chan readResult) buf.MultiBuffer {
	t.Helper()
	select {
	case read := <-result:
		common.Must(read.err)
		if read.buffer.IsEmpty() {
			t.Fatal("expect response, but nothing")
		}
		return read.buffer
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for response")
		return nil
	}
}
