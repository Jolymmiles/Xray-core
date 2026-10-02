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

type readResult struct {
	buffer buf.MultiBuffer
	err    error
}

// startRead hands the response to the test goroutine through a channel, so the
// assertions never race with the reader.
func startRead(reader buf.Reader) <-chan readResult {
	result := make(chan readResult, 1)
	go func() {
		buffer, err := reader.ReadMultiBuffer()
		result <- readResult{buffer: buffer, err: err}
	}()
	return result
}

func waitRead(t *testing.T, result <-chan readResult) buf.MultiBuffer {
	t.Helper()
	select {
	case read := <-result:
		common.Must(read.err)
		return read.buffer
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for blackhole response")
		return nil
	}
}

func TestBlackholeHTTPResponse(t *testing.T) {
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{}})
	handler, err := blackhole.New(ctx, &blackhole.Config{
		Response: &blackhole.Response{Type: "http"},
	})
	common.Must(err)

	reader, writer := pipe.New(pipe.WithoutSizeLimit())

	result := startRead(reader)
	link := transport.Link{
		Reader: reader,
		Writer: writer,
	}
	common.Must(handler.Process(ctx, &link, nil))

	mb := waitRead(t, result)
	defer buf.ReleaseMulti(mb)
	if mb.IsEmpty() {
		t.Fatal("expect http response, but nothing")
	}
	data := make([]byte, mb.Len())
	mb.Copy(data)
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
	result := startRead(reader)

	link := transport.Link{Reader: reader, Writer: writer}
	common.Must(handler.Process(ctx, &link, nil))

	actual := waitRead(t, result)
	defer buf.ReleaseMulti(actual)
	if actual.String() != string(expected) {
		t.Errorf("custom response mismatch")
	}
}
