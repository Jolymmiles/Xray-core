package freedom

import (
	"context"
	"strings"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	xctx "github.com/xtls/xray-core/common/ctx"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
)

// captureLog keeps the general messages logged while it is the handler, with
// debug logging on.
type captureLog struct {
	messages chan string
}

func (c captureLog) Handle(msg log.Message) {
	if m, ok := msg.(*log.GeneralMessage); ok {
		select {
		case c.messages <- m.String():
		default:
		}
	}
}

// silentLog accepts no message, as when no log handler is registered.
type silentLog struct{}

func (silentLog) Handle(log.Message)        {}
func (silentLog) Enabled(log.Severity) bool { return false }

// A route whose socket refuses every datagram must not pass for a healthy
// session without replies: freedom logs a dropped datagram at debug level,
// naming itself and the session, the first one at once and then one a second.
func TestPacketWriterLogsTheDropsOfItsSession(t *testing.T) {
	capture := captureLog{messages: make(chan string, 8)}
	log.RegisterHandler(capture)
	t.Cleanup(func() { log.RegisterHandler(silentLog{}) })

	ctx := xctx.ContextWithID(context.Background(), 4242)
	socket := &refusingSocket{refuse: map[byte]error{2: errTooLong}}
	writer := NewPacketWriter(ctx, socket, &Handler{}, nil, net.Destination{}, net.UDPDestination(net.IPAddress([]byte{192, 0, 2, 1}), 53), nil)
	long := buf.NewWithSize(65508)
	long.Extend(65508)
	long.Bytes()[0] = 1
	mb := append(datagrams(net.UDPDestination(net.IPAddress([]byte{192, 0, 2, 1}), 53), 2, 3), long)
	if err := writer.WriteMultiBuffer(mb); err != nil {
		t.Fatal(err)
	}
	select {
	case m := <-capture.messages:
		if !strings.HasPrefix(m, "[Debug] [4242] proxy/freedom: dropped a UDP datagram of 1200 bytes that the socket refuses as too long") {
			t.Fatalf("logged %q, want the drop at debug level as proxy/freedom in session 4242", m)
		}
	default:
		t.Fatal("the drop was not logged")
	}
	select {
	case m := <-capture.messages:
		t.Fatalf("logged %q, a second drop within the second", m)
	default:
	}
}
