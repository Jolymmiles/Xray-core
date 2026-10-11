package splithttp

import (
	"net/http"

	"golang.org/x/net/http2"
)

// flowServerReceiveWindow is what a governed server grants for uploads unless
// configured otherwise: the most Linux autotuning lets one TCP socket buffer
// (tcp_rmem). Go's own 1 MiB per connection caps every upload on it at
// 1 MiB per round trip; the governor still holds the window to what is read.
const flowServerReceiveWindow = 6 << 20

// h2FlowOn reports whether the governor runs on this inbound or outbound:
// "h2Flow.enabled" if set, XRAY_XHTTP_FLOW=on otherwise.
func (c *Config) h2FlowOn() bool {
	switch c.GetH2Flow().GetMode() {
	case 1:
		return true
	case 2:
		return false
	}
	return flowEnabled
}

// flowServerSendWindow is what a governed server lets one connection's client
// hold of its data unless configured otherwise: the window a Go client grants
// one stream. A client under a memory limit, such as a phone's network
// extension, holds a few connections of that and stays within tens of MiB.
const flowServerSendWindow = 4 << 20

// h2SendWindow returns what one connection's client may hold of a governed
// server's data, 0 for no limit: "h2Flow.maxConnectionSendWindow", where -1
// lifts the limit and unset means flowServerSendWindow.
func (c *Config) h2SendWindow() int64 {
	switch w := c.GetH2Flow().GetMaxConnectionSendWindow(); {
	case w < 0:
		return 0
	case w == 0:
		return flowServerSendWindow
	default:
		return int64(w)
	}
}

// h2ReceiveConfig returns the HTTP/2 receive windows this side grants, or nil
// to keep Go's defaults.
func (c *Config) h2ReceiveConfig(server bool) *http.HTTP2Config {
	f := c.GetH2Flow()
	stream, conn := int(f.GetMaxStreamReceiveWindow()), int(f.GetMaxConnectionReceiveWindow())
	if server && c.h2FlowOn() {
		if stream == 0 {
			stream = flowServerReceiveWindow
		}
		if conn == 0 {
			conn = flowServerReceiveWindow
		}
	}
	if stream == 0 && conn == 0 {
		return nil
	}
	return &http.HTTP2Config{
		MaxReceiveBufferPerStream:     stream,
		MaxReceiveBufferPerConnection: conn,
	}
}

// newH2Transport returns an HTTP/2 transport that grants the given receive
// windows. x/net takes them only from a linked net/http transport.
func newH2Transport(conf *http.HTTP2Config) *http2.Transport {
	if conf == nil {
		return &http2.Transport{}
	}
	t1 := &http.Transport{HTTP2: conf}
	t2, err := http2.ConfigureTransports(t1)
	if err != nil {
		panic(err)
	}
	unlinkH2Transport(t1, t2)
	return t2
}
