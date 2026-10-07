package splithttp

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
)

// frameSizes records the largest DATA frame seen in each direction.
type frameSizes struct {
	up, down atomic.Int64
}

type dataSniffer struct {
	max *atomic.Int64
}

func (d dataSniffer) frame(f h2Frame) {
	if f.typ == h2Data {
		for {
			cur := d.max.Load()
			if int64(f.length) <= cur || d.max.CompareAndSwap(cur, int64(f.length)) {
				return
			}
		}
	}
}

func (dataSniffer) control(_ h2Frame, header, payload, out []byte) []byte {
	return out
}

func (dataSniffer) boundary(out []byte) []byte { return out }

// sniffConn watches the frames on the wire of a server-side connection.
type sniffConn struct {
	net.Conn
	sizes   *frameSizes
	mu      sync.Mutex
	rp, wp  frameParser
	preface int
	upMax   dataSniffer
	downMax dataSniffer
}

func (c *sniffConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	in := b[:n]
	if skip := min(len(h2Preface)-c.preface, len(in)); skip > 0 {
		c.preface += skip
		in = in[skip:]
	}
	c.rp.feed(in, nil, c.upMax)
	return n, err
}

func (c *sniffConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	c.wp.feed(b, nil, c.downMax)
	c.mu.Unlock()
	return c.Conn.Write(b)
}

type sniffListener struct {
	net.Listener
	sizes *frameSizes
}

func (l sniffListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &sniffConn{Conn: c, sizes: l.sizes, upMax: dataSniffer{&l.sizes.up}, downMax: dataSniffer{&l.sizes.down}}, nil
}

func transferBoth(t *testing.T, client *http.Client) {
	resp, err := client.Post("http://x/", "", bytes.NewReader(make([]byte, 8<<20)))
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := io.Copy(io.Discard, resp.Body); n != 8<<20 {
		t.Fatalf("echoed %d bytes", n)
	}
	resp.Body.Close()
}

func TestFlowCapsFrameSize(t *testing.T) {
	echo := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 256<<10)
		for {
			n, err := io.ReadFull(r.Body, buf)
			if n > 0 {
				w.Write(buf[:n])
			}
			if err != nil {
				return
			}
		}
	})
	for _, tc := range []struct {
		name           string
		server, client bool
	}{
		{"stock both", false, false},
		{"stock server, x/net client", false, false},
		{"governed server, stock client", true, false},
		{"stock server, governed client", false, true},
	} {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		sizes := &frameSizes{}
		tl := &testListener{Listener: sniffListener{ln, sizes}}
		if tc.server {
			tl.up, tl.down = testUp, testDown
		}
		protocols := new(http.Protocols)
		protocols.SetHTTP1(true)
		protocols.SetUnencryptedHTTP2(true)
		srv := &http.Server{Handler: echo, Protocols: protocols}
		go srv.Serve(tl)
		addr := ln.Addr().String()
		if tc.client {
			transferBoth(t, newFlowTestClient(addr, true).Client)
		} else if tc.name == "stock server, x/net client" {
			transferBoth(t, newFlowTestClient(addr, false).Client)
		} else {
			transferBoth(t, h2Client(addr))
		}
		srv.Close()
		up, down := sizes.up.Load(), sizes.down.Load()
		t.Logf("%s: largest DATA frame client to server %d, server to client %d", tc.name, up, down)
		if (tc.server || tc.client) && (up > h2MinMaxFrameSize || down > h2MinMaxFrameSize) {
			t.Fatalf("%s: frames above %d on the wire", tc.name, h2MinMaxFrameSize)
		}
	}
}
