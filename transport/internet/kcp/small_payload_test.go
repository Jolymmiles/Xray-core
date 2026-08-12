package kcp_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	coreNet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/kcp"
	"github.com/xtls/xray-core/transport/internet/stat"
)

func TestDialAndListenDeliversFirstSmallWrite(t *testing.T) {
	config := &kcp.Config{
		Mtu:              1350,
		Tti:              50,
		UplinkCapacity:   5,
		DownlinkCapacity: 20,
		CwndMultiplier:   1,
		MaxSendingWindow: 2 * 1024 * 1024,
	}
	streamConfig := &internet.MemoryStreamConfig{
		ProtocolName:     "mkcp",
		ProtocolSettings: config,
	}
	firstReceived := make(chan error, 1)
	secondReceived := make(chan error, 1)
	physicalPeer := make(chan string, 1)
	firstPayload := []byte("\x00b831381d-6324-4d53-ad4f-8cda48b30811")
	secondPayload := []byte("second-mkcp-packet")

	listener, err := kcp.NewListener(context.Background(), coreNet.LocalHostIP, 0, streamConfig, func(connection stat.Connection) {
		if peer, ok := coreNet.PhysicalPeer(connection); ok {
			physicalPeer <- peer.String()
		} else {
			physicalPeer <- ""
		}
		_ = connection.SetReadDeadline(time.Now().Add(3 * time.Second))
		actual := make([]byte, len(firstPayload))
		_, err := io.ReadFull(connection, actual)
		if err == nil && !bytes.Equal(actual, firstPayload) {
			err = fmt.Errorf("received payload %q, want %q", actual, firstPayload)
		}
		firstReceived <- err
		if err != nil {
			return
		}

		actual = make([]byte, len(secondPayload))
		_, err = io.ReadFull(connection, actual)
		if err == nil && !bytes.Equal(actual, secondPayload) {
			err = fmt.Errorf("received payload %q, want %q", actual, secondPayload)
		}
		secondReceived <- err
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	port := coreNet.Port(listener.Addr().(*coreNet.UDPAddr).Port)
	client, err := kcp.DialKCP(context.Background(), coreNet.UDPDestination(coreNet.LocalHostIP, port), streamConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	_ = client.SetWriteDeadline(time.Now().Add(3 * time.Second))
	if _, err := client.Write(firstPayload); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-firstReceived:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("mKCP listener did not receive the first small write")
	}
	if got := <-physicalPeer; !strings.HasPrefix(got, "127.0.0.1:") {
		t.Fatalf("mKCP physical peer = %q, want loopback UDP peer", got)
	}

	if _, err := client.Write(secondPayload); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-secondReceived:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("synchronous connection handler blocked the mKCP packet loop")
	}
}
