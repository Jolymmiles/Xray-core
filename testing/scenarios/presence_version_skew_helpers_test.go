//go:build integration

package scenarios

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/xtls/xray-core/app/commander"
	"github.com/xtls/xray-core/app/policy"
	"github.com/xtls/xray-core/app/stats"
	statscmd "github.com/xtls/xray-core/app/stats/command"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	core "github.com/xtls/xray-core/core"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func enableVersionSkewStats(config *core.Config, commandPort net.Port) {
	config.App = append(config.App,
		serial.ToTypedMessage(&stats.Config{}),
		serial.ToTypedMessage(&policy.Config{Level: map[uint32]*policy.Policy{0: {Stats: &policy.Policy_Stats{UserOnline: true}}}}),
		serial.ToTypedMessage(&commander.Config{
			Listen:  "127.0.0.1:" + commandPort.String(),
			Service: []*serial.TypedMessage{serial.ToTypedMessage(&statscmd.Config{})},
		}),
	)
}

func openVerifiedTCPConnection(t *testing.T, port net.Port) net.Conn {
	t.Helper()
	connection, err := net.DialTCP("tcp", nil, &net.TCPAddr{IP: net.LocalHostIP.IP(), Port: int(port)})
	if err != nil {
		t.Fatal(err)
	}
	if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 1024)
	common.Must2(rand.Read(payload))
	if _, err := connection.Write(payload); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, len(payload))
	if _, err := io.ReadFull(connection, response); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response, xor(payload)) {
		t.Fatal("payload integrity mismatch")
	}
	return connection
}

func dialStatsService(t *testing.T, port net.Port) (*grpc.ClientConn, statscmd.StatsServiceClient) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	connection, err := grpc.DialContext(ctx, fmt.Sprintf("127.0.0.1:%d", port), grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	common.Must(err)
	t.Cleanup(func() { _ = connection.Close() })
	return connection, statscmd.NewStatsServiceClient(connection)
}

func waitStatsOnlineIPs(t *testing.T, client statscmd.StatsServiceClient, metric string, want ...string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		response, err := client.GetStatsOnlineIpList(context.Background(), &statscmd.GetStatsRequest{Name: metric})
		if err == nil && sameStatsIPs(response.Ips, want) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	response, err := client.GetStatsOnlineIpList(context.Background(), &statscmd.GetStatsRequest{Name: metric})
	if err != nil {
		t.Fatal(err)
	}
	t.Fatalf("online IPs = %v, want %v", response.Ips, want)
}

func sameStatsIPs(got map[string]int64, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for _, ip := range want {
		if _, found := got[ip]; !found {
			return false
		}
	}
	return true
}
