//go:build integration

package singmux_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	statscommand "github.com/xtls/xray-core/app/stats/command"
	"google.golang.org/grpc"
)

type onlineIPsClient struct {
	statscommand.StatsServiceClient
	query func(context.Context) (*statscommand.GetStatsOnlineIpListResponse, error)
}

func (c onlineIPsClient) GetStatsOnlineIpList(ctx context.Context, _ *statscommand.GetStatsRequest, _ ...grpc.CallOption) (*statscommand.GetStatsOnlineIpListResponse, error) {
	return c.query(ctx)
}

func TestAwaitStatsOnlineIPsMatchesExpectedSet(t *testing.T) {
	client := onlineIPsClient{query: func(context.Context) (*statscommand.GetStatsOnlineIpListResponse, error) {
		return &statscommand.GetStatsOnlineIpListResponse{Ips: map[string]int64{"192.0.2.8": 1}}, nil
	}}
	if err := awaitStatsOnlineIPs(context.Background(), client, "192.0.2.8"); err != nil {
		t.Fatal(err)
	}
}

func TestAwaitStatsOnlineIPsDeadlineInterruptsStalledRPC(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		client := onlineIPsClient{query: func(ctx context.Context) (*statscommand.GetStatsOnlineIpListResponse, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}}
		started := time.Now()
		err := awaitStatsOnlineIPs(ctx, client, "192.0.2.8")
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("stalled RPC result = %v, want deadline exceeded", err)
		}
		if elapsed := time.Since(started); elapsed != 5*time.Second {
			t.Fatalf("stalled RPC took %s, want the five-second budget", elapsed)
		}
	})
}

func TestAwaitStatsOnlineIPsDeadlineReportsLastIPs(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		client := onlineIPsClient{query: func(context.Context) (*statscommand.GetStatsOnlineIpListResponse, error) {
			return &statscommand.GetStatsOnlineIpListResponse{Ips: map[string]int64{"192.0.2.9": 1}}, nil
		}}
		err := awaitStatsOnlineIPs(ctx, client, "192.0.2.8")
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("mismatched IPs result = %v, want deadline exceeded", err)
		}
		if !strings.Contains(err.Error(), "192.0.2.9") || !strings.Contains(err.Error(), "192.0.2.8") {
			t.Fatalf("timeout lost observed or expected IPs: %v", err)
		}
	})
}
