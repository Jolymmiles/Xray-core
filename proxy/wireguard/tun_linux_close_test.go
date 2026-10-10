//go:build linux

package wireguard

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"
)

// countingTUN stands in for the native TUN, which wireguard-go already
// closes once; it counts the wrapper's teardown passes.
type countingTUN struct {
	tun.Device
	closes atomic.Int32
}

func (d *countingTUN) Close() error {
	d.closes.Add(1)
	return nil
}

// After a failed bind wireguard-go closes the device from its own goroutine
// while the owner closes it too. The kernel TUN wrapper must tear down its
// rules, routes and netlink handle once, however many callers close it and
// however they overlap. Uses a real NETLINK_ROUTE handle; creates no TUN and
// changes no route, rule or interface.
func TestKernelTunCloseTearsDownOnce(t *testing.T) {
	handle, err := netlink.NewHandle(unix.NETLINK_ROUTE)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(handle.Close)
	device := &countingTUN{}
	tunnel := &kernelTun{Device: device, handle: handle}

	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results <- tunnel.Close()
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	afterConcurrent := device.closes.Load()
	if err := tunnel.Close(); err != nil {
		t.Fatal(err)
	}
	if got := device.closes.Load(); got != afterConcurrent {
		t.Fatalf("a repeated Close tore the TUN down again: %d device closes, then %d", afterConcurrent, got)
	}
}
