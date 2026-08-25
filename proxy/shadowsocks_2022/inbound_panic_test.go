package shadowsocks_2022

import (
	"context"
	"strings"
	"testing"

	M "github.com/sagernet/sing/common/metadata"
)

// TestEntryPointsRecoverPanics covers every method sing calls into this package
// with. None of them has a recover above it in this tree: app/proxyman/inbound
// invokes proxy.Process bare, and the three packet ones do not even run on the
// caller's goroutine -- sing/common/udpnat spawns one per NAT entry. So a panic
// in any of the six ends the process, which is how one Shadowsocks-2022 UDP
// session took down a node on 2026-08-22.
//
// A context carrying no inbound session panics in the first statements of each,
// the same nil-dereference/bad-index shape as that crash. Every one must come
// back as an error naming itself.
func TestEntryPointsRecoverPanics(t *testing.T) {
	metadata := M.Metadata{
		Source:      M.ParseSocksaddr("10.0.0.1:1080"),
		Destination: M.ParseSocksaddr("1.2.3.4:443"),
	}
	ctx := context.Background()

	for _, entry := range []struct {
		name string
		call func() error
	}{
		{"Inbound.NewConnection", func() error {
			return (&Inbound{}).NewConnection(ctx, nil, metadata)
		}},
		{"Inbound.NewPacketConnection", func() error {
			return (&Inbound{}).NewPacketConnection(ctx, nil, metadata)
		}},
		{"MultiUserInbound.NewConnection", func() error {
			return (&MultiUserInbound{}).NewConnection(ctx, nil, metadata)
		}},
		{"MultiUserInbound.NewPacketConnection", func() error {
			return (&MultiUserInbound{}).NewPacketConnection(ctx, nil, metadata)
		}},
		{"RelayInbound.NewConnection", func() error {
			return (&RelayInbound{}).NewConnection(ctx, nil, metadata)
		}},
		{"RelayInbound.NewPacketConnection", func() error {
			return (&RelayInbound{}).NewPacketConnection(ctx, nil, metadata)
		}},
	} {
		t.Run(entry.name, func(t *testing.T) {
			err := entry.call()
			if err == nil {
				t.Fatal("panic was not converted into an error")
			}
			if want := "panic in singbridge." + entry.name; !strings.Contains(err.Error(), want) {
				t.Fatalf("error does not name %s: %v", want, err)
			}
		})
	}
}
