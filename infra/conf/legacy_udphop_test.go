package conf_test

import (
	"encoding/json"
	"testing"

	"github.com/xtls/xray-core/app/proxyman"
	. "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/finalmask/salamander"
	"github.com/xtls/xray-core/transport/internet/finalmask/udphop"
	"github.com/xtls/xray-core/transport/internet/splithttp"
	"google.golang.org/protobuf/proto"
)

func buildOutboundStream(t *testing.T, stream string) (*internet.StreamConfig, error) {
	t.Helper()
	var outbound OutboundDetourConfig
	if err := json.Unmarshal([]byte(`{"protocol":"freedom","streamSettings":`+stream+`}`), &outbound); err != nil {
		t.Fatal(err)
	}
	config, err := outbound.Build()
	if err != nil {
		return nil, err
	}
	sender, err := config.SenderSettings.GetInstance()
	if err != nil {
		t.Fatal(err)
	}
	return sender.(*proxyman.SenderConfig).StreamSettings, nil
}

func udpMaskInstances(t *testing.T, stream *internet.StreamConfig) []proto.Message {
	t.Helper()
	var masks []proto.Message
	for _, mask := range stream.Udpmasks {
		instance, err := mask.GetInstance()
		if err != nil {
			t.Fatal(err)
		}
		masks = append(masks, instance.(proto.Message))
	}
	return masks
}

func udpHopMasks(t *testing.T, stream *internet.StreamConfig) []*udphop.Config {
	t.Helper()
	var hops []*udphop.Config
	for _, mask := range udpMaskInstances(t, stream) {
		if hop, ok := mask.(*udphop.Config); ok {
			hops = append(hops, hop)
		}
	}
	return hops
}

// quicParams.udpHop was removed upstream in favor of the "udphop" UDP mask.
// Dialing stream settings keep hopping by translating the legacy option into
// the mask with the old behavior: a random remote port for each dial, then a
// new local socket and remote port every interval.
func TestLegacyQuicUDPHopMigratesToUDPHopMask(t *testing.T) {
	stream, err := buildOutboundStream(t, `{
		"network": "hysteria",
		"finalmask": {
			"udp": [{"type": "salamander", "settings": {"password": "legacy-hop"}}],
			"quicParams": {"udpHop": {"ports": "20000-20002", "interval": "6-9"}}
		}
	}`)
	if err != nil {
		t.Fatal(err)
	}
	masks := udpMaskInstances(t, stream)
	if len(masks) != 2 {
		t.Fatalf("udp masks = %v, want salamander followed by udphop", masks)
	}
	if _, ok := masks[0].(*salamander.Config); !ok {
		t.Fatalf("first udp mask = %T, want the configured salamander mask", masks[0])
	}
	// The hop dials its own sockets, so it must stay the mask closest to the wire.
	want := &udphop.Config{Local: true, Remote: true, IntervalMin: 6, IntervalMax: 9, RemotePorts: []uint32{20000, 20001, 20002}}
	if !proto.Equal(masks[1], want) {
		t.Fatalf("migrated udp mask = %v, want %v", masks[1], want)
	}
}

func TestLegacyQuicUDPHopKeepsDefaultInterval(t *testing.T) {
	stream, err := buildOutboundStream(t, `{"network": "xhttp", "finalmask": {"quicParams": {"udpHop": {"ports": "443,8443"}}}}`)
	if err != nil {
		t.Fatal(err)
	}
	hops := udpHopMasks(t, stream)
	want := &udphop.Config{Local: true, Remote: true, IntervalMin: 30, IntervalMax: 30, RemotePorts: []uint32{443, 8443}}
	if len(hops) != 1 || !proto.Equal(hops[0], want) {
		t.Fatalf("migrated udp masks = %v, want [%v]", hops, want)
	}
}

func TestLegacyQuicUDPHopRejectsInvalidOrAmbiguousConfig(t *testing.T) {
	for name, stream := range map[string]string{
		"interval below five seconds": `{"network": "hysteria", "finalmask": {"quicParams": {"udpHop": {"ports": "20000-20002", "interval": 3}}}}`,
		"explicit udphop mask":        `{"network": "hysteria", "finalmask": {"udp": [{"type": "udphop", "settings": {"mode": "intervalLocal", "remotePorts": "1000-1001"}}], "quicParams": {"udpHop": {"ports": "20000-20002"}}}}`,
		"xicmp dials its own sockets": `{"network": "hysteria", "finalmask": {"udp": [{"type": "xicmp", "settings": {}}], "quicParams": {"udpHop": {"ports": "20000-20002"}}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := buildOutboundStream(t, stream); err == nil {
				t.Fatal("legacy quicParams.udpHop was accepted")
			}
		})
	}
}

func TestLegacyQuicUDPHopLeavesOtherStreamsUnchanged(t *testing.T) {
	for name, stream := range map[string]string{
		"no ports":         `{"network": "hysteria", "finalmask": {"quicParams": {"udpHop": {"interval": "6-9"}}}}`,
		"non-QUIC network": `{"network": "raw", "finalmask": {"quicParams": {"udpHop": {"ports": "20000-20002"}}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			built, err := buildOutboundStream(t, stream)
			if err != nil {
				t.Fatal(err)
			}
			if masks := udpMaskInstances(t, built); len(masks) != 0 {
				t.Fatalf("udp masks = %v, want none", masks)
			}
		})
	}

	// Listeners never hopped and the udphop mask is client only, so inbound
	// stream settings must keep ignoring the legacy option.
	var inbound StreamConfig
	if err := json.Unmarshal([]byte(`{"network": "hysteria", "finalmask": {"quicParams": {"udpHop": {"ports": "20000-20002"}}}}`), &inbound); err != nil {
		t.Fatal(err)
	}
	built, err := inbound.Build()
	if err != nil {
		t.Fatal(err)
	}
	if masks := udpMaskInstances(t, built); len(masks) != 0 {
		t.Fatalf("inbound udp masks = %v, want none", masks)
	}
}

func TestLegacyQuicUDPHopMigratesXHTTPDownloadSettings(t *testing.T) {
	var config SplitHTTPConfig
	if err := json.Unmarshal([]byte(`{"downloadSettings": {"network": "xhttp", "finalmask": {"quicParams": {"udpHop": {"ports": "20000-20001", "interval": "10-20"}}}}}`), &config); err != nil {
		t.Fatal(err)
	}
	built, err := config.Build()
	if err != nil {
		t.Fatal(err)
	}
	download := built.(*splithttp.Config).DownloadSettings
	hops := udpHopMasks(t, download)
	want := &udphop.Config{Local: true, Remote: true, IntervalMin: 10, IntervalMax: 20, RemotePorts: []uint32{20000, 20001}}
	if len(hops) != 1 || !proto.Equal(hops[0], want) {
		t.Fatalf("downloadSettings udp masks = %v, want [%v]", hops, want)
	}
}
