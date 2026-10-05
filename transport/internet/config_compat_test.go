package internet

import (
	"encoding/hex"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestQuicParamsFieldNumbers(t *testing.T) {
	want := map[string]protowire.Number{
		"congestion": 1, "bbr_profile": 2, "brutal_up": 3, "brutal_down": 4,
		"init_stream_receive_window": 6, "max_stream_receive_window": 7,
		"init_conn_receive_window": 8, "max_conn_receive_window": 9, "max_idle_timeout": 10,
		"keep_alive_period": 11, "disable_path_mtu_discovery": 12, "max_incoming_streams": 13,
		"brutal_disable_loss_compensation": 14, "disable_chrome_parrot": 15, "disableGSO": 16,
		"disable_stateless_reset": 17,
	}
	descriptor := (&QuicParams{}).ProtoReflect().Descriptor()
	fields := descriptor.Fields()
	for name, number := range want {
		field := fields.ByName(protowireName(name))
		if field == nil || protowire.Number(field.Number()) != number {
			t.Fatalf("field %s number = %v, want %d", name, field, number)
		}
	}
	// udp_hop moved to the "udphop" UDP finalmask; its number stays reserved.
	if !descriptor.ReservedRanges().Has(5) || !descriptor.ReservedNames().Has("udp_hop") {
		t.Fatal("QuicParams must keep field 5 and name udp_hop reserved")
	}
}

func protowireName(name string) protoreflect.Name { return protoreflect.Name(name) }

func TestQuicParamsProtobufBackwardCompatibility(t *testing.T) {
	// The legacy wire still carries udp_hop (field 5); it must be skipped
	// without shifting any other field.
	legacy := &QuicParams{
		Congestion: "bbr", BbrProfile: "aggressive", BrutalUp: 3, BrutalDown: 4,
		InitStreamReceiveWindow: 6, MaxStreamReceiveWindow: 7,
		InitConnReceiveWindow: 8, MaxConnReceiveWindow: 9, MaxIdleTimeout: 10,
		KeepAlivePeriod: 11, DisablePathMtuDiscovery: true, MaxIncomingStreams: 13,
	}
	wire, err := hex.DecodeString("0a03626272120a61676772657373697665180320042a0a0a04e807e907100618093006380740084809500a580b6001680d")
	if err != nil {
		t.Fatal(err)
	}
	var got QuicParams
	if err := (proto.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(wire, &got); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(legacy, &got) {
		t.Fatalf("legacy round trip changed: got %v want %v", &got, legacy)
	}
}
