package internet_test

import (
	"testing"

	"github.com/xtls/xray-core/common/serial"
	. "github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/finalmask/mkcp/aes128gcm"
	"github.com/xtls/xray-core/transport/internet/finalmask/mkcp/original"
	"github.com/xtls/xray-core/transport/internet/finalmask/salamander"
	_ "github.com/xtls/xray-core/transport/internet/hysteria"
	_ "github.com/xtls/xray-core/transport/internet/kcp"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
	"google.golang.org/protobuf/proto"
)

// Stream settings also arrive as protobuf, from -format=pb configs and the
// HandlerService API, without passing the JSON config build. Gecko must be
// refused there too unless the transport authenticates whole datagrams.
func TestToMemoryStreamConfigRequiresDatagramIntegrityForGecko(t *testing.T) {
	masks := func(configs ...proto.Message) []*serial.TypedMessage {
		var typed []*serial.TypedMessage
		for _, config := range configs {
			typed = append(typed, serial.ToTypedMessage(config))
		}
		return typed
	}
	gecko := &salamander.GeckoConfig{Password: "gecko", MinPacketSize: 512, MaxPacketSize: 1200}
	for _, tc := range []struct {
		name     string
		protocol string
		masks    []*serial.TypedMessage
		accept   bool
	}{
		{"hysteria", "hysteria", masks(gecko), true},
		{"mkcp with the checksum mask outside", "mkcp", masks(&original.Config{}, gecko), true},
		{"mkcp with the AEAD mask outside", "mkcp", masks(&aes128gcm.Config{Password: "seed"}, gecko), true},
		{"mkcp with plain salamander", "mkcp", masks(&salamander.Config{Password: "plain"}), true},
		{"bare mkcp", "mkcp", masks(gecko), false},
		{"mkcp with the integrity mask inside", "mkcp", masks(gecko, &original.Config{}), false},
		{"tcp with the checksum mask outside", "tcp", masks(&original.Config{}, gecko), true},
		{"tcp", "tcp", masks(gecko), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ToMemoryStreamConfig(&StreamConfig{ProtocolName: tc.protocol, Udpmasks: tc.masks})
			switch {
			case tc.accept && err != nil:
				t.Fatalf("rejected: %v", err)
			case !tc.accept && err == nil:
				t.Fatal("accepted Gecko below a transport without datagram integrity")
			}
		})
	}
}
