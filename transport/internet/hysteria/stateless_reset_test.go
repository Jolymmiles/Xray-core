package hysteria

import (
	"context"
	"crypto/rand"
	"errors"
	stdnet "net"
	"strconv"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// Hysteria 2.12.1 answers a packet for an unknown connection with a QUIC
// stateless reset, so that clients notice a restarted server at once, and
// 2.12.2 added disableStatelessReset to stop that. What an unauthenticated
// prober's short header packet gets back must follow the option.
func TestHysteriaStatelessResetFollowsOption(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		t.Run("disableStatelessReset="+strconv.FormatBool(disabled), func(t *testing.T) {
			settings := hysteriaTestSettings(t)
			settings.QuicParams.DisableStatelessReset = disabled
			port := reserveHysteriaUDPPort(t)
			listener, err := Listen(context.Background(), xnet.LocalHostIP, xnet.Port(port), settings, func(stat.Connection) {})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()

			probe, err := stdnet.DialUDP("udp4", nil, &stdnet.UDPAddr{IP: stdnet.IPv4(127, 0, 0, 1), Port: port})
			if err != nil {
				t.Fatal(err)
			}
			defer probe.Close()
			packet := make([]byte, 100)
			if _, err := rand.Read(packet); err != nil {
				t.Fatal(err)
			}
			packet[0] = 0x40 | packet[0]&0x3f // short header with the fixed bit
			if _, err := probe.Write(packet); err != nil {
				t.Fatal(err)
			}
			if err := probe.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			reply := make([]byte, 1500)
			n, err := probe.Read(reply)
			var timeout stdnet.Error
			timedOut := errors.As(err, &timeout) && timeout.Timeout()

			switch {
			case disabled && err == nil:
				t.Errorf("with disableStatelessReset the server answered an unknown connection with %d bytes", n)
			case disabled && !timedOut:
				t.Errorf("with disableStatelessReset: %v, want no reply", err)
			case !disabled && err != nil:
				t.Errorf("without disableStatelessReset the server sent no stateless reset: %v", err)
			case !disabled && (n < 21 || n >= len(packet) || reply[0]&0xc0 != 0x40):
				t.Errorf("stateless reset of %d bytes starting %#02x, want a short header packet of 21 to %d bytes", n, reply[0], len(packet)-1)
			}
		})
	}
}
