//go:build integration

package singmux_test

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"
)

// hysteriaIPv6EchoCount is how many IPv6 echo targets a Hysteria cell sends
// UDP to: more than the server's UDPReader caches per session (four), so a
// full cycle evicts entries.
const hysteriaIPv6EchoCount = 6

// startUDPEchoIPv6 starts UDP echo servers on the IPv6 loopback address.
func startUDPEchoIPv6(t *testing.T, count int) []*net.UDPAddr {
	t.Helper()
	echoes := make([]*net.UDPAddr, 0, count)
	for range count {
		connection, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
		if err != nil {
			t.Fatalf("IPv6 loopback UDP echo: %v", err)
		}
		t.Cleanup(func() { _ = connection.Close() })
		go func() {
			payload := make([]byte, 65535)
			for {
				n, address, err := connection.ReadFromUDP(payload)
				if err != nil {
					return
				}
				_, _ = connection.WriteToUDP(payload[:n], address)
			}
		}()
		echoes = append(echoes, connection.LocalAddr().(*net.UDPAddr))
	}
	return echoes
}

// socksUDPAssociation is one SOCKS5 UDP ASSOCIATE: a client sends every
// datagram of it through the same proxy UDP session.
type socksUDPAssociation struct {
	control net.Conn
	udp     *net.UDPConn
	relay   *net.UDPAddr
}

func openSOCKSUDPAssociation(t *testing.T, socksPort int) *socksUDPAssociation {
	t.Helper()
	control, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = control.Close() })
	_ = control.SetDeadline(time.Now().Add(30 * time.Second))
	if err := socksGreeting(control); err != nil {
		t.Fatal(err)
	}
	if _, err := control.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	relay, err := readSOCKSReplyAddress(control)
	if err != nil {
		t.Fatal(err)
	}
	if relay.IP.IsUnspecified() {
		relay.IP = net.IPv4(127, 0, 0, 1)
	}
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = udp.Close() })
	return &socksUDPAssociation{control: control, udp: udp, relay: relay}
}

// appendSOCKSUDPAddress appends a SOCKS5 IPv4 or IPv6 address and port.
func appendSOCKSUDPAddress(packet []byte, destination *net.UDPAddr) []byte {
	if ip4 := destination.IP.To4(); ip4 != nil {
		packet = append(append(packet, 1), ip4...)
	} else {
		packet = append(append(packet, 4), destination.IP.To16()...)
	}
	return binary.BigEndian.AppendUint16(packet, uint16(destination.Port))
}

// parseSOCKSUDPSource returns the address of a SOCKS5 UDP reply, which is the
// source of the datagram it relays, and the payload after the header.
func parseSOCKSUDPSource(packet []byte) (netip.AddrPort, []byte, error) {
	if len(packet) < 4 {
		return netip.AddrPort{}, nil, fmt.Errorf("SOCKS UDP reply of %d bytes", len(packet))
	}
	var ip netip.Addr
	var rest []byte
	switch packet[3] {
	case 1:
		if len(packet) < 4+4+2 {
			return netip.AddrPort{}, nil, fmt.Errorf("short IPv4 SOCKS UDP reply")
		}
		ip = netip.AddrFrom4([4]byte(packet[4:8]))
		rest = packet[8:]
	case 4:
		if len(packet) < 4+16+2 {
			return netip.AddrPort{}, nil, fmt.Errorf("short IPv6 SOCKS UDP reply")
		}
		ip = netip.AddrFrom16([16]byte(packet[4:20]))
		rest = packet[20:]
	default:
		return netip.AddrPort{}, nil, fmt.Errorf("SOCKS UDP reply address type %d", packet[3])
	}
	port := binary.BigEndian.Uint16(rest)
	return netip.AddrPortFrom(ip.Unmap(), port), rest[2:], nil
}

// exchange sends payload to destination and checks that the reply comes back
// from destination with the same payload.
func (a *socksUDPAssociation) exchange(destination *net.UDPAddr, payload []byte) error {
	packet := appendSOCKSUDPAddress([]byte{0, 0, 0}, destination)
	packet = append(packet, payload...)
	if err := a.udp.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	if _, err := a.udp.WriteToUDP(packet, a.relay); err != nil {
		return fmt.Errorf("send to %s: %w", destination, err)
	}
	response := make([]byte, 65535)
	n, _, err := a.udp.ReadFromUDP(response)
	if err != nil {
		return fmt.Errorf("reply from %s: %w", destination, err)
	}
	source, reply, err := parseSOCKSUDPSource(response[:n])
	if err != nil {
		return err
	}
	want := destination.AddrPort()
	want = netip.AddrPortFrom(want.Addr().Unmap(), want.Port())
	if source != want {
		return fmt.Errorf("reply to %q came from %s, want %s", payload, source, want)
	}
	if !bytes.Equal(reply, payload) {
		return fmt.Errorf("reply from %s = %q, want %q", destination, reply, payload)
	}
	return nil
}

// testSOCKSUDPIPv6Targets sends UDP through one SOCKS association, so one
// Hysteria UDP session, to IPv6 targets: one target repeated, three in turn
// (within the server's per-session destination cache) and every target in
// turn (more than it holds). Each reply must come from its own target.
func testSOCKSUDPIPv6Targets(t *testing.T, socksPort int, targets []*net.UDPAddr) {
	t.Helper()
	if len(targets) <= 4 {
		t.Fatalf("%d IPv6 targets do not exceed the four cached destinations", len(targets))
	}
	association := openSOCKSUDPAssociation(t, socksPort)
	phases := []struct {
		name    string
		targets []*net.UDPAddr
		rounds  int
	}{
		{name: "repeated", targets: targets[:1], rounds: 3},
		{name: "alternating", targets: targets[:3], rounds: 3},
		{name: "evicting", targets: targets, rounds: 3},
	}
	for _, phase := range phases {
		for round := range phase.rounds {
			for index, target := range phase.targets {
				payload := fmt.Appendf(nil, "hysteria-ipv6-%s-%d-%d", phase.name, round, index)
				if err := association.exchange(target, payload); err != nil {
					t.Fatalf("%s phase: %v", phase.name, err)
				}
			}
		}
	}
}
