package finalmask

import (
	"github.com/xtls/xray-core/common/errors"
)

// IntegrityMask is a UDP mask that rejects a datagram whose bytes changed,
// such as the mKCP checksum and AES-128-GCM masks.
type IntegrityMask interface {
	DatagramIntegrity()
}

// SpliceMask is a UDP mask that can deliver one datagram spliced from two,
// like Gecko, whose reassembly cannot tell two messages apart when one lost a
// chunk and the rest stay consistent. It needs whole-datagram integrity above
// it.
type SpliceMask interface {
	MaySpliceDatagrams()
}

var (
	errSpliceWithoutIntegrity = errors.New(`the "salamander" UDP mask with packetSize (Gecko) can splice two packets into one after a lost fragment, so it needs whole-datagram integrity above it: use it under hysteria, xhttp or masque, list an "mkcp-legacy" mask without a header before it, or drop packetSize`)
	errRawUDPSplice           = errors.New(`the "salamander" UDP mask with packetSize (Gecko) can splice two packets into one after a lost fragment, and this UDP path (freedom and other outbounds' UDP, UDP inbounds, WireGuard) has no QUIC above it whatever the stream network is: list an "mkcp-legacy" mask without a header before it, or drop packetSize`)
)

// spliceUnchecked reports whether a SpliceMask has no IntegrityMask outside
// it. masks is in finalmask.udp order, outermost first.
func spliceUnchecked(masks []UDPMask) bool {
	integrity := false
	for _, mask := range masks {
		if _, ok := mask.(IntegrityMask); ok {
			integrity = true
		}
		if _, ok := mask.(SpliceMask); ok && !integrity {
			return true
		}
	}
	return false
}

// CheckDatagramIntegrity refuses a SpliceMask that nothing above checks. The
// QUIC transports (hysteria, splithttp, masque) authenticate every datagram;
// any other stream needs an IntegrityMask outside the SpliceMask. masks is in
// finalmask.udp order, outermost first; protocol is the transport protocol
// name. Paths that use the masks without the transport, such as the UDP
// dialer, check FinalMask.CheckRawUDP as well.
func CheckDatagramIntegrity(protocol string, masks []UDPMask) error {
	switch protocol {
	case "hysteria", "splithttp", "masque":
		return nil
	}
	if spliceUnchecked(masks) {
		return errSpliceWithoutIntegrity
	}
	return nil
}

// CheckRawUDP refuses a SpliceMask without an IntegrityMask outside it on a
// path that carries UDP without QUIC above the masks. The UDP dialer, the UDP
// hub and WireGuard use the stream's masks whatever its network is, so the
// QUIC exemption of CheckDatagramIntegrity does not hold for them.
func (fm *FinalMask) CheckRawUDP() error {
	return fm.rawUDPErr
}
