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

// CheckDatagramIntegrity refuses a SpliceMask below a transport that does not
// authenticate whole datagrams. QUIC transports (hysteria, splithttp, masque)
// reject a spliced packet; mKCP has no integrity check of its own and needs an
// IntegrityMask outside the SpliceMask. masks is in finalmask.udp order,
// outermost first; protocol is the transport protocol name.
func CheckDatagramIntegrity(protocol string, masks []UDPMask) error {
	integrity := false
	for _, mask := range masks {
		if _, ok := mask.(IntegrityMask); ok {
			integrity = true
		}
		if _, ok := mask.(SpliceMask); !ok {
			continue
		}
		switch {
		case protocol == "hysteria" || protocol == "splithttp" || protocol == "masque":
		case protocol == "mkcp" && integrity:
		default:
			return errors.New(`the "salamander" UDP mask with packetSize (Gecko) can splice two packets into one after a lost fragment, so it needs a transport that authenticates whole datagrams: use it with hysteria, xhttp or masque, list an "mkcp-legacy" mask without a header before it under kcp, or drop packetSize`)
		}
	}
	return nil
}
