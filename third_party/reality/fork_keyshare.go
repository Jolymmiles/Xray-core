// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package reality

import "slices"

// classicX25519KeyShare returns the X25519 key share of a Client Hello that
// does not offer X25519MLKEM768 at all: a browser fingerprint from before
// hybrid key exchange, or a client that strips the hybrid group. A hello that
// offers the hybrid group must still authenticate through its key share, as
// upstream requires. It returns nil unless the hello carries exactly one
// well-formed X25519 key share.
//
// Xray-core fork change: upstream rejects every hello without an
// X25519MLKEM768 key share.
func classicX25519KeyShare(hello *clientHelloMsg) []byte {
	if slices.Contains(hello.supportedCurves, X25519MLKEM768) {
		return nil
	}
	var share []byte
	for _, keyShare := range hello.keyShares {
		switch keyShare.group {
		case X25519MLKEM768:
			return nil
		case X25519:
			if share != nil || len(keyShare.data) != 32 {
				return nil
			}
			share = keyShare.data
		}
	}
	return share
}
