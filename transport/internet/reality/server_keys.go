package reality

import (
	"crypto/ecdh"
	"crypto/mldsa"

	"github.com/xtls/xray-core/common/errors"
)

// CheckServerKeys reports the keys and short IDs GetREALITYConfig would panic
// on. JSON configs check them when they are built; a protobuf or
// HandlerService config reaches the listener without that check.
func (c *Config) CheckServerKeys() error {
	if _, err := ecdh.X25519().NewPrivateKey(c.PrivateKey); err != nil {
		return errors.New("invalid REALITY private key").Base(err)
	}
	if c.Mldsa65Seed != nil {
		if _, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), c.Mldsa65Seed); err != nil {
			return errors.New("invalid REALITY ML-DSA-65 seed").Base(err)
		}
	}
	for _, shortId := range c.ShortIds {
		// GetREALITYConfig reads the first 8 bytes of each.
		if len(shortId) < 8 {
			return errors.New("invalid REALITY short ID: ", len(shortId), " bytes, want 8")
		}
	}
	return nil
}
