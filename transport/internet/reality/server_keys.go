package reality

import (
	"crypto/ecdh"
	"crypto/mldsa"

	"github.com/xtls/xray-core/common/errors"
)

// CheckServerKeys reports the key material GetREALITYConfig would panic on.
// JSON configs check both keys when they are built; a protobuf or
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
	return nil
}
