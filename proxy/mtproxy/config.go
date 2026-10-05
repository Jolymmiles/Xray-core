package mtproxy

import (
	"crypto/subtle"
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/xtls/xray-core/common/protocol"
)

type MemoryAccount struct {
	Secret [16]byte
}

func (a *MemoryAccount) Equals(other protocol.Account) bool {
	candidate, ok := other.(*MemoryAccount)
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare(a.Secret[:], candidate.Secret[:]) == 1
}

func (a *MemoryAccount) ToProto() proto.Message {
	return &Account{Secret: append([]byte(nil), a.Secret[:]...)}
}

func (a *Account) AsAccount() (protocol.Account, error) {
	if len(a.Secret) != 16 {
		return nil, fmt.Errorf("mtproxy: client secret must be exactly 16 bytes")
	}
	memory := new(MemoryAccount)
	copy(memory.Secret[:], a.Secret)
	return memory, nil
}

// ValidateFakeTLSDomain applies the same name policy to configuration and SNI.
func ValidateFakeTLSDomain(name string) error {
	if len(name) == 0 || len(name) > 253 {
		return fmt.Errorf("mtproxy: invalid Fake TLS domain length")
	}
	for _, character := range name {
		if !(character == '.' || character == '-' || character >= '0' && character <= '9' || character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z') {
			return fmt.Errorf("mtproxy: invalid Fake TLS domain character")
		}
	}
	return nil
}
