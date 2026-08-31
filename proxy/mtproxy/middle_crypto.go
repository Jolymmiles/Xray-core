package mtproxy

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"net/netip"
)

const (
	minMiddleSecretLength = 32
	maxMiddleSecretLength = 256
)

const (
	rpcNonceOperation uint32 = 0x7acb87aa
	middleCryptoAES   uint32 = 1
)

type MiddleNonce struct {
	KeySelector  uint32
	CryptoSchema uint32
	Timestamp    uint32
	Nonce        [16]byte
}

func NewMiddleClientNonce(secret []byte, timestamp uint32, nonce [16]byte) (MiddleNonce, error) {
	if len(secret) < minMiddleSecretLength || len(secret) > maxMiddleSecretLength {
		return MiddleNonce{}, fmt.Errorf("mtproxy: invalid Middle-End secret length %d", len(secret))
	}
	keySelector := binary.LittleEndian.Uint32(secret[:4])
	if keySelector == 0 {
		return MiddleNonce{}, fmt.Errorf("mtproxy: zero Middle-End key selector")
	}
	return MiddleNonce{KeySelector: keySelector, CryptoSchema: middleCryptoAES, Timestamp: timestamp, Nonce: nonce}, nil
}

func EncodeMiddleNonce(packet MiddleNonce) []byte {
	encoded := make([]byte, 0, 32)
	encoded = appendUint32(encoded, rpcNonceOperation)
	encoded = appendUint32(encoded, packet.KeySelector)
	encoded = appendUint32(encoded, packet.CryptoSchema)
	encoded = appendUint32(encoded, packet.Timestamp)
	return append(encoded, packet.Nonce[:]...)
}

func DecodeMiddleNonce(encoded []byte) (MiddleNonce, error) {
	var packet MiddleNonce
	if len(encoded) != 32 || binary.LittleEndian.Uint32(encoded[:4]) != rpcNonceOperation {
		return packet, fmt.Errorf("mtproxy: invalid Middle-End nonce packet")
	}
	packet.KeySelector = binary.LittleEndian.Uint32(encoded[4:8])
	packet.CryptoSchema = binary.LittleEndian.Uint32(encoded[8:12])
	packet.Timestamp = binary.LittleEndian.Uint32(encoded[12:16])
	copy(packet.Nonce[:], encoded[16:32])
	if packet.KeySelector == 0 || packet.CryptoSchema != middleCryptoAES {
		return MiddleNonce{}, fmt.Errorf("mtproxy: unsupported Middle-End nonce parameters")
	}
	return packet, nil
}

func ValidateMiddleServerNonce(packet MiddleNonce, secret []byte, now uint32) error {
	expected, err := NewMiddleClientNonce(secret, packet.Timestamp, packet.Nonce)
	if err != nil {
		return err
	}
	if packet.KeySelector != expected.KeySelector || packet.CryptoSchema != middleCryptoAES {
		return fmt.Errorf("mtproxy: Middle-End nonce key mismatch")
	}
	difference := int64(packet.Timestamp) - int64(now)
	if difference < -30 || difference > 30 {
		return fmt.Errorf("mtproxy: Middle-End nonce timestamp outside 30-second window")
	}
	return nil
}

type MiddleEndpoints struct {
	Server netip.AddrPort
	Client netip.AddrPort
}

type MiddleKeyData struct {
	ReadKey  [32]byte
	ReadIV   [16]byte
	WriteKey [32]byte
	WriteIV  [16]byte
}

// DeriveMiddleKeyData implements the legacy authenticated Middle-End key
// schedule. Endpoint ports and IPv4 numeric addresses are serialized in host
// little-endian form to preserve the established wire contract.
func DeriveMiddleKeyData(amClient bool, secret []byte, serverNonce, clientNonce [16]byte, clientTimestamp uint32, endpoints MiddleEndpoints) (MiddleKeyData, error) {
	var result MiddleKeyData
	if len(secret) < minMiddleSecretLength || len(secret) > maxMiddleSecretLength {
		return result, fmt.Errorf("mtproxy: invalid Middle-End secret length %d", len(secret))
	}
	serverAddress, clientAddress := endpoints.Server.Addr(), endpoints.Client.Addr()
	if !serverAddress.IsValid() || !clientAddress.IsValid() || endpoints.Server.Port() == 0 || endpoints.Client.Port() == 0 {
		return result, fmt.Errorf("mtproxy: invalid Middle-End endpoints")
	}
	if serverAddress.Is4() != clientAddress.Is4() {
		return result, fmt.Errorf("mtproxy: mixed Middle-End address families")
	}

	material := make([]byte, 0, 118+len(secret))
	material = append(material, serverNonce[:]...)
	material = append(material, clientNonce[:]...)
	material = appendUint32(material, clientTimestamp)
	if serverAddress.Is4() {
		serverIPv4 := serverAddress.As4()
		material = appendUint32(material, binary.BigEndian.Uint32(serverIPv4[:]))
	} else {
		material = appendUint32(material, 0)
	}
	material = appendUint16(material, endpoints.Client.Port())
	if amClient {
		material = append(material, "CLIENT"...)
	} else {
		material = append(material, "SERVER"...)
	}
	if clientAddress.Is4() {
		clientIPv4 := clientAddress.As4()
		material = appendUint32(material, binary.BigEndian.Uint32(clientIPv4[:]))
	} else {
		material = appendUint32(material, 0)
	}
	material = appendUint16(material, endpoints.Server.Port())
	material = append(material, secret...)
	material = append(material, serverNonce[:]...)
	if !serverAddress.Is4() {
		clientIPv6 := clientAddress.As16()
		serverIPv6 := serverAddress.As16()
		material = append(material, clientIPv6[:]...)
		material = append(material, serverIPv6[:]...)
	}
	material = append(material, clientNonce[:]...)

	result.WriteKey, result.WriteIV = deriveMiddleDirection(material)
	if amClient {
		copy(material[42:48], "SERVER")
	} else {
		copy(material[42:48], "CLIENT")
	}
	result.ReadKey, result.ReadIV = deriveMiddleDirection(material)
	clear(material)
	return result, nil
}

func deriveMiddleDirection(material []byte) ([32]byte, [16]byte) {
	md5Key := md5.Sum(material[1:])
	sha1Key := sha1.Sum(material)
	var key [32]byte
	copy(key[:12], md5Key[:12])
	copy(key[12:], sha1Key[:])
	iv := md5.Sum(material[2:])
	return key, iv
}

func appendUint16(destination []byte, value uint16) []byte {
	var encoded [2]byte
	binary.LittleEndian.PutUint16(encoded[:], value)
	return append(destination, encoded[:]...)
}

type MiddleCBC struct {
	encrypt cipher.BlockMode
	decrypt cipher.BlockMode
}

func NewMiddleCBC(keys MiddleKeyData) (*MiddleCBC, error) {
	writeBlock, err := aes.NewCipher(keys.WriteKey[:])
	if err != nil {
		return nil, err
	}
	readBlock, err := aes.NewCipher(keys.ReadKey[:])
	if err != nil {
		return nil, err
	}
	return &MiddleCBC{
		encrypt: cipher.NewCBCEncrypter(writeBlock, keys.WriteIV[:]),
		decrypt: cipher.NewCBCDecrypter(readBlock, keys.ReadIV[:]),
	}, nil
}

// Encrypt and Decrypt preserve CBC state across calls. Calls in one direction
// must be serialized and each input must contain complete AES blocks.
func (c *MiddleCBC) Encrypt(destination, source []byte) error {
	if c == nil || len(source) == 0 || len(source)%aes.BlockSize != 0 || len(destination) < len(source) {
		return fmt.Errorf("mtproxy: invalid Middle-End CBC plaintext length %d", len(source))
	}
	c.encrypt.CryptBlocks(destination[:len(source)], source)
	return nil
}

func (c *MiddleCBC) Decrypt(destination, source []byte) error {
	if c == nil || len(source) == 0 || len(source)%aes.BlockSize != 0 || len(destination) < len(source) {
		return fmt.Errorf("mtproxy: invalid Middle-End CBC ciphertext length %d", len(source))
	}
	c.decrypt.CryptBlocks(destination[:len(source)], source)
	return nil
}
