// Package mtproxy implements the Telegram MTProxy server protocol.
package mtproxy

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

const obfuscatedHeaderSize = 64

var (
	errNoSecrets         = errors.New("mtproxy: no client secrets configured")
	errInvalidObfuscated = errors.New("mtproxy: invalid obfuscated header")
)

// ObfuscatedState is the per-connection state established by the 64-byte
// MTProxy obfuscated transport header.
type ObfuscatedState struct {
	SecretIndex int
	Mode        FrameMode
	DCID        int16

	decrypt cipher.Stream
	encrypt cipher.Stream
}

// Decrypt decrypts client-to-proxy bytes in place. Calls must preserve stream
// order and must not overlap.
func (s *ObfuscatedState) Decrypt(payload []byte) {
	s.decrypt.XORKeyStream(payload, payload)
}

// Encrypt encrypts proxy-to-client bytes in place. Calls must preserve stream
// order and must not overlap.
func (s *ObfuscatedState) Encrypt(payload []byte) {
	s.encrypt.XORKeyStream(payload, payload)
}

// AcceptObfuscatedHeader authenticates a client header against the supplied
// raw 16-byte secrets and creates directional AES-CTR streams. The client read
// stream is advanced by the complete 64-byte header; the server write stream
// starts at position zero as required by the protocol.
func AcceptObfuscatedHeader(header [obfuscatedHeaderSize]byte, secrets [][16]byte) (*ObfuscatedState, error) {
	if len(secrets) == 0 {
		return nil, errNoSecrets
	}

	for secretIndex := range secrets {
		tail, readKey, readIV, err := probeObfuscatedHeader(header, secrets[secretIndex])
		if err != nil {
			return nil, err
		}
		mode, ok := frameModeFromTag(binary.LittleEndian.Uint32(tail[0:4]))
		if !ok {
			continue
		}

		readBlock, err := aes.NewCipher(readKey[:])
		if err != nil {
			return nil, err
		}
		readStream := cipher.NewCTR(readBlock, readIV[:])
		var advance [obfuscatedHeaderSize]byte
		readStream.XORKeyStream(advance[:], advance[:])

		writeKey, writeIV := deriveDirectionalMaterial(header, secrets[secretIndex], true)
		writeBlock, err := aes.NewCipher(writeKey[:])
		if err != nil {
			return nil, err
		}

		return &ObfuscatedState{
			SecretIndex: secretIndex,
			Mode:        mode,
			DCID:        int16(binary.LittleEndian.Uint16(tail[4:6])),
			decrypt:     readStream,
			encrypt:     cipher.NewCTR(writeBlock, writeIV[:]),
		}, nil
	}

	return nil, errInvalidObfuscated
}

// probeObfuscatedHeader decrypts only bytes 56..63. They occupy the upper half
// of the fourth CTR block, so failed secret candidates do not need to process
// the other 56 header bytes.
func probeObfuscatedHeader(header [obfuscatedHeaderSize]byte, secret [16]byte) ([8]byte, [32]byte, [16]byte, error) {
	readKey, readIV := deriveDirectionalMaterial(header, secret, false)
	block, err := aes.NewCipher(readKey[:])
	if err != nil {
		return [8]byte{}, [32]byte{}, [16]byte{}, err
	}

	counter := readIV
	addBigEndianCounter(&counter, 3)
	var keyStream [aes.BlockSize]byte
	block.Encrypt(keyStream[:], counter[:])

	var tail [8]byte
	for i := range tail {
		tail[i] = header[56+i] ^ keyStream[8+i]
	}
	return tail, readKey, readIV, nil
}

func deriveDirectionalMaterial(header [obfuscatedHeaderSize]byte, secret [16]byte, reverse bool) ([32]byte, [16]byte) {
	var seed [48]byte
	if reverse {
		for i := range seed {
			seed[i] = header[55-i]
		}
	} else {
		copy(seed[:], header[8:56])
	}

	var keyInput [48]byte
	copy(keyInput[:32], seed[:32])
	copy(keyInput[32:], secret[:])
	key := sha256.Sum256(keyInput[:])

	var iv [16]byte
	copy(iv[:], seed[32:])
	return key, iv
}

func addBigEndianCounter(counter *[16]byte, increment byte) {
	carry := uint16(increment)
	for i := len(counter) - 1; i >= 0 && carry != 0; i-- {
		sum := uint16(counter[i]) + carry
		counter[i] = byte(sum)
		carry = sum >> 8
	}
}
