package mtproxy

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

const (
	fakeTLSClientRandomOffset = 11
	fakeTLSMaxClientHello     = 4096
	fakeTLSMaxRecordPayload   = 16384
)

var (
	ErrInvalidFakeTLS = errors.New("mtproxy: invalid fake TLS handshake")
	ErrFakeTLSTime    = errors.New("mtproxy: fake TLS timestamp outside allowed window")
)

type parsedClientHello struct {
	serverName  string
	sessionID   []byte
	cipherSuite uint16
	random      [32]byte
}

// FakeTLSAuth is the authenticated state needed to synthesize the server
// response and later fence session registration against secret revocation.
type FakeTLSAuth struct {
	Fingerprint  SecretFingerprint
	ServerName   string
	CipherSuite  uint16
	ClientRandom [32]byte

	secret    [16]byte
	runtime   *secretRuntime
	sessionID []byte
}

type fakeTLSReplayCache interface {
	CheckAndAdd([16]byte, time.Time) error
}

type FakeTLSAuthenticator struct {
	secrets *SecretRegistry
	allowed map[string]struct{}
	replay  fakeTLSReplayCache
	now     func() time.Time
}

func NewFakeTLSAuthenticator(secrets *SecretRegistry, allowedDomains []string, replay fakeTLSReplayCache, now func() time.Time) *FakeTLSAuthenticator {
	allowed := make(map[string]struct{}, len(allowedDomains))
	for _, domain := range allowedDomains {
		allowed[strings.ToLower(domain)] = struct{}{}
	}
	if now == nil {
		now = time.Now
	}
	return &FakeTLSAuthenticator{secrets: secrets, allowed: allowed, replay: replay, now: now}
}

func (a *FakeTLSAuthenticator) Authenticate(clientHello []byte) (*FakeTLSAuth, error) {
	if a == nil || a.secrets == nil || a.replay == nil {
		return nil, ErrInvalidFakeTLS
	}
	parsed, err := parseFakeTLSClientHello(clientHello)
	if err != nil {
		return nil, err
	}
	if _, allowed := a.allowed[parsed.serverName]; !allowed {
		return nil, fmt.Errorf("%w: unconfigured server name", ErrInvalidFakeTLS)
	}

	zeroed := append([]byte(nil), clientHello...)
	clear(zeroed[fakeTLSClientRandomOffset : fakeTLSClientRandomOffset+32])
	now := a.now()

	for _, candidate := range a.secrets.candidates() {
		mac := hmac.New(sha256.New, candidate.secret[:])
		_, _ = mac.Write(zeroed)
		expected := mac.Sum(nil)
		if subtle.ConstantTimeCompare(expected[:28], parsed.random[:28]) != 1 {
			continue
		}

		timestamp := binary.LittleEndian.Uint32(expected[28:32]) ^ binary.LittleEndian.Uint32(parsed.random[28:32])
		timestamp64 := int64(timestamp)
		if timestamp64 > now.Unix()+3 || timestamp64 < now.Unix()-10*60 {
			return nil, ErrFakeTLSTime
		}

		var replayKey [16]byte
		copy(replayKey[:], parsed.random[:16])
		if err := a.replay.CheckAndAdd(replayKey, now); err != nil {
			return nil, err
		}

		return &FakeTLSAuth{
			Fingerprint:  candidate.fingerprint,
			ServerName:   parsed.serverName,
			CipherSuite:  parsed.cipherSuite,
			ClientRandom: parsed.random,
			secret:       candidate.secret,
			runtime:      candidate.runtime,
			sessionID:    append([]byte(nil), parsed.sessionID...),
		}, nil
	}
	return nil, fmt.Errorf("%w: authentication failed", ErrInvalidFakeTLS)
}

// AcceptInnerHeader authenticates the inner obfuscated transport with the same
// secret as the Fake TLS ClientHello and requires padded-intermediate mode.
func (a *FakeTLSAuth) AcceptInnerHeader(header [obfuscatedHeaderSize]byte) (*ObfuscatedState, error) {
	if a == nil || a.runtime == nil {
		return nil, ErrInvalidFakeTLS
	}
	state, err := AcceptObfuscatedHeader(header, [][16]byte{a.secret})
	if err != nil {
		return nil, err
	}
	if state.Mode != FrameModePaddedIntermediate {
		return nil, fmt.Errorf("%w: inner transport must be padded intermediate", ErrInvalidFakeTLS)
	}
	return state, nil
}

func FakeTLSFallbackServerName(clientHello []byte, allowedDomains []string) (string, bool) {
	parsed, err := parseFakeTLSClientHello(clientHello)
	if err != nil {
		return "", false
	}
	for _, domain := range allowedDomains {
		if strings.EqualFold(domain, parsed.serverName) {
			return parsed.serverName, true
		}
	}
	return "", false
}

func parseFakeTLSClientHello(record []byte) (parsedClientHello, error) {
	var result parsedClientHello
	if len(record) < fakeTLSClientRandomOffset+32 || len(record) > fakeTLSMaxClientHello {
		return result, fmt.Errorf("%w: ClientHello size", ErrInvalidFakeTLS)
	}
	if record[0] != 0x16 || record[1] != 0x03 || record[2] < 0x01 || record[2] > 0x03 {
		return result, fmt.Errorf("%w: TLS record header", ErrInvalidFakeTLS)
	}
	recordLength := int(binary.BigEndian.Uint16(record[3:5]))
	if recordLength != len(record)-5 || record[5] != 0x01 {
		return result, fmt.Errorf("%w: ClientHello record length", ErrInvalidFakeTLS)
	}
	handshakeLength := int(record[6])<<16 | int(record[7])<<8 | int(record[8])
	if handshakeLength != len(record)-9 || record[9] != 0x03 || record[10] != 0x03 {
		return result, fmt.Errorf("%w: ClientHello handshake length", ErrInvalidFakeTLS)
	}
	copy(result.random[:], record[fakeTLSClientRandomOffset:fakeTLSClientRandomOffset+32])

	position := fakeTLSClientRandomOffset + 32
	sessionLength, ok := readUint8Length(record, &position)
	if !ok || sessionLength > 32 || position+sessionLength > len(record) {
		return result, fmt.Errorf("%w: session ID", ErrInvalidFakeTLS)
	}
	result.sessionID = record[position : position+sessionLength]
	position += sessionLength

	cipherLength, ok := readUint16Length(record, &position)
	if !ok || cipherLength < 2 || cipherLength&1 != 0 || position+cipherLength > len(record) {
		return result, fmt.Errorf("%w: cipher suites", ErrInvalidFakeTLS)
	}
	for end := position + cipherLength; position < end; position += 2 {
		suite := binary.BigEndian.Uint16(record[position : position+2])
		if result.cipherSuite == 0 && suite >= 0x1301 && suite <= 0x1303 {
			result.cipherSuite = suite
		}
	}
	if result.cipherSuite == 0 {
		return result, fmt.Errorf("%w: no TLS 1.3 cipher suite", ErrInvalidFakeTLS)
	}

	compressionLength, ok := readUint8Length(record, &position)
	if !ok || compressionLength == 0 || position+compressionLength > len(record) {
		return result, fmt.Errorf("%w: compression methods", ErrInvalidFakeTLS)
	}
	position += compressionLength

	extensionsLength, ok := readUint16Length(record, &position)
	if !ok || position+extensionsLength != len(record) {
		return result, fmt.Errorf("%w: extensions length", ErrInvalidFakeTLS)
	}
	extensionsEnd := position + extensionsLength
	for position < extensionsEnd {
		if position+4 > extensionsEnd {
			return result, fmt.Errorf("%w: truncated extension", ErrInvalidFakeTLS)
		}
		extensionType := binary.BigEndian.Uint16(record[position : position+2])
		extensionLength := int(binary.BigEndian.Uint16(record[position+2 : position+4]))
		position += 4
		if position+extensionLength > extensionsEnd {
			return result, fmt.Errorf("%w: extension length", ErrInvalidFakeTLS)
		}
		if extensionType == 0 {
			serverName, err := parseServerNameExtension(record[position : position+extensionLength])
			if err != nil {
				return result, err
			}
			result.serverName = serverName
		}
		position += extensionLength
	}
	if result.serverName == "" {
		return result, fmt.Errorf("%w: missing SNI", ErrInvalidFakeTLS)
	}
	return result, nil
}

func parseServerNameExtension(extension []byte) (string, error) {
	if len(extension) < 5 || int(binary.BigEndian.Uint16(extension[:2])) != len(extension)-2 || extension[2] != 0 {
		return "", fmt.Errorf("%w: SNI list", ErrInvalidFakeTLS)
	}
	nameLength := int(binary.BigEndian.Uint16(extension[3:5]))
	if nameLength == 0 || nameLength > 253 || nameLength != len(extension)-5 {
		return "", fmt.Errorf("%w: SNI length", ErrInvalidFakeTLS)
	}
	name := strings.ToLower(string(extension[5:]))
	for _, character := range name {
		if !(character == '.' || character == '-' || character >= '0' && character <= '9' || character >= 'a' && character <= 'z') {
			return "", fmt.Errorf("%w: SNI character", ErrInvalidFakeTLS)
		}
	}
	return name, nil
}

func readUint8Length(data []byte, position *int) (int, bool) {
	if *position >= len(data) {
		return 0, false
	}
	length := int(data[*position])
	*position++
	return length, true
}

func readUint16Length(data []byte, position *int) (int, bool) {
	if *position+2 > len(data) {
		return 0, false
	}
	length := int(binary.BigEndian.Uint16(data[*position : *position+2]))
	*position += 2
	return length, true
}

func BuildFakeTLSServerHello(auth *FakeTLSAuth, random io.Reader, encryptedPayloadLength int) ([]byte, error) {
	if auth == nil || random == nil || len(auth.sessionID) > 32 || auth.CipherSuite < 0x1301 || auth.CipherSuite > 0x1303 {
		return nil, ErrInvalidFakeTLS
	}
	if encryptedPayloadLength <= 0 || encryptedPayloadLength > fakeTLSMaxRecordPayload {
		return nil, fmt.Errorf("%w: encrypted response length", ErrInvalidFakeTLS)
	}

	privateKey, err := ecdh.X25519().GenerateKey(random)
	if err != nil {
		return nil, err
	}
	publicKey := privateKey.PublicKey().Bytes()

	extensions := make([]byte, 0, 46)
	extensions = append(extensions, 0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20)
	extensions = append(extensions, publicKey...)
	extensions = append(extensions, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04)

	body := make([]byte, 0, 80+len(extensions))
	body = append(body, 0x03, 0x03)
	body = append(body, make([]byte, 32)...)
	body = append(body, byte(len(auth.sessionID)))
	body = append(body, auth.sessionID...)
	body = append(body, byte(auth.CipherSuite>>8), byte(auth.CipherSuite), 0)
	body = append(body, byte(len(extensions)>>8), byte(len(extensions)))
	body = append(body, extensions...)

	handshake := []byte{0x02, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	handshake = append(handshake, body...)
	response := []byte{0x16, 0x03, 0x03, byte(len(handshake) >> 8), byte(len(handshake))}
	response = append(response, handshake...)
	response = append(response, 0x14, 0x03, 0x03, 0x00, 0x01, 0x01)
	response = append(response, 0x17, 0x03, 0x03, byte(encryptedPayloadLength>>8), byte(encryptedPayloadLength))
	payloadStart := len(response)
	response = append(response, make([]byte, encryptedPayloadLength)...)
	if _, err := io.ReadFull(random, response[payloadStart:]); err != nil {
		return nil, err
	}

	if len(response) < fakeTLSClientRandomOffset+32 {
		return nil, ErrInvalidFakeTLS
	}
	mac := hmac.New(sha256.New, auth.secret[:])
	_, _ = mac.Write(auth.ClientRandom[:])
	_, _ = mac.Write(response)
	copy(response[fakeTLSClientRandomOffset:fakeTLSClientRandomOffset+32], mac.Sum(nil))
	return response, nil
}

func ConsumeFakeTLSChangeCipherSpec(reader io.Reader) error {
	var record [6]byte
	if _, err := io.ReadFull(reader, record[:]); err != nil {
		return err
	}
	expected := [6]byte{0x14, 0x03, 0x03, 0, 1, 1}
	if record != expected {
		return fmt.Errorf("%w: ChangeCipherSpec", ErrInvalidFakeTLS)
	}
	return nil
}

type FakeTLSRecordReader struct {
	reader    io.Reader
	remaining int
	maxRecord int
}

func NewFakeTLSRecordReader(reader io.Reader, maxRecord int) *FakeTLSRecordReader {
	return &FakeTLSRecordReader{reader: reader, maxRecord: maxRecord}
}

func (r *FakeTLSRecordReader) Read(payload []byte) (int, error) {
	if len(payload) == 0 {
		return 0, nil
	}
	if r.reader == nil || r.maxRecord <= 0 || r.maxRecord > fakeTLSMaxRecordPayload {
		return 0, ErrInvalidFakeTLS
	}
	if r.remaining == 0 {
		var header [5]byte
		if _, err := io.ReadFull(r.reader, header[:]); err != nil {
			return 0, err
		}
		if header[0] != 0x17 || header[1] != 0x03 || header[2] != 0x03 {
			return 0, fmt.Errorf("%w: application record header", ErrInvalidFakeTLS)
		}
		r.remaining = int(binary.BigEndian.Uint16(header[3:5]))
		if r.remaining <= 0 || r.remaining > r.maxRecord {
			return 0, fmt.Errorf("%w: application record length", ErrInvalidFakeTLS)
		}
	}

	count := len(payload)
	if count > r.remaining {
		count = r.remaining
	}
	read, err := io.ReadFull(r.reader, payload[:count])
	r.remaining -= read
	return read, err
}

func WriteFakeTLSApplicationData(writer io.Writer, payload []byte, maxRecord int) error {
	if writer == nil || maxRecord <= 0 || maxRecord > fakeTLSMaxRecordPayload {
		return ErrInvalidFakeTLS
	}
	for len(payload) > 0 {
		count := len(payload)
		if count > maxRecord {
			count = maxRecord
		}
		header := [5]byte{0x17, 0x03, 0x03, byte(count >> 8), byte(count)}
		if err := writeFull(writer, header[:]); err != nil {
			return err
		}
		if err := writeFull(writer, payload[:count]); err != nil {
			return err
		}
		payload = payload[count:]
	}
	return nil
}

func writeFull(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		written, err := writer.Write(payload)
		if written > 0 {
			payload = payload[written:]
		}
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
