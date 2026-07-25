package tls

import (
	"container/list"
	"context"
	"crypto/rand"
	"crypto/tls"
	"io"
	"math/big"
	"reflect"
	"slices"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/utils"
)

type Interface interface {
	net.Conn
	HandshakeContext(ctx context.Context) error
	VerifyHostname(host string) error
	HandshakeContextServerName(ctx context.Context) string
	NegotiatedProtocol() string
}

var (
	_ buf.Writer = (*Conn)(nil)
	_ Interface  = (*Conn)(nil)
)

type Conn struct {
	*tls.Conn
}

const tlsCloseTimeout = 250 * time.Millisecond
const tlsRecordSize = 16 * 1024

func (c *Conn) Close() error {
	timer := time.AfterFunc(tlsCloseTimeout, func() {
		c.Conn.NetConn().Close()
	})
	defer timer.Stop()
	return c.Conn.Close()
}

func (c *Conn) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)

	for len(mb) > 0 {
		if len(mb) == 1 {
			return writeAll(c, mb[0].Bytes())
		}

		record := buf.NewWithSize(tlsRecordSize)
		for len(mb) > 0 && record.Len() < tlsRecordSize {
			buffer := mb[0]
			copied, _ := record.Write(buffer.Bytes())
			buffer.Advance(int32(copied))
			if !buffer.IsEmpty() {
				break
			}
			buffer.Release()
			mb[0] = nil
			mb = mb[1:]
		}

		err := writeAll(c, record.Bytes())
		record.Release()
		if err != nil {
			return err
		}
	}
	return nil
}

func writeAll(writer io.Writer, payload []byte) error {
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

func (c *Conn) HandshakeContextServerName(ctx context.Context) string {
	if err := c.HandshakeContext(ctx); err != nil {
		return ""
	}
	return c.ConnectionState().ServerName
}

func (c *Conn) NegotiatedProtocol() string {
	state := c.ConnectionState()
	return state.NegotiatedProtocol
}

// Client initiates a TLS client handshake on the given connection.
func Client(c net.Conn, config *tls.Config) net.Conn {
	tlsConn := tls.Client(c, config)
	return &Conn{Conn: tlsConn}
}

// Server initiates a TLS server handshake on the given connection.
func Server(c net.Conn, config *tls.Config) net.Conn {
	tlsConn := tls.Server(c, config)
	return &Conn{Conn: tlsConn}
}

type UConn struct {
	*utls.UConn
}

var _ Interface = (*UConn)(nil)

const uTLSSessionCacheScopeCapacity = 256

type uTLSSessionCacheScope struct {
	source      uintptr
	fingerprint string
}

type uTLSSessionCacheEntry struct {
	scope uTLSSessionCacheScope
	cache utls.ClientSessionCache
}

var uTLSSessionCaches = struct {
	sync.Mutex
	entries map[uTLSSessionCacheScope]*list.Element
	lru     list.List
}{
	entries: make(map[uTLSSessionCacheScope]*list.Element),
}

type serializingUTLSSessionCache struct {
	sync.Mutex
	cache utls.ClientSessionCache
}

func newSerializingUTLSSessionCache() utls.ClientSessionCache {
	return &serializingUTLSSessionCache{
		cache: utls.NewLRUClientSessionCache(sessionCacheCapacity),
	}
}

func (c *serializingUTLSSessionCache) Get(sessionKey string) (*utls.ClientSessionState, bool) {
	c.Lock()
	defer c.Unlock()

	session, ok := c.cache.Get(sessionKey)
	if !ok {
		return nil, false
	}
	c.cache.Put(sessionKey, nil)
	cloned := cloneUTLSSession(session)
	return cloned, cloned != nil
}

func (c *serializingUTLSSessionCache) Put(sessionKey string, session *utls.ClientSessionState) {
	c.Lock()
	defer c.Unlock()

	if session == nil {
		c.cache.Put(sessionKey, nil)
		return
	}
	if cloned := cloneUTLSSession(session); cloned != nil {
		c.cache.Put(sessionKey, cloned)
	}
}

func cloneUTLSSession(session *utls.ClientSessionState) *utls.ClientSessionState {
	ticket, state, err := session.ResumptionState()
	if err != nil || state == nil {
		return nil
	}
	serialized, err := state.Bytes()
	if err != nil {
		return nil
	}
	clonedState, err := utls.ParseSessionState(serialized)
	if err != nil {
		return nil
	}
	cloned, err := utls.NewResumptionState(slices.Clone(ticket), clonedState)
	if err != nil {
		return nil
	}
	return cloned
}

func uTLSSessionCache(source uintptr, fingerprint utls.ClientHelloID) utls.ClientSessionCache {
	scope := uTLSSessionCacheScope{
		source:      source,
		fingerprint: fingerprint.Str(),
	}
	uTLSSessionCaches.Lock()
	defer uTLSSessionCaches.Unlock()

	if element := uTLSSessionCaches.entries[scope]; element != nil {
		uTLSSessionCaches.lru.MoveToFront(element)
		return element.Value.(*uTLSSessionCacheEntry).cache
	}
	entry := &uTLSSessionCacheEntry{
		scope: scope,
		cache: newSerializingUTLSSessionCache(),
	}
	element := uTLSSessionCaches.lru.PushFront(entry)
	uTLSSessionCaches.entries[scope] = element
	if uTLSSessionCaches.lru.Len() > uTLSSessionCacheScopeCapacity {
		oldest := uTLSSessionCaches.lru.Back()
		uTLSSessionCaches.lru.Remove(oldest)
		delete(uTLSSessionCaches.entries, oldest.Value.(*uTLSSessionCacheEntry).scope)
	}
	return entry.cache
}

func (c *UConn) Close() error {
	timer := time.AfterFunc(tlsCloseTimeout, func() {
		c.Conn.NetConn().Close()
	})
	defer timer.Stop()
	return c.Conn.Close()
}

func (c *UConn) HandshakeContextServerName(ctx context.Context) string {
	if err := c.HandshakeContext(ctx); err != nil {
		return ""
	}
	return c.ConnectionState().ServerName
}

// WebsocketHandshakeContext basically calls UConn.Handshake inside it but it will try
// to build outer ALPN to `http/1.1` or `h2 http/1.1` (if manually specified for camouflage)
func (c *UConn) WebsocketHandshakeContext(ctx context.Context) error {
	config := *utils.AccessField[*utls.Config](c, "config")
	ALPN := slices.Clone(config.NextProtos)
	// set other kinds of ALPN to http/1.1
	if !slices.Equal(ALPN, []string{"h2", "http/1.1"}) {
		ALPN = []string{"http/1.1"}
	}
	// Build the handshake state. This will apply every variable of the TLS of the
	// fingerprint in the UConn
	if err := c.BuildHandshakeState(); err != nil {
		return err
	}
	// Do not modify outer ALPN if ECH is used
	// Outer ALPN will be h2,http/1.1, and real http/1.1 in config will be hidden in ECH
	if config.EncryptedClientHelloConfigList != nil {
		config.NextProtos = []string{"http/1.1"}
		return c.HandshakeContext(ctx)
	}
	// Iterate over extensions and check for utls.ALPNExtension
	hasALPNExtension := false
	for _, extension := range c.Extensions {
		if alpn, ok := extension.(*utls.ALPNExtension); ok {
			hasALPNExtension = true
			alpn.AlpnProtocols = ALPN
			break
		}
	}
	if !hasALPNExtension { // Append extension if doesn't exists
		c.Extensions = append(c.Extensions, &utls.ALPNExtension{AlpnProtocols: ALPN})
	}
	// Rebuild the client hello and do the handshake
	if err := c.BuildHandshakeState(); err != nil {
		return err
	}
	return c.HandshakeContext(ctx)
}

func (c *UConn) NegotiatedProtocol() string {
	state := c.ConnectionState()
	return state.NegotiatedProtocol
}

func UClient(c net.Conn, config *tls.Config, fingerprint *utls.ClientHelloID) net.Conn {
	uTLSConfig, sessionCacheSource := copyConfig(config)
	utlsConn := newUClient(c, uTLSConfig, *fingerprint, sessionCacheSource)
	return &UConn{UConn: utlsConn}
}

func GeneraticUClient(c net.Conn, config *tls.Config) *utls.UConn {
	uTLSConfig, sessionCacheSource := copyConfig(config)
	return newUClient(c, uTLSConfig, utls.HelloChrome_Auto, sessionCacheSource)
}

func newUClient(c net.Conn, config *utls.Config, fingerprint utls.ClientHelloID, sessionCacheSource uintptr) *utls.UConn {
	if sessionCacheSource != 0 {
		config.ClientSessionCache = uTLSSessionCache(sessionCacheSource, fingerprint)
		if spec, ok := clientHelloSpecForResumption(fingerprint); ok {
			conn := utls.UClient(c, config, utls.HelloCustom)
			if err := conn.ApplyPreset(spec); err == nil {
				return conn
			}
		}
	}
	return utls.UClient(c, config, fingerprint)
}

func clientHelloSpecForResumption(fingerprint utls.ClientHelloID) (*utls.ClientHelloSpec, bool) {
	spec, err := utls.UTLSIdToSpec(fingerprint)
	if err != nil {
		return nil, false
	}

	// Some browser presets describe only a full handshake and omit the
	// extensions needed to obtain and later present a resumable session.
	// Keep PSK last as required by TLS 1.3; OmitEmptyPsk hides it until cached.
	hasPSKExchangeModes := false
	hasSessionTicket := false
	var pskExtension utls.PreSharedKeyExtension
	extensions := make([]utls.TLSExtension, 0, len(spec.Extensions)+3)
	for _, extension := range spec.Extensions {
		switch typedExtension := extension.(type) {
		case utls.PreSharedKeyExtension:
			pskExtension = typedExtension
		case *utls.PSKKeyExchangeModesExtension:
			hasPSKExchangeModes = true
			extensions = append(extensions, extension)
		case utls.ISessionTicketExtension:
			hasSessionTicket = true
			extensions = append(extensions, extension)
		default:
			extensions = append(extensions, extension)
		}
	}
	changed := false
	if !hasSessionTicket {
		extensions = append(extensions, &utls.SessionTicketExtension{})
		changed = true
	}
	if !hasPSKExchangeModes {
		extensions = append(extensions, &utls.PSKKeyExchangeModesExtension{
			Modes: []uint8{utls.PskModeDHE},
		})
		changed = true
	}
	if pskExtension == nil {
		pskExtension = &utls.UtlsPreSharedKeyExtension{}
		changed = true
	}
	extensions = append(extensions, pskExtension)
	spec.Extensions = extensions
	return &spec, changed
}

func copyConfig(c *tls.Config) (*utls.Config, uintptr) {
	config := &utls.Config{
		Rand:                           c.Rand,
		RootCAs:                        c.RootCAs,
		ServerName:                     c.ServerName,
		InsecureSkipVerify:             c.InsecureSkipVerify,
		VerifyPeerCertificate:          c.VerifyPeerCertificate,
		KeyLogWriter:                   c.KeyLogWriter,
		EncryptedClientHelloConfigList: c.EncryptedClientHelloConfigList,
		NextProtos:                     c.NextProtos,
		SessionTicketsDisabled:         c.SessionTicketsDisabled,
	}
	var sessionCacheSource uintptr
	if c.ClientSessionCache != nil && !c.SessionTicketsDisabled {
		config.OmitEmptyPsk = true
		cacheValue := reflect.ValueOf(c.ClientSessionCache)
		if cacheValue.Kind() == reflect.Pointer {
			sessionCacheSource = cacheValue.Pointer()
		}
	}
	return config, sessionCacheSource
}

func init() {
	bigInt, _ := rand.Int(rand.Reader, big.NewInt(int64(len(ModernFingerprints))))
	stopAt := int(bigInt.Int64())
	i := 0
	for _, v := range ModernFingerprints {
		if i == stopAt {
			PresetFingerprints["random"] = v
			break
		}
		i++
	}
	weights := utls.DefaultWeights
	weights.TLSVersMax_Set_VersionTLS13 = 1
	weights.FirstKeyShare_Set_CurveP256 = 0
	randomized := utls.HelloRandomizedALPN
	randomized.Seed, _ = utls.NewPRNGSeed()
	randomized.Weights = &weights
	randomizednoalpn := utls.HelloRandomizedNoALPN
	randomizednoalpn.Seed, _ = utls.NewPRNGSeed()
	randomizednoalpn.Weights = &weights
	PresetFingerprints["randomized"] = &randomized
	PresetFingerprints["randomizednoalpn"] = &randomizednoalpn
}

func GetFingerprint(name string) (fingerprint *utls.ClientHelloID) {
	if name == "" {
		return &utls.HelloChrome_Auto
	}
	if fingerprint = PresetFingerprints[name]; fingerprint != nil {
		return
	}
	if fingerprint = ModernFingerprints[name]; fingerprint != nil {
		return
	}
	if fingerprint = OtherFingerprints[name]; fingerprint != nil {
		return
	}
	return
}

var PresetFingerprints = map[string]*utls.ClientHelloID{
	// Recommended preset options in GUI clients
	"chrome":           &utls.HelloChrome_Auto,
	"firefox":          &utls.HelloFirefox_Auto,
	"safari":           &utls.HelloSafari_Auto,
	"ios":              &utls.HelloIOS_Auto,
	"android":          &utls.HelloAndroid_11_OkHttp,
	"edge":             &utls.HelloEdge_Auto,
	"360":              &utls.Hello360_Auto,
	"qq":               &utls.HelloQQ_Auto,
	"random":           nil,
	"randomized":       nil,
	"randomizednoalpn": nil,
	"unsafe":           nil,
}

var ModernFingerprints = map[string]*utls.ClientHelloID{
	// One of these will be chosen as `random` at startup
	"hellofirefox_120": &utls.HelloFirefox_120,
	"hellofirefox_148": &utls.HelloFirefox_148,
	"hellochrome_120":  &utls.HelloChrome_120,
	"hellochrome_131":  &utls.HelloChrome_131,
	"hellochrome_133":  &utls.HelloChrome_133,
	"helloios_13":      &utls.HelloIOS_13,
	"helloios_14":      &utls.HelloIOS_14,
	"helloedge_106":    &utls.HelloEdge_106,
	"hellosafari_26_3": &utls.HelloSafari_26_3,
	"hello360_11_0":    &utls.Hello360_11_0,
	"helloqq_11_1":     &utls.HelloQQ_11_1,
}

var OtherFingerprints = map[string]*utls.ClientHelloID{
	// Golang, randomized, auto, and fingerprints that are too old
	"hellogolang":             &utls.HelloGolang,
	"hellorandomized":         &utls.HelloRandomized,
	"hellorandomizedalpn":     &utls.HelloRandomizedALPN,
	"hellorandomizednoalpn":   &utls.HelloRandomizedNoALPN,
	"hellofirefox_auto":       &utls.HelloFirefox_Auto,
	"hellofirefox_55":         &utls.HelloFirefox_55,
	"hellofirefox_56":         &utls.HelloFirefox_56,
	"hellofirefox_63":         &utls.HelloFirefox_63,
	"hellofirefox_65":         &utls.HelloFirefox_65,
	"hellofirefox_99":         &utls.HelloFirefox_99,
	"hellofirefox_102":        &utls.HelloFirefox_102,
	"hellofirefox_105":        &utls.HelloFirefox_105,
	"hellochrome_auto":        &utls.HelloChrome_Auto,
	"hellochrome_58":          &utls.HelloChrome_58,
	"hellochrome_62":          &utls.HelloChrome_62,
	"hellochrome_70":          &utls.HelloChrome_70,
	"hellochrome_72":          &utls.HelloChrome_72,
	"hellochrome_83":          &utls.HelloChrome_83,
	"hellochrome_87":          &utls.HelloChrome_87,
	"hellochrome_96":          &utls.HelloChrome_96,
	"hellochrome_100":         &utls.HelloChrome_100,
	"hellochrome_102":         &utls.HelloChrome_102,
	"hellochrome_106_shuffle": &utls.HelloChrome_106_Shuffle,
	"helloios_auto":           &utls.HelloIOS_Auto,
	"helloios_11_1":           &utls.HelloIOS_11_1,
	"helloios_12_1":           &utls.HelloIOS_12_1,
	"helloandroid_11_okhttp":  &utls.HelloAndroid_11_OkHttp,
	"helloedge_85":            &utls.HelloEdge_85,
	"helloedge_auto":          &utls.HelloEdge_Auto,
	"hellosafari_16_0":        &utls.HelloSafari_16_0,
	"hellosafari_auto":        &utls.HelloSafari_Auto,
	"hello360_auto":           &utls.Hello360_Auto,
	"hello360_7_5":            &utls.Hello360_7_5,
	"helloqq_auto":            &utls.HelloQQ_Auto,

	// Chrome betas
	"hellochrome_100_psk":              &utls.HelloChrome_100_PSK,
	"hellochrome_112_psk_shuf":         &utls.HelloChrome_112_PSK_Shuf,
	"hellochrome_114_padding_psk_shuf": &utls.HelloChrome_114_Padding_PSK_Shuf,
	"hellochrome_115_pq":               &utls.HelloChrome_115_PQ,
	"hellochrome_115_pq_psk":           &utls.HelloChrome_115_PQ_PSK,
	"hellochrome_120_pq":               &utls.HelloChrome_120_PQ,
}
