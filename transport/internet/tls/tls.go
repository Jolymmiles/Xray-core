package tls

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"io"
	"math/big"
	"sync/atomic"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
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
	suppressCloseNotify atomic.Bool
}

const (
	tlsCloseTimeout = 250 * time.Millisecond
	tlsRecordSize   = 16 * 1024
)

func (c *Conn) SuppressCloseNotify() {
	c.suppressCloseNotify.Store(true)
}

func (c *Conn) Close() error {
	if c.suppressCloseNotify.Load() {
		return c.Conn.NetConn().Close()
	}
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
	suppressCloseNotify atomic.Bool
}

var _ Interface = (*UConn)(nil)

func (c *UConn) SuppressCloseNotify() {
	c.suppressCloseNotify.Store(true)
}

func (c *UConn) Close() error {
	if c.suppressCloseNotify.Load() {
		return c.Conn.NetConn().Close()
	}
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

func (c *UConn) NegotiatedProtocol() string {
	state := c.ConnectionState()
	return state.NegotiatedProtocol
}

// UClient returns a uTLS client for c whose ClientHello is built, see
// NewUClient. When UClient fails the caller still owns c.
func UClient(c net.Conn, config *tls.Config, fingerprint *utls.ClientHelloID, options ...UClientOption) (*UConn, error) {
	uTLSConfig, resumption := copyConfig(config)
	uConn, err := newUClient(c, uTLSConfig, *fingerprint, resumption, options)
	if err != nil {
		return nil, err
	}
	return &UConn{UConn: uConn}, nil
}

func GeneraticUClient(c net.Conn, config *tls.Config) (*utls.UConn, error) {
	uTLSConfig, resumption := copyConfig(config)
	return newUClient(c, uTLSConfig, utls.HelloChrome_Auto, resumption, nil)
}

func copyConfig(c *tls.Config) (*utls.Config, clientSessionResumption) {
	resumption := newClientSessionResumption(c)
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
		OmitEmptyPsk:                   resumption.enabled(),
	}
	if c.GetClientCertificate != nil {
		config.GetClientCertificate = func(info *utls.CertificateRequestInfo) (*utls.Certificate, error) {
			schemes := make([]tls.SignatureScheme, len(info.SignatureSchemes))
			for i, s := range info.SignatureSchemes {
				schemes[i] = tls.SignatureScheme(s)
			}
			cert, err := c.GetClientCertificate(&tls.CertificateRequestInfo{
				AcceptableCAs:    info.AcceptableCAs,
				SignatureSchemes: schemes,
				Version:          info.Version,
			})
			if err != nil || cert == nil {
				return &utls.Certificate{}, err
			}
			return &utls.Certificate{Certificate: cert.Certificate, PrivateKey: cert.PrivateKey, Leaf: cert.Leaf}, nil
		}
	}
	return config, resumption
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
	randomized := utls.HelloRandomizedALPN
	randomized.Seed, _ = utls.NewPRNGSeed()
	randomized.Weights = &randomizedWeights
	randomizednoalpn := utls.HelloRandomizedNoALPN
	randomizednoalpn.Seed, _ = utls.NewPRNGSeed()
	randomizednoalpn.Weights = &randomizedWeights
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
