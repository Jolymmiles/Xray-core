package reality

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/mldsa"
	"crypto/sha256"
	"crypto/sha512"
	gotls "crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/xtls/reality"
	"github.com/xtls/xray-core/common/crypto"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/utils"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/transport/internet/tls"
	"golang.org/x/net/http2"
)

type Conn struct {
	*reality.Conn
	suppressCloseNotify atomic.Bool
}

func (c *Conn) SuppressCloseNotify() {
	c.suppressCloseNotify.Store(true)
}

func (c *Conn) Close() error {
	if c.suppressCloseNotify.Load() {
		return c.Conn.NetConn().Close()
	}
	return c.Conn.Close()
}

func (c *Conn) HandshakeAddress() net.Address {
	if err := c.Handshake(); err != nil {
		return nil
	}
	state := c.ConnectionState()
	if state.ServerName == "" {
		return nil
	}
	return net.ParseAddress(state.ServerName)
}

func Server(c net.Conn, config *reality.Config) (net.Conn, error) {
	realityConn, err := reality.Server(context.Background(), c, config)
	return &Conn{Conn: realityConn}, err
}

type UConn struct {
	*utls.UConn
	Config              *Config
	ServerName          string
	AuthKey             []byte
	Verified            bool
	suppressCloseNotify atomic.Bool
}

func (c *UConn) SuppressCloseNotify() {
	c.suppressCloseNotify.Store(true)
}

func (c *UConn) Close() error {
	if c.suppressCloseNotify.Load() {
		return c.NetConn().Close()
	}
	return c.UConn.Close()
}

func (c *UConn) HandshakeAddress() net.Address {
	if err := c.Handshake(); err != nil {
		return nil
	}
	state := c.ConnectionState()
	if state.ServerName == "" {
		return nil
	}
	return net.ParseAddress(state.ServerName)
}

// VerifyConnection runs where VerifyPeerCertificate would, with the server's
// certificates already parsed. Do not call ConnectionState from it: the
// handshake holds the lock that takes.
func (c *UConn) VerifyConnection(state utls.ConnectionState) error {
	if c.Config.Show {
		localAddr := c.LocalAddr().String()
		fmt.Printf("REALITY localAddr: %v\tis using X25519MLKEM768 for TLS' communication: %v\n", localAddr, c.HandshakeState.ServerHello.ServerShare.Group == utls.X25519MLKEM768)
		fmt.Printf("REALITY localAddr: %v\tis using ML-DSA-65 for cert's extra verification: %v\n", localAddr, len(c.Config.Mldsa65Verify) > 0)
	}
	certs := state.PeerCertificates
	if len(certs) == 0 {
		return errors.New("REALITY: the server sent no certificate")
	}
	if pub, ok := certs[0].PublicKey.(ed25519.PublicKey); ok {
		h := hmac.New(sha512.New, c.AuthKey)
		h.Write(pub)
		if bytes.Equal(h.Sum(nil), certs[0].Signature) {
			if len(c.Config.Mldsa65Verify) > 0 {
				if len(certs[0].Extensions) > 0 {
					h.Write(c.HandshakeState.Hello.Raw)
					h.Write(c.HandshakeState.ServerHello.Raw)
					verify, _ := mldsa.NewPublicKey(mldsa.MLDSA65(), c.Config.Mldsa65Verify)
					if mldsa.Verify(verify, h.Sum(nil), certs[0].Extensions[0].Value, nil) == nil {
						c.Verified = true
						return nil
					}
				}
			} else {
				c.Verified = true
				return nil
			}
		}
	}
	opts := x509.VerifyOptions{
		DNSName:       c.ServerName,
		Intermediates: x509.NewCertPool(),
	}
	for _, cert := range certs[1:] {
		opts.Intermediates.AddCert(cert)
	}
	if _, err := certs[0].Verify(opts); err != nil {
		return err
	}
	return nil
}

// newUConn creates the uTLS client of UClient with the ClientHello of
// fingerprint built. When it fails the caller still owns c.
func newUConn(c net.Conn, config *Config, dest net.Destination, fingerprint utls.ClientHelloID) (*UConn, error) {
	uConn := &UConn{
		Config: config,
	}
	utlsConfig := &utls.Config{
		VerifyConnection:       uConn.VerifyConnection,
		ServerName:             config.ServerName,
		InsecureSkipVerify:     true,
		SessionTicketsDisabled: true,
		KeyLogWriter:           KeyLogWriterFromConfig(config),
	}
	if utlsConfig.ServerName == "" {
		utlsConfig.ServerName = dest.Address.String()
	}
	uConn.ServerName = utlsConfig.ServerName
	var err error
	if uConn.UConn, err = tls.NewUClient(c, utlsConfig, fingerprint); err != nil {
		return nil, errors.New("REALITY: failed to build the ClientHello").Base(err)
	}
	return uConn, nil
}

// seal writes the REALITY session ID into the built ClientHello and derives
// the key the server proves it holds. The session ID authenticates the whole
// hello, so nothing may change the hello afterwards.
func (c *UConn) seal() error {
	config := c.Config
	localAddr := c.LocalAddr().String()
	hello := c.HandshakeState.Hello
	// The legacy session ID is 32 bytes at a fixed offset: after version,
	// random and its length byte.
	if hello == nil || len(hello.Raw) < 39+32 || hello.Raw[38] != 32 {
		return errors.New("REALITY: the ClientHello of fingerprint ", c.ClientHelloID.Client, c.ClientHelloID.Version, " has no session ID to seal")
	}
	hello.SessionId = make([]byte, 32)
	copy(hello.Raw[39:], hello.SessionId) // the fixed location of `Session ID`
	hello.SessionId[0] = core.Version_x
	hello.SessionId[1] = core.Version_y
	hello.SessionId[2] = core.Version_z
	hello.SessionId[3] = 0 // reserved
	binary.BigEndian.PutUint32(hello.SessionId[4:], uint32(time.Now().Unix()))
	copy(hello.SessionId[8:], config.ShortId)
	if config.Show {
		fmt.Printf("REALITY localAddr: %v\thello.SessionId[:16]: %v\n", localAddr, hello.SessionId[:16])
	}
	publicKey, err := ecdh.X25519().NewPublicKey(config.PublicKey)
	if err != nil {
		return errors.New("REALITY: nil publicKey").Base(err)
	}
	ecdhe := c.HandshakeState.State13.KeyShareKeys.Ecdhe
	if ecdhe == nil {
		ecdhe = c.HandshakeState.State13.KeyShareKeys.MlkemEcdhe
	}
	if ecdhe == nil {
		return errors.New("Current fingerprint ", c.ClientHelloID.Client, c.ClientHelloID.Version, " does not support TLS 1.3, REALITY handshake cannot establish.")
	}
	if c.AuthKey, err = ecdhe.ECDH(publicKey); err != nil {
		return errors.New("REALITY: nil sharedKey").Base(err)
	}
	if c.AuthKey, err = hkdf.Key(sha256.New, c.AuthKey, hello.Random[:20], "REALITY", 32); err != nil {
		return errors.New("REALITY: nil authKey").Base(err)
	}
	aead := crypto.NewAesGcm(c.AuthKey)
	if config.Show {
		fmt.Printf("REALITY localAddr: %v\tuConn.AuthKey[:16]: %v\tAEAD: %T\n", localAddr, c.AuthKey[:16], aead)
	}
	aead.Seal(hello.SessionId[:0], hello.Random[20:], hello.SessionId[:16], hello.Raw)
	copy(hello.Raw[39:], hello.SessionId)
	return nil
}

// spiderLease is how long the spider keeps the connection it is handed.
// Servers close an idle HTTP/2 connection sooner by default (nginx after 75
// s, Cloudflare after 400 s, Google Cloud load balancers after 610 s), so
// normally the server closes it first; the lease ends a connection the peer
// keeps open.
var spiderLease = func() time.Duration {
	return time.Duration(crypto.RandBetween(660, 720)) * time.Second
}

// UClient dials REALITY over c. It owns c: on failure c is closed, except
// when the server shows a real certificate; then UClient hands c to the
// spider, which browses over it for a lease, and returns an error.
func UClient(c net.Conn, config *Config, ctx context.Context, dest net.Destination) (net.Conn, error) {
	localAddr := c.LocalAddr().String()
	uConn, err := func() (*UConn, error) {
		fingerprint := tls.GetFingerprint(config.Fingerprint)
		if fingerprint == nil {
			return nil, errors.New("REALITY: failed to get fingerprint")
		}
		uConn, err := newUConn(c, config, dest, *fingerprint)
		if err != nil {
			return nil, err
		}
		if err := uConn.seal(); err != nil {
			return nil, err
		}
		if err := uConn.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		return uConn, nil
	}()
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	if config.Show {
		fmt.Printf("REALITY localAddr: %v\tuConn.Verified: %v\n", localAddr, uConn.Verified)
	}
	if !uConn.Verified {
		errors.LogError(ctx, "REALITY: received real certificate (potential MITM or redirection)")
		go uConn.spider(c, localAddr, spiderLease())
		time.Sleep(time.Duration(crypto.RandBetween(config.SpiderY[8], config.SpiderY[9])) * time.Millisecond) // return
		return nil, errors.New("REALITY: processed invalid connection")
	}
	return uConn, nil
}

// spider browses the site whose real certificate the server showed, over the
// connection that showed it, as a browser sent there would. It owns raw, the
// connection under uConn: when lease has passed it closes raw, ending what is
// still in flight, unless the peer has closed it first. It sends nothing to
// close it, neither GOAWAY nor close_notify, as Chrome closes an idle
// HTTP/2 connection.
func (uConn *UConn) spider(raw net.Conn, localAddr string, lease time.Duration) {
	config := uConn.Config
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(lease, func() {
		cancel()
		_ = raw.Close()
	})
	var dialed atomic.Bool
	client := &http.Client{
		Transport: &http2.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string, cfg *gotls.Config) (net.Conn, error) {
				if config.Show {
					fmt.Printf("REALITY localAddr: %v\tDialTLSContext\n", localAddr)
				}
				// The spider has this one connection. Another dial, for a
				// redirect to another host or a retry, would start a second
				// HTTP/2 session on it.
				if !dialed.CompareAndSwap(false, true) {
					return nil, errors.New("REALITY: the spider has a single connection")
				}
				return uConn, nil
			},
		},
	}
	prefix := []byte("https://" + uConn.ServerName)
	maps.Lock()
	if maps.maps == nil {
		maps.maps = make(map[string]map[string]struct{})
	}
	paths := maps.maps[uConn.ServerName]
	if paths == nil {
		paths = make(map[string]struct{})
		paths[config.SpiderX] = struct{}{}
		maps.maps[uConn.ServerName] = paths
	}
	firstURL := string(prefix) + getPathLocked(paths)
	maps.Unlock()
	get := func(first bool) {
		var (
			req  *http.Request
			resp *http.Response
			err  error
			body []byte
		)
		if first {
			req, _ = http.NewRequestWithContext(ctx, "GET", firstURL, nil)
		} else {
			maps.Lock()
			req, _ = http.NewRequestWithContext(ctx, "GET", string(prefix)+getPathLocked(paths), nil)
			maps.Unlock()
		}
		if req == nil {
			return
		}
		utils.TryDefaultHeadersWith(req.Header, "nav")
		if first && config.Show {
			fmt.Printf("REALITY localAddr: %v\treq.UserAgent(): %v\n", localAddr, req.UserAgent())
		}
		times := 1
		if !first {
			times = int(crypto.RandBetween(config.SpiderY[4], config.SpiderY[5]))
		}
		for j := 0; j < times; j++ {
			if !first && j == 0 {
				req.Header.Set("Referer", firstURL)
			}
			req.AddCookie(&http.Cookie{Name: "padding", Value: strings.Repeat("0", int(crypto.RandBetween(config.SpiderY[0], config.SpiderY[1])))})
			if resp, err = client.Do(req); err != nil {
				break
			}
			defer resp.Body.Close()
			req.Header.Set("Referer", req.URL.String())
			if body, err = io.ReadAll(resp.Body); err != nil {
				break
			}
			maps.Lock()
			for _, m := range href.FindAllSubmatch(body, -1) {
				m[1] = bytes.TrimPrefix(m[1], prefix)
				if !bytes.Contains(m[1], dot) {
					paths[string(m[1])] = struct{}{}
				}
			}
			req.URL.Path = getPathLocked(paths)
			if config.Show {
				fmt.Printf("REALITY localAddr: %v\treq.Referer(): %v\n", localAddr, req.Referer())
				fmt.Printf("REALITY localAddr: %v\tlen(body): %v\n", localAddr, len(body))
				fmt.Printf("REALITY localAddr: %v\tlen(paths): %v\n", localAddr, len(paths))
			}
			maps.Unlock()
			if !first && !sleepContext(ctx, time.Duration(crypto.RandBetween(config.SpiderY[6], config.SpiderY[7]))*time.Millisecond) { // interval
				break
			}
		}
	}
	get(true)
	concurrency := int(crypto.RandBetween(config.SpiderY[2], config.SpiderY[3]))
	for i := 0; i < concurrency && ctx.Err() == nil; i++ {
		go get(false)
	}
	// Do not close the connection: the lease does
}

// sleepContext sleeps for d and reports whether it did so before ctx ended.
func sleepContext(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

var (
	href = regexp.MustCompile(`href="([/h].*?)"`)
	dot  = []byte(".")
)

var maps struct {
	sync.Mutex
	maps map[string]map[string]struct{}
}

func getPathLocked(paths map[string]struct{}) string {
	stopAt := int(crypto.RandBetween(0, int64(len(paths)-1)))
	i := 0
	for s := range paths {
		if i == stopAt {
			return s
		}
		i++
	}
	return "/"
}
