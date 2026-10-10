// Command origin is the far end of the slow-reader stand: an HTTP server that
// answers /ping at once and reads /up at a fixed rate, and a TLS 1.3 server
// that stands in as the REALITY target.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strconv"
	"time"
)

// maxRate bounds ?rate= on /up: a mebibyte per second per upload is far above
// what a slow reader stands for.
const maxRate = 1 << 20

func main() {
	httpAddr := flag.String("http", "127.0.0.1:18000", "address of the plain HTTP origin")
	tlsAddr := flag.String("tls", "127.0.0.1:8444", "address of the TLS server used as the REALITY target")
	flag.Parse()
	go serveTLS(*tlsAddr)

	mux := http.NewServeMux()
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("pong")) })
	// /up reads the body at ?rate= bytes per second, in pieces of a
	// twentieth of that, so the reader is slow but steady. It answers 200
	// with the byte count for a whole body, 400 for a bad rate or a body
	// that ends in an error.
	mux.HandleFunc("/up", func(w http.ResponseWriter, r *http.Request) {
		rate, err := strconv.ParseInt(r.URL.Query().Get("rate"), 10, 64)
		if err != nil || rate < 1 || rate > maxRate {
			http.Error(w, fmt.Sprintf("rate must be 1 to %d bytes per second", maxRate), http.StatusBadRequest)
			return
		}
		buf := make([]byte, max(rate/20, 1024))
		start := time.Now()
		var got int64
		for {
			n, err := r.Body.Read(buf)
			got += int64(n)
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				http.Error(w, fmt.Sprintf("after %d bytes: %v", got, err), http.StatusBadRequest)
				return
			}
			want := time.Duration(float64(got) / float64(rate) * float64(time.Second))
			if d := want - time.Since(start); d > 0 {
				time.Sleep(d)
			}
		}
		fmt.Fprintf(w, "%d", got)
	})
	panic(http.ListenAndServe(*httpAddr, mux))
}

func serveTLS(addr string) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "www.example.com"},
		DNSNames:     []string{"www.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	srv := &http.Server{
		Addr:    addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("hello")) }),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
			MinVersion:   tls.VersionTLS13,
			NextProtos:   []string{"h2", "http/1.1"},
		},
	}
	panic(srv.ListenAndServeTLS("", ""))
}
