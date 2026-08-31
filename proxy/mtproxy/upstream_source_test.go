package mtproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

const testProxyConfig = `proxy_for 1 149.154.175.50:8888;
default 1;
`

func TestUpstreamSourceFilesLoadsAndValidatesWithoutHTTP(t *testing.T) {
	directory := t.TempDir()
	secretPath := filepath.Join(directory, "proxy-secret")
	configPath := filepath.Join(directory, "proxy-multi.conf")
	secret := bytes.Repeat([]byte{0x5a}, 32)
	if err := os.WriteFile(secretPath, secret, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte(testProxyConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := LoadFileUpstream(secretPath, configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data.Secret, secret) || len(data.Config.Endpoints(1)) != 1 {
		t.Fatalf("loaded data = %+v", data)
	}

	if err := os.WriteFile(secretPath, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFileUpstream(secretPath, configPath); err == nil {
		t.Fatal("short upstream secret accepted")
	}
	if err := os.WriteFile(secretPath, secret, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte("malformed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFileUpstream(secretPath, configPath); err == nil {
		t.Fatal("malformed upstream config accepted")
	}
}

func TestUpstreamSourceTelegramDownloadsCachesAndUsesLastKnownGood(t *testing.T) {
	secret := bytes.Repeat([]byte{0x6b}, 32)
	var fail atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if fail.Load() {
			http.Error(writer, "failure", http.StatusServiceUnavailable)
			return
		}
		switch request.URL.Path {
		case "/secret":
			_, _ = writer.Write(secret)
		case "/config":
			_, _ = writer.Write([]byte(testProxyConfig))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	cacheDir := t.TempDir()
	source, err := newTelegramUpstreamSource(cacheDir, server.Client(), server.URL+"/secret", server.URL+"/config", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	first, err := source.LoadInitial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Secret, secret) {
		t.Fatalf("downloaded secret = %x", first.Secret)
	}
	cacheInfo, err := os.Stat(filepath.Join(cacheDir, upstreamCacheFile))
	if err != nil {
		t.Fatal(err)
	}
	if cacheInfo.Mode().Perm()&0o077 != 0 {
		t.Fatalf("cache permissions = %o, want owner-only", cacheInfo.Mode().Perm())
	}

	fail.Store(true)
	secondSource, err := newTelegramUpstreamSource(cacheDir, server.Client(), server.URL+"/secret", server.URL+"/config", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cached, err := secondSource.LoadInitial(context.Background())
	if err != nil {
		t.Fatalf("LoadInitial() with failed network and cache error = %v", err)
	}
	if !bytes.Equal(cached.Secret, first.Secret) || len(cached.Config.Endpoints(1)) != 1 {
		t.Fatal("last-known-good cache was not loaded")
	}
	if refreshed, err := secondSource.Refresh(context.Background()); err == nil || refreshed != nil {
		t.Fatalf("Refresh() = %+v, %v, want failure without replacement", refreshed, err)
	}
}

func TestUpstreamSourceTelegramRejectsCrossOriginRedirectAndOversize(t *testing.T) {
	destination := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = writer.Write(bytes.Repeat([]byte{1}, maxDownloadedSecret+1))
	}))
	defer destination.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, destination.URL, http.StatusFound)
	}))
	defer redirect.Close()

	source, err := newTelegramUpstreamSource(t.TempDir(), redirect.Client(), redirect.URL, redirect.URL, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.Refresh(context.Background()); err == nil {
		t.Fatal("cross-origin redirect accepted")
	}

	oversize := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/secret" {
			_, _ = writer.Write(bytes.Repeat([]byte{1}, maxDownloadedSecret+1))
			return
		}
		_, _ = writer.Write([]byte(testProxyConfig))
	}))
	defer oversize.Close()
	source, _ = newTelegramUpstreamSource(t.TempDir(), oversize.Client(), oversize.URL+"/secret", oversize.URL+"/config", time.Hour)
	if _, err := source.Refresh(context.Background()); err == nil {
		t.Fatal("oversized secret accepted")
	}
}

func TestUpstreamSourceTelegramRejectsStaleAndFutureCache(t *testing.T) {
	secret := bytes.Repeat([]byte{0x55}, 32)
	for _, fetchedAt := range []time.Time{time.Now().Add(-8 * 24 * time.Hour), time.Now().Add(10 * time.Minute)} {
		directory := t.TempDir()
		bundle := upstreamCacheBundle{Version: 1, Secret: secret, Config: []byte(testProxyConfig), FetchedAt: fetchedAt}
		encoded, err := json.Marshal(bundle)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, upstreamCacheFile), encoded, 0o600); err != nil {
			t.Fatal(err)
		}
		source, err := newTelegramUpstreamSource(directory, http.DefaultClient, "http://example.test/secret", "http://example.test/config", time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := source.loadCache(); err == nil {
			t.Fatalf("cache timestamp %s was accepted", fetchedAt)
		}
	}
}

func TestUpstreamSourceTelegramUsesValidDownloadWhenCacheWriteFails(t *testing.T) {
	secret := bytes.Repeat([]byte{0x56}, 32)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/secret" {
			_, _ = writer.Write(secret)
		} else {
			_, _ = writer.Write([]byte(testProxyConfig))
		}
	}))
	defer server.Close()
	directory := t.TempDir()
	cachePath := filepath.Join(directory, "not-a-directory")
	if err := os.WriteFile(cachePath, []byte("occupied"), 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := newTelegramUpstreamSource(cachePath, server.Client(), server.URL+"/secret", server.URL+"/config", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	data, refreshErr := source.Refresh(context.Background())
	if data == nil || refreshErr == nil {
		t.Fatalf("Refresh() = %+v, %v, want valid data plus cache error", data, refreshErr)
	}
	initial, err := source.LoadInitial(context.Background())
	if err != nil || initial == nil || !bytes.Equal(initial.Secret, secret) {
		t.Fatalf("LoadInitial() = %+v, %v", initial, err)
	}
}

func TestUpstreamSourceTelegramRunAppliesOnlySuccessfulRefresh(t *testing.T) {
	secret := bytes.Repeat([]byte{0x7c}, 32)
	var fail atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if fail.Load() {
			http.Error(writer, "no", http.StatusServiceUnavailable)
			return
		}
		if request.URL.Path == "/secret" {
			_, _ = writer.Write(secret)
		} else {
			_, _ = writer.Write([]byte(testProxyConfig))
		}
	}))
	defer server.Close()
	source, _ := newTelegramUpstreamSource(t.TempDir(), server.Client(), server.URL+"/secret", server.URL+"/config", 10*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	applied := make(chan *UpstreamData, 2)
	go source.Run(ctx, func(data *UpstreamData) { applied <- data })
	select {
	case <-applied:
	case <-time.After(time.Second):
		t.Fatal("successful refresh was not applied")
	}
	fail.Store(true)
	select {
	case <-applied:
		t.Fatal("failed refresh replaced active data")
	case <-time.After(60 * time.Millisecond):
	}
}
