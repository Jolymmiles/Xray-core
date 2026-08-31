package mtproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

const (
	telegramProxySecretURL = "https://core.telegram.org/getProxySecret"
	telegramProxyConfigURL = "https://core.telegram.org/getProxyConfig"
	upstreamCacheFile      = "upstream-cache.json"
	maxDownloadedSecret    = 4 << 10
)

type upstreamCacheBundle struct {
	Version   int       `json:"version"`
	Secret    []byte    `json:"secret"`
	Config    []byte    `json:"config"`
	FetchedAt time.Time `json:"fetchedAt"`
}

type TelegramUpstreamSource struct {
	cacheDir        string
	client          *http.Client
	secretURL       string
	configURL       string
	refreshInterval time.Duration
	minBackoff      time.Duration
}

func NewTelegramUpstreamSource(cacheDir string, refreshInterval time.Duration) (*TelegramUpstreamSource, error) {
	return newTelegramUpstreamSource(cacheDir, &http.Client{Timeout: 10 * time.Second}, telegramProxySecretURL, telegramProxyConfigURL, refreshInterval)
}

func newTelegramUpstreamSource(cacheDir string, client *http.Client, secretURL, configURL string, refreshInterval time.Duration) (*TelegramUpstreamSource, error) {
	if cacheDir == "" || client == nil || refreshInterval <= 0 {
		return nil, fmt.Errorf("mtproxy: invalid automatic upstream source settings")
	}
	secretOrigin, err := url.Parse(secretURL)
	if err != nil || secretOrigin.Scheme == "" || secretOrigin.Host == "" {
		return nil, fmt.Errorf("mtproxy: invalid upstream secret URL")
	}
	configOrigin, err := url.Parse(configURL)
	if err != nil || configOrigin.Scheme != secretOrigin.Scheme || configOrigin.Host != secretOrigin.Host {
		return nil, fmt.Errorf("mtproxy: automatic upstream URLs must share one origin")
	}
	clientCopy := *client
	if clientCopy.Timeout == 0 {
		clientCopy.Timeout = 10 * time.Second
	}
	clientCopy.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if len(via) >= 3 {
			return fmt.Errorf("mtproxy: too many upstream redirects")
		}
		if request.URL.Scheme != secretOrigin.Scheme || request.URL.Host != secretOrigin.Host {
			return fmt.Errorf("mtproxy: cross-origin upstream redirect denied")
		}
		return nil
	}
	minBackoff := time.Minute
	if refreshInterval < minBackoff {
		minBackoff = refreshInterval
	}
	return &TelegramUpstreamSource{
		cacheDir:        cacheDir,
		client:          &clientCopy,
		secretURL:       secretURL,
		configURL:       configURL,
		refreshInterval: refreshInterval,
		minBackoff:      minBackoff,
	}, nil
}

func (s *TelegramUpstreamSource) LoadInitial(ctx context.Context) (*UpstreamData, error) {
	if cached, err := s.loadCache(); err == nil {
		return cached, nil
	}
	data, err := s.Refresh(ctx)
	if data != nil {
		return data, nil
	}
	return nil, err
}

func (s *TelegramUpstreamSource) Refresh(ctx context.Context) (*UpstreamData, error) {
	secret, err := s.download(ctx, s.secretURL, maxDownloadedSecret)
	if err != nil {
		return nil, fmt.Errorf("mtproxy: download upstream secret: %w", err)
	}
	config, err := s.download(ctx, s.configURL, maxDownloadedConfig)
	if err != nil {
		return nil, fmt.Errorf("mtproxy: download upstream config: %w", err)
	}
	loadedAt := time.Now().UTC()
	data, err := newUpstreamData(secret, config, loadedAt)
	if err != nil {
		return nil, err
	}
	if err := s.storeCache(data); err != nil {
		return data, fmt.Errorf("mtproxy: persist upstream cache: %w", err)
	}
	return data, nil
}

func (s *TelegramUpstreamSource) Run(ctx context.Context, apply func(*UpstreamData)) {
	if apply == nil {
		return
	}
	delay := time.Duration(0)
	for {
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return
		case <-timer.C:
		}

		data, err := s.Refresh(ctx)
		if data != nil {
			apply(data)
		}
		if err == nil {
			delay = s.refreshInterval
			continue
		}
		if ctx.Err() != nil {
			return
		}
		if delay < s.minBackoff {
			delay = s.minBackoff
		} else {
			delay *= 2
			if delay > s.refreshInterval {
				delay = s.refreshInterval
			}
		}
	}
}

func (s *TelegramUpstreamSource) download(ctx context.Context, address string, maximum int) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, err
	}
	response, err := s.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected HTTP status %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, int64(maximum)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maximum {
		return nil, fmt.Errorf("response exceeds %d bytes", maximum)
	}
	return data, nil
}

func (s *TelegramUpstreamSource) loadCache() (*UpstreamData, error) {
	path := filepath.Join(s.cacheDir, upstreamCacheFile)
	encoded, err := readBoundedFile(path, maxDownloadedConfig+maxDownloadedSecret+4096)
	if err != nil {
		return nil, err
	}
	var bundle upstreamCacheBundle
	if err := json.Unmarshal(encoded, &bundle); err != nil || bundle.Version != 1 {
		return nil, fmt.Errorf("mtproxy: invalid upstream cache")
	}
	now := time.Now().UTC()
	if bundle.FetchedAt.IsZero() || bundle.FetchedAt.After(now.Add(5*time.Minute)) || bundle.FetchedAt.Before(now.Add(-7*24*time.Hour)) {
		return nil, fmt.Errorf("mtproxy: upstream cache timestamp is outside the accepted window")
	}
	return newUpstreamData(bundle.Secret, bundle.Config, bundle.FetchedAt)
}

func (s *TelegramUpstreamSource) storeCache(data *UpstreamData) error {
	if err := os.MkdirAll(s.cacheDir, 0o700); err != nil {
		return fmt.Errorf("mtproxy: create upstream cache directory: %w", err)
	}
	bundle := upstreamCacheBundle{Version: 1, Secret: data.Secret, Config: data.RawConfig, FetchedAt: data.LoadedAt}
	encoded, err := json.Marshal(bundle)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(s.cacheDir, ".upstream-cache-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	keep := false
	defer func() {
		_ = temporary.Close()
		if !keep {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if err := writeFull(temporary, encoded); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	finalPath := filepath.Join(s.cacheDir, upstreamCacheFile)
	if err := os.Rename(temporaryPath, finalPath); err != nil {
		return err
	}
	keep = true
	return nil
}
