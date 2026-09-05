package mtproxy

import (
	"bytes"
	"fmt"
	"time"
)

const maxDownloadedConfig = 1 << 20

type UpstreamData struct {
	Secret    []byte
	Config    *ProxyConfig
	RawConfig []byte
	LoadedAt  time.Time
}

func newUpstreamData(secret, rawConfig []byte, loadedAt time.Time) (*UpstreamData, error) {
	if len(secret) < minMiddleSecretLength || len(secret) > maxMiddleSecretLength {
		return nil, fmt.Errorf("mtproxy: invalid downloaded Middle-End secret length %d", len(secret))
	}
	if secret[0] == 0 && secret[1] == 0 && secret[2] == 0 && secret[3] == 0 {
		return nil, fmt.Errorf("mtproxy: zero Middle-End key selector")
	}
	if len(rawConfig) == 0 || len(rawConfig) > maxDownloadedConfig {
		return nil, fmt.Errorf("mtproxy: invalid downloaded proxy config length %d", len(rawConfig))
	}
	config, err := ParseProxyConfig(bytes.NewReader(rawConfig), 4096, 1024)
	if err != nil {
		return nil, err
	}
	return &UpstreamData{
		Secret:    append([]byte(nil), secret...),
		Config:    config,
		RawConfig: append([]byte(nil), rawConfig...),
		LoadedAt:  loadedAt,
	}, nil
}
