package mtproxy

import (
	"fmt"
	"io"
	"os"
	"time"
)

func LoadFileUpstream(secretPath, configPath string) (*UpstreamData, error) {
	if secretPath == "" || configPath == "" {
		return nil, fmt.Errorf("mtproxy: both upstream file paths are required")
	}
	secret, err := readBoundedFile(secretPath, maxMiddleSecretLength)
	if err != nil {
		return nil, fmt.Errorf("mtproxy: read upstream secret: %w", err)
	}
	config, err := readBoundedFile(configPath, maxDownloadedConfig)
	if err != nil {
		return nil, fmt.Errorf("mtproxy: read upstream config: %w", err)
	}
	return newUpstreamData(secret, config, time.Now())
}

func readBoundedFile(path string, maximum int) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, int64(maximum)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maximum {
		return nil, fmt.Errorf("file exceeds %d bytes", maximum)
	}
	return data, nil
}
