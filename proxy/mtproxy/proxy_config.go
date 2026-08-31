package mtproxy

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

type MiddleEndpoint struct {
	Host string
	Port uint16
}

type ProxyConfig struct {
	DefaultDC int16
	clusters  map[int16][]MiddleEndpoint
}

func (c *ProxyConfig) Endpoints(dcID int16) []MiddleEndpoint {
	if c == nil {
		return nil
	}
	endpoints := c.clusters[dcID]
	if len(endpoints) == 0 {
		endpoints = c.clusters[c.DefaultDC]
	}
	return append([]MiddleEndpoint(nil), endpoints...)
}

func ParseProxyConfig(reader io.Reader, maxTargets, maxClusters int) (*ProxyConfig, error) {
	if reader == nil || maxTargets <= 0 || maxClusters <= 0 {
		return nil, fmt.Errorf("mtproxy: invalid proxy configuration limits")
	}
	config := &ProxyConfig{clusters: make(map[int16][]MiddleEndpoint)}
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	targets := 0
	haveDefault := false

	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		line := scanner.Text()
		if comment := strings.IndexByte(line, '#'); comment >= 0 {
			line = line[:comment]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !strings.HasSuffix(line, ";") {
			return nil, fmt.Errorf("mtproxy: proxy config line %d has no semicolon", lineNumber)
		}
		line = strings.TrimSpace(strings.TrimSuffix(line, ";"))
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}

		switch fields[0] {
		case "default":
			if len(fields) != 2 || haveDefault {
				return nil, fmt.Errorf("mtproxy: invalid default directive on line %d", lineNumber)
			}
			dcID, err := parseDCID(fields[1])
			if err != nil {
				return nil, fmt.Errorf("mtproxy: line %d: %w", lineNumber, err)
			}
			config.DefaultDC = dcID
			haveDefault = true

		case "proxy", "proxy_for":
			expectedFields := 2
			dcID := int16(0)
			endpointField := 1
			if fields[0] == "proxy_for" {
				expectedFields = 3
				endpointField = 2
			}
			if len(fields) != expectedFields {
				return nil, fmt.Errorf("mtproxy: invalid %s directive on line %d", fields[0], lineNumber)
			}
			if fields[0] == "proxy_for" {
				var err error
				dcID, err = parseDCID(fields[1])
				if err != nil {
					return nil, fmt.Errorf("mtproxy: line %d: %w", lineNumber, err)
				}
			}
			endpoint, err := parseMiddleEndpoint(fields[endpointField])
			if err != nil {
				return nil, fmt.Errorf("mtproxy: line %d: %w", lineNumber, err)
			}
			if _, exists := config.clusters[dcID]; !exists && len(config.clusters) >= maxClusters {
				return nil, fmt.Errorf("mtproxy: proxy config exceeds %d clusters", maxClusters)
			}
			if targets >= maxTargets {
				return nil, fmt.Errorf("mtproxy: proxy config exceeds %d targets", maxTargets)
			}
			config.clusters[dcID] = append(config.clusters[dcID], endpoint)
			targets++

		default:
			return nil, fmt.Errorf("mtproxy: unknown proxy config directive %q on line %d", fields[0], lineNumber)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if targets == 0 {
		return nil, fmt.Errorf("mtproxy: proxy config contains no targets")
	}
	if !haveDefault {
		return nil, fmt.Errorf("mtproxy: proxy config contains no default DC")
	}
	if len(config.clusters[config.DefaultDC]) == 0 {
		return nil, fmt.Errorf("mtproxy: default DC %d has no targets", config.DefaultDC)
	}
	return config, nil
}

func parseDCID(value string) (int16, error) {
	parsed, err := strconv.ParseInt(value, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("invalid DC ID %q", value)
	}
	return int16(parsed), nil
}

func parseMiddleEndpoint(value string) (MiddleEndpoint, error) {
	host, portText, err := net.SplitHostPort(value)
	if err != nil || host == "" {
		return MiddleEndpoint{}, fmt.Errorf("invalid Middle-End endpoint %q", value)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return MiddleEndpoint{}, fmt.Errorf("invalid Middle-End port in %q", value)
	}
	return MiddleEndpoint{Host: host, Port: uint16(port)}, nil
}
