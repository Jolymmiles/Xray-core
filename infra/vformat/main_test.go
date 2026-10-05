package main

import (
	"path/filepath"
	"testing"
)

func TestIsFormatTarget(t *testing.T) {
	for _, root := range []string{
		filepath.FromSlash("/src/Xray-core"),
		filepath.FromSlash("/home/user/third_party/Xray-core"),
	} {
		for _, test := range []struct {
			path string
			want bool
		}{
			{"core/core.go", true},
			{"proxy/hysteria/server.go", true},
			{"core/config.pb.go", false},
			{"testing/mocks/dns.go", false},
			{"main/distro/all/all.go", false},
			{"third_party/reality/tls.go", false},
			{"proxy/third_party_test/ok.go", true},
		} {
			path := filepath.Join(root, filepath.FromSlash(test.path))
			if got := isFormatTarget(root, path); got != test.want {
				t.Errorf("isFormatTarget(%q, %q) = %v, want %v", root, path, got, test.want)
			}
		}
	}
}
