package conf

import (
	"encoding/json"
	"testing"

	"github.com/xtls/xray-core/transport/internet/reality"
)

func TestREALITYClientBrowser(t *testing.T) {
	base := func(browser string) *REALITYConfig {
		return &REALITYConfig{
			Fingerprint: "chrome",
			ServerName:  "example.com",
			Password:    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			Browser:     browser,
		}
	}
	for browser, want := range map[string]string{"": "", "off": "", "auto": "auto", "AUTO": "auto"} {
		message, err := base(browser).Build()
		if err != nil {
			t.Fatalf("browser %q: %v", browser, err)
		}
		if got := message.(*reality.Config).Browser; got != want {
			t.Fatalf("browser %q builds %q, want %q", browser, got, want)
		}
	}
	if _, err := base("chrome").Build(); err == nil {
		t.Fatal(`"browser" takes "auto" or "off"`)
	}
}

func TestREALITYServerBrowser(t *testing.T) {
	for _, browser := range []string{"", "off", "auto", "AUTO", "chrome"} {
		cfg := REALITYConfig{
			Target:      json.RawMessage(`"localhost:443"`),
			ServerNames: []string{"example.com"},
			PrivateKey:  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			ShortIds:    []string{""},
			Browser:     browser,
		}
		message, err := cfg.Build()
		if browser == "chrome" {
			if err == nil {
				t.Fatal("server accepted an invalid browser mode")
			}
			continue
		}
		if err != nil {
			t.Fatalf("browser %q: %v", browser, err)
		}
		want := browser == "auto" || browser == "AUTO"
		if got := message.(*reality.Config).GetREALITYConfig().BrowserMode; got != want {
			t.Errorf("browser %q enables server browser mode: %v, want %v", browser, got, want)
		}
	}
}
