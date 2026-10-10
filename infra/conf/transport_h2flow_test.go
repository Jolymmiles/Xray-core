package conf_test

import (
	"encoding/json"
	"strings"
	"testing"

	. "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/transport/internet/splithttp"
)

func TestXHTTPH2Flow(t *testing.T) {
	build := func(s string) (*splithttp.Config, error) {
		var c SplitHTTPConfig
		if err := json.Unmarshal([]byte(s), &c); err != nil {
			t.Fatal(err)
		}
		m, err := c.Build()
		if err != nil {
			return nil, err
		}
		return m.(*splithttp.Config), nil
	}

	for _, tc := range []struct {
		json         string
		mode         int32
		stream, conn int32
		send         int32
		absent       bool
	}{
		{json: `{}`, absent: true},
		{json: `{"h2Flow": {}}`},
		{json: `{"h2Flow": {"enabled": true}}`, mode: 1},
		{json: `{"h2Flow": {"enabled": false}}`, mode: 2},
		{json: `{"extra": {"h2Flow": {"enabled": true, "maxStreamReceiveWindow": 6291456, "maxConnectionReceiveWindow": 16777216}}}`, mode: 1, stream: 6291456, conn: 16777216},
		{json: `{"h2Flow": {"enabled": true, "maxConnectionSendWindow": 8388608}}`, mode: 1, send: 8388608},
		{json: `{"h2Flow": {"enabled": true, "maxConnectionSendWindow": -1}}`, mode: 1, send: -1},
	} {
		c, err := build(tc.json)
		if err != nil {
			t.Fatal(tc.json, err)
		}
		f := c.GetH2Flow()
		if tc.absent != (f == nil) {
			t.Fatalf("%s: h2Flow present = %v", tc.json, f != nil)
		}
		if f.GetMode() != tc.mode || f.GetMaxStreamReceiveWindow() != tc.stream || f.GetMaxConnectionReceiveWindow() != tc.conn ||
			f.GetMaxConnectionSendWindow() != tc.send {
			t.Errorf("%s: got %v", tc.json, f)
		}
	}

	for _, s := range []string{
		`{"h2Flow": {"maxStreamReceiveWindow": 1000}}`,
		`{"h2Flow": {"maxConnectionReceiveWindow": 2147483647}}`,
		`{"h2Flow": {"maxConnectionSendWindow": 1000}}`,
		`{"h2Flow": {"maxConnectionSendWindow": -2}}`,
		`{"h2Flow": {"maxConnectionSendWindow": 2147483647}}`,
	} {
		if _, err := build(s); err == nil || !strings.Contains(err.Error(), "h2Flow") {
			t.Errorf("%s: expected an h2Flow error, got %v", s, err)
		}
	}
}
