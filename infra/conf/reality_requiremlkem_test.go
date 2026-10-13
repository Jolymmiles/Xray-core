package conf_test

import (
	"testing"

	"github.com/xtls/xray-core/transport/internet/reality"
)

// TestREALITYRequireMlkemFieldNumber pins the protobuf number of the field.
// It is fork-owned and outside the blocks upstream numbers, 1-13 for the
// server, 21-27 for the client and 31: on the next number upstream would
// use, an API client built from upstream's .proto could turn it on without
// knowing, and a sync would collide. Persisted configs and API clients carry
// the number, so it is not to change silently either.
func TestREALITYRequireMlkemFieldNumber(t *testing.T) {
	field := (&reality.Config{}).ProtoReflect().Descriptor().Fields().ByName("require_mlkem")
	if field == nil {
		t.Fatal("the REALITY Config has no require_mlkem field")
	}
	if got := field.Number(); got != 100 {
		t.Fatalf("require_mlkem is field %d, want the fork-owned 100", got)
	}
}

// TestREALITYRequireMlkemParsing checks that "requireMlkem" reaches the
// REALITY server config and stays off when omitted, so that the fork keeps
// accepting hellos without the hybrid group unless the operator asks.
func TestREALITYRequireMlkemParsing(t *testing.T) {
	tests := []struct {
		name  string
		extra string
		want  bool
	}{
		{name: "unset is off", extra: "", want: false},
		{name: "false", extra: `, "requireMlkem": false`, want: false},
		{name: "true", extra: `, "requireMlkem": true`, want: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			built, err := buildREALITYServer(t, test.extra)
			if err != nil {
				t.Fatal(err)
			}
			if built.RequireMlkem != test.want {
				t.Fatalf("RequireMlkem = %v, want %v", built.RequireMlkem, test.want)
			}
			if got := built.GetREALITYConfig().RequireMLKEM; got != test.want {
				t.Fatalf("REALITY config RequireMLKEM = %v, want %v", got, test.want)
			}
		})
	}
}
