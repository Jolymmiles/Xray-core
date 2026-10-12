package conf_test

import "testing"

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
