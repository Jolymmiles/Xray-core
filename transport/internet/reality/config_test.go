package reality

import "testing"

func TestGetREALITYConfigDisablesClientVersionBounds(t *testing.T) {
	config := (&Config{
		MinClientVer: []byte{26, 3, 27},
		MaxClientVer: []byte{26, 7, 11},
	}).GetREALITYConfig()

	if config.MinClientVer != nil || config.MaxClientVer != nil {
		t.Fatalf("REALITY client version bounds = (%v, %v), want both disabled", config.MinClientVer, config.MaxClientVer)
	}
}
