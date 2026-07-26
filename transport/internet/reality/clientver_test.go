package reality

import "testing"

// TestGetREALITYConfigForwardsClientVerBounds guards the wiring between the
// parsed configuration and the REALITY handshake: the library only enforces a
// bound when the corresponding field is non-nil.
func TestGetREALITYConfigForwardsClientVerBounds(t *testing.T) {
	t.Run("configured bounds reach the handshake", func(t *testing.T) {
		config := &Config{
			MinClientVer: []byte{1, 2, 3},
			MaxClientVer: []byte{4, 5, 6},
		}

		built := config.GetREALITYConfig()

		if got := built.MinClientVer; len(got) != 3 || got[0] != 1 || got[1] != 2 || got[2] != 3 {
			t.Errorf("MinClientVer = %v, want [1 2 3]", got)
		}
		if got := built.MaxClientVer; len(got) != 3 || got[0] != 4 || got[1] != 5 || got[2] != 6 {
			t.Errorf("MaxClientVer = %v, want [4 5 6]", got)
		}
	})

	t.Run("unset bounds stay nil so no client is rejected", func(t *testing.T) {
		built := (&Config{}).GetREALITYConfig()

		if built.MinClientVer != nil {
			t.Errorf("MinClientVer = %v, want nil", built.MinClientVer)
		}
		if built.MaxClientVer != nil {
			t.Errorf("MaxClientVer = %v, want nil", built.MaxClientVer)
		}
	})
}
