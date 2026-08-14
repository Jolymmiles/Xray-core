package presence

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestProductionPresenceOwnershipSourceAudit(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("source path unavailable")
	}
	repositoryRoot := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", ".."))
	productionRoots := []string{"app", "common", "features", "proxy", "transport"}
	forbidden := []string{
		"trackOnlineIP",
		"XUDPManager",
		"xudpLifecycle",
		"PresenceModeLegacy",
		"PresenceModeStructural",
		"HandoffIP",
	}
	for _, root := range productionRoots {
		err := filepath.WalkDir(filepath.Join(repositoryRoot, root), func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") || strings.HasSuffix(path, ".pb.go") {
				return nil
			}
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for _, symbol := range forbidden {
				if bytes.Contains(content, []byte(symbol)) {
					t.Errorf("removed presence ownership symbol %q remains in %s", symbol, filepath.ToSlash(path))
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
