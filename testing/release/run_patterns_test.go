package release

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// TestStructuralPresenceRunPatternsSelectTheirTests reads every -run pattern
// of the release gate. Each test it names must exist, and the pattern's
// top-level part must select it: go test splits a pattern on '/' only outside
// parentheses, so '^(TestA|TestB/)' asks for a top-level test named "TestB/"
// and runs none.
func TestStructuralPresenceRunPatternsSelectTheirTests(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("source path unavailable")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", ".."))
	gate, err := os.ReadFile(filepath.Join(root, "testing", "release", "structural_presence.sh"))
	if err != nil {
		t.Fatal(err)
	}
	tests := testFunctions(t, root)
	patterns := regexp.MustCompile(`-run '([^']*)'`).FindAllStringSubmatch(string(gate), -1)
	if len(patterns) == 0 {
		t.Fatal("the release gate has no -run patterns")
	}
	for _, pattern := range patterns {
		topLevel, err := regexp.Compile(splitRunPattern(pattern[1])[0])
		if err != nil {
			t.Fatalf("-run %q: %v", pattern[1], err)
		}
		for _, name := range regexp.MustCompile(`Test\w+`).FindAllString(pattern[1], -1) {
			selected, exists := false, false
			for _, test := range tests {
				if strings.HasPrefix(test, name) {
					exists = true
					selected = selected || topLevel.MatchString(test)
				}
			}
			switch {
			case !exists:
				t.Errorf("-run %q names %s, which no test function starts with", pattern[1], name)
			case !selected:
				t.Errorf("-run %q names %s but selects no test of that name", pattern[1], name)
			}
		}
	}
}

// splitRunPattern splits a -run pattern into its per-level parts the way go
// test does: on '/' outside parentheses and brackets.
func splitRunPattern(pattern string) []string {
	var parts []string
	depth, start := 0, 0
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '\\':
			i++
		case '(', '[':
			depth++
		case ')', ']':
			depth--
		case '/':
			if depth == 0 {
				parts = append(parts, pattern[start:i])
				start = i + 1
			}
		}
	}
	return append(parts, pattern[start:])
}

// testFunctions lists the names of the top-level test functions in the
// repository's own test files.
func testFunctions(t *testing.T, root string) []string {
	t.Helper()
	declaration := regexp.MustCompile(`(?m)^func (Test\w+)\(t \*testing\.T\)`)
	var names []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() && (entry.Name() == "third_party" || strings.HasPrefix(entry.Name(), ".")) && path != root {
			return filepath.SkipDir
		}
		if entry.IsDir() || !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		source, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, match := range declaration.FindAllStringSubmatch(string(source), -1) {
			names = append(names, match[1])
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return names
}
