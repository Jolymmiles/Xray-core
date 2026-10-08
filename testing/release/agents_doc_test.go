package release

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Documents every agent session loads or follows. A backticked repository path
// that does not exist sends the agent to material that was never written:
// AGENTS.md once cited proxy/vless/TESTING.md as the authoritative VLESS
// release checklist and no such file ever existed.
var agentDocs = []string{
	"AGENTS.md",
	"docs/FORK.md",
	".claude/skills/release/SKILL.md",
	".claude/skills/xray-pr-review/SKILL.md",
	".claude/skills/xray-pr-review/GH.md",
	".claude/skills/xray-pr-review/ORCHESTRATOR.md",
	"docs/agents/issue-tracker.md",
}

var (
	inlineCodeSpan = regexp.MustCompile("`([^`\n]+)`")
	pathCharacters = regexp.MustCompile(`^[A-Za-z0-9_.*/-]+$`)
	fileExtension  = regexp.MustCompile(`\.(go|md|sh|yml|yaml|json|proto|dat|mod|sum)$`)
)

// repoPathCandidate reports whether an inline code span names a repository
// path and returns it relative to the repository root.
//
// A span is a candidate when it has a directory part and either starts with a
// top-level repository entry or ends in a source/doc file extension. Spans
// such as `refs/heads/main`, `origin/main`, `XTLS/Xray-core` or `Version_x/y/z`
// are not paths. Bare names (`BASELINE.md`) are relative to their context and
// are not checked.
func repoPathCandidate(span string, topLevel map[string]bool) (string, bool) {
	path := strings.TrimPrefix(span, "./")
	if !pathCharacters.MatchString(path) ||
		strings.HasPrefix(path, "/") ||
		strings.HasPrefix(path, "-") ||
		strings.Contains(path, "..") {
		return "", false
	}
	first, _, hasDirectory := strings.Cut(path, "/")
	if !hasDirectory {
		return "", false
	}
	if !topLevel[first] && !fileExtension.MatchString(path) {
		return "", false
	}
	return strings.TrimSuffix(path, "/"), true
}

func TestRepoPathCandidate(t *testing.T) {
	topLevel := map[string]bool{"proxy": true, "third_party": true, ".github": true, "main": true}
	for _, test := range []struct {
		span string
		path string
		want bool
	}{
		{"proxy/vless/TESTING.md", "proxy/vless/TESTING.md", true},
		{"./main", "", false},
		{"third_party/reality", "third_party/reality", true},
		{"third_party/", "third_party", true},
		{".github/workflows/release.yml", ".github/workflows/release.yml", true},
		{"transport/internet/splithttp/h2flow*.go", "transport/internet/splithttp/h2flow*.go", true},
		{"misspelled/dir/file.go", "misspelled/dir/file.go", true},
		{"refs/heads/main", "", false},
		{"origin/main", "", false},
		{"XTLS/Xray-core", "", false},
		{"Version_x/y/z", "", false},
		{"/tmp/review/pr1.md", "", false},
		{"../sing-box", "", false},
		{"BASELINE.md", "", false},
		{"go test ./...", "", false},
		{"-tags http2legacy", "", false},
		{"GOFLAGS=-tags=http2legacy", "", false},
		{"xhttpSettings.extra.h2Flow.enabled", "", false},
	} {
		path, got := repoPathCandidate(test.span, topLevel)
		if got != test.want || path != test.path {
			t.Errorf("repoPathCandidate(%q) = (%q, %v), want (%q, %v)", test.span, path, got, test.path, test.want)
		}
	}
}

func TestAgentDocPathsExist(t *testing.T) {
	root := repositoryRoot(t)
	topLevel := topLevelEntries(t, root)
	for _, doc := range agentDocs {
		content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(doc)))
		if err != nil {
			t.Errorf("%s: %v", doc, err)
			continue
		}
		inFence := false
		for index, line := range strings.Split(string(content), "\n") {
			lineNumber := index + 1
			if strings.HasPrefix(strings.TrimSpace(line), "```") {
				inFence = !inFence
				continue
			}
			if inFence {
				continue
			}
			// A span wrapped across lines flips the pairing of the backticks
			// after it and hides paths from this check.
			if strings.Count(line, "`")%2 != 0 {
				t.Errorf("%s:%d has an unbalanced inline code span; keep each span on one line", doc, lineNumber)
				continue
			}
			for _, match := range inlineCodeSpan.FindAllStringSubmatch(line, -1) {
				path, ok := repoPathCandidate(match[1], topLevel)
				if !ok {
					continue
				}
				if !repoPathExists(t, root, path) && !gitIgnores(t, root, path) {
					t.Errorf("%s:%d names `%s`, which does not exist in the repository", doc, lineNumber, match[1])
				}
			}
		}
	}
}

// The release procedure and the intentional fork behavior live outside
// AGENTS.md. Without a pointer from AGENTS.md no agent reaches them.
func TestAgentsDocPointsToMovedDocuments(t *testing.T) {
	root := repositoryRoot(t)
	assertFileContains(t, filepath.Join(root, "AGENTS.md"), []string{
		"`.claude/skills/release/SKILL.md`",
		"`.claude/skills/xray-pr-review/SKILL.md`",
		"`docs/FORK.md`",
	})
}

func topLevelEntries(t *testing.T, root string) map[string]bool {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	names := make(map[string]bool, len(entries))
	for _, entry := range entries {
		names[entry.Name()] = true
	}
	return names
}

// gitIgnores reports whether git ignores path. Agent documents name local
// assets such as resources/geoip.dat that a fresh checkout lacks on purpose;
// they are not missing repository material.
func gitIgnores(t *testing.T, root, path string) bool {
	t.Helper()
	err := exec.Command("git", "-C", root, "check-ignore", "-q", "--", path).Run()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return true
	case errors.As(err, &exit) && exit.ExitCode() == 1:
		return false
	default:
		t.Fatalf("git check-ignore %s: %v", path, err)
		return false
	}
}

func repoPathExists(t *testing.T, root, path string) bool {
	t.Helper()
	full := filepath.Join(root, filepath.FromSlash(path))
	if strings.Contains(path, "*") {
		matches, err := filepath.Glob(full)
		if err != nil {
			t.Fatalf("invalid pattern %q: %v", path, err)
		}
		return len(matches) > 0
	}
	_, err := os.Stat(full)
	return err == nil
}
