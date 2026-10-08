package release

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
	"unicode"
)

// requiredBuildTag is the tag every Xray build, test and vet command that
// names its own tags must list (XTLS/Xray-core#6797).
const requiredBuildTag = "http2legacy"

// An explicit `-tags` flag replaces the tags in GOFLAGS instead of adding to
// them, so every command that names its own tags must list http2legacy too.
// TestExplicitBuildTagsKeepHTTP2Legacy walks every file in `git ls-files`, so
// a new script, workflow, document or exec'd go command is covered without
// editing a file list. Run it with -count=1: the go test cache does not notice
// a newly added file.
func TestExplicitBuildTagsKeepHTTP2Legacy(t *testing.T) {
	root := repositoryRoot(t)
	exemptionHits := make([]int, len(tagsExemptions))
	for _, path := range trackedFiles(t, root) {
		if tagsSkippedTree(path) {
			continue
		}
		content, ok := readTextFile(t, filepath.Join(root, filepath.FromSlash(path)))
		if !ok {
			continue
		}
		for _, hit := range findTagsWithoutHTTP2Legacy(path, content) {
			if index := matchTagsExemption(path, hit.text); index >= 0 {
				exemptionHits[index]++
				continue
			}
			t.Errorf("%s:%d sets tags without %s: %s", path, hit.line, requiredBuildTag, hit.text)
		}
	}
	for index, exemption := range tagsExemptions {
		switch {
		case exemptionHits[index] == 0:
			t.Errorf("stale exemption: %s %q matched nothing; remove it (%s)", exemption.path, exemption.contains, exemption.reason)
		case exemption.count > 0 && exemptionHits[index] != exemption.count:
			t.Errorf("exemption %s %q covers %d lines, want exactly %d; new lines must list %s (%s)",
				exemption.path, exemption.contains, exemptionHits[index], exemption.count, requiredBuildTag, exemption.reason)
		}
	}
}

// tagsSkippedTrees are not scanned at all.
var tagsSkippedTrees = []struct{ prefix, reason string }{
	{"third_party/", "vendored modules keep their upstream bytes (see third_party/reality/FORK.md)"},
	// The scanner's own fixtures contain deliberate violations.
	{"testing/release/build_tags_test.go", "scanner test cases"},
}

// tagsExemption allows known lines that name tags without http2legacy.
// Every entry must still match at least one line, and an entry with count set
// must match exactly that many, so an exemption cannot hide a new violation.
type tagsExemption struct {
	path     string // repository file path, or a directory prefix ending in "/"
	contains string // substring of the offending line; empty exempts every hit under path
	count    int    // exact number of covered lines; 0 means at least one
	reason   string
}

var tagsExemptions = []tagsExemption{
	// Interop peers are built the way their users build them. They are not Xray
	// builds, and http2legacy is an Xray build tag.
	{
		path:     ".github/workflows/pre-release-validation.yml",
		contains: "with_utls,with_quic",
		count:    1,
		reason:   "builds the sing-box interop peer",
	},
	{
		path:     "common/singmux/e2e_integration_test.go",
		contains: "with_utls,with_quic",
		count:    1,
		reason:   "builds the sing-box interop peer",
	},

	// Historical records. http2legacy joined the build on 2026-10-05
	// (b98f8a0a), and every command below is dated before it. Each one
	// records what a past run executed, so adding the tag would claim a run
	// that never happened. The counts are exact: a new command written into
	// one of these files after the cutover must list http2legacy, and a
	// command that is removed or fixed must lower its count.
	{
		path:   "common/log/BASELINE.md",
		count:  2,
		reason: "gate commands recorded for the 2026-07-19 log change",
	},
	{
		path:   "common/singmux/BASELINE.md",
		count:  5,
		reason: "benchmark, stress, kernel and performance commands recorded between 2026-07-21 and 2026-09-05",
	},
	{
		path:   "proxy/vless/BASELINE.md",
		count:  3,
		reason: "benchmark and process-regression commands recorded on 2026-07-18 and 2026-08-25",
	},
	{
		path:   "docs/audits/2026-09-04-fork-audit.md",
		count:  8,
		reason: "dated audit; commands are the ones that audit ran",
	},
	{
		path:   "docs/audits/2026-09-05-review-followup.md",
		count:  10,
		reason: "dated audit follow-up; commands are the ones it ran",
	},
	{
		path:   "docs/superpowers/plans/2026-08-11-smux-brutal-server.md",
		count:  2,
		reason: "dated implementation plan; commands are the ones the plan listed",
	},
}

func tagsSkippedTree(path string) bool {
	for _, tree := range tagsSkippedTrees {
		if strings.HasPrefix(path, tree.prefix) {
			return true
		}
	}
	return false
}

func matchTagsExemption(path, text string) int {
	for index, exemption := range tagsExemptions {
		inPath := path == exemption.path || (strings.HasSuffix(exemption.path, "/") && strings.HasPrefix(path, exemption.path))
		if inPath && strings.Contains(text, exemption.contains) {
			return index
		}
	}
	return -1
}

type tagsHit struct {
	line int
	text string
}

var (
	// tagsFlagWithValue finds `-tags VALUE` and `-tags=VALUE` in shell, YAML,
	// Markdown, Dockerfile and Go text. The flag needs a value after it, so
	// prose that only names the flag in backticks does not match.
	tagsFlagWithValue = regexp.MustCompile("(?:^|[\\s`\"'(=:])-tags(?:=|\\s+)(\"[^\"]*\"|'[^']*'|[^\\s\"'`]+)")
	// tagsFlagEndingLine finds a `-tags` flag whose value is not on the same
	// line, which this scan cannot read.
	tagsFlagEndingLine = regexp.MustCompile("(?:^|[\\s`\"'(=:])-tags\\s*\\\\?\\s*$")
	// goTagsFlag starts a Go string literal, interpreted or raw, that opens
	// with the flag.
	goTagsFlag = regexp.MustCompile("[\"`]-tags")
	// goTagsArgument reads an exec argument list: "-tags=VALUE" or "-tags", "VALUE",
	// and a literal that holds a whole flag: "-tags VALUE". Either literal may
	// be a raw string.
	goTagsArgument = regexp.MustCompile("^[\"`]-tags(?:=([^\"`]*)[\"`]|\\s+([^\"`]*)[\"`]|[\"`]\\s*,\\s*[\"`]([^\"`]*)[\"`])")
	// goRawTagsInArguments is a raw-string flag followed by another argument.
	// Any other unreadable raw `-tags` is prose in a comment.
	goRawTagsInArguments = regexp.MustCompile("^`-tags`\\s*,")
)

// findTagsWithoutHTTP2Legacy returns the lines of one file that pass a tag
// list without http2legacy, or a tag list it cannot read. Go files are also
// checked for exec'd go commands that pass "-tags" as separate arguments.
func findTagsWithoutHTTP2Legacy(path, content string) []tagsHit {
	lines := strings.Split(content, "\n")
	flagged := map[int]bool{}
	for index, line := range lines {
		if tagsFlagEndingLine.MatchString(line) {
			flagged[index+1] = true
			continue
		}
		for _, match := range tagsFlagWithValue.FindAllStringSubmatch(line, -1) {
			if !listsHTTP2Legacy(match[1]) {
				flagged[index+1] = true
			}
		}
	}
	if strings.HasSuffix(path, ".go") {
		for _, location := range goTagsFlag.FindAllStringIndex(content, -1) {
			start := location[0]
			match := goTagsArgument.FindStringSubmatch(content[start:])
			switch {
			case match != nil && listsHTTP2Legacy(match[1]+match[2]+match[3]):
			case match == nil && content[start] == '`' && !goRawTagsInArguments.MatchString(content[start:]):
			default:
				flagged[1+strings.Count(content[:start], "\n")] = true
			}
		}
	}
	numbers := make([]int, 0, len(flagged))
	for number := range flagged {
		numbers = append(numbers, number)
	}
	sort.Ints(numbers)
	hits := make([]tagsHit, 0, len(numbers))
	for _, number := range numbers {
		hits = append(hits, tagsHit{line: number, text: strings.TrimSpace(lines[number-1])})
	}
	return hits
}

func listsHTTP2Legacy(value string) bool {
	tags := strings.FieldsFunc(strings.Trim(value, `"'`), func(r rune) bool {
		return r == ',' || unicode.IsSpace(r)
	})
	for _, tag := range tags {
		// Prose may end the tag list with punctuation: "built with -tags http2legacy."
		if strings.TrimRight(tag, ".;:)") == requiredBuildTag {
			return true
		}
	}
	return false
}

func TestFindTagsWithoutHTTP2Legacy(t *testing.T) {
	for _, test := range []struct {
		name    string
		path    string
		content string
		want    []int
	}{
		{"shell with tag", "run.sh", "go test -tags 'integration http2legacy' ./x\n", nil},
		{"shell without tag", "run.sh", "ok\ngo test -tags integration ./x\n", []int{2}},
		{"double quoted without tag", "run.sh", `go test -tags "integration stress" ./x`, []int{1}},
		{"comma list with tag", "doc.md", "go test -tags=integration,http2legacy ./x", nil},
		{"comma list without tag", "doc.md", "go test -tags integration,stress ./x", []int{1}},
		{"tag as substring only", "doc.md", "go test -tags=http2legacy_off ./x", []int{1}},
		{"prose ending the tag list with a period", "doc.md", "Builds use -tags http2legacy. Without it", nil},
		{"prose naming another tag with a period", "doc.md", "Builds use -tags integration. Without it", []int{1}},
		{"goflags in yaml", "ci.yml", "  GOFLAGS: -tags=http2legacy\n", nil},
		{"goflags in shell", "run.sh", `export GOFLAGS="${GOFLAGS:+${GOFLAGS} }-tags=http2legacy"`, nil},
		{"goflags without tag", "run.sh", "export GOFLAGS=-tags=integration", []int{1}},
		{"dockerfile", "Dockerfile", "RUN go build -tags http2legacy -o xray ./main", nil},
		{"prose naming the flag", "AGENTS.md", "An explicit `-tags` replaces the tags in `GOFLAGS`.", nil},
		{"flag ending the line", "run.sh", "go test -tags \\\n  'integration' ./x", []int{1}},
		{"variable value", "run.sh", `go build -tags "$TAGS" ./x`, []int{1}},
		{"go exec separate arguments with tag", "x.go", `exec.Command("go", "test", "-tags", "coverage http2legacy", "-c")`, nil},
		{"go exec separate arguments without tag", "x.go", "exec.Command(\"go\", \"test\",\n\t\"-tags\", \"coverage\", \"-c\")", []int{2}},
		{"go exec joined argument without tag", "x.go", `exec.Command("go", "build", "-tags=with_utls", "./x")`, []int{1}},
		{"go exec non-literal value", "x.go", `exec.Command("go", "build", "-tags", tags, "./x")`, []int{1}},
		{"go exec joined argument with tag", "x.go", `exec.Command("go", "build", "-tags=http2legacy", "./x")`, nil},
		{"go exec raw-string arguments without tag", "x.go", "exec.Command(\"go\", \"build\", `-tags`, `integration`, \"./x\")", []int{1}},
		{"go exec raw-string arguments with tag", "x.go", "exec.Command(\"go\", \"build\", `-tags`, `integration http2legacy`, \"./x\")", nil},
		{"go exec raw-string flag and quoted value without tag", "x.go", "exec.Command(\"go\", \"build\", `-tags`, \"integration\", \"./x\")", []int{1}},
		{"go exec quoted flag and raw-string value with tag", "x.go", "exec.Command(\"go\", \"build\", \"-tags\", `integration http2legacy`, \"./x\")", nil},
		{"go raw-string literal holding flag and value without tag", "x.go", "{`-tags integration`, \"\", false},", []int{1}},
		{"go exec raw-string flag with non-literal value", "x.go", "exec.Command(\"go\", \"build\", `-tags`, tags, \"./x\")", []int{1}},
		{"go comment naming the flag", "x.go", "// An explicit `-tags` flag replaces the tags in GOFLAGS.", nil},
		{"go literal holding flag and value with tag", "x.go", `{"-tags http2legacy", "", false},`, nil},
		{"go literal holding flag and value without tag", "x.go", `{"-tags integration", "", false},`, []int{1}},
		{"go argument form is not read outside go files", "doc.md", `"-tags", "coverage"`, nil},
		{"no tags at all", "run.sh", "go test ./...", nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			var got []int
			for _, hit := range findTagsWithoutHTTP2Legacy(test.path, test.content) {
				got = append(got, hit.line)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("lines = %v, want %v", got, test.want)
			}
		})
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("source path unavailable")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", ".."))
}

// trackedFiles lists the files git tracks plus the untracked files it does not
// ignore, as slash-separated paths relative to root. The untracked files are
// what the next `git add` would stage, so a new script or document is checked
// before it is committed.
func trackedFiles(t *testing.T, root string) []string {
	t.Helper()
	command := exec.Command("git", "-C", root, "ls-files", "-z", "--cached", "--others", "--exclude-standard")
	var stderr bytes.Buffer
	command.Stderr = &stderr
	output, err := command.Output()
	if err != nil {
		t.Fatalf("list tracked files in %s: %v\n%s", root, err, stderr.String())
	}
	var paths []string
	for _, path := range strings.Split(string(output), "\x00") {
		if path != "" {
			paths = append(paths, path)
		}
	}
	if len(paths) == 0 {
		t.Fatalf("git ls-files in %s returned no files", root)
	}
	return paths
}

// readTextFile returns the content of a regular text file. It reports false
// for symlinks, submodules, files deleted from the work tree and binary files.
func readTextFile(t *testing.T, path string) (string, bool) {
	t.Helper()
	info, err := os.Lstat(path)
	if os.IsNotExist(err) || (err == nil && !info.Mode().IsRegular()) {
		return "", false
	}
	if err != nil {
		t.Fatal(fmt.Errorf("stat tracked file: %w", err))
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(fmt.Errorf("read tracked file: %w", err))
	}
	if bytes.IndexByte(content[:min(len(content), 8000)], 0) >= 0 {
		return "", false
	}
	return string(content), true
}
