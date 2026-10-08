package release

import (
	"bytes"
	"fmt"
	"go/scanner"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strconv"
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
	var hits []fileTagsHit
	for _, path := range trackedFiles(t, root) {
		if tagsSkippedTree(path) {
			continue
		}
		content, ok := readTextFile(t, filepath.Join(root, filepath.FromSlash(path)))
		if !ok {
			continue
		}
		for _, hit := range findTagsWithoutHTTP2Legacy(path, content) {
			hits = append(hits, fileTagsHit{path: path, tagsHit: hit})
		}
	}
	violations, stale := applyTagsExemptions(hits, tagsExemptions)
	for _, hit := range violations {
		t.Errorf("%s:%d sets tags without %s: %s", hit.path, hit.line, requiredBuildTag, hit.text)
	}
	for _, message := range stale {
		t.Errorf("stale exemption %s; update tagsExemptions", message)
	}
}

// tagsSkippedTrees are not scanned at all.
var tagsSkippedTrees = []struct{ prefix, reason string }{
	{"third_party/", "vendored modules keep their upstream bytes (see third_party/reality/FORK.md)"},
	// The scanner's own fixtures contain deliberate violations.
	{"testing/release/build_tags_test.go", "scanner test cases"},
}

// tagsExemption allows known lines of one file that name tags without
// http2legacy. It lists each line's exact text, trimmed of surrounding
// space, once per occurrence. An edited or added line is therefore a
// violation, and a listed line that no longer appears makes the entry stale.
type tagsExemption struct {
	path   string
	reason string
	lines  []string
}

var tagsExemptions = []tagsExemption{
	// Interop peers are built the way their users build them. They are not Xray
	// builds, and http2legacy is an Xray build tag.
	{
		path:   ".github/workflows/pre-release-validation.yml",
		reason: "builds the sing-box interop peer",
		lines: []string{
			`go -C .interop/sing-box build -trimpath -tags=with_utls,with_quic -o "$RUNNER_TEMP/sing-box" ./cmd/sing-box`,
		},
	},
	{
		path:   "common/singmux/e2e_integration_test.go",
		reason: "builds the sing-box interop peer",
		lines: []string{
			`singBox: buildPeerE2EBinary(t, interop.SingBox, filepath.Join(workDir, "sing-box"), xrayRoot, "./cmd/sing-box", "-tags=with_utls,with_quic"),`,
		},
	},

	// Historical records. http2legacy joined the build on 2026-10-05
	// (b98f8a0a), and every command below is dated before it. Each one
	// records what a past run executed, so adding the tag would claim a run
	// that never happened. A command written into one of these files after the
	// cutover must list http2legacy.
	{
		path:   "common/log/BASELINE.md",
		reason: "gate commands recorded for the 2026-07-19 log change",
		lines: []string{
			`go test -tags integration ./common/singmux \`,
			`go test -tags integration ./common/singmux \`,
		},
	},
	{
		path:   "common/singmux/BASELINE.md",
		reason: "benchmark, stress, kernel and performance commands recorded between 2026-07-21 and 2026-09-05",
		lines: []string{
			`go test -tags 'integration stress' ./common/singmux \`,
			`go test -timeout=45m -tags "integration stress" ./common/singmux \`,
			`CGO_ENABLED=0 go test -c -tags 'integration brutalkernel' \`,
			`go test -timeout=45m -tags 'integration stress' ./common/singmux \`,
			"`go test -tags 'integration stress performance' ./common/singmux",
		},
	},
	{
		path:   "proxy/vless/BASELINE.md",
		reason: "benchmark and process-regression commands recorded on 2026-07-18 and 2026-08-25",
		lines: []string{
			`GOTOOLCHAIN=auto go test -tags integration ./common/singmux \`,
			`GOTOOLCHAIN=auto go test -tags integration ./common/singmux \`,
			`go test -tags integration ./common/singmux -run '^$' \`,
		},
	},
	{
		path:   "docs/audits/2026-09-04-fork-audit.md",
		reason: "dated audit; commands are the ones that audit ran",
		lines: []string{
			`go vet -tags integration,stress,performance ./common/singmux ./testing/release`,
			`go test -tags integration ./common/singmux \`,
			`go test -tags integration ./common/singmux -run '^TestVLESSTCPProcessMatrix/' -count=3 -v`,
			`go test -tags integration ./common/singmux \`,
			`go test -tags integration ./common/singmux -run '^TestRemnaNodeConfigProcessE2E$' -count=1 -v`,
			`go test -tags integration ./testing/scenarios -run '^TestReverseVersionSkew$' -count=1 -v`,
			`go test -tags integration,stress ./common/singmux \`,
			`go test -tags integration,stress ./common/singmux \`,
		},
	},
	{
		path:   "docs/audits/2026-09-05-review-followup.md",
		reason: "dated audit follow-up; commands are the ones it ran",
		lines: []string{
			`go test -tags integration ./common/singmux -run '^TestAwaitStatsOnlineIPs' -count=1`,
			`go test -race -tags integration ./common/singmux -run '^TestAwaitStatsOnlineIPs' -count=1`,
			`go vet -tags integration,stress,performance ./common/singmux`,
			`go test -tags integration ./common/singmux \`,
			`go test -tags integration ./common/singmux -run '^TestVLESSTCPProcessMatrix/' -count=3 -v`,
			`go test -tags integration ./common/singmux -run '^TestSMUXProcessInteropMatrix$' -count=1 -v`,
			`go vet -tags integration ./main ./proxy/mtproxy`,
			`go test -tags integration ./proxy/mtproxy \`,
			`go test -race -tags integration ./proxy/mtproxy -run '^TestMTProxySubprocess$' -count=1 -v`,
			`go test -gcflags=all=-d=checkptr=2 -tags integration ./proxy/mtproxy \`,
		},
	},
	{
		path:   "docs/superpowers/plans/2026-08-11-smux-brutal-server.md",
		reason: "dated implementation plan; commands are the ones the plan listed",
		lines: []string{
			`go test -tags integration ./common/singmux -run '^TestSMUXProcessInteropMatrix$' -count=1 -v`,
			`go test -tags integration ./common/singmux -run '^TestH2MUXProcessInteropMatrix$' -count=1 -v`,
		},
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

type tagsHit struct {
	line int
	text string
}

type fileTagsHit struct {
	path string
	tagsHit
}

// applyTagsExemptions returns the hits no exemption line covers, and one
// message per exempted line that was found fewer times than listed.
func applyTagsExemptions(hits []fileTagsHit, exemptions []tagsExemption) ([]fileTagsHit, []string) {
	type exemptLine struct{ path, text string }
	remaining := make(map[exemptLine]int)
	for _, exemption := range exemptions {
		for _, line := range exemption.lines {
			remaining[exemptLine{exemption.path, line}]++
		}
	}
	var violations []fileTagsHit
	for _, hit := range hits {
		key := exemptLine{hit.path, hit.text}
		if remaining[key] > 0 {
			remaining[key]--
			continue
		}
		violations = append(violations, hit)
	}
	var stale []string
	for _, exemption := range exemptions {
		reported := make(map[string]bool)
		for _, line := range exemption.lines {
			missing := remaining[exemptLine{exemption.path, line}]
			if missing == 0 || reported[line] {
				continue
			}
			reported[line] = true
			listed := 0
			for _, other := range exemption.lines {
				if other == line {
					listed++
				}
			}
			stale = append(stale, fmt.Sprintf("%s: %q listed %d times, found %d (%s)", exemption.path, line, listed, listed-missing, exemption.reason))
		}
	}
	return violations, stale
}

var (
	// tagsFlagWithValue finds `-tags VALUE` and `-tags=VALUE` in shell, YAML,
	// Markdown, Dockerfile and Go text. The flag needs a value after it, so
	// prose that only names the flag in backticks does not match.
	tagsFlagWithValue = regexp.MustCompile("(?:^|[\\s`\"'(=:])-tags(?:=|\\s+)(\"[^\"]*\"|'[^']*'|[^\\s\"'`]+)")
	// tagsFlagEndingLine finds a `-tags` flag whose value is not on the same
	// line, which this scan cannot read.
	tagsFlagEndingLine = regexp.MustCompile("(?:^|[\\s`\"'(=:])-tags\\s*\\\\?\\s*$")
)

// findTagsWithoutHTTP2Legacy returns the lines of one file that pass a tag
// list without http2legacy, or a tag list it cannot read. Go files are also
// read token by token for exec'd go commands that pass the flag as a string
// literal.
func findTagsWithoutHTTP2Legacy(path, content string) []tagsHit {
	lines := strings.Split(content, "\n")
	flagged := map[int]bool{}
	for index, line := range lines {
		if tagsFlagEndingLine.MatchString(line) {
			flagged[index+1] = true
			continue
		}
		for _, match := range tagsFlagWithValue.FindAllStringSubmatch(line, -1) {
			if !slices.Contains(tagsOfValue(match[1]), requiredBuildTag) {
				flagged[index+1] = true
			}
		}
	}
	if strings.HasSuffix(path, ".go") {
		for _, line := range goTagsWithoutHTTP2Legacy(content) {
			flagged[line] = true
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

// tagsOfValue splits a -tags value found in text. A quoted value is one shell
// word and is read as written. An unquoted value may run into a shell `;` or
// the `)` that closes $(...), which are not part of its last tag. Any other
// trailing character stays in the tag: `go build -tags http2legacy.` builds
// without http2legacy, so prose wraps such a flag in backticks.
func tagsOfValue(value string) []string {
	if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
		return splitTags(value[1 : len(value)-1])
	}
	return splitTags(strings.TrimRight(value, ";)"))
}

func splitTags(list string) []string {
	return strings.FieldsFunc(list, func(r rune) bool {
		return r == ',' || unicode.IsSpace(r)
	})
}

// goTagsWithoutHTTP2Legacy reads Go source token by token and returns the
// lines of string literals, interpreted or raw, that give a go command a tag
// list without http2legacy: "-tags=VALUE", "-tags VALUE", or "-tags" whose
// value is the next argument. A next argument that is not a string literal
// cannot be read and is reported. Comments are not tokens, so prose that
// names the flag is never read as an argument.
func goTagsWithoutHTTP2Legacy(content string) []int {
	if !strings.Contains(content, "-tags") {
		return nil
	}
	fileSet := token.NewFileSet()
	file := fileSet.AddFile("", fileSet.Base(), len(content))
	var source scanner.Scanner
	source.Init(file, []byte(content), nil, 0)
	scan := func() (int, token.Token, string) {
		position, kind, literal := source.Scan()
		return fileSet.Position(position).Line, kind, literal
	}
	stringValue := func(kind token.Token, literal string) (string, bool) {
		if kind != token.STRING {
			return "", false
		}
		value, err := strconv.Unquote(literal)
		return value, err == nil
	}
	var lines []int
	for {
		line, kind, literal := scan()
		if kind == token.EOF {
			return lines
		}
		text, ok := stringValue(kind, literal)
		if !ok {
			continue
		}
		var list string
		if rest, found := strings.CutPrefix(text, "-tags"); !found {
			continue
		} else if value, isJoined := strings.CutPrefix(rest, "="); isJoined {
			list = value
		} else if rest != "" && unicode.IsSpace(rune(rest[0])) {
			list = rest
		} else if rest == "" {
			_, separator, _ := scan()
			_, valueKind, valueLiteral := scan()
			value, readable := stringValue(valueKind, valueLiteral)
			if separator != token.COMMA || !readable {
				lines = append(lines, line)
				continue
			}
			list = value
		} else {
			continue // another flag, such as -tagsfoo
		}
		if !slices.Contains(splitTags(list), requiredBuildTag) {
			lines = append(lines, line)
		}
	}
}

// An exemption covers the exact lines it lists, each as often as listed. A
// historical command replaced by a new one without http2legacy is a new
// violation, and a listed line that no longer appears is a stale exemption.
func TestApplyTagsExemptions(t *testing.T) {
	exemptions := []tagsExemption{{path: "doc.md", lines: []string{"go test -tags a ./x", "go test -tags a ./x"}, reason: "old"}}
	hits := []fileTagsHit{
		{path: "doc.md", tagsHit: tagsHit{line: 1, text: "go test -tags a ./x"}},
		{path: "doc.md", tagsHit: tagsHit{line: 2, text: "go test -tags b ./x"}},
		{path: "other.md", tagsHit: tagsHit{line: 3, text: "go test -tags a ./x"}},
	}
	violations, stale := applyTagsExemptions(hits, exemptions)
	var got []string
	for _, hit := range violations {
		got = append(got, fmt.Sprintf("%s:%d", hit.path, hit.line))
	}
	if want := []string{"doc.md:2", "other.md:3"}; !reflect.DeepEqual(got, want) {
		t.Errorf("violations = %v, want %v", got, want)
	}
	if want := []string{`doc.md: "go test -tags a ./x" listed 2 times, found 1 (old)`}; !reflect.DeepEqual(stale, want) {
		t.Errorf("stale = %q, want %q", stale, want)
	}
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
		{"prose with the flag in backticks before a period", "doc.md", "Builds use `-tags http2legacy`. Without it", nil},
		{"unquoted tag with a period is another tag", "run.sh", "go build -tags http2legacy. ./x", []int{1}},
		{"quoted tag list ending with punctuation", "run.sh", "go test -tags 'integration http2legacy.' ./x\ngo test -tags 'http2legacy;' ./x\ngo test -tags \"http2legacy)\" ./x", []int{1, 2, 3}},
		{"shell separator after an unquoted list", "run.sh", "go build -tags http2legacy; echo built", nil},
		{"command substitution closing after an unquoted list", "run.sh", "version=$(go list -tags http2legacy)", nil},
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
		{"go comment quoting the flag", "x.go", "// The \"-tags\" flag replaces GOFLAGS.", nil},
		{"go exec raw-string flag with a comment before its value", "x.go", "exec.Command(\"go\", \"test\", `-tags` /* why */, `integration`, \"./x\")", []int{1}},
		{"go exec quoted flag with a comment before its value", "x.go", "exec.Command(\"go\", \"test\", \"-tags\", // why\n\t\"integration http2legacy\", \"./x\")", nil},
		{"go exec quoted tag value ending with punctuation", "x.go", `exec.Command("go", "build", "-tags", "integration http2legacy.", "./x")`, []int{1}},
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
