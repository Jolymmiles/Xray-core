package release

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// These tests run testing/setup-worktree.sh and testing/gates.sh in a scratch
// repository with one linked worktree, so the geodata in the main checkout and
// in the worktree is under the test's control.

// A worktree that holds its own geodata is ready even when the main checkout
// has none. Failing it here stops every gates.sh tier before any test runs.
var geodataAssets = []string{"geoip.dat", "geosite.dat"}

func TestSetupWorktreeKeepsOwnGeodataWithoutMainCopy(t *testing.T) {
	scratch := newScratchWorktree(t)
	for _, asset := range geodataAssets {
		writeScratchFile(t, filepath.Join(scratch.worktree, "resources", asset), "local geodata", 0o644)
	}
	output, err := scratch.run(t, "testing/setup-worktree.sh")
	if err != nil {
		t.Fatalf("setup-worktree.sh: %v\n%s", err, output)
	}
	if kept := strings.Count(output, "kept the existing file"); kept != 2 {
		t.Fatalf("setup-worktree.sh kept %d files, want 2:\n%s", kept, output)
	}
}

func TestSetupWorktreeFailsWithoutAnyGeodata(t *testing.T) {
	scratch := newScratchWorktree(t)
	output, err := scratch.run(t, "testing/setup-worktree.sh")
	if code := scriptExitCode(t, err); code != 1 {
		t.Fatalf("setup-worktree.sh exit code = %d, want 1:\n%s", code, output)
	}
	if missing := strings.Count(output, "missing "); missing != 2 {
		t.Fatalf("setup-worktree.sh reported %d missing files, want 2:\n%s", missing, output)
	}
}

// Empty geodata is missing geodata, also when the script runs in the main
// checkout itself or the worktree links to an emptied main file.
func TestSetupWorktreeRejectsEmptyGeodata(t *testing.T) {
	scratch := newScratchWorktree(t)
	for _, asset := range geodataAssets {
		writeScratchFile(t, filepath.Join(scratch.main, "resources", asset), "main geodata", 0o644)
	}
	if output, err := scratch.runFrom(t, scratch.worktree, "testing/setup-worktree.sh"); err != nil {
		t.Fatalf("setup-worktree.sh: %v\n%s", err, output)
	}
	for _, asset := range geodataAssets {
		writeScratchFile(t, filepath.Join(scratch.main, "resources", asset), "", 0o644)
	}
	for _, directory := range []string{scratch.main, scratch.worktree} {
		output, err := scratch.runFrom(t, directory, "testing/setup-worktree.sh")
		if code := scriptExitCode(t, err); code != 1 || strings.Count(output, "missing ") != 2 {
			t.Errorf("setup-worktree.sh in %s with empty geodata: exit code %d, want 1 and two missing files:\n%s", directory, code, output)
		}
	}
}

// After a linking run, --copy turns the links into copies. A link left in
// place loses the data when the main checkout's file goes away.
func TestSetupWorktreeCopyReplacesExistingLinks(t *testing.T) {
	scratch := newScratchWorktree(t)
	for _, asset := range geodataAssets {
		writeScratchFile(t, filepath.Join(scratch.main, "resources", asset), "main geodata", 0o644)
	}
	for _, args := range [][]string{nil, {"--copy"}} {
		if output, err := scratch.run(t, "testing/setup-worktree.sh", args...); err != nil {
			t.Fatalf("setup-worktree.sh %v: %v\n%s", args, err, output)
		}
	}
	for _, asset := range geodataAssets {
		path := filepath.Join(scratch.worktree, "resources", asset)
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if !info.Mode().IsRegular() {
			t.Errorf("%s has mode %v after --copy, want a regular file", path, info.Mode())
			continue
		}
		if content, err := os.ReadFile(path); err != nil || string(content) != "main geodata" {
			t.Errorf("%s = %q (%v), want the main checkout's content", path, content, err)
		}
	}
}

// Help and a mistyped tier must not depend on test prerequisites: gates.sh
// reads its arguments before it prepares the worktree or creates a log
// directory.
func TestGatesReadsArgumentsBeforeSetup(t *testing.T) {
	scratch := newScratchWorktree(t)
	for _, test := range []struct {
		argument string
		code     int
		want     string
	}{
		{"--help", 0, "usage: testing/gates.sh"},
		{"nosuchtier", 2, "unknown tier: nosuchtier"},
	} {
		output, err := scratch.run(t, "testing/gates.sh", test.argument)
		if code := scriptExitCode(t, err); code != test.code || !strings.Contains(output, test.want) {
			t.Errorf("gates.sh %s: exit code %d, want %d with %q:\n%s", test.argument, code, test.code, test.want, output)
		}
	}
	if _, err := os.Stat(scratch.logDir); !os.IsNotExist(err) {
		t.Errorf("gates.sh created %s before reading its arguments (stat: %v)", scratch.logDir, err)
	}
}

// A tier named twice, directly and through "all", runs once; a second run
// would truncate the first run's log.
func TestGatesRunsEachTierOnce(t *testing.T) {
	scratch := newScratchWorktree(t)
	scratch.useFakeGo(t)
	for _, asset := range geodataAssets {
		writeScratchFile(t, filepath.Join(scratch.worktree, "resources", asset), "local geodata", 0o644)
	}
	output, err := scratch.run(t, "testing/gates.sh", "unit", "all", "unit")
	if err != nil {
		t.Fatalf("gates.sh unit all unit: %v\n%s", err, output)
	}
	for _, tier := range []string{"unit", "vless", "smux", "xhttp"} {
		if runs := strings.Count(output, "== "+tier+"\n"); runs != 1 {
			t.Errorf("tier %s ran %d times, want 1:\n%s", tier, runs, output)
		}
	}
}

type scratchWorktree struct {
	main     string
	worktree string
	logDir   string // GATES_LOG_DIR for gates.sh; not created by the test
	env      []string
}

func newScratchWorktree(t *testing.T) scratchWorktree {
	t.Helper()
	root := repositoryRoot(t)
	base := t.TempDir()
	mainCheckout := filepath.Join(base, "main")
	for _, script := range []string{"setup-worktree.sh", "gates.sh"} {
		content, err := os.ReadFile(filepath.Join(root, "testing", script))
		if err != nil {
			t.Fatal(err)
		}
		writeScratchFile(t, filepath.Join(mainCheckout, "testing", script), string(content), 0o755)
	}
	writeScratchFile(t, filepath.Join(mainCheckout, ".gitignore"), "/resources/*.dat\n", 0o644)

	scratch := scratchWorktree{
		main:     mainCheckout,
		worktree: filepath.Join(base, "worktree"),
		logDir:   filepath.Join(base, "logs"),
		env:      isolatedGitEnv(),
	}
	for _, args := range [][]string{
		{"init", "-q"},
		{"add", "."},
		{"commit", "-q", "-m", "scratch"},
		{"worktree", "add", "-q", "--detach", scratch.worktree},
	} {
		command := exec.Command("git", args...)
		command.Dir = mainCheckout
		command.Env = scratch.env
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, output)
		}
	}
	return scratch
}

// run executes a script of the scratch worktree from the worktree root and
// returns its combined output. A non-zero exit is returned as the error.
func (scratch scratchWorktree) run(t *testing.T, script string, args ...string) (string, error) {
	t.Helper()
	return scratch.runFrom(t, scratch.worktree, script, args...)
}

// runFrom is run from directory, the scratch main checkout or worktree.
func (scratch scratchWorktree) runFrom(t *testing.T, directory, script string, args ...string) (string, error) {
	t.Helper()
	command := exec.Command("bash", append([]string{script}, args...)...)
	command.Dir = directory
	command.Env = append(scratch.env, "GATES_LOG_DIR="+scratch.logDir)
	output, err := command.CombinedOutput()
	return string(output), err
}

// useFakeGo puts first on PATH a go command that only prints its arguments,
// so gates.sh walks every step of a tier without building or testing.
func (scratch *scratchWorktree) useFakeGo(t *testing.T) {
	t.Helper()
	bin := t.TempDir()
	writeScratchFile(t, filepath.Join(bin, "go"), "#!/bin/sh\necho \"fake go $*\"\n", 0o755)
	for index, variable := range scratch.env {
		if path, ok := strings.CutPrefix(variable, "PATH="); ok {
			scratch.env[index] = "PATH=" + bin + string(os.PathListSeparator) + path
			return
		}
	}
	scratch.env = append(scratch.env, "PATH="+bin)
}

// isolatedGitEnv keeps the caller's git configuration and repository
// variables (GIT_DIR when run from a hook) out of the scratch repository.
func isolatedGitEnv() []string {
	var env []string
	for _, variable := range os.Environ() {
		if !strings.HasPrefix(variable, "GIT_") {
			env = append(env, variable)
		}
	}
	return append(env,
		"GIT_CONFIG_GLOBAL="+os.DevNull,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=scratch",
		"GIT_AUTHOR_EMAIL=scratch@example.invalid",
		"GIT_COMMITTER_NAME=scratch",
		"GIT_COMMITTER_EMAIL=scratch@example.invalid",
	)
}

func writeScratchFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

// scriptExitCode returns the exit code of a finished script; it fails the
// test when the script could not run at all.
func scriptExitCode(t *testing.T, err error) int {
	t.Helper()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &exit):
		return exit.ExitCode()
	default:
		t.Fatalf("run script: %v", err)
		return -1
	}
}
