// Package interop locates the source trees of the client peers (sing-box,
// Mihomo) that the process-level interoperability tests build and run against
// the Xray server.
//
// The tests are run from the main checkout and from linked git worktrees that
// live anywhere on disk (for example under /tmp or an agent runner's own
// directory). A peer checked out next to the main checkout must therefore be
// found from a worktree too, which is why the main checkout is recovered
// through the git common directory instead of the worktree's own path.
package interop

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
)

// SourceDir returns the directory holding the Go module of the peer called
// name (the directory name, such as "sing-box" or "mihomo"). repoRoot is the
// root of the Xray checkout the test runs from. environment is the variable
// that overrides the build with a prebuilt binary; it only appears in the
// error message, the caller applies the override before calling SourceDir.
//
// Candidates are tried in this order, and the first directory that contains a
// go.mod wins:
//
//  1. a sibling of repoRoot,
//  2. a sibling of repoRoot's parent,
//  3. a sibling of the main checkout (the parent of the git common directory),
//  4. a sibling of the main checkout's parent.
//
// Candidates 3 and 4 only exist when git can name the main checkout. If no
// candidate qualifies, the error lists every path tried.
func SourceDir(repoRoot, name, environment string) (string, error) {
	mainRoot, mainErr := mainCheckout(repoRoot)
	candidates := sourceCandidates(repoRoot, mainRoot, name)
	for _, candidate := range candidates {
		if isGoModule(candidate) {
			return candidate, nil
		}
	}
	return "", notFoundError(name, environment, candidates, mainErr)
}

// sourceCandidates lists the directories SourceDir tries, in order and
// without duplicates. mainRoot is empty when the main checkout is unknown.
func sourceCandidates(repoRoot, mainRoot, name string) []string {
	var roots []string
	for _, root := range []string{repoRoot, mainRoot} {
		if root == "" {
			continue
		}
		parent := filepath.Dir(root)
		roots = append(roots, parent, filepath.Dir(parent))
	}
	var candidates []string
	seen := make(map[string]bool)
	for _, root := range roots {
		candidate := filepath.Join(root, name)
		if !seen[candidate] {
			seen[candidate] = true
			candidates = append(candidates, candidate)
		}
	}
	return candidates
}

// mainCheckout returns the root of the main checkout that repoRoot belongs
// to. For the main checkout itself this is repoRoot; for a linked worktree it
// is the checkout that owns the shared .git directory.
func mainCheckout(repoRoot string) (string, error) {
	command := exec.Command("git", "-C", repoRoot, "rev-parse", "--path-format=absolute", "--git-common-dir")
	command.Env = withoutRepositoryVariables(os.Environ())
	output, err := command.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && len(exitErr.Stderr) != 0 {
			return "", fmt.Errorf("git rev-parse --git-common-dir in %s: %w: %s", repoRoot, err, strings.TrimSpace(string(exitErr.Stderr)))
		}
		return "", fmt.Errorf("git rev-parse --git-common-dir in %s: %w", repoRoot, err)
	}
	commonDir := strings.TrimSpace(string(output))
	if filepath.Base(commonDir) != ".git" {
		return "", fmt.Errorf("git common directory %q is not <checkout>/.git", commonDir)
	}
	return filepath.Dir(commonDir), nil
}

// repositoryVariables name a repository regardless of `git -C`, and a git hook
// exports them to the commands it runs. They are the location variables that
// `git rev-parse --local-env-vars` lists.
var repositoryVariables = []string{
	"GIT_ALTERNATE_OBJECT_DIRECTORIES",
	"GIT_COMMON_DIR",
	"GIT_DIR",
	"GIT_GRAFT_FILE",
	"GIT_IMPLICIT_WORK_TREE",
	"GIT_INDEX_FILE",
	"GIT_NO_REPLACE_OBJECTS",
	"GIT_OBJECT_DIRECTORY",
	"GIT_PREFIX",
	"GIT_REPLACE_REF_BASE",
	"GIT_SHALLOW_FILE",
	"GIT_WORK_TREE",
}

func withoutRepositoryVariables(environment []string) []string {
	kept := make([]string, 0, len(environment))
	for _, variable := range environment {
		name, _, _ := strings.Cut(variable, "=")
		if !slices.Contains(repositoryVariables, name) {
			kept = append(kept, variable)
		}
	}
	return kept
}

func isGoModule(directory string) bool {
	info, err := os.Stat(filepath.Join(directory, "go.mod"))
	return err == nil && info.Mode().IsRegular()
}

func notFoundError(name, environment string, candidates []string, mainErr error) error {
	var message strings.Builder
	fmt.Fprintf(&message, "%s source not found (no directory with a go.mod at any of these paths):\n", name)
	for _, candidate := range candidates {
		fmt.Fprintf(&message, "  %s\n", candidate)
	}
	if mainErr != nil {
		fmt.Fprintf(&message, "main checkout lookup failed: %v\n", mainErr)
	}
	fmt.Fprintf(&message, "Clone %s to one of those paths, or set %s to a prebuilt %s binary", name, environment, name)
	message.WriteString(" (XRAY_E2E_BIN, SING_BOX_E2E_BIN and MIHOMO_E2E_BIN each replace one build).")
	return errors.New(message.String())
}
