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
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Peer is a client that the interop tests build from its source checkout.
type Peer struct {
	Name        string // directory name of the checkout
	Module      string // module path its go.mod declares
	Environment string // variable naming a prebuilt binary that replaces the build
}

// The client peers of the process interoperability tests.
var (
	SingBox = Peer{Name: "sing-box", Module: "github.com/sagernet/sing-box", Environment: "SING_BOX_E2E_BIN"}
	Mihomo  = Peer{Name: "mihomo", Module: "github.com/metacubex/mihomo", Environment: "MIHOMO_E2E_BIN"}
)

// SourceDir returns the checkout of peer that the tests of the Xray checkout
// at repoRoot build. The caller applies peer.Environment before calling it;
// the variable only appears in the error message.
//
// A candidate is a directory named peer.Name whose go.mod declares
// peer.Module. Candidates are tried in this order, and the first one wins:
//
//  1. a sibling of repoRoot,
//  2. a sibling of the main checkout (the parent of the git common directory),
//  3. a sibling of repoRoot's parent,
//  4. a sibling of the main checkout's parent.
//
// The direct siblings come first, so a worktree in a shared directory such as
// /tmp does not pick up whatever checkout sits beside that directory before the
// peer beside the main checkout. Candidates 2 and 4 only exist when git can
// name the main checkout. If no candidate qualifies, the error lists every
// path tried and why it was skipped.
func SourceDir(repoRoot string, peer Peer) (string, error) {
	mainRoot, mainErr := mainCheckout(repoRoot)
	candidates := sourceCandidates(repoRoot, mainRoot, peer.Name)
	skipped := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		module, err := modulePath(candidate)
		switch {
		case err != nil:
			skipped = append(skipped, fmt.Sprintf("%s: %v", candidate, err))
		case module != peer.Module:
			skipped = append(skipped, fmt.Sprintf("%s: module %s, want %s", candidate, module, peer.Module))
		default:
			return candidate, nil
		}
	}
	return "", notFoundError(peer, skipped, mainErr)
}

// sourceCandidates lists the directories SourceDir tries, in order and
// without duplicates. mainRoot is empty when the main checkout is unknown.
func sourceCandidates(repoRoot, mainRoot, name string) []string {
	var parents, grandparents []string
	for _, root := range []string{repoRoot, mainRoot} {
		if root == "" {
			continue
		}
		parent := filepath.Dir(root)
		parents = append(parents, parent)
		grandparents = append(grandparents, filepath.Dir(parent))
	}
	var candidates []string
	seen := make(map[string]bool)
	for _, root := range append(parents, grandparents...) {
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

// moduleDirective reads the module path of a go.mod, quoted or not.
var moduleDirective = regexp.MustCompile("(?m)^[ \\t]*module[ \\t]+(\"[^\"\\n]*\"|`[^`\\n]*`|[^\\s/]\\S*)")

// modulePath returns the module path the go.mod in directory declares.
func modulePath(directory string) (string, error) {
	path := filepath.Join(directory, "go.mod")
	info, err := os.Stat(path)
	if err != nil {
		return "", errors.New("no go.mod")
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("go.mod is not a regular file")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read go.mod: %w", err)
	}
	match := moduleDirective.FindSubmatch(content)
	if match == nil {
		return "", errors.New("go.mod declares no module")
	}
	module := string(match[1])
	if unquoted, err := strconv.Unquote(module); err == nil {
		module = unquoted
	}
	return module, nil
}

func notFoundError(peer Peer, skipped []string, mainErr error) error {
	var message strings.Builder
	fmt.Fprintf(&message, "%s source not found (no directory whose go.mod declares %s):\n", peer.Name, peer.Module)
	for _, reason := range skipped {
		fmt.Fprintf(&message, "  %s\n", reason)
	}
	if mainErr != nil {
		fmt.Fprintf(&message, "main checkout lookup failed: %v\n", mainErr)
	}
	fmt.Fprintf(&message, "Clone %s to one of those paths, or set %s to a prebuilt %s binary", peer.Name, peer.Environment, peer.Name)
	message.WriteString(" (XRAY_E2E_BIN, SING_BOX_E2E_BIN and MIHOMO_E2E_BIN each replace one build).")
	return errors.New(message.String())
}
