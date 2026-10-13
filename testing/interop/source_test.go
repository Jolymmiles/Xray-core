package interop

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestSourceCandidatesOrderAndDeduplication(t *testing.T) {
	for _, test := range []struct {
		name               string
		repoRoot, mainRoot string
		want               []string
	}{
		{"no main checkout", "/dev/Xray-core", "", []string{"/dev/sing-box", "/sing-box"}},
		{"linked worktree", "/tmp/wt/deep/Xray-core", "/dev/Xray-core", []string{"/tmp/wt/deep/sing-box", "/dev/sing-box", "/tmp/wt/sing-box", "/sing-box"}},
		{"main checkout is the repo", "/dev/Xray-core", "/dev/Xray-core", []string{"/dev/sing-box", "/sing-box"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := sourceCandidates(filepath.FromSlash(test.repoRoot), filepath.FromSlash(test.mainRoot), "sing-box")
			var want []string
			for _, path := range test.want {
				want = append(want, filepath.FromSlash(path))
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("got %q, want %q", got, want)
			}
		})
	}
}

func TestSourceDirFindsMainCheckoutSiblingFromLinkedWorktree(t *testing.T) {
	root := hermeticGit(t)
	mainCheckout, worktree := newRepoWithWorktree(t, filepath.Join(root, "dev", "Xray-core"), filepath.Join(root, "elsewhere", "deep", "worktree"))
	peer := filepath.Join(root, "dev", "mihomo")
	writeModule(t, peer, Mihomo.Module)

	for _, from := range []string{worktree, mainCheckout} {
		got, err := SourceDir(from, Mihomo)
		if err != nil {
			t.Fatalf("from %s: %v", from, err)
		}
		assertSameDir(t, got, peer)
	}
}

// A git hook exports GIT_DIR and its companions to the commands it runs. The
// lookup must still resolve the main checkout that repoRoot belongs to.
func TestSourceDirIgnoresInheritedRepositoryVariables(t *testing.T) {
	root := hermeticGit(t)
	_, worktree := newRepoWithWorktree(t, filepath.Join(root, "dev", "Xray-core"), filepath.Join(root, "elsewhere", "deep", "worktree"))
	peer := filepath.Join(root, "dev", "mihomo")
	writeModule(t, peer, Mihomo.Module)
	other := filepath.Join(root, "other", "repo")
	mustMkdir(t, other)
	git(t, other, "init", "--quiet")
	t.Setenv("GIT_DIR", filepath.Join(other, ".git"))
	t.Setenv("GIT_WORK_TREE", other)

	got, err := SourceDir(worktree, Mihomo)
	if err != nil {
		t.Fatal(err)
	}
	assertSameDir(t, got, peer)
}

// A worktree under a shared directory such as /tmp must not pick up whatever
// checkout sits beside that directory before the peer beside the main
// checkout.
func TestSourceDirPrefersMainCheckoutPeerOverWorktreeAncestor(t *testing.T) {
	root := hermeticGit(t)
	_, worktree := newRepoWithWorktree(t, filepath.Join(root, "dev", "Xray-core"), filepath.Join(root, "tmp", "review", "pr1"))
	writeModule(t, filepath.Join(root, "tmp", "sing-box"), SingBox.Module)
	peer := filepath.Join(root, "dev", "sing-box")
	writeModule(t, peer, SingBox.Module)

	got, err := SourceDir(worktree, SingBox)
	if err != nil {
		t.Fatal(err)
	}
	assertSameDir(t, got, peer)
}

// A directory with the peer's name but another module is not the peer.
func TestSourceDirSkipsAForeignModule(t *testing.T) {
	root := hermeticGit(t)
	_, worktree := newRepoWithWorktree(t, filepath.Join(root, "dev", "Xray-core"), filepath.Join(root, "wt", "Xray-core"))
	writeModule(t, filepath.Join(root, "wt", "mihomo"), "example.invalid/not-mihomo")
	peer := filepath.Join(root, "dev", "mihomo")
	writeModule(t, peer, Mihomo.Module)

	got, err := SourceDir(worktree, Mihomo)
	if err != nil {
		t.Fatal(err)
	}
	assertSameDir(t, got, peer)
}

func TestSourceDirPrefersTheWorktreesOwnNeighbour(t *testing.T) {
	root := hermeticGit(t)
	_, worktree := newRepoWithWorktree(t, filepath.Join(root, "dev", "Xray-core"), filepath.Join(root, "wt", "Xray-core"))
	writeModule(t, filepath.Join(root, "dev", "sing-box"), SingBox.Module)
	local := filepath.Join(root, "wt", "sing-box")
	writeModule(t, local, SingBox.Module)

	got, err := SourceDir(worktree, SingBox)
	if err != nil {
		t.Fatal(err)
	}
	assertSameDir(t, got, local)
}

func TestSourceDirSkipsDirectoriesWithoutGoModule(t *testing.T) {
	root := hermeticGit(t)
	repo := filepath.Join(root, "dev", "Xray-core")
	mustMkdir(t, repo)
	mustMkdir(t, filepath.Join(root, "dev", "mihomo"))
	real := filepath.Join(root, "mihomo")
	writeModule(t, real, Mihomo.Module)

	got, err := SourceDir(repo, Mihomo)
	if err != nil {
		t.Fatal(err)
	}
	assertSameDir(t, got, real)
}

func TestSourceDirNotFoundNamesEnvironmentAndEveryPathTried(t *testing.T) {
	root := hermeticGit(t)
	repo := filepath.Join(root, "dev", "Xray-core")
	mustMkdir(t, repo)
	writeModule(t, filepath.Join(root, "sing-box"), "example.invalid/not-sing-box")

	_, err := SourceDir(repo, SingBox)
	if err == nil {
		t.Fatal("SourceDir succeeded without any sing-box source")
	}
	message := err.Error()
	for _, want := range []string{
		"SING_BOX_E2E_BIN",
		"MIHOMO_E2E_BIN",
		"XRAY_E2E_BIN",
		filepath.Join(root, "dev", "sing-box"),
		filepath.Join(root, "sing-box") + ": module example.invalid/not-sing-box, want github.com/sagernet/sing-box",
		"main checkout lookup failed",
	} {
		if !strings.Contains(message, want) {
			t.Errorf("error is missing %q:\n%s", want, message)
		}
	}
}

// hermeticGit returns a fresh temporary root and makes git ignore the user's
// and the system's configuration and any repository above the root.
func hermeticGit(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_CEILING_DIRECTORIES", filepath.Dir(root))
	for _, name := range repositoryVariables {
		t.Setenv(name, "")
		if err := os.Unsetenv(name); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// newRepoWithWorktree creates a repository with one commit at mainCheckout
// and a linked worktree at worktree.
func newRepoWithWorktree(t *testing.T, mainCheckout, worktree string) (string, string) {
	t.Helper()
	mustMkdir(t, mainCheckout)
	mustMkdir(t, filepath.Dir(worktree))
	git(t, mainCheckout, "init", "--quiet")
	git(t, mainCheckout, "-c", "user.name=test", "-c", "user.email=test@example.invalid", "-c", "commit.gpgsign=false",
		"commit", "--quiet", "--allow-empty", "-m", "init")
	git(t, mainCheckout, "worktree", "add", "--quiet", "-b", "linked", worktree)
	return mainCheckout, worktree
}

func git(t *testing.T, directory string, arguments ...string) {
	t.Helper()
	command := exec.Command("git", arguments...)
	command.Dir = directory
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %s in %s: %v\n%s", strings.Join(arguments, " "), directory, err, output)
	}
}

func mustMkdir(t *testing.T, directory string) {
	t.Helper()
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}
}

func writeModule(t *testing.T, directory, module string) {
	t.Helper()
	mustMkdir(t, directory)
	if err := os.WriteFile(filepath.Join(directory, "go.mod"), []byte("module "+module+"\n\ngo 1.24\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func assertSameDir(t *testing.T, got, want string) {
	t.Helper()
	resolvedGot, err := filepath.EvalSymlinks(got)
	if err != nil {
		t.Fatal(err)
	}
	resolvedWant, err := filepath.EvalSymlinks(want)
	if err != nil {
		t.Fatal(err)
	}
	if resolvedGot != resolvedWant {
		t.Fatalf("SourceDir = %s, want %s", got, want)
	}
}
