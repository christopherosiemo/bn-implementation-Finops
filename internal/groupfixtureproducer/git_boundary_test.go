package groupfixtureproducer

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
)

func TestGitBoundaryChecksActualInstalledConfigurationBeforeStatus(t *testing.T) {
	if _, err := os.Stat(git); err != nil {
		t.Skip("pinned container Git required")
	}
	base := t.TempDir()
	bare, tree := filepath.Join(base, "control"), filepath.Join(base, "fixture")
	run := func(input string, args ...string) string {
		t.Helper()
		cmd := exec.Command(git, append([]string{"-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid"}, args...)...)
		cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + base, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_NO_REPLACE_OBJECTS=1"}
		cmd.Stdin = strings.NewReader(input)
		raw, err := cmd.Output()
		if err != nil {
			t.Fatal("isolated native Git setup failed", err)
		}
		return strings.TrimSpace(string(raw))
	}
	run("", "init", "--bare", "--initial-branch=proposals", bare)
	blob := run("{}", "--git-dir="+bare, "hash-object", "-w", "--stdin", "--no-filters")
	oid := run("100644 blob "+blob+"\t"+g.GitDesiredPath+"\n100644 blob "+blob+"\t"+g.GitMainPath+"\n", "--git-dir="+bare, "mktree")
	commit := run("", "--git-dir="+bare, "commit-tree", oid, "-m", "isolated boundary setup")
	run("", "--git-dir="+bare, "update-ref", executionRef, commit)
	run("", "--git-dir="+bare, "worktree", "add", tree, "approved")
	if err := verifyGitBoundaryAt(bare, tree, false); err != nil {
		t.Fatal("actual generated Git closure differs", err)
	}
	config, err := os.ReadFile(filepath.Join(bare, "config"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(config, []byte(isolatedBareConfig)) {
		t.Fatal("generated configuration is not the installed exact shape")
	}
	for _, target := range []string{filepath.Join(bare, "info", "attributes"), filepath.Join(tree, ".gitattributes"), filepath.Join(bare, "worktrees", "fixture", "config.worktree")} {
		if err = os.WriteFile(target, []byte("* filter=unexpected\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if err = verifyGitBoundaryAt(bare, tree, false); err == nil {
			t.Fatal("attribute/filter path admitted before Git invocation")
		}
		if err = os.Remove(target); err != nil {
			t.Fatal(err)
		}
	}
	if err = os.WriteFile(filepath.Join(bare, "config"), append(config, []byte("[include]\n\tpath = /unapproved/config\n")...), 0600); err != nil {
		t.Fatal(err)
	}
	if err = verifyGitBoundaryAt(bare, tree, false); err == nil {
		t.Fatal("repository configuration include admitted")
	}
}
