package groupfixtureproducer

import (
	"bytes"
	"os"
	"path/filepath"

	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
)

const isolatedBareConfig = "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = true\n"

// Git reads local configuration and attributes even for status/checkout.
// Validate their exact installed closure before invoking it; inspecting them
// through Git itself would already permit include/filter execution.
func verifyGitBoundary(initializing bool) error {
	return verifyGitBoundaryAt(control, repository, initializing)
}

func verifyGitBoundaryAt(bare, tree string, initializing bool) error {
	config, err := readPrivate(filepath.Join(bare, "config"))
	if err != nil {
		if initializing {
			if _, e := os.Lstat(filepath.Join(bare, "config")); os.IsNotExist(e) {
				return nil
			}
		}
		return ErrBoundary
	}
	if !bytes.Equal(config, []byte(isolatedBareConfig)) {
		return ErrBoundary
	}
	for _, name := range []string{"config.worktree", "info/attributes", "objects/info/alternates", "objects/info/http-alternates"} {
		if _, e := os.Lstat(filepath.Join(bare, filepath.FromSlash(name))); !os.IsNotExist(e) {
			return ErrBoundary
		}
	}
	info, err := os.Lstat(tree)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrBoundary
	}
	entries, err := os.ReadDir(tree)
	if err != nil || len(entries) != 3 {
		return ErrBoundary
	}
	wanted := map[string]bool{".git": true, g.GitMainPath: true, g.GitDesiredPath: true}
	for _, entry := range entries {
		if !wanted[entry.Name()] || entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return ErrBoundary
		}
	}
	admin := filepath.Join(bare, "worktrees", "fixture")
	for _, item := range []struct{ name, want string }{
		{filepath.Join(tree, ".git"), "gitdir: " + admin + "\n"},
		{filepath.Join(admin, "commondir"), "../..\n"},
		{filepath.Join(admin, "gitdir"), filepath.Join(tree, ".git") + "\n"},
		{filepath.Join(admin, "HEAD"), "ref: " + executionRef + "\n"},
	} {
		raw, e := readPrivate(item.name)
		if e != nil || !bytes.Equal(raw, []byte(item.want)) {
			return ErrBoundary
		}
	}
	for _, name := range []string{"config.worktree", "info/attributes"} {
		if _, e := os.Lstat(filepath.Join(admin, filepath.FromSlash(name))); !os.IsNotExist(e) {
			return ErrBoundary
		}
	}
	return nil
}
