package configuration

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func revisionFixture(t *testing.T) (*LocalRevisionResolver, Repository, string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("existing Git executable required")
	}
	root := t.TempDir()
	repository := Repository{URL: "https://github.com/example/approved-infrastructure.git", Ref: "main", Directory: "."}
	run := func(args ...string) {
		t.Helper()
		if _, err := artifactCommand(context.Background(), "git", root, args...); err != nil {
			t.Fatal("local Git fixture setup failed")
		}
	}
	run("init", "--initial-branch=main")
	run("config", "user.name", "Read-only revision fixture")
	run("config", "user.email", "fixture@example.invalid")
	run("remote", "add", "origin", repository.URL)
	if err := os.WriteFile(filepath.Join(root, "main.tf"), []byte("resource \"terraform_data\" \"fixture\" { input = \"original\" }\n"), 0600); err != nil {
		t.Fatal(err)
	}
	run("add", "main.tf")
	run("commit", "--message", "Initial reviewed configuration")
	resolver := &LocalRevisionResolver{Bindings: map[string]RepositoryRevisionBinding{"tenant:authority": {TenantID: "tenant", AuthorityID: "authority", RepositoryRoot: root, Repository: repository}}}
	// Deterministic transport injection: this isolated fixture's independently
	// observed remote branch tracks the test's committed source. Production
	// always uses the exact operator-approved HTTPS ls-remote command.
	resolver.RemoteRevision = func(ctx context.Context, _ Repository) (string, error) {
		raw, err := artifactCommand(ctx, "git", root, "rev-parse", "--verify", "HEAD^{commit}")
		return strings.TrimSpace(string(raw)), err
	}
	return resolver, repository, root
}

func TestLocalRepositoryRevisionRequiresIndependentRemoteObservation(t *testing.T) {
	resolver, repository, _ := revisionFixture(t)
	resolver.RemoteRevision = func(context.Context, Repository) (string, error) {
		return "", errors.New("private remote unavailable")
	}
	if commit, err := resolver.Resolve(context.Background(), "tenant", "authority", repository); !errors.Is(err, ErrRevisionUnavailable) || commit != "" {
		t.Fatal("local checkout substituted for unavailable remote state")
	}
	newCommit := strings.Repeat("a", 40)
	resolver.RemoteRevision = func(context.Context, Repository) (string, error) { return newCommit, nil }
	if commit, err := resolver.Resolve(context.Background(), "tenant", "authority", repository); err != nil || commit != newCommit {
		t.Fatal("new remote revision hidden behind unchanged local checkout", err)
	}
	resolver.RemoteRevision = func(context.Context, Repository) (string, error) { return "invalid revision", nil }
	if commit, err := resolver.Resolve(context.Background(), "tenant", "authority", repository); !errors.Is(err, ErrRevisionUnavailable) || commit != "" {
		t.Fatal("malformed remote observation accepted")
	}
}

func TestLocalRepositoryRevisionDetectsChangedReviewedRef(t *testing.T) {
	resolver, repository, root := revisionFixture(t)
	ctx := context.Background()
	before, err := resolver.Resolve(ctx, "tenant", "authority", repository)
	if err != nil || !artifactCommit.MatchString(before) {
		t.Fatal("registered clean source revision unavailable", err)
	}
	unchanged, err := resolver.Resolve(ctx, "tenant", "authority", repository)
	if err != nil || unchanged != before {
		t.Fatal("unchanged registered ref became different")
	}
	if err := os.WriteFile(filepath.Join(root, "main.tf"), []byte("resource \"terraform_data\" \"fixture\" { input = \"changed\" }\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = resolver.Resolve(ctx, "tenant", "authority", repository); !errors.Is(err, ErrRevisionUnavailable) {
		t.Fatal("dirty source must not claim a current commit")
	}
	for _, args := range [][]string{{"add", "main.tf"}, {"commit", "--message", "Changed reviewed configuration"}} {
		if _, err := artifactCommand(ctx, "git", root, args...); err != nil {
			t.Fatal("local revision fixture update failed")
		}
	}
	after, err := resolver.Resolve(ctx, "tenant", "authority", repository)
	if err != nil || !artifactCommit.MatchString(after) || before == after {
		t.Fatal("changed approved ref was not resolved", err)
	}
}

func TestLocalRepositoryRevisionRefusesConfusedOrUnapprovedSource(t *testing.T) {
	resolver, repository, root := revisionFixture(t)
	for _, scenario := range []string{"tenant", "authority", "repository", "ref", "directory", "unknown ref", "cancelled", "unsafe config"} {
		t.Run(scenario, func(t *testing.T) {
			tenant, authority, selected := "tenant", "authority", repository
			ctx := context.Background()
			switch scenario {
			case "tenant":
				tenant = "other"
			case "authority":
				authority = "other"
			case "repository":
				selected.URL = "https://github.com/example/other.git"
			case "ref":
				selected.Ref = "--upload-pack=untrusted"
			case "directory":
				selected.Directory = "../escape"
			case "unknown ref":
				selected.Ref = "missing"
			case "cancelled":
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				ctx = cancelled
			case "unsafe config":
				if _, err := artifactCommand(ctx, "git", root, "config", "core.fsmonitor", "unapproved-command"); err != nil {
					t.Fatal("local safety fixture config failed")
				}
			}
			if commit, err := resolver.Resolve(ctx, tenant, authority, selected); !errors.Is(err, ErrRevisionUnavailable) || commit != "" {
				t.Fatal("unresolved or unapproved source acquired currentness")
			}
		})
	}
}

func TestRevisionBindingRegistryIsOperatorScopedAndStrict(t *testing.T) {
	resolver, _, _ := revisionFixture(t)
	raw, _ := json.Marshal(resolver.Bindings)
	bindings, err := ParseRevisionBindings(string(raw))
	if err != nil || len(bindings) != 1 {
		t.Fatal("valid operator registry rejected", err)
	}
	for _, raw := range []string{"null", `{ "tenant:authority": {"tenant_id":"other"} }`, `{ "tenant:authority": {"tenant_id":"tenant","authority_id":"authority","repository_root":"../../unapproved","repository":{"url":"https://github.com/example/approved-infrastructure.git","ref":"main","directory":"."}} }`, `{ "tenant:authority": {"unknown":"not allowed"} }`} {
		if bindings, err := ParseRevisionBindings(raw); err == nil || bindings != nil {
			t.Fatal("invalid private registry accepted")
		}
	}
	bindings, err = ParseRevisionBindings("")
	if err != nil || len(bindings) != 0 {
		t.Fatal("unconfigured resolver should be unavailable per authority")
	}
}

func TestRepositoryRemoteRevisionRequiresExplicitBranch(t *testing.T) {
	collector := &LocalArtifactCollector{}
	for _, ref := range []string{"HEAD", "refs/tags/v1", "refs/remotes/origin/main", "--unsafe"} {
		commit, err := collector.repositoryRemoteRevision(context.Background(), "", Repository{URL: "https://github.com/example/approved-infrastructure.git", Ref: ref, Directory: "."})
		if !errors.Is(err, ErrRevisionUnavailable) || commit != "" {
			t.Fatal("ambiguous remote ref acquired currentness")
		}
	}
}
