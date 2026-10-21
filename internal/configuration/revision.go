package configuration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var ErrRevisionUnavailable = errors.New("IAC_REVISION_UNAVAILABLE")

// RepositoryRevisionBinding is private operator configuration. Public authority
// declarations select no filesystem path, executable, credential or fetch URL.
// The checkout establishes the existing authority's repository binding. The
// current branch revision is read independently from the exact approved HTTPS
// remote; resolution never fetches into or mutates the checkout.
type RepositoryRevisionBinding struct {
	TenantID       string     `json:"tenant_id"`
	AuthorityID    string     `json:"authority_id"`
	RepositoryRoot string     `json:"repository_root"`
	Repository     Repository `json:"repository"`
}

type LocalRevisionResolver struct {
	Bindings map[string]RepositoryRevisionBinding
	// Optional typed transport injection for deterministic acceptance only; no
	// environment or public JSON can supply a callback or executable.
	RemoteRevision func(context.Context, Repository) (string, error)
}

// ParseRevisionBindings reads an operator-owned registry, not a public request.
// Empty configuration deliberately leaves declarative revision currentness
// unavailable. Registry paths never enter any public evidence or error body.
func ParseRevisionBindings(raw string) (map[string]RepositoryRevisionBinding, error) {
	bindings := map[string]RepositoryRevisionBinding{}
	if raw == "" {
		return bindings, nil
	}
	decoder := json.NewDecoder(bytes.NewBufferString(raw))
	decoder.DisallowUnknownFields()
	if len(raw) > 64<<10 || decoder.Decode(&bindings) != nil || bindings == nil || decoder.Decode(&struct{}{}) != io.EOF || len(bindings) > 256 {
		return nil, ErrRevisionUnavailable
	}
	for id, binding := range bindings {
		if !artifactID.MatchString(binding.TenantID) || !artifactID.MatchString(binding.AuthorityID) || id != binding.TenantID+":"+binding.AuthorityID || !filepath.IsAbs(binding.RepositoryRoot) || !HTTPSMetadata(binding.Repository.URL) || !ValidRef(binding.Repository.Ref) || !ValidDirectory(binding.Repository.Directory) {
			return nil, ErrRevisionUnavailable
		}
	}
	return bindings, nil
}

// Resolve returns the exact registered remote branch's observed commit. Reuse the
// existing artifact collector's hardened Git command environment, repository
// identity/configuration checks, symlink refusals and bounded clean-source
// inspection. A bounded HTTPS ls-remote reads the exact approved URL; it neither
// fetches objects nor changes files. Unknown remote state stays unavailable.
func (r *LocalRevisionResolver) Resolve(ctx context.Context, tenant, authority string, repository Repository) (string, error) {
	if r == nil || !artifactID.MatchString(tenant) || !artifactID.MatchString(authority) || !HTTPSMetadata(repository.URL) || !ValidRef(repository.Ref) || !ValidDirectory(repository.Directory) {
		return "", ErrRevisionUnavailable
	}
	binding, approved := r.Bindings[tenant+":"+authority]
	if !approved || binding.TenantID != tenant || binding.AuthorityID != authority || binding.Repository != repository || !filepath.IsAbs(binding.RepositoryRoot) {
		return "", ErrRevisionUnavailable
	}
	root, err := filepath.Abs(binding.RepositoryRoot)
	if err != nil {
		return "", ErrRevisionUnavailable
	}
	if resolved, err := filepath.EvalSymlinks(root); err != nil || resolved != root {
		return "", ErrRevisionUnavailable
	}
	directory := filepath.Join(root, filepath.FromSlash(repository.Directory))
	if !artifactInside(root, directory) {
		return "", ErrRevisionUnavailable
	}
	if info, err := os.Stat(directory); err != nil || !info.IsDir() {
		return "", ErrRevisionUnavailable
	}
	// A resolver stays within the caller's deadline and a small bounded read. A
	// large/unavailable repository remains unknown instead of delaying the API.
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	collector := &LocalArtifactCollector{}
	git, _, _, err := collector.source(bounded, ArtifactRegistration{Declaration: Declaration{Repository: repository}}, root)
	if err != nil || !artifactCommit.MatchString(git.Commit) || git.Ref != repository.Ref {
		return "", ErrRevisionUnavailable
	}
	if r.RemoteRevision != nil {
		commit, err := r.RemoteRevision(bounded, repository)
		if err != nil || !artifactCommit.MatchString(commit) {
			return "", ErrRevisionUnavailable
		}
		return commit, nil
	}
	return collector.repositoryRemoteRevision(bounded, root, repository)
}

func (c *LocalArtifactCollector) repositoryRemoteRevision(ctx context.Context, root string, repository Repository) (string, error) {
	ref := repository.Ref
	if strings.HasPrefix(ref, "refs/heads/") {
		ref = strings.TrimPrefix(ref, "refs/heads/")
	} else if strings.HasPrefix(ref, "refs/") || ref == "HEAD" {
		// The initial currentness reader requires an explicit branch. Annotated
		// tags need independently resolved peeled commits and remain unavailable.
		return "", ErrRevisionUnavailable
	}
	if !ValidRef(ref) {
		return "", ErrRevisionUnavailable
	}
	remoteRef := "refs/heads/" + ref
	out, err := c.git(ctx, root,
		"-c", "credential.helper=", "-c", "credential.interactive=never", "-c", "core.askPass=",
		"-c", "http.sslVerify=true", "-c", "http.followRedirects=false", "-c", "http.extraHeader=", "-c", "http.proxy=",
		"-c", "protocol.allow=never", "-c", "protocol.https.allow=always",
		"ls-remote", "--exit-code", "--refs", repository.URL, remoteRef)
	if err != nil || len(out) > 1024 {
		return "", ErrRevisionUnavailable
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) != 1 {
		return "", ErrRevisionUnavailable
	}
	fields := strings.Fields(lines[0])
	if len(fields) != 2 || !artifactCommit.MatchString(fields[0]) || fields[1] != remoteRef {
		return "", ErrRevisionUnavailable
	}
	return fields[0], nil
}
