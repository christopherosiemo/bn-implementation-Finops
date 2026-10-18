package configuration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

type ArtifactInspection struct {
	PlanJSON, StateJSON, VersionJSON []byte
	Workspace                        string
}
type ArtifactTools interface {
	Inspect(context.Context, ArtifactRegistration, string, []byte, []byte) (ArtifactInspection, error)
	ContainerIsolated() bool
}

// Paths and tools are private process configuration. No HTTP or console input
// selects a filesystem path, image, argument, repository URL or executable.
type ArtifactLocalSource struct{ RepositoryRoot, SavedPlanPath, StatePath string }
type LocalArtifactCollector struct {
	Sources   map[string]ArtifactLocalSource
	Tools     ArtifactTools
	GitBinary string
}

func artifactReadFile(name string) ([]byte, error) {
	s, e := os.Lstat(name)
	if e != nil || !s.Mode().IsRegular() || s.Size() < 0 || s.Size() > ArtifactMaxBytes {
		return nil, errors.New("CONFIGURATION_ARTIFACT_FILE_INVALID")
	}
	f, e := os.Open(name)
	if e != nil {
		return nil, errors.New("CONFIGURATION_ARTIFACT_FILE_UNAVAILABLE")
	}
	defer f.Close()
	raw, e := io.ReadAll(io.LimitReader(f, ArtifactMaxBytes+1))
	if e != nil || len(raw) > ArtifactMaxBytes {
		return nil, errors.New("CONFIGURATION_ARTIFACT_FILE_LIMIT")
	}
	after, e := f.Stat()
	if e != nil || !os.SameFile(s, after) || s.Size() != after.Size() || !s.ModTime().Equal(after.ModTime()) {
		return nil, errors.New("CONFIGURATION_ARTIFACT_FILE_CHANGED")
	}
	return raw, nil
}

type artifactBoundedBuffer struct{ bytes.Buffer }

func (b *artifactBoundedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > ArtifactMaxBytes {
		return 0, errors.New("limit")
	}
	return b.Buffer.Write(p)
}
func artifactCommand(ctx context.Context, binary, dir string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Dir = dir
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "SYSTEMROOT=" + os.Getenv("SYSTEMROOT"), "WINDIR=" + os.Getenv("WINDIR"), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=" + os.DevNull, "GIT_NO_REPLACE_OBJECTS=1", "GIT_NO_LAZY_FETCH=1", "GIT_OPTIONAL_LOCKS=0", "GIT_TERMINAL_PROMPT=0", "TF_CLI_CONFIG_FILE=" + os.DevNull, "TF_IN_AUTOMATION=1", "CHECKPOINT_DISABLE=1"}
	var out artifactBoundedBuffer
	cmd.Stdout = &out
	cmd.Stderr = io.Discard
	if cmd.Run() != nil {
		return nil, errors.New("CONFIGURATION_ARTIFACT_TOOL_FAILED")
	}
	return out.Bytes(), nil
}
func (c *LocalArtifactCollector) git(ctx context.Context, root string, args ...string) ([]byte, error) {
	binary := c.GitBinary
	if binary == "" {
		binary = "git"
	}
	return artifactCommand(ctx, binary, root, append([]string{"--no-optional-locks", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=" + os.DevNull}, args...)...)
}
func artifactInside(root, name string) bool {
	rel, e := filepath.Rel(root, name)
	return e == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}
func (c *LocalArtifactCollector) source(ctx context.Context, r ArtifactRegistration, root string) (ArtifactGit, []ArtifactFile, []byte, error) {
	var g ArtifactGit
	// Config listing itself does not run filters. Reject local execution hooks,
	// includes, worktree redirection, partial-clone fetch and attribute commands
	// before status touches source content. Global/system/env Git config is off.
	gitdir, e := os.Lstat(filepath.Join(root, ".git"))
	if e != nil || !gitdir.IsDir() {
		return g, nil, nil, errors.New("CONFIGURATION_ARTIFACT_GIT_DIRECTORY_UNSUPPORTED")
	}
	keys, e := c.git(ctx, root, "config", "--local", "--no-includes", "--name-only", "--null", "--list")
	if e != nil {
		return g, nil, nil, e
	}
	allowed := map[string]bool{"core.repositoryformatversion": true, "core.filemode": true, "core.bare": true, "core.logallrefupdates": true, "core.ignorecase": true, "core.precomposeunicode": true, "user.name": true, "user.email": true, "remote.origin.url": true, "remote.origin.fetch": true}
	for _, raw := range bytes.Split(keys, []byte{0}) {
		key := strings.ToLower(string(raw))
		if key != "" && !allowed[key] {
			return g, nil, nil, errors.New("CONFIGURATION_ARTIFACT_GIT_CONFIG_UNSAFE")
		}
	}
	for _, name := range []string{filepath.Join(root, ".gitmodules"), filepath.Join(root, ".git", "objects", "info", "alternates"), filepath.Join(root, ".git", "commondir")} {
		if _, e := os.Lstat(name); e == nil {
			return g, nil, nil, errors.New("CONFIGURATION_ARTIFACT_GIT_EXTERNAL_SOURCE_UNSUPPORTED")
		}
	}
	if e := filepath.WalkDir(root, func(name string, d os.DirEntry, err error) error {
		if err != nil {
			return errors.New("CONFIGURATION_ARTIFACT_SOURCE_UNAVAILABLE")
		}
		if d.IsDir() {
			if name == filepath.Join(root, ".git") || d.Name() == ".terraform" {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() == ".gitattributes" {
			return errors.New("CONFIGURATION_ARTIFACT_GIT_ATTRIBUTES_UNSUPPORTED")
		}
		return nil
	}); e != nil {
		return g, nil, nil, e
	}
	if info, e := os.Stat(filepath.Join(root, ".git", "info", "attributes")); e == nil && info.Size() > 0 {
		return g, nil, nil, errors.New("CONFIGURATION_ARTIFACT_GIT_ATTRIBUTES_UNSUPPORTED")
	}
	top, e := c.git(ctx, root, "rev-parse", "--show-toplevel")
	if e != nil {
		return g, nil, nil, e
	}
	abs, e := filepath.Abs(strings.TrimSpace(string(top)))
	if e != nil || abs != root {
		return g, nil, nil, errors.New("CONFIGURATION_ARTIFACT_REPOSITORY_ROOT_INVALID")
	}
	remote, e := c.git(ctx, root, "config", "--local", "--no-includes", "--get", "remote.origin.url")
	if e != nil || strings.TrimSpace(string(remote)) != r.Declaration.Repository.URL {
		return g, nil, nil, errors.New("CONFIGURATION_ARTIFACT_REPOSITORY_CHANGED")
	}
	commit, e := c.git(ctx, root, "rev-parse", "--verify", "HEAD^{commit}")
	if e != nil {
		return g, nil, nil, e
	}
	g.Commit = strings.TrimSpace(string(commit))
	tree, e := c.git(ctx, root, "rev-parse", "--verify", g.Commit+"^{tree}")
	if e != nil {
		return g, nil, nil, e
	}
	g.Tree = strings.TrimSpace(string(tree))
	ref, e := c.git(ctx, root, "rev-parse", "--verify", r.Declaration.Repository.Ref+"^{commit}")
	if e != nil || strings.TrimSpace(string(ref)) != g.Commit {
		return g, nil, nil, errors.New("CONFIGURATION_ARTIFACT_COMMIT_CHANGED")
	}
	g.Ref = r.Declaration.Repository.Ref
	// Never run status/diff: they can invoke clean/process filters while reading
	// worktree content. Compare cached index/object metadata and raw bytes
	// ourselves, so even a concurrent local-config edit cannot enable a filter.
	listing, e := c.git(ctx, root, "ls-tree", "-r", "-z", g.Commit)
	if e != nil {
		return g, nil, nil, e
	}
	files := []ArtifactFile{}
	indexExpected := map[string]string{}
	var total int64
	for _, entry := range bytes.Split(listing, []byte{0}) {
		if len(entry) == 0 {
			continue
		}
		parts := bytes.SplitN(entry, []byte{'\t'}, 2)
		if len(parts) != 2 {
			return g, nil, nil, errors.New("CONFIGURATION_ARTIFACT_GIT_TREE_INVALID")
		}
		fields := strings.Fields(string(parts[0]))
		if len(fields) != 3 || fields[1] != "blob" || (fields[0] != "100644" && fields[0] != "100755") {
			return g, nil, nil, errors.New("CONFIGURATION_ARTIFACT_SYMLINK_OR_SUBMODULE_UNSUPPORTED")
		}
		name := string(parts[1])
		indexExpected[name] = fields[0] + " " + fields[2] + " 0"
		full := filepath.Join(root, filepath.FromSlash(name))
		if !artifactInside(root, full) {
			return g, nil, nil, errors.New("CONFIGURATION_ARTIFACT_SOURCE_ESCAPE")
		}
		body, e := artifactReadFile(full)
		if e != nil {
			return g, nil, nil, e
		}
		if runtime.GOOS == "linux" {
			info, e := os.Lstat(full)
			if e != nil || (info.Mode().Perm()&0111 != 0) != (fields[0] == "100755") {
				return g, nil, nil, errors.New("CONFIGURATION_ARTIFACT_SOURCE_MODE_CHANGED")
			}
		}
		tracked, e := c.git(ctx, root, "cat-file", "blob", fields[2])
		if e != nil || !bytes.Equal(body, tracked) {
			return g, nil, nil, errors.New("CONFIGURATION_ARTIFACT_SOURCE_CHANGED")
		}
		total += int64(len(body))
		if total > ArtifactMaxBytes || len(files) >= 4096 {
			return g, nil, nil, errors.New("CONFIGURATION_ARTIFACT_SOURCE_LIMIT")
		}
		files = append(files, ArtifactFile{name, fields[0], artifactBytesHash(body), body})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	index, e := c.git(ctx, root, "ls-files", "--cached", "--stage", "-z")
	if e != nil {
		return g, nil, nil, e
	}
	indexSeen := map[string]bool{}
	for _, entry := range bytes.Split(index, []byte{0}) {
		if len(entry) == 0 {
			continue
		}
		parts := bytes.SplitN(entry, []byte{'\t'}, 2)
		if len(parts) != 2 || indexSeen[string(parts[1])] || indexExpected[string(parts[1])] != string(parts[0]) {
			return g, nil, nil, errors.New("CONFIGURATION_ARTIFACT_GIT_INDEX_CHANGED")
		}
		indexSeen[string(parts[1])] = true
	}
	if len(indexSeen) != len(indexExpected) {
		return g, nil, nil, errors.New("CONFIGURATION_ARTIFACT_GIT_INDEX_CHANGED")
	}
	g.ConfigurationSHA256 = artifactFilesDigest(files)
	modules := []byte(`{"Modules":[{"Key":"","Source":"","Dir":"."}]}`)
	tfroot := filepath.Join(root, filepath.FromSlash(r.Declaration.Repository.Directory))
	if !artifactInside(root, tfroot) {
		return g, nil, nil, errors.New("CONFIGURATION_ARTIFACT_SOURCE_ESCAPE")
	}
	if e := filepath.WalkDir(root, func(name string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return errors.New("CONFIGURATION_ARTIFACT_SOURCE_UNAVAILABLE")
		}
		if name == filepath.Join(root, ".git") || name == filepath.Join(tfroot, ".terraform") {
			if !d.IsDir() || d.Type()&os.ModeSymlink != 0 {
				return errors.New("CONFIGURATION_ARTIFACT_SOURCE_ESCAPE")
			}
			return filepath.SkipDir
		}
		if d.Type()&os.ModeSymlink != 0 {
			return errors.New("CONFIGURATION_ARTIFACT_SYMLINK_OR_SUBMODULE_UNSUPPORTED")
		}
		if d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(root, name)
		if !indexSeen[filepath.ToSlash(rel)] {
			return errors.New("CONFIGURATION_ARTIFACT_GIT_NOT_CLEAN")
		}
		return nil
	}); e != nil {
		return g, nil, nil, e
	}
	moduleFile := filepath.Join(tfroot, ".terraform", "modules", "modules.json")
	if _, e := os.Stat(moduleFile); e == nil {
		modules, e = artifactReadFile(moduleFile)
		if e != nil {
			return g, nil, nil, e
		}
	}
	// A built-in provider needs no executable dependency cache. Reject all other
	// ignored .terraform content rather than trusting an unbound plugin/module.
	e = filepath.WalkDir(filepath.Join(tfroot, ".terraform"), func(name string, d os.DirEntry, walkErr error) error {
		if os.IsNotExist(walkErr) {
			return nil
		}
		if walkErr != nil {
			return errors.New("CONFIGURATION_ARTIFACT_DEPENDENCY_UNAVAILABLE")
		}
		if d.Type()&os.ModeSymlink != 0 {
			return errors.New("CONFIGURATION_ARTIFACT_DEPENDENCY_ESCAPE")
		}
		if d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(filepath.Join(tfroot, ".terraform"), name)
		rel = filepath.ToSlash(rel)
		if rel != "environment" && rel != "modules/modules.json" {
			return errors.New("CONFIGURATION_ARTIFACT_EXTERNAL_DEPENDENCY_UNSUPPORTED")
		}
		return nil
	})
	if e != nil {
		return g, nil, nil, e
	}
	endHead, e := c.git(ctx, root, "rev-parse", "--verify", "HEAD^{commit}")
	if e != nil || strings.TrimSpace(string(endHead)) != g.Commit {
		return g, nil, nil, errors.New("CONFIGURATION_ARTIFACT_COMMIT_CHANGED")
	}
	return g, files, modules, nil
}
func (c *LocalArtifactCollector) Collect(ctx context.Context, r ArtifactRegistration) (ArtifactBundle, error) {
	var b ArtifactBundle
	if runtime.GOOS != "linux" {
		return b, errors.New("CONFIGURATION_ARTIFACT_POSIX_COLLECTOR_REQUIRED")
	}
	if e := ValidateArtifactRegistration(r); e != nil {
		return b, e
	}
	s, ok := c.Sources[r.ID]
	if !ok || c.Tools == nil {
		return b, errors.New("CONFIGURATION_ARTIFACT_LOCAL_SOURCE_UNAVAILABLE")
	}
	root, e := filepath.Abs(s.RepositoryRoot)
	if e != nil {
		return b, errors.New("CONFIGURATION_ARTIFACT_LOCAL_SOURCE_INVALID")
	}
	if resolved, e := filepath.EvalSymlinks(root); e != nil || resolved != root {
		return b, errors.New("CONFIGURATION_ARTIFACT_REPOSITORY_SYMLINK")
	}
	g, files, modules, e := c.source(ctx, r, root)
	if e != nil {
		return b, e
	}
	plan, e := artifactReadFile(s.SavedPlanPath)
	if e != nil {
		return b, e
	}
	state, e := artifactReadFile(s.StatePath)
	if e != nil {
		return b, e
	}
	inspection, e := c.Tools.Inspect(ctx, r, root, plan, state)
	if e != nil {
		return b, e
	}
	final, finalFiles, finalModules, e := c.source(ctx, r, root)
	if e != nil || final != g || artifactHash(finalFiles) != artifactHash(files) || !bytes.Equal(modules, finalModules) {
		return b, errors.New("CONFIGURATION_ARTIFACT_CAPTURE_SOURCE_CHANGED")
	}
	p2, e := artifactReadFile(s.SavedPlanPath)
	if e != nil || !bytes.Equal(plan, p2) {
		return b, errors.New("CONFIGURATION_ARTIFACT_CAPTURE_PLAN_CHANGED")
	}
	s2, e := artifactReadFile(s.StatePath)
	if e != nil || !bytes.Equal(state, s2) {
		return b, errors.New("CONFIGURATION_ARTIFACT_CAPTURE_STATE_CHANGED")
	}
	raw, e := artifactDecode(state)
	if e != nil {
		return b, e
	}
	serial, ok := raw["serial"].(json.Number)
	if !ok {
		return b, errors.New("CONFIGURATION_ARTIFACT_STATE_INVALID")
	}
	n, e := serial.Int64()
	if e != nil || n < 0 {
		return b, errors.New("CONFIGURATION_ARTIFACT_STATE_INVALID")
	}
	b = ArtifactBundle{SchemaVersion: "1", Git: g, Toolchain: r.Toolchain, State: ArtifactState{artifactString(raw, "lineage"), uint64(n), inspection.Workspace}, Files: files, SavedPlan: plan, PlanJSON: inspection.PlanJSON, StateRaw: state, StateJSON: inspection.StateJSON, VersionJSON: inspection.VersionJSON, ModuleManifest: modules}
	b.Git.DependencySHA256 = artifactDependencyDigest(b)
	return b, nil
}

// DockerArtifactTools invokes only read commands in a pinned image. It does not
// init, plan, refresh, apply, download providers/modules or inherit cloud/TF vars.
type DockerArtifactTools struct{ DockerBinary string }

func (*DockerArtifactTools) ContainerIsolated() bool { return true }
func (t *DockerArtifactTools) Inspect(ctx context.Context, r ArtifactRegistration, root string, plan, state []byte) (ArtifactInspection, error) {
	var out ArtifactInspection
	if os.Getenv("DOCKER_HOST") != "" || os.Getenv("DOCKER_CONTEXT") != "" {
		return out, errors.New("CONFIGURATION_ARTIFACT_REMOTE_DOCKER_UNSUPPORTED")
	}
	dir, e := os.MkdirTemp("", "finops-artifact-inspect-")
	if e != nil {
		return out, errors.New("CONFIGURATION_ARTIFACT_TEMP_UNAVAILABLE")
	}
	defer os.RemoveAll(dir)
	if e = os.Chmod(dir, 0700); e != nil {
		return out, e
	}
	for name, body := range map[string][]byte{"plan.bin": plan, "state.raw": state} {
		if e = os.WriteFile(filepath.Join(dir, name), body, 0600); e != nil {
			return out, errors.New("CONFIGURATION_ARTIFACT_TEMP_UNAVAILABLE")
		}
	}
	uid, gid := os.Getuid(), os.Getgid()
	if uid < 0 {
		uid, gid = 65534, 65534
	}
	binary := t.DockerBinary
	if binary == "" {
		binary = "docker"
	}
	endpoint, e := artifactCommand(ctx, binary, "", "context", "inspect", "--format", "{{json .Endpoints.docker.Host}}")
	var host string
	if e != nil || json.Unmarshal(bytes.TrimSpace(endpoint), &host) != nil || host != "unix:///var/run/docker.sock" && host != fmt.Sprintf("unix:///run/user/%d/docker.sock", uid) {
		return out, errors.New("CONFIGURATION_ARTIFACT_LOCAL_DOCKER_REQUIRED")
	}
	run := func(args ...string) ([]byte, error) {
		base := []string{"--host=" + host, "run", "--rm", "--pull=never", "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=64", "--memory=512m", "--cpus=1", "--user=" + fmt.Sprintf("%d:%d", uid, gid), "--tmpfs=/tmp:rw,noexec,nosuid,size=64m", "--mount", "type=bind,src=" + root + ",dst=/workspace,readonly", "--mount", "type=bind,src=" + dir + ",dst=/artifacts,readonly", "--workdir", r.Toolchain.WorkingDirectory, "--entrypoint=/bin/terraform", r.Toolchain.Image}
		return artifactCommand(ctx, binary, "", append(base, args...)...)
	}
	if out.VersionJSON, e = run("version", "-json"); e != nil {
		return out, e
	}
	if out.PlanJSON, e = run("show", "-json", "/artifacts/plan.bin"); e != nil {
		return out, e
	}
	if out.StateJSON, e = run("show", "-json", "/artifacts/state.raw"); e != nil {
		return out, e
	}
	workspace, e := run("workspace", "show")
	if e != nil {
		return out, e
	}
	out.Workspace = strings.TrimSpace(string(workspace))
	if out.Workspace == "" {
		return out, fmt.Errorf("CONFIGURATION_ARTIFACT_WORKSPACE_UNAVAILABLE")
	}
	return out, nil
}
