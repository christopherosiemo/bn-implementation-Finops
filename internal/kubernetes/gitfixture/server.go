// Package gitfixture serves one synthetic, local bare Git repository for the
// Kubernetes integration lab. It is intentionally not a general Git host.
// The repository must be mounted read-only for the lifetime of the handler.
package gitfixture

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cgi"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

const (
	GitExecutable      = "/usr/bin/git"
	BackendExecutable  = "/usr/lib/git-core/git-http-backend"
	RepositoryName     = "repository.git"
	ListenAddress      = ":8080"
	MaxRequestBytes    = 1 << 20
	MaxResponseBytes   = 32 << 20
	maxRepositorySize  = 64 << 20
	maxRepositoryFiles = 20000
)

// Config identifies the sole approved synthetic fixture repository. It must be
// an absolute, symlink-free path ending in repository.git, with no remotes,
// includes, alternate object stores, or custom Git configuration.
type Config struct {
	RepositoryDir string
}

// Handler serves only smart-HTTP upload-pack. Its request concurrency and
// request/response sizes are bounded independently of the HTTP server.
type Handler struct {
	repository string
	backend    http.Handler
	slots      chan struct{}
	validateMu sync.Mutex
}

// New validates a local fixture and the fixed Git binaries. Linux is required;
// callers on other platforms should run this fixture in the pinned lab image.
func New(config Config) (*Handler, error) {
	if runtime.GOOS != "linux" {
		return nil, errors.New("git fixture requires the Linux lab image")
	}
	if !filepath.IsAbs(config.RepositoryDir) || filepath.Clean(config.RepositoryDir) != config.RepositoryDir || filepath.Base(config.RepositoryDir) != RepositoryName {
		return nil, errors.New("repository must be an absolute clean path ending in repository.git")
	}
	for _, binary := range []string{GitExecutable, BackendExecutable} {
		if err := validateExecutable(binary); err != nil {
			return nil, err
		}
	}
	if err := validateRepository(config.RepositoryDir); err != nil {
		return nil, err
	}
	backend := &cgi.Handler{
		Path: BackendExecutable,
		Dir:  config.RepositoryDir,
		Env:  backendEnvironment(config.RepositoryDir),
		// CGI errors and Git diagnostics must not leak filesystem/configuration
		// details into either the response or the host's shared logs.
		Logger: log.New(io.Discard, "", 0),
		Stderr: io.Discard,
	}
	return &Handler{repository: config.RepositoryDir, backend: backend, slots: make(chan struct{}, 2)}, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if !allowedRequest(r) {
		http.Error(w, "fixture route rejected", http.StatusBadRequest)
		return
	}
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	default:
		http.Error(w, "fixture busy", http.StatusServiceUnavailable)
		return
	}
	if r.ContentLength > MaxRequestBytes {
		http.Error(w, "fixture request too large", http.StatusRequestEntityTooLarge)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxRequestBytes+1))
	if err != nil {
		http.Error(w, "fixture request unreadable", http.StatusBadRequest)
		return
	}
	if len(body) > MaxRequestBytes {
		http.Error(w, "fixture request too large", http.StatusRequestEntityTooLarge)
		return
	}
	if r.Method == http.MethodGet && len(body) != 0 {
		http.Error(w, "fixture discovery body rejected", http.StatusBadRequest)
		return
	}
	if r.Method == http.MethodPost && len(body) == 0 {
		http.Error(w, "fixture upload-pack body required", http.StatusBadRequest)
		return
	}
	// A read-only mount is part of the fixture contract. Revalidate before each
	// request as an additional fail-closed check against accidental replacement.
	h.validateMu.Lock()
	err = validateRepository(h.repository)
	h.validateMu.Unlock()
	if err != nil {
		http.Error(w, "fixture repository rejected", http.StatusServiceUnavailable)
		return
	}
	request := r.Clone(r.Context())
	request.Body = io.NopCloser(bytes.NewReader(body))
	request.ContentLength = int64(len(body))
	request.TransferEncoding = nil // CGI requires a known, bounded body length.
	request.Trailer = nil
	request.Host = "fixture.invalid"
	request.RemoteAddr = "127.0.0.1:0"
	request.Header = make(http.Header)
	if r.Method == http.MethodPost {
		request.Header.Set("Content-Type", "application/x-git-upload-pack-request")
	}
	if protocol := r.Header.Get("Git-Protocol"); protocol != "" {
		request.Header.Set("Git-Protocol", protocol)
	}
	// No authorization, cookie, proxy, or caller-selected HTTP environment is
	// propagated to Git. The two allowed URL values were checked byte-for-byte.
	h.backend.ServeHTTP(&boundedResponse{ResponseWriter: w, remaining: MaxResponseBytes}, request)
}

func allowedRequest(r *http.Request) bool {
	if r.URL == nil || r.URL.User != nil || r.URL.Opaque != "" || r.URL.Fragment != "" || r.URL.RawPath != "" || r.URL.ForceQuery {
		return false
	}
	wantURI := ""
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/repository.git/info/refs" && r.URL.RawQuery == "service=git-upload-pack":
		wantURI = "/repository.git/info/refs?service=git-upload-pack"
	case r.Method == http.MethodPost && r.URL.Path == "/repository.git/git-upload-pack" && r.URL.RawQuery == "":
		wantURI = "/repository.git/git-upload-pack"
		if len(r.Header.Values("Content-Type")) != 1 || r.Header.Get("Content-Type") != "application/x-git-upload-pack-request" {
			return false
		}
	default:
		return false
	}
	if r.RequestURI != "" && r.RequestURI != wantURI {
		return false
	}
	if r.ContentLength < -1 || len(r.Header) > 64 {
		return false
	}
	headerBytes := 0
	for key, values := range r.Header {
		for _, value := range values {
			headerBytes += len(key) + len(value)
		}
	}
	if headerBytes > 16<<10 || len(r.Header.Values("Git-Protocol")) > 1 {
		return false
	}
	if protocol := r.Header.Get("Git-Protocol"); protocol != "" && protocol != "version=1" && protocol != "version=2" {
		return false
	}
	return r.Header.Get("Content-Encoding") == "" && r.Header.Get("Authorization") == "" && r.Header.Get("Proxy-Authorization") == ""
}

type boundedResponse struct {
	http.ResponseWriter
	remaining int
}

func (w *boundedResponse) Write(p []byte) (int, error) {
	if len(p) > w.remaining {
		return 0, errors.New("fixture response exceeds limit")
	}
	n, err := w.ResponseWriter.Write(p)
	w.remaining -= n
	return n, err
}

func backendEnvironment(repository string) []string {
	env := []string{
		"PATH=/usr/bin:/bin", "HOME=/nonexistent", "XDG_CONFIG_HOME=/nonexistent",
		"LANG=C", "LC_ALL=C", "LD_LIBRARY_PATH=", "LD_PRELOAD=",
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_EXEC_PATH=/usr/lib/git-core", "GIT_TERMINAL_PROMPT=0", "GIT_ASKPASS=", "SSH_ASKPASS=",
		"GIT_ALLOW_PROTOCOL=", "GIT_PROTOCOL_FROM_USER=0",
		"GIT_PROJECT_ROOT=" + filepath.Dir(repository), "GIT_HTTP_EXPORT_ALL=1",
	}
	settings := [][2]string{
		{"safe.directory", repository}, {"core.hooksPath", "/dev/null"},
		{"http.receivepack", "false"}, {"http.uploadpack", "true"}, {"http.getanyfile", "false"},
		{"protocol.allow", "never"}, {"protocol.ext.allow", "never"}, {"protocol.file.allow", "never"},
		{"submodule.recurse", "false"}, {"uploadpack.allowFilter", "false"},
		{"uploadpack.allowAnySHA1InWant", "false"}, {"uploadpack.allowTipSHA1InWant", "false"},
		{"uploadpack.allowReachableSHA1InWant", "false"},
	}
	env = append(env, fmt.Sprintf("GIT_CONFIG_COUNT=%d", len(settings)))
	for i, setting := range settings {
		env = append(env, fmt.Sprintf("GIT_CONFIG_KEY_%d=%s", i, setting[0]), fmt.Sprintf("GIT_CONFIG_VALUE_%d=%s", i, setting[1]))
	}
	return env
}

func validateExecutable(path string) error {
	if err := rejectSymlinkComponents(path); err != nil {
		return fmt.Errorf("fixture executable rejected: %w", err)
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 || info.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("fixture executable is unavailable or writable: %s", path)
	}
	return nil
}

func rejectSymlinkComponents(path string) error {
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("symlink path rejected")
		}
		if filepath.Dir(current) == current {
			return nil
		}
	}
}

func validateRepository(repository string) error {
	if err := rejectSymlinkComponents(repository); err != nil {
		return fmt.Errorf("fixture repository path rejected: %w", err)
	}
	info, err := os.Stat(repository)
	if err != nil || !info.IsDir() {
		return errors.New("fixture repository is not a directory")
	}
	var size int64
	files := 0
	err = filepath.WalkDir(repository, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		files++
		if files > maxRepositoryFiles {
			return errors.New("fixture repository has too many files")
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
			return errors.New("fixture repository contains a symlink or special file")
		}
		size += info.Size()
		if size > maxRepositorySize {
			return errors.New("fixture repository exceeds size limit")
		}
		relative, err := filepath.Rel(repository, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		switch relative {
		case "objects/info/alternates", "objects/info/http-alternates", "info/grafts", "commondir", "gitdir":
			return errors.New("fixture repository has an external or replacement object store")
		}
		if strings.HasPrefix(relative, "hooks/") && !info.IsDir() && !strings.HasSuffix(relative, ".sample") {
			return errors.New("fixture repository has a custom hook")
		}
		return nil
	})
	if err != nil {
		return err
	}
	config, err := os.ReadFile(filepath.Join(repository, "config"))
	if err != nil || len(config) > 4096 {
		return errors.New("fixture repository config missing or oversized")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, GitExecutable, "config", "--no-includes", "--file", filepath.Join(repository, "config"), "--null", "--list")
	cmd.Dir = repository
	cmd.Env = backendEnvironment(repository)
	cmd.Stderr = io.Discard
	output, err := cmd.Output()
	if err != nil || len(output) > 8192 {
		return errors.New("fixture repository config cannot be validated")
	}
	seen := make(map[string]bool)
	for _, entry := range bytes.Split(bytes.TrimSuffix(output, []byte{0}), []byte{0}) {
		pair := strings.SplitN(string(entry), "\n", 2)
		if len(pair) != 2 || seen[pair[0]] {
			return errors.New("fixture repository config has duplicate or malformed settings")
		}
		seen[pair[0]] = true
		valid := false
		switch pair[0] {
		case "core.repositoryformatversion":
			valid = pair[1] == "0"
		case "core.bare":
			valid = pair[1] == "true"
		case "core.filemode", "core.logallrefupdates":
			valid = pair[1] == "true" || pair[1] == "false"
		}
		if !valid {
			return errors.New("fixture repository config contains an unsupported setting")
		}
	}
	if !seen["core.bare"] || !seen["core.repositoryformatversion"] {
		return errors.New("fixture repository is not an approved bare repository")
	}
	for _, directory := range []string{"objects", "refs"} {
		info, err := os.Stat(filepath.Join(repository, directory))
		if err != nil || !info.IsDir() {
			return errors.New("fixture bare repository structure missing")
		}
	}
	head, err := os.ReadFile(filepath.Join(repository, "HEAD"))
	if err != nil || len(head) == 0 || len(head) > 1024 {
		return errors.New("fixture repository HEAD missing or oversized")
	}
	return nil
}
