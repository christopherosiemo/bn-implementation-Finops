package gitfixture

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func requireGit(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("real Git fixture is Linux-only; run in golang:1.27.3-bookworm@sha256:32fa283222e2905d9fee971f60c842e5c815fdc036cf7ea599bf36bd7ca8f67f")
	}
	for _, path := range []string{GitExecutable, BackendExecutable} {
		if _, err := os.Stat(path); err != nil {
			t.Skipf("fixed local Git binary unavailable: %s", path)
		}
	}
}

func localGit(t *testing.T, directory string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, GitExecutable, args...)
	cmd.Dir = directory
	cmd.Env = []string{
		"PATH=/usr/bin:/bin", "HOME=/nonexistent", "XDG_CONFIG_HOME=/nonexistent",
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_TERMINAL_PROMPT=0", "GIT_EXEC_PATH=/usr/lib/git-core", "LC_ALL=C",
		"GIT_AUTHOR_NAME=Fixture", "GIT_AUTHOR_EMAIL=fixture@example.invalid",
		"GIT_COMMITTER_NAME=Fixture", "GIT_COMMITTER_EMAIL=fixture@example.invalid",
		"GIT_ALLOW_PROTOCOL=file:http", "GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=core.hooksPath", "GIT_CONFIG_VALUE_0=/dev/null",
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("local Git %v failed: %v\n%s", args, err, output)
	}
	return strings.TrimSpace(string(output))
}

func fixture(t *testing.T) (bare, work string) {
	t.Helper()
	requireGit(t)
	root := t.TempDir()
	bare = filepath.Join(root, RepositoryName)
	work = filepath.Join(root, "work")
	localGit(t, root, "init", "--initial-branch=main", work)
	if err := os.WriteFile(filepath.Join(work, "deployment.yaml"), []byte("kind: Deployment\nmetadata:\n  name: synthetic-fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	localGit(t, work, "add", "deployment.yaml")
	localGit(t, work, "commit", "-m", "synthetic fixture")
	localGit(t, root, "init", "--bare", "--initial-branch=main", bare)
	localGit(t, work, "push", bare, "main")
	return bare, work
}

func TestRealGitSmartHTTPCloneFetchAndReadOnly(t *testing.T) {
	bare, work := fixture(t)
	handler, err := New(Config{RepositoryDir: bare})
	if err != nil {
		t.Fatal(err)
	}
	counts := make(map[string]int)
	var countsMu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		countsMu.Lock()
		counts[r.Method+" "+r.URL.Path]++
		countsMu.Unlock()
		handler.ServeHTTP(w, r)
	}))
	defer server.Close()
	url := server.URL + "/repository.git"
	clone := filepath.Join(t.TempDir(), "clone")
	poisonHome := t.TempDir()
	marker := filepath.Join(poisonHome, "unexpected-helper")
	writeTestFile(t, filepath.Join(poisonHome, ".gitconfig"), []byte("[uploadpack]\n\tpackObjectsHook = touch "+marker+"\n"))
	t.Setenv("HOME", poisonHome)
	t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(poisonHome, ".gitconfig"))
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_CONFIG_KEY_0", "uploadpack.packObjectsHook")
	t.Setenv("GIT_CONFIG_VALUE_0", "touch "+marker)
	localGit(t, t.TempDir(), "clone", "--no-local", url, clone)
	if got, want := localGit(t, clone, "rev-parse", "HEAD"), localGit(t, work, "rev-parse", "HEAD"); got != want {
		t.Fatalf("cloned commit = %s, want %s", got, want)
	}
	data, err := os.ReadFile(filepath.Join(clone, "deployment.yaml"))
	if err != nil || !bytes.Contains(data, []byte("synthetic-fixture")) {
		t.Fatalf("real cloned content missing: %q, %v", data, err)
	}
	// The server mount remains read-only. A fixture producer can publish a new
	// synthetic commit through the host-owned local bare repository.
	if err := os.WriteFile(filepath.Join(work, "deployment.yaml"), []byte("kind: Deployment\nmetadata:\n  name: synthetic-fixture-v2\n"), 0600); err != nil {
		t.Fatal(err)
	}
	localGit(t, work, "commit", "-am", "synthetic revision two")
	localGit(t, work, "push", bare, "main")
	localGit(t, clone, "fetch", "origin")
	localGit(t, clone, "-c", "protocol.version=0", "fetch", "origin")
	if got, want := localGit(t, clone, "rev-parse", "origin/main"), localGit(t, work, "rev-parse", "HEAD"); got != want {
		t.Fatalf("fetched commit = %s, want %s", got, want)
	}
	countsMu.Lock()
	if counts["GET /repository.git/info/refs"] < 3 || counts["POST /repository.git/git-upload-pack"] < 2 {
		t.Fatalf("clone/fetch did not use smart HTTP: %#v", counts)
	}
	countsMu.Unlock()
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("host Git configuration/helper was used: %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "/repository.git/info/refs?service=git-receive-pack", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("receive-pack discovery accepted: %d", response.Code)
	}
	request = httptest.NewRequest(http.MethodPost, "/repository.git/git-receive-pack", strings.NewReader("0000"))
	request.Header.Set("Content-Type", "application/x-git-receive-pack-request")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("receive-pack write accepted: %d", response.Code)
	}
	if got := localGit(t, bare, "for-each-ref", "--format=%(refname)"); got != "refs/heads/main" {
		t.Fatalf("unexpected bare references: %q", got)
	}
}

func TestRouteAllowlistRejectsAliasesTraversalAndOtherServices(t *testing.T) {
	tests := []struct{ method, url, contentType string }{
		{"GET", "/", ""}, {"HEAD", "/repository.git/info/refs?service=git-upload-pack", ""},
		{"PUT", "/repository.git/git-upload-pack", "application/x-git-upload-pack-request"},
		{"GET", "/repository.git/info/refs", ""}, {"GET", "/repository.git/info/refs?service=git-receive-pack", ""},
		{"GET", "/repository.git/info/refs?service=git-upload-pack&extra=1", ""},
		{"GET", "/repository.git/info/refs?service=git-upload-pack&service=git-upload-pack", ""},
		{"GET", "/repository.git/info/refs?service=git%2dupload-pack", ""},
		{"GET", "/repository.git/info/refs?%73ervice=git-upload-pack", ""},
		{"GET", "/repository.git//info/refs?service=git-upload-pack", ""},
		{"GET", "/other.git/info/refs?service=git-upload-pack", ""},
		{"GET", "/repository.git/../other.git/info/refs?service=git-upload-pack", ""},
		{"GET", "/repository.git/%2e%2e/other.git/info/refs?service=git-upload-pack", ""},
		{"GET", "/%72epository.git/info/refs?service=git-upload-pack", ""},
		{"GET", "/repository.git/HEAD", ""}, {"GET", "/repository.git/config", ""},
		{"GET", "/repository.git/objects/info/packs", ""},
		{"POST", "/repository.git/git-upload-pack?x=1", "application/x-git-upload-pack-request"},
		{"POST", "/repository.git/git-upload-pack?", "application/x-git-upload-pack-request"},
		{"POST", "/repository.git/git-upload-pack", "text/plain"},
		{"POST", "/repository.git/git-upload-pack", "application/x-git-upload-pack-request; charset=utf-8"},
	}
	for _, test := range tests {
		t.Run(test.method+" "+test.url, func(t *testing.T) {
			r := httptest.NewRequest(test.method, test.url, strings.NewReader("0000"))
			if test.contentType != "" {
				r.Header.Set("Content-Type", test.contentType)
			}
			h := &Handler{}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("route accepted with status %d", w.Code)
			}
		})
	}
}

func TestRequestBoundsAndSensitiveHeaderRejection(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*http.Request)
		status int
	}{
		{"authorization", func(r *http.Request) { r.Header.Set("Authorization", "Bearer synthetic-secret") }, 400},
		{"proxy-authorization", func(r *http.Request) { r.Header.Set("Proxy-Authorization", "Basic synthetic-secret") }, 400},
		{"encoding", func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") }, 400},
		{"protocol", func(r *http.Request) { r.Header.Set("Git-Protocol", "version=2:agent=custom") }, 400},
		{"duplicate-protocol", func(r *http.Request) { r.Header["Git-Protocol"] = []string{"version=2", "version=2"} }, 400},
		{"headers", func(r *http.Request) { r.Header.Set("X-Large", strings.Repeat("a", 16<<10)) }, 400},
		{"content-length", func(r *http.Request) { r.ContentLength = MaxRequestBytes + 1 }, 413},
		{"streamed-body", func(r *http.Request) {
			r.ContentLength = -1
			r.Body = io.NopCloser(strings.NewReader(strings.Repeat("a", MaxRequestBytes+1)))
		}, 413},
		{"empty-upload", func(r *http.Request) { r.ContentLength = 0; r.Body = http.NoBody }, 400},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/repository.git/git-upload-pack", strings.NewReader("0000"))
			r.Header.Set("Content-Type", "application/x-git-upload-pack-request")
			test.mutate(r)
			h := &Handler{slots: make(chan struct{}, 2)}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != test.status {
				t.Fatalf("status = %d, want %d", w.Code, test.status)
			}
		})
	}
	w := &boundedResponse{ResponseWriter: httptest.NewRecorder(), remaining: 3}
	if _, err := w.Write([]byte("1234")); err == nil {
		t.Fatal("response over limit was accepted")
	}
	if n, err := w.Write([]byte("123")); n != 3 || err != nil {
		t.Fatalf("bounded response: %d, %v", n, err)
	}
}

func TestSanitizedCGIRequestAndEnvironment(t *testing.T) {
	bare, _ := fixture(t)
	handler, err := New(Config{RepositoryDir: bare})
	if err != nil {
		t.Fatal(err)
	}
	called := false
	handler.backend = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if r.Host != "fixture.invalid" || r.RemoteAddr != "127.0.0.1:0" || len(r.Header) != 2 || r.ContentLength != 4 || len(r.TransferEncoding) != 0 || len(r.Trailer) != 0 {
			t.Errorf("CGI request was not sanitized: %#v", r)
		}
		if r.Header.Get("Cookie") != "" || r.Header.Get("X-Host-Secret") != "" || r.Header.Get("Git-Protocol") != "version=2" {
			t.Errorf("CGI headers were not allowlisted: %#v", r.Header)
		}
		w.WriteHeader(200)
	})
	r := httptest.NewRequest("POST", "/repository.git/git-upload-pack", strings.NewReader("0000"))
	r.ContentLength = -1
	r.TransferEncoding = []string{"chunked"}
	r.Host = "host-secret.invalid"
	r.Header.Set("Content-Type", "application/x-git-upload-pack-request")
	r.Header.Set("Git-Protocol", "version=2")
	r.Header.Set("Cookie", "host-secret=synthetic")
	r.Header.Set("X-Host-Secret", "synthetic")
	r.Trailer = http.Header{"X-Secret": []string{"synthetic"}}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != 200 || !called {
		t.Fatalf("valid normalized request rejected: %d, called=%v", w.Code, called)
	}
	t.Setenv("GIT_CONFIG_GLOBAL", "/host/secret")
	t.Setenv("GIT_SSH_COMMAND", "unexpected-helper")
	t.Setenv("LD_LIBRARY_PATH", "/host/secrets")
	env := strings.Join(backendEnvironment(bare), "\n")
	for _, unsafe := range []string{"/host/secret", "unexpected-helper"} {
		if strings.Contains(env, unsafe) {
			t.Fatalf("host environment inherited: %s", unsafe)
		}
	}
	for _, expected := range []string{"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null", "HOME=/nonexistent", "GIT_EXEC_PATH=/usr/lib/git-core", "GIT_ALLOW_PROTOCOL=", "LD_LIBRARY_PATH="} {
		if !strings.Contains(env, expected) {
			t.Errorf("missing fixed environment value %q", expected)
		}
	}
}

func TestRepositoryConfigAndPathFailClosed(t *testing.T) {
	requireGit(t)
	for _, test := range []struct {
		name   string
		mutate func(t *testing.T, bare string)
	}{
		{"remote", func(t *testing.T, bare string) {
			localGit(t, bare, "config", "remote.origin.url", "https://example.invalid/source.git")
		}},
		{"include", func(t *testing.T, bare string) { localGit(t, bare, "config", "include.path", "/host/secret") }},
		{"hook-config", func(t *testing.T, bare string) {
			localGit(t, bare, "config", "uploadpack.packObjectsHook", "touch /tmp/unexpected")
		}},
		{"not-bare", func(t *testing.T, bare string) { localGit(t, bare, "config", "core.bare", "false") }},
		{"alternates", func(t *testing.T, bare string) {
			writeTestFile(t, filepath.Join(bare, "objects/info/alternates"), []byte("/host/objects\n"))
		}},
		{"hook-file", func(t *testing.T, bare string) {
			writeTestFile(t, filepath.Join(bare, "hooks/upload-pack"), []byte("#!/bin/sh\nexit 0\n"))
		}},
		{"object-symlink", func(t *testing.T, bare string) {
			if err := os.Symlink(t.TempDir(), filepath.Join(bare, "objects/escape")); err != nil {
				t.Fatal(err)
			}
		}},
		{"oversized-config", func(t *testing.T, bare string) {
			writeTestFile(t, filepath.Join(bare, "config"), []byte(strings.Repeat("#", 4097)))
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			bare, _ := fixture(t)
			test.mutate(t, bare)
			if _, err := New(Config{RepositoryDir: bare}); err == nil {
				t.Fatal("unsafe repository accepted")
			}
		})
	}
	bare, _ := fixture(t)
	link := filepath.Join(t.TempDir(), RepositoryName)
	if err := os.Symlink(bare, link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"repository.git", filepath.Join(bare, "..", "work"), link} {
		if _, err := New(Config{RepositoryDir: path}); err == nil {
			t.Fatalf("unsafe path accepted: %s", path)
		}
	}
	handler, err := New(Config{RepositoryDir: bare})
	if err != nil {
		t.Fatal(err)
	}
	localGit(t, bare, "config", "include.path", "/host/secret")
	r := httptest.NewRequest("GET", "/repository.git/info/refs?service=git-upload-pack", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), "/host/secret") {
		t.Fatalf("late repository mutation did not fail closed: %d %s", w.Code, w.Body.String())
	}
}

func writeTestFile(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestFixtureBusyRejectsAdditionalRequests(t *testing.T) {
	h := &Handler{slots: make(chan struct{}, 2)}
	h.slots <- struct{}{}
	h.slots <- struct{}{}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/repository.git/info/refs?service=git-upload-pack", nil)
	h.ServeHTTP(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatal(fmt.Sprintf("busy status = %d", w.Code))
	}
}
