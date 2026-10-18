package kubernetes

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func fluxTestArchive(t *testing.T, files map[string][]byte, extras ...*tar.Header) []byte {
	t.Helper()
	var buffer bytes.Buffer
	gz := gzip.NewWriter(&buffer)
	tarWriter := tar.NewWriter(gz)
	for name, content := range files {
		if e := tarWriter.WriteHeader(&tar.Header{Name: name, Mode: 0444, Typeflag: tar.TypeReg, Size: int64(len(content))}); e != nil {
			t.Fatal(e)
		}
		if _, e := tarWriter.Write(content); e != nil {
			t.Fatal(e)
		}
	}
	for _, extra := range extras {
		if extra == nil {
			continue
		}
		if e := tarWriter.WriteHeader(extra); e != nil {
			t.Fatal(e)
		}
	}
	if e := tarWriter.Close(); e != nil {
		t.Fatal(e)
	}
	if e := gz.Close(); e != nil {
		t.Fatal(e)
	}
	return buffer.Bytes()
}

func TestFluxObservedNativeRootDirectoryPreservesExactStaticProof(t *testing.T) {
	b, _, _, files := fluxTestDocuments(t)
	root := &tar.Header{Name: ".", Typeflag: tar.TypeDir, Mode: 0755}
	dir := &tar.Header{Name: "workload", Typeflag: tar.TypeDir, Mode: 0755}
	hash, err := fluxManifest(fluxTestArchive(t, files, root, dir), b)
	if err != nil || hash != testInput(t).Snapshot.Deployment.SpecHash {
		t.Fatalf("observed empty native directories changed proof: %s, %v", hash, err)
	}
	for _, tc := range []struct {
		name    string
		headers []*tar.Header
		paxKey  string
	}{
		{"duplicate-root", []*tar.Header{root, root}, ""},
		{"duplicate-workload-directory", []*tar.Header{dir, dir}, ""},
		{"root-alias", []*tar.Header{{Name: "./", Typeflag: tar.TypeDir, Mode: 0755}}, ""},
		{"root-regular-file", []*tar.Header{{Name: ".", Typeflag: tar.TypeReg, Mode: 0444}}, ""},
		{"root-symlink", []*tar.Header{{Name: ".", Typeflag: tar.TypeSymlink, Linkname: "workload"}}, ""},
		{"root-link-metadata", []*tar.Header{{Name: ".", Typeflag: tar.TypeDir, Linkname: "../outside"}}, ""},
		{"root-parent", []*tar.Header{{Name: "..", Typeflag: tar.TypeDir}}, ""},
		// Long names force real standard PAX records. archive/tar deliberately
		// ignores caller-provided path/linkpath overrides in PAXRecords.
		{"pax-path", []*tar.Header{{Name: "../" + strings.Repeat("x", 101), Typeflag: tar.TypeDir, Format: tar.FormatPAX}}, "path"},
		{"pax-linkpath", []*tar.Header{{Name: ".", Typeflag: tar.TypeSymlink, Linkname: "../" + strings.Repeat("x", 101), Format: tar.FormatPAX}}, "linkpath"},
		{"pax-unknown-metadata", []*tar.Header{{Name: ".", Typeflag: tar.TypeDir, Format: tar.FormatPAX, PAXRecords: map[string]string{"fixture.unapproved": "true"}}}, "fixture.unapproved"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := fluxTestArchive(t, files, tc.headers...)
			if tc.paxKey != "" {
				gz, err := gzip.NewReader(bytes.NewReader(raw))
				if err != nil {
					t.Fatal(err)
				}
				defer gz.Close()
				tr := tar.NewReader(gz)
				found := false
				for {
					h, err := tr.Next()
					if err == io.EOF {
						break
					}
					if err != nil {
						t.Fatal(err)
					}
					found = found || h.PAXRecords[tc.paxKey] != ""
				}
				if !found {
					t.Fatal("fixture did not emit the required PAX record")
				}
			}
			if _, err := fluxManifest(raw, b); err == nil {
				t.Fatal("unsafe root or metadata became rendered authority")
			}
		})
	}
}

func fluxTestDocuments(t *testing.T) (Binding, Document, Document, map[string][]byte) {
	t.Helper()
	in := testInput(t)
	b := in.Snapshot.Binding
	b.Git = GitBinding{Engine: "FLUX", Repository: "http://172.18.0.10:8080/repository.git", Path: "./workload", ControllerNamespace: "flux-lab", ControllerName: "workload", ControllerUID: "kustomization-uid", SourceName: "workload", SourceUID: "source-uid", ManifestPath: "workload/deployment.json", SourceBranch: "main", ApplyServiceAccount: "workload"}
	rev := "main@sha1:" + in.ExpectedGitRevision
	kustomization := Document{"metadata": Document{"uid": b.Git.ControllerUID, "generation": 2, "resourceVersion": "k2"}, "spec": Document{"path": b.Git.Path, "targetNamespace": b.Namespace, "serviceAccountName": "workload", "sourceRef": Document{"kind": "GitRepository", "name": b.Git.SourceName}, "wait": true, "prune": false, "deletionPolicy": "Orphan"}, "status": Document{"observedGeneration": 2, "lastAppliedRevision": rev, "lastAttemptedRevision": rev, "conditions": []any{Document{"type": "Ready", "status": "True", "observedGeneration": 2}}, "history": []any{Document{"lastReconciledStatus": "ReconciliationSucceeded", "lastReconciled": in.Now.Format(time.RFC3339Nano), "metadata": Document{"revision": rev}}}}}
	source := Document{"metadata": Document{"uid": b.Git.SourceUID, "generation": 1, "resourceVersion": "s1"}, "spec": Document{"url": b.Git.Repository, "ref": Document{"branch": "main"}}, "status": Document{"observedGeneration": 1, "conditions": []any{Document{"type": "Ready", "status": "True", "observedGeneration": 1}}, "artifact": Document{"revision": rev, "path": "gitrepository/flux-lab/workload/commit.tar.gz", "url": "http://source-controller.flux-lab.svc.cluster.local./gitrepository/flux-lab/workload/commit.tar.gz"}}}
	manifest, _ := json.Marshal(Document{"apiVersion": "apps/v1", "kind": "Deployment", "metadata": Document{"namespace": b.Namespace, "name": b.Deployment}, "spec": in.Snapshot.Deployment.Spec})
	code, _ := json.Marshal(Document{"apiVersion": "v1", "kind": "ConfigMap", "metadata": Document{"namespace": b.Namespace, "name": "gateway-code"}, "data": Document{"gateway.py": "print('local fixture')"}})
	files := map[string][]byte{"workload/deployment.json": manifest, "workload/gateway-code.json": code, "workload/kustomization.yaml": []byte(`{"apiVersion":"kustomize.config.k8s.io/v1beta1","kind":"Kustomization","resources":["deployment.json","gateway-code.json"]}`)}
	return b, kustomization, source, files
}

func TestFluxNativeSourceAndDigestPinnedManifestProof(t *testing.T) {
	b, k, source, files := fluxTestDocuments(t)
	raw := fluxTestArchive(t, files, nil)
	object(object(source["status"])["artifact"])["digest"] = "sha256:" + HashBytes(raw)
	reads := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		reads++
		if request.Method != "GET" || request.Header.Get("Authorization") != "Bearer read-only" || request.URL.Path != "/api/v1/namespaces/flux-lab/services/source-controller:80/proxy/gitrepository/flux-lab/workload/commit.tar.gz" {
			t.Error("artifact escaped pinned read-only Kubernetes Service proxy")
		}
		_, _ = w.Write(raw)
	}))
	defer server.Close()
	r := Reader{URL: server.URL, Token: "read-only", Client: server.Client()}
	read := func(key, _ string) (Document, error) {
		if strings.HasPrefix(key, "git_source") {
			return source, nil
		}
		return k, nil
	}
	g, err := r.flux(context.Background(), b, read)
	if err != nil || !g.Ready || !g.Synced || g.Repository != b.Git.Repository || g.DeploymentSpecHash != testInput(t).Snapshot.Deployment.SpecHash || g.ArtifactHash != HashBytes(raw) || g.ObservedAt.IsZero() || reads != 1 {
		t.Fatalf("native proof missing: %+v, %v", g, err)
	}
	// An arbitrary request annotation never refreshes controller evidence.
	delete(object(k["status"]), "history")
	object(k["status"])["lastHandledReconcileAt"] = time.Now().UTC().Format(time.RFC3339Nano)
	g, err = r.flux(context.Background(), b, read)
	if err != nil || !g.ObservedAt.IsZero() {
		t.Fatal("client request token became a controller observation timestamp")
	}
}

func TestFluxPartialFailedOrChangedAuthorityNeverClaimsSync(t *testing.T) {
	for _, mode := range []string{"generation", "failure", "source-revision", "controller-uid", "source-uid", "repository", "transform", "cross-namespace", "branch", "ref-selector", "applier", "deletion-policy", "repository-credentials"} {
		t.Run(mode, func(t *testing.T) {
			b, k, source, _ := fluxTestDocuments(t)
			switch mode {
			case "generation":
				object(k["status"])["observedGeneration"] = 1
			case "failure":
				object(k["status"])["conditions"] = []any{Document{"type": "Ready", "status": "False", "observedGeneration": 2}}
			case "source-revision":
				object(object(source["status"])["artifact"])["revision"] = "main@sha1:" + strings.Repeat("f", 40)
			case "controller-uid":
				object(k["metadata"])["uid"] = "replaced"
			case "source-uid":
				object(source["metadata"])["uid"] = "replaced"
			case "repository":
				object(source["spec"])["url"] = "http://different.invalid/repository.git"
			case "transform":
				object(k["spec"])["postBuild"] = Document{"substitute": Document{"memory": "1"}}
			case "cross-namespace":
				object(object(k["spec"])["sourceRef"])["namespace"] = "another-tenant"
			case "branch":
				object(object(source["spec"])["ref"])["branch"] = "other"
			case "ref-selector":
				object(object(source["spec"])["ref"])["commit"] = strings.Repeat("a", 40)
			case "applier":
				object(k["spec"])["serviceAccountName"] = "cluster-admin"
			case "deletion-policy":
				object(k["spec"])["deletionPolicy"] = "Delete"
			case "repository-credentials":
				b.Git.Repository = "http://user:secret@172.18.0.10:8080/repository.git"
				object(source["spec"])["url"] = b.Git.Repository
			}
			r := Reader{}
			g, e := r.flux(context.Background(), b, func(key, _ string) (Document, error) {
				if strings.HasPrefix(key, "git_source") {
					return source, nil
				}
				return k, nil
			})
			if e == nil && g.Synced {
				t.Fatal("partial/failed/changed source claimed successful reconciliation")
			}
		})
	}
}

func TestFluxAuthorityCannotChangeDuringArtifactRead(t *testing.T) {
	for _, changed := range []string{"git_ack_after", "git_source_after"} {
		t.Run(changed, func(t *testing.T) {
			b, k, source, files := fluxTestDocuments(t)
			raw := fluxTestArchive(t, files, nil)
			object(object(source["status"])["artifact"])["digest"] = "sha256:" + HashBytes(raw)
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(raw) }))
			defer server.Close()
			r := Reader{URL: server.URL, Token: "read-only", Client: server.Client()}
			_, err := r.flux(context.Background(), b, func(key, _ string) (Document, error) {
				d := k
				if strings.HasPrefix(key, "git_source") {
					d = source
				}
				if key == changed {
					copy := Document{}
					for name, value := range d {
						copy[name] = value
					}
					meta := Document{}
					for name, value := range object(d["metadata"]) {
						meta[name] = value
					}
					meta["resourceVersion"] = "new-authority"
					copy["metadata"] = meta
					return copy, nil
				}
				return d, nil
			})
			if err == nil || !strings.Contains(err.Error(), "AUTHORITY_CHANGED") {
				t.Fatalf("changed authority accepted: %v", err)
			}
		})
	}
}

func TestFluxArtifactArchiveAndStaticRenderingFailClosed(t *testing.T) {
	for _, mode := range []string{"traversal", "symlink", "duplicate", "extra", "transform", "target", "missing", "render-drift"} {
		t.Run(mode, func(t *testing.T) {
			b, _, _, files := fluxTestDocuments(t)
			var extra *tar.Header
			switch mode {
			case "traversal":
				extra = &tar.Header{Name: "../escape", Typeflag: tar.TypeReg, Mode: 0444}
			case "symlink":
				extra = &tar.Header{Name: "workload/link", Typeflag: tar.TypeSymlink, Linkname: "deployment.json"}
			case "duplicate":
				extra = &tar.Header{Name: "workload/deployment.json", Typeflag: tar.TypeReg, Mode: 0444}
			case "extra":
				files["workload/unapproved.json"] = []byte(`{}`)
			case "transform":
				files["workload/kustomization.yaml"] = []byte(`{"apiVersion":"kustomize.config.k8s.io/v1beta1","kind":"Kustomization","resources":["deployment.json","gateway-code.json"],"namePrefix":"changed-"}`)
			case "target":
				b.Deployment = "different"
			case "missing":
				delete(files, "workload/gateway-code.json")
			case "render-drift":
				files["workload/deployment.json"] = bytes.ReplaceAll(files["workload/deployment.json"], []byte(`"replicas":2`), []byte(`"replicas":3`))
			}
			hash, e := fluxManifest(fluxTestArchive(t, files, extra), b)
			if mode == "render-drift" {
				if e != nil || hash == testInput(t).Snapshot.Deployment.SpecHash {
					t.Fatal("Git manifest hash was copied from live state")
				}
				return
			}
			if e == nil {
				t.Fatal("unsupported archive/render accepted")
			}
		})
	}
}

func TestFluxArtifactURLHashAndRedirectCannotEscapeCredentialBoundary(t *testing.T) {
	for _, mode := range []string{"external", "traversal", "hash", "redirect"} {
		t.Run(mode, func(t *testing.T) {
			b, _, source, files := fluxTestDocuments(t)
			raw := fluxTestArchive(t, files, nil)
			a := object(object(source["status"])["artifact"])
			a["digest"] = "sha256:" + HashBytes(raw)
			targetCalled := false
			target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { targetCalled = true }))
			defer target.Close()
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if mode == "redirect" {
					http.Redirect(w, r, target.URL, 307)
					return
				}
				_, _ = w.Write(raw)
			}))
			defer server.Close()
			if mode == "external" {
				a["url"] = target.URL
			}
			if mode == "traversal" {
				a["path"] = "gitrepository/flux-lab/workload/../secret.tar.gz"
				a["url"] = "http://source-controller.flux-lab.svc.cluster.local./" + str(a, "path")
			}
			if mode == "hash" {
				a["digest"] = "sha256:" + strings.Repeat("0", 64)
			}
			r := Reader{URL: server.URL, Token: "never-forward", Client: server.Client()}
			if _, e := r.fluxArtifact(context.Background(), b, a); e == nil || targetCalled {
				t.Fatal("artifact escaped URL/hash/redirect boundary")
			}
		})
	}
}
