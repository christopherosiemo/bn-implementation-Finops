package kubernetes

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"
)

// This first Flux proof supports an explicit, static local Kustomization only.
// Unknown transforms remain blocked instead of hashing the live spec as Git.
func (r Reader) flux(ctx context.Context, b Binding, read func(string, string) (Document, error)) (GitObservation, error) {
	g := GitObservation{Engine: "FLUX"}
	prefix := b.Git.ControllerNamespace
	d, err := read("git_ack", "/apis/kustomize.toolkit.fluxcd.io/v1/namespaces/"+prefix+"/kustomizations/"+b.Git.ControllerName)
	if err != nil {
		return g, err
	}
	spec, status := object(d["spec"]), object(d["status"])
	ref := object(spec["sourceRef"])
	if str(object(d["metadata"]), "uid") != b.Git.ControllerUID || str(ref, "kind") != "GitRepository" || str(ref, "name") != b.Git.SourceName || str(ref, "namespace") != "" && str(ref, "namespace") != prefix || str(spec, "targetNamespace") != b.Namespace || str(spec, "path") != b.Git.Path || str(spec, "serviceAccountName") != b.Git.ApplyServiceAccount || str(spec, "deletionPolicy") != "Orphan" || !boolean(spec, "wait") || boolean(spec, "suspend") || boolean(spec, "prune") || boolean(spec, "force") {
		return g, errors.New("K8S_FLUX_CONTROLLER_BINDING_INVALID")
	}
	allowed := map[string]bool{"interval": true, "retryInterval": true, "timeout": true, "path": true, "prune": true, "deletionPolicy": true, "sourceRef": true, "targetNamespace": true, "serviceAccountName": true, "wait": true, "suspend": true, "force": true}
	for key := range spec {
		if !allowed[key] {
			return g, errors.New("K8S_FLUX_TRANSFORM_UNSUPPORTED")
		}
	}
	source, err := read("git_source", "/apis/source.toolkit.fluxcd.io/v1/namespaces/"+prefix+"/gitrepositories/"+b.Git.SourceName)
	if err != nil {
		return g, err
	}
	sourceSpec, sourceStatus := object(source["spec"]), object(source["status"])
	sourceRef := object(sourceSpec["ref"])
	if len(sourceRef) != 1 || str(sourceRef, "branch") != b.Git.SourceBranch {
		return g, errors.New("K8S_FLUX_SOURCE_BRANCH_INVALID")
	}
	if !fluxRepositoryURL(str(sourceSpec, "url")) || !fluxRepositoryURL(b.Git.Repository) {
		return g, errors.New("K8S_FLUX_REPOSITORY_URL_INVALID")
	}
	g.Repository, g.Path, g.SourceUID = str(sourceSpec, "url"), str(spec, "path"), str(object(source["metadata"]), "uid")
	if g.SourceUID != b.Git.SourceUID || g.Repository != b.Git.Repository || boolean(sourceSpec, "suspend") || sourceSpec["include"] != nil || boolean(sourceSpec, "recurseSubmodules") || sourceSpec["secretRef"] != nil || sourceSpec["proxySecretRef"] != nil || sourceSpec["provider"] != nil && str(sourceSpec, "provider") != "generic" {
		return g, errors.New("K8S_FLUX_SOURCE_BINDING_INVALID")
	}
	artifact := object(sourceStatus["artifact"])
	revision := str(status, "lastAppliedRevision")
	g.Revision = fluxRevision(revision)
	g.Generation = num(object(d["metadata"]), "generation")
	g.ObservedGeneration = num(status, "observedGeneration")
	sourceGeneration := num(object(source["metadata"]), "generation")
	g.Ready = fluxReady(status, g.Generation) && fluxReady(sourceStatus, sourceGeneration)
	g.Synced = g.Ready && g.Generation > 0 && sourceGeneration > 0 && g.ObservedGeneration >= g.Generation && num(sourceStatus, "observedGeneration") >= sourceGeneration && g.Revision != "" && fluxRevision(str(artifact, "revision")) == g.Revision && fluxRevision(str(status, "lastAttemptedRevision")) == g.Revision
	// lastHandledReconcileAt echoes an arbitrary client annotation. Only the
	// controller's matching successful history entry supplies observation time.
	for _, entry := range array(status["history"]) {
		h := object(entry)
		if str(h, "lastReconciledStatus") == "ReconciliationSucceeded" && fluxRevision(str(object(h["metadata"]), "revision")) == g.Revision {
			at, e := time.Parse(time.RFC3339Nano, str(h, "lastReconciled"))
			if e == nil && at.After(g.ObservedAt) {
				g.ObservedAt = at
			}
		}
	}
	if !g.Synced {
		g.RawHash = Hash(Document{"kustomization": d, "source": source})
		return g, nil
	}
	raw, err := r.fluxArtifact(ctx, b, artifact)
	if err != nil {
		return g, err
	}
	g.ArtifactHash = HashBytes(raw)
	g.DeploymentSpecHash, err = fluxManifest(raw, b)
	if err != nil {
		return g, err
	}
	for _, check := range []struct {
		key, endpoint string
		before        Document
	}{
		{"git_ack_after", "/apis/kustomize.toolkit.fluxcd.io/v1/namespaces/" + prefix + "/kustomizations/" + b.Git.ControllerName, d},
		{"git_source_after", "/apis/source.toolkit.fluxcd.io/v1/namespaces/" + prefix + "/gitrepositories/" + b.Git.SourceName, source},
	} {
		after, e := read(check.key, check.endpoint)
		if e != nil {
			return g, e
		}
		prior, current := object(check.before["metadata"]), object(after["metadata"])
		if str(prior, "resourceVersion") == "" || str(prior, "uid") != str(current, "uid") || str(prior, "resourceVersion") != str(current, "resourceVersion") {
			return g, errors.New("K8S_FLUX_AUTHORITY_CHANGED_DURING_COLLECTION")
		}
	}
	g.RawHash = Hash(Document{"kustomization": d, "source": source, "artifact_hash": g.ArtifactHash, "manifest_spec_hash": g.DeploymentSpecHash})
	return g, err
}

func fluxRepositoryURL(value string) bool {
	u, err := url.Parse(value)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" && u.User == nil && u.RawQuery == "" && u.Fragment == "" && u.RawPath == "" && strings.HasPrefix(u.Path, "/") && path.Clean(u.Path) == u.Path
}

func fluxReady(status Document, generation int64) bool {
	ready := false
	for _, entry := range array(status["conditions"]) {
		condition := object(entry)
		if str(condition, "type") == "Ready" && str(condition, "status") == "True" && num(condition, "observedGeneration") >= generation {
			ready = true
		}
		if (str(condition, "type") == "Reconciling" || str(condition, "type") == "Stalled") && str(condition, "status") == "True" {
			return false
		}
	}
	return ready
}

func fluxRevision(value string) string {
	for _, separator := range []string{"@sha1:", "@sha256:"} {
		if parts := strings.Split(value, separator); len(parts) == 2 && parts[0] != "" && revisionPattern.MatchString(parts[1]) && (separator == "@sha1:" && len(parts[1]) == 40 || separator == "@sha256:" && len(parts[1]) == 64) {
			return parts[1]
		}
	}
	return ""
}

func (r Reader) fluxArtifact(ctx context.Context, b Binding, artifact Document) ([]byte, error) {
	digest := str(artifact, "digest")
	if !regexp.MustCompile(`^sha256:[a-f0-9]{64}$`).MatchString(digest) {
		return nil, errors.New("K8S_FLUX_ARTIFACT_DIGEST_REQUIRED")
	}
	u, err := url.Parse(str(artifact, "url"))
	expectedHost := "source-controller." + b.Git.ControllerNamespace + ".svc.cluster.local"
	artifactPath := str(artifact, "path")
	if err != nil || u.Scheme != "http" || strings.TrimSuffix(u.Host, ".") != expectedHost || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || u.Path != "/"+artifactPath || path.Clean(artifactPath) != artifactPath || !strings.HasPrefix(artifactPath, "gitrepository/"+b.Git.ControllerNamespace+"/"+b.Git.SourceName+"/") || !strings.HasSuffix(artifactPath, ".tar.gz") {
		return nil, errors.New("K8S_FLUX_ARTIFACT_ENDPOINT_INVALID")
	}
	// Fetch through the pinned TLS Kubernetes endpoint and its namespaced Service
	// proxy. Native artifact URLs never receive the Kubernetes bearer credential.
	base, err := url.Parse(r.URL)
	if err != nil || base.Scheme != "https" || base.Host == "" || base.User != nil || base.Path != "" || base.RawQuery != "" || base.Fragment != "" || r.Client == nil || strings.TrimSpace(r.Token) == "" || strings.ContainsAny(r.Token, "\r\n") {
		return nil, errors.New("K8S_ENDPOINT_INVALID")
	}
	requestPath := "/api/v1/namespaces/" + b.Git.ControllerNamespace + "/services/source-controller:80/proxy/" + artifactPath
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.URL+requestPath, nil)
	if err != nil {
		return nil, errors.New("K8S_FLUX_ARTIFACT_REQUEST_INVALID")
	}
	req.Header.Set("Authorization", "Bearer "+r.Token)
	req.Header.Set("Accept-Encoding", "identity")
	client := *r.Client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Do(req)
	if err != nil {
		return nil, errors.New("K8S_FLUX_ARTIFACT_READ_UNAVAILABLE")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 || response.Header.Get("Content-Encoding") != "" && response.Header.Get("Content-Encoding") != "identity" {
		return nil, errors.New("K8S_FLUX_ARTIFACT_READ_REJECTED")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 4<<20+1))
	if err != nil || len(raw) > 4<<20 || len(raw) == 0 || "sha256:"+HashBytes(raw) != digest {
		return nil, errors.New("K8S_FLUX_ARTIFACT_HASH_OR_SIZE_INVALID")
	}
	return raw, nil
}

func fluxManifest(raw []byte, b Binding) (string, error) {
	directory := strings.TrimPrefix(b.Git.Path, "./")
	if directory == "" || path.Clean(directory) != directory || strings.HasPrefix(directory, "/") || strings.Contains(directory, "\\") || strings.HasPrefix(directory, "../") || b.Git.ManifestPath != directory+"/deployment.json" {
		return "", errors.New("K8S_FLUX_MANIFEST_PATH_INVALID")
	}
	gz, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return "", errors.New("K8S_FLUX_ARTIFACT_ARCHIVE_INVALID")
	}
	defer gz.Close()
	expanded := &io.LimitedReader{R: gz, N: 8<<20 + 1}
	tr := tar.NewReader(expanded)
	files := map[string][]byte{}
	var total int64
	for count := 0; ; count++ {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil || count >= 16 || path.Clean(strings.TrimSuffix(h.Name, "/")) != strings.TrimSuffix(h.Name, "/") || strings.HasPrefix(h.Name, "/") || strings.Contains(h.Name, "\\") || strings.HasPrefix(h.Name, "../") {
			return "", errors.New("K8S_FLUX_ARTIFACT_ENTRY_INVALID")
		}
		if h.Typeflag == tar.TypeDir {
			if strings.TrimSuffix(h.Name, "/") != directory {
				return "", errors.New("K8S_FLUX_ARTIFACT_ENTRY_UNSUPPORTED")
			}
			continue
		}
		if h.Typeflag != tar.TypeReg || h.Size < 0 || h.Size > 2<<20 || files[h.Name] != nil || h.Name != directory+"/kustomization.yaml" && h.Name != b.Git.ManifestPath && h.Name != directory+"/gateway-code.json" {
			return "", errors.New("K8S_FLUX_ARTIFACT_ENTRY_UNSUPPORTED")
		}
		total += h.Size
		if total > 4<<20 {
			return "", errors.New("K8S_FLUX_ARTIFACT_EXPANSION_LIMIT")
		}
		files[h.Name], e = io.ReadAll(io.LimitReader(tr, h.Size+1))
		if e != nil || int64(len(files[h.Name])) != h.Size {
			return "", errors.New("K8S_FLUX_ARTIFACT_ENTRY_INVALID")
		}
	}
	_, err = io.Copy(io.Discard, expanded)
	if err != nil || expanded.N <= 0 {
		return "", errors.New("K8S_FLUX_ARTIFACT_TRAILER_INVALID")
	}
	var config struct {
		APIVersion string   `json:"apiVersion"`
		Kind       string   `json:"kind"`
		Resources  []string `json:"resources"`
	}
	decoder := json.NewDecoder(bytes.NewReader(files[directory+"/kustomization.yaml"]))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&config) != nil || decoder.Decode(new(any)) != io.EOF || config.APIVersion != "kustomize.config.k8s.io/v1beta1" || config.Kind != "Kustomization" || len(config.Resources) != 2 || config.Resources[0] != "deployment.json" || config.Resources[1] != "gateway-code.json" || len(files) != 3 {
		return "", errors.New("K8S_FLUX_STATIC_RENDER_REQUIRED")
	}
	decode := func(raw []byte) (Document, error) {
		var d Document
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		if decoder.Decode(&d) != nil || decoder.Decode(new(any)) != io.EOF {
			return nil, errors.New("K8S_FLUX_MANIFEST_INVALID_JSON")
		}
		return d, nil
	}
	manifest, err := decode(files[b.Git.ManifestPath])
	if err != nil {
		return "", err
	}
	if str(manifest, "apiVersion") != "apps/v1" || str(manifest, "kind") != "Deployment" || str(object(manifest["metadata"]), "namespace") != b.Namespace || str(object(manifest["metadata"]), "name") != b.Deployment || manifest["status"] != nil || len(object(manifest["spec"])) == 0 {
		return "", errors.New("K8S_FLUX_MANIFEST_TARGET_INVALID")
	}
	configMap, err := decode(files[directory+"/gateway-code.json"])
	if err != nil {
		return "", err
	}
	if str(configMap, "apiVersion") != "v1" || str(configMap, "kind") != "ConfigMap" || str(object(configMap["metadata"]), "namespace") != b.Namespace || str(object(configMap["metadata"]), "name") != "gateway-code" || configMap["binaryData"] != nil || len(object(configMap["data"])) != 1 || str(object(configMap["data"]), "gateway.py") == "" {
		return "", errors.New("K8S_FLUX_CONFIGMAP_TARGET_INVALID")
	}
	return SpecHash(object(manifest["spec"])), nil
}
