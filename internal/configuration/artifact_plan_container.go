package configuration

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path"
	"strings"
)

// Terraform's binary format is explicitly opaque, not a public interchange
// contract. This adapter supports only the reviewed 1.16.0 layout and never
// extracts files or interprets tfplan protobuf. The pinned official CLI remains
// responsible for show; this extra check binds saved source/state bytes to Git.
// https://github.com/hashicorp/terraform/tree/v1.16.0/internal/plans/planfile
func validateArtifactPlanContainer(r ArtifactRegistration, b ArtifactBundle) error {
	if r.Toolchain.TerraformVersion != "1.16.0" {
		return errors.New("CONFIGURATION_ARTIFACT_PLAN_CONTAINER_VERSION_UNSUPPORTED")
	}
	z, e := zip.NewReader(bytes.NewReader(b.SavedPlan), int64(len(b.SavedPlan)))
	if e != nil || len(z.File) > 8192 {
		return errors.New("CONFIGURATION_ARTIFACT_PLAN_CONTAINER_UNSUPPORTED")
	}
	entries := map[string][]byte{}
	var total int64
	for _, f := range z.File {
		if f.Name != path.Clean(f.Name) || strings.HasPrefix(f.Name, "/") || strings.HasPrefix(f.Name, "../") || strings.ContainsAny(f.Name, "\\\x00") || f.FileInfo().Mode()&os.ModeSymlink != 0 || f.UncompressedSize64 > ArtifactMaxBytes || entries[f.Name] != nil {
			return errors.New("CONFIGURATION_ARTIFACT_PLAN_CONTAINER_INVALID")
		}
		reader, e := f.Open()
		if e != nil {
			return errors.New("CONFIGURATION_ARTIFACT_PLAN_CONTAINER_INVALID")
		}
		raw, e := io.ReadAll(io.LimitReader(reader, ArtifactMaxBytes+1))
		reader.Close()
		if e != nil || len(raw) > ArtifactMaxBytes {
			return errors.New("CONFIGURATION_ARTIFACT_PLAN_CONTAINER_LIMIT")
		}
		total += int64(len(raw))
		if total > ArtifactMaxBytes {
			return errors.New("CONFIGURATION_ARTIFACT_PLAN_CONTAINER_LIMIT")
		}
		entries[f.Name] = raw
	}
	if len(entries["tfplan"]) == 0 {
		return errors.New("CONFIGURATION_ARTIFACT_PLAN_CONTAINER_INVALID")
	}
	state, e := artifactDecode(b.StateRaw)
	if e != nil {
		return e
	}
	for _, name := range []string{"tfstate", "tfstate-prev"} {
		embedded, e := artifactDecode(entries[name])
		// The reviewed local backend deliberately writes a stub header for
		// tfstate-prev; identity comes from tfstate, whose complete header must
		// match. Only that exact native empty-lineage/zero-serial pair is allowed.
		// v1.16.0/internal/backend/local/backend_plan.go:159-170.
		if e == nil && name == "tfstate-prev" && artifactString(embedded, "lineage") == "" && embedded["serial"] == json.Number("0") {
			embedded["lineage"], embedded["serial"] = state["lineage"], state["serial"]
		}
		if e != nil || artifactHash(embedded) != artifactHash(state) {
			return errors.New("CONFIGURATION_ARTIFACT_EMBEDDED_STATE_CHANGED")
		}
	}
	type module struct {
		Key     string `json:"Key"`
		Source  string `json:"Source"`
		Version string `json:"Version"`
		Dir     string `json:"Dir"`
	}
	var modules []module
	if json.Unmarshal(entries["tfconfig/modules.json"], &modules) != nil || len(modules) == 0 || len(modules) > 512 {
		return errors.New("CONFIGURATION_ARTIFACT_EMBEDDED_MODULES_INVALID")
	}
	byPath := map[string]ArtifactFile{}
	for _, f := range b.Files {
		byPath[f.Path] = f
	}
	seen := map[string]bool{}
	seenModule := map[string]bool{}
	for _, m := range modules {
		if seenModule[m.Key] || m.Version != "" || m.Source != "" && !strings.HasPrefix(m.Source, "./") && !strings.HasPrefix(m.Source, "../") {
			return errors.New("CONFIGURATION_ARTIFACT_EMBEDDED_MODULE_UNSUPPORTED")
		}
		seenModule[m.Key] = true
		dir := m.Dir
		if strings.HasPrefix(dir, r.Toolchain.WorkingDirectory+"/") {
			dir = strings.TrimPrefix(dir, r.Toolchain.WorkingDirectory+"/")
		}
		if dir == r.Toolchain.WorkingDirectory {
			dir = "."
		}
		if dir == "" || dir != path.Clean(dir) || strings.HasPrefix(dir, "/") || strings.HasPrefix(dir, "../") || strings.ContainsAny(dir, "\\\x00") {
			return errors.New("CONFIGURATION_ARTIFACT_EMBEDDED_MODULE_ESCAPE")
		}
		prefix := "tfconfig/m-" + m.Key + "/"
		found := false
		for name, body := range entries {
			if !strings.HasPrefix(name, prefix) {
				continue
			}
			file := strings.TrimPrefix(name, prefix)
			if path.Base(file) != file || !strings.HasSuffix(file, ".tf") && !strings.HasSuffix(file, ".tf.json") {
				return errors.New("CONFIGURATION_ARTIFACT_EMBEDDED_SOURCE_INVALID")
			}
			full := path.Join(r.Declaration.Repository.Directory, dir, file)
			tracked, ok := byPath[full]
			if !ok || !bytes.Equal(tracked.Body, body) {
				return errors.New("CONFIGURATION_ARTIFACT_PLAN_SOURCE_COMMIT_MISMATCH")
			}
			seen[full] = true
			found = true
		}
		if !found {
			return errors.New("CONFIGURATION_ARTIFACT_EMBEDDED_MODULE_EMPTY")
		}
		for name := range byPath {
			if path.Dir(name) == path.Clean(path.Join(r.Declaration.Repository.Directory, dir)) && (strings.HasSuffix(name, ".tf") || strings.HasSuffix(name, ".tf.json")) && !seen[name] {
				return errors.New("CONFIGURATION_ARTIFACT_PLAN_SOURCE_COMMIT_MISMATCH")
			}
		}
	}
	for name := range entries {
		if name == "tfplan" || name == "tfstate" || name == "tfstate-prev" || name == "tfconfig/modules.json" || name == ".terraform.lock.hcl" {
			continue
		}
		if !strings.HasPrefix(name, "tfconfig/m-") {
			return errors.New("CONFIGURATION_ARTIFACT_PLAN_CONTAINER_ENTRY_UNSUPPORTED")
		}
		matched := false
		for key := range seenModule {
			if strings.HasPrefix(name, "tfconfig/m-"+key+"/") {
				matched = true
			}
		}
		if !matched {
			return errors.New("CONFIGURATION_ARTIFACT_EMBEDDED_MODULES_INVALID")
		}
	}
	lock := byPath[path.Join(r.Declaration.Repository.Directory, ".terraform.lock.hcl")]
	// With only built-in providers no on-disk lock file is needed, but the
	// native plan writer serializes the exact standard empty-lock header.
	emptyLock := []byte("# This file is maintained automatically by \"terraform init\".\n# Manual edits may be lost in future updates.")
	if len(lock.Body) == 0 && bytes.Equal(bytes.TrimSpace(entries[".terraform.lock.hcl"]), emptyLock) {
		return nil
	}
	if !bytes.Equal(bytes.TrimSpace(lock.Body), bytes.TrimSpace(entries[".terraform.lock.hcl"])) {
		return errors.New("CONFIGURATION_ARTIFACT_LOCK_FILE_CHANGED")
	}
	return nil
}
