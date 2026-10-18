package configuration

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/telemetry"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
)

func artifactTestRegistration() ArtifactRegistration {
	d := declaration()
	d.Repository.Directory = "."
	d.Terraform.Workspace = "default"
	d.Terraform.Addresses = []string{"aws_instance.api"}
	return ArtifactRegistration{SchemaVersion: "1", ID: "artifact-machine", Version: 1, Binding: Binding{Binding: telemetry.Binding{TenantID: "tenant-a", WorkloadID: "workload-a", ResourceID: "resource-a", Provider: "AWS", ProviderResourceID: "i-fixture-only", AccountID: "111122223333", Region: "eu-west-1"}, ResourceVersion: 1, ResourceSnapshotHash: strings.Repeat("a", 64)}, AuthorityID: "authority-a", AuthorityVersion: 1, AuthorityHash: strings.Repeat("b", 64), Declaration: d, Issuer: d.Pipeline.Identity.Issuer, Audience: ArtifactAudience, Subject: d.Pipeline.Identity.Subject, PipelineID: d.Pipeline.Identity.PipelineID, Toolchain: ArtifactToolchain{TerraformVersion: "1.16.0", Image: "hashicorp/terraform@sha256:64360659224d6cbeb099eeed61aa66a80e02c18ba08c0243bd905165b47b088e", OS: "linux", Architecture: "amd64", WorkingDirectory: "/workspace"}}
}
func artifactTestBundle(r ArtifactRegistration) ArtifactBundle {
	source := []byte(`resource "terraform_data" "fixture" { input = "sensitive-fixture" }`)
	values := json.RawMessage(`{"root_module":{"resources":[{"address":"terraform_data.fixture","mode":"managed","type":"terraform_data","name":"fixture","provider_name":"terraform.io/builtin/terraform","values":{"input":"sensitive-fixture"}}]}}`)
	stateJSON, _ := json.Marshal(map[string]any{"format_version": "1.0", "terraform_version": r.Toolchain.TerraformVersion, "values": values})
	planJSON, _ := json.Marshal(map[string]any{"format_version": "1.2", "terraform_version": r.Toolchain.TerraformVersion, "prior_state": map[string]any{"values": values}, "resource_changes": []any{map[string]any{"address": "terraform_data.fixture", "change": map[string]any{"actions": []string{"no-op"}}}}, "configuration": map[string]any{"provider_config": map[string]any{"terraform": map[string]any{"full_name": "terraform.io/builtin/terraform"}}}})
	state, _ := json.Marshal(map[string]any{"version": 4, "terraform_version": r.Toolchain.TerraformVersion, "lineage": r.Declaration.Terraform.StateLineage, "serial": 7, "resources": []any{map[string]any{"provider": `provider["terraform.io/builtin/terraform"]`}}})
	version, _ := json.Marshal(map[string]any{"terraform_version": r.Toolchain.TerraformVersion, "platform": "linux_amd64", "provider_selections": map[string]any{}})
	b := ArtifactBundle{SchemaVersion: "1", Git: ArtifactGit{Commit: strings.Repeat("c", 40), Tree: strings.Repeat("d", 40), Ref: r.Declaration.Repository.Ref}, Toolchain: r.Toolchain, State: ArtifactState{r.Declaration.Terraform.StateLineage, 7, r.Declaration.Terraform.Workspace}, Files: []ArtifactFile{{"main.tf", "100644", artifactBytesHash(source), source}}, PlanJSON: planJSON, StateRaw: state, StateJSON: stateJSON, VersionJSON: version, ModuleManifest: []byte(`{"Modules":[{"Key":"","Source":"","Dir":"."}]}`)}
	artifactTestPlanZip(&b)
	b.Git.ConfigurationSHA256 = artifactFilesDigest(b.Files)
	b.Git.DependencySHA256 = artifactDependencyDigest(b)
	return b
}
func artifactTestPlanZip(b *ArtifactBundle) {
	var out bytes.Buffer
	z := zip.NewWriter(&out)
	for name, raw := range map[string][]byte{"tfplan": []byte("unit-test-opaque-protobuf"), "tfstate": b.StateRaw, "tfstate-prev": b.StateRaw, "tfconfig/modules.json": []byte(`[{"Key":"","Dir":"."}]`), "tfconfig/m-/" + path.Base(b.Files[0].Path): b.Files[0].Body, ".terraform.lock.hcl": {}} {
		f, _ := z.Create(name)
		f.Write(raw)
	}
	z.Close()
	b.SavedPlan = out.Bytes()
}

func TestArtifactEveryFilesystemFunctionAndEscapedJSONIsBlocked(t *testing.T) {
	r := artifactTestRegistration()
	for _, name := range []string{"file", "filemd5", "filesha1", "filesha256", "filesha512", "filebase64", "filebase64sha256", "filebase64sha512", "fileexists", "fileset", "templatefile"} {
		t.Run(name, func(t *testing.T) {
			b := artifactTestBundle(r)
			b.Files[0].Body = []byte(`resource "terraform_data" "fixture" { input = ` + name + `("/private/untracked") }`)
			b.Files[0].SHA256 = artifactBytesHash(b.Files[0].Body)
			artifactTestPlanZip(&b)
			b.Git.ConfigurationSHA256 = artifactFilesDigest(b.Files)
			b.Git.DependencySHA256 = artifactDependencyDigest(b)
			m, e := ValidateArtifactBundle(r, b)
			if e != nil || !artifactHasReason(m, "CONFIGURATION_EXTERNAL_INPUT_CLOSURE_UNSUPPORTED") {
				t.Fatal("filesystem function escaped closure blocker", e)
			}
		})
	}
	b := artifactTestBundle(r)
	b.Files[0].Path = "main.tf.json"
	b.Files[0].Body = []byte(`{"resource":{"terraform_data":{"fixture":{"input":"${\u0066ilemd5(\"/private/untracked\")}"}}}}`)
	b.Files[0].SHA256 = artifactBytesHash(b.Files[0].Body)
	artifactTestPlanZip(&b)
	b.Git.ConfigurationSHA256 = artifactFilesDigest(b.Files)
	b.Git.DependencySHA256 = artifactDependencyDigest(b)
	m, e := ValidateArtifactBundle(r, b)
	if e != nil || !artifactHasReason(m, "CONFIGURATION_EXTERNAL_INPUT_CLOSURE_UNSUPPORTED") {
		t.Fatal("JSON-escaped filesystem function escaped closure blocker", e)
	}
}
func TestArtifactDockerReadToolsPinValidatedDaemon(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-only private container adapter")
	}
	dir := t.TempDir()
	binary := filepath.Join(dir, "docker-fixture")
	log := filepath.Join(dir, "invocations")
	script := "#!/bin/sh\nif [ \"$1\" = context ]; then printf '\"unix:///var/run/docker.sock\"\\n'; exit 0; fi\nif [ \"$1\" != --host=unix:///var/run/docker.sock ]; then exit 42; fi\nprintf '%s\\n' \"$*\" >> '" + log + "'\ncase \"$*\" in *'workspace show') printf 'default\\n';; *) printf '{}\\n';; esac\n"
	if e := os.WriteFile(binary, []byte(script), 0700); e != nil {
		t.Fatal(e)
	}
	tools := DockerArtifactTools{DockerBinary: binary}
	if _, e := tools.Inspect(context.Background(), artifactTestRegistration(), dir, []byte("sensitive-plan"), []byte("sensitive-state")); e != nil {
		t.Fatal("validated daemon was not pinned", e)
	}
	calls, e := os.ReadFile(log)
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Count(calls, []byte("--host=unix:///var/run/docker.sock")) != 4 || !bytes.Contains(calls, []byte("--network=none --read-only --cap-drop=ALL")) || bytes.Contains(calls, []byte("sensitive-plan")) || bytes.Contains(calls, []byte("sensitive-state")) {
		t.Fatal("read tool command scope or secret boundary invalid")
	}
}
func artifactHasReason(m ArtifactMetadata, code string) bool {
	for _, v := range m.ReasonCodes {
		if v == code {
			return true
		}
	}
	return false
}
func TestArtifactBundleNeverPromotesLocalFixtureToCloudAuthority(t *testing.T) {
	r := artifactTestRegistration()
	b := artifactTestBundle(r)
	m, e := ValidateArtifactBundle(r, b)
	if e != nil {
		t.Fatal(e)
	}
	if m.Status != "BLOCKED" || !artifactHasReason(m, "CONFIGURATION_DECLARED_ADDRESS_UNOBSERVED") || m.ExecutionAuthorized || m.VerifiedSaving != nil {
		t.Fatal("local terraform_data became cloud authority")
	}
	receipt := ArtifactReceipt{Metadata: m, Archive: ArtifactArchiveRef{Key: "private-object-key"}}
	raw, _ := json.Marshal(receipt.PublicProjection())
	for _, secret := range []string{"sensitive-fixture", "private-object-key", "saved_plan\"", "state_raw", "files\""} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("sensitive raw artifact escaped public projection")
		}
	}
}
func TestArtifactRejectsChangedStateToolchainDriftAndUnrelatedDestruction(t *testing.T) {
	r := artifactTestRegistration()
	for name, mutate := range map[string]func(*ArtifactBundle){"source": func(b *ArtifactBundle) { b.Files[0].Body = []byte("changed") }, "commit": func(b *ArtifactBundle) { b.Git.Commit = "not-a-commit" }, "lineage": func(b *ArtifactBundle) { b.State.Lineage = "00000000-0000-0000-0000-000000000000" }, "serial": func(b *ArtifactBundle) { b.State.Serial++ }, "workspace": func(b *ArtifactBundle) { b.State.Workspace = "other" }, "version": func(b *ArtifactBundle) {
		b.VersionJSON = []byte(`{"terraform_version":"0.1.0","platform":"linux_amd64"}`)
	}, "prior-state": func(b *ArtifactBundle) {
		b.StateJSON = bytes.ReplaceAll(b.StateJSON, []byte("sensitive-fixture"), []byte("changed-state"))
	}, "destroy": func(b *ArtifactBundle) { b.PlanJSON = bytes.ReplaceAll(b.PlanJSON, []byte("no-op"), []byte("delete")) }, "drift": func(b *ArtifactBundle) {
		d, _ := artifactDecode(b.PlanJSON)
		d["resource_drift"] = []any{map[string]any{"change": map[string]any{"actions": []string{"update"}}}}
		b.PlanJSON, _ = json.Marshal(d)
	}} {
		t.Run(name, func(t *testing.T) {
			b := artifactTestBundle(r)
			mutate(&b)
			if _, e := ValidateArtifactBundle(r, b); e == nil {
				t.Fatal("accepted changed provenance")
			}
		})
	}
}
func TestArtifactDependencyInputsRemainExplicitlyBlocked(t *testing.T) {
	r := artifactTestRegistration()
	for name, mutate := range map[string]func(*ArtifactBundle){"external-provider": func(b *ArtifactBundle) {
		b.VersionJSON = []byte(`{"terraform_version":"1.16.0","platform":"linux_amd64","provider_selections":{"registry.terraform.io/hashicorp/aws":"6.0.0"}}`)
	}, "external-module": func(b *ArtifactBundle) {
		b.ModuleManifest = []byte(`{"Modules":[{"Key":"remote","Source":"git::https://example.test/repo","Dir":".terraform/modules/remote"}]}`)
	}, "filesystem-input": func(b *ArtifactBundle) {
		b.Files[0].Body = []byte(`resource "terraform_data" "fixture" { input = file("/untracked-secret") }`)
		b.Files[0].SHA256 = artifactBytesHash(b.Files[0].Body)
	}} {
		t.Run(name, func(t *testing.T) {
			b := artifactTestBundle(r)
			mutate(&b)
			artifactTestPlanZip(&b)
			b.Git.ConfigurationSHA256 = artifactFilesDigest(b.Files)
			b.Git.DependencySHA256 = artifactDependencyDigest(b)
			m, e := ValidateArtifactBundle(r, b)
			if e != nil || m.Status != "BLOCKED" {
				t.Fatal("unsupported dependency granted complete observation", e)
			}
		})
	}
}
func TestArtifactAuthenticatedDedicatedMachineAndTenant(t *testing.T) {
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "fixture", Algorithm: "RS256", Use: "sig"}}})
	}))
	defer server.Close()
	ctx := oidc.ClientContext(context.Background(), server.Client())
	a, e := NewArtifactAuthenticator(ctx, server.URL, ArtifactAudience, server.URL+"/keys", false)
	if e != nil {
		t.Fatal(e)
	}
	signer, e := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "fixture"))
	if e != nil {
		t.Fatal(e)
	}
	token := func(aud, tenant string, human bool) string {
		claims := map[string]any{"iss": server.URL, "sub": "machine-subject", "aud": aud, "tenant_id": tenant, "exp": time.Now().Add(time.Minute).Unix(), "iat": time.Now().Unix()}
		if aud == "MULTI" {
			claims["aud"] = []string{ArtifactAudience, "finops"}
		}
		if human {
			claims["roles"] = []string{"PLATFORM_ADMIN"}
		}
		raw, _ := json.Marshal(claims)
		signed, _ := signer.Sign(raw)
		s, _ := signed.CompactSerialize()
		return s
	}
	for _, test := range []struct {
		aud, tenant string
		human, want bool
	}{{ArtifactAudience, "tenant-a", false, true}, {"finops", "tenant-a", false, false}, {"MULTI", "tenant-a", false, false}, {ArtifactAudience, "tenant-a", true, false}, {ArtifactAudience, "", false, false}} {
		req := httptest.NewRequest("POST", "https://attestor.test/private", nil)
		req.Header.Set("Authorization", "Bearer "+token(test.aud, test.tenant, test.human))
		p, e := a.Authenticate(req)
		if (e == nil) != test.want {
			t.Fatal("machine OIDC acceptance mismatch", e)
		}
		if e == nil && (p.tenant != "tenant-a" || p.subject != "machine-subject") {
			t.Fatal("identity not selected from signed token")
		}
	}
}
func TestArtifactEncryptionAADAndNoLiveLocalFallback(t *testing.T) {
	keys, e := NewArtifactFixtureKeys(bytes.Repeat([]byte{7}, 32))
	if e != nil {
		t.Fatal(e)
	}
	ctx := context.Background()
	plain := []byte("sensitive-state-value")
	raw, e := artifactSeal(ctx, keys, true, "tenant-a", "job-a", plain)
	if e != nil || bytes.Contains(raw, plain) {
		t.Fatal("plaintext archive", e)
	}
	if _, e = artifactSeal(ctx, keys, false, "tenant-a", "job-a", plain); e == nil {
		t.Fatal("live capture used local key")
	}
	for _, test := range []struct{ tenant, job, sha string }{{"tenant-b", "job-a", artifactBytesHash(plain)}, {"tenant-a", "job-b", artifactBytesHash(plain)}, {"tenant-a", "job-a", strings.Repeat("a", 64)}} {
		if _, e = artifactOpen(ctx, keys, true, test.tenant, test.job, test.sha, raw); e == nil {
			t.Fatal("ciphertext rebound across context")
		}
	}
	raw[len(raw)/2] ^= 1
	if _, e = artifactOpen(ctx, keys, true, "tenant-a", "job-a", artifactBytesHash(plain), raw); e == nil {
		t.Fatal("tampered ciphertext decrypted")
	}
	kms := &ArtifactKMSKeys{KeyARN: "arn:aws:kms:eu-west-1:111122223333:key/00000000-0000-0000-0000-000000000000"}
	if _, e = artifactSeal(ctx, kms, false, "tenant-a", "job-a", plain); e == nil {
		t.Fatal("unavailable live KMS bypassed")
	}
}
