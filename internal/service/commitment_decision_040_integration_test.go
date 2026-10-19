package service

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	portfolio "github.com/christopherosiemo/bn-implementation-Finops/internal/commitmentportfolio"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/configuration"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/go-jose/go-jose/v4"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// This is a restricted-PostgreSQL component test. Its Git/Terraform collector,
// immutable object transport and source acquisition are explicit local doubles.
// The production artifact pipeline performs actual authenticated encryption and
// exact version readback. The test does not create provider history, backdate
// operator registrations, calibrate a forecast or recommend a purchase.
type decision040Archive struct{ objects map[string][]byte }

func (a *decision040Archive) Put(_ context.Context, tenant, job string, raw []byte) (configuration.ArtifactArchiveRef, error) {
	key := "tenant/" + tenant + "/configuration-artifacts/" + job + "/fixture.encrypted"
	a.objects[key] = append([]byte{}, raw...)
	return configuration.ArtifactArchiveRef{Bucket: "component-fixture", Key: key, VersionID: "immutable-" + source.BytesHash(raw), SHA256: source.BytesHash(raw), Bytes: int64(len(raw))}, nil
}
func (a *decision040Archive) Read(_ context.Context, _ string, ref configuration.ArtifactArchiveRef) ([]byte, error) {
	raw := a.objects[ref.Key]
	if ref.VersionID != "immutable-"+source.BytesHash(raw) || ref.SHA256 != source.BytesHash(raw) {
		return nil, errors.New("component archive differs")
	}
	return append([]byte{}, raw...), nil
}

type decision040Collector struct{ bundle configuration.ArtifactBundle }

func (c decision040Collector) Collect(context.Context, configuration.ArtifactRegistration) (configuration.ArtifactBundle, error) {
	return c.bundle, nil
}

func decision040JSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, e := json.Marshal(v)
	if e != nil {
		t.Fatal("component JSON failed")
	}
	return raw
}
func decision040Decode(t *testing.T, raw []byte, v any) {
	t.Helper()
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if d.Decode(v) != nil {
		t.Fatal("component JSON decode failed")
	}
}
func decision040LegacyHash(t *testing.T, v any) string {
	return source.BytesHash(decision040JSON(t, v))
}
func decision040Now(t *testing.T, ctx context.Context, pool *pgxpool.Pool) time.Time {
	t.Helper()
	var now time.Time
	if pool.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now) != nil {
		t.Fatal("component database clock unavailable")
	}
	return now.UTC()
}

func decision040Role(t *testing.T, ctx context.Context, admin *store.Store, role string) *store.Store {
	t.Helper()
	login := "decision040_" + strings.ReplaceAll(model.ID(), "-", "")
	password := model.ID()
	if _, e := admin.Pool.Exec(ctx, "CREATE ROLE "+pgx.Identifier{login}.Sanitize()+" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '"+password+"' IN ROLE "+pgx.Identifier{role}.Sanitize()); e != nil {
		t.Fatal("component role install failed", e)
	}
	cfg := admin.Pool.Config().Copy()
	cfg.ConnConfig.User = login
	cfg.ConnConfig.Password = password
	cfg.ConnConfig.RuntimeParams = map[string]string{}
	cfg.AfterConnect = func(c context.Context, p *pgx.Conn) error {
		_, e := p.Exec(c, "SET ROLE "+pgx.Identifier{role}.Sanitize())
		return e
	}
	pool, e := pgxpool.NewWithConfig(ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		pool.Close()
		if _, e := admin.Pool.Exec(context.Background(), "DROP ROLE "+pgx.Identifier{login}.Sanitize()); e != nil {
			t.Error("component owned login cleanup failed")
		}
	})
	return &store.Store{Pool: pool}
}

func decision040Bundle(t *testing.T, r configuration.ArtifactRegistration) configuration.ArtifactBundle {
	t.Helper()
	body := []byte(`resource "terraform_data" "fixture" { input = "component-only" }`)
	values := json.RawMessage(`{"root_module":{"resources":[{"address":"terraform_data.fixture","mode":"managed","type":"terraform_data","name":"fixture","provider_name":"terraform.io/builtin/terraform","values":{"input":"component-only"}}]}}`)
	state := decision040JSON(t, map[string]any{"version": 4, "terraform_version": r.Toolchain.TerraformVersion, "lineage": r.Declaration.Terraform.StateLineage, "serial": 7, "resources": []any{map[string]any{"provider": `provider["terraform.io/builtin/terraform"]`}}})
	b := configuration.ArtifactBundle{SchemaVersion: "1", Git: configuration.ArtifactGit{Commit: strings.Repeat("a", 40), Tree: strings.Repeat("b", 40), Ref: r.Declaration.Repository.Ref}, Toolchain: r.Toolchain, State: configuration.ArtifactState{Lineage: r.Declaration.Terraform.StateLineage, Serial: 7, Workspace: r.Declaration.Terraform.Workspace}, Files: []configuration.ArtifactFile{{Path: "main.tf", Mode: "100644", SHA256: source.BytesHash(body), Body: body}}, StateRaw: state, StateJSON: decision040JSON(t, map[string]any{"format_version": "1.0", "terraform_version": r.Toolchain.TerraformVersion, "values": values}), PlanJSON: decision040JSON(t, map[string]any{"format_version": "1.2", "terraform_version": r.Toolchain.TerraformVersion, "prior_state": map[string]any{"values": values}, "resource_changes": []any{map[string]any{"address": "terraform_data.fixture", "change": map[string]any{"actions": []string{"no-op"}}}}, "configuration": map[string]any{"provider_config": map[string]any{"terraform": map[string]any{"full_name": "terraform.io/builtin/terraform"}}}}), VersionJSON: decision040JSON(t, map[string]any{"terraform_version": r.Toolchain.TerraformVersion, "platform": "linux_amd64", "provider_selections": map[string]any{}}), ModuleManifest: []byte(`{"Modules":[{"Key":"","Source":"","Dir":"."}]}`)}
	var zipped bytes.Buffer
	z := zip.NewWriter(&zipped)
	for _, file := range []struct {
		name string
		raw  []byte
	}{{"tfplan", []byte("explicit component opaque plan double")}, {"tfstate", state}, {"tfstate-prev", state}, {"tfconfig/modules.json", []byte(`[{"Key":"","Dir":"."}]`)}, {"tfconfig/m-/main.tf", body}, {".terraform.lock.hcl", []byte{}}} {
		w, e := z.Create(file.name)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = w.Write(file.raw); e != nil {
			t.Fatal(e)
		}
	}
	if z.Close() != nil {
		t.Fatal("component saved plan failed")
	}
	b.SavedPlan = zipped.Bytes()
	type entry struct{ Path, Mode, SHA256 string }
	b.Git.ConfigurationSHA256 = decision040LegacyHash(t, []entry{{"main.tf", "100644", source.BytesHash(body)}})
	b.Git.DependencySHA256 = decision040LegacyHash(t, map[string]any{"source": b.Git.ConfigurationSHA256, "modules": source.BytesHash(b.ModuleManifest), "toolchain": b.Toolchain})
	return b
}

// A provider-shaped COMPONENT transport, not live Terraform/AWS history. The
// exact declared resource exists in all immutable state/no-op plan views. The
// ordinary external-provider execution blocker remains observable.
func decision040BoundBundle(t *testing.T, r configuration.ArtifactRegistration) configuration.ArtifactBundle {
	t.Helper()
	bundle := decision040Bundle(t, r)
	body := []byte(`resource "aws_instance" "api" { ami = "ami-0123456789abcdef0" instance_type = "m6i.large" }`)
	attributes := map[string]any{"id": r.Binding.ProviderResourceID, "arn": "arn:aws:ec2:" + r.Binding.Region + ":" + r.Binding.AccountID + ":instance/" + r.Binding.ProviderResourceID, "instance_type": "m6i.large", "ami": "ami-0123456789abcdef0"}
	resource := map[string]any{"address": "aws_instance.api", "mode": "managed", "type": "aws_instance", "name": "api", "provider_name": "registry.terraform.io/hashicorp/aws", "values": attributes}
	values := map[string]any{"root_module": map[string]any{"resources": []any{resource}}}
	bundle.Files = []configuration.ArtifactFile{{Path: "main.tf", Mode: "100644", SHA256: source.BytesHash(body), Body: body}}
	bundle.StateRaw = decision040JSON(t, map[string]any{"version": 4, "terraform_version": r.Toolchain.TerraformVersion, "lineage": bundle.State.Lineage, "serial": bundle.State.Serial, "resources": []any{map[string]any{"mode": "managed", "type": "aws_instance", "name": "api", "provider": `provider["registry.terraform.io/hashicorp/aws"]`, "instances": []any{map[string]any{"schema_version": 1, "attributes": attributes}}}}})
	bundle.StateJSON = decision040JSON(t, map[string]any{"format_version": "1.0", "terraform_version": r.Toolchain.TerraformVersion, "values": values})
	bundle.PlanJSON = decision040JSON(t, map[string]any{"format_version": "1.2", "terraform_version": r.Toolchain.TerraformVersion, "prior_state": map[string]any{"values": values}, "planned_values": values, "resource_changes": []any{map[string]any{"address": "aws_instance.api", "mode": "managed", "type": "aws_instance", "name": "api", "provider_name": "registry.terraform.io/hashicorp/aws", "change": map[string]any{"actions": []string{"no-op"}, "before": attributes, "after": attributes}}}, "configuration": map[string]any{"provider_config": map[string]any{"aws": map[string]any{"full_name": "registry.terraform.io/hashicorp/aws"}}}})
	bundle.VersionJSON = decision040JSON(t, map[string]any{"terraform_version": r.Toolchain.TerraformVersion, "platform": "linux_amd64", "provider_selections": map[string]any{"registry.terraform.io/hashicorp/aws": "6.0.0"}})
	var zipped bytes.Buffer
	writer := zip.NewWriter(&zipped)
	for _, entry := range []struct {
		name string
		raw  []byte
	}{{"tfplan", []byte("explicit component provider-shaped opaque plan double")}, {"tfstate", bundle.StateRaw}, {"tfstate-prev", bundle.StateRaw}, {"tfconfig/modules.json", []byte(`[{"Key":"","Dir":"."}]`)}, {"tfconfig/m-/main.tf", body}, {".terraform.lock.hcl", []byte{}}} {
		file, err := writer.Create(entry.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = file.Write(entry.raw); err != nil {
			t.Fatal(err)
		}
	}
	if writer.Close() != nil {
		t.Fatal("component bound saved plan failed")
	}
	bundle.SavedPlan = zipped.Bytes()
	type entry struct{ Path, Mode, SHA256 string }
	bundle.Git.ConfigurationSHA256 = decision040LegacyHash(t, []entry{{"main.tf", "100644", source.BytesHash(body)}})
	bundle.Git.DependencySHA256 = decision040LegacyHash(t, map[string]any{"source": bundle.Git.ConfigurationSHA256, "modules": source.BytesHash(bundle.ModuleManifest), "toolchain": bundle.Toolchain})
	return bundle
}

func decision040Artifact(t *testing.T, ctx context.Context, f *mutationReplayFixture, admin *store.Store, currentType ...string) (configuration.ArtifactReceipt, *decision040Archive) {
	t.Helper()
	workloadID, resourceID, instanceType := "ownership-component", "ownership-component-resource", "m6i.large"
	if len(currentType) > 1 {
		t.Fatal("component type fixture arguments differ")
	}
	if len(currentType) == 1 {
		instanceType = currentType[0]
		workloadID += "-unknown-type"
		resourceID += "-unknown-type"
	}
	var declaration configuration.Declaration
	decision040Decode(t, decision040JSON(t, configurationRequest()), &declaration)
	declaration.Repository.Directory = "."
	declaration.Terraform.Workspace = "default"
	declaration.Terraform.Addresses = []string{"aws_instance.api"}
	var authority model.Document
	if e := f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		if _, e := tx.Create(ctx, "workloads", model.Document{"id": workloadID, "owner": "assigned-owner", "environment": "NON_PRODUCTION"}); e != nil {
			return e
		}
		resource := model.Document{"id": resourceID, "workload_id": workloadID, "provider": "AWS", "provider_resource_id": "i-0f040000000000001", "account_id": "111122223333", "region": "eu-west-1"}
		if instanceType != "" {
			resource["instance_type"] = instanceType
		}
		if len(currentType) == 1 {
			resource["provider_resource_id"] = "i-0f040000000000002"
		}
		if _, e := tx.Create(ctx, "resources", resource); e != nil {
			return e
		}
		var e error
		authority, e = tx.ConfigurationAuthorityAppend(ctx, resourceID, 0, "component-platform", declaration)
		return e
	}); e != nil {
		t.Fatal("component declaration failed", e)
	}
	var binding configuration.Binding
	decision040Decode(t, decision040JSON(t, authority["binding"]), &binding)
	r := configuration.ArtifactRegistration{SchemaVersion: "1", ID: "component-artifact-machine", Version: 1, Binding: binding, AuthorityID: model.String(authority, "id"), AuthorityVersion: 1, AuthorityHash: decision040LegacyHash(t, authority), Declaration: declaration, Issuer: declaration.Pipeline.Identity.Issuer, Audience: configuration.ArtifactAudience, Subject: declaration.Pipeline.Identity.Subject, PipelineID: declaration.Pipeline.Identity.PipelineID, Toolchain: configuration.ArtifactToolchain{TerraformVersion: "1.16.0", Image: "hashicorp/terraform@sha256:64360659224d6cbeb099eeed61aa66a80e02c18ba08c0243bd905165b47b088e", OS: "linux", Architecture: "amd64", WorkingDirectory: "/workspace"}}
	if len(currentType) == 1 {
		r.ID += "-unknown-type"
	}
	// Authority hash is an issued column, not a re-created map hash.
	if admin.Pool.QueryRow(ctx, "SELECT content_hash FROM configuration_authority_revisions WHERE tenant_id=$1 AND id=$2", f.tenant, r.AuthorityID).Scan(&r.AuthorityHash) != nil {
		t.Fatal("issued authority hash missing")
	}
	attestor := decision040Role(t, ctx, admin, "finops_configuration_attestor")
	repo := &configuration.ArtifactPostgresRepository{Pool: attestor.Pool}
	if e := repo.Register(ctx, r); e != nil {
		t.Fatal("component actual attestor registration failed", e)
	}
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	signer, e := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "component-artifact"))
	if e != nil {
		t.Fatal(e)
	}
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "component-artifact", Algorithm: "RS256", Use: "sig"}}})
	}))
	defer jwks.Close()
	authenticator, e := configuration.NewArtifactAuthenticator(ctx, r.Issuer, r.Audience, jwks.URL, true)
	if e != nil {
		t.Fatal(e)
	}
	signed, e := signer.Sign(decision040JSON(t, map[string]any{"iss": r.Issuer, "aud": r.Audience, "sub": r.Subject, "tenant_id": f.tenant, "exp": time.Now().Add(time.Hour).Unix()}))
	if e != nil {
		t.Fatal(e)
	}
	token, e := signed.CompactSerialize()
	if e != nil {
		t.Fatal(e)
	}
	request := httptest.NewRequest("POST", "http://component.invalid/capture", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	principal, e := authenticator.Authenticate(request)
	if e != nil {
		t.Fatal("component real signature/audience verification failed", e)
	}
	keys, e := configuration.NewArtifactFixtureKeys(bytes.Repeat([]byte{11}, 32))
	if e != nil {
		t.Fatal(e)
	}
	archive := &decision040Archive{objects: map[string][]byte{}}
	pipeline := configuration.ArtifactPipeline{Repository: repo, Collector: decision040Collector{decision040Bundle(t, r)}, Archive: archive, Keys: keys, Fixture: true}
	negative, replayed, e := pipeline.Capture(ctx, principal, r.ID, "component-negative-capture-key")
	if e != nil || replayed || negative.Metadata.Status != "BLOCKED" || !strings.Contains(strings.Join(negative.Metadata.ReasonCodes, ","), "CONFIGURATION_DECLARED_ADDRESS_UNOBSERVED") {
		t.Fatal("local negative artifact lost missing-address label", e)
	}
	var negativeMappingNull bool
	if admin.Pool.QueryRow(ctx, "SELECT resource_binding IS NULL FROM configuration_artifact_readback_proofs WHERE tenant_id=$1 AND receipt_id=$2", f.tenant, negative.ID).Scan(&negativeMappingNull) != nil || !negativeMappingNull {
		t.Fatal("unobserved address acquired retained mapping")
	}
	e = admin.Do(ctx, f.tenant, func(tx *store.Tx) error {
		_, e := tx.Exec(ctx, "SELECT public.commitment_ownership_artifact_assert($1,$2,$3,$4::jsonb)", f.tenant, negative.ID, portfolio.Hash(negative), decision040JSON(t, negative.Archive))
		return e
	})
	decision040ExpectedSQL(t, e, "ownership artifact resource binding unobserved")
	pipeline.Collector = decision040Collector{decision040BoundBundle(t, r)}
	receipt, replayed, e := pipeline.Capture(ctx, principal, r.ID, "component-bound-capture-key")
	if instanceType == "" {
		decision040ExpectedSQL(t, e, "ownership artifact current native resource differs")
		var count int
		if admin.Pool.QueryRow(ctx, "SELECT count(*) FROM configuration_artifact_readback_proofs WHERE tenant_id=$1 AND registration_id=$2 AND resource_binding IS NOT NULL", f.tenant, r.ID).Scan(&count) != nil || count != 0 {
			t.Fatal("unknown current native type acquired retained mapping")
		}
		return negative, archive
	}
	if e != nil || replayed || receipt.Metadata.ExecutionAuthorized || receipt.Metadata.VerifiedSaving != nil {
		t.Fatal("component actual encrypted pipeline failed", e)
	}
	if receipt.Metadata.Status != "BLOCKED" || !strings.Contains(strings.Join(receipt.Metadata.ReasonCodes, ","), "CONFIGURATION_EXTERNAL_PROVIDER_UNSUPPORTED") || strings.Contains(strings.Join(receipt.Metadata.ReasonCodes, ","), "CONFIGURATION_DECLARED_ADDRESS_UNOBSERVED") {
		t.Fatal("bound component must retain external-provider execution blocker with actual declared address")
	}
	var bound bool
	if admin.Pool.QueryRow(ctx, "SELECT resource_binding->>'terraform_address'='aws_instance.api' AND resource_binding->'binding'=receipt->'metadata'->'binding' AND resource_binding->>'instance_type'='m6i.large' FROM configuration_artifact_readback_proofs WHERE tenant_id=$1 AND receipt_id=$2", f.tenant, receipt.ID).Scan(&bound) != nil || !bound {
		t.Fatal("actual decrypted readback did not issue exact resource mapping")
	}
	var mappingRaw []byte
	if admin.Pool.QueryRow(ctx, "SELECT resource_binding FROM configuration_artifact_readback_proofs WHERE tenant_id=$1 AND receipt_id=$2", f.tenant, receipt.ID).Scan(&mappingRaw) != nil {
		t.Fatal("issued resource mapping missing")
	}
	for _, mutation := range []struct{ key, value, message string }{{"terraform_address", "aws_instance.absent", "ownership artifact declared address differs"}, {"instance_type", "m6i.xlarge", "ownership artifact current native resource differs"}, {"resource_arn", "arn:aws:ec2:eu-west-1:999988887777:instance/" + r.Binding.ProviderResourceID, "ownership artifact resource binding unobserved"}} {
		var bad model.Document
		decision040Decode(t, mappingRaw, &bad)
		bad[mutation.key] = mutation.value
		e = admin.Do(ctx, f.tenant, func(tx *store.Tx) error {
			_, e := tx.Exec(ctx, "SELECT public.commitment_artifact_resource_binding_assert($1,$2::jsonb,$3::jsonb)", f.tenant, decision040JSON(t, receipt), decision040JSON(t, bad))
			return e
		})
		decision040ExpectedSQL(t, e, mutation.message)
	}
	e = f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		_, e := tx.Exec(ctx, "SELECT public.commitment_artifact_resource_binding_assert($1,$2::jsonb,$3::jsonb)", f.tenant, decision040JSON(t, receipt), mappingRaw)
		return e
	})
	var permission *pgconn.PgError
	if !errors.As(e, &permission) || permission.Code != "42501" {
		t.Fatal("private resource mapping validator acquired API EXECUTE", e)
	}
	var count int
	if admin.Pool.QueryRow(ctx, "SELECT count(*) FROM configuration_artifact_readback_proofs WHERE tenant_id=$1 AND receipt_id=$2 AND writer_role='finops_configuration_attestor'", f.tenant, receipt.ID).Scan(&count) != nil || count != 1 {
		t.Fatal("actual pipeline did not retain authenticated readback")
	}
	return receipt, archive
}

// The adapter obtains every byte via the actual restricted040 SQL interfaces.
// It does not substitute caller-created receipts or assert unobserved native data.
type decision040Reader struct {
	db     *store.Store
	tenant string
}

func (r decision040Reader) read(ctx context.Context, fn func(pgx.Tx) error) error {
	return r.db.Do(ctx, r.tenant, func(tx *store.Tx) error { return fn(tx.Tx) })
}
func (r decision040Reader) OwnershipRegistration(ctx context.Context, id string) (portfolio.DecisionOwnershipRegistration, error) {
	var out portfolio.DecisionOwnershipRegistration
	e := r.read(ctx, func(tx pgx.Tx) error {
		var raw []byte
		if e := tx.QueryRow(ctx, "SELECT public.commitment_ownership_registration($1,$2)", r.tenant, id).Scan(&raw); e != nil {
			return e
		}
		d := json.NewDecoder(bytes.NewReader(raw))
		d.UseNumber()
		var document any
		if d.Decode(&document) != nil || json.Unmarshal(raw, &out) != nil {
			return portfolio.ErrEvidence
		}
		out.IssuedDocumentSHA256 = portfolio.Hash(document)
		return nil
	})
	return out, e
}
func (r decision040Reader) OwnershipReview(ctx context.Context, q portfolio.DecisionOwnershipQuery) (portfolio.DecisionOwnershipStoredEnvelope, error) {
	var out portfolio.DecisionOwnershipStoredEnvelope
	out.Reference.Kind = "OWNERSHIP_REVIEW"
	e := r.read(ctx, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, "SELECT id,envelope_sha256,server_recorded_at,raw_envelope FROM public.commitment_ownership_review($1,$2,$3,$4,$5)", r.tenant, q.Scope.WorkloadID, portfolio.Hash(q.Scope), q.Period.Start, q.Period.End).Scan(&out.Reference.ID, &out.Reference.SHA256, &out.ServerRecordedAt, &out.RawEnvelope)
	})
	if errors.Is(e, pgx.ErrNoRows) {
		e = portfolio.ErrDecisionOwnershipAbsent
	}
	return out, e
}
func (r decision040Reader) OwnershipJournalPage(ctx context.Context, q portfolio.DecisionOwnershipQuery, registration, cursor string) (portfolio.DecisionOwnershipPage, error) {
	out := portfolio.DecisionOwnershipPage{Items: []portfolio.DecisionOwnershipStoredEnvelope{}}
	if cursor != "" {
		return out, portfolio.ErrEvidence
	}
	ids := []string{}
	for _, resource := range q.Scope.Resources {
		ids = append(ids, resource.ResourceID)
	}
	e := r.read(ctx, func(tx pgx.Tx) error {
		rows, e := tx.Query(ctx, "SELECT id,envelope_sha256,server_recorded_at,raw_envelope FROM public.commitment_ownership_journal_page($1,$2,$3,$4,$5,$6,$7,'',0)", r.tenant, q.Scope.WorkloadID, portfolio.Hash(q.Scope), registration, q.Period.Start, q.Period.End, ids)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			v := portfolio.DecisionOwnershipStoredEnvelope{Reference: portfolio.Ref{Kind: "OWNERSHIP_JOURNAL"}}
			if e = rows.Scan(&v.Reference.ID, &v.Reference.SHA256, &v.ServerRecordedAt, &v.RawEnvelope); e != nil {
				return e
			}
			out.Items = append(out.Items, v)
		}
		return rows.Err()
	})
	return out, e
}
func (r decision040Reader) OwnershipArtifact(ctx context.Context, ref portfolio.Ref, archive configuration.ArtifactArchiveRef) (configuration.ArtifactReceipt, []byte, error) {
	var out configuration.ArtifactReceipt
	var cipher []byte
	e := r.read(ctx, func(tx pgx.Tx) error {
		rawArchive, e := json.Marshal(archive)
		if e != nil {
			return e
		}
		var raw []byte
		if e = tx.QueryRow(ctx, "SELECT receipt,ciphertext FROM public.commitment_ownership_artifact($1,$2,$3,$4::jsonb)", r.tenant, ref.ID, ref.SHA256, rawArchive).Scan(&raw, &cipher); e != nil {
			return e
		}
		return json.Unmarshal(raw, &out)
	})
	return out, cipher, e
}
func (r decision040Reader) OwnershipDeployment(ctx context.Context, ref portfolio.Ref) (portfolio.DecisionOwnershipDeployment, error) {
	var out portfolio.DecisionOwnershipDeployment
	e := r.read(ctx, func(tx pgx.Tx) error {
		var raw []byte
		if e := tx.QueryRow(ctx, "SELECT raw_body,body_sha256,issuer,subject,audience,server_recorded_at FROM public.commitment_ownership_deployment($1,$2,$3)", r.tenant, ref.ID, ref.SHA256).Scan(&raw, &out.Reference.SHA256, &out.Issuer, &out.Subject, &out.Audience, &out.ServerRecordedAt); e != nil {
			return e
		}
		var body portfolio.DecisionOwnershipDeploymentObservation
		if json.Unmarshal(raw, &body) != nil || source.BytesHash(raw) != ref.SHA256 {
			return portfolio.ErrEvidence
		}
		out.Reference.Kind, out.Reference.ID = "DEPLOYMENT_RECEIPT", body.ID
		out.TenantID, out.WorkloadID, out.Resource, out.ObservedAt = body.TenantID, body.WorkloadID, body.Resource, body.ObservedAt
		return nil
	})
	return out, e
}

func decision040Append(t *testing.T, ctx context.Context, observer *store.Store, tenant, subject, kind string, raw []byte) (portfolio.DecisionOwnershipStoredEnvelope, bool, error) {
	t.Helper()
	var out portfolio.DecisionOwnershipStoredEnvelope
	var replay bool
	e := observer.Do(ctx, tenant, func(tx *store.Tx) error {
		var e error
		out, replay, e = portfolio.AppendDecisionOwnership(ctx, tx.Tx, tenant, "https://ownership-component.invalid", subject, configuration.ObserverAudience, kind, raw)
		return e
	})
	return out, replay, e
}
func decision040ExpectedSQL(t *testing.T, e error, message string) {
	t.Helper()
	var pg *pgconn.PgError
	if !errors.As(e, &pg) || pg.Code != "P0001" || pg.Message != message {
		t.Fatalf("wrong restricted rejection: want %s, got %v", message, e)
	}
}

// PRIVATE_GUARD_COMPONENT only. Production does not expose this private helper
// to the analyst. Its NOLOGIN group receives a transaction-local catalog change
// solely in this operator-owned child transaction. Session identity is switched
// to the actual commissioned LOGIN; rollback removes the grant and restores the
// original session. No public publisher/history acceptance is inferred.
func decision040PrivateGuard(t *testing.T, ctx context.Context, admin, analyst *store.Store, tenant, workload string, raw []byte) error {
	t.Helper()
	login := analyst.Pool.Config().ConnConfig.User
	if !strings.HasPrefix(login, "portfolio_native_") {
		t.Fatal("private guard exact-login ownership differs")
	}
	const signature = "public.commitment_ownership_validate(text,text,jsonb)"
	var acl string
	var executable bool
	if admin.Pool.QueryRow(ctx, "SELECT coalesce(proacl::text,''),has_function_privilege($1,oid,'EXECUTE') FROM pg_proc WHERE oid=$2::regprocedure", login, signature).Scan(&acl, &executable) != nil || executable {
		t.Fatal("private guard permission was already widened")
	}
	var expectedOID uint32
	var boundTenant string
	if admin.Pool.QueryRow(ctx, "SELECT r.oid,c.tenant_id FROM pg_roles r JOIN commitment_portfolio_credentials c ON c.database_login=r.rolname AND c.role_oid=r.oid WHERE r.rolname=$1", login).Scan(&expectedOID, &boundTenant) != nil || expectedOID == 0 {
		t.Fatal("private guard commissioned login/OID missing")
	}
	tx, e := admin.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, "GRANT EXECUTE ON FUNCTION "+signature+" TO finops_commitment_portfolio"); e != nil {
		t.Fatal("rollback-only private guard grant failed", e)
	}
	if _, e = tx.Exec(ctx, "SET LOCAL SESSION AUTHORIZATION "+pgx.Identifier{login}.Sanitize()); e != nil {
		t.Fatal("private guard exact session switch failed", e)
	}
	if _, e = tx.Exec(ctx, "SET LOCAL ROLE finops_commitment_portfolio"); e != nil {
		t.Fatal(e)
	}
	if _, e = tx.Exec(ctx, "SELECT set_config('app.tenant_id',$1,true)", tenant); e != nil {
		t.Fatal(e)
	}
	var session, role string
	var actualOID uint32
	if tx.QueryRow(ctx, "SELECT session_user,current_user,(SELECT oid FROM pg_roles WHERE rolname=session_user)").Scan(&session, &role, &actualOID) != nil || session != login || role != "finops_commitment_portfolio" || actualOID != expectedOID {
		t.Fatal("private guard did not use actual dedicated identity/OID")
	}
	var scoped bool
	if tx.QueryRow(ctx, "SELECT public.commitment_portfolio_scope($1)", tenant).Scan(&scoped) != nil || scoped != (tenant == boundTenant) {
		t.Fatal("private guard credential scope differs")
	}
	_, guardError := tx.Exec(ctx, "SELECT public.commitment_ownership_validate($1,$2,$3::jsonb)", tenant, workload, raw)
	if e = tx.Rollback(ctx); e != nil {
		t.Fatal("private guard rollback failed", e)
	}
	var after string
	if admin.Pool.QueryRow(ctx, "SELECT coalesce(proacl::text,''),has_function_privilege($1,oid,'EXECUTE') FROM pg_proc WHERE oid=$2::regprocedure", login, signature).Scan(&after, &executable) != nil || after != acl || executable {
		t.Fatal("rollback failed to restore original private helper ACL")
	}
	return guardError
}

// Explicit acquisition/model doubles for component integration. Issuance, API
// selection, credential checks, immutable queue/result guards and Process are
// real. Empty inventory and missing billing remain visible unavailable values.
type decision040QuoteReader struct {
	*source.FixtureReader
	projection model.Document
}

func (r decision040QuoteReader) BillingSavingsPlanQuotes(context.Context, string, provider.SavingsPlanQuoteSelection) (model.Document, error) {
	return model.Clone(r.projection), nil
}

type decision040Calculator struct{}

func (decision040Calculator) Evaluate(_ context.Context, in portfolio.Input) (portfolio.Analysis, error) {
	out := portfolio.Analysis{SchemaVersion: "1", RequestID: in.RequestID, Selection: in.Selection, InputRefs: in.InputRefs, ObservedAt: in.ObservedAt, InventoryStatus: in.InventoryStatus, BillingStatus: in.BillingStatus, Positions: []portfolio.PositionAnalysis{}, Partitions: []portfolio.Partition{}, UnmatchedBilling: []portfolio.UnmatchedBilling{}, OptimizationOrder: in.OptimizationOrder, RecommendationStatus: "BLOCKED", ReasonCodes: []string{"COMPONENT_MODEL_DOUBLE_NO_PURCHASE_AUTHORITY"}}
	for _, stage := range []string{"REMOVE_IDLE", "SCHEDULE", "RIGHTSIZE", "AUTOSCALE", "RECALCULATE_STABLE_DEMAND"} {
		out.OptimizationOrder = append(out.OptimizationOrder, portfolio.OptimizationStage{Stage: stage, Status: "BLOCKED", ReasonCodes: []string{"ISSUED_OPTIMIZATION_OUTCOME_UNAVAILABLE"}})
	}
	if len(in.Positions) != 0 {
		return out, portfolio.ErrEvidence
	}
	out.ID = portfolio.Hash(out)
	return out, nil
}
func (decision040Calculator) EvaluateDecision(context.Context, portfolio.DecisionInput) (portfolio.Decision, error) {
	return portfolio.Decision{}, errors.New("component must not evaluate purchase")
}
func (decision040Calculator) ProduceDecisionForecast(context.Context, portfolio.DecisionForecastRequest) (portfolio.DecisionForecastProduction, error) {
	return portfolio.DecisionForecastProduction{}, errors.New("component must not fabricate forecast")
}

func decision040PrepareBlocked(t *testing.T, ctx context.Context, f *mutationReplayFixture, analyst *store.Store, workload string) string {
	t.Helper()
	const sourceID = "ownership-component-source"
	registration := source.FixtureRegistration(f.tenant, sourceID)
	if e := f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error { _, e := tx.SourceCreate(ctx, registration); return e }); e != nil {
		t.Fatal("component source registration failed", e)
	}
	config := source.ConfigurationHash(registration)
	inventoryID := model.ID()
	now := time.Now().UTC()
	native := model.Document{"receipt_id": inventoryID, "observed_at": now.Format(time.RFC3339Nano), "payer_account_id": "111122223333", "usage_account_ids": []string{"111122223333"}, "scope": "PAYER_ALL_LINKED_ACCOUNTS_ALL_REGIONS", "complete": true, "reserved_instance_count": 0, "savings_plan_count": 0, "native_snapshots": []model.Document{{"account_id": "111122223333", "reserved_instances": []model.Document{}, "savings_plans": []model.Document{}, "regions": []string{"eu-west-1"}}}}
	if e := f.roles["ingester"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		if _, e := tx.SourceReceiptCreate(ctx, model.Document{"id": inventoryID, "kind": "AWS_COMMITMENT", "source_id": sourceID, "config_hash": config, "observed_at": native["observed_at"], "commitment_scope": native, "native_hash": source.Hash(native)}); e != nil {
			return e
		}
		return tx.SourceCheckpointSet(ctx, sourceID, "status", model.Document{"status": "HEALTHY", "config_hash": config, "commitment_receipt_id": inventoryID, "last_sync_at": now.Format(time.RFC3339Nano)})
	}); e != nil {
		t.Fatal("restricted ingester component receipt failed", e)
	}
	offering := model.Document{"offeringId": "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa", "currency": "USD", "durationSeconds": 31536000, "paymentOption": "No Upfront", "planType": "Compute", "productTypes": []string{"EC2"}}
	pages := []model.Document{{"ordinal": 1, "operation": "DescribeSavingsPlansOfferings", "request": model.Document{"planTypes": []string{"Compute"}, "paymentOptions": []string{"No Upfront"}, "durations": []int64{31536000}, "currencies": []string{"USD"}, "maxResults": 1000}, "response": model.Document{"searchResults": []model.Document{offering}}}, {"ordinal": 2, "operation": "DescribeSavingsPlansOfferingRates", "request": model.Document{"savingsPlanOfferingIds": []string{model.String(offering, "offeringId")}, "maxResults": 1000}, "response": model.Document{"searchResults": []model.Document{}}}}
	hashes := []string{}
	for _, page := range pages {
		hash := portfolio.Hash(page)
		page["sha256"] = hash
		hashes = append(hashes, hash)
	}
	projection := model.Document{"native_projection": provider.SavingsPlanQuoteProjection, "serialization": "SDK_PROJECTION", "authenticated_account_id": "111122223333", "observed_at": time.Now().UTC().Format(time.RFC3339Nano), "complete": true, "selection": provider.SavingsPlanQuoteSelection{PlanType: "Compute", PaymentOption: "No Upfront", DurationSeconds: 31536000, Currency: "USD", ExistingPlanIDs: []string{}}, "pages": pages, "ordered_page_sha256s": hashes, "offerings": []model.Document{{"native": offering, "page_sha256": hashes[0]}}, "offering_rates": []model.Document{}, "existing_plan_rates": []model.Document{}}
	reader := decision040QuoteReader{FixtureReader: &source.FixtureReader{}, projection: projection}
	quote := source.SavingsPlanQuotePipeline{Store: f.roles["ingester"], ReaderFactory: func(context.Context, source.Registration) (source.Reader, error) { return reader, nil }, Archive: func(_ context.Context, tenant, src string, raw []byte) (model.Document, error) {
		// Exact immutable byte transport double; explicitly no S3/CH claim.
		back := append([]byte{}, raw...)
		if !bytes.Equal(raw, back) {
			return nil, errors.New("component quote archive changed")
		}
		return model.Document{"bucket": "component-fixture", "key": "tenant/" + tenant + "/commitment-quotes/" + src + "/quotes.bin", "version_id": "immutable-" + source.BytesHash(raw), "body_sha256": source.BytesHash(back)}, nil
	}}
	offers, e := quote.Capture(ctx, source.SavingsPlanQuoteTarget{TenantID: f.tenant, SourceID: sourceID, PlanType: "Compute", Currency: "USD"})
	if e != nil || len(offers) != 1 {
		t.Fatal("actual quote issuer failed on explicit acquisition double", e)
	}
	day := time.Now().UTC().Truncate(24 * time.Hour)
	selection := portfolio.Selection{SourceID: sourceID, CommitmentReceiptID: inventoryID, BillingReceiptIDs: []string{}, Period: portfolio.Period{Start: day.Add(-24 * time.Hour), End: day}}
	finance := f.token(f.tenant, "ownership-finance", "FINANCE")
	code, queued, _ := f.request("commitment-portfolio-analyses", `"0"`, "ownership-component-analysis", finance, source.Object(selection))
	if code != 202 {
		t.Fatal("actual039 finance API did not queue component selection", code)
	}
	worker := portfolio.Worker{Pool: analyst.Pool, Tenant: f.tenant, Calculator: decision040Calculator{}}
	if replay, e := worker.Process(ctx, model.String(queued, "id")); e != nil || replay {
		t.Fatal("actual039 worker/guards rejected component model", e)
	}
	inputs := model.Document{"portfolio_analysis_request_id": queued["id"], "offer_receipt_id": offers[0]["id"]}
	path := "workloads/" + workload + "/commitment-decision-inputs"
	for _, check := range []struct {
		token string
		want  int
	}{{f.token(f.tenant, "component-viewer", "VIEWER"), 403}, {f.token(f.tenant+"-other", "foreign-finance", "FINANCE"), 404}} {
		if code, _, _ := f.request(path, `"0"`, "component-role-negative", check.token, inputs); code != check.want {
			t.Fatal("component preparation role/tenant boundary differs", code, check.want)
		}
	}
	code, queued, _ = f.request(path, `"0"`, "ownership-component-preparation", finance, inputs)
	if code != 202 {
		t.Fatal("actual040 finance API did not queue component preparation", code)
	}
	requestID := model.String(queued, "id")
	if replay, e := worker.ProcessDecision(ctx, requestID); e != nil || replay {
		t.Fatal("actual040 blocked preparation failed", e)
	}
	var raw []byte
	var terminalStatus string
	if e := analyst.Do(ctx, f.tenant, func(tx *store.Tx) error {
		return tx.QueryRow(ctx, "SELECT status,document FROM commitment_decision_results WHERE tenant_id=$1 AND request_id=$2 AND purpose='PREPARE'", f.tenant, requestID).Scan(&terminalStatus, &raw)
	}); e != nil {
		t.Fatal("component terminal preparation missing", e)
	}
	terminal := model.Document{}
	decision040Decode(t, raw, &terminal)
	if terminalStatus != "ASSESSED" {
		safeStatus, safeReason := "UNKNOWN", "UNKNOWN"
		if terminalStatus == "REFUSED" {
			safeStatus = "REFUSED"
		}
		switch model.String(terminal, "reason_code") {
		case "ISSUED_INPUTS_CHANGED", "ISSUED_INPUT_FORMAT_UNSUPPORTED", "DECISION_MODEL_EVIDENCE_UNSUPPORTED":
			safeReason = model.String(terminal, "reason_code")
		}
		t.Fatalf("component terminal preparation status=%s reason_code=%s", safeStatus, safeReason)
	}
	var assessment, forecast []byte
	if e := f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		if e := tx.QueryRow(ctx, "SELECT document->'payload' FROM entities WHERE tenant_id=$1 AND kind='commitment_decision_evidence' AND id=$2", f.tenant, terminal["post_optimization_assessment_id"]).Scan(&assessment); e != nil {
			return e
		}
		return tx.QueryRow(ctx, "SELECT document->'payload' FROM entities WHERE tenant_id=$1 AND kind='commitment_decision_evidence' AND id=$2", f.tenant, terminal["forecast_id"]).Scan(&forecast)
	}); e != nil {
		t.Fatal("component persisted scoped evidence unreadable", e)
	}
	a, b := model.Document{}, model.Document{}
	decision040Decode(t, assessment, &a)
	decision040Decode(t, forecast, &b)
	if a["status"] != "BLOCKED" || b["status"] != "UNAVAILABLE" || len(source.Rows(b["hours"])) != 0 || a["execution_authorized"] != false || a["verified_saving"] != nil {
		t.Fatal("fresh installation fabricated past-day ownership/forecast")
	}
	if replay, e := worker.ProcessDecision(ctx, requestID); e != nil || !replay {
		t.Fatal("actual040 terminal replay failed", e)
	}
	final := model.Document{"portfolio_analysis_request_id": inputs["portfolio_analysis_request_id"], "offer_receipt_id": inputs["offer_receipt_id"], "post_optimization_assessment_id": terminal["post_optimization_assessment_id"], "forecast_id": terminal["forecast_id"]}
	if code, _, _ := f.request("workloads/"+workload+"/commitment-decisions", `"0"`, "component-no-final-authority", finance, final); code != 422 && code != 409 {
		t.Fatal("unavailable historical scope reached final decision", code)
	}
	return requestID
}

func TestCommitmentDecision040RestrictedOwnershipGuardAndBlockedPreparation(t *testing.T) {
	f, admin, _, _ := newFleetNativeHTTPTest(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if e := admin.Migrate(ctx, "../../migrations"); e != nil {
		var failure *pgconn.PgError
		if errors.As(e, &failure) {
			t.Logf("private DDL diagnostic: SQLSTATE=%s position=%d internal_position=%d where=%s", failure.Code, failure.Position, failure.InternalPosition, failure.Where)
		}
		t.Fatal("historical migrations failed", e)
	}
	dir := t.TempDir()
	raw, e := os.ReadFile(filepath.Join("..", "..", "migrations", "040_commitment_decisions.sql"))
	if e != nil {
		t.Fatal(e)
	}
	if os.WriteFile(filepath.Join(dir, "040_commitment_decisions.sql"), raw, 0600) != nil {
		t.Fatal("040 copy failed")
	}
	if e = admin.Migrate(ctx, dir); e != nil {
		t.Fatal("040 DDL failed", e)
	}
	analyst := commitmentPortfolioNativeRuntime(t, ctx, admin, f.tenant)
	observer := decision040Role(t, ctx, admin, "finops_deployment_observer")
	receipt, _ := decision040Artifact(t, ctx, f, admin)
	t.Run("missing_current_native_type_cannot_bind", func(t *testing.T) { decision040Artifact(t, ctx, f, admin, "") })
	reader := decision040Reader{analyst, f.tenant}
	resource := portfolio.DecisionOwnershipResource{ResourceID: receipt.Metadata.Binding.ResourceID, ProviderResourceID: receipt.Metadata.Binding.ProviderResourceID, AccountID: receipt.Metadata.Binding.AccountID, Region: receipt.Metadata.Binding.Region, RepositoryID: receipt.Metadata.AuthorityID, GitCommit: receipt.Metadata.Git.Commit, ConfigurationSHA256: receipt.Metadata.Git.ConfigurationSHA256, StateLineage: receipt.Metadata.State.Lineage}
	scope := portfolio.DecisionOwnershipScope{TenantID: f.tenant, WorkloadID: receipt.Metadata.Binding.WorkloadID, Resources: []portfolio.DecisionOwnershipResource{resource}}
	scope.ConfigurationSHA256 = portfolio.DecisionOwnershipConfigurationSHA256(scope.Resources)
	_, journalKey, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	_, reviewKey, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	keys := []struct {
		id, purpose, subject string
		key                  ed25519.PrivateKey
	}{{"component-journal", "DEPLOYMENT_JOURNAL", "journal-machine", journalKey}, {"component-review", "OWNERSHIP_REVIEW", "independent-review-machine", reviewKey}}
	issuedHashes := map[string]string{}
	for _, key := range keys {
		now := decision040Now(t, ctx, admin.Pool).Truncate(time.Second)
		reg := portfolio.DecisionOwnershipRegistration{ID: key.id, Revision: 1, ScopeSHA256: portfolio.Hash(scope), Purpose: key.purpose, Issuer: "https://ownership-component.invalid", Subject: key.subject, Audience: configuration.ObserverAudience, PublicKey: append([]byte{}, key.key.Public().(ed25519.PublicKey)...), ValidFrom: now.Add(-time.Hour), ValidUntil: now.Add(time.Hour)}
		document := model.Document{}
		decision040Decode(t, decision040JSON(t, reg), &document)
		// Retain a valid native JSON spelling which typed Time normalizes away.
		document["valid_from"], document["valid_until"] = reg.ValidFrom.Format("2006-01-02T15:04:05.000Z"), reg.ValidUntil.Format("2006-01-02T15:04:05.000Z")
		if portfolio.Hash(document) == portfolio.Hash(reg) {
			t.Fatal("fractional registration control did not differ")
		}
		if _, e = admin.Pool.Exec(ctx, "INSERT INTO commitment_ownership_registrations(tenant_id,id,revision,document) VALUES($1,$2,1,$3)", f.tenant, key.id, decision040JSON(t, document)); e != nil {
			t.Fatal("operator key install failed", e)
		}
		var projected []byte
		if admin.Pool.QueryRow(ctx, "SELECT document FROM commitment_ownership_registrations WHERE tenant_id=$1 AND id=$2", f.tenant, key.id).Scan(&projected) != nil {
			t.Fatal("issued registration missing")
		}
		var issued any
		decision040Decode(t, projected, &issued)
		issuedHashes[key.id] = portfolio.Hash(issued)
		loaded, e := reader.OwnershipRegistration(ctx, key.id)
		if e != nil || loaded.IssuedDocumentSHA256 != issuedHashes[key.id] || portfolio.Hash(loaded) == issuedHashes[key.id] {
			t.Fatal("actual reader lost issued fractional-time hash", e)
		}
	}
	// All intervals start after actual operator installation, never backfilled.
	start := decision040Now(t, ctx, admin.Pool)
	deployment := portfolio.DecisionOwnershipDeploymentObservation{SchemaVersion: "1", ID: "component-deployment", RegistrationID: keys[0].id, RegistrationRevision: 1, ScopeSHA256: portfolio.Hash(scope), TenantID: f.tenant, WorkloadID: scope.WorkloadID, Resource: resource, ArtifactRef: portfolio.Ref{Kind: "CONFIGURATION_ARTIFACT", ID: receipt.ID, SHA256: portfolio.Hash(receipt)}, ArchiveRef: receipt.Archive, ObservedAt: start}
	storedDeployment, replay, e := decision040Append(t, ctx, observer, f.tenant, keys[0].subject, "DEPLOYMENT", decision040JSON(t, deployment))
	if e != nil || replay {
		t.Fatal("actual authenticated deployment append failed", e)
	}
	end := decision040Now(t, ctx, admin.Pool)
	if !end.After(start) {
		t.Fatal("database interval did not advance")
	}
	journal := portfolio.DecisionOwnershipJournal{SchemaVersion: "1", ID: "component-journal-row", RegistrationID: keys[0].id, RegistrationRevision: 1, ScopeSHA256: portfolio.Hash(scope), TenantID: f.tenant, WorkloadID: scope.WorkloadID, Resource: resource, Period: portfolio.Period{Start: start, End: end}, StateSerial: receipt.Metadata.State.Serial, ArtifactRef: deployment.ArtifactRef, ArchiveRef: receipt.Archive, DeploymentRef: storedDeployment.Reference, Sequence: 1, SignedAt: end}
	signing, _ := portfolio.DecisionOwnershipJournalSigningBytes(journal)
	envelope := portfolio.DecisionOwnershipJournalEnvelope{Journal: journal, Algorithm: "Ed25519/commitment-ownership-journal/v1", Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(journalKey, signing))}
	journalRaw := decision040JSON(t, envelope)
	storedJournal, replay, e := decision040Append(t, ctx, observer, f.tenant, keys[0].subject, "JOURNAL", journalRaw)
	if e != nil || replay {
		t.Fatal("actual signed journal append failed", e)
	}
	head := portfolio.DecisionOwnershipHead{ResourceID: resource.ResourceID, Count: 1, FirstSequence: 1, LastSequence: 1, FirstSHA256: storedJournal.Reference.SHA256, LastSHA256: storedJournal.Reference.SHA256}
	review := portfolio.DecisionOwnershipReview{SchemaVersion: "1", ID: "component-independent-review", RegistrationID: keys[1].id, RegistrationRevision: 1, JournalRegistrationID: keys[0].id, JournalRegistrationRevision: 1, ScopeSHA256: portfolio.Hash(scope), TenantID: f.tenant, WorkloadID: scope.WorkloadID, Period: journal.Period, Heads: []portfolio.DecisionOwnershipHead{head}, SignedAt: decision040Now(t, ctx, admin.Pool)}
	review.ChainRootSHA256 = portfolio.Hash(review.Heads)
	message, _ := portfolio.DecisionOwnershipReviewSigningBytes(review)
	reviewRaw := decision040JSON(t, portfolio.DecisionOwnershipReviewEnvelope{Review: review, Algorithm: "Ed25519/commitment-ownership-review/v1", Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(reviewKey, message))})
	if _, replay, e = decision040Append(t, ctx, observer, f.tenant, keys[1].subject, "REVIEW", reviewRaw); e != nil || replay {
		t.Fatal("actual independent review append failed", e)
	}
	query := portfolio.DecisionOwnershipQuery{Scope: scope, Period: journal.Period}
	evidence, e := portfolio.VerifyDecisionOwnership(ctx, reader, query, decision040Now(t, ctx, admin.Pool))
	if e != nil || evidence.Status != portfolio.DecisionOwnershipObserved || len(evidence.Segments) != 1 {
		t.Fatal("actual restricted readers/factory did not qualify component ownership", e)
	}
	for _, pin := range evidence.RegistrationPins {
		if pin.SHA256 != issuedHashes[pin.ID] {
			t.Fatal("publication pin is normalized instead of issued document hash")
		}
	}
	// Assert the real production denial before any rollback-only test grant.
	denied := analyst.Do(ctx, f.tenant, func(tx *store.Tx) error {
		_, e := tx.Exec(ctx, "SELECT public.commitment_ownership_validate($1,$2,$3::jsonb)", f.tenant, scope.WorkloadID, decision040JSON(t, evidence))
		return e
	})
	var denial *pgconn.PgError
	if !errors.As(denied, &denial) || denial.Code != "42501" {
		t.Fatal("normal analyst could directly execute private validator", denied)
	}
	validate := func(v any, tenant string) error {
		return decision040PrivateGuard(t, ctx, admin, analyst, tenant, scope.WorkloadID, decision040JSON(t, v))
	}
	if e = validate(evidence, f.tenant); e != nil {
		t.Fatal("positive actual publication guard refused valid component ownership", e)
	}
	t.Run("null_observed_timestamp_resealed", func(t *testing.T) {
		bad := model.Document{}
		decision040Decode(t, decision040JSON(t, evidence), &bad)
		bad["observed_at"], bad["id"] = nil, ""
		bad["id"] = portfolio.Hash(bad)
		decision040ExpectedSQL(t, validate(bad, f.tenant), "ownership observed timestamp required")
	})
	t.Run("duplicate_resource_resealed", func(t *testing.T) {
		bad := model.Document{}
		decision040Decode(t, decision040JSON(t, evidence), &bad)
		bad["segments"] = []any{evidence.Segments[0], evidence.Segments[0]}
		bad["id"] = ""
		bad["id"] = portfolio.Hash(bad)
		if validate(bad, f.tenant) == nil {
			t.Fatal("duplicate component segment admitted")
		}
	})
	t.Run("gap_and_duplicate_append", func(t *testing.T) {
		for _, sequence := range []uint64{1, 3} {
			bad := journal
			bad.ID = fmt.Sprintf("component-bad-%d", sequence)
			bad.Sequence = sequence
			bad.PreviousSHA256 = storedJournal.Reference.SHA256
			bad.Period.Start = journal.Period.End
			bad.Period.End = decision040Now(t, ctx, admin.Pool)
			bad.SignedAt = bad.Period.End
			m, _ := portfolio.DecisionOwnershipJournalSigningBytes(bad)
			raw := decision040JSON(t, portfolio.DecisionOwnershipJournalEnvelope{Journal: bad, Algorithm: envelope.Algorithm, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(journalKey, m))})
			if _, _, e := decision040Append(t, ctx, observer, f.tenant, keys[0].subject, "JOURNAL", raw); e == nil {
				t.Fatal("gap or duplicate chain sequence admitted")
			}
		}
	})
	t.Run("exact_replay_preserves_database_time", func(t *testing.T) {
		got, replayed, e := decision040Append(t, ctx, observer, f.tenant, keys[0].subject, "JOURNAL", journalRaw)
		if e != nil || !replayed || !got.ServerRecordedAt.Equal(storedJournal.ServerRecordedAt) || got.Reference != storedJournal.Reference {
			t.Fatal("exact replay changed immutable timestamp/ref", e)
		}
	})
	t.Run("late_new_interval_refused_without_clock_override", func(t *testing.T) {
		bad := journal
		bad.ID = "component-late-new"
		bad.Sequence = 2
		bad.PreviousSHA256 = storedJournal.Reference.SHA256
		bad.Period = portfolio.Period{Start: start.Add(-7 * time.Minute), End: start.Add(-6 * time.Minute)}
		bad.SignedAt = decision040Now(t, ctx, admin.Pool)
		m, _ := portfolio.DecisionOwnershipJournalSigningBytes(bad)
		raw := decision040JSON(t, portfolio.DecisionOwnershipJournalEnvelope{Journal: bad, Algorithm: envelope.Algorithm, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(journalKey, m))})
		_, _, e := decision040Append(t, ctx, observer, f.tenant, keys[0].subject, "JOURNAL", raw)
		decision040ExpectedSQL(t, e, "ownership historical body cannot be backfilled")
	})
	t.Run("role_and_tenant", func(t *testing.T) {
		if validate(evidence, f.tenant+"-foreign") == nil {
			t.Fatal("foreign credential authorized ownership")
		}
		for _, role := range []string{"api", "ingester"} {
			if e := f.roles[role].Do(ctx, f.tenant, func(tx *store.Tx) error {
				_, e := tx.Exec(ctx, "SELECT public.commitment_ownership_validate($1,$2,$3::jsonb)", f.tenant, scope.WorkloadID, decision040JSON(t, evidence))
				return e
			}); e == nil {
				t.Fatal("unprivileged role published ownership", role)
			}
		}
		if _, _, e := decision040Append(t, ctx, observer, f.tenant, "wrong-machine", "JOURNAL", journalRaw); e == nil {
			t.Fatal("unregistered authenticated subject appended")
		}
	})
	t.Run("past_day_preparation_persists_blocked", func(t *testing.T) {
		requestID := decision040PrepareBlocked(t, ctx, f, analyst, scope.WorkloadID)
		e := analyst.Do(ctx, f.tenant, func(tx *store.Tx) error {
			_, e := tx.Exec(ctx, "SELECT public.commitment_ownership_publish($1,$2,$3::jsonb)", f.tenant, requestID, decision040JSON(t, evidence))
			return e
		})
		decision040ExpectedSQL(t, e, "ownership preparation interval not covered")
	})
	t.Run("revocation_fences_current_publication_and_replay", func(t *testing.T) {
		if _, e := admin.Pool.Exec(ctx, "INSERT INTO commitment_ownership_revocations(tenant_id,registration_id,revision,reason_code) VALUES($1,$2,1,'COMPONENT_REVOKED')", f.tenant, keys[0].id); e != nil {
			t.Fatal(e)
		}
		decision040ExpectedSQL(t, validate(evidence, f.tenant), "ownership registered key changed")
		if _, _, e := decision040Append(t, ctx, observer, f.tenant, keys[0].subject, "JOURNAL", journalRaw); e == nil {
			t.Fatal("revoked exact replay admitted")
		}
	})
	t.Log("PRIVATE_GUARD_COMPONENT: actual040 DDL, issued raw registration hashes, attestor encrypted local fixture capture/readback, restricted observer append/database clocks, independent signatures, rollback-only private validator positive/negatives with ACL restored; actual public unrelated-period publication refused and API/worker preparation BLOCKED; no native history or purchase/forecast acceptance")
}
