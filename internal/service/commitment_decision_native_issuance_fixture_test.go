//go:build commitment_decision_native_integration

package service

// Deterministic provider/Git/Terraform transports, real issuance. This file
// creates declarations/registrations, never trusted facts or historical DB rows.
import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/commitmentarchive"
	portfolio "github.com/christopherosiemo/bn-implementation-Finops/internal/commitmentportfolio"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/configuration"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/slo"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/go-jose/go-jose/v4"
)

const decisionNativeSource = "decision-native"
const decisionNativeWorkload = "decision-native-workload"
const decisionNativeResource = "decision-native-resource"
const decisionNativeID = "i-0d040000000000001"
const decisionNativeReviewer = "e66a8a4c-1e42-4b97-8c31-85a9ef27b847"

func commitmentDecisionNativeDeclarations(ctx context.Context, f *mutationReplayFixture) error {
	return f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		if _, err := tx.Create(ctx, "workloads", model.Document{"id": decisionNativeWorkload, "name": "Simulated 974-day provider history — native adapter fixture", "owner": "fixture-owner", "environment": "NON_PRODUCTION"}); err != nil {
			return err
		}
		if _, err := tx.Create(ctx, "resources", model.Document{"id": decisionNativeResource, "workload_id": decisionNativeWorkload, "provider": "AWS", "resource_type": "EC2", "provider_resource_id": decisionNativeID, "account_id": nativeAssessmentAccount, "region": "eu-west-1", "instance_type": "m6i.large", "environment": "NON_PRODUCTION", "name": "Explicit simulated provider transport"}); err != nil {
			return err
		}
		objective := slo.Objective{SchemaVersion: "1", ID: "decision-native-continuous-availability", Version: 1, WorkloadID: decisionNativeWorkload, Limits: slo.Limits{MaxErrorRatePPM: 10000, MinAvailabilityPPM: 990000, MaxP95LatencyMS: 180, MaxP99LatencyMS: 250, MinLatencySamples: 10}, EvaluationMinutes: 2, Availability: slo.Availability{Mode: "ALWAYS", Timezone: "UTC", Windows: []slo.Window{}}}
		if _, err := tx.SLOObjectiveAppend(ctx, decisionNativeWorkload, 0, slo.Document(objective)); err != nil {
			return err
		}
		registration := source.FixtureRegistration(f.tenant, decisionNativeSource)
		_, err := tx.SourceCreate(ctx, registration)
		return err
	})
}

type commitmentDecisionArtifactArchive struct {
	put    func(context.Context, string, []byte) (model.Document, error)
	client *s3.Client
}

func (a commitmentDecisionArtifactArchive) Put(ctx context.Context, tenant, job string, raw []byte) (configuration.ArtifactArchiveRef, error) {
	ref, err := a.put(ctx, "tenant/"+tenant+"/decision-current-artifact/"+job+"/"+source.BytesHash(raw)+".encrypted", raw)
	if err != nil {
		return configuration.ArtifactArchiveRef{}, err
	}
	return configuration.ArtifactArchiveRef{Bucket: model.String(ref, "bucket"), Key: model.String(ref, "key"), VersionID: model.String(ref, "version_id"), SHA256: model.String(ref, "body_sha256"), Bytes: int64(len(raw))}, nil
}
func (a commitmentDecisionArtifactArchive) Read(ctx context.Context, tenant string, ref configuration.ArtifactArchiveRef) ([]byte, error) {
	if a.client == nil || !strings.HasPrefix(ref.Key, "tenant/"+tenant+"/decision-current-artifact/") {
		return nil, errors.New("DECISION_CURRENT_ARTIFACT_SCOPE")
	}
	out, err := a.client.GetObject(ctx, &s3.GetObjectInput{Bucket: &ref.Bucket, Key: &ref.Key, VersionId: &ref.VersionID})
	if err != nil {
		return nil, err
	}
	defer out.Body.Close()
	// Reuse the source bounded read function; artifacts remain encrypted bytes.
	raw, err := io.ReadAll(io.LimitReader(out.Body, configuration.ArtifactMaxBytes+1))
	if err != nil || len(raw) > configuration.ArtifactMaxBytes || int64(len(raw)) != ref.Bytes || source.BytesHash(raw) != ref.SHA256 || out.VersionId == nil || *out.VersionId != ref.VersionID {
		return nil, errors.New("DECISION_CURRENT_ARTIFACT_READBACK")
	}
	return raw, nil
}

// Provider-shaped Git/Terraform transport double for the EXACT declared native
// fixture resource. Unlike the negative component bundle, its declared address
// really occurs in state and no-op plan. An external AWS provider remains
// unsupported for execution; this is neither terraform apply nor live state.
func commitmentDecisionNativeArtifactBundle(t *testing.T, r configuration.ArtifactRegistration) configuration.ArtifactBundle {
	t.Helper()
	bundle := decision040Bundle(t, r)
	if r.Binding.ProviderResourceID != decisionNativeID || r.Binding.ResourceID != decisionNativeResource || len(r.Declaration.Terraform.Addresses) != 1 || r.Declaration.Terraform.Addresses[0] != "aws_instance.api" {
		t.Fatal("native artifact exact declaration differs")
	}
	body := []byte(`resource "aws_instance" "api" {
  ami = "` + nativeAssessmentImage + `"
  instance_type = "m6i.large"
}
`)
	attributes := map[string]any{"id": decisionNativeID, "ami": nativeAssessmentImage, "instance_type": "m6i.large", "arn": "arn:aws:ec2:eu-west-1:" + nativeAssessmentAccount + ":instance/" + decisionNativeID, "availability_zone": "eu-west-1a", "instance_state": "running"}
	resource := map[string]any{"address": "aws_instance.api", "mode": "managed", "type": "aws_instance", "name": "api", "provider_name": "registry.terraform.io/hashicorp/aws", "schema_version": 1, "values": attributes}
	values := map[string]any{"root_module": map[string]any{"resources": []any{resource}}}
	bundle.Files = []configuration.ArtifactFile{{Path: "main.tf", Mode: "100644", SHA256: source.BytesHash(body), Body: body}}
	bundle.StateRaw = decision040JSON(t, map[string]any{"version": 4, "terraform_version": r.Toolchain.TerraformVersion, "lineage": r.Declaration.Terraform.StateLineage, "serial": bundle.State.Serial, "resources": []any{map[string]any{"mode": "managed", "type": "aws_instance", "name": "api", "provider": `provider["registry.terraform.io/hashicorp/aws"]`, "instances": []any{map[string]any{"schema_version": 1, "attributes": attributes}}}}})
	bundle.StateJSON = decision040JSON(t, map[string]any{"format_version": "1.0", "terraform_version": r.Toolchain.TerraformVersion, "values": values})
	bundle.PlanJSON = decision040JSON(t, map[string]any{"format_version": "1.2", "terraform_version": r.Toolchain.TerraformVersion, "prior_state": map[string]any{"values": values}, "planned_values": values, "resource_changes": []any{map[string]any{"address": "aws_instance.api", "mode": "managed", "type": "aws_instance", "name": "api", "provider_name": "registry.terraform.io/hashicorp/aws", "change": map[string]any{"actions": []string{"no-op"}, "before": attributes, "after": attributes}}}, "configuration": map[string]any{"provider_config": map[string]any{"aws": map[string]any{"full_name": "registry.terraform.io/hashicorp/aws"}}}})
	bundle.VersionJSON = decision040JSON(t, map[string]any{"terraform_version": r.Toolchain.TerraformVersion, "platform": "linux_amd64", "provider_selections": map[string]any{"registry.terraform.io/hashicorp/aws": "6.0.0"}})
	var zipped bytes.Buffer
	writer := zip.NewWriter(&zipped)
	for _, file := range []struct {
		name string
		raw  []byte
	}{{"tfplan", []byte("explicit synthetic provider-shaped native saved-plan transport")}, {"tfstate", bundle.StateRaw}, {"tfstate-prev", bundle.StateRaw}, {"tfconfig/modules.json", []byte(`[{"Key":"","Dir":"."}]`)}, {"tfconfig/m-/main.tf", body}, {".terraform.lock.hcl", []byte{}}} {
		entry, err := writer.Create(file.name)
		if err != nil {
			t.Fatal("native saved-plan fixture failed")
		}
		if _, err = entry.Write(file.raw); err != nil {
			t.Fatal("native saved-plan fixture failed")
		}
	}
	if writer.Close() != nil {
		t.Fatal("native saved-plan fixture failed")
	}
	bundle.SavedPlan = zipped.Bytes()
	type entry struct{ Path, Mode, SHA256 string }
	bundle.Git.ConfigurationSHA256 = decision040LegacyHash(t, []entry{{"main.tf", "100644", source.BytesHash(body)}})
	bundle.Git.DependencySHA256 = decision040LegacyHash(t, map[string]any{"source": bundle.Git.ConfigurationSHA256, "modules": source.BytesHash(bundle.ModuleManifest), "toolchain": bundle.Toolchain})
	metadata, err := configuration.ValidateArtifactBundle(r, bundle)
	if err != nil || metadata.ExecutionAuthorized || metadata.VerifiedSaving != nil {
		t.Fatal("native bound artifact fixture did not validate", err)
	}
	externalUnsupported := false
	for _, reason := range metadata.ReasonCodes {
		if reason == "CONFIGURATION_DECLARED_ADDRESS_UNOBSERVED" {
			t.Fatal("native fixture declared address absent")
		}
		if reason == "CONFIGURATION_EXTERNAL_PROVIDER_UNSUPPORTED" {
			externalUnsupported = true
		}
	}
	if metadata.Status != "BLOCKED" || !externalUnsupported {
		t.Fatal("native fixture falsely acquired external-provider execution support")
	}
	return bundle
}

func commitmentDecisionNativeCurrentArtifact(t *testing.T, ctx context.Context, f *mutationReplayFixture, admin, analyst *store.Store, client *s3.Client, put func(context.Context, string, []byte) (model.Document, error), refresh *func(context.Context) error) (portfolio.DecisionOwnershipScope, error) {
	t.Helper()
	var scope portfolio.DecisionOwnershipScope
	var declaration configuration.Declaration
	decision040Decode(t, decision040JSON(t, configurationRequest()), &declaration)
	declaration.Repository.Directory = "."
	declaration.Terraform.Workspace = "default"
	declaration.Terraform.Addresses = []string{"aws_instance.api"}
	var authority model.Document
	err := f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		var err error
		authority, err = tx.ConfigurationAuthorityAppend(ctx, decisionNativeResource, 0, "explicit-fixture-platform", declaration)
		return err
	})
	if err != nil {
		return scope, err
	}
	var binding configuration.Binding
	decision040Decode(t, decision040JSON(t, authority["binding"]), &binding)
	registration := configuration.ArtifactRegistration{SchemaVersion: "1", ID: "decision-native-current-artifact", Version: 1, Binding: binding, AuthorityID: model.String(authority, "id"), AuthorityVersion: 1, Declaration: declaration, Issuer: declaration.Pipeline.Identity.Issuer, Audience: configuration.ArtifactAudience, Subject: declaration.Pipeline.Identity.Subject, PipelineID: declaration.Pipeline.Identity.PipelineID, Toolchain: configuration.ArtifactToolchain{TerraformVersion: "1.16.0", Image: "hashicorp/terraform@sha256:64360659224d6cbeb099eeed61aa66a80e02c18ba08c0243bd905165b47b088e", OS: "linux", Architecture: "amd64", WorkingDirectory: "/workspace"}}
	if err = admin.Pool.QueryRow(ctx, "SELECT content_hash FROM configuration_authority_revisions WHERE tenant_id=$1 AND id=$2", f.tenant, registration.AuthorityID).Scan(&registration.AuthorityHash); err != nil {
		return scope, err
	}
	attestor := decision040Role(t, ctx, admin, "finops_configuration_attestor")
	repository := &configuration.ArtifactPostgresRepository{Pool: attestor.Pool}
	if err = repository.Register(ctx, registration); err != nil {
		return scope, err
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return scope, err
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "decision-native-current"))
	if err != nil {
		return scope, err
	}
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "decision-native-current", Algorithm: "RS256", Use: "sig"}}})
	}))
	t.Cleanup(jwks.Close)
	authenticator, err := configuration.NewArtifactAuthenticator(ctx, registration.Issuer, registration.Audience, jwks.URL, true)
	if err != nil {
		return scope, err
	}
	signed, err := signer.Sign(decision040JSON(t, map[string]any{"iss": registration.Issuer, "aud": registration.Audience, "sub": registration.Subject, "tenant_id": f.tenant, "exp": time.Now().Add(time.Hour).Unix()}))
	if err != nil {
		return scope, err
	}
	token, err := signed.CompactSerialize()
	if err != nil {
		return scope, err
	}
	request := httptest.NewRequest("POST", "http://fixture.invalid/capture", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	principal, err := authenticator.Authenticate(request)
	if err != nil {
		return scope, err
	}
	keys, err := configuration.NewArtifactFixtureKeys(bytes.Repeat([]byte{19}, 32))
	if err != nil {
		return scope, err
	}
	// Actual encrypted attestor publication/readback over the visibly synthetic
	// native bound bundle above. External-provider BLOCKED remains explicit.
	pipeline := configuration.ArtifactPipeline{Repository: repository, Collector: decision040Collector{commitmentDecisionNativeArtifactBundle(t, registration)}, Archive: commitmentDecisionArtifactArchive{put: put, client: client}, Keys: keys, Fixture: true}
	receipt, replayed, err := pipeline.Capture(ctx, principal, registration.ID, "decision-current-artifact")
	if err != nil || replayed || receipt.Metadata.ExecutionAuthorized || receipt.Metadata.VerifiedSaving != nil {
		return scope, errors.New("DECISION_CURRENT_ARTIFACT_ISSUANCE")
	}
	// The current-scope SQL helper is deliberately owner-only. Construct this
	// expected query from the actual issued attestor receipt; the actual archive
	// publisher/resolver separately authenticates every field under its fences.
	if refresh == nil {
		return scope, errors.New("DECISION_CURRENT_ARTIFACT_REFRESH_REQUIRED")
	}
	*refresh = func(c context.Context) error {
		current, replayed, err := pipeline.Capture(c, principal, registration.ID, "decision-current-artifact-"+model.ID())
		if err != nil {
			return err
		}
		if replayed || portfolio.Hash(current.Metadata) != portfolio.Hash(receipt.Metadata) || current.Metadata.ExecutionAuthorized || current.Metadata.VerifiedSaving != nil {
			return errors.New("DECISION_CURRENT_ARTIFACT_METADATA_CHANGED")
		}
		return nil
	}
	metadata := receipt.Metadata
	scope = portfolio.DecisionOwnershipScope{TenantID: f.tenant, WorkloadID: decisionNativeWorkload, Resources: []portfolio.DecisionOwnershipResource{{ResourceID: metadata.Binding.ResourceID, ProviderResourceID: metadata.Binding.ProviderResourceID, AccountID: metadata.Binding.AccountID, Region: metadata.Binding.Region, RepositoryID: metadata.AuthorityID, GitCommit: metadata.Git.Commit, ConfigurationSHA256: metadata.Git.ConfigurationSHA256, StateLineage: metadata.State.Lineage}}}
	scope.ConfigurationSHA256 = portfolio.DecisionOwnershipConfigurationSHA256(scope.Resources)
	if len(scope.Resources) != 1 || scope.Resources[0].ResourceID != decisionNativeResource || scope.Resources[0].ProviderResourceID != decisionNativeID {
		return scope, errors.New("DECISION_CURRENT_ATTESTED_SCOPE")
	}
	return scope, nil
}

// Current operator commissioning is explicit customer trust, not historical
// native evidence. Every historical witness is subsequently issued by Pipeline.
func commitmentDecisionNativeArchive(t *testing.T, ctx context.Context, f *mutationReplayFixture, admin *store.Store, scope portfolio.DecisionOwnershipScope, period portfolio.Period, client *s3.Client, bucket string) (portfolio.DecisionOwnershipArchiveEvidence, func(context.Context) error, error) {
	t.Helper()
	var empty portfolio.DecisionOwnershipArchiveEvidence
	now := time.Now().UTC()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return empty, nil, err
	}
	reviewPub, reviewKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return empty, nil, err
	}
	resource := scope.Resources[0]
	var repositoryURI string
	if err = admin.Pool.QueryRow(ctx, "SELECT document->'repository'->>'url' FROM configuration_authority_revisions WHERE tenant_id=$1 AND id=$2", f.tenant, resource.RepositoryID).Scan(&repositoryURI); err != nil {
		return empty, nil, err
	}
	const originalBucket = "synthetic-original-customer-archive"
	const bindingID = "decision-original-read"
	const role = "arn:aws:iam::111122223333:role/FixtureOriginalArchiveRead"
	const externalID = "decision-native-fixture-external-id-012345678901234567890"
	policy := model.Document{"Version": "2012-10-17", "Statement": []model.Document{{"Effect": "Allow", "Principal": model.Document{"AWS": "arn:aws:iam::111122223333:role/customer-archive-writer"}, "Action": "s3:PutObject", "Resource": "arn:aws:s3:::" + originalBucket + "/customer-history/*"}}}
	external := portfolio.DecisionOwnershipArchiveExternalResource{CustomerWorkloadID: "customer-preexisting-api", AccountID: resource.AccountID, Region: resource.Region, ProviderID: resource.ProviderResourceID, RepositoryURI: repositoryURI, GitCommit: resource.GitCommit, ConfigurationSHA256: resource.ConfigurationSHA256, TerraformAddress: "aws_instance.api", StateLineage: resource.StateLineage}
	registration := portfolio.DecisionOwnershipArchiveRegistration{ID: "decision-simulated-original-archive", Revision: 1, ScopeSHA256: portfolio.Hash(scope), CustomerNamespace: "customer-existing-namespace", ExternalResources: []portfolio.DecisionOwnershipArchiveResourceMapping{{ResourceID: resource.ResourceID, ExternalResource: external}}, TenantID: f.tenant, AccountID: resource.AccountID, BucketOwner: resource.AccountID, Bucket: originalBucket, Prefix: "customer-history/", Region: resource.Region, ReadRoleBinding: portfolio.Ref{Kind: "APPROVED_READ_ROLE_BINDING", ID: bindingID, SHA256: portfolio.Hash(map[string]any{"role": role, "tenant": f.tenant, "account": resource.AccountID})}, CurrentBucketPolicySHA256: portfolio.Hash(policy), SignerKeyID: "decision-simulated-historical-key", SignerPublicKey: pub, SignerCustodianIssuer: "https://fixture-customer-archive.invalid", SignerCustodianSubject: "historical-fixture-writer", ValidUntil: now.Add(time.Hour)}
	reviewer := portfolio.DecisionOwnershipRegistration{ID: "decision-independent-current-review", Revision: 1, ScopeSHA256: portfolio.Hash(scope), Purpose: "OWNERSHIP_REVIEW", Issuer: "https://fixture-customer-review.invalid", Subject: "independent-fixture-reviewer", Audience: configuration.ObserverAudience, PublicKey: reviewPub, ValidFrom: now.Add(-time.Minute), ValidUntil: now.Add(time.Hour)}
	if _, err = admin.Pool.Exec(ctx, "INSERT INTO commitment_ownership_archive_sources(tenant_id,id,revision,document,content_hash) VALUES($1,$2,1,$3,'')", f.tenant, registration.ID, decision040JSON(t, registration)); err != nil {
		return empty, nil, err
	}
	if _, err = admin.Pool.Exec(ctx, "INSERT INTO commitment_ownership_registrations(tenant_id,id,revision,document) VALUES($1,$2,1,$3)", f.tenant, reviewer.ID, decision040JSON(t, reviewer)); err != nil {
		return empty, nil, err
	}
	storage := &commitmentarchive.ImmutableArchive{Client: client, Bucket: bucket}
	repository := &commitmentarchive.PostgresRepository{Store: f.roles["ingester"], Tenant: f.tenant, Archive: storage.Witness, ArchiveReview: storage.Review}
	registration, err = repository.ArchiveRegistration(ctx, registration.ID)
	if err != nil {
		return empty, nil, err
	}
	reviewer, err = repository.ArchiveReviewRegistration(ctx, reviewer.ID)
	if err != nil {
		return empty, nil, err
	}
	original, err := commitmentDecisionBuildOriginalArchive(registration, reviewer, portfolio.DecisionOwnershipQuery{Scope: scope, Period: period}, key, reviewKey, now)
	if err != nil {
		return empty, nil, err
	}
	savedEnvironment := map[string]string{}
	for _, key := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_EC2_METADATA_DISABLED", "AWS_ENDPOINT_URL_STS", "AWS_ENDPOINT_URL_S3", "AWS_ENDPOINT_URL", "AWS_PROFILE", "AWS_SHARED_CREDENTIALS_FILE", "AWS_CONFIG_FILE"} {
		savedEnvironment[key] = os.Getenv(key)
	}
	defer func() {
		for key, value := range savedEnvironment {
			t.Setenv(key, value)
		}
	}()
	transport := commitmentDecisionOriginalHTTPServer(t, originalBucket, resource.AccountID, role, externalID, policy, original.Objects)
	bindings, _ := json.Marshal(map[string]source.AWSReadBinding{bindingID: {TenantID: f.tenant, PayerAccountID: resource.AccountID, AccountID: resource.AccountID, RoleARN: role, ExternalID: externalID, Region: resource.Region}})
	target := commitmentarchive.Target{TenantID: f.tenant, SourceID: registration.ID, Review: original.Review}
	evidence, err := commitmentDecisionCaptureOriginalArchive(ctx, f.roles["ingester"], string(bindings), storage, target)
	if err != nil {
		return empty, nil, err
	}
	if transport.AssumeRoleCalls.Load() < 1 || transport.VersionedObjectReads.Load() < int64(original.HourlyObjects+1) || transport.RejectedRequests.Load() != 0 {
		return empty, nil, errors.New("DECISION_ORIGINAL_SDK_TRANSPORT_NOT_EXERCISED")
	}
	factory, err := source.AWSFactory(string(bindings))
	if err != nil {
		return empty, nil, err
	}
	reader, err := factory(ctx, source.Registration{ID: registration.ID, TenantID: f.tenant, PayerAccountID: resource.AccountID, Region: resource.Region, Bucket: registration.Bucket, BucketOwner: resource.AccountID, Prefix: registration.Prefix, ReadRoleBindingID: bindingID, Version: 1})
	if err != nil {
		return empty, nil, err
	}
	repository.ReadCurrentBucket = func(c context.Context, _ portfolio.DecisionOwnershipArchiveRegistration) (map[string]any, error) {
		v, err := reader.BillingBucket(c, registration.Bucket)
		return map[string]any(v), err
	}
	refresh := func(c context.Context) error { return repository.RefreshArchiveSource(c, registration) }
	return evidence, refresh, nil
}

// Source.Capture validates and issues the actual complete native SDK projection;
// this transport constructs SDK-shaped pages, not an authoritative offer row.
type commitmentDecisionNativeQuoteReader struct{ *source.FixtureReader }

func (commitmentDecisionNativeQuoteReader) BillingSavingsPlanQuotes(_ context.Context, account string, selection provider.SavingsPlanQuoteSelection) (model.Document, error) {
	if account != nativeAssessmentAccount || selection.PlanType != "Compute" || selection.PaymentOption != "No Upfront" || selection.DurationSeconds != 31536000 || selection.Currency != "USD" || len(selection.ExistingPlanIDs) != 0 {
		return nil, errors.New("DECISION_NATIVE_QUOTE_SELECTOR")
	}
	return commitmentDecisionNativeQuoteProjection(time.Now().UTC()), nil
}
func commitmentDecisionNativeQuotes(t *testing.T, ctx context.Context, f *mutationReplayFixture, put func(context.Context, string, []byte) (model.Document, error)) ([]model.Document, func(context.Context) error, error) {
	t.Helper()
	reader := commitmentDecisionNativeQuoteReader{FixtureReader: &source.FixtureReader{}}
	pipeline := source.SavingsPlanQuotePipeline{Store: f.roles["ingester"], ReaderFactory: func(context.Context, source.Registration) (source.Reader, error) { return reader, nil }, Archive: func(c context.Context, tenant, src string, raw []byte) (model.Document, error) {
		return put(c, "tenant/"+tenant+"/commitment-quotes/"+src+"/"+source.BytesHash(raw)+".json", raw)
	}}
	target := source.SavingsPlanQuoteTarget{TenantID: f.tenant, SourceID: decisionNativeSource, PlanType: "Compute", Currency: "USD"}
	offers, err := pipeline.Capture(ctx, target)
	if err != nil {
		return nil, nil, err
	}
	return offers, func(c context.Context) error { _, err := pipeline.CaptureIfDue(c, target); return err }, nil
}

func commitmentDecisionNativeQuoteProjection(now time.Time) model.Document {
	offers := []model.Document{}
	rates := []model.Document{}
	for index, id := range []string{"aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa", "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb"} {
		offer := model.Document{"offeringId": id, "currency": "USD", "durationSeconds": 31536000, "paymentOption": "No Upfront", "planType": "Compute", "productTypes": []string{"EC2"}}
		offers = append(offers, offer)
		price := []string{"0.1", "0.3"}[index]
		rates = append(rates, model.Document{"savingsPlanOffering": offer, "rate": price, "unit": "Hrs", "serviceCode": "AmazonEC2", "productType": "EC2", "usageType": "EUW1-BoxUsage:m6i.large", "operation": "RunInstances", "properties": []model.Document{{"name": "region", "value": "eu-west-1"}, {"name": "instanceType", "value": "m6i.large"}, {"name": "instanceFamily", "value": "m6i"}, {"name": "productDescription", "value": "Linux/UNIX"}, {"name": "tenancy", "value": "Shared"}}})
	}
	pages := []model.Document{{"ordinal": 1, "operation": "DescribeSavingsPlansOfferings", "request": model.Document{"planTypes": []string{"Compute"}, "paymentOptions": []string{"No Upfront"}, "durations": []int64{31536000}, "currencies": []string{"USD"}, "maxResults": 1000}, "response": model.Document{"searchResults": offers}}, {"ordinal": 2, "operation": "DescribeSavingsPlansOfferingRates", "request": model.Document{"savingsPlanOfferingIds": []string{model.String(offers[0], "offeringId"), model.String(offers[1], "offeringId")}, "maxResults": 1000}, "response": model.Document{"searchResults": rates}}}
	hashes := []string{}
	for _, page := range pages {
		hash := portfolio.Hash(page)
		page["sha256"] = hash
		hashes = append(hashes, hash)
	}
	offeringRows, rateRows := []model.Document{}, []model.Document{}
	for _, offer := range offers {
		offeringRows = append(offeringRows, model.Document{"native": offer, "page_sha256": hashes[0]})
	}
	for _, rate := range rates {
		rateRows = append(rateRows, model.Document{"native": rate, "page_sha256": hashes[1]})
	}
	return model.Document{"native_projection": provider.SavingsPlanQuoteProjection, "serialization": "SDK_PROJECTION", "authenticated_account_id": nativeAssessmentAccount, "observed_at": now.UTC().Format(time.RFC3339Nano), "complete": true, "selection": provider.SavingsPlanQuoteSelection{PlanType: "Compute", PaymentOption: "No Upfront", DurationSeconds: 31536000, Currency: "USD", ExistingPlanIDs: []string{}}, "pages": pages, "ordered_page_sha256s": hashes, "offerings": offeringRows, "offering_rates": rateRows, "existing_plan_rates": []model.Document{}}
}
