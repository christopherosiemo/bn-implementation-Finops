package service

// Restricted PostgreSQL COMPONENT regression. Original S3 metadata and the
// immutable object transport below are explicit doubles. The test exercises the
// production verifier, version write/readback, repository, RLS and currentness
// guards; it establishes neither native historical ownership nor a purchase.
import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/commitmentarchive"
	portfolio "github.com/christopherosiemo/bn-implementation-Finops/internal/commitmentportfolio"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/configuration"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type decisionArchiveObjects struct {
	objects     map[string][]byte
	puts, gets  int
	corruptRead bool
}

func (a *decisionArchiveObjects) PutObject(_ context.Context, in *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	if aws.ToString(in.Bucket) != "component-archive-mirror" || !strings.Contains(aws.ToString(in.Key), "/commitment-ownership-archive/") {
		return nil, errors.New("component app archive scope differs")
	}
	raw, err := io.ReadAll(io.LimitReader(in.Body, (24<<20)+1))
	if err != nil || len(raw) == 0 || len(raw) > 24<<20 {
		return nil, errors.New("component app archive bytes differ")
	}
	version := "component-version-" + source.BytesHash(raw)
	a.objects[aws.ToString(in.Key)+"\x00"+version] = append([]byte{}, raw...)
	a.puts++
	return &s3.PutObjectOutput{VersionId: aws.String(version)}, nil
}

func (a *decisionArchiveObjects) GetObject(_ context.Context, in *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	if aws.ToString(in.Bucket) != "component-archive-mirror" {
		return nil, errors.New("component app archive bucket differs")
	}
	raw, ok := a.objects[aws.ToString(in.Key)+"\x00"+aws.ToString(in.VersionId)]
	if !ok {
		return nil, errors.New("component app archive version absent")
	}
	raw = append([]byte{}, raw...)
	if a.corruptRead {
		raw = append(raw, ' ')
	}
	a.gets++
	return &s3.GetObjectOutput{VersionId: in.VersionId, ContentLength: aws.Int64(int64(len(raw))), Body: io.NopCloser(bytes.NewReader(raw))}, nil
}

type decisionArchiveReader struct {
	repository               *commitmentarchive.PostgresRepository
	bucket                   map[string]any
	objects                  map[string]provider.BillingObject
	cache                    *commitmentarchive.ReplayCache
	originalReads, cacheHits int
}

func (r *decisionArchiveReader) ArchiveRegistration(ctx context.Context, id string) (portfolio.DecisionOwnershipArchiveRegistration, error) {
	return r.repository.ArchiveRegistration(ctx, id)
}
func (r *decisionArchiveReader) ArchiveReviewRegistration(ctx context.Context, id string) (portfolio.DecisionOwnershipRegistration, error) {
	return r.repository.ArchiveReviewRegistration(ctx, id)
}
func (r *decisionArchiveReader) ArchiveBucket(context.Context, portfolio.DecisionOwnershipArchiveRegistration) (map[string]any, error) {
	return r.bucket, nil
}
func (r *decisionArchiveReader) ArchiveObject(ctx context.Context, reg portfolio.DecisionOwnershipArchiveRegistration, pin portfolio.DecisionOwnershipArchiveObjectPin) (provider.BillingObject, error) {
	if r.cache != nil {
		object, found, err := r.cache.Lookup(ctx, reg, pin)
		if err != nil {
			return object, err
		}
		if found {
			r.cacheHits++
			return object, nil
		}
	}
	object, found := r.objects[pin.Key+"\x00"+pin.VersionID]
	if !found {
		return object, errors.New("component original version absent")
	}
	r.originalReads++
	return object, nil
}
func (r *decisionArchiveReader) PersistArchiveWitness(ctx context.Context, reg portfolio.DecisionOwnershipArchiveRegistration, witness portfolio.DecisionOwnershipArchiveWitness, raw []byte) (portfolio.Ref, error) {
	if r.cache != nil {
		ref, found, err := r.cache.RecordedWitness(witness, raw)
		if err != nil || found {
			return ref, err
		}
	}
	return r.repository.PersistArchiveWitness(ctx, reg, witness, raw)
}

func decisionArchiveResolve(ctx context.Context, db *store.Store, tenant, workload string, ref portfolio.Ref, period portfolio.Period) (portfolio.DecisionResolvedOwnership, error) {
	var out portfolio.DecisionResolvedOwnership
	err := db.Do(ctx, tenant, func(tx *store.Tx) error {
		var raw []byte
		if err := tx.QueryRow(ctx, "SELECT public.commitment_decision_ownership_assert($1,$2,$3::jsonb,$4,$5)", tenant, workload, decisionArchiveWire(ref), period.Start, period.End).Scan(&raw); err != nil {
			return err
		}
		return decisionArchiveDecode(raw, &out)
	})
	return out, err
}

func decisionArchiveWire(v any) []byte              { raw, _ := json.Marshal(v); return raw }
func decisionArchiveDecode(raw []byte, v any) error { return json.Unmarshal(raw, v) }

// The operator change is rolled back after invoking the resolver under the
// actual commissioned analyst LOGIN/OID. It never changes durable fixtures or
// relaxes a production ACL, and no fake clock is installed.
func decisionArchiveChanged(t *testing.T, ctx context.Context, admin, analyst *store.Store, tenant, workload string, ref portfolio.Ref, period portfolio.Period, mutate func(pgx.Tx) error) error {
	t.Helper()
	tx, err := admin.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, "SELECT set_config('app.tenant_id',$1,true)", tenant); err != nil {
		t.Fatal(err)
	}
	if err = mutate(tx); err != nil {
		t.Fatal("component operator mutation did not reach its precondition", err)
	}
	login := analyst.Pool.Config().ConnConfig.User
	if !strings.HasPrefix(login, "portfolio_native_") {
		t.Fatal("component analyst identity differs")
	}
	if _, err = tx.Exec(ctx, "SET LOCAL SESSION AUTHORIZATION "+pgx.Identifier{login}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, "SET LOCAL ROLE finops_commitment_portfolio"); err != nil {
		t.Fatal(err)
	}
	var session, role string
	var scoped bool
	if err = tx.QueryRow(ctx, "SELECT session_user,current_user,public.commitment_portfolio_scope($1)", tenant).Scan(&session, &role, &scoped); err != nil || session != login || role != "finops_commitment_portfolio" || !scoped {
		t.Fatal("component mutation did not retain actual commissioned identity")
	}
	_, err = tx.Exec(ctx, "SELECT public.commitment_decision_ownership_assert($1,$2,$3::jsonb,$4,$5)", tenant, workload, decisionArchiveWire(ref), period.Start, period.End)
	if rollback := tx.Rollback(ctx); rollback != nil {
		t.Fatal("component operator rollback failed")
	}
	return err
}

func TestCommitmentDecision040ArchiveRestrictedPublicationReplayAndCurrentness(t *testing.T) {
	f, admin, _, _ := newFleetNativeHTTPTest(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if err := admin.Migrate(ctx, "../../migrations"); err != nil {
		t.Fatal("component archive migrations failed", err)
	}
	analyst := commitmentPortfolioNativeRuntime(t, ctx, admin, f.tenant)
	ingester := decision040Role(t, ctx, admin, "finops_ingester")
	if err := ingester.Do(ctx, f.tenant, func(tx *store.Tx) error {
		var login, role string
		if err := tx.QueryRow(ctx, "SELECT session_user,current_user").Scan(&login, &role); err != nil {
			return err
		}
		if login != ingester.Pool.Config().ConnConfig.User || role != "finops_ingester" {
			return errors.New("actual archive ingester session differs")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	receipt, _ := decision040Artifact(t, ctx, f, admin)
	resource := portfolio.DecisionOwnershipResource{ResourceID: receipt.Metadata.Binding.ResourceID, ProviderResourceID: receipt.Metadata.Binding.ProviderResourceID, AccountID: receipt.Metadata.Binding.AccountID, Region: receipt.Metadata.Binding.Region, RepositoryID: receipt.Metadata.AuthorityID, GitCommit: receipt.Metadata.Git.Commit, ConfigurationSHA256: receipt.Metadata.Git.ConfigurationSHA256, StateLineage: receipt.Metadata.State.Lineage}
	scope := portfolio.DecisionOwnershipScope{TenantID: f.tenant, WorkloadID: receipt.Metadata.Binding.WorkloadID, Resources: []portfolio.DecisionOwnershipResource{resource}}
	scope.ConfigurationSHA256 = portfolio.DecisionOwnershipConfigurationSHA256(scope.Resources)
	now := decision040Now(t, ctx, admin.Pool)
	period := portfolio.Period{Start: now.Truncate(time.Hour).Add(-48 * time.Hour), End: now.Truncate(time.Hour).Add(-46 * time.Hour)}
	query := portfolio.DecisionOwnershipQuery{Scope: scope, Period: period}
	var repositoryURI string
	if err := admin.Pool.QueryRow(ctx, "SELECT document->'repository'->>'url' FROM configuration_authority_revisions WHERE tenant_id=$1 AND id=$2", f.tenant, resource.RepositoryID).Scan(&repositoryURI); err != nil {
		t.Fatal("component approved repository authority absent", err)
	}
	external := portfolio.DecisionOwnershipArchiveExternalResource{CustomerWorkloadID: "customer-pre-onboarding-workload", AccountID: resource.AccountID, Region: resource.Region, ProviderID: resource.ProviderResourceID, RepositoryURI: repositoryURI, GitCommit: resource.GitCommit, ConfigurationSHA256: resource.ConfigurationSHA256, TerraformAddress: "aws_instance.api", StateLineage: resource.StateLineage}
	signerPublic, signerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	reviewerPublic, reviewerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	policy := map[string]any{"Version": "2012-10-17", "Statement": []any{map[string]any{"Effect": "Allow", "Principal": map[string]any{"AWS": "arn:aws:iam::111122223333:role/component-archive-custodian"}, "Action": "s3:PutObject", "Resource": "arn:aws:s3:::component-original-archive/customer-owned/history/*"}}}
	registration := portfolio.DecisionOwnershipArchiveRegistration{ID: "component-original-archive-source", Revision: 1, ScopeSHA256: portfolio.Hash(scope), CustomerNamespace: "customer-existing-namespace", ExternalResources: []portfolio.DecisionOwnershipArchiveResourceMapping{{ResourceID: resource.ResourceID, ExternalResource: external}}, TenantID: f.tenant, AccountID: resource.AccountID, BucketOwner: resource.AccountID, Bucket: "component-original-archive", Prefix: "customer-owned/history/", Region: resource.Region, ReadRoleBinding: portfolio.Ref{Kind: "APPROVED_READ_ROLE_BINDING", ID: "component-approved-reader", SHA256: portfolio.Hash("explicit-component-read-role-binding")}, CurrentBucketPolicySHA256: portfolio.Hash(policy), SignerKeyID: "component-historical-customer-key", SignerPublicKey: signerPublic, SignerCustodianIssuer: "https://customer-archive.invalid", SignerCustodianSubject: "historical-writer", ValidUntil: now.Add(time.Hour)}
	if _, err = admin.Pool.Exec(ctx, "INSERT INTO commitment_ownership_archive_sources(tenant_id,id,revision,document,content_hash) VALUES($1,$2,1,$3,'')", f.tenant, registration.ID, decision040JSON(t, registration)); err != nil {
		t.Fatal("component archive operator commission failed", err)
	}
	reviewer := portfolio.DecisionOwnershipRegistration{ID: "component-archive-independent-reviewer", Revision: 1, ScopeSHA256: portfolio.Hash(scope), Purpose: "OWNERSHIP_REVIEW", Issuer: "https://customer-review.invalid", Subject: "independent-reviewer", Audience: configuration.ObserverAudience, PublicKey: reviewerPublic, ValidFrom: now.Add(-time.Hour), ValidUntil: now.Add(time.Hour)}
	if _, err = admin.Pool.Exec(ctx, "INSERT INTO commitment_ownership_registrations(tenant_id,id,revision,document) VALUES($1,$2,1,$3)", f.tenant, reviewer.ID, decision040JSON(t, reviewer)); err != nil {
		t.Fatal("component independent reviewer commission failed", err)
	}
	app := &decisionArchiveObjects{objects: map[string][]byte{}}
	storage := &commitmentarchive.ImmutableArchive{Client: app, Bucket: "component-archive-mirror"}
	bucket := map[string]any{"versioning": "Enabled", "region": resource.Region, "bucket_owner": resource.AccountID, "policy": policy}
	repository := &commitmentarchive.PostgresRepository{Store: ingester, Tenant: f.tenant, Archive: storage.Witness, ArchiveReview: storage.Review, ReadCurrentBucket: func(context.Context, portfolio.DecisionOwnershipArchiveRegistration) (map[string]any, error) {
		return map[string]any{"versioning": "Enabled", "region": resource.Region, "bucket_owner": resource.AccountID, "policy": policy, "observed_at": decision040Now(t, ctx, admin.Pool).Format(time.RFC3339Nano)}, nil
	}}
	registration, err = repository.ArchiveRegistration(ctx, registration.ID)
	if err != nil || registration.IssuedDocumentSHA256 == "" {
		t.Fatal("actual ingester could not read issued archive registration", err)
	}
	reader := &decisionArchiveReader{repository: repository, bucket: bucket, objects: map[string]provider.BillingObject{}}
	review := portfolio.DecisionOwnershipArchiveReview{SchemaVersion: "1", ID: "component-archive-review", Query: query, SourceRegistrationSHA256: registration.IssuedDocumentSHA256, SignerPublicKeySHA256: source.BytesHash(signerPublic), Objects: []portfolio.DecisionOwnershipArchiveObjectPin{}, Heads: []portfolio.DecisionOwnershipHead{}, ReviewerRegistrationID: reviewer.ID, ReviewerRegistrationRevision: 1}
	head := portfolio.DecisionOwnershipHead{ResourceID: resource.ResourceID, FirstSequence: 1}
	previous := ""
	for i, id := range []string{"component-original-hour-one", "component-original-hour-two"} {
		configurationRaw := decision040JSON(t, portfolio.DecisionOwnershipArchiveConfiguration{ExternalResource: external, StateSerial: receipt.Metadata.State.Serial, ConfigurationBundleSHA256: source.BytesHash([]byte("explicit historical customer bundle claim"))})
		deploymentRaw := decision040JSON(t, portfolio.DecisionOwnershipArchiveDeployment{ExternalResource: external, StateSerial: receipt.Metadata.State.Serial, ConfigurationDocumentSHA256: source.BytesHash(configurationRaw), Revision: resource.GitCommit, Result: "SUCCEEDED", CompletedAt: period.Start.Add(-time.Hour)})
		start := period.Start.Add(time.Duration(i) * time.Hour)
		claim := portfolio.DecisionOwnershipArchiveClaim{SchemaVersion: "1", ID: id, CustomerNamespace: registration.CustomerNamespace, SignerKeyID: registration.SignerKeyID, ExternalResource: external, Period: portfolio.Period{Start: start, End: start.Add(time.Hour)}, StateSerial: receipt.Metadata.State.Serial, Sequence: uint64(i + 1), PreviousSHA256: previous, ConfigurationDocument: configurationRaw, DeploymentDocument: deploymentRaw, SignedAt: start.Add(time.Hour)}
		message, err := portfolio.DecisionOwnershipArchiveSigningBytes(claim)
		if err != nil {
			t.Fatal(err)
		}
		raw := decision040JSON(t, portfolio.DecisionOwnershipArchiveEnvelope{Claim: claim, Algorithm: "Ed25519/commitment-ownership-archive/v1", Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(signerPrivate, message))})
		for _, platformID := range []string{scope.TenantID, scope.WorkloadID, resource.ResourceID, resource.RepositoryID} {
			if bytes.Contains(raw, []byte(platformID)) {
				t.Fatal("component historical signed bytes contain newly allocated platform identity")
			}
		}
		pin := portfolio.DecisionOwnershipArchiveObjectPin{Key: registration.Prefix + id + ".json", VersionID: "component-original-version-" + id, SHA256: source.BytesHash(raw), Bytes: int64(len(raw))}
		reader.objects[pin.Key+"\x00"+pin.VersionID] = provider.BillingObject{Key: pin.Key, VersionID: pin.VersionID, Data: raw, LastModified: claim.Period.End.Add(time.Minute)}
		review.Objects = append(review.Objects, pin)
		if i == 0 {
			head.FirstSHA256 = pin.SHA256
		}
		head.Count++
		head.LastSequence = claim.Sequence
		head.LastSHA256 = pin.SHA256
		previous = pin.SHA256
	}
	review.Heads = append(review.Heads, head)
	review.SignedAt = decision040Now(t, ctx, admin.Pool)
	message, err := portfolio.DecisionOwnershipArchiveReviewSigningBytes(review)
	if err != nil {
		t.Fatal(err)
	}
	rawReview := decision040JSON(t, portfolio.DecisionOwnershipArchiveReviewEnvelope{Review: review, Algorithm: "Ed25519/commitment-ownership-archive-review/v1", Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(reviewerPrivate, message))})
	observed := decision040Now(t, ctx, admin.Pool)
	evidence, err := portfolio.VerifyDecisionOwnershipArchive(ctx, reader, registration.ID, rawReview, query, observed)
	if err != nil || evidence.WitnessCount != 2 || len(evidence.Heads) != 1 || reader.originalReads != 2 || app.puts != 2 || app.gets != 2 {
		t.Fatal("two-interval restricted archive verification/readback failed", err)
	}
	if err = repository.PublishArchiveEvidence(ctx, registration, evidence, rawReview); err != nil {
		t.Fatal("actual restricted archive aggregate publication failed", err)
	}
	var exactWitnesses bool
	if err = admin.Pool.QueryRow(ctx, "SELECT count(*)=2 AND bool_and(writer_role='finops_ingester' AND source_hash=$3 AND server_recorded_at>=$4 AND period_end<$4 AND archive->>'version_id'<>'') FROM commitment_ownership_archive_witnesses WHERE tenant_id=$1 AND source_id=$2", f.tenant, registration.ID, registration.IssuedDocumentSHA256, now).Scan(&exactWitnesses); err != nil || !exactWitnesses {
		t.Fatal("actual ingester witness rows lost source, original interval, readback or present DB receipt binding", err)
	}
	ref := portfolio.Ref{Kind: "HISTORICAL_OWNERSHIP", ID: evidence.ID, SHA256: portfolio.Hash(evidence)}
	resolved, err := decisionArchiveResolve(ctx, analyst, f.tenant, scope.WorkloadID, ref, period)
	if err != nil || resolved.Reference != ref || resolved.Basis != portfolio.DecisionOwnershipArchiveBasis || portfolio.Hash(resolved.Scope) != portfolio.Hash(scope) || !resolved.Period.Start.Equal(period.Start) || !resolved.Period.End.Equal(period.End) || len(resolved.RegistrationPins) != 2 {
		t.Fatal("actual scoped archive/ownership union resolution failed", err)
	}
	var originalRecorded time.Time
	var count int
	if err = admin.Pool.QueryRow(ctx, "SELECT count(*),min(server_recorded_at) FROM commitment_ownership_archive_evidence WHERE tenant_id=$1 AND id=$2", f.tenant, evidence.ID).Scan(&count, &originalRecorded); err != nil || count != 1 || originalRecorded.Before(now) {
		t.Fatal("archive aggregate did not retain actual present DB receipt time")
	}
	var liveCount int
	if err = admin.Pool.QueryRow(ctx, "SELECT (SELECT count(*) FROM commitment_ownership_journals WHERE tenant_id=$1)+(SELECT count(*) FROM commitment_ownership_reviews WHERE tenant_id=$1)", f.tenant).Scan(&liveCount); err != nil || liveCount != 0 {
		t.Fatal("historical import wrote a live guarded journal or review")
	}

	t.Run("native_issued_page_cache_and_exact_replay", func(t *testing.T) {
		reader.cache = commitmentarchive.NewReplayCache(repository, storage, review.Objects)
		puts, gets, reads := app.puts, app.gets, reader.originalReads
		replayed, err := portfolio.VerifyDecisionOwnershipArchive(ctx, reader, registration.ID, rawReview, query, observed)
		if err != nil || portfolio.Hash(replayed) != portfolio.Hash(evidence) || reader.cacheHits != 2 || reader.originalReads != reads || app.puts != puts || app.gets != gets {
			t.Fatal("actual issued-witness cache did not preserve exact proof without rereading completed objects", err)
		}
		if err = repository.PublishArchiveEvidence(ctx, registration, replayed, rawReview); err != nil {
			t.Fatal("exact archive aggregate replay failed", err)
		}
		var recorded time.Time
		if err = admin.Pool.QueryRow(ctx, "SELECT count(*),min(server_recorded_at) FROM commitment_ownership_archive_evidence WHERE tenant_id=$1 AND id=$2", f.tenant, evidence.ID).Scan(&count, &recorded); err != nil || count != 1 || !recorded.Equal(originalRecorded) {
			t.Fatal("archive replay changed immutable row identity/time")
		}
	})
	t.Run("resealed_compact_root_refused", func(t *testing.T) {
		bad := evidence
		bad.WitnessRootSHA256 = strings.Repeat("a", 64)
		bad.ID = ""
		bad.ID = portfolio.Hash(bad)
		decision040ExpectedSQL(t, repository.PublishArchiveEvidence(ctx, registration, bad, rawReview), "archive exact native root differs")
	})
	t.Run("resealed_object_order_and_heads_refused", func(t *testing.T) {
		for _, name := range []string{"object_order", "heads"} {
			t.Run(name, func(t *testing.T) {
				changed := review
				changed.Objects = append([]portfolio.DecisionOwnershipArchiveObjectPin{}, review.Objects...)
				changed.Heads = append([]portfolio.DecisionOwnershipHead{}, review.Heads...)
				bad := evidence
				expected := "archive complete reviewed heads differ"
				if name == "object_order" {
					changed.Objects[0], changed.Objects[1] = changed.Objects[1], changed.Objects[0]
					var root bytes.Buffer
					for _, pin := range changed.Objects {
						object := reader.objects[pin.Key+"\x00"+pin.VersionID]
						witness := portfolio.DecisionOwnershipArchiveWitness{TenantID: f.tenant, SourceRegistrationSHA256: registration.IssuedDocumentSHA256, AccountID: registration.AccountID, BucketOwner: registration.BucketOwner, Bucket: registration.Bucket, Region: registration.Region, Pin: pin, NativeLastModified: object.LastModified, NativeTimeResolutionSeconds: 1}
						id := portfolio.Hash(witness)
						root.Write(decision040JSON(t, map[string]string{"id": id, "kind": "AWS_OWNERSHIP_ARCHIVE_OBJECT", "sha256": id}))
						root.WriteByte('\n')
					}
					bad.WitnessRootSHA256 = source.BytesHash(root.Bytes())
					expected = "archive reviewed slice origin differs"
				} else {
					changed.Heads[0].Count = 1
					bad.Heads = changed.Heads
				}
				message, err := portfolio.DecisionOwnershipArchiveReviewSigningBytes(changed)
				if err != nil {
					t.Fatal(err)
				}
				raw := decision040JSON(t, portfolio.DecisionOwnershipArchiveReviewEnvelope{Review: changed, Algorithm: "Ed25519/commitment-ownership-archive-review/v1", Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(reviewerPrivate, message))})
				bad.ReviewSHA256 = source.BytesHash(raw)
				bad.ID = ""
				bad.ID = portfolio.Hash(bad)
				decision040ExpectedSQL(t, repository.PublishArchiveEvidence(ctx, registration, bad, raw), expected)
			})
		}
	})
	t.Run("readback_mismatch_cannot_issue_witness", func(t *testing.T) {
		app.corruptRead = true
		defer func() { app.corruptRead = false }()
		_, err := storage.Witness(ctx, f.tenant, registration.ID, []byte("explicit readback failure component"))
		if err == nil {
			t.Fatal("changed immutable object readback admitted")
		}
	})
	t.Run("roles_and_foreign_tenant", func(t *testing.T) {
		_, err := decisionArchiveResolve(ctx, analyst, f.tenant+"-foreign", scope.WorkloadID, ref, period)
		if err == nil {
			t.Fatal("same analyst credential resolved foreign tenant")
		}
		if err = analyst.Do(ctx, f.tenant+"-foreign", func(tx *store.Tx) error {
			return tx.QueryRow(ctx, "SELECT count(*) FROM commitment_ownership_archive_evidence WHERE id=$1", evidence.ID).Scan(&count)
		}); err != nil || count != 0 {
			t.Fatal("foreign tenant RLS exposed archive evidence", err)
		}
		for _, db := range []*store.Store{f.roles["api"], ingester} {
			_, err = decisionArchiveResolve(ctx, db, f.tenant, scope.WorkloadID, ref, period)
			var pg *pgconn.PgError
			if !errors.As(err, &pg) || pg.Code != "42501" {
				t.Fatal("ungranted role reached analytical union", err)
			}
		}
		err = analyst.Do(ctx, f.tenant, func(tx *store.Tx) error {
			_, err := tx.Exec(ctx, "SELECT raw_envelope FROM commitment_ownership_archive_witnesses LIMIT 1")
			return err
		})
		var pg *pgconn.PgError
		if !errors.As(err, &pg) || pg.Code != "42501" {
			t.Fatal("analyst acquired original raw witness table access", err)
		}
		err = ingester.Do(ctx, f.tenant, func(tx *store.Tx) error {
			_, err := tx.Exec(ctx, "INSERT INTO commitment_ownership_archive_sources(tenant_id,id,revision,document,content_hash) VALUES($1,'forbidden',1,'{}','')", f.tenant)
			return err
		})
		if !errors.As(err, &pg) || pg.Code != "42501" {
			t.Fatal("ingester acquired operator commissioning writes", err)
		}
	})
	t.Run("changed_mapping_and_revocations_refuse_currentness", func(t *testing.T) {
		for _, change := range []string{"mapping", "source_revoke", "reviewer_revoke"} {
			t.Run(change, func(t *testing.T) {
				err := decisionArchiveChanged(t, ctx, admin, analyst, f.tenant, scope.WorkloadID, ref, period, func(tx pgx.Tx) error {
					switch change {
					case "source_revoke":
						_, err := tx.Exec(ctx, "INSERT INTO commitment_ownership_archive_revocations(tenant_id,id,revision,reason_code) VALUES($1,$2,1,'COMPONENT_REVOKED')", f.tenant, registration.ID)
						return err
					case "reviewer_revoke":
						_, err := tx.Exec(ctx, "INSERT INTO commitment_ownership_revocations(tenant_id,registration_id,revision,reason_code) VALUES($1,$2,1,'COMPONENT_REVOKED')", f.tenant, reviewer.ID)
						return err
					default:
						changed := registration
						changed.Revision = 2
						changed.ExternalResources = append([]portfolio.DecisionOwnershipArchiveResourceMapping{}, registration.ExternalResources...)
						changed.ExternalResources[0].ExternalResource.RepositoryURI = "https://github.com/foreign/customer-infrastructure"
						_, err := tx.Exec(ctx, "INSERT INTO commitment_ownership_archive_sources(tenant_id,id,revision,document,content_hash) VALUES($1,$2,2,$3,'')", f.tenant, registration.ID, decision040JSON(t, changed))
						return err
					}
				})
				var pg *pgconn.PgError
				if !errors.As(err, &pg) || pg.Code != "P0001" {
					t.Fatal("changed actual source/key mapping was not refused by currentness", err)
				}
				if _, err = decisionArchiveResolve(ctx, analyst, f.tenant, scope.WorkloadID, ref, period); err != nil {
					t.Fatal("rollback mutation leaked into immutable archive evidence", err)
				}
			})
		}
	})
	t.Run("uncached_witness_insert_reconciles_exact_concurrent_row_and_refuses_changed_native_time", func(t *testing.T) {
		pin := review.Objects[0]
		object := reader.objects[pin.Key+"\x00"+pin.VersionID]
		witness := portfolio.DecisionOwnershipArchiveWitness{TenantID: f.tenant, SourceRegistrationSHA256: registration.IssuedDocumentSHA256, AccountID: registration.AccountID, BucketOwner: registration.BucketOwner, Bucket: registration.Bucket, Region: registration.Region, Pin: pin, NativeLastModified: object.LastModified, NativeTimeResolutionSeconds: 1}
		id := portfolio.Hash(witness)
		var before time.Time
		if err := admin.Pool.QueryRow(ctx, "SELECT server_recorded_at FROM commitment_ownership_archive_witnesses WHERE tenant_id=$1 AND id=$2", f.tenant, id).Scan(&before); err != nil {
			t.Fatal("original witness absent", err)
		}
		// Models a row committed after a request-local page reported a miss.
		// No speculative SELECT precedes the guarded insert; the existing row,
		// raw bytes, digest and original DB receipt time must remain exact.
		ref, err := repository.PersistArchiveWitness(ctx, registration, witness, object.Data)
		if err != nil || ref.ID != id || ref.SHA256 != id || ref.Kind != "AWS_OWNERSHIP_ARCHIVE_OBJECT" {
			t.Fatal("uncached exact witness reconciliation failed", err)
		}
		var after time.Time
		var rows int
		if err = admin.Pool.QueryRow(ctx, "SELECT server_recorded_at FROM commitment_ownership_archive_witnesses WHERE tenant_id=$1 AND id=$2", f.tenant, id).Scan(&after); err != nil || !before.Equal(after) {
			t.Fatal("uncached replay changed original witness time", err)
		}
		if err = admin.Pool.QueryRow(ctx, "SELECT count(*) FROM commitment_ownership_archive_witnesses WHERE tenant_id=$1 AND source_id=$2", f.tenant, registration.ID).Scan(&rows); err != nil || rows != 2 {
			t.Fatal("uncached replay duplicated a native version", err)
		}
		changed := witness
		changed.NativeLastModified = changed.NativeLastModified.Add(time.Second)
		_, err = repository.PersistArchiveWitness(ctx, registration, changed, object.Data)
		var pg *pgconn.PgError
		if !errors.As(err, &pg) || pg.Code != "23505" {
			t.Fatal("same original version acquired a different native time", err)
		}
	})
	t.Run("uncached_conflict_still_rechecks_revoked_source_before_returning_existing_ref", func(t *testing.T) {
		pin := review.Objects[0]
		object := reader.objects[pin.Key+"\x00"+pin.VersionID]
		witness := portfolio.DecisionOwnershipArchiveWitness{TenantID: f.tenant, SourceRegistrationSHA256: registration.IssuedDocumentSHA256, AccountID: registration.AccountID, BucketOwner: registration.BucketOwner, Bucket: registration.Bucket, Region: registration.Region, Pin: pin, NativeLastModified: object.LastModified, NativeTimeResolutionSeconds: 1}
		if _, err := admin.Pool.Exec(ctx, "INSERT INTO commitment_ownership_archive_revocations(tenant_id,id,revision,reason_code) VALUES($1,$2,1,'COMPONENT_FINAL_REVOKED')", f.tenant, registration.ID); err != nil {
			t.Fatal("component source revocation failed", err)
		}
		_, err := repository.PersistArchiveWitness(ctx, registration, witness, object.Data)
		var pg *pgconn.PgError
		if !errors.As(err, &pg) || pg.Code != "P0001" {
			t.Fatal("ON CONFLICT returned an existing witness after source revocation", err)
		}
		var rows int
		if err = admin.Pool.QueryRow(ctx, "SELECT count(*) FROM commitment_ownership_archive_witnesses WHERE tenant_id=$1 AND source_id=$2", f.tenant, registration.ID).Scan(&rows); err != nil || rows != 2 {
			t.Fatal("source revocation changed historical witness population", err)
		}
	})
	t.Log("ARCHIVE_COMPONENT: actual restricted ingester LOGIN/RLS, present-time operator/reviewer commission, two signed historical-interval transport doubles, actual immutable write/readback, native-issued witness cache/root/heads publication, scoped analyst resolution/replay and current mapping/revocation controls; no live journal/backfill/native-history/forecast/purchase claim")
}
