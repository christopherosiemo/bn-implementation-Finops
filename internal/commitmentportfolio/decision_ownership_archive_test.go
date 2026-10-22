package commitmentportfolio

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
)

// Explicit native-transport doubles. Only the source collector can issue real
// version/time receipts; these unit responses do not establish native acceptance.
type archiveTestReader struct {
	reg             DecisionOwnershipArchiveRegistration
	reviewer        DecisionOwnershipRegistration
	bucket          map[string]any
	objects         map[string]provider.BillingObject
	reads           int
	changeAfterRead bool
}

func (f *archiveTestReader) ArchiveRegistration(context.Context, string) (DecisionOwnershipArchiveRegistration, error) {
	r := f.reg
	if f.changeAfterRead && f.reads > 0 {
		r.Revision++
	}
	return r, nil
}
func (f *archiveTestReader) ArchiveReviewRegistration(context.Context, string) (DecisionOwnershipRegistration, error) {
	return f.reviewer, nil
}
func (f *archiveTestReader) ArchiveBucket(context.Context, DecisionOwnershipArchiveRegistration) (map[string]any, error) {
	return f.bucket, nil
}
func (f *archiveTestReader) ArchiveObject(_ context.Context, _ DecisionOwnershipArchiveRegistration, p DecisionOwnershipArchiveObjectPin) (provider.BillingObject, error) {
	f.reads++
	o, ok := f.objects[p.Key]
	if !ok {
		return o, errors.New("missing original version")
	}
	return o, nil
}

func (f *archiveTestReader) PersistArchiveWitness(_ context.Context, _ DecisionOwnershipArchiveRegistration, w DecisionOwnershipArchiveWitness, _ []byte) (Ref, error) {
	return Ref{Kind: "AWS_OWNERSHIP_ARCHIVE_OBJECT", ID: Hash(w), SHA256: Hash(w)}, nil
}

func archiveFixture(t *testing.T) (*archiveTestReader, DecisionOwnershipQuery, DecisionOwnershipArchiveReviewEnvelope, ed25519.PrivateKey, time.Time) {
	t.Helper()
	now := time.Date(2026, 10, 19, 20, 0, 0, 0, time.UTC)
	resource := DecisionOwnershipResource{ResourceID: "archive-resource", ProviderResourceID: "i-0123456789abcdef0", AccountID: "111122223333", Region: "eu-west-1", RepositoryID: "archive-authority", GitCommit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ConfigurationSHA256: Hash("archived-config"), StateLineage: "archive-lineage"}
	external := DecisionOwnershipArchiveExternalResource{CustomerWorkloadID: "customer-payments", AccountID: resource.AccountID, Region: resource.Region, ProviderID: resource.ProviderResourceID, RepositoryURI: "https://github.com/customer/infrastructure", GitCommit: resource.GitCommit, ConfigurationSHA256: resource.ConfigurationSHA256, TerraformAddress: "aws_instance.payments", StateLineage: resource.StateLineage}
	scope := DecisionOwnershipScope{TenantID: "archive-tenant", WorkloadID: "archive-workload", Resources: []DecisionOwnershipResource{resource}}
	scope.ConfigurationSHA256 = DecisionOwnershipConfigurationSHA256(scope.Resources)
	query := DecisionOwnershipQuery{Scope: scope, Period: Period{Start: now.Add(-365 * 24 * time.Hour), End: now.Add(-365*24*time.Hour + 2*time.Hour)}}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	reviewPub, reviewPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	policy := map[string]any{"Version": "2012-10-17", "Statement": []any{map[string]any{"Effect": "Allow", "Principal": map[string]any{"AWS": "arn:aws:iam::111122223333:role/archive-writer"}, "Action": "s3:PutObject", "Resource": "arn:aws:s3:::archive-bucket/tenant/archive-tenant/*"}}}
	f := &archiveTestReader{reg: DecisionOwnershipArchiveRegistration{ID: "archive-source", Revision: 1, ScopeSHA256: Hash(scope), TenantID: scope.TenantID, AccountID: resource.AccountID, BucketOwner: resource.AccountID, Bucket: "archive-bucket", Prefix: "tenant/archive-tenant/", Region: "eu-west-1", ReadRoleBinding: Ref{Kind: "APPROVED_READ_ROLE_BINDING", ID: "archive-read", SHA256: Hash("read-binding")}, CurrentBucketPolicySHA256: Hash(policy), SignerKeyID: "archive-customer-key", SignerPublicKey: pub, SignerCustodianIssuer: "https://customer.invalid", SignerCustodianSubject: "deploy-writer", ValidUntil: now.Add(time.Hour)}, reviewer: DecisionOwnershipRegistration{ID: "archive-independent-reviewer", Revision: 1, ScopeSHA256: Hash(scope), Purpose: "OWNERSHIP_REVIEW", Issuer: "https://customer.invalid", Subject: "independent-reviewer", Audience: "finops-deployment-observer", PublicKey: reviewPub, ValidFrom: now.Add(-time.Hour), ValidUntil: now.Add(time.Hour), IssuedDocumentSHA256: Hash("actual-issued-review-registration")}, bucket: map[string]any{"versioning": "Enabled", "region": "eu-west-1", "bucket_owner": resource.AccountID, "policy": policy}, objects: map[string]provider.BillingObject{}}
	f.reg.IssuedDocumentSHA256 = Hash(f.reg)
	// Existing customer prefixes and signed identities predate platform tenant,
	// workload, resource and authority IDs; only today's registry maps those IDs.
	f.reg.Prefix = "customer-audit/deployments/"
	f.reg.CustomerNamespace = "customer-infra"
	f.reg.ExternalResources = []DecisionOwnershipArchiveResourceMapping{{ResourceID: resource.ResourceID, ExternalResource: external}}
	f.reg.IssuedDocumentSHA256 = Hash(f.reg)
	r := DecisionOwnershipArchiveReview{SchemaVersion: "1", ID: "archive-review", Query: query, SourceRegistrationSHA256: f.reg.IssuedDocumentSHA256, SignerPublicKeySHA256: ownershipBytesHash(pub), Objects: []DecisionOwnershipArchiveObjectPin{}, Heads: []DecisionOwnershipHead{}, ReviewerRegistrationID: f.reviewer.ID, ReviewerRegistrationRevision: 1, SignedAt: now}
	head := DecisionOwnershipHead{ResourceID: resource.ResourceID, FirstSequence: 1}
	previous := ""
	for i := 0; i < 2; i++ {
		config, _ := json.Marshal(DecisionOwnershipArchiveConfiguration{ExternalResource: external, StateSerial: 42, ConfigurationBundleSHA256: Hash("retained-customer-config-bundle")})
		deployment, _ := json.Marshal(DecisionOwnershipArchiveDeployment{ExternalResource: external, StateSerial: 42, ConfigurationDocumentSHA256: ownershipBytesHash(config), Revision: resource.GitCommit, Result: "SUCCEEDED", CompletedAt: query.Period.Start.Add(-time.Hour)})
		start := query.Period.Start.Add(time.Duration(i) * time.Hour)
		claim := DecisionOwnershipArchiveClaim{SchemaVersion: "1", ID: []string{"archive-hour-one", "archive-hour-two"}[i], CustomerNamespace: f.reg.CustomerNamespace, SignerKeyID: f.reg.SignerKeyID, ExternalResource: external, Period: Period{Start: start, End: start.Add(time.Hour)}, StateSerial: 42, Sequence: uint64(i + 1), PreviousSHA256: previous, ConfigurationDocument: config, DeploymentDocument: deployment, SignedAt: start.Add(time.Hour)}
		message, e := DecisionOwnershipArchiveSigningBytes(claim)
		if e != nil {
			t.Fatal(e)
		}
		body, e := json.Marshal(DecisionOwnershipArchiveEnvelope{Claim: claim, Algorithm: ownershipArchiveAlgorithm, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, message))})
		if e != nil {
			t.Fatal(e)
		}
		key := f.reg.Prefix + claim.ID + ".json"
		pin := DecisionOwnershipArchiveObjectPin{Key: key, VersionID: "original-version-" + claim.ID, SHA256: ownershipBytesHash(body), Bytes: int64(len(body))}
		f.objects[key] = provider.BillingObject{Key: key, VersionID: pin.VersionID, LastModified: claim.Period.End.Add(time.Minute), Data: body}
		r.Objects = append(r.Objects, pin)
		if i == 0 {
			head.FirstSHA256 = pin.SHA256
		}
		head.Count++
		head.LastSequence = claim.Sequence
		head.LastSHA256 = pin.SHA256
		previous = pin.SHA256
	}
	r.Heads = append(r.Heads, head)
	return f, query, DecisionOwnershipArchiveReviewEnvelope{Review: r, Algorithm: "Ed25519/commitment-ownership-archive-review/v1"}, reviewPriv, now
}
func signArchiveReview(t *testing.T, e DecisionOwnershipArchiveReviewEnvelope, key ed25519.PrivateKey) []byte {
	t.Helper()
	message, err := DecisionOwnershipArchiveReviewSigningBytes(e.Review)
	if err != nil {
		t.Fatal(err)
	}
	e.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, message))
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestDecisionOwnershipArchiveOriginalVersionWitnessAndCurrentReview(t *testing.T) {
	f, q, r, key, now := archiveFixture(t)
	raw := signArchiveReview(t, r, key)
	proof, err := VerifyDecisionOwnershipArchive(context.Background(), f, f.reg.ID, raw, q, now)
	if err != nil || proof.Basis != DecisionOwnershipArchiveBasis || proof.WitnessCount != 2 || !shaPattern.MatchString(proof.WitnessRootSHA256) || len(proof.Heads) != 1 || proof.ExecutionAuthorized || proof.VerifiedSaving != nil {
		t.Fatal("supported original customer archive unavailable", err)
	}
	if !proof.Query.Period.End.Before(now.Add(-300*24*time.Hour)) || !proof.ObservedAt.Equal(now) {
		t.Fatal("native historical time and present receipt time were confused")
	}
	copy := proof
	copy.ID = ""
	if proof.ID != Hash(copy) {
		t.Fatal("archive proof identity changed")
	}
}

func TestDecisionOwnershipArchivePredatesPlatformIdentityWithoutRewritingHistory(t *testing.T) {
	f, q, r, key, now := archiveFixture(t)
	original := map[string][]byte{}
	for k, o := range f.objects {
		original[k] = append([]byte(nil), o.Data...)
		for _, platform := range []string{q.Scope.TenantID, q.Scope.WorkloadID, q.Scope.Resources[0].ResourceID, q.Scope.Resources[0].RepositoryID} {
			if bytes.Contains(o.Data, []byte(platform)) {
				t.Fatal("historical bytes contain platform identity")
			}
		}
	}
	// A new independently commissioned onboarding maps the same pre-existing
	// customer tuple; only today's registry/review changes, never historic bytes.
	q.Scope.TenantID = "new-platform-tenant"
	q.Scope.WorkloadID = "new-platform-workload"
	q.Scope.Resources[0].ResourceID = "new-platform-resource"
	q.Scope.Resources[0].RepositoryID = "new-platform-authority"
	q.Scope.ConfigurationSHA256 = DecisionOwnershipConfigurationSHA256(q.Scope.Resources)
	f.reg.TenantID = q.Scope.TenantID
	f.reg.ScopeSHA256 = Hash(q.Scope)
	f.reg.ExternalResources[0].ResourceID = q.Scope.Resources[0].ResourceID
	f.reg.IssuedDocumentSHA256 = Hash(f.reg)
	f.reviewer.ScopeSHA256 = Hash(q.Scope)
	r.Review.Query = q
	r.Review.SourceRegistrationSHA256 = f.reg.IssuedDocumentSHA256
	r.Review.Heads[0].ResourceID = q.Scope.Resources[0].ResourceID
	proof, err := VerifyDecisionOwnershipArchive(context.Background(), f, f.reg.ID, signArchiveReview(t, r, key), q, now)
	if err != nil || proof.Heads[0].ResourceID != q.Scope.Resources[0].ResourceID {
		t.Fatal("pre-onboarding external identity not resolved", err)
	}
	for k, o := range f.objects {
		if !bytes.Equal(original[k], o.Data) {
			t.Fatal("historical bytes were rewritten")
		}
	}
}

func TestDecisionOwnershipArchiveRefusesBackfillForeignSourcesAndAlteredVersions(t *testing.T) {
	cases := map[string]func(*archiveTestReader, *DecisionOwnershipQuery, *DecisionOwnershipArchiveReviewEnvelope, time.Time){
		"today-reupload": func(f *archiveTestReader, _ *DecisionOwnershipQuery, r *DecisionOwnershipArchiveReviewEnvelope, n time.Time) {
			p := r.Review.Objects[0]
			o := f.objects[p.Key]
			o.LastModified = n
			f.objects[p.Key] = o
		},
		"altered-body": func(f *archiveTestReader, _ *DecisionOwnershipQuery, r *DecisionOwnershipArchiveReviewEnvelope, _ time.Time) {
			p := r.Review.Objects[0]
			o := f.objects[p.Key]
			o.Data = append(o.Data, ' ')
			f.objects[p.Key] = o
		},
		"changed-version": func(f *archiveTestReader, _ *DecisionOwnershipQuery, r *DecisionOwnershipArchiveReviewEnvelope, _ time.Time) {
			p := r.Review.Objects[0]
			o := f.objects[p.Key]
			o.VersionID = "replacement"
			f.objects[p.Key] = o
		},
		"missing-object": func(f *archiveTestReader, _ *DecisionOwnershipQuery, r *DecisionOwnershipArchiveReviewEnvelope, _ time.Time) {
			delete(f.objects, r.Review.Objects[0].Key)
		},
		"duplicate-object": func(_ *archiveTestReader, _ *DecisionOwnershipQuery, r *DecisionOwnershipArchiveReviewEnvelope, _ time.Time) {
			r.Review.Objects[1] = r.Review.Objects[0]
		},
		"gap": func(_ *archiveTestReader, _ *DecisionOwnershipQuery, r *DecisionOwnershipArchiveReviewEnvelope, _ time.Time) {
			r.Review.Objects = r.Review.Objects[1:]
		},
		"foreign-tenant": func(_ *archiveTestReader, q *DecisionOwnershipQuery, _ *DecisionOwnershipArchiveReviewEnvelope, _ time.Time) {
			q.Scope.TenantID = "foreign-tenant"
		},
		"wrong-external-identity": func(f *archiveTestReader, _ *DecisionOwnershipQuery, _ *DecisionOwnershipArchiveReviewEnvelope, _ time.Time) {
			f.reg.ExternalResources[0].ExternalResource.ProviderID = "i-0ffffffffffffffff"
		},
		"unmapped-external-repository": func(f *archiveTestReader, _ *DecisionOwnershipQuery, _ *DecisionOwnershipArchiveReviewEnvelope, _ time.Time) {
			f.reg.ExternalResources[0].ExternalResource.RepositoryURI = "https://github.com/other/infrastructure"
		},
		"credential-in-external-repository": func(f *archiveTestReader, _ *DecisionOwnershipQuery, _ *DecisionOwnershipArchiveReviewEnvelope, _ time.Time) {
			f.reg.ExternalResources[0].ExternalResource.RepositoryURI = "https://user:secret@github.com/customer/infrastructure"
		},
		"unsafe-native-prefix": func(f *archiveTestReader, _ *DecisionOwnershipQuery, _ *DecisionOwnershipArchiveReviewEnvelope, _ time.Time) {
			f.reg.Prefix = "../other/"
		},
		"external-namespace-confusion": func(f *archiveTestReader, _ *DecisionOwnershipQuery, _ *DecisionOwnershipArchiveReviewEnvelope, _ time.Time) {
			f.reg.CustomerNamespace = "other-customer"
		},
		"wrong-owner": func(f *archiveTestReader, _ *DecisionOwnershipQuery, _ *DecisionOwnershipArchiveReviewEnvelope, _ time.Time) {
			f.bucket["bucket_owner"] = "999988887777"
		},
		"non-eu-storage": func(f *archiveTestReader, _ *DecisionOwnershipQuery, _ *DecisionOwnershipArchiveReviewEnvelope, _ time.Time) {
			f.bucket["region"] = "us-east-1"
		},
		"versioning-disabled": func(f *archiveTestReader, _ *DecisionOwnershipQuery, _ *DecisionOwnershipArchiveReviewEnvelope, _ time.Time) {
			f.bucket["versioning"] = "Suspended"
		},
		"policy-changed": func(f *archiveTestReader, _ *DecisionOwnershipQuery, _ *DecisionOwnershipArchiveReviewEnvelope, _ time.Time) {
			f.bucket["policy"] = map[string]any{"Principal": "*"}
		},
		"source-revoked": func(f *archiveTestReader, _ *DecisionOwnershipQuery, _ *DecisionOwnershipArchiveReviewEnvelope, n time.Time) {
			f.reg.RevokedAt = &n
		},
		"revocation-race": func(f *archiveTestReader, _ *DecisionOwnershipQuery, _ *DecisionOwnershipArchiveReviewEnvelope, _ time.Time) {
			f.changeAfterRead = true
		},
		"same-custodian": func(f *archiveTestReader, _ *DecisionOwnershipQuery, r *DecisionOwnershipArchiveReviewEnvelope, _ time.Time) {
			f.reg.SignerCustodianSubject = f.reviewer.Subject
			r.Review.SourceRegistrationSHA256 = f.reg.IssuedDocumentSHA256
		},
		"stale-current-review": func(_ *archiveTestReader, _ *DecisionOwnershipQuery, r *DecisionOwnershipArchiveReviewEnvelope, n time.Time) {
			r.Review.SignedAt = n.Add(-25 * time.Hour)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f, q, r, key, now := archiveFixture(t)
			mutate(f, &q, &r, now)
			raw := signArchiveReview(t, r, key)
			if _, err := VerifyDecisionOwnershipArchive(context.Background(), f, f.reg.ID, raw, q, now); err == nil {
				t.Fatal("unsupported archive accepted")
			}
		})
	}
}
