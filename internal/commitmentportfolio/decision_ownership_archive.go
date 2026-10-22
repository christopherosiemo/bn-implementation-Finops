package commitmentportfolio

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
)

// Historical import is a separate protocol. Native S3 version creation times
// witness when the signed customer claims existed; they do not turn customer
// claims into native AWS configuration history or previously received ingress.
const DecisionOwnershipArchiveBasis = "CUSTOMER_SIGNED_ARCHIVE_NATIVE_VERSION_WITNESS"
const ownershipArchiveAlgorithm = "Ed25519/commitment-ownership-archive/v1"
const ownershipArchiveDomain = "finops/commitment-ownership/archive/v1\x00"
const ownershipArchiveMaxObjects = 100000
const ownershipArchiveMaxBytes = 128 << 20

// Private operator/source-registry projection. The public console cannot submit
// this structure or set a historical valid_from. Signing-key custody and the
// interpretation of customer deployment claims remain customer trust boundaries.
type DecisionOwnershipArchiveRegistration struct {
	ID                        string                                    `json:"id"`
	IssuedDocumentSHA256      string                                    `json:"-"`
	Revision                  int64                                     `json:"revision"`
	ScopeSHA256               string                                    `json:"scope_sha256"`
	CustomerNamespace         string                                    `json:"customer_namespace"`
	ExternalResources         []DecisionOwnershipArchiveResourceMapping `json:"external_resources"`
	TenantID                  string                                    `json:"tenant_id"`
	AccountID                 string                                    `json:"account_id"`
	BucketOwner               string                                    `json:"bucket_owner"`
	Bucket                    string                                    `json:"bucket"`
	Prefix                    string                                    `json:"prefix"`
	Region                    string                                    `json:"region"`
	ReadRoleBinding           Ref                                       `json:"read_role_binding"`
	CurrentBucketPolicySHA256 string                                    `json:"current_bucket_policy_sha256"`
	SignerKeyID               string                                    `json:"signer_key_id"`
	SignerPublicKey           []byte                                    `json:"signer_public_key"`
	// Current operator-approved custodian; this does not attest historic OIDC.
	SignerCustodianIssuer  string     `json:"signer_custodian_issuer"`
	SignerCustodianSubject string     `json:"signer_custodian_subject"`
	ValidUntil             time.Time  `json:"valid_until"`
	RevokedAt              *time.Time `json:"revoked_at"`
}

// Pins are supplied by an authenticated current independent review and resolved
// by the ingestion identity, never interpreted as caller-proven S3 metadata.
type DecisionOwnershipArchiveObjectPin struct {
	Key       string `json:"key"`
	VersionID string `json:"version_id"`
	SHA256    string `json:"sha256"`
	Bytes     int64  `json:"bytes"`
}

type DecisionOwnershipArchiveClaim struct {
	SchemaVersion     string                                   `json:"schema_version"`
	ID                string                                   `json:"id"`
	CustomerNamespace string                                   `json:"customer_namespace"`
	SignerKeyID       string                                   `json:"signer_key_id"`
	ExternalResource  DecisionOwnershipArchiveExternalResource `json:"external_resource"`
	Period            Period                                   `json:"period"`
	StateSerial       uint64                                   `json:"state_serial"`
	Sequence          uint64                                   `json:"sequence"`
	PreviousSHA256    string                                   `json:"previous_sha256"`
	// Hashes bind the exact historical customer deployment/configuration records
	// retained in the signed envelope; they are not newly issued API receipts.
	ConfigurationDocument json.RawMessage `json:"configuration_document"`
	DeploymentDocument    json.RawMessage `json:"deployment_document"`
	SignedAt              time.Time       `json:"signed_at"`
}

// These identifiers existed in the customer's system before onboarding. A
// historical signature must never require newly allocated platform IDs. The
// current independently approved registration maps the external tuple to today's
// tenant/workload/resource/authority scope without rewriting original bytes.
type DecisionOwnershipArchiveExternalResource struct {
	CustomerWorkloadID  string `json:"customer_workload_id"`
	AccountID           string `json:"account_id"`
	Region              string `json:"region"`
	ProviderID          string `json:"provider_id"`
	RepositoryURI       string `json:"repository_uri"`
	GitCommit           string `json:"git_commit"`
	ConfigurationSHA256 string `json:"configuration_sha256"`
	TerraformAddress    string `json:"terraform_address"`
	StateLineage        string `json:"state_lineage"`
}
type DecisionOwnershipArchiveResourceMapping struct {
	ResourceID       string                                   `json:"resource_id"`
	ExternalResource DecisionOwnershipArchiveExternalResource `json:"external_resource"`
}

type DecisionOwnershipArchiveEnvelope struct {
	Claim     DecisionOwnershipArchiveClaim `json:"claim"`
	Algorithm string                        `json:"algorithm"`
	Signature string                        `json:"signature"`
}

// Minimal sanitized historical records. Full state/plan material is deliberately
// excluded here because it can contain secrets. A customer archive claims exact
// binding and hashes, not an executable or newly attested Terraform plan.
type DecisionOwnershipArchiveConfiguration struct {
	ExternalResource          DecisionOwnershipArchiveExternalResource `json:"external_resource"`
	StateSerial               uint64                                   `json:"state_serial"`
	ConfigurationBundleSHA256 string                                   `json:"configuration_bundle_sha256"`
}

type DecisionOwnershipArchiveDeployment struct {
	ExternalResource            DecisionOwnershipArchiveExternalResource `json:"external_resource"`
	StateSerial                 uint64                                   `json:"state_serial"`
	ConfigurationDocumentSHA256 string                                   `json:"configuration_document_sha256"`
	Revision                    string                                   `json:"revision"`
	Result                      string                                   `json:"result"`
	CompletedAt                 time.Time                                `json:"completed_at"`
}

type DecisionOwnershipArchiveReview struct {
	SchemaVersion                string                              `json:"schema_version"`
	ID                           string                              `json:"id"`
	Query                        DecisionOwnershipQuery              `json:"query"`
	SourceRegistrationSHA256     string                              `json:"source_registration_sha256"`
	SignerPublicKeySHA256        string                              `json:"signer_public_key_sha256"`
	Objects                      []DecisionOwnershipArchiveObjectPin `json:"objects"`
	Heads                        []DecisionOwnershipHead             `json:"heads"`
	ReviewerRegistrationID       string                              `json:"reviewer_registration_id"`
	ReviewerRegistrationRevision int64                               `json:"reviewer_registration_revision"`
	SignedAt                     time.Time                           `json:"signed_at"`
}

type DecisionOwnershipArchiveReviewEnvelope struct {
	Review    DecisionOwnershipArchiveReview `json:"review"`
	Algorithm string                         `json:"algorithm"`
	Signature string                         `json:"signature"`
}

type DecisionOwnershipArchiveWitness struct {
	TenantID                    string                            `json:"tenant_id"`
	SourceRegistrationSHA256    string                            `json:"source_registration_sha256"`
	AccountID                   string                            `json:"account_id"`
	BucketOwner                 string                            `json:"bucket_owner"`
	Bucket                      string                            `json:"bucket"`
	Region                      string                            `json:"region"`
	Pin                         DecisionOwnershipArchiveObjectPin `json:"pin"`
	NativeLastModified          time.Time                         `json:"native_last_modified"`
	NativeTimeResolutionSeconds int                               `json:"native_time_resolution_seconds"`
}

type DecisionOwnershipArchiveEvidence struct {
	SchemaVersion              string                  `json:"schema_version"`
	ID                         string                  `json:"id"`
	Basis                      string                  `json:"basis"`
	Query                      DecisionOwnershipQuery  `json:"query"`
	RegistrationSHA256         string                  `json:"registration_sha256"`
	ReviewerRegistrationSHA256 string                  `json:"reviewer_registration_sha256"`
	ReviewSHA256               string                  `json:"review_sha256"`
	Heads                      []DecisionOwnershipHead `json:"heads"`
	WitnessCount               int                     `json:"witness_count"`
	WitnessRootSHA256          string                  `json:"witness_root_sha256"`
	ObservedAt                 time.Time               `json:"observed_at"`
	ExecutionAuthorized        bool                    `json:"execution_authorized"`
	VerifiedSaving             *string                 `json:"verified_saving"`
}

// Implemented only by the source-ingestion process using a registered read role.
// An analyst must consume persisted readback receipts, never receive AWS creds.
// BucketDocument is a native ExpectedBucketOwner/region/versioning/policy read.
type DecisionOwnershipArchiveReader interface {
	ArchiveRegistration(context.Context, string) (DecisionOwnershipArchiveRegistration, error)
	ArchiveReviewRegistration(context.Context, string) (DecisionOwnershipRegistration, error)
	ArchiveBucket(context.Context, DecisionOwnershipArchiveRegistration) (map[string]any, error)
	ArchiveObject(context.Context, DecisionOwnershipArchiveRegistration, DecisionOwnershipArchiveObjectPin) (provider.BillingObject, error)
	// Raw evidence is archived before the ingester issues the immutable native
	// readback. Interrupted collections can retain rows without an accepted aggregate.
	PersistArchiveWitness(context.Context, DecisionOwnershipArchiveRegistration, DecisionOwnershipArchiveWitness, []byte) (Ref, error)
}

func DecisionOwnershipArchiveSigningBytes(claim DecisionOwnershipArchiveClaim) ([]byte, error) {
	raw, err := json.Marshal(claim)
	if err != nil {
		return nil, err
	}
	return append([]byte(ownershipArchiveDomain), raw...), nil
}
func DecisionOwnershipArchiveReviewSigningBytes(review DecisionOwnershipArchiveReview) ([]byte, error) {
	raw, err := json.Marshal(review)
	if err != nil {
		return nil, err
	}
	return append([]byte("finops/commitment-ownership/archive-review/v1\x00"), raw...), nil
}
func ownershipArchiveRegistrationValid(reg DecisionOwnershipArchiveRegistration, query DecisionOwnershipQuery, now time.Time) bool {
	if !idPattern.MatchString(reg.CustomerNamespace) || len(reg.ExternalResources) != len(query.Scope.Resources) {
		return false
	}
	seen := map[string]bool{}
	for i, m := range reg.ExternalResources {
		e := m.ExternalResource
		r := query.Scope.Resources[i]
		u, err := url.Parse(e.RepositoryURI)
		if m.ResourceID != r.ResourceID || !idPattern.MatchString(e.CustomerWorkloadID) || e.AccountID != r.AccountID || e.AccountID != reg.AccountID || e.Region != r.Region || e.ProviderID != r.ProviderResourceID || e.GitCommit != r.GitCommit || e.ConfigurationSHA256 != r.ConfigurationSHA256 || e.StateLineage != r.StateLineage || e.TerraformAddress == "" || len(e.TerraformAddress) > 1024 || strings.ContainsAny(e.TerraformAddress, "\x00\r\n") || err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || len(e.RepositoryURI) > 2048 || seen[Hash(e)] {
			return false
		}
		seen[Hash(e)] = true
	}
	return idPattern.MatchString(reg.ID) && shaPattern.MatchString(reg.IssuedDocumentSHA256) && reg.Revision > 0 && reg.ScopeSHA256 == Hash(query.Scope) && reg.TenantID == query.Scope.TenantID && ownershipAccount.MatchString(reg.AccountID) && reg.BucketOwner == reg.AccountID && idPattern.MatchString(reg.Bucket) && reg.Prefix != "" && !strings.HasPrefix(reg.Prefix, "/") && strings.HasSuffix(reg.Prefix, "/") && !strings.Contains(reg.Prefix, "//") && !strings.Contains(reg.Prefix, "..") && !strings.ContainsAny(reg.Prefix, "\\\x00\r\n") && len(reg.Prefix) <= 1024 && reg.Region == "eu-west-1" && ownershipRef(reg.ReadRoleBinding, "APPROVED_READ_ROLE_BINDING") && shaPattern.MatchString(reg.CurrentBucketPolicySHA256) && idPattern.MatchString(reg.SignerKeyID) && len(reg.SignerPublicKey) == ed25519.PublicKeySize && reg.SignerCustodianIssuer != "" && len(reg.SignerCustodianIssuer) <= 2048 && reg.SignerCustodianSubject != "" && len(reg.SignerCustodianSubject) <= 256 && reg.RevokedAt == nil && ownershipUTC(reg.ValidUntil) && now.Before(reg.ValidUntil)
}
func archiveBucketMatches(bucket map[string]any, reg DecisionOwnershipArchiveRegistration) bool {
	return bucket["versioning"] == "Enabled" && bucket["region"] == reg.Region && bucket["bucket_owner"] == reg.BucketOwner && Hash(bucket["policy"]) == reg.CurrentBucketPolicySHA256
}

// VerifyDecisionOwnershipArchive never writes live journals or stamps their
// server_recorded_at. Every original version must already have existed within
// five minutes of its claimed interval. Re-uploading old signed claims today
// fails. Current policy is pinned without claiming it proves historical policy.
func VerifyDecisionOwnershipArchive(ctx context.Context, reader DecisionOwnershipArchiveReader, registrationID string, rawReview []byte, query DecisionOwnershipQuery, now time.Time) (DecisionOwnershipArchiveEvidence, error) {
	var out DecisionOwnershipArchiveEvidence
	if reader == nil || !idPattern.MatchString(registrationID) || !ownershipScope(query.Scope) || !ownershipPeriod(query.Period) || !ownershipUTC(now) || query.Period.End.After(now) || query.Period.End.Sub(query.Period.Start) > 5*366*24*time.Hour {
		return out, ErrDecisionOwnershipEvidence
	}
	var review DecisionOwnershipArchiveReviewEnvelope
	if !ownershipCanonical(rawReview, &review, 24<<20) || review.Algorithm != "Ed25519/commitment-ownership-archive-review/v1" {
		return out, ErrDecisionOwnershipEvidence
	}
	reg, err := reader.ArchiveRegistration(ctx, registrationID)
	if err != nil || !ownershipArchiveRegistrationValid(reg, query, now) {
		return out, ErrDecisionOwnershipEvidence
	}
	r := review.Review
	reviewer, err := reader.ArchiveReviewRegistration(ctx, r.ReviewerRegistrationID)
	signing, signErr := DecisionOwnershipArchiveReviewSigningBytes(r)
	if err != nil || signErr != nil || !ownershipRegistration(reviewer, "OWNERSHIP_REVIEW", Hash(query.Scope), now) || reviewer.Revision != r.ReviewerRegistrationRevision || reviewer.ID == reg.SignerKeyID || reviewer.Issuer == reg.SignerCustodianIssuer && reviewer.Subject == reg.SignerCustodianSubject || bytes.Equal(reviewer.PublicKey, reg.SignerPublicKey) || !ownershipSignature(reviewer.PublicKey, signing, review.Signature) || r.SchemaVersion != "1" || !idPattern.MatchString(r.ID) || Hash(r.Query) != Hash(query) || r.SourceRegistrationSHA256 != reg.IssuedDocumentSHA256 || r.SignerPublicKeySHA256 != ownershipBytesHash(reg.SignerPublicKey) || !ownershipUTC(r.SignedAt) || r.SignedAt.Before(query.Period.End) || r.SignedAt.Before(reviewer.ValidFrom) || r.SignedAt.After(now) || now.Sub(r.SignedAt) > 24*time.Hour || len(r.Objects) == 0 || len(r.Objects) > ownershipArchiveMaxObjects || len(r.Heads) != len(query.Scope.Resources) {
		return out, ErrDecisionOwnershipEvidence
	}
	bucket, err := reader.ArchiveBucket(ctx, reg)
	if err != nil || !archiveBucketMatches(bucket, reg) {
		return out, ErrDecisionOwnershipEvidence
	}
	out = DecisionOwnershipArchiveEvidence{SchemaVersion: "1", Basis: DecisionOwnershipArchiveBasis, Query: query, RegistrationSHA256: reg.IssuedDocumentSHA256, ReviewerRegistrationSHA256: reviewer.IssuedDocumentSHA256, ReviewSHA256: ownershipBytesHash(rawReview), Heads: []DecisionOwnershipHead{}, ObservedAt: now.UTC()}
	witnessDigest := sha256.New()
	seen := map[string]bool{}
	var total int64
	resourceIndex := 0
	var head DecisionOwnershipHead
	var end time.Time
	var serial uint64
	finish := func() bool {
		if head.Count == 0 || resourceIndex >= len(query.Scope.Resources) || !end.Equal(query.Period.End) || Hash(head) != Hash(r.Heads[resourceIndex]) {
			return false
		}
		out.Heads = append(out.Heads, head)
		resourceIndex++
		head = DecisionOwnershipHead{}
		return true
	}
	for _, pin := range r.Objects {
		if ctx.Err() != nil {
			return DecisionOwnershipArchiveEvidence{}, ctx.Err()
		}
		key := pin.Key + "\x00" + pin.VersionID
		if !strings.HasPrefix(pin.Key, reg.Prefix) || strings.Contains(pin.Key, "..") || strings.ContainsAny(pin.Key, "\\\x00\r\n") || len(pin.Key) > 2048 || pin.VersionID == "" || pin.VersionID == "null" || len(pin.VersionID) > 1024 || !shaPattern.MatchString(pin.SHA256) || pin.Bytes < 1 || pin.Bytes > 64<<10 || seen[key] || total+pin.Bytes > ownershipArchiveMaxBytes {
			return DecisionOwnershipArchiveEvidence{}, ErrDecisionOwnershipEvidence
		}
		seen[key] = true
		total += pin.Bytes
		object, e := reader.ArchiveObject(ctx, reg, pin)
		if e != nil || object.Key != pin.Key || object.VersionID != pin.VersionID || int64(len(object.Data)) != pin.Bytes || ownershipBytesHash(object.Data) != pin.SHA256 || !ownershipUTC(object.LastModified) || object.LastModified.After(now) || object.LastModified.Nanosecond() != 0 {
			return DecisionOwnershipArchiveEvidence{}, ErrDecisionOwnershipEvidence
		}
		var envelope DecisionOwnershipArchiveEnvelope
		if !ownershipCanonical(object.Data, &envelope, 64<<10) || envelope.Algorithm != ownershipArchiveAlgorithm {
			return DecisionOwnershipArchiveEvidence{}, ErrDecisionOwnershipEvidence
		}
		c := envelope.Claim
		message, e := DecisionOwnershipArchiveSigningBytes(c)
		// S3's HTTP Last-Modified has whole-second resolution. Preserve that
		// interval. Require its lower bound after the claimed signing/interval
		// completion; ambiguous subsecond ordering stays unavailable. Do not extend the five-minute
		// admission budget by accepting an upper bound after its deadline.
		nativeUpper := object.LastModified.Add(time.Second)
		if e != nil || !ownershipSignature(reg.SignerPublicKey, message, envelope.Signature) || c.SchemaVersion != "1" || !idPattern.MatchString(c.ID) || c.CustomerNamespace != reg.CustomerNamespace || c.SignerKeyID != reg.SignerKeyID || !ownershipPeriod(c.Period) || c.Period.Start.Before(query.Period.Start) || c.Period.End.After(query.Period.End) || c.Period.End.Sub(c.Period.Start) > time.Hour || !ownershipUTC(c.SignedAt) || c.SignedAt.Before(c.Period.End) || object.LastModified.Before(c.SignedAt) || nativeUpper.Sub(c.Period.End) > 5*time.Minute || c.Sequence == 0 {
			return DecisionOwnershipArchiveEvidence{}, ErrDecisionOwnershipEvidence
		}
		if resourceIndex >= len(query.Scope.Resources) {
			return DecisionOwnershipArchiveEvidence{}, ErrDecisionOwnershipEvidence
		}
		if head.Count > 0 && Hash(c.ExternalResource) != Hash(reg.ExternalResources[resourceIndex].ExternalResource) {
			if !finish() {
				return DecisionOwnershipArchiveEvidence{}, ErrDecisionOwnershipEvidence
			}
		}
		if resourceIndex >= len(query.Scope.Resources) || Hash(c.ExternalResource) != Hash(reg.ExternalResources[resourceIndex].ExternalResource) {
			return DecisionOwnershipArchiveEvidence{}, ErrDecisionOwnershipEvidence
		}
		var config DecisionOwnershipArchiveConfiguration
		var deployment DecisionOwnershipArchiveDeployment
		if !ownershipCanonical(c.ConfigurationDocument, &config, 16<<10) || !ownershipCanonical(c.DeploymentDocument, &deployment, 16<<10) || Hash(config.ExternalResource) != Hash(c.ExternalResource) || Hash(deployment.ExternalResource) != Hash(c.ExternalResource) || config.StateSerial != c.StateSerial || deployment.StateSerial != c.StateSerial || !shaPattern.MatchString(config.ConfigurationBundleSHA256) || deployment.ConfigurationDocumentSHA256 != ownershipBytesHash(c.ConfigurationDocument) || deployment.Revision != c.ExternalResource.GitCommit || deployment.Result != "SUCCEEDED" || !ownershipUTC(deployment.CompletedAt) || deployment.CompletedAt.After(c.Period.Start) {
			return DecisionOwnershipArchiveEvidence{}, ErrDecisionOwnershipEvidence
		}
		if head.Count == 0 {
			if !c.Period.Start.Equal(query.Period.Start) || c.Sequence == 1 && c.PreviousSHA256 != "" || c.Sequence > 1 && !shaPattern.MatchString(c.PreviousSHA256) {
				return DecisionOwnershipArchiveEvidence{}, ErrDecisionOwnershipEvidence
			}
			head = DecisionOwnershipHead{ResourceID: query.Scope.Resources[resourceIndex].ResourceID, FirstSequence: c.Sequence, FirstSHA256: pin.SHA256}
		} else if !end.Equal(c.Period.Start) || c.Sequence != head.LastSequence+1 || c.PreviousSHA256 != head.LastSHA256 || c.StateSerial < serial {
			return DecisionOwnershipArchiveEvidence{}, ErrDecisionOwnershipEvidence
		}
		head.Count++
		head.LastSequence = c.Sequence
		head.LastSHA256 = pin.SHA256
		end = c.Period.End
		serial = c.StateSerial
		witness := DecisionOwnershipArchiveWitness{TenantID: reg.TenantID, SourceRegistrationSHA256: reg.IssuedDocumentSHA256, AccountID: reg.AccountID, BucketOwner: reg.BucketOwner, Bucket: reg.Bucket, Region: reg.Region, Pin: pin, NativeLastModified: object.LastModified, NativeTimeResolutionSeconds: 1}
		receipt, e := reader.PersistArchiveWitness(ctx, reg, witness, object.Data)
		if e != nil || receipt.Kind != "AWS_OWNERSHIP_ARCHIVE_OBJECT" || receipt.ID != Hash(witness) || receipt.SHA256 != Hash(witness) {
			return DecisionOwnershipArchiveEvidence{}, ErrDecisionOwnershipEvidence
		}
		encoded, _ := json.Marshal(map[string]string{"id": receipt.ID, "kind": receipt.Kind, "sha256": receipt.SHA256})
		witnessDigest.Write(encoded)
		witnessDigest.Write([]byte{'\n'})
		out.WitnessCount++
	}
	if !finish() || resourceIndex != len(query.Scope.Resources) {
		return DecisionOwnershipArchiveEvidence{}, ErrDecisionOwnershipEvidence
	}
	current, err := reader.ArchiveRegistration(ctx, registrationID)
	currentReviewer, e := reader.ArchiveReviewRegistration(ctx, r.ReviewerRegistrationID)
	currentBucket, bucketErr := reader.ArchiveBucket(ctx, reg)
	if err != nil || e != nil || bucketErr != nil || Hash(current) != Hash(reg) || current.IssuedDocumentSHA256 != reg.IssuedDocumentSHA256 || Hash(currentReviewer) != Hash(reviewer) || currentReviewer.IssuedDocumentSHA256 != reviewer.IssuedDocumentSHA256 || !ownershipArchiveRegistrationValid(current, query, now) || !ownershipRegistration(currentReviewer, "OWNERSHIP_REVIEW", Hash(query.Scope), now) || !archiveBucketMatches(currentBucket, reg) {
		return DecisionOwnershipArchiveEvidence{}, ErrDecisionOwnershipEvidence
	}
	out.WitnessRootSHA256 = hex.EncodeToString(witnessDigest.Sum(nil))
	out.ID = Hash(out)
	return out, nil
}
