package commitmentportfolio

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/configuration"
)

const DecisionOwnershipBasis = "CUSTOMER_REGISTERED_DEPLOYMENT_JOURNAL_WITH_INDEPENDENT_REVIEW"
const DecisionOwnershipObserved = "CUSTOMER_JOURNAL_REVIEWED_INTERVALS"
const ownershipJournalAlgorithm = "Ed25519/commitment-ownership-journal/v1"
const ownershipReviewAlgorithm = "Ed25519/commitment-ownership-review/v1"
const ownershipJournalDomain = "finops/commitment-ownership/journal/v1\x00"
const ownershipReviewDomain = "finops/commitment-ownership/review/v1\x00"
const ownershipMaxRows = 100000
const ownershipMaxWireBytes = 128 << 20
const ownershipMaxArchiveBytes = 64 << 20

var ErrDecisionOwnershipAbsent = errors.New("COMMITMENT_HISTORICAL_OWNERSHIP_ABSENT")
var ErrDecisionOwnershipEvidence = errors.New("COMMITMENT_HISTORICAL_OWNERSHIP_UNSUPPORTED")
var ownershipCommit = regexp.MustCompile(`^(?:[a-f0-9]{40}|[a-f0-9]{64})$`)
var ownershipAccount = regexp.MustCompile(`^[0-9]{12}$`)

// Both native and internal IDs are authenticated. Current equal endpoints never
// imply any interval between them, nor establish historical resource ownership.
type DecisionOwnershipResource struct {
	ResourceID         string `json:"resource_id"`
	ProviderResourceID string `json:"provider_resource_id"`
	AccountID          string `json:"account_id"`
	Region             string `json:"region"`
	// The actual configuration-authority entity ID; its immutable declaration
	// identifies the repository. This is not a caller-created repository alias.
	RepositoryID        string `json:"repository_id"`
	GitCommit           string `json:"git_commit"`
	ConfigurationSHA256 string `json:"configuration_sha256"`
	StateLineage        string `json:"state_lineage"`
}

type DecisionOwnershipScope struct {
	TenantID            string                      `json:"tenant_id"`
	WorkloadID          string                      `json:"workload_id"`
	ConfigurationSHA256 string                      `json:"configuration_sha256"`
	Resources           []DecisionOwnershipResource `json:"resources"`
}

type DecisionOwnershipQuery struct {
	Scope  DecisionOwnershipScope `json:"scope"`
	Period Period                 `json:"period"`
}

// Operator-created database rows; none of these fields are public evidence
// uploads. Revocation is append-only, projected by the trusted repository.
type DecisionOwnershipRegistration struct {
	ID          string     `json:"id"`
	Revision    int64      `json:"revision"`
	ScopeSHA256 string     `json:"scope_sha256"`
	Purpose     string     `json:"purpose"`
	Issuer      string     `json:"issuer"`
	Subject     string     `json:"subject"`
	Audience    string     `json:"audience"`
	PublicKey   []byte     `json:"public_key"`
	ValidFrom   time.Time  `json:"valid_from"`
	ValidUntil  time.Time  `json:"valid_until"`
	RevokedAt   *time.Time `json:"revoked_at"`
	// Pin the actual issued JSON document, including its timestamp spelling.
	// Typed time.Time values are used for validity checks, never to recreate it.
	IssuedDocumentSHA256 string `json:"-"`
}

type DecisionOwnershipJournal struct {
	SchemaVersion        string                           `json:"schema_version"`
	ID                   string                           `json:"id"`
	RegistrationID       string                           `json:"registration_id"`
	RegistrationRevision int64                            `json:"registration_revision"`
	ScopeSHA256          string                           `json:"scope_sha256"`
	TenantID             string                           `json:"tenant_id"`
	WorkloadID           string                           `json:"workload_id"`
	Resource             DecisionOwnershipResource        `json:"resource"`
	Period               Period                           `json:"period"`
	StateSerial          uint64                           `json:"state_serial"`
	ArtifactRef          Ref                              `json:"artifact_ref"`
	ArchiveRef           configuration.ArtifactArchiveRef `json:"archive_ref"`
	DeploymentRef        Ref                              `json:"deployment_ref"`
	Sequence             uint64                           `json:"sequence"`
	PreviousSHA256       string                           `json:"previous_sha256"`
	SignedAt             time.Time                        `json:"signed_at"`
}

type DecisionOwnershipJournalEnvelope struct {
	Journal   DecisionOwnershipJournal `json:"journal"`
	Algorithm string                   `json:"algorithm"`
	Signature string                   `json:"signature"`
}

type DecisionOwnershipHead struct {
	ResourceID    string `json:"resource_id"`
	Count         uint64 `json:"count"`
	FirstSequence uint64 `json:"first_sequence"`
	LastSequence  uint64 `json:"last_sequence"`
	FirstSHA256   string `json:"first_sha256"`
	LastSHA256    string `json:"last_sha256"`
}

type DecisionOwnershipReview struct {
	SchemaVersion               string                  `json:"schema_version"`
	ID                          string                  `json:"id"`
	RegistrationID              string                  `json:"registration_id"`
	RegistrationRevision        int64                   `json:"registration_revision"`
	JournalRegistrationID       string                  `json:"journal_registration_id"`
	JournalRegistrationRevision int64                   `json:"journal_registration_revision"`
	ScopeSHA256                 string                  `json:"scope_sha256"`
	TenantID                    string                  `json:"tenant_id"`
	WorkloadID                  string                  `json:"workload_id"`
	Period                      Period                  `json:"period"`
	Heads                       []DecisionOwnershipHead `json:"heads"`
	ChainRootSHA256             string                  `json:"chain_root_sha256"`
	SignedAt                    time.Time               `json:"signed_at"`
}

type DecisionOwnershipReviewEnvelope struct {
	Review    DecisionOwnershipReview `json:"review"`
	Algorithm string                  `json:"algorithm"`
	Signature string                  `json:"signature"`
}

// ServerRecordedAt is assigned by the authenticated append transaction's clock,
// never copied from the signed client body. Raw bytes and their DB hash survive
// JSONB projection; canonical signatures are not reconstructed from JSONB text.
type DecisionOwnershipStoredEnvelope struct {
	Reference        Ref
	ServerRecordedAt time.Time
	RawEnvelope      []byte
}

type DecisionOwnershipPage struct {
	Items      []DecisionOwnershipStoredEnvelope
	NextCursor string
}

// This projection must come from an actual immutable deployment-observer row,
// authenticated to the registration identity and exact resource/configuration.
// The reader verifies its raw-row reference; it is not a caller-supplied bool.
type DecisionOwnershipDeployment struct {
	Reference        Ref
	TenantID         string
	WorkloadID       string
	Resource         DecisionOwnershipResource
	Issuer           string
	Subject          string
	Audience         string
	ObservedAt       time.Time
	ServerRecordedAt time.Time
}

// Implemented by the private040 resolver over actual issued database receipts,
// operator keys and exact encrypted/versioned object readback. This interface
// is not an HTTP body. No current-point interpolation or role-boolean adapter
// qualifies. Artifact ciphertext is verified here; the existing capture pipeline
// owns its authenticated encryption/decryption and metadata validation.
type DecisionOwnershipReader interface {
	OwnershipReview(context.Context, DecisionOwnershipQuery) (DecisionOwnershipStoredEnvelope, error)
	OwnershipRegistration(context.Context, string) (DecisionOwnershipRegistration, error)
	OwnershipJournalPage(context.Context, DecisionOwnershipQuery, string, string) (DecisionOwnershipPage, error)
	OwnershipArtifact(context.Context, Ref, configuration.ArtifactArchiveRef) (configuration.ArtifactReceipt, []byte, error)
	OwnershipDeployment(context.Context, Ref) (DecisionOwnershipDeployment, error)
}

type DecisionOwnershipRegistrationPin struct {
	ID       string `json:"id"`
	Revision int64  `json:"revision"`
	SHA256   string `json:"sha256"`
}

type DecisionOwnershipSegment struct {
	Resource         DecisionOwnershipResource `json:"resource"`
	Period           Period                    `json:"period"`
	Head             DecisionOwnershipHead     `json:"head"`
	FirstStateSerial uint64                    `json:"first_state_serial"`
	LastStateSerial  uint64                    `json:"last_state_serial"`
	FirstJournal     Ref                       `json:"first_journal"`
	LastJournal      Ref                       `json:"last_journal"`
}

type DecisionOwnershipEvidence struct {
	SchemaVersion       string                             `json:"schema_version"`
	ID                  string                             `json:"id"`
	Scope               DecisionOwnershipScope             `json:"scope"`
	ScopeSHA256         string                             `json:"scope_sha256"`
	Period              Period                             `json:"period"`
	Status              string                             `json:"status"`
	Basis               string                             `json:"basis"`
	Segments            []DecisionOwnershipSegment         `json:"segments"`
	RegistrationPins    []DecisionOwnershipRegistrationPin `json:"registration_pins"`
	InputRefs           []Ref                              `json:"input_refs"`
	ReasonCodes         []string                           `json:"reason_codes"`
	ObservedAt          time.Time                          `json:"observed_at"`
	ExecutionAuthorized bool                               `json:"execution_authorized"`
	VerifiedSaving      *string                            `json:"verified_saving"`
}

func DecisionOwnershipConfigurationSHA256(resources []DecisionOwnershipResource) string {
	return Hash(resources)
}

func DecisionOwnershipJournalSigningBytes(value DecisionOwnershipJournal) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, ErrDecisionOwnershipEvidence
	}
	return append([]byte(ownershipJournalDomain), raw...), nil
}

func DecisionOwnershipReviewSigningBytes(value DecisionOwnershipReview) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, ErrDecisionOwnershipEvidence
	}
	return append([]byte(ownershipReviewDomain), raw...), nil
}

func ownershipBytesHash(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func ownershipRef(value Ref, kind string) bool {
	return value.Kind == kind && idPattern.MatchString(value.ID) && shaPattern.MatchString(value.SHA256)
}
func ownershipUTC(value time.Time) bool {
	_, offset := value.Zone()
	return !value.IsZero() && offset == 0
}
func ownershipPeriod(value Period) bool {
	return ownershipUTC(value.Start) && ownershipUTC(value.End) && value.Start.Before(value.End)
}

func ownershipCanonical(raw []byte, out any, max int) bool {
	if len(raw) == 0 || len(raw) > max {
		return false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return false
	}
	encoded, err := json.Marshal(out)
	return err == nil && bytes.Equal(raw, encoded)
}

func ownershipSignature(key []byte, message []byte, encoded string) bool {
	signature, err := base64.StdEncoding.Strict().DecodeString(encoded)
	return err == nil && len(key) == ed25519.PublicKeySize && len(signature) == ed25519.SignatureSize && base64.StdEncoding.EncodeToString(signature) == encoded && ed25519.Verify(key, message, signature)
}

func ownershipRegistration(r DecisionOwnershipRegistration, purpose, scope string, now time.Time) bool {
	return idPattern.MatchString(r.ID) && r.Revision > 0 && shaPattern.MatchString(r.IssuedDocumentSHA256) && r.Purpose == purpose && r.ScopeSHA256 == scope && len(r.PublicKey) == ed25519.PublicKeySize && r.Issuer != "" && r.Subject != "" && len(r.Issuer) <= 2048 && len(r.Subject) <= 256 && r.Audience == configuration.ObserverAudience && ownershipUTC(r.ValidFrom) && ownershipUTC(r.ValidUntil) && !r.ValidFrom.After(now) && now.Before(r.ValidUntil) && r.RevokedAt == nil
}

func ownershipScope(s DecisionOwnershipScope) bool {
	if !idPattern.MatchString(s.TenantID) || !idPattern.MatchString(s.WorkloadID) || len(s.Resources) < 1 || len(s.Resources) > 128 || s.ConfigurationSHA256 != DecisionOwnershipConfigurationSHA256(s.Resources) {
		return false
	}
	previous, native := "", map[string]bool{}
	for _, r := range s.Resources {
		key := r.AccountID + ":" + r.Region + ":" + r.ProviderResourceID
		if !idPattern.MatchString(r.ResourceID) || r.ResourceID <= previous || !idPattern.MatchString(r.ProviderResourceID) || !ownershipAccount.MatchString(r.AccountID) || r.Region == "" || len(r.Region) > 64 || !idPattern.MatchString(r.RepositoryID) || !ownershipCommit.MatchString(r.GitCommit) || !shaPattern.MatchString(r.ConfigurationSHA256) || !idPattern.MatchString(r.StateLineage) || native[key] {
			return false
		}
		previous, native[key] = r.ResourceID, true
	}
	return true
}

func ownershipArchive(ref configuration.ArtifactArchiveRef, tenant string) bool {
	return idPattern.MatchString(ref.Bucket) && strings.HasPrefix(ref.Key, "tenant/"+tenant+"/configuration-artifacts/") && !strings.Contains(ref.Key, "..") && !strings.ContainsAny(ref.Key, "\\\x00\r\n") && len(ref.Key) <= 2048 && ref.VersionID != "" && ref.VersionID != "null" && len(ref.VersionID) <= 1024 && shaPattern.MatchString(ref.SHA256) && ref.Bytes > 0 && ref.Bytes <= 8<<20
}

func (value DecisionOwnershipEvidence) HistoricalReference() (Ref, error) {
	identity := value
	identity.ID = ""
	if value.Status != DecisionOwnershipObserved || value.Basis != DecisionOwnershipBasis || value.ID != Hash(identity) || len(value.Segments) == 0 || value.ExecutionAuthorized || value.VerifiedSaving != nil {
		return Ref{}, ErrDecisionOwnershipEvidence
	}
	return Ref{Kind: "HISTORICAL_OWNERSHIP", ID: value.ID, SHA256: Hash(value)}, nil
}

// Verification streams ordered rows and retains only bounded chain summaries.
// 040 must repeat the registration pins and chain/review identity under its shared
// credential fence in READ COMMITTED at publication; a final application read
// alone cannot close a concurrent revocation race.
func VerifyDecisionOwnership(ctx context.Context, reader DecisionOwnershipReader, query DecisionOwnershipQuery, now time.Time) (DecisionOwnershipEvidence, error) {
	query.Scope.Resources = append([]DecisionOwnershipResource(nil), query.Scope.Resources...)
	out := DecisionOwnershipEvidence{SchemaVersion: "1", Scope: query.Scope, ScopeSHA256: Hash(query.Scope), Period: query.Period, Status: "UNAVAILABLE", Basis: DecisionOwnershipBasis, Segments: []DecisionOwnershipSegment{}, RegistrationPins: []DecisionOwnershipRegistrationPin{}, InputRefs: []Ref{}, ReasonCodes: []string{}, ObservedAt: now.UTC()}
	fail := func(reason string, err error) (DecisionOwnershipEvidence, error) {
		out.Segments = []DecisionOwnershipSegment{}
		out.RegistrationPins = []DecisionOwnershipRegistrationPin{}
		out.InputRefs = []Ref{}
		out.ReasonCodes = []string{reason}
		out.ID = ""
		out.ID = Hash(out)
		return out, err
	}
	if reader == nil || !ownershipUTC(now) || !ownershipScope(query.Scope) || !ownershipPeriod(query.Period) || query.Period.End.After(now) || query.Period.End.Sub(query.Period.Start) > 5*366*24*time.Hour {
		return fail("HISTORICAL_OWNERSHIP_QUERY_UNSUPPORTED", ErrDecisionOwnershipEvidence)
	}
	if err := ctx.Err(); err != nil {
		return fail("HISTORICAL_OWNERSHIP_CANCELLED", err)
	}
	stored, err := reader.OwnershipReview(ctx, query)
	if errors.Is(err, ErrDecisionOwnershipAbsent) {
		return fail("INDEPENDENT_CONTINUOUS_OWNERSHIP_REVIEW_UNAVAILABLE", nil)
	}
	var envelope DecisionOwnershipReviewEnvelope
	if err != nil || !ownershipCanonical(stored.RawEnvelope, &envelope, 64<<10) || !ownershipRef(stored.Reference, "OWNERSHIP_REVIEW") || stored.Reference.ID != envelope.Review.ID || stored.Reference.SHA256 != ownershipBytesHash(stored.RawEnvelope) {
		return fail("HISTORICAL_OWNERSHIP_REVIEW_INVALID", ErrDecisionOwnershipEvidence)
	}
	review := envelope.Review
	journalReg, err1 := reader.OwnershipRegistration(ctx, review.JournalRegistrationID)
	reviewReg, err2 := reader.OwnershipRegistration(ctx, review.RegistrationID)
	journalReg.PublicKey = append([]byte(nil), journalReg.PublicKey...)
	reviewReg.PublicKey = append([]byte(nil), reviewReg.PublicKey...)
	message, signErr := DecisionOwnershipReviewSigningBytes(review)
	if err1 != nil || err2 != nil || signErr != nil || !ownershipRegistration(journalReg, "DEPLOYMENT_JOURNAL", out.ScopeSHA256, now) || !ownershipRegistration(reviewReg, "OWNERSHIP_REVIEW", out.ScopeSHA256, now) || journalReg.ID == reviewReg.ID || journalReg.Issuer == reviewReg.Issuer && journalReg.Subject == reviewReg.Subject || bytes.Equal(journalReg.PublicKey, reviewReg.PublicKey) || envelope.Algorithm != ownershipReviewAlgorithm || !ownershipSignature(reviewReg.PublicKey, message, envelope.Signature) {
		return fail("HISTORICAL_OWNERSHIP_COMMISSION_OR_SIGNATURE_INVALID", ErrDecisionOwnershipEvidence)
	}
	if review.SchemaVersion != "1" || review.RegistrationRevision != reviewReg.Revision || review.JournalRegistrationRevision != journalReg.Revision || review.TenantID != query.Scope.TenantID || review.WorkloadID != query.Scope.WorkloadID || review.ScopeSHA256 != out.ScopeSHA256 || Hash(review.Period) != Hash(query.Period) || len(review.Heads) != len(query.Scope.Resources) || review.ChainRootSHA256 != Hash(review.Heads) || !ownershipUTC(review.SignedAt) || review.SignedAt.Before(query.Period.End) || review.SignedAt.Before(reviewReg.ValidFrom) || !ownershipUTC(stored.ServerRecordedAt) || stored.ServerRecordedAt.Before(review.SignedAt) || stored.ServerRecordedAt.After(now) || now.Sub(stored.ServerRecordedAt) > 24*time.Hour || journalReg.ValidFrom.After(query.Period.Start) {
		return fail("HISTORICAL_OWNERSHIP_REVIEW_SCOPE_OR_TIME_INVALID", ErrDecisionOwnershipEvidence)
	}
	for i, head := range review.Heads {
		if head.ResourceID != query.Scope.Resources[i].ResourceID || head.Count < 1 || head.Count > ownershipMaxRows || head.FirstSequence < 1 || head.LastSequence < head.FirstSequence || head.LastSequence-head.FirstSequence+1 != head.Count || !shaPattern.MatchString(head.FirstSHA256) || !shaPattern.MatchString(head.LastSHA256) {
			return fail("HISTORICAL_OWNERSHIP_CHAIN_HEAD_INVALID", ErrDecisionOwnershipEvidence)
		}
	}
	cursor, seenCursor, seenID := "", map[string]bool{}, map[string]bool{}
	artifactCache := map[string]configuration.ArtifactReceipt{}
	deploymentCache := map[string]DecisionOwnershipDeployment{}
	resourceIndex, count, wireBytes, archiveBytes := 0, 0, len(stored.RawEnvelope), int64(0)
	var segment *DecisionOwnershipSegment
	finish := func() bool {
		if segment == nil {
			return false
		}
		expected := review.Heads[resourceIndex]
		if !segment.Period.End.Equal(query.Period.End) || Hash(segment.Head) != Hash(expected) {
			return false
		}
		out.Segments = append(out.Segments, *segment)
		out.InputRefs = append(out.InputRefs, segment.FirstJournal, segment.LastJournal)
		resourceIndex++
		segment = nil
		return true
	}
	for {
		if err := ctx.Err(); err != nil {
			return fail("HISTORICAL_OWNERSHIP_CANCELLED", err)
		}
		page, readErr := reader.OwnershipJournalPage(ctx, query, journalReg.ID, cursor)
		if readErr != nil || page.Items == nil || len(page.Items) > 256 || len(page.Items) == 0 && page.NextCursor != "" {
			return fail("HISTORICAL_OWNERSHIP_JOURNAL_UNAVAILABLE", ErrDecisionOwnershipEvidence)
		}
		for _, row := range page.Items {
			count++
			wireBytes += len(row.RawEnvelope)
			if count > ownershipMaxRows || wireBytes > ownershipMaxWireBytes {
				return fail("HISTORICAL_OWNERSHIP_EVIDENCE_LIMIT", ErrDecisionOwnershipEvidence)
			}
			var signed DecisionOwnershipJournalEnvelope
			if !ownershipCanonical(row.RawEnvelope, &signed, 16<<10) || !ownershipRef(row.Reference, "OWNERSHIP_JOURNAL") || row.Reference.ID != signed.Journal.ID || row.Reference.SHA256 != ownershipBytesHash(row.RawEnvelope) || seenID[row.Reference.ID] {
				return fail("HISTORICAL_OWNERSHIP_JOURNAL_BYTES_INVALID", ErrDecisionOwnershipEvidence)
			}
			seenID[row.Reference.ID] = true
			j := signed.Journal
			if segment != nil && j.Resource.ResourceID != segment.Resource.ResourceID && !finish() {
				return fail("HISTORICAL_OWNERSHIP_INTERVAL_GAP_OR_CHAIN_CHANGED", ErrDecisionOwnershipEvidence)
			}
			if resourceIndex >= len(query.Scope.Resources) || Hash(j.Resource) != Hash(query.Scope.Resources[resourceIndex]) {
				return fail("HISTORICAL_OWNERSHIP_RESOURCE_SCOPE_CHANGED", ErrDecisionOwnershipEvidence)
			}
			body, bodyErr := DecisionOwnershipJournalSigningBytes(j)
			if bodyErr != nil || signed.Algorithm != ownershipJournalAlgorithm || !ownershipSignature(journalReg.PublicKey, body, signed.Signature) || j.SchemaVersion != "1" || j.RegistrationID != journalReg.ID || j.RegistrationRevision != journalReg.Revision || j.ScopeSHA256 != out.ScopeSHA256 || j.TenantID != query.Scope.TenantID || j.WorkloadID != query.Scope.WorkloadID {
				return fail("HISTORICAL_OWNERSHIP_JOURNAL_SIGNATURE_INVALID", ErrDecisionOwnershipEvidence)
			}
			if !ownershipPeriod(j.Period) || j.Period.Start.Before(query.Period.Start) || j.Period.End.After(query.Period.End) || j.Period.End.Sub(j.Period.Start) > time.Hour || !ownershipUTC(j.SignedAt) || j.SignedAt.Before(j.Period.End) || !ownershipUTC(row.ServerRecordedAt) || row.ServerRecordedAt.Before(j.SignedAt) || row.ServerRecordedAt.Sub(j.Period.End) > 5*time.Minute || row.ServerRecordedAt.After(stored.ServerRecordedAt) || row.ServerRecordedAt.After(now) {
				return fail("HISTORICAL_OWNERSHIP_BACKFILL_OR_INTERVAL_INVALID", ErrDecisionOwnershipEvidence)
			}
			if segment == nil {
				if !j.Period.Start.Equal(query.Period.Start) || j.Sequence < 1 || j.Sequence == 1 && j.PreviousSHA256 != "" || j.Sequence > 1 && !shaPattern.MatchString(j.PreviousSHA256) {
					return fail("HISTORICAL_OWNERSHIP_CHAIN_ORIGIN_INVALID", ErrDecisionOwnershipEvidence)
				}
				segment = &DecisionOwnershipSegment{Resource: j.Resource, Period: Period{Start: j.Period.Start}, Head: DecisionOwnershipHead{ResourceID: j.Resource.ResourceID, FirstSequence: j.Sequence, FirstSHA256: row.Reference.SHA256}, FirstStateSerial: j.StateSerial, FirstJournal: row.Reference}
			} else if !segment.Period.End.Equal(j.Period.Start) || j.Sequence != segment.Head.LastSequence+1 || j.PreviousSHA256 != segment.Head.LastSHA256 || j.StateSerial < segment.LastStateSerial {
				return fail("HISTORICAL_OWNERSHIP_INTERVAL_GAP_OR_CHAIN_CHANGED", ErrDecisionOwnershipEvidence)
			}
			if !ownershipRef(j.ArtifactRef, "CONFIGURATION_ARTIFACT") || !ownershipArchive(j.ArchiveRef, query.Scope.TenantID) || !ownershipRef(j.DeploymentRef, "DEPLOYMENT_RECEIPT") {
				return fail("HISTORICAL_OWNERSHIP_SOURCE_PIN_INVALID", ErrDecisionOwnershipEvidence)
			}
			cacheKey := Hash(struct {
				Ref     Ref
				Archive configuration.ArtifactArchiveRef
			}{j.ArtifactRef, j.ArchiveRef})
			artifact, cached := artifactCache[cacheKey]
			if !cached {
				if archiveBytes+j.ArchiveRef.Bytes > ownershipMaxArchiveBytes {
					return fail("HISTORICAL_OWNERSHIP_EVIDENCE_LIMIT", ErrDecisionOwnershipEvidence)
				}
				var ciphertext []byte
				var archiveErr error
				artifact, ciphertext, archiveErr = reader.OwnershipArtifact(ctx, j.ArtifactRef, j.ArchiveRef)
				if archiveErr != nil || artifact.ID != j.ArtifactRef.ID || Hash(artifact) != j.ArtifactRef.SHA256 || Hash(artifact.Archive) != Hash(j.ArchiveRef) || int64(len(ciphertext)) != j.ArchiveRef.Bytes || ownershipBytesHash(ciphertext) != j.ArchiveRef.SHA256 {
					return fail("HISTORICAL_OWNERSHIP_ARCHIVE_OR_ARTIFACT_CHANGED", ErrDecisionOwnershipEvidence)
				}
				archiveBytes += int64(len(ciphertext))
				artifactCache[cacheKey] = artifact
			}
			m := artifact.Metadata
			if m.Binding.Provider != "AWS" || m.Binding.TenantID != j.TenantID || m.Binding.WorkloadID != j.WorkloadID || m.Binding.ResourceID != j.Resource.ResourceID || m.Binding.ProviderResourceID != j.Resource.ProviderResourceID || m.Binding.AccountID != j.Resource.AccountID || m.Binding.Region != j.Resource.Region || m.AuthorityID != j.Resource.RepositoryID || m.AuthorityVersion < 1 || !shaPattern.MatchString(m.AuthorityHash) || !idPattern.MatchString(m.RegistrationID) || m.RegistrationVersion < 1 || !shaPattern.MatchString(m.RegistrationHash) || m.Git.Commit != j.Resource.GitCommit || m.Git.ConfigurationSHA256 != j.Resource.ConfigurationSHA256 || m.State.Lineage != j.Resource.StateLineage || m.State.Serial != j.StateSerial || !shaPattern.MatchString(m.BundleSHA256) || m.ExecutionAuthorized || m.VerifiedSaving != nil || !ownershipUTC(artifact.ReceivedAt) || artifact.ReceivedAt.After(row.ServerRecordedAt) {
				return fail("HISTORICAL_OWNERSHIP_ARCHIVE_OR_ARTIFACT_CHANGED", ErrDecisionOwnershipEvidence)
			}
			deploymentKey := Hash(j.DeploymentRef)
			deployment, deploymentCached := deploymentCache[deploymentKey]
			var deploymentErr error
			if !deploymentCached {
				deployment, deploymentErr = reader.OwnershipDeployment(ctx, j.DeploymentRef)
			}
			if deploymentErr != nil || Hash(deployment.Reference) != Hash(j.DeploymentRef) || deployment.TenantID != j.TenantID || deployment.WorkloadID != j.WorkloadID || Hash(deployment.Resource) != Hash(j.Resource) || deployment.Issuer != journalReg.Issuer || deployment.Subject != journalReg.Subject || deployment.Audience != configuration.ObserverAudience || !ownershipUTC(deployment.ObservedAt) || !ownershipUTC(deployment.ServerRecordedAt) || deployment.ObservedAt.After(deployment.ServerRecordedAt) || deployment.ServerRecordedAt.After(row.ServerRecordedAt) {
				return fail("HISTORICAL_OWNERSHIP_DEPLOYMENT_BINDING_INVALID", ErrDecisionOwnershipEvidence)
			}
			deploymentCache[deploymentKey] = deployment
			segment.Period.End = j.Period.End
			segment.Head.Count++
			segment.Head.LastSequence = j.Sequence
			segment.Head.LastSHA256 = row.Reference.SHA256
			segment.LastStateSerial = j.StateSerial
			segment.LastJournal = row.Reference
		}
		if page.NextCursor == "" {
			break
		}
		if len(page.NextCursor) > 2048 || page.NextCursor == cursor || seenCursor[page.NextCursor] {
			return fail("HISTORICAL_OWNERSHIP_CURSOR_INVALID", ErrDecisionOwnershipEvidence)
		}
		seenCursor[page.NextCursor] = true
		cursor = page.NextCursor
	}
	if !finish() || resourceIndex != len(query.Scope.Resources) {
		return fail("HISTORICAL_OWNERSHIP_INTERVAL_GAP_OR_CHAIN_CHANGED", ErrDecisionOwnershipEvidence)
	}
	if err := ctx.Err(); err != nil {
		return fail("HISTORICAL_OWNERSHIP_CANCELLED", err)
	}
	// Refresh actual operator/revocation projections after all potentially slow IO.
	for _, pinned := range []DecisionOwnershipRegistration{journalReg, reviewReg} {
		current, readErr := reader.OwnershipRegistration(ctx, pinned.ID)
		if readErr != nil || Hash(current) != Hash(pinned) || current.IssuedDocumentSHA256 != pinned.IssuedDocumentSHA256 || !ownershipRegistration(current, pinned.Purpose, out.ScopeSHA256, now) {
			return fail("HISTORICAL_OWNERSHIP_COMMISSION_CHANGED", ErrDecisionOwnershipEvidence)
		}
		out.RegistrationPins = append(out.RegistrationPins, DecisionOwnershipRegistrationPin{ID: pinned.ID, Revision: pinned.Revision, SHA256: pinned.IssuedDocumentSHA256})
	}
	refs, refsErr := decisionRefs(append(out.InputRefs, stored.Reference))
	if refsErr != nil {
		return fail("HISTORICAL_OWNERSHIP_SOURCE_PIN_INVALID", ErrDecisionOwnershipEvidence)
	}
	sort.Slice(out.RegistrationPins, func(i, j int) bool { return out.RegistrationPins[i].ID < out.RegistrationPins[j].ID })
	out.InputRefs = refs
	out.Status = DecisionOwnershipObserved
	out.ReasonCodes = []string{"CUSTOMER_JOURNAL_INTERVAL_AUTHORITY_NOT_NATIVE_PROVIDER_HISTORY", "ARTIFACT_POINT_METADATA_ALONE_DOES_NOT_PROVE_HISTORY"}
	out.ID = Hash(out)
	return out, nil
}
