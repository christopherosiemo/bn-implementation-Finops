package commitmentportfolio

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/configuration"
)

// Cryptographically signed unit doubles. Cipher bytes and deployment projections
// here do not claim an actual provider, encrypted archive, SQL append or identity.
type ownershipFixture struct {
	query                                  DecisionOwnershipQuery
	now                                    time.Time
	journalKey, reviewKey                  ed25519.PrivateKey
	registrations                          map[string]DecisionOwnershipRegistration
	registrationReads                      map[string]int
	journals                               []DecisionOwnershipStoredEnvelope
	unsigned                               []DecisionOwnershipJournal
	review                                 DecisionOwnershipReview
	storedReview                           DecisionOwnershipStoredEnvelope
	artifacts                              map[string]configuration.ArtifactReceipt
	ciphers                                map[string][]byte
	deployments                            map[string]DecisionOwnershipDeployment
	artifactReads                          int
	deploymentReads                        int
	pageReads                              int
	noReview, revokeOnReload, repeatCursor bool
	cancelArchive                          context.CancelFunc
}

func (f *ownershipFixture) OwnershipReview(context.Context, DecisionOwnershipQuery) (DecisionOwnershipStoredEnvelope, error) {
	if f.noReview {
		return DecisionOwnershipStoredEnvelope{}, ErrDecisionOwnershipAbsent
	}
	return f.storedReview, nil
}
func (f *ownershipFixture) OwnershipRegistration(_ context.Context, id string) (DecisionOwnershipRegistration, error) {
	r, ok := f.registrations[id]
	if !ok {
		return r, ErrDecisionOwnershipAbsent
	}
	f.registrationReads[id]++
	if f.revokeOnReload && f.registrationReads[id] > 1 {
		at := f.now
		r.RevokedAt = &at
	}
	if r.IssuedDocumentSHA256 == "" {
		r.IssuedDocumentSHA256 = Hash(r)
	}
	return r, nil
}
func (f *ownershipFixture) OwnershipJournalPage(_ context.Context, _ DecisionOwnershipQuery, _ string, cursor string) (DecisionOwnershipPage, error) {
	f.pageReads++
	offset := 0
	if cursor != "" {
		n, err := strconv.Atoi(cursor)
		if err != nil {
			return DecisionOwnershipPage{}, err
		}
		offset = n
	}
	if offset > len(f.journals) {
		return DecisionOwnershipPage{}, ErrDecisionOwnershipEvidence
	}
	end := offset + 2
	if end > len(f.journals) {
		end = len(f.journals)
	}
	next := ""
	if end < len(f.journals) {
		next = strconv.Itoa(end)
	}
	if f.repeatCursor && cursor != "" {
		next = cursor
	}
	return DecisionOwnershipPage{Items: append([]DecisionOwnershipStoredEnvelope{}, f.journals[offset:end]...), NextCursor: next}, nil
}
func (f *ownershipFixture) OwnershipArtifact(_ context.Context, ref Ref, _ configuration.ArtifactArchiveRef) (configuration.ArtifactReceipt, []byte, error) {
	f.artifactReads++
	if f.cancelArchive != nil {
		f.cancelArchive()
	}
	r, ok := f.artifacts[ref.ID]
	if !ok {
		return r, nil, ErrDecisionOwnershipAbsent
	}
	return r, append([]byte{}, f.ciphers[ref.ID]...), nil
}
func (f *ownershipFixture) OwnershipDeployment(_ context.Context, ref Ref) (DecisionOwnershipDeployment, error) {
	f.deploymentReads++
	r, ok := f.deployments[ref.ID]
	if !ok {
		return r, ErrDecisionOwnershipAbsent
	}
	return r, nil
}

func ownershipTestFixture(t *testing.T) *ownershipFixture {
	t.Helper()
	_, journalKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, reviewKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	end := start.Add(3 * time.Hour)
	f := &ownershipFixture{now: end.Add(time.Minute), journalKey: journalKey, reviewKey: reviewKey, registrations: map[string]DecisionOwnershipRegistration{}, registrationReads: map[string]int{}, artifacts: map[string]configuration.ArtifactReceipt{}, ciphers: map[string][]byte{}, deployments: map[string]DecisionOwnershipDeployment{}}
	resources := []DecisionOwnershipResource{}
	for i := 0; i < 2; i++ {
		resources = append(resources, DecisionOwnershipResource{ResourceID: fmt.Sprintf("internal-%d", i), ProviderResourceID: fmt.Sprintf("i-native%d", i), AccountID: "111122223333", Region: "eu-west-1", RepositoryID: "repository-issued", GitCommit: strings.Repeat("a", 40), ConfigurationSHA256: strings.Repeat("b", 64), StateLineage: "11111111-2222-4333-8444-555555555555"})
	}
	f.query = DecisionOwnershipQuery{Scope: DecisionOwnershipScope{TenantID: "tenant-owned", WorkloadID: "workload-owned", Resources: resources, ConfigurationSHA256: DecisionOwnershipConfigurationSHA256(resources)}, Period: Period{Start: start, End: end}}
	scopeSHA := Hash(f.query.Scope)
	for _, purpose := range []string{"DEPLOYMENT_JOURNAL", "OWNERSHIP_REVIEW"} {
		id, key, subject := "journal-key", journalKey, "pipeline-observer"
		if purpose == "OWNERSHIP_REVIEW" {
			id, key, subject = "review-key", reviewKey, "independent-reviewer"
		}
		f.registrations[id] = DecisionOwnershipRegistration{ID: id, Revision: 1, ScopeSHA256: scopeSHA, Purpose: purpose, Issuer: "https://issuer.invalid", Subject: subject, Audience: configuration.ObserverAudience, PublicKey: append([]byte{}, key.Public().(ed25519.PublicKey)...), ValidFrom: start.Add(-24 * time.Hour), ValidUntil: end.Add(30 * 24 * time.Hour)}
	}
	for i, resource := range resources {
		artifactID := fmt.Sprintf("artifact-%d", i)
		cipher := []byte("explicit unit encrypted-object double " + artifactID)
		archive := configuration.ArtifactArchiveRef{Bucket: "fixture-evidence", Key: "tenant/tenant-owned/configuration-artifacts/job-" + artifactID + "/cipher.encrypted", VersionID: "version-" + artifactID, SHA256: ownershipBytesHash(cipher), Bytes: int64(len(cipher))}
		artifact := configuration.ArtifactReceipt{ID: artifactID, JobID: "job-" + artifactID, Archive: archive, ObservedAt: start.Add(-time.Minute), ReceivedAt: start.Add(-30 * time.Second), ExpiresAt: start.Add(time.Minute)}
		artifact.Metadata = configuration.ArtifactMetadata{SchemaVersion: "1", AuthorityID: resource.RepositoryID, AuthorityVersion: 1, AuthorityHash: strings.Repeat("d", 64), RegistrationID: "artifact-registration", RegistrationVersion: 1, RegistrationHash: strings.Repeat("e", 64), Git: configuration.ArtifactGit{Commit: resource.GitCommit, ConfigurationSHA256: resource.ConfigurationSHA256}, State: configuration.ArtifactState{Lineage: resource.StateLineage, Serial: 7}, BundleSHA256: strings.Repeat("c", 64), Status: "BLOCKED", ReasonCodes: []string{"REMOTE_GIT_HEAD_UNVERIFIED", "NATIVE_STATE_FRESHNESS_UNPROVEN"}}
		artifact.Metadata.Binding.Provider = "AWS"
		artifact.Metadata.Binding.TenantID = f.query.Scope.TenantID
		artifact.Metadata.Binding.WorkloadID = f.query.Scope.WorkloadID
		artifact.Metadata.Binding.ResourceID = resource.ResourceID
		artifact.Metadata.Binding.ProviderResourceID = resource.ProviderResourceID
		artifact.Metadata.Binding.AccountID = resource.AccountID
		artifact.Metadata.Binding.Region = resource.Region
		f.artifacts[artifactID] = artifact
		f.ciphers[artifactID] = cipher
		deploymentRef := Ref{Kind: "DEPLOYMENT_RECEIPT", ID: fmt.Sprintf("deployment-%d", i), SHA256: Hash(resource)}
		f.deployments[deploymentRef.ID] = DecisionOwnershipDeployment{Reference: deploymentRef, TenantID: f.query.Scope.TenantID, WorkloadID: f.query.Scope.WorkloadID, Resource: resource, Issuer: "https://issuer.invalid", Subject: "pipeline-observer", Audience: configuration.ObserverAudience, ObservedAt: start.Add(-time.Minute), ServerRecordedAt: start.Add(-30 * time.Second)}
		for hour := 0; hour < 3; hour++ {
			span := Period{Start: start.Add(time.Duration(hour) * time.Hour), End: start.Add(time.Duration(hour+1) * time.Hour)}
			f.unsigned = append(f.unsigned, DecisionOwnershipJournal{SchemaVersion: "1", ID: fmt.Sprintf("journal-%d-%d", i, hour), RegistrationID: "journal-key", RegistrationRevision: 1, ScopeSHA256: scopeSHA, TenantID: f.query.Scope.TenantID, WorkloadID: f.query.Scope.WorkloadID, Resource: resource, Period: span, StateSerial: 7, ArtifactRef: Ref{Kind: "CONFIGURATION_ARTIFACT", ID: artifactID, SHA256: Hash(artifact)}, ArchiveRef: archive, DeploymentRef: deploymentRef, Sequence: uint64(hour + 1), SignedAt: span.End.Add(time.Second)})
		}
	}
	f.review = DecisionOwnershipReview{SchemaVersion: "1", ID: "review-issued", RegistrationID: "review-key", RegistrationRevision: 1, JournalRegistrationID: "journal-key", JournalRegistrationRevision: 1, ScopeSHA256: scopeSHA, TenantID: f.query.Scope.TenantID, WorkloadID: f.query.Scope.WorkloadID, Period: f.query.Period, SignedAt: end.Add(3 * time.Second)}
	f.reseal(t)
	return f
}

func (f *ownershipFixture) reseal(t *testing.T) {
	t.Helper()
	f.journals = nil
	f.review.Heads = nil
	for _, resource := range f.query.Scope.Resources {
		var head DecisionOwnershipHead
		previous := ""
		for _, original := range f.unsigned {
			if original.Resource.ResourceID != resource.ResourceID {
				continue
			}
			j := original
			if head.Count == 0 && j.Sequence > 1 {
				previous = strings.Repeat("d", 64)
			}
			j.PreviousSHA256 = previous
			body, err := DecisionOwnershipJournalSigningBytes(j)
			if err != nil {
				t.Fatal(err)
			}
			signed := DecisionOwnershipJournalEnvelope{Journal: j, Algorithm: ownershipJournalAlgorithm, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(f.journalKey, body))}
			raw, err := json.Marshal(signed)
			if err != nil {
				t.Fatal(err)
			}
			ref := Ref{Kind: "OWNERSHIP_JOURNAL", ID: j.ID, SHA256: ownershipBytesHash(raw)}
			f.journals = append(f.journals, DecisionOwnershipStoredEnvelope{Reference: ref, RawEnvelope: raw, ServerRecordedAt: j.Period.End.Add(2 * time.Second)})
			if head.Count == 0 {
				head = DecisionOwnershipHead{ResourceID: resource.ResourceID, FirstSequence: j.Sequence, FirstSHA256: ref.SHA256}
			}
			head.Count++
			head.LastSequence = j.Sequence
			head.LastSHA256 = ref.SHA256
			previous = ref.SHA256
		}
		f.review.Heads = append(f.review.Heads, head)
	}
	f.review.ChainRootSHA256 = Hash(f.review.Heads)
	f.signReview(t)
}
func (f *ownershipFixture) signReview(t *testing.T) {
	t.Helper()
	body, err := DecisionOwnershipReviewSigningBytes(f.review)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(DecisionOwnershipReviewEnvelope{Review: f.review, Algorithm: ownershipReviewAlgorithm, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(f.reviewKey, body))})
	if err != nil {
		t.Fatal(err)
	}
	f.storedReview = DecisionOwnershipStoredEnvelope{Reference: Ref{Kind: "OWNERSHIP_REVIEW", ID: f.review.ID, SHA256: ownershipBytesHash(raw)}, RawEnvelope: raw, ServerRecordedAt: f.query.Period.End.Add(4 * time.Second)}
}

func TestDecisionOwnershipSignedContinuousJournalAndIndependentReview(t *testing.T) {
	f := ownershipTestFixture(t)
	out, err := VerifyDecisionOwnership(context.Background(), f, f.query, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != DecisionOwnershipObserved || out.Basis != DecisionOwnershipBasis || len(out.Segments) != 2 || f.pageReads != 3 || f.artifactReads != 2 || f.deploymentReads != 2 || out.ExecutionAuthorized || out.VerifiedSaving != nil {
		t.Fatalf("incorrect bounded result: status=%s segments=%d pages=%d archiveReads=%d deploymentReads=%d", out.Status, len(out.Segments), f.pageReads, f.artifactReads, f.deploymentReads)
	}
	for _, segment := range out.Segments {
		if segment.Head.Count != 3 || !segment.Period.Start.Equal(f.query.Period.Start) || !segment.Period.End.Equal(f.query.Period.End) {
			t.Fatal("interval coverage changed")
		}
	}
	ref, err := out.HistoricalReference()
	if err != nil || ref.Kind != "HISTORICAL_OWNERSHIP" || ref.ID != out.ID || ref.SHA256 != Hash(out) {
		t.Fatal("issued historical content/full hashes differ")
	}
	if ref.ID == ref.SHA256 {
		t.Fatal("content ID was relabelled as full payload hash")
	}
	pinned := Hash(out)
	f.query.Scope.Resources[0].GitCommit = strings.Repeat("f", 40)
	if Hash(out) != pinned {
		t.Fatal("returned ownership scope aliases caller mutation")
	}
	for _, artifact := range f.artifacts {
		if artifact.Metadata.ReasonCodes[0] != "REMOTE_GIT_HEAD_UNVERIFIED" || artifact.Metadata.Status != "BLOCKED" {
			t.Fatal("point metadata relabelled")
		}
	}
	// Slice an actual continuously chained journal at an independently reviewed
	// interval boundary. Its starting sequence need not be registration genesis.
	f = ownershipTestFixture(t)
	for i := range f.unsigned {
		f.unsigned[i].Sequence += 10
	}
	f.reseal(t)
	if _, err = VerifyDecisionOwnership(context.Background(), f, f.query, f.now); err != nil {
		t.Fatal("reviewed non-genesis chain slice refused", err)
	}
}

func TestDecisionOwnershipPinsIssuedRegistrationTimestampSpelling(t *testing.T) {
	f := ownershipTestFixture(t)
	registration := f.registrations["journal-key"]
	raw, err := json.Marshal(registration)
	if err != nil {
		t.Fatal(err)
	}
	document, ok := documentFromRaw(raw).(map[string]any)
	if !ok {
		t.Fatal("registration document must be an object")
	}
	document["valid_from"] = registration.ValidFrom.Format("2006-01-02T15:04:05.000Z")
	document["valid_until"] = registration.ValidUntil.Format("2006-01-02T15:04:05.000Z")
	issued, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	var projected DecisionOwnershipRegistration
	if err = decodeOwnershipRegistration(issued, &projected); err != nil {
		t.Fatal(err)
	}
	if Hash(projected) == projected.IssuedDocumentSHA256 || projected.IssuedDocumentSHA256 != Hash(document) {
		t.Fatal("issued timestamp spelling was reconstructed from typed time")
	}
	f.registrations[projected.ID] = projected
	evidence, err := VerifyDecisionOwnership(context.Background(), f, f.query, f.now)
	if err != nil || evidence.Status != DecisionOwnershipObserved {
		t.Fatal("equivalent issued registration timestamps refused", err)
	}
	for _, pin := range evidence.RegistrationPins {
		if pin.ID == projected.ID && pin.SHA256 != Hash(document) {
			t.Fatal("publication pin lost actual issued document hash")
		}
	}
}

func TestDecisionOwnershipRejectsSignedGapsScopeBackfillAndSwappedObjects(t *testing.T) {
	cases := map[string]func(*ownershipFixture){
		"gap": func(f *ownershipFixture) {
			f.unsigned[1].Period.Start = f.unsigned[1].Period.Start.Add(time.Minute)
			f.reseal(t)
		},
		"overlap": func(f *ownershipFixture) {
			f.unsigned[1].Period.Start = f.unsigned[1].Period.Start.Add(-time.Minute)
			f.reseal(t)
		},
		"config": func(f *ownershipFixture) {
			f.unsigned[0].Resource.ConfigurationSHA256 = strings.Repeat("e", 64)
			f.reseal(t)
		},
		"native_identity":            func(f *ownershipFixture) { f.unsigned[0].Resource.ProviderResourceID = "i-swapped"; f.reseal(t) },
		"registration_revision":      func(f *ownershipFixture) { f.unsigned[0].RegistrationRevision = 2; f.reseal(t) },
		"serial_with_cached_archive": func(f *ownershipFixture) { f.unsigned[1].StateSerial = 8; f.reseal(t) },
		"archive_version":            func(f *ownershipFixture) { f.unsigned[0].ArchiveRef.VersionID = "swapped-version"; f.reseal(t) },
		"ciphertext":                 func(f *ownershipFixture) { f.ciphers["artifact-0"][0] ^= 1 },
		"deployment_scope": func(f *ownershipFixture) {
			d := f.deployments["deployment-0"]
			d.Resource.ProviderResourceID = "i-unrelated"
			f.deployments["deployment-0"] = d
		},
		"deployment_issuer": func(f *ownershipFixture) {
			d := f.deployments["deployment-0"]
			d.Issuer = "https://other.invalid"
			f.deployments["deployment-0"] = d
		},
		"late_recorded_backfill": func(f *ownershipFixture) {
			f.journals[0].ServerRecordedAt = f.unsigned[0].Period.End.Add(6 * time.Minute)
		},
		"future_recorded": func(f *ownershipFixture) { f.journals[0].ServerRecordedAt = f.now.Add(time.Second) },
		"missing_last":    func(f *ownershipFixture) { f.journals = f.journals[:len(f.journals)-1] },
		"review_period": func(f *ownershipFixture) {
			f.review.Period.Start = f.review.Period.Start.Add(time.Minute)
			f.signReview(t)
		},
		"review_chain_root": func(f *ownershipFixture) { f.review.ChainRootSHA256 = strings.Repeat("e", 64); f.signReview(t) },
		"raw_canonical": func(f *ownershipFixture) {
			f.journals[0].RawEnvelope = append(f.journals[0].RawEnvelope, '\n')
			f.journals[0].Reference.SHA256 = ownershipBytesHash(f.journals[0].RawEnvelope)
		},
		"raw_signature": func(f *ownershipFixture) {
			var e DecisionOwnershipJournalEnvelope
			_ = json.Unmarshal(f.journals[0].RawEnvelope, &e)
			e.Signature = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
			raw, _ := json.Marshal(e)
			f.journals[0].RawEnvelope = raw
			f.journals[0].Reference.SHA256 = ownershipBytesHash(raw)
		},
		"cursor_repeat": func(f *ownershipFixture) { f.repeatCursor = true },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := ownershipTestFixture(t)
			mutate(f)
			out, err := VerifyDecisionOwnership(context.Background(), f, f.query, f.now)
			if !errors.Is(err, ErrDecisionOwnershipEvidence) || out.Status != "UNAVAILABLE" || len(out.Segments) != 0 {
				t.Fatalf("invalid proof acquired history: %s %v", out.Status, err)
			}
			if _, err = out.HistoricalReference(); err == nil {
				t.Fatal("gap acquired historical ref")
			}
		})
	}
}

func TestDecisionOwnershipCommissionIndependenceRevocationAndNoPointInterpolation(t *testing.T) {
	for _, name := range []string{"same_key", "same_subject", "revoked", "revoked_during_io", "new_registration", "expired_review"} {
		t.Run(name, func(t *testing.T) {
			f := ownershipTestFixture(t)
			r := f.registrations["review-key"]
			switch name {
			case "same_key":
				r.PublicKey = f.registrations["journal-key"].PublicKey
				f.reviewKey = f.journalKey
				f.signReview(t)
			case "same_subject":
				r.Subject = f.registrations["journal-key"].Subject
			case "revoked":
				at := f.now
				r.RevokedAt = &at
			case "revoked_during_io":
				f.revokeOnReload = true
			case "new_registration":
				j := f.registrations["journal-key"]
				j.ValidFrom = f.query.Period.Start.Add(time.Minute)
				f.registrations[j.ID] = j
			case "expired_review":
				f.now = f.now.Add(25 * time.Hour)
			}
			f.registrations[r.ID] = r
			out, err := VerifyDecisionOwnership(context.Background(), f, f.query, f.now)
			if err == nil || out.Status != "UNAVAILABLE" || len(out.InputRefs) != 0 {
				t.Fatal("commission boundary bypassed")
			}
		})
	}
	f := ownershipTestFixture(t)
	f.noReview = true
	out, err := VerifyDecisionOwnership(context.Background(), f, f.query, f.now)
	if err != nil || out.Status != "UNAVAILABLE" || f.pageReads != 0 || f.artifactReads != 0 {
		t.Fatal("equal current points invented interval ownership")
	}
	if _, err = out.HistoricalReference(); err == nil {
		t.Fatal("unreviewed artifact points acquired interval ref")
	}
}

func TestDecisionOwnershipCancellationAndBoundedEvidence(t *testing.T) {
	f := ownershipTestFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := VerifyDecisionOwnership(ctx, f, f.query, f.now); !errors.Is(err, context.Canceled) || f.pageReads != 0 {
		t.Fatal("cancelled read continued")
	}
	f = ownershipTestFixture(t)
	ctx, cancel = context.WithCancel(context.Background())
	f.cancelArchive = cancel
	if _, err := VerifyDecisionOwnership(ctx, f, f.query, f.now); !errors.Is(err, context.Canceled) {
		t.Fatal("IO cancellation lost", err)
	}
	f = ownershipTestFixture(t)
	f.query.Scope.Resources = append(f.query.Scope.Resources, f.query.Scope.Resources[1])
	f.query.Scope.ConfigurationSHA256 = DecisionOwnershipConfigurationSHA256(f.query.Scope.Resources)
	if _, err := VerifyDecisionOwnership(context.Background(), f, f.query, f.now); err == nil {
		t.Fatal("duplicate native/internal roster accepted")
	}
}
