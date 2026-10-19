package fleetcapacityworker

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	a "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetassessment"
	archive "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetassessmentworker"
	b "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetbilling"
	c "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetcapacity"
	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/native"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func testConfig() Config {
	return Config{Archive: archive.Config{Enabled: true, TenantID: "tenant", DatabaseFile: "/run/secrets/database", ArchiveMode: archive.LocalArchive, ArchiveRegion: "eu-west-1", ArchiveEndpoint: "http://minio:9000", ArchiveBucket: "fixture-raw", ArchiveAccessKeyFile: "/run/secrets/access", ArchiveSecretKeyFile: "/run/secrets/secret"}, ServiceMode: PrivateServices, ReaderURL: "http://telemetry-reader:8095", ReaderTokenFile: "/run/secrets/reader", ModelURL: "http://economics:8000", ModelTokenFile: "/run/secrets/model"}
}
func testScope() c.ScopeCapture {
	selection := func(name, suffix string) g.Selection {
		return g.Selection{Target: g.GroupTarget{TenantID: "tenant", WorkloadID: "workload", Provider: "AWS", AccountID: "111122223333", Region: "eu-west-1", FleetID: name, ASGARN: "arn:aws:autoscaling:eu-west-1:111122223333:autoScalingGroup:00000000-0000-4000-8000-00000000000" + suffix + ":autoScalingGroupName/" + name}, Registration: g.VersionedRef{ID: name + "-registration", Version: 1, SHA256: strings.Repeat("a", 64)}, Declaration: g.VersionedRef{ID: name + "-declaration", Version: 1, SHA256: strings.Repeat("b", 64)}, Scope: g.SnapshotRef{ID: name + "-scope", SHA256: strings.Repeat("c", 64)}, SourceID: "source", SourceRegistrationVersion: 1, SourceConfigSHA256: strings.Repeat("d", 64)}
	}
	s := c.ScopeCapture{SchemaVersion: "1", RequestID: "request", Scope: c.Scope{Selection: a.Selection{Groups: b.GroupSelection{OldProposal: g.SnapshotRef{ID: "old-proposal", SHA256: strings.Repeat("e", 64)}, CandidateProposal: g.SnapshotRef{ID: "candidate-proposal", SHA256: strings.Repeat("f", 64)}, Binding: g.Binding{Old: selection("old", "1"), Candidate: selection("candidate", "2")}}, SafetyProfile: g.VersionedRef{ID: "profile", Version: 1, SHA256: strings.Repeat("a", 64)}}, PopulationStatus: "OBSERVED_POINT", ObservedAt: time.Now().Add(-time.Hour).UTC(), CurrentMemberIDs: []string{"i-0123456789abcdef0", "i-22222222222222222"}, MembershipPins: []b.GroupNativePin{{ReceiptID: "old-membership", RevisionID: "revision", ReceiptSHA256: strings.Repeat("a", 64), RawSHA256: strings.Repeat("b", 64), ReceiptVersionID: "version", RevisionVersionID: "version"}}}, SourcePins: []b.GroupNativePin{}, ReasonCodes: []string{"CAPACITY_CANDIDATE_NATIVE_TEMPLATE_UNAVAILABLE"}}
	s.Scope.SnapshotSHA256 = c.ScopeHash(s)
	return s
}

type fakeRepository struct {
	scopeDoc                                                 c.ScopeCapture
	requestDoc                                               model.Document
	stored                                                   []model.Document
	appendCalls, completeCalls, locks, unlocks, resolveCalls int
	failAt                                                   int
	busy                                                     bool
	faults                                                   map[string]error
	missingScope, currentInputs                              bool
	resolveDoc                                               model.Document
}

func (r *fakeRepository) lock(context.Context, string, string) (func(), error) {
	r.locks++
	if r.busy {
		return nil, ErrBusy
	}
	return func() { r.unlocks++ }, nil
}
func (r *fakeRepository) request(context.Context, string, string) (model.Document, error) {
	return r.requestDoc, r.faults["request"]
}
func (r *fakeRepository) pending(context.Context, string, string) ([]model.Document, error) {
	return []model.Document{r.requestDoc}, r.faults["pending"]
}
func (r *fakeRepository) resolve(context.Context, string, string) (model.Document, error) {
	r.resolveCalls++
	if e := r.faults["resolve"]; e != nil {
		return nil, e
	}
	if r.resolveDoc != nil {
		return r.resolveDoc, nil
	}
	return nil, errors.New("unexpected current native resolution")
}
func (r *fakeRepository) scope(context.Context, string, string) (model.Document, error) {
	if e := r.faults["scope"]; e != nil {
		return nil, e
	}
	if r.missingScope {
		return nil, pgx.ErrNoRows
	}
	return document(r.scopeDoc), nil
}
func (r *fakeRepository) scopeAppend(context.Context, string, string, string, model.Document) (model.Document, error) {
	if e := r.faults["scopeAppend"]; e != nil {
		return nil, e
	}
	return nil, ErrJob
}
func (r *fakeRepository) evidence(context.Context, string, string) (model.Document, error) {
	if e := r.faults["evidence"]; e != nil {
		return nil, e
	}
	return nil, errors.New("unexpected old candidate readback")
}
func (r *fakeRepository) members(_ context.Context, _, _, after string) ([]model.Document, error) {
	if e := r.faults["members"]; e != nil {
		return nil, e
	}
	out := []model.Document{}
	for _, d := range r.stored {
		if model.String(d, "id") > after {
			out = append(out, d)
		}
	}
	return out, nil
}
func (r *fakeRepository) inputs(_ context.Context, _, _, instance string) (model.Document, error) {
	return model.Document{"scope_record": r.scopeDoc, "instance_id": instance, "current": r.currentInputs, "reason_codes": []string{"FLEET_CAPACITY_SCOPE_NOT_CURRENT"}, "resource": nil, "connection": nil, "hardware": nil, "profile": nil}, r.faults["inputs"]
}
func (r *fakeRepository) append(_ context.Context, _, _, hash string, in model.Document) (model.Document, error) {
	r.appendCalls++
	if e := r.faults["append"]; e != nil {
		return nil, e
	}
	if r.appendCalls == r.failAt {
		return nil, errors.New("publication refused")
	}
	want, _ := r.inputs(context.Background(), "", "", model.String(in, "instance_id"))
	if b.Hash(want) != hash {
		return nil, ErrJob
	}
	summary := model.Document{"id": in["id"], "instance_id": in["instance_id"], "sha256": b.Hash(in), "status": in["status"], "model_evaluated": in["model_evaluated"], "capacity_suitable": in["capacity_suitable"]}
	r.stored = append(r.stored, summary)
	return model.Document{"id": in["id"], "instance_id": in["instance_id"], "sha256": b.Hash(in), "member": in}, nil
}
func (r *fakeRepository) complete(_ context.Context, _, _ string, in model.Document) (model.Document, bool, error) {
	r.completeCalls++
	if e := r.faults["complete"]; e != nil {
		return nil, false, e
	}
	var summary c.BatchResult
	if decode(in, &summary) != nil || len(summary.Members) != 2 || summary.Coverage != "PARTIAL" {
		return nil, false, ErrJob
	}
	r.requestDoc["batch"] = in
	return r.requestDoc, false, nil
}

type neverArchive struct{ calls int }

func (a *neverArchive) ReadPinned(context.Context, string, model.Document) (b.PinnedObject, error) {
	a.calls++
	return b.PinnedObject{}, errors.New("unexpected archive read")
}

type neverReader struct{ calls int }

func (r *neverReader) Read(context.Context, native.CapacityInputRequest) (native.CapacityPopulation, error) {
	r.calls++
	return native.CapacityPopulation{}, ErrJob
}

type neverModel struct{ calls int }

func (m *neverModel) Calculate(context.Context, native.CapacityModelRequest) ([]byte, error) {
	m.calls++
	return nil, ErrJob
}
func fakeWorker() (*Worker, *fakeRepository, *neverArchive, *neverReader, *neverModel) {
	s := testScope()
	r := &fakeRepository{scopeDoc: s, requestDoc: model.Document{"id": "request", "selection": s.Scope.Selection, "batch": nil}}
	a, p, m := &neverArchive{}, &neverReader{}, &neverModel{}
	return &Worker{config: testConfig(), repository: r, archive: a, population: p, calculator: m}, r, a, p, m
}

func TestWorkerResumesIssuedPopulationAfterRevocationWithoutInventingFacts(t *testing.T) {
	w, r, a, p, m := fakeWorker()
	// Historical native template metadata exists, but a revoked member must
	// finish as a gap without depending on its old archive's availability.
	r.scopeDoc.CandidateTemplate = &c.CandidateTemplate{ID: "lt-0123456789abcdef0", Version: "2", DefinitionSHA256: strings.Repeat("a", 64)}
	r.scopeDoc.Scope.SnapshotSHA256 = c.ScopeHash(r.scopeDoc)
	r.failAt = 2
	if _, e := w.Process(context.Background(), "request"); e == nil || len(r.stored) != 1 || r.completeCalls != 0 || r.unlocks != 1 {
		t.Fatal("failed publication lost resumable member", e)
	}
	r.failAt = 0
	out, e := w.Process(context.Background(), "request")
	if e != nil || out.Members != 2 || r.appendCalls != 3 || r.completeCalls != 1 || r.resolveCalls != 0 || r.locks != 2 || r.unlocks != 2 {
		t.Fatal("resume duplicated member or refreshed historical scope", e, out)
	}
	for _, d := range r.stored {
		if model.Bool(d, "model_evaluated") || d["capacity_suitable"] != nil || model.String(d, "status") != "UNAVAILABLE" {
			t.Fatal("gap manufactured member capacity")
		}
	}
	if a.calls+p.calls+m.calls != 0 {
		t.Fatal("revoked gap read external evidence")
	}
	replay, e := w.Process(context.Background(), "request")
	if e != nil || !replay.Existing || r.completeCalls != 1 || r.appendCalls != 3 || a.calls+p.calls+m.calls != 0 {
		t.Fatal("cached result borrowed new evidence", e)
	}
}
func TestWorkerRejectsForeignScopeAndSerializesJobBeforeAnyReadback(t *testing.T) {
	w, r, a, p, m := fakeWorker()
	r.busy = true
	if _, e := w.Process(context.Background(), "request"); !errors.Is(e, ErrBusy) {
		t.Fatal("overlapping worker admitted")
	}
	r.busy = false
	r.scopeDoc.Scope.Selection.Groups.Binding.Old.Target.TenantID = "foreign"
	if _, e := w.Process(context.Background(), "request"); e == nil {
		t.Fatal("foreign immutable scope accepted")
	}
	if a.calls+p.calls+m.calls+r.appendCalls+r.completeCalls != 0 {
		t.Fatal("invalid selection performed work")
	}
}
func TestSnapshotDocumentHashPreservesDecimalVersionsAndTypedCandidate(t *testing.T) {
	s := testScope()
	s.CandidateTemplate = &c.CandidateTemplate{ID: "lt-0123456789abcdef0", Version: "9007199254740993"}
	s.Scope.SnapshotSHA256 = c.ScopeHash(s)
	doc := document(s)
	var roundtrip c.ScopeCapture
	if decode(doc, &roundtrip) != nil || roundtrip.CandidateTemplate.Version != "9007199254740993" || b.Hash(roundtrip) != b.Hash(doc) || c.ScopeHash(roundtrip) != s.Scope.SnapshotSHA256 {
		t.Fatal("typed/current projection hash or version changed")
	}
}

func TestRepositoryContentionKeepsNormalPollRetryWithoutMaskingRefusals(t *testing.T) {
	for _, boundary := range []string{"request", "scope", "resolve", "scopeAppend", "members", "inputs", "evidence", "append", "complete"} {
		for _, failure := range []struct {
			name string
			err  error
			busy bool
		}{
			{"typed_busy", fmt.Errorf("source guard: %w", store.ErrFleetFixtureBusy), true},
			{"permission", &pgconn.PgError{Code: "42501", Message: "permission denied"}, false},
			{"integrity", &pgconn.PgError{Code: "23514", Message: "constraint refused"}, false},
			{"text_is_not_identity", errors.New(store.ErrFleetFixtureBusy.Error()), false},
		} {
			t.Run(boundary+"/"+failure.name, func(t *testing.T) {
				w, r, a, p, m := fakeWorker()
				r.faults = map[string]error{boundary: failure.err}
				if boundary == "resolve" || boundary == "scopeAppend" {
					r.missingScope = true
					r.resolveDoc = document(selectionSnapshot{Selection: r.scopeDoc.Scope.Selection})
				}
				if boundary == "evidence" {
					r.currentInputs = true
					r.scopeDoc.CandidateTemplate = &c.CandidateTemplate{ID: "lt-0123456789abcdef0", Version: "2"}
					r.scopeDoc.Scope.SnapshotSHA256 = c.ScopeHash(r.scopeDoc)
				}
				before := time.Now()
				out, err := w.Poll(context.Background())
				if err != nil || out.Completed != 0 || r.locks != r.unlocks || a.calls+p.calls+m.calls != 0 {
					t.Fatal("repository refusal performed external work or lost lock", out, err)
				}
				if failure.busy {
					if out.Busy != 1 || out.Failed != 0 || len(w.retry) != 0 {
						t.Fatal("typed source contention received generic minute backoff", out, w.retry)
					}
					if next, err := w.Poll(context.Background()); err != nil || next.Busy != 1 || r.locks != 2 || len(w.retry) != 0 {
						t.Fatal("busy request was not eligible on next ordinary poll", next, err)
					}
				} else {
					until := w.retry["request"]
					if out.Busy != 0 || out.Failed != 1 || until.Before(before.Add(time.Minute)) || until.After(time.Now().Add(time.Minute)) {
						t.Fatal("permission/integrity error gained contention retry", out, until)
					}
					if next, err := w.Poll(context.Background()); err != nil || next.Failed != 0 || r.locks != 1 {
						t.Fatal("generic refusal lost existing minute backoff", next, err)
					}
				}
			})
		}
	}
}

func TestPendingRepositoryContentionDoesNotBecomeGenericFailure(t *testing.T) {
	for _, failure := range []struct {
		err  error
		want error
	}{{fmt.Errorf("pending source guard: %w", store.ErrFleetFixtureBusy), ErrBusy}, {&pgconn.PgError{Code: "42501"}, ErrJob}} {
		w, r, _, _, _ := fakeWorker()
		r.faults = map[string]error{"pending": failure.err}
		if _, err := w.Poll(context.Background()); !errors.Is(err, failure.want) || r.locks != 0 || len(w.retry) != 0 {
			t.Fatal("pending classification changed job admission", err)
		}
	}
}
