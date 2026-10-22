package multicloud

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func publicationFixture(t *testing.T, kind Kind) (RegistrationSnapshot, Snapshot) {
	t.Helper()
	var s Snapshot
	var e error
	var cfg Config
	var r Registration
	switch kind {
	case AzureActual, AzureAmortized, AzureFOCUS:
		r = azureRegistration(kind)
		d := &azureDouble{t: t, r: r}
		cfg = config(r, d.transport)
		s, e = (AzureReader{Config: cfg}).Collect(context.Background(), r, AzureRequest{})
	default:
		r = gcpRegistration(kind)
		d := &gcpDouble{t: t, r: r}
		cfg = config(r, d.transport)
		s, e = (GCPReader{Config: cfg}).Collect(context.Background(), r, Period{testNow.Add(-14 * 24 * time.Hour), testNow.Add(-time.Hour)})
	}
	if e != nil {
		t.Fatal(e)
	}
	reg, e := PrivateRegistration(r, cfg.Binding)
	if e != nil {
		t.Fatal(e)
	}
	return reg, s
}

type publicationMemoryRepo struct {
	reg       RegistrationSnapshot
	job       *PublicationJob
	stages    map[string]PublicationCheckpoint
	receipt   *PublicationReceipt
	failStage string
	revoked   bool
}

func (m *publicationMemoryRepo) Register(_ context.Context, r RegistrationSnapshot) error {
	m.reg = r
	return nil
}
func (m *publicationMemoryRepo) Current(_ context.Context, tenant, id string) (RegistrationSnapshot, error) {
	if m.revoked || m.reg.Registration.TenantID != tenant || m.reg.Registration.ID != id {
		return RegistrationSnapshot{}, ErrPublicationInactive
	}
	return m.reg, nil
}
func (m *publicationMemoryRepo) Prepare(_ context.Context, r RegistrationSnapshot, key string, manifest PublicationManifest) (PublicationJob, bool, error) {
	if m.job != nil {
		if m.job.Key != key || Hash(m.job.Manifest) != Hash(manifest) {
			return PublicationJob{}, false, ErrPublicationConflict
		}
		return *m.job, true, nil
	}
	m.job = &PublicationJob{ID: "job-1", Key: key, Manifest: manifest, CreatedAt: testNow}
	return *m.job, false, nil
}
func (m *publicationMemoryRepo) Job(_ context.Context, tenant, id string) (PublicationJob, error) {
	if m.job == nil || m.job.ID != id || m.reg.Registration.TenantID != tenant {
		return PublicationJob{}, errors.New("job missing")
	}
	return *m.job, nil
}
func (m *publicationMemoryRepo) Checkpoints(context.Context, string, string) ([]PublicationCheckpoint, error) {
	out := []PublicationCheckpoint{}
	for _, stage := range []string{"RAW_ARCHIVED", "CANONICAL_ARCHIVED", "ANALYTICS_PERSISTED"} {
		if c, ok := m.stages[stage]; ok {
			out = append(out, c)
		}
	}
	return out, nil
}
func (m *publicationMemoryRepo) Checkpoint(_ context.Context, _, _ string, c PublicationCheckpoint) error {
	if m.failStage == c.Stage {
		m.failStage = ""
		return errors.New("simulated process termination before checkpoint")
	}
	if old, ok := m.stages[c.Stage]; ok && Hash(old) != Hash(c) {
		return ErrPublicationConflict
	}
	if m.stages == nil {
		m.stages = map[string]PublicationCheckpoint{}
	}
	m.stages[c.Stage] = c
	return nil
}
func (m *publicationMemoryRepo) Publish(context.Context, string, string) (PublicationReceipt, bool, error) {
	if m.revoked {
		return PublicationReceipt{}, false, ErrPublicationInactive
	}
	if len(m.stages) != 3 {
		return PublicationReceipt{}, false, errors.New("incomplete")
	}
	if m.receipt != nil {
		return *m.receipt, true, nil
	}
	m.receipt = &PublicationReceipt{ID: "receipt-1", JobID: m.job.ID, Manifest: m.job.Manifest, Sequence: 1, CreatedAt: testNow, ActiveSource: true, IsCurrent: true}
	return *m.receipt, false, nil
}
func (m *publicationMemoryRepo) Revoke(context.Context, string, string, int64, string) error {
	m.revoked = true
	return nil
}

type publicationMemoryArchive struct {
	objects     map[string][]byte
	puts        int
	tamper      bool
	unversioned bool
}

func (a *publicationMemoryArchive) Put(_ context.Context, tenant, job, kind string, raw []byte) (ArchiveRef, error) {
	a.puts++
	if a.objects == nil {
		a.objects = map[string][]byte{}
	}
	key := "tenant/" + tenant + "/multicloud/" + job + "/" + kind + "/" + BytesHash(raw)
	version := fmt.Sprint(a.puts)
	if a.unversioned {
		version = ""
	}
	a.objects[key+":"+version] = append([]byte{}, raw...)
	return ArchiveRef{Bucket: "private-fixture", Key: key, VersionID: version, SHA256: BytesHash(raw), Bytes: int64(len(raw))}, nil
}
func (a *publicationMemoryArchive) Read(_ context.Context, _ string, ref ArchiveRef) ([]byte, error) {
	if a.tamper {
		return []byte("tampered"), nil
	}
	raw, ok := a.objects[ref.Key+":"+ref.VersionID]
	if !ok {
		return nil, errors.New("missing version")
	}
	return raw, nil
}

type publicationMemoryFacts struct {
	populations map[string]FactPopulation
	writes      int
	fail        bool
	tamper      bool
}

func (f *publicationMemoryFacts) Write(_ context.Context, p FactPopulation) (FactAck, error) {
	f.writes++
	if f.fail {
		return FactAck{}, errors.New("warehouse unavailable")
	}
	ack := factsAck(p, "fixture", "multicloud_population")
	if f.populations == nil {
		f.populations = map[string]FactPopulation{}
	}
	f.populations[ack.PopulationID] = p
	return ack, nil
}
func (f *publicationMemoryFacts) Readback(_ context.Context, ack FactAck) (FactAck, error) {
	p, ok := f.populations[ack.PopulationID]
	if !ok {
		return FactAck{}, errors.New("population missing")
	}
	if f.tamper {
		ack.RecordCount++
		return ack, nil
	}
	if factsAck(p, ack.Database, ack.Table) != ack {
		return FactAck{}, errors.New("changed population")
	}
	return ack, nil
}

func TestPublicationReDerivesAllNativeFamiliesAndRejectsUploads(t *testing.T) {
	for _, kind := range []Kind{AzureActual, AzureAmortized, AzureFOCUS, GCPDetailed, GCPPricing, GCPCommitments} {
		t.Run(string(kind), func(t *testing.T) {
			reg, s := publicationFixture(t, kind)
			manifest, canonical, facts, e := PublicationContent(reg, s)
			if e != nil {
				t.Fatal(e)
			}
			if manifest.Status != "PROVISIONAL" || manifest.CanonicalSHA256 != BytesHash(canonical) || manifest.FactHash != Hash(facts) || manifest.RecordCount != int64(len(s.Records)) || !hasReason(manifest.ReasonCodes, "VM_INCARNATION_ALLOCATION_UNPROVEN") {
				t.Fatalf("bad provisional content: %+v", manifest)
			}
			// Even a freshly rehashed caller snapshot cannot substitute monetary values.
			value := "987.654"
			s.Records[0].BilledCost = &value
			s = seal(s)
			_, _, _, e = PublicationContent(reg, s)
			wantError(t, e, "CANONICAL_NATIVE_VALUES_CHANGED")
			uploaded := CustomerImport(reg.Registration, s.Records, testNow)
			_, _, _, e = PublicationContent(reg, uploaded)
			wantError(t, e, "SNAPSHOT_BINDING_INVALID")
		})
	}
}
func TestPublicationRestartsAtDurableStagesAndRevalidatesPinnedEvidence(t *testing.T) {
	for _, failStage := range []string{"RAW_ARCHIVED", "CANONICAL_ARCHIVED", "ANALYTICS_PERSISTED"} {
		t.Run(failStage, func(t *testing.T) {
			reg, s := publicationFixture(t, GCPDetailed)
			repo := &publicationMemoryRepo{reg: reg, failStage: failStage}
			archive := &publicationMemoryArchive{}
			facts := &publicationMemoryFacts{}
			p := &PublicationPipeline{repo, archive, facts}
			if _, _, e := p.Publish(context.Background(), reg, s, "query-1"); e == nil {
				t.Fatal("expected interrupted stage")
			}
			if repo.receipt != nil {
				t.Fatal("published before all stages")
			}
			before := archive.puts
			// A different pipeline process reconstructs from persisted job/checkpoints.
			p = &PublicationPipeline{repo, archive, facts}
			receipt, replay, e := p.Publish(context.Background(), reg, s, "query-1")
			if e != nil {
				t.Fatal(e)
			}
			if !replay || receipt.ExecutionAuthorized || receipt.VerifiedSaving != nil || len(repo.stages) != 3 {
				t.Fatal("resume created authority or lost checkpoint")
			}
			if failStage == "ANALYTICS_PERSISTED" && archive.puts != before {
				t.Fatal("already acknowledged raw/canonical objects were rewritten")
			}
			oldPuts := archive.puts
			if _, _, e = p.Publish(context.Background(), reg, s, "query-1"); e != nil || archive.puts != oldPuts || len(facts.populations) != 1 {
				t.Fatal("replay duplicated population", e)
			}
			archive.tamper = true
			if _, _, e = p.Publish(context.Background(), reg, s, "query-1"); e == nil {
				t.Fatal("replayed corrupt immutable object")
			}
		})
	}
}
func TestPublicationNoReceiptForUnversionedArchiveOrChangedAnalytics(t *testing.T) {
	for _, test := range []struct {
		name                           string
		unversioned, tampered, failure bool
	}{{"no-version", true, false, false}, {"warehouse-readback", false, true, false}, {"warehouse-failure", false, false, true}} {
		t.Run(test.name, func(t *testing.T) {
			reg, s := publicationFixture(t, AzureActual)
			repo := &publicationMemoryRepo{reg: reg}
			p := PublicationPipeline{repo, &publicationMemoryArchive{unversioned: test.unversioned}, &publicationMemoryFacts{tamper: test.tampered, fail: test.failure}}
			if _, _, e := p.Publish(context.Background(), reg, s, "run-1"); e == nil {
				t.Fatal("accepted unpersisted/changed evidence")
			}
			if repo.receipt != nil {
				t.Fatal("receipt escaped readback gates")
			}
		})
	}
}
func TestPublicationDatabaseTransportDefaultsFailClosed(t *testing.T) {
	for _, dsn := range []string{"postgres://user:not-a-secret@postgres/db?sslmode=disable", "postgres://user:not-a-secret@postgres/db?sslmode=prefer", "postgres://user:not-a-secret@postgres/db?sslmode=require", "postgres://user:not-a-secret@postgres/db?sslmode=verify-ca"} {
		if repo, e := OpenPublicationRepository(context.Background(), dsn); e == nil {
			repo.Pool.Close()
			t.Fatal("non-fixture publication database accepted unverified transport")
		}
	}
	if _, e := OpenPublicationRepository(context.Background(), "postgres://user:not-a-secret@customer.example/db?sslmode=disable", PublicationDatabaseOptions{Fixture: true}); e == nil {
		t.Fatal("fixture database option accepted a customer endpoint")
	}
}
func TestEconomicMultisetPreservesMultiplicityAndIgnoresQueryOrdinals(t *testing.T) {
	reg, s := publicationFixture(t, GCPDetailed)
	original := economicPopulation(reg, s.Period, s.Records)
	shuffled := append([]Record{}, s.Records...)
	for i := range shuffled {
		shuffled[i].ID = fmt.Sprintf("new-query#%d", i)
		shuffled[i].Native = Document{}
		for k, v := range s.Records[i].Native {
			shuffled[i].Native[k] = v
		}
		if _, ok := shuffled[i].Native["parent_row_id"]; ok {
			shuffled[i].Native["parent_row_id"] = "new-query#0"
		}
	}
	shuffled[0], shuffled[2] = shuffled[2], shuffled[0]
	again := economicPopulation(reg, s.Period, shuffled)
	if Hash(original) != Hash(again) {
		t.Fatal("volatile query/row identity changes economic spend")
	}
	doubled := economicPopulation(reg, s.Period, append(shuffled, shuffled[0]))
	if doubled.RecordCount != original.RecordCount+1 || doubled.EconomicHash == original.EconomicHash {
		t.Fatal("duplicate native rows lost their economic multiplicity")
	}
	var count int64
	for _, row := range doubled.Rows {
		count += row.Multiplicity
	}
	if count != doubled.RecordCount {
		t.Fatal("multiset does not conserve native rows")
	}
	value := "0.123456789012345678901234567890"
	missing := Record{Kind: GCPDetailed, ID: "missing", MappingGaps: []string{}, Native: Document{}}
	precise := missing
	precise.ID = "precise"
	precise.BilledCost = &value
	zero := "0"
	genuineZero := missing
	genuineZero.ID = "zero"
	genuineZero.BilledCost = &zero
	p := economicPopulation(reg, s.Period, []Record{missing, precise, genuineZero})
	for _, row := range p.Rows {
		switch {
		case row.Native.BilledCost == nil:
			if row.BilledDecimal != nil {
				t.Fatal("missing money became zero")
			}
		case *row.Native.BilledCost == value:
			if row.BilledDecimal != nil || len(row.ProjectionGaps) == 0 || *row.Native.BilledCost != value {
				t.Fatal("high precision money rounded")
			}
		case *row.Native.BilledCost == "0":
			if row.BilledDecimal == nil || strings.Trim(*row.BilledDecimal, "0.") != "" {
				t.Fatal("genuine zero lost")
			}
		}
	}
}
