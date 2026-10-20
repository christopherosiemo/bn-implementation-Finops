package commitmentarchive

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	portfolio "github.com/christopherosiemo/bn-implementation-Finops/internal/commitmentportfolio"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
)

// These are transport doubles only. They do not issue database receipts or
// claim signed provenance, historical coverage or financial authority.
func archiveWindowFixture(t *testing.T, count int) (*archiveObjectWindow, portfolio.DecisionOwnershipArchiveRegistration, map[string][]byte) {
	t.Helper()
	pins := []portfolio.DecisionOwnershipArchiveObjectPin{}
	raw := map[string][]byte{}
	for i := 0; i < count; i++ {
		key := fmt.Sprintf("history/%03d.json", i)
		body := []byte(fmt.Sprintf(`{"transport_fixture":%d}`, i))
		raw[key] = body
		pins = append(pins, portfolio.DecisionOwnershipArchiveObjectPin{Key: key, VersionID: fmt.Sprintf("version-%d", i), SHA256: source.BytesHash(body), Bytes: int64(len(body))})
	}
	w, err := newArchiveObjectWindow(pins)
	if err != nil {
		t.Fatal(err)
	}
	reg := portfolio.DecisionOwnershipArchiveRegistration{ID: "source-one", TenantID: "tenant-one", Prefix: "history/", IssuedDocumentSHA256: source.BytesHash([]byte("registered-source"))}
	w.lookup = func(context.Context, portfolio.DecisionOwnershipArchiveRegistration, portfolio.DecisionOwnershipArchiveObjectPin) (provider.BillingObject, bool, error) {
		return provider.BillingObject{}, false, nil
	}
	w.read = func(_ context.Context, _ portfolio.DecisionOwnershipArchiveRegistration, p portfolio.DecisionOwnershipArchiveObjectPin) (provider.BillingObject, error) {
		return provider.BillingObject{Key: p.Key, VersionID: p.VersionID, Data: raw[p.Key]}, nil
	}
	w.write = func(_ context.Context, tenant, id string, body []byte) (model.Document, error) {
		h := source.BytesHash(body)
		return model.Document{"bucket": "app-evidence", "key": "tenant/" + tenant + "/commitment-ownership-archive/" + id + "/" + h + ".json", "version_id": "read-back-version", "body_sha256": h}, nil
	}
	return w, reg, raw
}

func TestArchiveWindowOverlapsOnlyFourRawTransportsAndReusesExactReadbacks(t *testing.T) {
	w, reg, raw := archiveWindowFixture(t, 8)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	gate := make(chan struct{})
	var entered, active, maximum, reads, writes atomic.Int32
	read := w.read
	w.read = func(ctx context.Context, r portfolio.DecisionOwnershipArchiveRegistration, p portfolio.DecisionOwnershipArchiveObjectPin) (provider.BillingObject, error) {
		n := active.Add(1)
		defer active.Add(-1)
		for old := maximum.Load(); n > old && !maximum.CompareAndSwap(old, n); old = maximum.Load() {
		}
		reads.Add(1)
		if entered.Add(1) == archiveObjectWindowSize {
			close(gate)
		}
		select {
		case <-gate:
		case <-ctx.Done():
			return provider.BillingObject{}, ctx.Err()
		}
		return read(ctx, r, p)
	}
	write := w.write
	w.write = func(ctx context.Context, tenant, id string, body []byte) (model.Document, error) {
		writes.Add(1)
		return write(ctx, tenant, id, body)
	}
	for _, p := range w.pins {
		value, err := w.object(ctx, reg, p)
		if err != nil || string(value.Data) != string(raw[p.Key]) {
			t.Fatal("exact original object unavailable", err)
		}
		ref, err := w.mirror(ctx, reg.TenantID, reg.ID, value.Data)
		if err != nil || model.String(ref, "body_sha256") != p.SHA256 || model.String(ref, "version_id") != "read-back-version" {
			t.Fatal("the exact completed readback was not reused", err)
		}
		if _, err = w.mirror(ctx, "other-tenant", reg.ID, value.Data); err == nil {
			t.Fatal("foreign tenant reused a mirror")
		}
		if _, err = w.mirror(ctx, reg.TenantID, reg.ID, []byte("altered")); err == nil {
			t.Fatal("altered bytes reused a mirror")
		}
	}
	if maximum.Load() != archiveObjectWindowSize || active.Load() != 0 || reads.Load() != 8 || writes.Load() != 8 || len(w.values) > archiveObjectWindowSize {
		t.Fatal("raw overlap, exact work count or bounded window changed")
	}
	last := w.pins[len(w.pins)-1]
	changed := last
	changed.VersionID = "changed-version"
	if _, err := w.object(ctx, reg, changed); err == nil {
		t.Fatal("changed selector was accepted")
	}
	if _, err := w.mirror(ctx, reg.TenantID, reg.ID, raw[last.Key]); err == nil {
		t.Fatal("failed selection retained a previous active readback")
	}
}

func TestArchiveWindowRetainsIssuedReplayAndRefusesSelectorOrSourceChanges(t *testing.T) {
	w, reg, raw := archiveWindowFixture(t, 4)
	var reads atomic.Int32
	read := w.read
	w.read = func(ctx context.Context, r portfolio.DecisionOwnershipArchiveRegistration, p portfolio.DecisionOwnershipArchiveObjectPin) (provider.BillingObject, error) {
		reads.Add(1)
		return read(ctx, r, p)
	}
	w.lookup = func(_ context.Context, _ portfolio.DecisionOwnershipArchiveRegistration, p portfolio.DecisionOwnershipArchiveObjectPin) (provider.BillingObject, bool, error) {
		return provider.BillingObject{Key: p.Key, VersionID: p.VersionID, Data: raw[p.Key]}, true, nil
	}
	for _, p := range w.pins {
		if _, err := w.object(context.Background(), reg, p); err != nil {
			t.Fatal(err)
		}
		if _, err := w.mirror(context.Background(), reg.TenantID, reg.ID, raw[p.Key]); err == nil {
			t.Fatal("issued replay incorrectly requested a new raw mirror")
		}
	}
	if reads.Load() != 0 {
		t.Fatal("issued replay was fetched again")
	}
	changed := w.pins[0]
	changed.SHA256 = source.BytesHash([]byte("changed"))
	if _, err := w.object(context.Background(), reg, changed); err == nil {
		t.Fatal("changed native pin was accepted")
	}
	reg.TenantID = "other-tenant"
	if _, err := w.object(context.Background(), reg, w.pins[0]); err == nil {
		t.Fatal("window crossed a registered source binding")
	}
}

func TestArchiveWindowRejectsAlteredTransportAndDrainsCancelledWorkers(t *testing.T) {
	w, reg, _ := archiveWindowFixture(t, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var active atomic.Int32
	w.read = func(ctx context.Context, _ portfolio.DecisionOwnershipArchiveRegistration, _ portfolio.DecisionOwnershipArchiveObjectPin) (provider.BillingObject, error) {
		active.Add(1)
		defer active.Add(-1)
		cancel()
		<-ctx.Done()
		return provider.BillingObject{}, ctx.Err()
	}
	if _, err := w.object(ctx, reg, w.pins[0]); err == nil || active.Load() != 0 || len(w.values) != 0 {
		t.Fatal("cancelled window leaked workers or published partial readbacks")
	}
	w, reg, _ = archiveWindowFixture(t, 4)
	read := w.read
	w.read = func(ctx context.Context, r portfolio.DecisionOwnershipArchiveRegistration, p portfolio.DecisionOwnershipArchiveObjectPin) (provider.BillingObject, error) {
		v, err := read(ctx, r, p)
		v.VersionID = "wrong-version"
		return v, err
	}
	if _, err := w.object(context.Background(), reg, w.pins[0]); err == nil || len(w.values) != 0 {
		t.Fatal("wrong original version was accepted")
	}
}
