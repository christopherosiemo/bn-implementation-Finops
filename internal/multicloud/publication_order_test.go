package multicloud

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func publicationGCPAt(t *testing.T, at time.Time, jobID, cost string, period Period) (RegistrationSnapshot, Snapshot) {
	t.Helper()
	r := gcpRegistration(GCPDetailed)
	native := &gcpDouble{t: t, r: r}
	transport := func(req *http.Request) (*http.Response, error) {
		resp, e := native.transport(req)
		if e != nil {
			return nil, e
		}
		raw, e := io.ReadAll(resp.Body)
		resp.Body.Close()
		if e != nil {
			return nil, e
		}
		d, e := decode(raw)
		if e != nil {
			return nil, e
		}
		if job := obj(d["jobReference"]); len(job) > 0 {
			job["jobId"] = jobID
		}
		for _, x := range list(d["rows"]) {
			fields := list(obj(x)["f"])
			if len(fields) != 1 {
				continue
			}
			cell := obj(fields[0])
			row, e := decode([]byte(str(cell, "v")))
			if e != nil {
				return nil, e
			}
			if v, ok := row["cost"]; ok && !strings.HasPrefix(stringValue(v), "-") {
				row["cost"] = json.Number(cost)
			}
			cell["v"] = string(wire(t, row))
		}
		raw = wire(t, d)
		resp.Body = io.NopCloser(bytes.NewReader(raw))
		resp.ContentLength = int64(len(raw))
		return resp, nil
	}
	cfg := config(r, transport)
	cfg.Now = func() time.Time { return at }
	s, e := (GCPReader{Config: cfg}).Collect(context.Background(), r, period)
	if e != nil {
		t.Fatal(e)
	}
	reg, e := PrivateRegistration(r, cfg.Binding)
	if e != nil {
		t.Fatal(e)
	}
	return reg, s
}
func stringValue(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case json.Number:
		return string(x)
	}
	return ""
}

func TestPublicationNativeOrderingCannotUseCallerCollectionTime(t *testing.T) {
	reg, s := publicationFixture(t, GCPDetailed)
	m, _, _, e := PublicationContent(reg, s)
	if e != nil {
		t.Fatal(e)
	}
	if !m.NativeObservedAt.Equal(testNow.Add(-5 * time.Second)) {
		t.Fatal("native query snapshot timestamp was not used")
	}
	s.ObservedAt = testNow.AddDate(100, 0, 0)
	s = seal(s)
	again, _, _, e := PublicationContent(reg, s)
	if e != nil || !again.NativeObservedAt.Equal(m.NativeObservedAt) {
		t.Fatal("caller observed_at changed native current head ordering", e)
	}
}

func TestPublicationPostgresNativeOrderingOutOfOrderCompletionAndRevival(t *testing.T) {
	pg := publicationPostgres(t)
	ctx := context.Background()
	period := Period{testNow.Add(-14 * 24 * time.Hour), testNow.Add(-time.Hour)}
	reg, old := publicationGCPAt(t, testNow, "query-old", "0.10000000000000001", period)
	if e := pg.repo.Register(ctx, reg); e != nil {
		t.Fatal(e)
	}
	archive := &publicationMemoryArchive{}
	facts := &publicationMemoryFacts{fail: true}
	pipeline := PublicationPipeline{pg.repo, archive, facts}
	if _, _, e := pipeline.Publish(ctx, reg, old, "older-prepared"); e == nil {
		t.Fatal("expected interrupted older observation")
	}
	pending, e := pg.repo.Pending(ctx, "tenant-a", "gcp-source")
	if e != nil || len(pending) != 1 {
		t.Fatal("pending durable observation unavailable", e)
	}
	olderJob := pending[0].ID
	_, newer := publicationGCPAt(t, testNow.Add(time.Minute), "query-newer", "0.7", period)
	facts.fail = false
	newReceipt, _, e := pipeline.Publish(ctx, reg, newer, "newer-completed-first")
	if e != nil {
		t.Fatal(e)
	}
	oldReceipt, _, e := pipeline.Resume(ctx, "tenant-a", olderJob)
	if e != nil {
		t.Fatal(e)
	}
	if oldReceipt.Sequence <= newReceipt.Sequence || oldReceipt.IsCurrent {
		t.Fatal("delayed older completion replaced newer native query")
	}
	history, e := pg.repo.Receipts(ctx, "tenant-a", "gcp-source")
	if e != nil {
		t.Fatal(e)
	}
	var head PublicationReceipt
	for _, r := range history {
		if r.IsCurrent {
			head = r
		}
	}
	if head.ID != newReceipt.ID {
		t.Fatal("native current head reverted to older money")
	}
	// Equal source snapshot times cannot establish which different content is
	// later. Do not settle that ambiguity with publication arrival sequence.
	_, conflict := publicationGCPAt(t, testNow.Add(time.Minute), "query-same-snapshot-conflict", "0.9", period)
	if _, _, e = pipeline.Publish(ctx, reg, conflict, "same-source-time-conflict"); e != nil {
		t.Fatal(e)
	}
	history, e = pg.repo.Receipts(ctx, "tenant-a", "gcp-source")
	if e != nil {
		t.Fatal(e)
	}
	for _, r := range history {
		if r.IsCurrent || r.HeadReasonCode != "NATIVE_OBSERVATION_ORDER_AMBIGUOUS" {
			t.Fatal("ambiguous native correction became current")
		}
	}
	// A genuinely later source query can revive A after B without reusing A's
	// old receipt creation order or appending another economic population.
	_, revived := publicationGCPAt(t, testNow.Add(2*time.Minute), "query-revived", "0.10000000000000001", period)
	revivedReceipt, _, e := pipeline.Publish(ctx, reg, revived, "native-revival")
	if e != nil {
		t.Fatal(e)
	}
	if !revivedReceipt.IsCurrent || revivedReceipt.HeadReasonCode != "" || revivedReceipt.Manifest.PopulationID != oldReceipt.Manifest.PopulationID || len(facts.populations) != 3 {
		t.Fatal("revived source content lost identity or remained ambiguous")
	}
	// An exact old sync replay never changes head order.
	replayed, _, e := pipeline.Publish(ctx, reg, newer, "newer-completed-first")
	if e != nil || replayed.IsCurrent {
		t.Fatal("old sync replay changed current native observation", e)
	}
	otherPeriod := Period{period.Start.Add(-time.Hour), period.End}
	_, other := publicationGCPAt(t, testNow.Add(3*time.Minute), "query-other-period", "0.5", otherPeriod)
	otherReceipt, _, e := pipeline.Publish(ctx, reg, other, "other-period")
	if e != nil || !otherReceipt.IsCurrent {
		t.Fatal("different exact period unavailable", e)
	}
	history, e = pg.repo.Receipts(ctx, "tenant-a", "gcp-source")
	if e != nil {
		t.Fatal(e)
	}
	heads := 0
	for _, r := range history {
		if r.IsCurrent {
			heads++
		}
	}
	if heads != 2 {
		t.Fatal("new exact period hid the prior distinct-period head")
	}
}
