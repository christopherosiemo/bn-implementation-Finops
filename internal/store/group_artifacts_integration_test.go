package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	ff "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetfixture"
	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// These are restricted-role metadata/protocol tests. Artifact bytes are clearly
// labelled doubles, not positive S3 readback, actual Terraform or health proof.
func newGroupArtifactTest(t *testing.T) (*groupJournalTest, g.JournalCommand) {
	t.Helper()
	h := newGroupJournalTest(t)
	raw, e := os.ReadFile(filepath.Join("..", "..", "migrations", "032_group_artifacts.sql"))
	if e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	if e = os.WriteFile(filepath.Join(dir, "032_group_artifacts.sql"), raw, 0600); e != nil {
		t.Fatal(e)
	}
	if e = h.f.admin.Migrate(h.f.ctx, dir); e != nil {
		t.Fatal(e)
	}
	r, head := h.preparing(t, "artifact-command")
	h.f.must("finops_group_ledger", func(tx *Tx) error {
		var e error
		h.cursor, _, e = tx.FleetGroupJournalAppendOriginal(h.f.ctx, h.b.ChainID, h.cursor, r, head)
		return e
	})
	return h, *r.Command
}
func groupArtifactIdentity() FleetGroupPipelineIdentity {
	return FleetGroupPipelineIdentity{"fixture-machine", "https://fixture.example.invalid", "group-pipeline", "finops-group-pipeline"}
}
func groupArtifactRef(t *testing.T, h *groupJournalTest, c g.JournalCommand, id, hash string) ff.ArtifactReference {
	t.Helper()
	var scope groupArtifactScope
	h.f.must("finops_group_pipeline", func(tx *Tx) error {
		var e error
		scope, e = tx.groupArtifactScope(h.f.ctx, h.b.ChainID, c.ID)
		return e
	})
	return ff.ArtifactReference{ID: id, Bucket: "isolated-metadata-test", Key: "tenant/" + h.f.tenant + "/fleet-group-fixture/" + scope.ProposalID + "/" + scope.ProfileGeneration + "/" + id + ".encrypted", VersionID: "actual-version-label-double", SHA256: hash, SizeBytes: 12}
}
func TestGroupArtifactsReplayPaginationRolesAndTenant(t *testing.T) {
	h, c := newGroupArtifactTest(t)
	f := h.f
	ref := groupArtifactRef(t, h, c, "first-capture", strings.Repeat("b", 64))
	var original model.Document
	f.must("finops_group_pipeline", func(tx *Tx) error {
		var replay bool
		var e error
		original, replay, e = tx.GroupArtifactAppend(f.ctx, h.b.ChainID, c.ID, "SAVED_PLAN", groupArtifactIdentity(), ref)
		if replay {
			return errors.New("first capture replayed")
		}
		return e
	})
	f.must("finops_group_pipeline", func(tx *Tx) error {
		d, replay, e := tx.GroupArtifactAppend(f.ctx, h.b.ChainID, c.ID, "SAVED_PLAN", groupArtifactIdentity(), ref)
		if e == nil && (!replay || g.Digest(d) != g.Digest(original)) {
			return errors.New("replay changed immutable capture/time")
		}
		return e
	})
	changed := ref
	changed.VersionID = "different-version"
	f.denied("finops_group_pipeline", func(tx *Tx) error {
		_, _, e := tx.GroupArtifactAppend(f.ctx, h.b.ChainID, c.ID, "SAVED_PLAN", groupArtifactIdentity(), changed)
		return e
	})
	for _, role := range []string{"finops_api", "finops_worker", "finops_signer", "finops_executor", "finops_ingester", "finops_group_fixture"} {
		f.denied(role, func(tx *Tx) error {
			_, e := tx.GroupArtifactGet(f.ctx, h.b.ChainID, c.ID, "SAVED_PLAN", ref.ID)
			return e
		})
		f.denied(role, func(tx *Tx) error {
			_, _, e := tx.GroupArtifactAppend(f.ctx, h.b.ChainID, c.ID, "SAVED_PLAN", groupArtifactIdentity(), ref)
			return e
		})
	}
	f.denied("finops_group_ledger", func(tx *Tx) error {
		_, _, e := tx.GroupArtifactAppend(f.ctx, h.b.ChainID, c.ID, "SAVED_PLAN", groupArtifactIdentity(), ref)
		return e
	})
	for _, role := range []string{"finops_group_pipeline", "finops_group_ledger"} {
		f.must(role, func(tx *Tx) error {
			_, e := tx.GroupArtifactGet(f.ctx, h.b.ChainID, c.ID, "SAVED_PLAN", ref.ID)
			return e
		})
		for _, statement := range []string{`UPDATE public.fleet_group_artifacts SET document=document WHERE tenant_id=$1`, `DELETE FROM public.fleet_group_artifacts WHERE tenant_id=$1`} {
			f.denied(role, func(tx *Tx) error { _, e := tx.Exec(f.ctx, statement, f.tenant); return e })
		}
		if e := f.roles[role].Do(f.ctx, f.tenant+"-other", func(tx *Tx) error {
			rows, e := tx.GroupArtifactPage(f.ctx, h.b.ChainID, c.ID, "SAVED_PLAN", "", 10)
			if e != nil {
				return e
			}
			if len(rows) != 0 {
				return errors.New("foreign artifact page exposed")
			}
			_, e = tx.GroupArtifactGet(f.ctx, h.b.ChainID, c.ID, "SAVED_PLAN", ref.ID)
			if !errors.Is(e, pgx.ErrNoRows) {
				return fmt.Errorf("foreign artifact exposed: %v", e)
			}
			return nil
		}); e != nil {
			t.Fatal(e)
		}
	}
	// More than one page and repeated plaintext SHA are legitimate captures.
	f.must("finops_group_pipeline", func(tx *Tx) error {
		for i := 0; i < 105; i++ {
			r := ref
			r.ID = fmt.Sprintf("health-%03d", i)
			r.Key = strings.TrimSuffix(ref.Key, ref.ID+".encrypted") + r.ID + ".encrypted"
			if _, _, e := tx.GroupArtifactAppend(f.ctx, h.b.ChainID, c.ID, "HEALTH_RECEIPT", groupArtifactIdentity(), r); e != nil {
				return e
			}
		}
		return nil
	})
	f.must("finops_group_ledger", func(tx *Tx) error {
		seen := map[string]bool{}
		after := ""
		for {
			page, e := tx.GroupArtifactPage(f.ctx, h.b.ChainID, c.ID, "HEALTH_RECEIPT", after, 17)
			if e != nil {
				return e
			}
			for _, d := range page {
				a := fleetHistoryDocument(d["artifact"])
				id := model.String(a, "id")
				if seen[id] || id <= after {
					return errors.New("page repeated or misordered capture")
				}
				seen[id] = true
				after = id
			}
			if len(page) < 17 {
				break
			}
		}
		if len(seen) != 105 {
			return fmt.Errorf("page truncated %d captures", len(seen))
		}
		return nil
	})
	var wg sync.WaitGroup
	results := make(chan bool, 2)
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e := f.roles["finops_group_pipeline"].Do(f.ctx, f.tenant, func(tx *Tx) error {
				r := ref
				r.ID = "concurrent"
				r.Key = strings.TrimSuffix(ref.Key, ref.ID+".encrypted") + r.ID + ".encrypted"
				_, replay, e := tx.GroupArtifactAppend(f.ctx, h.b.ChainID, c.ID, "PLAN_JSON", groupArtifactIdentity(), r)
				if e == nil {
					results <- replay
				}
				return e
			})
			errs <- e
		}()
	}
	wg.Wait()
	close(results)
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	replays := 0
	for replay := range results {
		if replay {
			replays++
		}
	}
	if replays != 1 {
		t.Fatalf("concurrent replay count %d", replays)
	}
}

func TestGroupArtifactsRejectForgedScopeObjectAndMachine(t *testing.T) {
	h, c := newGroupArtifactTest(t)
	f := h.f
	ref := groupArtifactRef(t, h, c, "capture", strings.Repeat("b", 64))
	for _, change := range []func(*FleetGroupPipelineIdentity){func(i *FleetGroupPipelineIdentity) { i.SourceID = "wrong-source" }, func(i *FleetGroupPipelineIdentity) { i.Issuer = "https://other.invalid" }, func(i *FleetGroupPipelineIdentity) { i.Subject = "human" }, func(i *FleetGroupPipelineIdentity) { i.Audience = "console" }} {
		i := groupArtifactIdentity()
		change(&i)
		f.denied("finops_group_pipeline", func(tx *Tx) error {
			_, _, e := tx.GroupArtifactAppend(f.ctx, h.b.ChainID, c.ID, "SAVED_PLAN", i, ref)
			return e
		})
	}
	for _, change := range []func(*ff.ArtifactReference){func(r *ff.ArtifactReference) { r.Key = "tenant/foreign/object" }, func(r *ff.ArtifactReference) {
		r.Key = strings.ReplaceAll(r.Key, "/fleet-group-fixture/", "/fleet-history/")
	}, func(r *ff.ArtifactReference) { r.VersionID = "" }, func(r *ff.ArtifactReference) { r.VersionID = "null" }, func(r *ff.ArtifactReference) { r.VersionID = "v\n" }, func(r *ff.ArtifactReference) { r.SHA256 = "wrong" }, func(r *ff.ArtifactReference) { r.SizeBytes = 0 }, func(r *ff.ArtifactReference) { r.SizeBytes = 16<<20 + 1 }} {
		r := ref
		change(&r)
		f.denied("finops_group_pipeline", func(tx *Tx) error {
			_, _, e := tx.GroupArtifactAppend(f.ctx, h.b.ChainID, c.ID, "SAVED_PLAN", groupArtifactIdentity(), r)
			return e
		})
	}
	var scope groupArtifactScope
	f.must("finops_group_pipeline", func(tx *Tx) error { var e error; scope, e = tx.groupArtifactScope(f.ctx, h.b.ChainID, c.ID); return e })
	for name, change := range map[string]func(*groupArtifactDocument){"profile_generation": func(d *groupArtifactDocument) { d.Scope.ProfileGeneration = "wrong" }, "key_revision": func(d *groupArtifactDocument) { d.Scope.KeyBindingID = "wrong-version" }, "image": func(d *groupArtifactDocument) {
		d.Scope.ProducerImageSHA256 = g.BytesDigest([]byte("wrong fixture image"))
	}, "operation": func(d *groupArtifactDocument) { d.Scope.OperationID = "other-op" }, "fence": func(d *groupArtifactDocument) { d.Scope.Fence++ }, "source": func(d *groupArtifactDocument) { d.Scope.SourceID = "other" }, "proposal": func(d *groupArtifactDocument) { d.Scope.ProposalID = "other" }, "issuer": func(d *groupArtifactDocument) { d.Scope.Issuer = "https://other.invalid" }, "object": func(d *groupArtifactDocument) { d.Artifact.Key = "tenant/foreign/object" }, "null_version": func(d *groupArtifactDocument) { d.Artifact.VersionID = "null" }} {
		t.Run(name, func(t *testing.T) {
			d := groupArtifactDocument{"1", scope, "SAVED_PLAN", ref}
			change(&d)
			err := f.run("finops_group_pipeline", func(tx *Tx) error {
				raw, hash, e := groupJournalBytes(d)
				if e != nil {
					return e
				}
				_, e = tx.Exec(f.ctx, `INSERT INTO public.fleet_group_artifacts(tenant_id,chain_id,command_id,operation_id,fence,kind,id,content_hash,document,raw_document) VALUES($1,$2,$3,$4,$5,$6,$7,$8,convert_from($9::bytea,'UTF8')::jsonb,$9)`, f.tenant, h.b.ChainID, c.ID, d.Scope.OperationID, d.Scope.Fence, d.Kind, d.Artifact.ID, hash, raw)
				return e
			})
			var pg *pgconn.PgError
			if !errors.As(err, &pg) || pg.Code != "P0001" {
				t.Fatalf("forged scope was not rejected by actual guard: %v", err)
			}
		})
	}
	for _, limit := range []int{0, 102} {
		f.denied("finops_group_pipeline", func(tx *Tx) error {
			_, e := tx.GroupArtifactPage(f.ctx, h.b.ChainID, c.ID, "SAVED_PLAN", "", limit)
			return e
		})
	}
	f.denied("finops_group_pipeline", func(tx *Tx) error {
		_, _, e := tx.GroupArtifactAppend(f.ctx, h.b.ChainID, "not-issued", "SAVED_PLAN", groupArtifactIdentity(), ref)
		return e
	})
}

func TestGroupArtifactsSelectedHashesRequireCurrentFinalization(t *testing.T) {
	h, c := newGroupArtifactTest(t)
	f := h.f
	git := h.protocolOriginalReceipt(t, g.JournalGitAdvanced)
	h.originalEvent(t, g.JournalRecord{Kind: g.JournalGitAdvanced, Receipt: &git})
	p := h.b.Parent.Program
	entry := p.Manifest.Entries[0]
	at := time.Now().UTC()
	a := g.GitArtifact{Kind: g.BuiltinFixtureArtifact, Receipt: g.SnapshotRef{ID: "artifact-review", SHA256: strings.Repeat("a", 64)}, BaseContextSHA256: g.Digest(p.ArtifactContext), ManifestSHA256: p.ManifestSHA256, ManifestEntrySHA256: g.Digest(entry), PreviousRevision: c.Before.Revision, Revision: entry.Revision, BeforeStateSerial: c.Before.StateSerial, BeforeStateSHA256: c.Before.StateSHA256, SavedPlanSHA256: strings.Repeat("b", 64), PlanJSONSHA256: strings.Repeat("c", 64), Before: entry.Before, After: entry.After}
	refs := map[string]string{}
	for kind, hash := range map[string]string{"SAVED_PLAN": a.SavedPlanSHA256, "PLAN_JSON": a.PlanJSONSHA256, "BEFORE_NATIVE_STATE": a.BeforeStateSHA256, "NATIVE_ARTIFACT_REVIEW": a.Receipt.SHA256} {
		id := "capture-" + strings.ToLower(kind)
		if kind == "NATIVE_ARTIFACT_REVIEW" {
			id = a.Receipt.ID
		}
		r := groupArtifactRef(t, h, c, id, hash)
		refs[kind] = id
		f.must("finops_group_pipeline", func(tx *Tx) error {
			_, _, e := tx.GroupArtifactAppend(f.ctx, h.b.ChainID, c.ID, kind, groupArtifactIdentity(), r)
			return e
		})
	}
	f.denied("finops_group_ledger", func(tx *Tx) error { return tx.GroupArtifactRequireFinalized(f.ctx, h.b.ChainID, c.ID, a, refs) })
	child := g.GitChild{SchemaVersion: g.GitSchemaVersion, ID: "signed-artifact-child", ParentID: p.ID, ParentSHA256: g.Digest(p), BindingSHA256: g.Digest(p.Binding), RealmSHA256: g.Digest(p.Realm), Mode: g.Forward, StageID: entry.StageID, StageSHA256: entry.StageSHA256, Sequence: 1, Artifact: a, MinimumObservationSeconds: entry.MinimumObservationSeconds, CreatedAt: at, ExpiresAt: at.Add(10 * time.Minute), Nonce: "artifact-child-nonce"}
	for _, kind := range []string{"FIXTURE_CURRENT", "FIXTURE_DEPENDENCY", "FIXTURE_SLO"} {
		child.Evidence = append(child.Evidence, g.EvidenceRef{Kind: kind, ID: "explicit-protocol-" + kind, SHA256: strings.Repeat("f", 64), BindingSHA256: g.Digest(p.Binding), RealmSHA256: g.Digest(p.Realm), ObservedAt: at, ValidUntil: at.Add(15 * time.Minute)})
	}
	signed, e := g.SignGitChild(child, h.b.Parent, h.signer, at)
	if e != nil {
		t.Fatal(e)
	}
	c.Forward = &signed
	h.originalEvent(t, g.JournalRecord{Kind: g.JournalReserved, Command: &c})
	f.must("finops_group_ledger", func(tx *Tx) error { return tx.GroupArtifactRequireFinalized(f.ctx, h.b.ChainID, c.ID, a, refs) })
	wrong := a
	wrong.SavedPlanSHA256 = strings.Repeat("d", 64)
	f.denied("finops_group_ledger", func(tx *Tx) error { return tx.GroupArtifactRequireFinalized(f.ctx, h.b.ChainID, c.ID, wrong, refs) })
	// A new capture is retained before replacement finalization, without gaining
	// authority from the currently issued artifact or displacing its old version.
	r := groupArtifactRef(t, h, c, "replacement-plan", wrong.SavedPlanSHA256)
	f.must("finops_group_pipeline", func(tx *Tx) error {
		_, _, e := tx.GroupArtifactAppend(f.ctx, h.b.ChainID, c.ID, "SAVED_PLAN", groupArtifactIdentity(), r)
		return e
	})
	wrongRefs := map[string]string{}
	for k, v := range refs {
		wrongRefs[k] = v
	}
	wrongRefs["SAVED_PLAN"] = r.ID
	f.denied("finops_group_ledger", func(tx *Tx) error { return tx.GroupArtifactRequireFinalized(f.ctx, h.b.ChainID, c.ID, a, wrongRefs) })
	child.ID = "replacement-child"
	child.Nonce = "replacement-child-nonce"
	child.Artifact = wrong
	child.CreatedAt = time.Now().UTC()
	child.ExpiresAt = child.CreatedAt.Add(10 * time.Minute)
	signed, e = g.SignGitChild(child, h.b.Parent, h.signer, child.CreatedAt)
	if e != nil {
		t.Fatal(e)
	}
	c.Forward = &signed
	h.originalEvent(t, g.JournalRecord{Kind: g.JournalReserved, Command: &c})
	f.denied("finops_group_ledger", func(tx *Tx) error { return tx.GroupArtifactRequireFinalized(f.ctx, h.b.ChainID, c.ID, a, refs) })
	f.must("finops_group_ledger", func(tx *Tx) error {
		return tx.GroupArtifactRequireFinalized(f.ctx, h.b.ChainID, c.ID, wrong, wrongRefs)
	})
}

func TestGroupArtifactReferenceBounds(t *testing.T) {
	s := groupArtifactScope{TenantID: "tenant", ProposalID: "proposal", ProfileGeneration: "generation"}
	r := ff.ArtifactReference{ID: "capture", Bucket: "fixture-bucket", Key: "tenant/tenant/fleet-group-fixture/proposal/generation/capture.encrypted", VersionID: strings.Repeat("v", 1024), SHA256: strings.Repeat("b", 64), SizeBytes: 16 << 20}
	for _, kind := range []string{"SAVED_PLAN", "PLAN_JSON", "BEFORE_NATIVE_STATE", "AFTER_NATIVE_STATE", "NATIVE_CAPTURE", "NATIVE_OPERATION_PROOF", "NATIVE_ARTIFACT_REVIEW", "HEALTH_RECEIPT", "HEALTH_BASELINE", "HEALTH_VERDICT", "GIT_PROOF_SET", "FIXTURE_CURRENT", "FIXTURE_DEPENDENCY", "FIXTURE_SLO"} {
		if e := validateGroupArtifactReference(s, kind, r); e != nil {
			t.Fatalf("valid %s boundary: %v", kind, e)
		}
	}
	for name, change := range map[string]func(*ff.ArtifactReference){"too-long-version": func(r *ff.ArtifactReference) { r.VersionID += "x" }, "blank-version": func(r *ff.ArtifactReference) { r.VersionID = "" }, "space-version": func(r *ff.ArtifactReference) { r.VersionID = "version value" }, "null-version": func(r *ff.ArtifactReference) { r.VersionID = "null" }, "wrong-generation": func(r *ff.ArtifactReference) { r.Key = strings.Replace(r.Key, "/generation/", "/other/", 1) }, "oversized": func(r *ff.ArtifactReference) { r.SizeBytes++ }, "negative": func(r *ff.ArtifactReference) { r.SizeBytes = -1 }} {
		t.Run(name, func(t *testing.T) {
			x := r
			change(&x)
			if validateGroupArtifactReference(s, "NATIVE_CAPTURE", x) == nil {
				t.Fatal("invalid reference accepted")
			}
		})
	}
	if validateGroupArtifactReference(s, "PUBLIC_PROOF", r) == nil {
		t.Fatal("unknown kind accepted")
	}
	// A private inspection DTO must not round a valid PostgreSQL uint64 fence.
	s.Fence = ^uint64(0)
	body := groupArtifactDocument{"1", s, "NATIVE_CAPTURE", r}
	raw, hash, e := groupJournalBytes(body)
	if e != nil {
		t.Fatal(e)
	}
	d, e := groupArtifactProjection(raw, hash, "finops_group_pipeline", time.Now().UTC())
	if e != nil {
		t.Fatal(e)
	}
	encoded, e := json.Marshal(d["scope"])
	if e != nil || !strings.Contains(string(encoded), `"fence":18446744073709551615`) {
		t.Fatalf("inspection rounded uint64 fence: %s %v", encoded, e)
	}
}
