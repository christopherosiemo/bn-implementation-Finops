package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	a "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetassessment"
	b "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetbilling"
	c "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetcapacity"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleetdecisionworker"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func jointDocument(t *testing.T, v any) model.Document {
	t.Helper()
	raw, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	var d model.Document
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if e = dec.Decode(&d); e != nil {
		t.Fatal(e)
	}
	return d
}
func jointDecode(t *testing.T, v any, out any) {
	t.Helper()
	raw, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if e = dec.Decode(out); e != nil {
		t.Fatal(e)
	}
}
func jointRuntime(t *testing.T, admin *store.Store, role, purpose string, tenant ...string) *store.Store {
	t.Helper()
	ctx := context.Background()
	if len(tenant) > 1 || len(tenant) == 1 && (role != "finops_group_decision" || purpose != "group-decision-reader" || tenant[0] == "") {
		t.Fatal("explicit decision credential fixture tenant required")
	}
	login := "joint_http_" + strings.ReplaceAll(model.ID(), "-", "")
	password := model.ID()
	if _, e := admin.Pool.Exec(ctx, "CREATE ROLE "+pgx.Identifier{login}.Sanitize()+" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '"+password+"' IN ROLE "+pgx.Identifier{role}.Sanitize()); e != nil {
		t.Fatal(e)
	}
	cfg := admin.Pool.Config().ConnConfig
	dsn := url.URL{Scheme: "postgres", Host: net.JoinHostPort(cfg.Host, strconv.Itoa(int(cfg.Port))), Path: "/" + cfg.Database, User: url.UserPassword(login, password), RawQuery: "sslmode=disable"}
	runtime, e := store.OpenRuntime(ctx, dsn.String(), purpose)
	if e != nil {
		t.Fatal(e)
	}
	if len(tenant) == 1 {
		dir := t.TempDir()
		raw, e := os.ReadFile(filepath.Join("..", "..", "migrations", "038_fleet_decision_credential_scope.sql"))
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(dir, "038_fleet_decision_credential_scope.sql"), raw, 0600); e != nil {
			t.Fatal(e)
		}
		if e = admin.Migrate(ctx, dir); e != nil {
			t.Fatal(e)
		}
		tag, e := admin.Pool.Exec(ctx, `INSERT INTO public.fleet_decision_credentials(id,database_login,role_oid,tenant_id) SELECT $1,rolname,oid,$2 FROM pg_roles WHERE rolname=$3`, model.ID(), tenant[0], login)
		if e != nil || tag.RowsAffected() != 1 {
			t.Fatal("explicit decision credential fixture installation", e)
		}
	}
	t.Cleanup(func() {
		runtime.Pool.Close()
		if _, e := admin.Pool.Exec(context.Background(), "DROP ROLE "+pgx.Identifier{login}.Sanitize()); e != nil {
			t.Error(e)
		}
	})
	return runtime
}

// This is an actual restricted-role/JWT/PG publication test. Native source
// transport is explicitly metadata-doubled; no rate, hardware measurement,
// model result, cost or physical PASS is manufactured by this fixture.
func jointIssuedUnknownChildren(t *testing.T, f *mutationReplayFixture, assessor, evaluator *store.Store, proposals []string) (string, string) {
	t.Helper()
	ctx := context.Background()
	owner := f.token(f.tenant, "assigned-owner", "ORGANISATION_OWNER")
	body := model.Document{"old_configuration_proposal_id": proposals[0], "candidate_configuration_proposal_id": proposals[1]}
	code, ar, _ := f.request("workloads/fixture-workload/fleet-native-assessments", `"1"`, "joint-child-rates", owner, body)
	if code != 202 {
		t.Fatal("assessment queue", code, ar)
	}
	code, cr, _ := f.request("workloads/fixture-workload/fleet-native-capacity-batches", `"1"`, "joint-child-capacity", owner, body)
	if code != 202 {
		t.Fatal("capacity queue", code, cr)
	}
	var selection a.Selection
	jointDecode(t, ar["selection"], &selection)
	ids := []string{"i-22222222222222222", "i-aaaaaaaaaaaaaaaaa"}
	now := time.Now().UTC()
	at := now.Add(-time.Second)
	pinIDs := []string{}
	membershipIDs := []string{}
	templateID := ""
	var pins []b.GroupNativePin
	publish := func(kind string, extra model.Document) string {
		id := "joint-native-" + model.ID()
		revision := "joint-revision-" + model.ID()
		raw := model.Document{"bucket": "explicit-metadata-fixture", "key": "tenant/" + f.tenant + "/explicit-transport-double/" + id, "version_id": "metadata-version-" + id, "body_sha256": strings.Repeat("c", 64)}
		e := f.roles["ingester"].Do(ctx, f.tenant, func(tx *store.Tx) error {
			reg, e := tx.SourceGet(ctx, "assessment-native")
			if e != nil {
				return e
			}
			hash := source.ConfigurationHash(reg)
			base := model.Document{"id": revision, "source_id": "assessment-native", "kind": kind, "revision_hash": b.Hash(raw), "config_hash": hash, "registration_version": reg["version"], "raw_object": raw}
			if _, e = tx.SourceRevisionCreate(ctx, base); e != nil {
				return e
			}
			receipt := model.Document{"id": id, "source_id": "assessment-native", "kind": kind, "revision_id": revision, "config_hash": hash, "registration_version": reg["version"], "raw_object": raw, "collected_at": at.Format(time.RFC3339Nano)}
			for k, v := range extra {
				receipt[k] = v
			}
			_, e = tx.SourceReceiptCreate(ctx, receipt)
			return e
		})
		if e != nil {
			t.Fatal("metadata-only native point", e)
		}
		pinIDs = append(pinIDs, id)
		return id
	}
	binding := selection.Groups.Binding
	for n, side := range []any{binding.Old, binding.Candidate} {
		d := jointDocument(t, side)
		reg := sourceDocument(d["registration"])
		target := sourceDocument(d["target"])
		members := []model.Document{}
		if n == 0 {
			for _, id := range ids {
				members = append(members, model.Document{"instance_id": id})
			}
		}
		id := publish("AWS_FLEET_MEMBERSHIP", model.Document{"history_registration_id": reg["id"], "history_registration_version": reg["version"], "history_registration_hash": reg["sha256"], "binding": model.Document{"tenant_id": f.tenant, "workload_id": "fixture-workload", "provider": "AWS", "account_id": target["account_id"], "region": target["region"]}, "groups": []model.Document{{"name": "explicit-transport-double", "arn": target["asg_arn"], "launch_template": model.Document{"id": "lt-0123456789abcdef0", "version": "7"}, "members": members}}})
		membershipIDs = append(membershipIDs, id)
	}
	templateID = publish("AWS_FLEET_LAUNCH_TEMPLATES", model.Document{"templates": []model.Document{{"id": "lt-0123456789abcdef0", "version": "7", "data": model.Document{"instance_type": "m6i.large", "image_id": "ami-0123456789abcdef0", "instance_requirements": false}}}})
	if e := f.roles["ingester"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		for _, id := range pinIDs {
			r, e := tx.SourceReceiptGet(ctx, id)
			if e != nil {
				return e
			}
			raw := sourceDocument(r["raw_object"])
			pins = append(pins, b.GroupNativePin{ReceiptID: id, RevisionID: model.String(r, "revision_id"), ReceiptSHA256: b.Hash(r), RawSHA256: model.String(raw, "body_sha256"), ReceiptVersionID: model.String(raw, "version_id"), RevisionVersionID: model.String(raw, "version_id")})
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	if e := assessor.Do(ctx, f.tenant, func(tx *store.Tx) error {
		snapshot, e := tx.FleetNativeAssessmentSnapshot(ctx, model.String(ar, "id"))
		if e != nil {
			return e
		}
		prices := b.GroupNativeEvidence{SchemaVersion: "1", Kind: b.GroupNativePriceKind, Selection: selection.Groups, SnapshotSHA256: b.Hash(snapshot), SourcePins: pins, BillingSourceRefs: []b.SourceRef{}, CurrentMemberIDs: ids, ObservedAt: now, ValidUntil: now, Status: "UNAVAILABLE", ReasonCodes: []string{"NATIVE_BILLING_UNAVAILABLE"}}
		observation, e := a.Build(selection, prices, nil, now)
		if e != nil {
			return e
		}
		_, _, e = tx.FleetNativeAssessmentAppend(ctx, model.String(ar, "id"), b.Hash(snapshot), jointDocument(t, observation))
		return e
	}); e != nil {
		t.Fatal("publish genuine unknown rates", e)
	}
	byID := map[string]b.GroupNativePin{}
	for _, p := range pins {
		byID[p.ReceiptID] = p
	}
	scope := c.ScopeCapture{SchemaVersion: "1", RequestID: model.String(cr, "id"), Scope: c.Scope{Selection: selection, PopulationStatus: "OBSERVED_POINT", ObservedAt: at, CurrentMemberIDs: ids, MembershipPins: []b.GroupNativePin{byID[membershipIDs[0]], byID[membershipIDs[1]]}}, CandidateTemplate: &c.CandidateTemplate{ID: "lt-0123456789abcdef0", Version: "7", InstanceType: "m6i.large", ImageID: "ami-0123456789abcdef0", SourcePin: byID[templateID], DefinitionSHA256: strings.Repeat("d", 64), ReasonCodes: []string{}}, SourcePins: []b.GroupNativePin{byID[membershipIDs[0]], byID[membershipIDs[1]], byID[templateID]}, ReasonCodes: []string{"CAPACITY_PRIVATE_TRANSPORT_METADATA_ONLY"}}
	var issued model.Document
	if e := evaluator.Do(ctx, f.tenant, func(tx *store.Tx) error {
		snapshot, e := tx.FleetCapacityBatchResolve(ctx, model.String(cr, "id"))
		if e != nil {
			return e
		}
		issued, _, e = tx.FleetCapacityBatchScopeAppend(ctx, model.String(cr, "id"), b.Hash(snapshot), jointDocument(t, scope))
		return e
	}); e != nil {
		t.Fatal("issue pinned unknown scope", e)
	}
	jointDecode(t, issued, &scope)
	members := []c.MemberResult{}
	for _, id := range ids {
		gap, e := c.Unavailable(scope.Scope, scope.RequestID, id, "FLEET_CAPACITY_NATIVE_INPUTS_UNAVAILABLE", time.Now().UTC())
		if e != nil {
			t.Fatal(e)
		}
		members = append(members, gap)
		if e = evaluator.Do(ctx, f.tenant, func(tx *store.Tx) error {
			input, e := tx.FleetCapacityBatchMemberInputs(ctx, scope.RequestID, id)
			if e != nil {
				return e
			}
			_, _, e = tx.FleetCapacityBatchMemberAppend(ctx, scope.RequestID, b.Hash(input), jointDocument(t, gap))
			return e
		}); e != nil {
			t.Fatal("publish explicit member gap", e)
		}
	}
	summary, e := c.Summarize(scope.Scope, members)
	if e != nil {
		t.Fatal(e)
	}
	if e = evaluator.Do(ctx, f.tenant, func(tx *store.Tx) error {
		_, _, e := tx.FleetCapacityBatchComplete(ctx, scope.RequestID, jointDocument(t, summary))
		return e
	}); e != nil {
		t.Fatal("complete exact unknown roster", e)
	}
	return model.String(ar, "id"), model.String(cr, "id")
}

func TestJointDecisionActualJWTPGWorkerPersistsUnknownAndRechecksAuthority(t *testing.T) {
	f, admin, evaluator, proposals := newFleetCapacityHTTPTest(t)
	ctx := context.Background()
	dir := t.TempDir()
	raw, e := os.ReadFile(filepath.Join("..", "..", "migrations", "037_fleet_joint_decisions.sql"))
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(dir, "037_fleet_joint_decisions.sql"), raw, 0600); e != nil {
		t.Fatal(e)
	}
	if e = admin.Migrate(ctx, dir); e != nil {
		t.Fatal(e)
	}
	assessor := jointRuntime(t, admin, "finops_group_assessor", "group-assessment-reader")
	writer := jointRuntime(t, admin, "finops_group_decision", "group-decision-reader", f.tenant)
	ar, cr := jointIssuedUnknownChildren(t, f, assessor, evaluator, proposals)
	owner := f.token(f.tenant, "assigned-owner", "ORGANISATION_OWNER")
	auditor := f.token(f.tenant, "joint-auditor", "AUDITOR")
	path := "workloads/fixture-workload/fleet-joint-decisions"
	body := model.Document{"assessment_request_id": ar, "capacity_batch_request_id": cr}
	code, queued, _ := f.request(path, `"1"`, "joint-positive", owner, body)
	if code != 202 || queued["decision"] != nil || model.String(queued, "status") != "QUEUED" {
		t.Fatal("joint queue", code, queued)
	}
	id := model.String(queued, "id")
	if code, replayed, _ := f.request(path, `"0"`, "joint-positive", owner, body); code != 202 || replayed["id"] != id {
		t.Fatal("idempotent queue replay differs", code, replayed)
	}
	if code, _, _ := f.request(path, `"2"`, "joint-stale-profile", owner, body); code != 409 {
		t.Fatal("profile CAS bypass", code)
	}
	if code, _, _ := f.request(path, `"1"`, "joint-readonly", auditor, body); code != 403 {
		t.Fatal("auditor writer admitted", code)
	}
	fixedObservation := time.Now().UTC()
	worker := &fleetdecisionworker.Worker{Store: writer, Tenant: f.tenant, Now: func() time.Time { return fixedObservation }}
	out, replay, e := worker.Process(ctx, id)
	if e != nil || replay {
		t.Fatal("production queue worker", e, replay)
	}
	decision := sourceDocument(out["decision"])
	if model.String(out, "status") != "ASSESSED" || model.String(decision, "physical_status") != "UNKNOWN" || model.Bool(decision, "execution_authorized") || decision["estimated_saving"] != nil || decision["verified_saving"] != nil || model.String(sourceDocument(decision["scenario"]), "status") != "UNAVAILABLE" {
		t.Fatal("unknown join gained authority or money", out)
	}
	var members []model.Document
	jointDecode(t, decision["members"], &members)
	if len(members) != 2 {
		t.Fatal("whole roster lost", len(members))
	}
	for _, member := range members {
		if model.String(member, "status") != "UNKNOWN" {
			t.Fatal("unevaluated member granted physical pass", member)
		}
	}
	if code, d := fleetNativeHTTPGet(t, f, "fleet-joint-decisions/"+id, auditor); code != 200 || model.String(d, "status") != "ASSESSED" || d["decision_summary"] != nil {
		t.Fatal("scoped detail", code, d)
	}
	if code, p := fleetNativeHTTPGet(t, f, path+"?limit=1", auditor); code != 200 {
		t.Fatal("scoped page", code, p)
	} else {
		var rows []model.Document
		jointDecode(t, p["items"], &rows)
		if len(rows) != 1 || rows[0]["decision"] != nil || sourceDocument(rows[0]["decision_summary"])["member_count"] != float64(2) {
			t.Fatal("page expanded full decision or lost summary", p)
		}
	}
	if _, replay, e = worker.Process(ctx, id); e != nil || !replay {
		t.Fatal("immutable worker replay", e, replay)
	}
	code, twin, _ := f.request(path, `"1"`, "joint-independent-same-time", owner, body)
	if code != 202 || twin["id"] == id {
		t.Fatal("independent queue request unavailable", code, twin)
	}
	second, replay, e := worker.Process(ctx, model.String(twin, "id"))
	secondDecision := sourceDocument(second["decision"])
	if e != nil || replay || model.String(second, "status") != "ASSESSED" || secondDecision["id"] == decision["id"] || secondDecision["observed_at"] != decision["observed_at"] || secondDecision["request_id"] != twin["id"] || decision["request_id"] != id {
		t.Fatal("identical input/time requests collided or crossed mappings", e, secondDecision)
	}
	// Exercise direct private-role INSERTs with fully resealed IDs/raw hashes.
	// These reach SQL semantic guards rather than merely failing a digest.
	code, forgedRequest, _ := f.request(path, `"1"`, "joint-direct-negatives", owner, body)
	if code != 202 {
		t.Fatal("negative queue", code, forgedRequest)
	}
	e = writer.Do(ctx, f.tenant, func(tx *store.Tx) error {
		_, _, e := tx.FleetJointDecisionRefuse(ctx, model.String(forgedRequest, "id"), "JOINT_DECISION_INPUTS_CHANGED")
		return e
	})
	var dishonest *pgconn.PgError
	if !errors.As(e, &dishonest) || dishonest.Code != "P0001" || !strings.Contains(dishonest.Message, "current inputs cannot be labelled stale") {
		t.Fatal("current inputs accepted false stale refusal", e)
	}
	for name, mutate := range map[string]func(model.Document){
		"member_money": func(d model.Document) {
			var m []model.Document
			jointDecode(t, d["members"], &m)
			m[0]["estimated_saving"] = "100"
			d["members"] = m
		},
		"dimension_authority": func(d model.Document) {
			var m []model.Document
			jointDecode(t, d["members"], &m)
			var dims []model.Document
			jointDecode(t, m[0]["dimensions"], &dims)
			dims[0]["execution_authorized"] = true
			m[0]["dimensions"] = dims
			d["members"] = m
		},
		"missing_reason": func(d model.Document) { delete(d, "reason_codes") },
		"dimension_reason_type": func(d model.Document) {
			var m []model.Document
			jointDecode(t, d["members"], &m)
			var dims []model.Document
			jointDecode(t, m[0]["dimensions"], &dims)
			dims[0]["reason_codes"] = "unsupported"
			m[0]["dimensions"] = dims
			d["members"] = m
		},
		"physical_extrapolation": func(d model.Document) { d["physical_status"] = "PASS" },
		"cross_request":          func(d model.Document) { d["request_id"] = id },
	} {
		t.Run(name, func(t *testing.T) {
			bad := jointDocument(t, decision)
			bad["request_id"] = forgedRequest["id"]
			mutate(bad)
			bad["id"] = ""
			bad["id"] = "group-joint-decision-" + b.Hash(bad)
			e := writer.Do(ctx, f.tenant, func(tx *store.Tx) error {
				in, e := tx.FleetJointDecisionInputs(ctx, model.String(forgedRequest, "id"))
				if e != nil {
					return e
				}
				raw, e := json.Marshal(bad)
				if e != nil {
					return e
				}
				_, e = tx.Exec(ctx, `INSERT INTO public.fleet_joint_decisions(tenant_id,id,request_id,content_hash,input_snapshot_hash,document,raw_document) VALUES($1,$2,$3,$4,$5,$6,$7)`, f.tenant, bad["id"], forgedRequest["id"], b.Hash(bad), b.Hash(in), raw, raw)
				return e
			})
			var pg *pgconn.PgError
			if !errors.As(e, &pg) || pg.Code != "P0001" || !strings.HasPrefix(pg.Message, "joint decision ") {
				t.Fatal("forgery missed semantic SQL guard", e)
			}
		})
	}
	if code, _, _ := f.request(path, `"1"`, "joint-crossed-child-kinds", owner, model.Document{"assessment_request_id": cr, "capacity_batch_request_id": ar}); code != 409 {
		t.Fatal("mismatched issued child IDs admitted", code)
	}
	if code, _ := fleetNativeHTTPGet(t, f, "fleet-joint-decisions/"+id, f.token(f.tenant+"-foreign", "joint-auditor", "AUDITOR")); code != 404 {
		t.Fatal("foreign decision visible", code)
	}
	// Revocation blocks fresh publication but cannot erase an issued historical
	// analytical result. No old source observations are renewed or relabelled.
	code, pending, _ := f.request(path, `"1"`, "joint-before-revoke", owner, body)
	if code != 202 {
		t.Fatal("second queue", code, pending)
	}
	if e = f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE public.source_registrations SET document=document||'{"enabled":false,"revoked":true}' WHERE tenant_id=$1 AND id='assessment-native'`, f.tenant)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	refused, replay, e := worker.Process(ctx, model.String(pending, "id"))
	if e != nil || replay || model.String(refused, "status") != "REFUSED" || refused["decision"] != nil || model.String(sourceDocument(refused["refusal"]), "request_id") != model.String(pending, "id") {
		t.Fatal("revoked job remained queued or gained a decision", refused, replay, e)
	}
	if again, replay, e := worker.Process(ctx, model.String(pending, "id")); e != nil || !replay || b.Hash(again) != b.Hash(refused) {
		t.Fatal("terminal refusal replay differs", e, replay)
	}
	if e = writer.Do(ctx, f.tenant, func(tx *store.Tx) error {
		rows, e := tx.FleetJointDecisionPending(ctx, "", 100)
		if e != nil {
			return e
		}
		for _, row := range rows {
			if row["id"] == pending["id"] {
				return errors.New("refused request remained in queue")
			}
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	if code, d := fleetNativeHTTPGet(t, f, "fleet-joint-decisions/"+id, auditor); code != 200 || model.String(d, "status") != "ASSESSED" {
		t.Fatal("revocation erased historical read", code, d)
	}
}
