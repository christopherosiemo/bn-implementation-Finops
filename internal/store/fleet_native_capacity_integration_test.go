package store

import (
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

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func newFleetCapacityDBTest(t *testing.T) (*fleetHistoryDBTest, SelectionPair) {
	t.Setenv("DB_GROUP_CAPACITY_PASSWORD", "")
	f, pair := newFleetNativeAssessmentTest(t)
	dir := t.TempDir()
	raw, e := os.ReadFile(filepath.Join("..", "..", "migrations", "036_fleet_native_capacity.sql"))
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(dir, "036_fleet_native_capacity.sql"), raw, 0600); e != nil {
		t.Fatal(e)
	}
	if e = f.admin.Migrate(f.ctx, dir); e != nil {
		var p *pgconn.PgError
		if errors.As(e, &p) {
			t.Fatalf("migration: %v position=%d internal_position=%d internal_query=%s", e, p.Position, p.InternalPosition, p.InternalQuery)
		}
		t.Fatal(e)
	}
	var canLogin bool
	if e = f.admin.Pool.QueryRow(f.ctx, `SELECT rolcanlogin FROM pg_roles WHERE rolname='finops_group_capacity'`).Scan(&canLogin); e != nil || canLogin {
		t.Fatal("capacity role became LOGIN without explicit password opt-in", e)
	}
	login := "capacity_" + strings.ReplaceAll(model.ID(), "-", "")
	password := model.ID()
	if _, e = f.admin.Pool.Exec(f.ctx, "CREATE ROLE "+pgx.Identifier{login}.Sanitize()+" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '"+password+"' IN ROLE finops_group_capacity"); e != nil {
		t.Fatal(e)
	}
	var db *Store
	t.Cleanup(func() {
		if db != nil {
			db.Pool.Close()
		}
		if _, e := f.admin.Pool.Exec(context.Background(), "DROP ROLE "+pgx.Identifier{login}.Sanitize()); e != nil {
			t.Error(e)
		}
	})
	c := f.admin.Pool.Config().ConnConfig
	dsn := url.URL{Scheme: "postgres", Host: net.JoinHostPort(c.Host, strconv.Itoa(int(c.Port))), Path: "/" + c.Database, User: url.UserPassword(login, password), RawQuery: "sslmode=disable"}
	db, e = OpenRuntime(f.ctx, dsn.String(), "group-capacity-evaluator")
	if e != nil {
		t.Fatal(e)
	}
	f.roles["finops_group_capacity"] = db
	return f, pair
}
func fleetCapacityRequest(t *testing.T, f *fleetHistoryDBTest, pair SelectionPair) model.Document {
	t.Helper()
	var d model.Document
	f.must("finops_api", func(tx *Tx) error {
		var e error
		d, e = tx.FleetCapacityBatchRequestCreate(f.ctx, f.activity.WorkloadID, "actual-platform-subject", pair.Request.OldConfigurationProposalID, pair.Request.CandidateConfigurationProposalID, 1)
		return e
	})
	return d
}
func fleetCapacityUnknownScope(request model.Document) model.Document {
	return model.Document{"schema_version": "1", "request_id": request["id"], "scope": model.Document{"selection": request["selection"], "snapshot_sha256": "", "population_status": "UNAVAILABLE", "observed_at": time.Now().UTC().Format(time.RFC3339Nano), "membership_pins": []any{}, "current_member_ids": []any{}}, "candidate_template": nil, "source_pins": []any{}, "reason_codes": []string{"CAPACITY_ORIGINAL_MEMBERSHIP_UNAVAILABLE"}, "execution_authorized": false, "verified_saving": nil}
}
func fleetCapacityScopeSummary(scope model.Document) model.Document {
	return model.Document{"schema_version": "1", "scope": scope["scope"], "members": []any{}, "coverage": "UNAVAILABLE", "status": "BLOCKED", "reason_codes": []string{"EXECUTION_AUTHORITY_NOT_GRANTED", "GROUP_CAPACITY_AUTHORITY_UNAVAILABLE"}, "group_capacity_authorized": false, "completed_business_work_preserved": nil, "execution_authorized": false, "verified_saving": nil}
}
func TestFleetCapacityRestrictedScopeUnknownAndHistoricalCompletion(t *testing.T) {
	f, pair := newFleetCapacityDBTest(t)
	request := fleetCapacityRequest(t, f, pair)
	id := model.String(request, "id")
	if request["scope"] != nil || request["batch"] != nil || model.String(request, "status") != "QUEUED" {
		t.Fatal("request fabricated completed batch")
	}
	var snapshot, scope model.Document
	f.must("finops_group_capacity", func(tx *Tx) error { var e error; snapshot, e = tx.FleetCapacityBatchResolve(f.ctx, id); return e })
	f.must("finops_group_capacity", func(tx *Tx) error {
		var e error
		scope, _, e = tx.FleetCapacityBatchScopeAppend(f.ctx, id, fleetNativeHash(snapshot), fleetCapacityUnknownScope(request))
		return e
	})
	for _, role := range []string{"finops_api", "finops_group_assessor", "finops_ingester", "finops_worker", "finops_signer", "finops_executor"} {
		f.denied(role, func(tx *Tx) error {
			raw, _ := jsonMarshalForCapacity(scope)
			_, e := tx.Exec(f.ctx, `INSERT INTO public.fleet_native_capacity_scopes(tenant_id,request_id,content_hash,input_snapshot_hash,document,raw_document) VALUES($1,$2,$3,$4,$5,$6)`, f.tenant, id, fleetNativeHash(scope), fleetNativeHash(snapshot), raw, raw)
			return e
		})
	}
	f.must("finops_group_capacity", func(tx *Tx) error {
		var nativeWrite bool
		if e := tx.QueryRow(f.ctx, `SELECT has_table_privilege(current_user,'public.native_capacity_results','INSERT')`).Scan(&nativeWrite); e != nil {
			return e
		}
		if nativeWrite {
			return errors.New("new evaluator acquired old017 write authority")
		}
		return nil
	})
	f.must("finops_api", func(tx *Tx) error {
		_, e := tx.Exec(f.ctx, `UPDATE public.source_registrations SET document=document||'{"enabled":false,"revoked":true}' WHERE tenant_id=$1 AND id=$2`, f.tenant, f.registration.SourceID)
		return e
	})
	f.must("finops_group_capacity", func(tx *Tx) error {
		out, replay, e := tx.FleetCapacityBatchScopeAppend(f.ctx, id, "not-current", model.Document{})
		if e == nil && (!replay || fleetNativeHash(out) != fleetNativeHash(scope)) {
			return errors.New("issued scope lost after revocation")
		}
		return e
	})
	f.must("finops_group_capacity", func(tx *Tx) error {
		out, replay, e := tx.FleetCapacityBatchComplete(f.ctx, id, fleetCapacityScopeSummary(scope))
		if e == nil && (replay || model.String(out, "status") != "ASSESSED") {
			return errors.New("unknown batch not explicitly completed")
		}
		return e
	})
	f.must("finops_api", func(tx *Tx) error {
		d, e := tx.FleetCapacityBatchGet(f.ctx, id)
		if e == nil && (model.String(sourceDocument(d["batch"]), "coverage") != "UNAVAILABLE" || model.Bool(d, "execution_authorized")) {
			return errors.New("unknown point became empty or authoritative")
		}
		return e
	})
	if e := f.roles["finops_api"].Do(f.ctx, f.tenant+"-foreign", func(tx *Tx) error { _, e := tx.FleetCapacityBatchGet(f.ctx, id); return e }); !errors.Is(e, pgx.ErrNoRows) {
		t.Fatal("foreign capacity request visible", e)
	}
	f.must("finops_group_capacity", func(tx *Tx) error {
		_, replay, e := tx.FleetCapacityBatchComplete(f.ctx, id, model.Document{})
		if e == nil && !replay {
			return errors.New("completion replay lost")
		}
		return e
	})
}

func jsonMarshalForCapacity(v any) ([]byte, error) { return json.Marshal(v) }

func fleetCapacityObservedMetadataScope(t *testing.T, f *fleetHistoryDBTest, request model.Document, empty bool) model.Document {
	t.Helper()
	selection := sourceDocument(request["selection"])
	old := sourceDocument(sourceDocument(sourceDocument(selection["groups"])["binding"])["old"])
	registration := sourceDocument(old["registration"])
	target := sourceDocument(old["target"])
	at := time.Now().UTC().Add(-3 * time.Minute)
	raw := model.Document{"bucket": "explicit-metadata-fixture", "key": "tenant/" + f.tenant + "/membership/point", "version_id": "explicit-point-version", "body_sha256": strings.Repeat("c", 64)}
	id := "observed-original-point"
	revision := "observed-original-revision"
	ids := []string{}
	members := []model.Document{}
	if !empty {
		ids = append(ids, f.activity.ProviderResourceID)
		members = append(members, model.Document{"instance_id": f.activity.ProviderResourceID})
	}
	f.must("finops_ingester", func(tx *Tx) error {
		if _, e := tx.SourceRevisionCreate(f.ctx, model.Document{"id": revision, "source_id": f.registration.SourceID, "kind": "AWS_FLEET_MEMBERSHIP", "revision_hash": fleetNativeHash(raw), "config_hash": f.registration.SourceConfigHash, "registration_version": f.registration.SourceRegistrationVersion, "raw_object": raw}); e != nil {
			return e
		}
		_, e := tx.SourceReceiptCreate(f.ctx, model.Document{"id": id, "source_id": f.registration.SourceID, "kind": "AWS_FLEET_MEMBERSHIP", "revision_id": revision, "config_hash": f.registration.SourceConfigHash, "registration_version": f.registration.SourceRegistrationVersion, "raw_object": raw, "collected_at": at.Format(time.RFC3339Nano), "history_registration_id": registration["id"], "history_registration_version": registration["version"], "history_registration_hash": registration["sha256"], "binding": model.Document{"tenant_id": f.tenant, "workload_id": f.activity.WorkloadID, "provider": "AWS", "account_id": f.activity.AccountID, "region": f.activity.Region}, "groups": []model.Document{{"name": "history", "arn": target["asg_arn"], "launch_template": model.Document{"id": "lt-0123456789abcdef0", "version": "7"}, "members": members}}})
		return e
	})
	var snapshot, receipt model.Document
	f.must("finops_group_capacity", func(tx *Tx) error {
		var e error
		receipt, e = tx.fleetCapacityReceipt(f.ctx, id)
		if e != nil {
			return e
		}
		snapshot, e = tx.FleetCapacityBatchResolve(f.ctx, model.String(request, "id"))
		return e
	})
	pin := model.Document{"receipt_id": id, "revision_id": revision, "receipt_sha256": fleetNativeHash(receipt), "raw_sha256": raw["body_sha256"], "receipt_version_id": raw["version_id"], "revision_version_id": raw["version_id"]}
	d := fleetCapacityUnknownScope(request)
	scope := sourceDocument(d["scope"])
	scope["population_status"] = "OBSERVED_POINT"
	scope["observed_at"] = at.Format(time.RFC3339Nano)
	scope["current_member_ids"] = ids
	scope["membership_pins"] = []model.Document{pin}
	d["scope"] = scope
	d["source_pins"] = []model.Document{pin}
	d["reason_codes"] = []string{"CAPACITY_CANDIDATE_MEMBERSHIP_UNAVAILABLE"}
	// Both an observed empty point and an observed nonempty point must stay
	// observed. An evaluator cannot hide the authoritative roster as missing.
	hidden := model.Clone(d)
	hiddenScope := sourceDocument(hidden["scope"])
	hiddenScope["population_status"] = "UNAVAILABLE"
	hiddenScope["current_member_ids"] = []string{}
	hidden["scope"] = hiddenScope
	f.denied("finops_group_capacity", func(tx *Tx) error {
		_, _, e := tx.FleetCapacityBatchScopeAppend(f.ctx, model.String(request, "id"), fleetNativeHash(snapshot), hidden)
		if e == nil || !strings.Contains(e.Error(), "unknown population cannot replace an observed point") {
			t.Fatal("observed roster suppression did not reach the SQL guard", e)
		}
		return e
	})
	var issued model.Document
	f.must("finops_group_capacity", func(tx *Tx) error {
		var e error
		issued, _, e = tx.FleetCapacityBatchScopeAppend(f.ctx, model.String(request, "id"), fleetNativeHash(snapshot), d)
		return e
	})
	return issued
}
func fleetCapacityGapDocument(request, scope model.Document, instance string) model.Document {
	d := model.Document{"schema_version": "1", "id": "", "batch_id": request["id"], "scope": scope["scope"], "instance_id": instance, "resource_id": "", "binding": nil, "observed_at": time.Now().UTC().Format(time.RFC3339Nano), "telemetry": nil, "hardware": nil, "candidate_template": nil, "input_kind": "UNAVAILABLE", "input_hash": fleetNativeHash(model.Document{"missing": "native-inputs"}), "hardware_mapping": nil, "model_requested": false, "model_evaluated": false, "model_evaluation": nil, "capacity_suitable": nil, "status": "UNAVAILABLE", "reason_codes": []string{"FLEET_CAPACITY_SCOPE_NOT_CURRENT", "EXECUTION_AUTHORITY_NOT_GRANTED", "GROUP_CAPACITY_AUTHORITY_UNAVAILABLE"}, "demand_meaning": "UNAVAILABLE", "group_capacity_authorized": false, "completed_business_work_preserved": nil, "execution_authorized": false, "estimated_saving": nil, "verified_saving": nil, "change_plan_id": nil}
	d["id"] = "fleet-capacity-member-" + fleetNativeHash(d)
	return d
}
func TestFleetCapacityObservedRosterSurvivesRevocationAsExplicitGaps(t *testing.T) {
	f, pair := newFleetCapacityDBTest(t)
	request := fleetCapacityRequest(t, f, pair)
	id := model.String(request, "id")
	// Native transport is explicitly doubled here; the separate service/native
	// acceptance authenticates actual versioned raw XML and the real evaluator.
	scope := fleetCapacityObservedMetadataScope(t, f, request, false)
	if model.String(sourceDocument(scope["scope"]), "population_status") != "OBSERVED_POINT" {
		t.Fatal("known original membership was erased by missing candidate")
	}
	before := fleetCapacityScopeSummary(scope)
	before["coverage"] = "PARTIAL"
	f.denied("finops_group_capacity", func(tx *Tx) error { _, _, e := tx.FleetCapacityBatchComplete(f.ctx, id, before); return e })
	f.must("finops_api", func(tx *Tx) error {
		_, e := tx.Exec(f.ctx, `UPDATE public.source_registrations SET document=document||'{"enabled":false,"revoked":true}' WHERE tenant_id=$1 AND id=$2`, f.tenant, f.registration.SourceID)
		return e
	})
	var inputs model.Document
	f.must("finops_group_capacity", func(tx *Tx) error {
		var e error
		inputs, e = tx.FleetCapacityBatchMemberInputs(f.ctx, id, f.activity.ProviderResourceID)
		if e == nil && (model.Bool(inputs, "current") || inputs["hardware"] != nil || inputs["connection"] != nil) {
			return errors.New("revoked source supplied new member observations")
		}
		return e
	})
	gap := fleetCapacityGapDocument(request, scope, f.activity.ProviderResourceID)
	for _, field := range []string{"execution_authorized", "model_evaluated", "estimated_saving", "status", "instance_id"} {
		t.Run(field, func(t *testing.T) {
			d := model.Clone(gap)
			switch field {
			case "execution_authorized", "model_evaluated":
				d[field] = true
			case "estimated_saving":
				d[field] = "100"
			case "status":
				d[field] = nil
			case "instance_id":
				d[field] = "i-bbbbbbbbbbbbbbbbb"
			}
			f.denied("finops_group_capacity", func(tx *Tx) error {
				raw, _ := json.Marshal(d)
				_, e := tx.Exec(f.ctx, `INSERT INTO public.fleet_native_capacity_members(tenant_id,id,request_id,instance_id,content_hash,input_snapshot_hash,document,raw_document) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, f.tenant, d["id"], id, d["instance_id"], fleetNativeHash(d), fleetNativeHash(inputs), raw, raw)
				return e
			})
		})
	}
	var member model.Document
	f.must("finops_group_capacity", func(tx *Tx) error {
		var e error
		member, _, e = tx.FleetCapacityBatchMemberAppend(f.ctx, id, fleetNativeHash(inputs), gap)
		return e
	})
	f.must("finops_api", func(tx *Tx) error {
		rows, e := tx.FleetCapacityBatchMemberPage(f.ctx, id, "", 1)
		if e == nil && (len(rows) != 1 || rows[0]["member"] != nil || rows[0]["model_evaluated"] != false) {
			return errors.New("member page exposed full detail or invented evaluation")
		}
		return e
	})
	forged := fleetCapacityScopeSummary(scope)
	forged["coverage"] = "ALL_MEMBER_RESULTS_OBSERVED"
	forged["members"] = []model.Document{{"instance_id": f.activity.ProviderResourceID, "result_id": member["id"], "sha256": member["sha256"], "status": "UNAVAILABLE", "model_evaluated": true, "capacity_suitable": true}}
	f.denied("finops_group_capacity", func(tx *Tx) error { _, _, e := tx.FleetCapacityBatchComplete(f.ctx, id, forged); return e })
	correct := fleetCapacityScopeSummary(scope)
	correct["coverage"] = "PARTIAL"
	correct["members"] = []model.Document{{"instance_id": f.activity.ProviderResourceID, "result_id": member["id"], "sha256": member["sha256"], "status": "UNAVAILABLE", "model_evaluated": false, "capacity_suitable": nil}}
	f.must("finops_group_capacity", func(tx *Tx) error {
		d, _, e := tx.FleetCapacityBatchComplete(f.ctx, id, correct)
		if e == nil && model.String(d, "status") != "ASSESSED" {
			return errors.New("explicit gap batch did not complete")
		}
		return e
	})
	f.must("finops_api", func(tx *Tx) error {
		d, e := tx.FleetCapacityBatchMemberGet(f.ctx, model.String(member, "id"))
		if e == nil && (model.String(d, "writer_role") != "finops_group_capacity" || model.String(d, "kind") != "FLEET_NATIVE_CAPACITY_MEMBER_V1") {
			return errors.New("new evaluation falsely borrowed017 provenance")
		}
		return e
	})
}

func TestFleetCapacityRuntimeIdentityCannotBorrowFinancialWriter(t *testing.T) {
	f, _ := newFleetCapacityDBTest(t)
	c := f.roles["finops_group_capacity"].Pool.Config().ConnConfig
	dsn := url.URL{Scheme: "postgres", Host: net.JoinHostPort(c.Host, strconv.Itoa(int(c.Port))), Path: "/" + c.Database, User: url.UserPassword(c.User, c.Password), RawQuery: "sslmode=disable"}
	if db, e := OpenRuntime(f.ctx, dsn.String(), "group-assessment-reader"); e == nil {
		db.Pool.Close()
		t.Fatal("capacity login borrowed financial assessor purpose")
	}
	login := pgx.Identifier{c.User}.Sanitize()
	if _, e := f.admin.Pool.Exec(f.ctx, "GRANT finops_group_assessor TO "+login); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if _, e := f.admin.Pool.Exec(context.Background(), "REVOKE finops_group_assessor FROM "+login); e != nil {
			t.Error(e)
		}
	})
	if db, e := OpenRuntime(f.ctx, dsn.String(), "group-capacity-evaluator"); e == nil {
		db.Pool.Close()
		t.Fatal("mixed financial/capacity identity accepted")
	}
}

func TestFleetCapacityDocumentPreservesExactNativeVersion(t *testing.T) {
	d, e := fleetCapacityDecodeDocument([]byte(`{"versions":[{"version":18446744073709551615}],"exact":9007199254740993}`))
	if e != nil {
		t.Fatal(e)
	}
	raw, e := json.Marshal(d)
	if e != nil || string(raw) != `{"exact":9007199254740993,"versions":[{"version":18446744073709551615}]}` {
		t.Fatal("036 decoder rounded versioned native evidence", string(raw), e)
	}
}

func TestFleetCapacityKnownEmptyPointIsNotUnknown(t *testing.T) {
	f, pair := newFleetCapacityDBTest(t)
	request := fleetCapacityRequest(t, f, pair)
	scope := fleetCapacityObservedMetadataScope(t, f, request, true)
	unknown := fleetCapacityScopeSummary(scope)
	f.denied("finops_group_capacity", func(tx *Tx) error {
		_, _, e := tx.FleetCapacityBatchComplete(f.ctx, model.String(request, "id"), unknown)
		return e
	})
	empty := fleetCapacityScopeSummary(scope)
	empty["coverage"] = "EMPTY_POINT"
	f.must("finops_group_capacity", func(tx *Tx) error {
		_, _, e := tx.FleetCapacityBatchComplete(f.ctx, model.String(request, "id"), empty)
		return e
	})
}

func TestFleetCapacityChangedGroupPointCannotPublishNewObservations(t *testing.T) {
	f, pair := newFleetCapacityDBTest(t)
	request := fleetCapacityRequest(t, f, pair)
	id := model.String(request, "id")
	issued := fleetCapacityObservedMetadataScope(t, f, request, false)
	// Metadata transport is doubled: the native lab separately authenticates XML
	// and raw archive versions. This test exercises the independent SQL fence.
	var prior model.Document
	f.must("finops_group_capacity", func(tx *Tx) error {
		var e error
		prior, e = tx.fleetCapacityReceipt(f.ctx, "observed-original-point")
		return e
	})
	fresh := model.Clone(prior)
	fresh["id"] = "new-original-point"
	fresh["revision_id"] = "new-original-revision"
	fresh["collected_at"] = time.Now().UTC().Format(time.RFC3339Nano)
	delete(fresh, "writer_role")
	delete(fresh, "created_at")
	raw := sourceDocument(fresh["raw_object"])
	raw["version_id"] = "new-provider-capture"
	raw["body_sha256"] = strings.Repeat("b", 64)
	fresh["raw_object"] = raw
	f.must("finops_ingester", func(tx *Tx) error {
		if _, e := tx.SourceRevisionCreate(f.ctx, model.Document{"id": fresh["revision_id"], "source_id": fresh["source_id"], "kind": "AWS_FLEET_MEMBERSHIP", "revision_hash": fleetNativeHash(raw), "config_hash": fresh["config_hash"], "registration_version": fresh["registration_version"], "raw_object": raw}); e != nil {
			return e
		}
		_, e := tx.SourceReceiptCreate(f.ctx, fresh)
		return e
	})
	var inputs model.Document
	f.must("finops_group_capacity", func(tx *Tx) error {
		var e error
		inputs, e = tx.FleetCapacityBatchMemberInputs(f.ctx, id, f.activity.ProviderResourceID)
		if e == nil && model.Bool(inputs, "current") {
			return errors.New("changed group point reused old scope for new observations")
		}
		return e
	})
	gap := fleetCapacityGapDocument(request, issued, f.activity.ProviderResourceID)
	forged := model.Clone(gap)
	forged["input_kind"] = "MAPPING_OBSERVATION"
	f.denied("finops_group_capacity", func(tx *Tx) error {
		raw, _ := json.Marshal(forged)
		_, e := tx.Exec(f.ctx, `INSERT INTO public.fleet_native_capacity_members(tenant_id,id,request_id,instance_id,content_hash,input_snapshot_hash,document,raw_document) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, f.tenant, forged["id"], id, forged["instance_id"], fleetNativeHash(forged), fleetNativeHash(inputs), raw, raw)
		if e == nil || !strings.Contains(e.Error(), "fleet capacity captured group point changed") {
			t.Fatal("direct evaluator bypassed changed point publication fence", e)
		}
		return e
	})
	f.must("finops_group_capacity", func(tx *Tx) error {
		_, _, e := tx.FleetCapacityBatchMemberAppend(f.ctx, id, fleetNativeHash(inputs), gap)
		return e
	})
}
