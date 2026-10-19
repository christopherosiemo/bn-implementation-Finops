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
	"github.com/christopherosiemo/bn-implementation-Finops/internal/workload"
	"github.com/jackc/pgx/v5"
)

// Actual restricted PostgreSQL. 025/027 declarations are real persisted rows;
// this initial family deliberately has no native transport or rate authority.
func newFleetNativeAssessmentTest(t *testing.T) (*fleetHistoryDBTest, SelectionPair) {
	t.Helper()
	f, pair := newFleetFixtureTest(t)
	dir := t.TempDir()
	for _, name := range []string{"010_native_telemetry.sql", "011_workload_safety.sql", "017_native_hardware.sql", "035_group_native_assessments.sql"} {
		raw, e := os.ReadFile(filepath.Join("..", "..", "migrations", name))
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(dir, name), raw, 0600); e != nil {
			t.Fatal(e)
		}
	}
	if e := f.admin.Migrate(f.ctx, dir); e != nil {
		t.Fatal(e)
	}
	login := "assessor_" + strings.ReplaceAll(model.ID(), "-", "")
	password := model.ID()
	if _, e := f.admin.Pool.Exec(f.ctx, "CREATE ROLE "+pgx.Identifier{login}.Sanitize()+" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '"+password+"' IN ROLE finops_group_assessor"); e != nil {
		t.Fatal(e)
	}
	var runtime *Store
	t.Cleanup(func() {
		if runtime != nil {
			runtime.Pool.Close()
		}
		if _, e := f.admin.Pool.Exec(context.Background(), "DROP ROLE "+pgx.Identifier{login}.Sanitize()); e != nil {
			t.Error(e)
		}
	})
	cfg := f.admin.Pool.Config().Copy()
	cfg.ConnConfig.User = login
	cfg.ConnConfig.Password = password
	cfg.ConnConfig.RuntimeParams = map[string]string{}
	cfg.AfterConnect = nil
	dsn := url.URL{Scheme: "postgres", Host: net.JoinHostPort(cfg.ConnConfig.Host, strconv.Itoa(int(cfg.ConnConfig.Port))), Path: "/" + cfg.ConnConfig.Database, User: url.UserPassword(login, password), RawQuery: "sslmode=disable"}
	runtime, e := OpenRuntime(f.ctx, dsn.String(), "group-assessment-reader")
	if e != nil {
		t.Fatal(e)
	}
	f.roles["finops_group_assessor"] = runtime
	profile := workload.Profile{SchemaVersion: "1", Criticality: "NON_PRODUCTION", Statefulness: "STATELESS", Timezone: "UTC", MinReplicas: 1, MinZones: 1, Headroom: workload.Headroom{CPUFreePPM: 300000, MemoryFreePPM: 300000}, Saturation: workload.Saturation{CPUP99PPM: 850000, MemoryP99PPM: 900000}, RTOSeconds: 900, MaxSimultaneousChangePPM: 100000}
	f.must("finops_api", func(tx *Tx) error {
		_, e := tx.WorkloadSafetyAppend(f.ctx, f.activity.WorkloadID, 0, profile)
		return e
	})
	return f, pair
}
func fleetNativeRequest(t *testing.T, f *fleetHistoryDBTest, pair SelectionPair) model.Document {
	t.Helper()
	var request model.Document
	f.must("finops_api", func(tx *Tx) error {
		var e error
		request, e = tx.FleetNativeAssessmentRequestCreate(f.ctx, f.activity.WorkloadID, "actual-finance-subject", pair.Request.OldConfigurationProposalID, pair.Request.CandidateConfigurationProposalID, 1)
		return e
	})
	return request
}
func unavailableFleetNativeResult(request, snapshot model.Document) model.Document {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	return model.Document{"schema_version": "1", "id": "group-native-assessment-" + model.ID(), "selection": request["selection"], "observed_at": now, "status": "BLOCKED", "reason_codes": []string{"EXECUTION_AUTHORITY_NOT_GRANTED", "GROUP_CAPACITY_AUTHORITY_UNAVAILABLE"}, "execution_authorized": false, "change_plan_id": nil, "verified_saving": nil,
		"native_rates": model.Document{"schema_version": "1", "current_member_ids": []any{}, "kind": "AWS_GROUP_HISTORICAL_ACCOUNT_RATES", "selection": sourceDocument(request["selection"])["groups"], "snapshot_sha256": fleetNativeHash(snapshot), "source_pins": []any{}, "billing_source_refs": []any{}, "status": "UNAVAILABLE", "observed_at": now, "valid_until": time.Time{}.Format(time.RFC3339Nano), "execution_authorized": false, "hard_spend_cap": false, "verified_saving": nil},
		"capacity":     model.Document{"status": "UNAVAILABLE", "members": []any{}, "missing_instance_ids": []any{}, "historical_membership": "INTERVAL_OWNERSHIP_UNPROVEN", "group_capacity_authorized": false, "completed_business_work_preserved": nil},
		"scenario":     model.Document{"status": "UNAVAILABLE", "basis": "LIKE_FOR_LIKE_CURRENT_MEMBER_COUNT", "rate_basis": "HISTORICAL_ACCOUNT_RATE_ESTIMATE", "currency": nil, "member_count": 0, "old_hourly_rate": nil, "candidate_hourly_rate": nil, "old_hourly_compute": nil, "candidate_hourly_compute": nil, "hourly_compute_difference": nil, "contracted_avoidable_cost": nil, "estimated_saving": nil, "verified_saving": nil, "hard_spend_cap": false}}
}
func insertFleetNativeDirect(ctx context.Context, tx *Tx, request string, d model.Document) error {
	raw, e := json.Marshal(d)
	if e != nil {
		return e
	}
	_, e = tx.Exec(ctx, `INSERT INTO public.fleet_native_assessments(tenant_id,id,request_id,content_hash,input_snapshot_hash,document,raw_document) VALUES($1,$2,$3,$4,$5,$6,$7)`, tx.Tenant, d["id"], request, fleetNativeHash(d), sourceDocument(d["native_rates"])["snapshot_sha256"], raw, raw)
	return e
}

func TestFleetNativeAssessmentRestrictedPublicationReplayAndHistory(t *testing.T) {
	f, pair := newFleetNativeAssessmentTest(t)
	request := fleetNativeRequest(t, f, pair)
	id := model.String(request, "id")
	if model.String(request, "status") != "QUEUED" || request["assessment"] != nil || model.Bool(request, "execution_authorized") {
		t.Fatal("request invented native result")
	}
	if e := f.run("finops_api", func(tx *Tx) error {
		_, e := tx.FleetNativeAssessmentRequestCreate(f.ctx, f.activity.WorkloadID, "finance", pair.Request.OldConfigurationProposalID, pair.Request.CandidateConfigurationProposalID, 2)
		return e
	}); !errors.Is(e, ErrConflict) {
		t.Fatal("stale profile CAS accepted", e)
	}
	var snapshot, result model.Document
	f.must("finops_group_assessor", func(tx *Tx) error { var e error; snapshot, e = tx.FleetNativeAssessmentSnapshot(f.ctx, id); return e })
	result = unavailableFleetNativeResult(request, snapshot)
	for _, role := range []string{"finops_api", "finops_worker", "finops_signer", "finops_executor", "finops_ingester", "finops_group_fixture"} {
		f.denied(role, func(tx *Tx) error { return insertFleetNativeDirect(f.ctx, tx, id, result) })
	}
	type publication struct {
		replay bool
		err    error
	}
	outcomes := make(chan publication, 2)
	start := make(chan struct{})
	for n := 0; n < 2; n++ {
		go func() {
			<-start
			var replay bool
			e := f.run("finops_group_assessor", func(tx *Tx) error {
				out, r, e := tx.FleetNativeAssessmentAppend(f.ctx, id, fleetNativeHash(snapshot), result)
				replay = r
				if e == nil && model.String(out, "status") != "ASSESSED" {
					return errors.New("missing immutable result")
				}
				return e
			})
			outcomes <- publication{replay, e}
		}()
	}
	close(start)
	replays := 0
	for n := 0; n < 2; n++ {
		out := <-outcomes
		if out.err != nil {
			t.Fatal("concurrent private publication", out.err)
		}
		if out.replay {
			replays++
		}
	}
	if replays != 1 {
		t.Fatal("concurrent append did not preserve exact replay", replays)
	}
	f.denied("finops_group_assessor", func(tx *Tx) error {
		_, e := tx.Exec(f.ctx, `UPDATE public.source_registrations SET version=version+1 WHERE tenant_id=$1`, f.tenant)
		return e
	})
	f.denied("finops_api", func(tx *Tx) error {
		_, e := tx.Exec(f.ctx, `DELETE FROM public.fleet_native_assessment_requests WHERE tenant_id=$1 AND id=$2`, f.tenant, id)
		return e
	})
	f.must("finops_api", func(tx *Tx) error {
		_, e := tx.Exec(f.ctx, `UPDATE public.source_registrations SET document=document||'{"enabled":false,"revoked":true}' WHERE tenant_id=$1 AND id=$2`, f.tenant, f.registration.SourceID)
		return e
	})
	// Historical read/replay survives source invalidation; no new result is made.
	f.must("finops_group_assessor", func(tx *Tx) error {
		out, replay, e := tx.FleetNativeAssessmentAppend(f.ctx, id, "not-a-current-proof", model.Document{})
		if e == nil && (!replay || model.String(out, "status") != "ASSESSED") {
			return errors.New("old result lost after source revocation")
		}
		return e
	})
	f.must("finops_api", func(tx *Tx) error {
		out, e := tx.FleetNativeAssessmentGet(f.ctx, id)
		if e == nil && model.String(out, "status") != "ASSESSED" {
			return errors.New("historical read hidden")
		}
		return e
	})
	if e := f.roles["finops_api"].Do(f.ctx, f.tenant+"-foreign", func(tx *Tx) error { _, e := tx.FleetNativeAssessmentGet(f.ctx, id); return e }); !errors.Is(e, pgx.ErrNoRows) {
		t.Fatal("cross-tenant row visible", e)
	}
	f.denied("finops_api", func(tx *Tx) error {
		_, e := tx.FleetNativeAssessmentRequestCreate(f.ctx, f.activity.WorkloadID, "finance", pair.Request.OldConfigurationProposalID, pair.Request.CandidateConfigurationProposalID, 1)
		return e
	})
}

func TestFleetNativeAssessmentDirectSQLClassificationAndNullClosure(t *testing.T) {
	f, pair := newFleetNativeAssessmentTest(t)
	request := fleetNativeRequest(t, f, pair)
	id := model.String(request, "id")
	var snapshot model.Document
	f.must("finops_group_assessor", func(tx *Tx) error { var e error; snapshot, e = tx.FleetNativeAssessmentSnapshot(f.ctx, id); return e })
	for _, name := range []string{"null-observed", "null-native-observed", "null-expiry", "execution", "money", "workload", "null-count", "string-count", "arithmetic", "extra", "member"} {
		t.Run(name, func(t *testing.T) {
			d := unavailableFleetNativeResult(request, snapshot)
			native := sourceDocument(d["native_rates"])
			scenario := sourceDocument(d["scenario"])
			switch name {
			case "null-observed":
				d["observed_at"] = nil
			case "null-native-observed":
				native["observed_at"] = nil
			case "null-expiry":
				native["valid_until"] = nil
			case "execution":
				d["execution_authorized"] = true
			case "money":
				scenario["estimated_saving"] = "1"
			case "workload":
				selection := sourceDocument(d["selection"])
				selection["safety_profile"] = model.Document{"id": "foreign-profile", "version": 1, "sha256": strings.Repeat("a", 64)}
				d["selection"] = selection
			case "null-count", "string-count", "arithmetic":
				scenario["status"] = "OBSERVED_CONDITIONAL"
				native["status"] = "OBSERVED_CONDITIONAL"
				native["valid_until"] = time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano)
				scenario["currency"] = "USD"
				scenario["member_count"] = 2
				scenario["old_hourly_rate"] = "0.2"
				scenario["candidate_hourly_rate"] = "0.12"
				scenario["old_hourly_compute"] = "0.4"
				scenario["candidate_hourly_compute"] = "0.24"
				scenario["hourly_compute_difference"] = "0.16"
				native["old"] = model.Document{"observed_hourly_rate": "0.2", "rate_dimensions": model.Document{"currency": "USD"}}
				native["candidate"] = model.Document{"observed_hourly_rate": "0.12", "rate_dimensions": model.Document{"currency": "USD"}}
				if name == "null-count" {
					scenario["member_count"] = nil
				} else if name == "string-count" {
					scenario["member_count"] = "2"
				} else {
					scenario["hourly_compute_difference"] = "100"
				}
			case "extra":
				d["raw_receipts"] = []any{}
			case "member":
				capacity := sourceDocument(d["capacity"])
				capacity["members"] = []model.Document{{"instance_id": f.activity.ProviderResourceID, "resource_id": f.activity.ResourceID, "result_id": "unissued-017-result", "result_sha256": strings.Repeat("a", 64), "hardware_receipt_id": "unissued-hardware"}}
				d["capacity"] = capacity
			}
			d["native_rates"], d["scenario"] = native, scenario
			if e := f.run("finops_group_assessor", func(tx *Tx) error { return insertFleetNativeDirect(f.ctx, tx, id, d) }); e == nil {
				t.Fatal("direct private-role forgery accepted", name)
			}
		})
	}
	f.denied("finops_group_assessor", func(tx *Tx) error {
		_, _, e := tx.FleetNativeAssessmentAppend(f.ctx, id, strings.Repeat("a", 64), unavailableFleetNativeResult(request, snapshot))
		return e
	})
}

func TestFleetNativeAssessmentSnapshotPublicationCorrection(t *testing.T) {
	f, pair := newFleetNativeAssessmentTest(t)
	request := fleetNativeRequest(t, f, pair)
	id := model.String(request, "id")
	var snapshot model.Document
	f.must("finops_group_assessor", func(tx *Tx) error { var e error; snapshot, e = tx.FleetNativeAssessmentSnapshot(f.ctx, id); return e })
	// A genuine new ingester status publication changes the selected input
	// snapshot; old readback cannot publish against it even while HEALTHY.
	f.must("finops_ingester", func(tx *Tx) error {
		return tx.SourceCheckpointSet(f.ctx, f.registration.SourceID, "status", model.Document{"status": "HEALTHY", "last_sync_at": time.Now().UTC().Add(time.Second).Format(time.RFC3339Nano), "config_hash": f.registration.SourceConfigHash})
	})
	if e := f.run("finops_group_assessor", func(tx *Tx) error {
		_, _, e := tx.FleetNativeAssessmentAppend(f.ctx, id, fleetNativeHash(snapshot), unavailableFleetNativeResult(request, snapshot))
		return e
	}); !errors.Is(e, ErrFleetNativeEvidence) {
		t.Fatal("changed source snapshot published", e)
	}
	f.must("finops_api", func(tx *Tx) error {
		d, e := tx.FleetNativeAssessmentGet(f.ctx, id)
		if e == nil && d["assessment"] != nil {
			return errors.New("failed publication left result")
		}
		return e
	})
}

func TestFleetNativeAssessmentPredecodeSelectedJobBudgets(t *testing.T) {
	for _, which := range []string{"aggregate-bytes", "aggregate-rows"} {
		t.Run(which, func(t *testing.T) {
			f, pair := newFleetNativeAssessmentTest(t)
			request := fleetNativeRequest(t, f, pair)
			// These deliberately synthetic ingester headers select oversized private
			// jobs. No billing decoder or conditional amount is reached or claimed.
			for n := 0; n < 2; n++ {
				id := "oversized-job-" + strconv.Itoa(n)
				records := []any{model.Document{}}
				job := model.Document{"id": id, "status": "PERSISTED", "raw": model.Document{"records": records}}
				if which == "aggregate-bytes" {
					job["padding"] = strings.Repeat("x", 17<<20)
				} else {
					records = make([]any, 50001)
					for i := range records {
						records[i] = model.Document{}
					}
					job["raw"] = model.Document{"records": records}
				}
				f.must("finops_ingester", func(tx *Tx) error {
					_, e := tx.Create(f.ctx, "ingestion_jobs", job)
					if e != nil {
						return e
					}
					revision := "budget-revision-" + strconv.Itoa(n)
					receipt := "budget-receipt-" + strconv.Itoa(n)
					period := time.Now().UTC().AddDate(0, -n, 0).Format("2006-01") + "-01T00:00:00Z"
					_, e = tx.SourceRevisionCreate(f.ctx, model.Document{"id": revision, "source_id": f.registration.SourceID, "revision_hash": fleetNativeHash(model.Document{"id": revision}), "config_hash": f.registration.SourceConfigHash})
					if e != nil {
						return e
					}
					_, e = tx.SourceReceiptCreate(f.ctx, model.Document{"id": receipt, "source_id": f.registration.SourceID, "revision_id": revision, "kind": "AWS_CUR2", "ingestion_job_id": id, "config_hash": f.registration.SourceConfigHash, "source_proof": model.Document{"billing_period_start": period}})
					if e != nil {
						return e
					}
					return tx.SourceCheckpointSet(f.ctx, f.registration.SourceID, "month:"+f.registration.SourceConfigHash+":"+period, model.Document{"receipt_id": receipt})
				})
			}
			if e := f.run("finops_group_assessor", func(tx *Tx) error {
				_, e := tx.FleetNativeAssessmentSnapshot(f.ctx, model.String(request, "id"))
				return e
			}); !errors.Is(e, ErrFleetNativeBounds) {
				t.Fatal("selected oversized jobs materialized instead of bounded refusal", e)
			}
			f.must("finops_api", func(tx *Tx) error {
				d, e := tx.FleetNativeAssessmentGet(f.ctx, model.String(request, "id"))
				if e == nil && d["assessment"] != nil {
					return errors.New("budget refusal published result")
				}
				return e
			})
		})
	}
}

func TestFleetNativeAssessmentNativeHeadSameInstantConflict(t *testing.T) {
	f, pair := newFleetNativeAssessmentTest(t)
	request := fleetNativeRequest(t, f, pair)
	now := time.Now().UTC()
	binding := sourceDocument(sourceDocument(request["selection"])["groups"])["binding"]
	for n := 0; n < 2; n++ {
		f.must("finops_ingester", func(tx *Tx) error {
			id := "ambiguous-native-" + strconv.Itoa(n)
			at := now
			if n == 1 {
				at = at.In(time.FixedZone("equivalent-native-time", 3600))
			}
			raw := model.Document{"bucket": "explicit-transport-fixture", "key": "tenant/" + f.tenant + "/native/" + id, "version_id": "version-" + id, "body_sha256": fleetNativeHash(model.Document{"native": n})}
			revision := model.Document{"id": "revision-" + id, "source_id": f.registration.SourceID, "kind": "AWS_FLEET_LAUNCH_TEMPLATES", "revision_hash": fleetNativeHash(raw), "raw_object": raw}
			if _, e := tx.SourceRevisionCreate(f.ctx, revision); e != nil {
				return e
			}
			_, e := tx.SourceReceiptCreate(f.ctx, model.Document{"id": id, "source_id": f.registration.SourceID, "revision_id": revision["id"], "kind": "AWS_FLEET_LAUNCH_TEMPLATES", "raw_object": raw, "collected_at": at.Format(time.RFC3339Nano)})
			return e
		})
	}
	if e := f.run("finops_group_assessor", func(tx *Tx) error {
		_, e := tx.fleetNativeNewest(f.ctx, f.registration.SourceID, "AWS_FLEET_LAUNCH_TEMPLATES", "")
		return e
	}); !errors.Is(e, ErrFleetNativeEvidence) {
		t.Fatal("Go resolver chose an economic order for equal native instants", e)
	}
	if e := f.run("finops_group_assessor", func(tx *Tx) error {
		raw, _ := json.Marshal(binding)
		var ids []string
		return tx.QueryRow(f.ctx, `SELECT public.fleet_native_current_pin_ids($1,$2)`, f.tenant, raw).Scan(&ids)
	}); e == nil {
		t.Fatal("direct SQL helper chose a conflicting native pin")
	}
}

func TestFleetNativeAssessmentCanonicalIssuedReceiptHashPrivilege(t *testing.T) {
	f, _ := newFleetNativeAssessmentTest(t)
	// The invoker hash function recursively calls the canonical text function.
	// Both narrow EXECUTE grants are required by the real result trigger.
	f.must("finops_group_assessor", func(tx *Tx) error {
		issued := model.Document{"writer_role": "finops_ingester", "raw_object": model.Document{"version_id": "explicit-version"}, "nested": []any{model.Document{"value": "<native>&"}}}
		raw, e := json.Marshal(issued)
		if e != nil {
			return e
		}
		var actual string
		if e = tx.QueryRow(f.ctx, `SELECT public.fleet_history_json_hash($1::jsonb)`, raw).Scan(&actual); e != nil {
			return e
		}
		if actual != fleetNativeHash(issued) {
			return errors.New("canonical issued receipt hash differs")
		}
		return nil
	})
}

func TestFleetNativeAssessmentOrdinaryBillingMonthHeadAndCorrection(t *testing.T) {
	f, pair := newFleetNativeAssessmentTest(t)
	request := fleetNativeRequest(t, f, pair)
	period := time.Now().UTC()
	period = time.Date(period.Year(), period.Month(), 1, 0, 0, 0, 0, time.UTC)
	refs := []model.Document{}
	for n := 0; n < 2; n++ {
		id := "ordinary-billing-head-" + strconv.Itoa(n)
		rawHash := fleetNativeHash(model.Document{"raw": n})
		canonicalHash := fleetNativeHash(model.Document{"canonical": n})
		f.must("finops_ingester", func(tx *Tx) error {
			// Explicit ingester metadata double, with no decoded price or native
			// authority: only the ordinary pipeline's checkpoint convention is tested.
			if _, e := tx.Create(f.ctx, "ingestion_jobs", model.Document{"id": id + "-job", "raw": model.Document{"records": []any{}}}); e != nil {
				return e
			}
			if _, e := tx.SourceRevisionCreate(f.ctx, model.Document{"id": id + "-revision", "source_id": f.registration.SourceID, "revision_hash": rawHash}); e != nil {
				return e
			}
			if _, e := tx.SourceReceiptCreate(f.ctx, model.Document{"id": id, "source_id": f.registration.SourceID, "revision_id": id + "-revision", "kind": "AWS_CUR2", "config_hash": f.registration.SourceConfigHash, "ingestion_job_id": id + "-job", "raw_hash": rawHash, "canonical_hash": canonicalHash, "source_proof": model.Document{"billing_period_start": period.Format(time.RFC3339Nano)}}); e != nil {
				return e
			}
			return tx.SourceCheckpointSet(f.ctx, f.registration.SourceID, "month:"+f.registration.SourceConfigHash+":"+period.Format("2006-01"), model.Document{"receipt_id": id})
		})
		refs = append(refs, model.Document{"receipt_id": id, "revision_id": id + "-revision", "ingestion_job_id": id + "-job", "raw_hash": rawHash, "canonical_hash": canonicalHash, "period_start": period.Format(time.RFC3339Nano), "period_end": period.AddDate(0, 1, 0).Format(time.RFC3339Nano)})
	}
	var snapshot model.Document
	f.must("finops_group_assessor", func(tx *Tx) error {
		var e error
		snapshot, e = tx.FleetNativeAssessmentSnapshot(f.ctx, model.String(request, "id"))
		return e
	})
	for n, ref := range refs {
		d := unavailableFleetNativeResult(request, snapshot)
		native := sourceDocument(d["native_rates"])
		native["billing_source_refs"] = []model.Document{ref}
		d["native_rates"] = native
		e := f.run("finops_group_assessor", func(tx *Tx) error { return insertFleetNativeDirect(f.ctx, tx, model.String(request, "id"), d) })
		if n == 0 && e == nil {
			t.Fatal("corrected ordinary month accepted its historical receipt")
		}
		if n == 1 && e != nil {
			t.Fatal("actual YYYY-MM current head rejected", e)
		}
	}
}

func TestFleetNativeAssessmentNewestHardwareConflictCannotResurrectOlder(t *testing.T) {
	f, pair := newFleetNativeAssessmentTest(t)
	request := fleetNativeRequest(t, f, pair)
	instance := "i-" + strings.ReplaceAll(model.ID(), "-", "")[:17]
	resource := "hardware-ambiguity-" + model.ID()
	var inventory, source model.Document
	f.must("finops_api", func(tx *Tx) error {
		var e error
		source, e = tx.SourceGet(f.ctx, f.registration.SourceID)
		if e != nil {
			return e
		}
		inventory, e = tx.Create(f.ctx, "resources", model.Document{"id": resource, "workload_id": f.activity.WorkloadID, "provider": "AWS", "provider_resource_id": instance, "account_id": f.activity.AccountID, "region": f.activity.Region, "instance_type": "m6i.large"})
		return e
	})
	selected := sourceDocument(sourceDocument(request["selection"])["groups"])["binding"]
	now := time.Now().UTC()
	assertHardware := func(expected int) {
		t.Helper()
		f.must("finops_group_assessor", func(tx *Tx) error {
			snapshot, e := tx.FleetNativeAssessmentSnapshot(f.ctx, model.String(request, "id"))
			if e != nil {
				return e
			}
			var hardware []model.Document
			if e = fleetFixtureDecode(snapshot["hardware"], &hardware); e != nil {
				return e
			}
			if len(hardware) != expected {
				return errors.New("Go hardware resolver resurrected an older capture")
			}
			raw, _ := json.Marshal(selected)
			var ids []string
			if e = tx.QueryRow(f.ctx, `SELECT public.fleet_native_current_pin_ids($1,$2)`, f.tenant, raw).Scan(&ids); e != nil {
				return e
			}
			if len(ids) != expected {
				return errors.New("SQL hardware resolver resurrected an older capture")
			}
			return nil
		})
	}
	for n := 0; n < 3; n++ {
		id := "hardware-capture-" + strconv.Itoa(n)
		at := now
		if n == 0 {
			at = at.Add(-30 * time.Second)
		} else if n == 2 {
			at = at.In(time.FixedZone("same-hardware-instant", 3600))
		}
		hash := fleetNativeHash(model.Document{"explicit_metadata_double": n})
		raw := model.Document{"bucket": "explicit-transport-double", "key": "tenant/" + f.tenant + "/hardware/" + id, "version_id": "version-" + id, "body_sha256": hash}
		f.must("finops_ingester", func(tx *Tx) error {
			if _, e := tx.SourceRevisionCreate(f.ctx, model.Document{"id": id + "-revision", "source_id": f.registration.SourceID, "kind": "AWS_EC2_HARDWARE", "registration_version": model.Number(source, "version"), "revision_hash": hash, "config_hash": f.registration.SourceConfigHash, "resource_snapshot_hash": fleetNativeHash(inventory), "raw_object": raw, "observed_at": at.Format(time.RFC3339Nano)}); e != nil {
				return e
			}
			_, e := tx.SourceReceiptCreate(f.ctx, model.Document{"id": id, "source_id": f.registration.SourceID, "kind": "AWS_EC2_HARDWARE", "revision_id": id + "-revision", "registration_version": model.Number(source, "version"), "config_hash": f.registration.SourceConfigHash, "read_role_binding_id": source["read_role_binding_id"], "binding": model.Document{"tenant_id": f.tenant, "resource_id": resource, "workload_id": f.activity.WorkloadID, "provider": "AWS", "provider_resource_id": instance, "account_id": f.activity.AccountID, "region": f.activity.Region}, "resource_version": model.Number(inventory, "version"), "resource_snapshot_hash": fleetNativeHash(inventory), "inventory_snapshot": inventory, "candidate_types": []string{"m6i.large"}, "native": model.Document{"schema_version": "1", "provider": "AWS", "account_id": f.activity.AccountID, "region": f.activity.Region, "collected_at": at.Format(time.RFC3339Nano), "raw_sha256": hash, "instance": model.Document{"id": instance, "instance_type": "m6i.large"}}, "collected_at": at.Format(time.RFC3339Nano), "raw_object": raw, "execution_authorized": false})
			return e
		})
		if n == 0 {
			assertHardware(1)
		}
	}
	assertHardware(0)
}
