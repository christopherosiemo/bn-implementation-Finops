package service

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/evidence"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/slo"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/telemetry"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/workload"
	"github.com/jackc/pgx/v5"
)

// These are currentness/ACL components under independently authenticated
// PostgreSQL roles, not a provider acquisition, safety or savings acceptance.
// Synthetic historical recommendation bodies remain unchanged throughout.
func TestRecommendationCurrentnessImmutableContextAndTrustedChanges(t *testing.T) {
	f := newMutationReplayFixture(t)
	ctx := context.Background()
	for n, scenario := range []string{"resource_configuration", "workload_mapping", "resource_owner", "workload_criticality", "policy", "safety_profile", "slo", "telemetry_revision"} {
		t.Run(scenario, func(t *testing.T) {
			rid, id := "currentness-resource-"+scenario, "currentness-recommendation-"+scenario
			nativeID := fmt.Sprintf("i-%017x", n+100)
			var original, before model.Document
			if err := f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
				_, err := tx.Create(ctx, "resources", model.Document{"id": rid, "provider": "AWS", "resource_type": "EC2", "provider_resource_id": nativeID, "account_id": "111122223333", "region": "eu-west-1", "workload_id": "workload-dev", "owner": "currentness-owner", "environment": "NON_PRODUCTION", "configuration_authority": "MANUAL", "instance_type": "m6i.large", "state": "running", "last_seen_at": model.Now()})
				if err != nil {
					return err
				}
				if scenario == "telemetry_revision" {
					c := telemetry.Connection{SchemaVersion: "1", ID: "currentness-native-telemetry", Version: 1, Kind: "PROMETHEUS", ReadBindingID: "currentness-approved-reader", Enabled: true, Binding: telemetry.Binding{TenantID: f.tenant, ResourceID: rid, WorkloadID: "workload-dev", Provider: "AWS", ProviderResourceID: nativeID, AccountID: "111122223333", Region: "eu-west-1"}, Definitions: []telemetry.Definition{{ID: "cpu", Version: "1", Metric: "CPUUtilization", Name: "cpu_utilization", Unit: "Percent", Type: "GAUGE", CadenceSeconds: 300, MaxGapSeconds: 300}}}
					if _, err = tx.TelemetryConnectionAppend(ctx, c.ID, 0, telemetry.Document(c)); err != nil {
						return err
					}
				}
				original, err = tx.Create(ctx, "recommendations", model.Document{"id": id, "resource_id": rid, "workload_id": "workload-dev", "status": "VALIDATED", "pre_execution_ready": true, "title": "Synthetic context component", "monthly_saving": "12.340000000001", "currency": "GBP", "created_at": model.Now(), "expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)})
				if err != nil {
					return err
				}
				before, err = tx.RecommendationCurrentnessContext(ctx, "EC2", id)
				if err != nil {
					return err
				}
				current, err := f.api.recommendationCurrentness(ctx, tx, "EC2", original)
				if err == nil && storageObject(current["currentness"])["status"] != "CURRENT" {
					t.Fatalf("unchanged evidence became unavailable: %#v", current["currentness"])
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if scenario == "resource_configuration" {
				reader := f.token(f.tenant, "currentness-reader", "PLATFORM_ADMIN")
				code, public := fleetNativeHTTPGet(t, f, "recommendations/"+id, reader)
				if code != http.StatusOK || storageObject(public["currentness"])["status"] != "CURRENT" {
					t.Fatalf("ordinary authenticated recommendation read lost currentness: code=%d projection=%#v", code, public["currentness"])
				}
			}
			originalHash, baselineHash := evidence.Hash(original), evidence.Hash(before["baseline"])
			if err := f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
				update := func(kind, identifier string, change func(model.Document)) error {
					d, err := tx.Get(ctx, kind, identifier)
					if err != nil {
						return err
					}
					change(d)
					_, err = tx.Update(ctx, kind, identifier, model.Number(d, "version"), d)
					return err
				}
				switch scenario {
				case "resource_configuration":
					return update("resources", rid, func(d model.Document) { d["instance_type"] = "m6i.xlarge" })
				case "workload_mapping":
					return update("resources", rid, func(d model.Document) { d["workload_id"] = "replay-workload" })
				case "resource_owner":
					return update("resources", rid, func(d model.Document) { d["owner"] = "new-owner" })
				case "workload_criticality":
					return update("workloads", "workload-dev", func(d model.Document) { d["criticality"] = "PRODUCTION" })
				case "policy":
					return update("policies", "policy-default", func(d model.Document) { d["max_off_hours"] = model.Number(d, "max_off_hours") - 1 })
				case "safety_profile":
					p := workload.Profile{SchemaVersion: "1", Criticality: "NON_PRODUCTION", Statefulness: "STATELESS", Timezone: "UTC", MinReplicas: 1, MinZones: 1, Headroom: workload.Headroom{CPUFreePPM: 300000, MemoryFreePPM: 300000}, Saturation: workload.Saturation{CPUP99PPM: 850000, MemoryP99PPM: 900000}, RTOSeconds: 900, MaxSimultaneousChangePPM: 100000}
					latest, err := tx.WorkloadSafetyLatest(ctx, "workload-dev")
					if err != nil && !errors.Is(err, pgx.ErrNoRows) {
						return err
					}
					_, err = tx.WorkloadSafetyAppend(ctx, "workload-dev", model.Number(latest, "version"), p)
					return err
				case "slo":
					o := slo.Objective{SchemaVersion: "1", WorkloadID: "workload-dev", Limits: slo.Limits{MaxErrorRatePPM: 0, MinAvailabilityPPM: 1000000, MaxP95LatencyMS: 200, MaxP99LatencyMS: 200, MinLatencySamples: 1}, EvaluationMinutes: 2, Availability: slo.Availability{Mode: "ALWAYS", Timezone: "UTC", Windows: []slo.Window{}}, Regression: slo.Regression{Enabled: false, MaxPercent: 15}}
					latest, err := tx.SLOObjectiveLatest(ctx, "workload-dev")
					if err != nil && !errors.Is(err, pgx.ErrNoRows) {
						return err
					}
					_, err = tx.SLOObjectiveAppend(ctx, "workload-dev", model.Number(latest, "version"), slo.Document(o))
					return err
				case "telemetry_revision":
					connection, err := tx.TelemetryConnection(ctx, "currentness-native-telemetry")
					if err != nil {
						return err
					}
					_, _, err = tx.TelemetryRevocationAppend(ctx, model.String(connection, "revision_id"), "registered source withdrawn")
					return err
				}
				return errors.New("unhandled currentness scenario")
			}); err != nil {
				t.Fatal(err)
			}
			if scenario == "resource_configuration" {
				reader := f.token(f.tenant, "currentness-reader", "PLATFORM_ADMIN")
				code, public := fleetNativeHTTPGet(t, f, "recommendations/"+id, reader)
				state := storageObject(public["currentness"])
				if code != http.StatusOK || state["status"] != "STALE" || public["pre_execution_ready"] != false || !slices.Contains(model.Strings(state, "reason_codes"), "STALE_RECOMMENDATION") {
					t.Fatalf("ordinary authenticated recommendation read did not project stale evidence: code=%d projection=%#v", code, public["currentness"])
				}
			}
			if err := f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
				historical, err := tx.Get(ctx, "recommendations", id)
				if err != nil {
					return err
				}
				if evidence.Hash(historical) != originalHash {
					t.Fatal("trusted state change rewrote historical recommendation")
				}
				current, err := f.api.recommendationCurrentness(ctx, tx, "EC2", historical)
				if err != nil {
					return err
				}
				state := storageObject(current["currentness"])
				if state["status"] != "STALE" || current["current"] != false || current["pre_execution_ready"] != false || !strings.Contains(strings.Join(model.Strings(state, "reason_codes"), ","), "STALE_RECOMMENDATION") {
					t.Fatalf("changed evidence retained current eligibility: %#v", state)
				}
				if _, err = time.Parse(time.RFC3339Nano, model.String(state, "checked_at")); err != nil {
					t.Fatal("currentness detection time missing", err)
				}
				if evidence.Hash(historical) != originalHash {
					t.Fatal("read-time decoration mutated its input")
				}
				after, err := tx.RecommendationCurrentnessContext(ctx, "EC2", id)
				if err == nil && evidence.Hash(after["baseline"]) != baselineHash {
					t.Fatal("read-time currentness rebased immutable evidence")
				}
				return err
			}); err != nil {
				t.Fatal(err)
			}
			operator := f.token(f.tenant, "currentness-operator", "PLATFORM_ADMIN")
			code, refusal, _ := f.request("change-plans", "", id+"-stale-plan", operator, model.Document{"recommendation_id": id, "schedule_id": "schedule-dev", "memory_state_acknowledged": true, "public_ip_change_acknowledged": true})
			if code != 422 || refusal["error"] != "STALE_RECOMMENDATION" {
				t.Fatal("stale historical recommendation reached new plan creation", code, refusal["error"])
			}
		})
	}
}

// The existing provider-shaped fixture transport issues two distinct CUR heads
// through the ordinary registered-source pipeline. Archive/analytics and Python
// normalization are explicit component doubles, not connected financial proof.
func TestRecommendationCurrentnessRejectsCorrectedNativeBillingHead(t *testing.T) {
	f := newMutationReplayFixture(t)
	ctx := context.Background()
	endpoint, token := trustedEconomics(t)
	api := &API{Store: f.roles["api"], Config: Config{Fixture: true, EconomicsURL: endpoint, EconomicsToken: token}, Client: &http.Client{Timeout: HTTPTimeout}}
	registration := source.FixtureRegistration(f.tenant, "currentness-billing-source")
	if err := f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error { _, err := tx.SourceCreate(ctx, registration); return err }); err != nil {
		t.Fatal(err)
	}
	registered, err := source.ParseRegistration(registration)
	if err != nil {
		t.Fatal(err)
	}
	native := source.FixtureBillingRows(registered, "i-0123456789abcdef0")[:1]
	reader, err := source.NewFixtureReader(registered, native)
	if err != nil {
		t.Fatal(err)
	}
	retimeTrustedDelivery(reader, "currentness-original-delivery", time.Now().UTC().Add(-time.Minute))
	pipeline := source.Pipeline{Store: f.roles["ingester"], ProviderFactory: func(context.Context, source.Registration) (source.Reader, error) { return reader, nil }, Normalize: func(ctx context.Context, in model.Document) (model.Document, error) { return api.economics(ctx, "v3/normalize", in) }, Persist: func(_ context.Context, tenant, _ string, raw, canonical model.Document) error {
		if tenant != f.tenant || len(evidence.Rows(raw["records"])) != len(evidence.Rows(canonical["records"])) || len(evidence.Rows(canonical["records"])) != 1 {
			return errors.New("currentness component canonical population differs")
		}
		return nil
	}, ArchiveObject: func(_ context.Context, tenant, sourceID, _ string, raw []byte) error {
		if tenant != f.tenant || sourceID != registered.ID || len(raw) == 0 {
			return errors.New("currentness component archive binding differs")
		}
		return nil
	}}
	if err = pipeline.Sync(ctx, f.tenant, registered.ID); err != nil {
		t.Fatal(err)
	}
	var original, originalSource, before model.Document
	if err = f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		var err error
		originalSource, err = tx.SourceGet(ctx, registered.ID)
		if err != nil {
			return err
		}
		original, err = tx.Create(ctx, "recommendations", model.Document{"id": "currentness-billing-recommendation", "resource_id": "resource-dev-api", "workload_id": "workload-dev", "status": "VALIDATED", "pre_execution_ready": true, "monthly_saving": "12.340000000001", "currency": "GBP", "source_refs": []model.Document{{"kind": "AWS_CUR2_CONNECTION", "source_connection_id": registered.ID, "source_receipt_id": originalSource["latest_receipt_id"]}}, "expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)})
		if err != nil {
			return err
		}
		before, err = tx.RecommendationCurrentnessContext(ctx, "EC2", model.String(original, "id"))
		if err != nil {
			return err
		}
		current, err := api.recommendationCurrentness(ctx, tx, "EC2", original)
		if err == nil && storageObject(current["currentness"])["status"] != "CURRENT" {
			t.Fatal("original issued billing head was not current", current["currentness"])
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	corrected := model.Clone(native[0])
	corrected["line_item_unblended_cost"] = "0.96"
	previous := reader
	reader, err = source.NewFixtureReader(registered, []model.Document{corrected})
	if err != nil {
		t.Fatal(err)
	}
	retimeTrustedDelivery(reader, "currentness-corrected-delivery", time.Now().UTC().Add(-30*time.Second))
	// The normal synchronizer revisits recent historical execution heads. Keep
	// both genuine fixture deliveries available to that existing reader path.
	reader.Executions = []model.Document{model.Clone(reader.Execution), model.Clone(previous.Execution)}
	for key, object := range previous.Objects {
		reader.Objects[key] = object
	}
	reader.ManifestKeys = append(reader.ManifestKeys, previous.ManifestKeys...)
	if err = pipeline.Sync(ctx, f.tenant, registered.ID); err != nil {
		t.Fatal(err)
	}
	if err = f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		head, err := tx.SourceCheckpointGet(ctx, registered.ID, "month:"+source.ConfigurationHash(registration)+":2026-09")
		if err != nil {
			return err
		}
		if originalSource["latest_receipt_id"] == nil || head["receipt_id"] == originalSource["latest_receipt_id"] {
			t.Fatal("native correction did not issue a new current billing receipt")
		}
		historical, err := tx.Get(ctx, "recommendations", model.String(original, "id"))
		if err != nil {
			return err
		}
		if evidence.Hash(historical) != evidence.Hash(original) {
			t.Fatal("billing correction rewrote historical amount or recommendation")
		}
		current, err := api.recommendationCurrentness(ctx, tx, "EC2", historical)
		if err != nil {
			return err
		}
		state := storageObject(current["currentness"])
		if state["status"] != "STALE" || state["economics_recompute"] != true || current["pre_execution_ready"] != false || !slices.Contains(model.Strings(state, "reason_codes"), "BILLING_SOURCE_CHANGED_OR_REVOKED") {
			t.Fatal("corrected canonical source retained current economics", state)
		}
		after, err := tx.RecommendationCurrentnessContext(ctx, "EC2", model.String(original, "id"))
		if err == nil && evidence.Hash(before["baseline"]) != evidence.Hash(after["baseline"]) {
			t.Fatal("billing correction rebased immutable analysis context")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	viewer := f.token(f.tenant, "currentness-reviewer", "VIEWER")
	code, visible := fleetNativeHTTPGet(t, f, "recommendations/"+model.String(original, "id"), viewer)
	if code != 200 || storageObject(visible["currentness"])["status"] != "STALE" || visible["monthly_saving"] != original["monthly_saving"] || visible["pre_execution_ready"] != false {
		t.Fatal("ordinary authenticated API lost historical money qualification", code, visible["currentness"])
	}
}

func TestRecommendationCurrentnessTenantIsolationAndAppendOnlyContext(t *testing.T) {
	f := newMutationReplayFixture(t)
	ctx := context.Background()
	const recommendationID = "currentness-tenant-isolation-recommendation"
	var original, contextBefore model.Document
	if err := f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		var err error
		original, err = tx.Create(ctx, "recommendations", model.Document{"id": recommendationID, "resource_id": "resource-dev-api", "workload_id": "workload-dev", "status": "VALIDATED", "pre_execution_ready": true, "title": "Tenant isolation fixture", "monthly_saving": "12.340000000001", "currency": "GBP", "expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)})
		if err != nil {
			return err
		}
		contextBefore, err = tx.RecommendationCurrentnessContext(ctx, "EC2", recommendationID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.roles["api"].Do(ctx, f.tenant+"-foreign", func(tx *store.Tx) error {
		d, err := tx.RecommendationCurrentnessContext(ctx, "EC2", recommendationID)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if len(d) != 0 {
			t.Fatal("foreign tenant read captured recommendation context")
		}
		if err = tx.Seed(ctx, true); err != nil {
			return err
		}
		r, err := tx.Get(ctx, "resources", "resource-dev-api")
		if err != nil {
			return err
		}
		r["instance_type"], r["owner"] = "m6i.32xlarge", "foreign-owner"
		_, err = tx.Update(ctx, "resources", "resource-dev-api", model.Number(r, "version"), r)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		after, err := tx.RecommendationCurrentnessContext(ctx, "EC2", recommendationID)
		if err == nil && (evidence.Hash(after["baseline"]) != evidence.Hash(contextBefore["baseline"]) || evidence.Hash(after["current"]) != evidence.Hash(contextBefore["current"])) {
			t.Fatal("foreign tenant changed this recommendation's evidence context")
		}
		if err != nil {
			return err
		}
		raw, err := tx.Get(ctx, "recommendations", recommendationID)
		if err == nil && evidence.Hash(raw) != evidence.Hash(original) {
			t.Fatal("foreign evidence changed immutable historical body")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"UPDATE recommendation_currentness_contexts SET document='{}' WHERE tenant_id=$1 AND family='EC2' AND recommendation_id=$2", "DELETE FROM recommendation_currentness_contexts WHERE tenant_id=$1 AND family='EC2' AND recommendation_id=$2"} {
		if err := f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error { _, err := tx.Exec(ctx, action, f.tenant, recommendationID); return err }); err == nil {
			t.Fatal("API rewrote or removed immutable analysis context")
		}
	}
	foreign := f.token(f.tenant+"-different", "foreign-reviewer", "VIEWER")
	if code, _ := fleetNativeHTTPGet(t, f, "recommendations/"+recommendationID, foreign); code != 404 {
		t.Fatal("cross-tenant recommendation read disclosed context", code)
	}
}

func TestFleetCurrentnessSQLRefusalPreservesReadTransaction(t *testing.T) {
	f := newMutationReplayFixture(t)
	ctx := context.Background()
	admin := databaseAssessmentTestAdmin(t, ctx, f)
	// Fault injection changes only this marked disposable database's broker.
	// It exercises a native SQL domain refusal, not a worker/decision journey.
	if _, err := admin.Pool.Exec(ctx, `CREATE OR REPLACE FUNCTION public.fleet_native_selection_current(p_tenant text,p_old text,p_candidate text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$ BEGIN RAISE EXCEPTION 'fleet history source changed'; END $$`); err != nil {
		t.Fatal(err)
	}
	if err := f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		p := workload.Profile{SchemaVersion: "1", Criticality: "NON_PRODUCTION", Statefulness: "STATELESS", Timezone: "UTC", MinReplicas: 1, MinZones: 1, Headroom: workload.Headroom{CPUFreePPM: 300000, MemoryFreePPM: 300000}, Saturation: workload.Saturation{CPUP99PPM: 850000, MemoryP99PPM: 900000}, RTOSeconds: 900, MaxSimultaneousChangePPM: 100000}
		profile, err := tx.WorkloadSafetyAppend(ctx, "workload-dev", 0, p)
		if err != nil {
			return err
		}
		historical := model.Document{"id": "historical-fleet-component", "workload_id": "workload-dev", "status": "ASSESSED", "selection": model.Document{"groups": model.Document{"old_configuration_proposal": model.Document{"id": "old-stale"}, "candidate_configuration_proposal": model.Document{"id": "candidate-stale"}}, "safety_profile": model.Document{"id": profile["id"], "version": profile["version"], "sha256": profile["hash"]}}, "assessment": model.Document{"status": "BLOCKED"}, "execution_authorized": false, "verified_saving": nil}
		hash := evidence.Hash(historical)
		view, err := f.api.fleetSelectionCurrentness(ctx, tx, historical)
		if err != nil {
			return err
		}
		if storageObject(view["currentness"])["status"] != "STALE" || view["current"] != false || view["execution_authorized"] != false || evidence.Hash(historical) != hash {
			t.Fatal("native refusal did not preserve stale immutable read")
		}
		var healthy bool
		if err = tx.QueryRow(ctx, "SELECT current_user='finops_api'").Scan(&healthy); err != nil || !healthy {
			t.Fatal("SQL domain refusal poisoned the restricted read transaction", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestRecommendationCurrentnessFixtureResetPreservesOriginalContext(t *testing.T) {
	f := newMutationReplayFixture(t)
	ctx := context.Background()
	operator := f.token(f.tenant, "currentness-reset-operator", "PLATFORM_ADMIN")
	var original model.Document
	var previousGeneration string
	if err := f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		var err error
		original, err = tx.RecommendationCurrentnessContext(ctx, "EC2", "recommendation-dev")
		if err != nil {
			return err
		}
		org, err := tx.Get(ctx, "org", f.tenant)
		previousGeneration = model.String(org, "fixture_generation")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if original == nil || previousGeneration == "" {
		t.Fatal("fixture seed did not capture its original generation")
	}
	originalHash := evidence.Hash(original["baseline"])
	code, authority, _ := f.request("resources/resource-dev-api/configuration-authorities", `"0"`, "currentness-pre-reset-authority", operator, configurationRequest())
	if code != 201 || authority["status"] != "DECLARED_NOT_ATTESTED" {
		t.Fatal("fixture authority declaration was not retained", code, authority)
	}
	authorityHash := evidence.Hash(authority)
	if err := f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		fresh, err := tx.Create(ctx, "recommendations", model.Document{"resource_id": "resource-dev-api", "workload_id": "workload-dev", "status": "VALIDATED", "pre_execution_ready": true, "fixture": true, "title": "Same-generation unknown Git regression", "expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)})
		if err != nil {
			return err
		}
		view, err := f.api.recommendationCurrentness(ctx, tx, "EC2", fresh)
		state := storageObject(view["currentness"])
		if err == nil && (state["status"] != "BLOCKED" || view["pre_execution_ready"] != false || !slices.Contains(model.Strings(state, "reason_codes"), "IAC_REVISION_UNAVAILABLE")) {
			t.Fatal("same-generation unattested authority became current", state)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for reset := 0; reset < 2; reset++ {
		code, response, _ := f.request("demo/reset", "", fmt.Sprintf("currentness-reset-%d", reset), operator, model.Document{})
		if code != 200 || response["reset"] != true || response["audit_preserved"] != true || response["ledger_preserved"] != true {
			t.Fatal("fixture reset collided with immutable recommendation context", code, response)
		}
		if err := f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
			org, err := tx.Get(ctx, "org", f.tenant)
			if err != nil {
				return err
			}
			generation := model.String(org, "fixture_generation")
			if generation == "" || generation == previousGeneration {
				t.Fatal("reset reused the earlier fixture evidence generation")
			}
			previousGeneration = generation
			retained, err := tx.RecommendationCurrentnessContext(ctx, "EC2", "recommendation-dev")
			if err != nil {
				return err
			}
			if evidence.Hash(retained["baseline"]) != originalHash || retained["captured_at"] != original["captured_at"] {
				t.Fatal("reset rewrote or renewed the original immutable context")
			}
			retainedAuthority, err := tx.ConfigurationAuthorityGet(ctx, model.String(authority, "id"))
			if err != nil {
				return err
			}
			if evidence.Hash(retainedAuthority) != authorityHash {
				t.Fatal("reset rewrote or removed the original immutable authority")
			}
			seed, err := tx.Get(ctx, "recommendations", "recommendation-dev")
			if err != nil {
				return err
			}
			stale, err := f.api.recommendationCurrentness(ctx, tx, "EC2", seed)
			if err != nil {
				return err
			}
			state := storageObject(stale["currentness"])
			if state["status"] != "STALE" || stale["pre_execution_ready"] != false || !slices.Contains(model.Strings(state, "reason_codes"), "FIXTURE_GENERATION_CHANGED") || state["economics_recompute"] != true || state["telemetry_recollect"] != true {
				t.Fatal("reset seed inherited evidence from the old generation", state)
			}
			fresh, err := tx.Create(ctx, "recommendations", model.Document{"resource_id": "resource-dev-api", "workload_id": "workload-dev", "status": "VALIDATED", "pre_execution_ready": false, "fixture": true, "title": "Fixture context regression component", "expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)})
			if err != nil {
				return err
			}
			current, err := f.api.recommendationCurrentness(ctx, tx, "EC2", fresh)
			if err == nil && (storageObject(current["currentness"])["status"] != "CURRENT" || fresh["id"] == "recommendation-dev") {
				t.Fatal("new recommendation did not capture the current fixture generation", current["currentness"])
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
}
