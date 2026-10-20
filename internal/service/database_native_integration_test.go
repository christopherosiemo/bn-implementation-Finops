package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/auth"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/native"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/slo"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/workload"
	"github.com/jackc/pgx/v5"
)

// COMPONENT evidence: native-shaped billing uses the real source pipeline,
// private Python normalizer, actual versioned object storage and ClickHouse.
// The RDS canonical projection is an explicitly synthetic transport double;
// the separate workflow collector test proves the actual AWS adapter/parser.
// Neither this test nor its JWT/JWKS helper is live AWS or browser/OIDC proof.
func TestDatabaseNativeBillingPersistedAssessmentThroughActualPython(t *testing.T) {
	if os.Getenv("RDS_TEST_STORAGE_ENABLED") != "true" {
		t.Skip("existing owned RDS PostgreSQL/object/analytics lab required")
	}
	if os.Getenv("ECONOMICS_TEST_URL") == "" || os.Getenv("ECONOMICS_TEST_TOKEN") == "" {
		t.Fatal("actual private Python endpoint and token required")
	}
	f := newMutationReplayFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	if os.Getenv("FINOPS_DATABASE_BROWSER") == "true" {
		f.tenant = "tenant-demo"
		if err := f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error { return tx.Seed(ctx, true) }); err != nil {
			t.Fatal(err)
		}
	}
	admin := databaseAssessmentTestAdmin(t, ctx, f)
	analyst := databaseAssessmentTestRuntime(t, ctx, admin, "database-assessor", "finops_database_analyst")
	activity := databaseAssessmentTestRuntime(t, ctx, admin, "activity-ingress", "finops_activity")
	storage, err := native.StorageFromEnvironment(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	end := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	start := end.AddDate(0, 0, -14)
	type caseData struct {
		name, rate, want          string
		resource, current, target model.Document
		sourceID                  string
	}
	cases := []caseData{{name: "positive", rate: "0.25", want: "RECOMMENDED"}, {name: "uneconomic", rate: "0.5", want: "NO_CHANGE"}, {name: "unknown-capacity", rate: "0.25", want: "BLOCKED"}}
	allNativeRows := []model.Document{}
	for j := range cases {
		c := &cases[j]
		c.current = databaseInputTestNative("db.r6i.12xlarge", "synthetic-"+c.name)
		c.target = databaseInputTestNative("db.r6i.8xlarge", "synthetic-"+c.name+"-target")
		if c.name == "uneconomic" {
			c.current["class"] = "db.r6i.8xlarge"
			c.target["class"] = "db.r6i.12xlarge"
		}
		for _, instance := range []model.Document{c.current, c.target} {
			instance["instance_create_time"] = start.AddDate(0, 0, -30).Format(time.RFC3339)
		}
		wid, rid := "rds-"+c.name, "rds-resource-"+c.name
		if err = f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
			if _, e := tx.Create(ctx, "workloads", model.Document{"id": wid, "name": "Synthetic RDS " + c.name, "owner_subject": "database-component-owner", "environment": "NON_PRODUCTION"}); e != nil {
				return e
			}
			p := workload.Profile{SchemaVersion: "1", Criticality: "NON_PRODUCTION", Statefulness: "STATEFUL", Timezone: "UTC", MinReplicas: 1, MinZones: 1, Headroom: workload.Headroom{CPUFreePPM: 200000, MemoryFreePPM: 200000, ReserveAboveForecastPPM: 100000}, Saturation: workload.Saturation{CPUP99PPM: 700000, MemoryP99PPM: 800000}, RTOSeconds: 300, MaxSimultaneousChangePPM: 100000, VMCooldownSeconds: 86400, Database: &workload.DatabaseLimits{ConnectionsMaxFraction: "0.8", IOPSMaxFraction: "0.8", ThroughputMaxFraction: "0.8", StorageMaxFraction: "0.8", MaxReadLatencySeconds: "0.02", MaxWriteLatencySeconds: "0.02", MaxDiskQueueDepth: "2", MaxReplicaLagSeconds: "2"}}
			if _, e := tx.WorkloadSafetyAppend(ctx, wid, 0, p); e != nil {
				return e
			}
			var e error
			c.resource, e = tx.Create(ctx, "resources", model.Document{"id": rid, "name": "Synthetic provider-shaped RDS " + c.name, "resource_type": "RDS_INSTANCE", "provider": "AWS", "provider_resource_id": c.current["arn"], "account_id": c.current["account_id"], "region": c.current["region"], "workload_id": wid, "owner": "database-component-owner", "environment": "NON_PRODUCTION", "configuration_authority": "GITOPS", "database_configuration": c.current, "tags": model.Document{"evidence_basis": "SYNTHETIC_COMPONENT_NATIVE_SHAPES"}})
			return e
		}); err != nil {
			t.Fatal(err)
		}
		currentRate := "0.5"
		if c.name == "uneconomic" {
			currentRate = "0.25"
		}
		for at := start; at.Before(end); at = at.Add(24 * time.Hour) {
			for _, pair := range []struct {
				native model.Document
				rate   string
			}{{c.current, currentRate}, {c.target, c.rate}} {
				for _, row := range databaseInputTestCUR(pair.native, at, pair.rate) {
					raw := databaseInputObject(row["x_ProviderFields"])
					raw["identity_line_item_id"] = row["x_SourceRecordId"]
					raw["line_item_usage_start_date"] = row["ChargePeriodStart"]
					raw["line_item_usage_end_date"] = row["ChargePeriodEnd"]
					raw["line_item_unblended_cost"] = raw["line_item_net_unblended_cost"]
					raw["line_item_unblended_rate"] = pair.rate
					raw["line_item_usage_type"] = "EU-InstanceUsage:" + model.String(pair.native, "class")
					raw["product_sku"] = "SYNTHETIC-RDS-COMPONENT-" + model.String(pair.native, "class")
					allNativeRows = append(allNativeRows, raw)
				}
			}
		}
	}
	// Genuine payer-shaped fees/credits retain empty usage-account/resource IDs;
	// an unrelated S3 usage line must remain in the spend denominator as well.
	for _, extra := range []struct{ id, service, kind, account, resource, cost string }{{"payer-fee", "AWSSupport", "Fee", "", "", "3"}, {"payer-credit", "AWSSupport", "Credit", "", "", "-2"}, {"unregistered-s3", "AmazonS3", "Usage", "111122223333", "arn:aws:s3:::synthetic-rds-coverage", "7"}} {
		allNativeRows = append(allNativeRows, model.Document{"identity_line_item_id": extra.id, "line_item_usage_account_id": extra.account, "line_item_resource_id": extra.resource, "line_item_currency_code": "USD", "line_item_line_item_type": extra.kind, "line_item_usage_start_date": end.Add(-time.Hour).Format(time.RFC3339), "line_item_usage_end_date": end.Format(time.RFC3339), "line_item_unblended_cost": extra.cost, "line_item_net_unblended_cost": extra.cost, "pricing_term": "OnDemand", "line_item_operation": "SyntheticComponentCharge", "product_servicecode": extra.service, "product_product_family": "Service Charge", "product_region_code": "eu-west-1"})
	}
	sourceID := "rds-native-billing-" + model.ID()
	normalizer := &API{Config: Config{Fixture: true, EconomicsURL: os.Getenv("ECONOMICS_TEST_URL"), EconomicsToken: os.Getenv("ECONOMICS_TEST_TOKEN")}, Client: &http.Client{Timeout: HTTPTimeout}}
	versions := map[string]provider.BillingObject{}
	executions := map[string]*source.FixtureReader{}
	databaseAssessmentTestBilling(t, ctx, f, storage, normalizer, sourceID, allNativeRows, now, versions, executions)
	allInstances := []model.Document{}
	for _, c := range cases {
		allInstances = append(allInstances, c.current, c.target)
	}
	for j := range cases {
		c := &cases[j]
		c.sourceID = sourceID
		canonical := databaseAssessmentTestCanonical(t, ctx, storage, f.tenant, c.resource, c.current, c.target, allInstances, start, end, c.name == "unknown-capacity")
		raw, e := json.Marshal(canonical)
		if e != nil {
			t.Fatal(e)
		}
		ref := databaseAssessmentTestArchive(t, ctx, storage, f.tenant, "canonical", "rds-snapshot-"+model.ID(), raw)
		if err = f.roles["ingester"].Do(ctx, f.tenant, func(tx *store.Tx) error {
			_, e := tx.DatabaseEvidenceAppend(ctx, model.Document{"id": model.ID(), "schema_version": "1", "resource_id": c.resource["id"], "account_id": c.resource["account_id"], "region": c.resource["region"], "config_hash": DatabaseConfigurationHash(c.resource), "content_hash": ref["body_sha256"], "archive": ref, "source_refs": databaseAssessmentTestRawRefs(canonical), "observed_at": time.Now().UTC().Format(time.RFC3339Nano), "period": canonical["period"], "observation_basis": "SYNTHETIC_COMPONENT_NATIVE_SHAPES"})
			return e
		}); err != nil {
			t.Fatal(err)
		}
	}
	// Current application observations use the actual guarded activity LOGIN and
	// actual database receive clock. They continue through minute rollovers.
	resources := []model.Document{}
	for _, c := range cases {
		resources = append(resources, c.resource)
	}
	stopSLO := databaseAssessmentTestSLO(t, ctx, f, activity, resources)
	defer stopSLO()
	workerCtx, stopWorker := context.WithCancel(ctx)
	defer stopWorker()
	workerDone := make(chan error, 1)
	workerStopped := false
	go func() {
		workerDone <- RunDatabaseAssessor(workerCtx, Config{Fixture: true, EconomicsURL: os.Getenv("ECONOMICS_TEST_URL"), EconomicsToken: os.Getenv("ECONOMICS_TEST_TOKEN")}, analyst)
	}()
	t.Cleanup(func() {
		if workerStopped {
			return
		}
		stopWorker()
		select {
		case e := <-workerDone:
			if e != nil {
				t.Error(e)
			}
		case <-time.After(5 * time.Second):
			t.Error("database analyst did not stop")
		}
	})
	token := f.token(f.tenant, "database-component-requester", "FINOPS_ADMIN")
	issuedIDs := map[string]string{}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, queued, _ := f.request("database-assessments", `"0"`, "database-native-"+c.name, token, model.Document{"resource_id": c.resource["id"]})
			if code != 202 || model.String(queued, "status") != "QUEUED" {
				t.Fatal("IDs-only queue", code, queued)
			}
			issuedIDs[c.name] = model.String(queued, "id")
			deadline := time.Now().Add(30 * time.Second)
			var persisted model.Document
			for time.Now().Before(deadline) {
				code, persisted = fleetNativeHTTPGet(t, f, "database-assessments/"+model.String(queued, "id"), token)
				if code != 200 {
					t.Fatal("persisted read", code, persisted)
				}
				if model.String(persisted, "status") == "ASSESSED" || model.String(persisted, "status") == "BLOCKED" {
					break
				}
				time.Sleep(100 * time.Millisecond)
			}
			assessment := databaseInputObject(persisted["assessment"])
			if model.String(assessment, "status") != c.want {
				t.Fatalf("actual persisted result got %s want %s; blockers=%v", model.String(assessment, "status"), c.want, assessment["blockers"])
			}
			if model.String(assessment, "model_version") != databaseModelVersion || model.String(assessment, "model_assessment_hash") == "" {
				t.Fatal("actual Python result not retained", assessment["model_version"])
			}
			proposal := databaseInputObject(assessment["proposal"])
			if proposal["executable"] != false || proposal["execution_authorized"] != false || proposal["risk_class"] != "R3" || assessment["verified_saving"] != nil {
				t.Fatal("read-only boundary changed")
			}
			if c.want != "BLOCKED" {
				if !model.Bool(persisted, "current") {
					t.Fatal("fresh publication not current")
				}
				econ := databaseInputObject(assessment["economics"])
				wantCost := "0.500000000000"
				if c.name == "uneconomic" {
					wantCost = "0.250000000000"
				}
				if econ["currency"] != "USD" || econ["current_hourly_cost"] != wantCost {
					t.Fatal("actual current native CUR price changed", econ)
				}
				if c.want == "RECOMMENDED" && econ["estimated_monthly_saving"] != "182.500000000000" {
					t.Fatal("actual economic difference changed", econ)
				}
				found := false
				for _, ref := range databaseInputRows(assessment["source_refs"]) {
					if model.String(ref, "kind") == "AWS_CUR2_CONNECTION" && len(model.Strings(ref, "economic_record_ids")) >= 48 && len(model.Strings(ref, "historical_configuration_record_ids")) >= 336 {
						found = true
					}
				}
				if !found {
					t.Fatal("server selected economic/history rows not retained")
				}
			}
			if c.name == "uneconomic" {
				found := false
				for _, candidate := range databaseInputRows(assessment["candidates"]) {
					if model.String(candidate, "id") == "class:db.r6i.12xlarge" && model.String(candidate, "decision_code") == "DO_NOT_PROCEED" && strings.HasPrefix(model.String(databaseInputObject(candidate["economics"]), "estimated_monthly_saving"), "-") {
						found = true
					}
				}
				if !found {
					t.Fatal("negative customer price candidate disappeared")
				}
			}
			code, again := fleetNativeHTTPGet(t, f, "database-assessments/"+model.String(queued, "id"), token)
			if code != 200 || source.Hash(again["assessment"]) != source.Hash(persisted["assessment"]) {
				t.Fatal("persisted reload changed assessment")
			}
			other := f.token("other-"+f.tenant, "database-component-reader", "FINOPS_ADMIN")
			if code, _ = fleetNativeHTTPGet(t, f, "database-assessments/"+model.String(queued, "id"), other); code != 404 {
				t.Fatal("cross-tenant read disclosed assessment", code)
			}
		})
	}
	if !t.Failed() {
		databaseAssessmentTestCoverage(t, f, token, allNativeRows, true, true)
		corrected := databaseInputRows(allNativeRows)
		for _, row := range corrected {
			if model.String(row, "product_instance_type") == "db.r6i.8xlarge" {
				for _, key := range []string{"line_item_net_unblended_rate", "line_item_unblended_rate", "line_item_net_unblended_cost", "line_item_unblended_cost"} {
					row[key] = "0.3"
				}
			}
		}
		databaseAssessmentTestBilling(t, ctx, f, storage, normalizer, sourceID, corrected, time.Now().UTC(), versions, executions)
		code, old := fleetNativeHTTPGet(t, f, "database-assessments/"+issuedIDs["positive"], token)
		if code != 200 || model.Bool(old, "current") {
			t.Fatal("actual native CUR correction failed to invalidate old advice", code)
		}
		databaseAssessmentTestCoverage(t, f, token, corrected, true, false)
		partial := []model.Document{}
		for _, row := range corrected {
			right, e := time.Parse(time.RFC3339Nano, model.String(row, "line_item_usage_end_date"))
			if e != nil {
				t.Fatal(e)
			}
			if !right.After(end.Add(-24 * time.Hour)) {
				partial = append(partial, row)
			}
		}
		databaseAssessmentTestBilling(t, ctx, f, storage, normalizer, sourceID, partial, time.Now().UTC(), versions, executions)
		databaseAssessmentTestCoverage(t, f, token, partial, false, false)
		// Restore a fresh complete provider delivery before any optional browser
		// phase. Old immutable publications remain stale; no history is rewritten.
		databaseAssessmentTestBilling(t, ctx, f, storage, normalizer, sourceID, corrected, time.Now().UTC(), versions, executions)
		if os.Getenv("FINOPS_DATABASE_BROWSER") == "true" {
			stopWorker()
			select {
			case err := <-workerDone:
				workerStopped = true
				if err != nil {
					t.Fatal("component analyst shutdown failed")
				}
			case <-ctx.Done():
				t.Fatal("component analyst shutdown deadline")
			}
			databaseAssessmentTestBrowser(t, ctx, f, analyst, []model.Document{cases[0].resource, cases[2].resource, cases[1].resource}, issuedIDs)
		}
	}
}

// Optional normal-console handoff. The fixture keeps its original 120-second
// context; the actual browser must finish in the remaining time. The numerical
// analyst is the real compiled CLI in a separate OS process with its dedicated
// LOGIN. Storage uses the existing local version-only assessment reader, not
// proof of a newly commissioned customer database-specific storage principal.
func databaseAssessmentTestBrowser(t *testing.T, ctx context.Context, f *mutationReplayFixture, analyst *store.Store, resources []model.Document, componentIDs map[string]string) {
	t.Helper()
	const binary = "/tmp/rds-finops"
	if os.Getenv("FINOPS_DATABASE_ASSESSOR_BINARY") != binary {
		t.Fatal("actual compiled database analyst required")
	}
	info, err := os.Lstat(binary)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode()&0111 == 0 {
		t.Fatal("actual database analyst executable unavailable")
	}
	log, err := os.OpenFile("/results/database-analyst.log", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal("private analyst log unavailable")
	}
	defer log.Close()
	cmd := exec.CommandContext(ctx, binary, "--mode", "database-assessor")
	cmd.Env = []string{"FIXTURE_MODE=true", "PORT=8098", "DATABASE_URL=" + analyst.Pool.Config().ConnConfig.ConnString(), "ECONOMICS_URL=" + os.Getenv("ECONOMICS_TEST_URL"), "ECONOMICS_TOKEN=" + os.Getenv("ECONOMICS_TEST_TOKEN")}
	for _, key := range []string{"OBJECT_REGION", "OBJECT_ENDPOINT", "OBJECT_BUCKET_RAW"} {
		value := os.Getenv(key)
		if value == "" {
			t.Fatal("fixture analyst object binding incomplete")
		}
		cmd.Env = append(cmd.Env, key+"="+value)
	}
	for _, pair := range [][2]string{{"OBJECT_ACCESS_KEY", "FINOPS_DATABASE_READER_ACCESS_KEY"}, {"OBJECT_SECRET_KEY", "FINOPS_DATABASE_READER_SECRET_KEY"}} {
		value := os.Getenv(pair[1])
		if value == "" {
			t.Fatal("version-only assessment object reader required")
		}
		cmd.Env = append(cmd.Env, pair[0]+"="+value)
	}
	cmd.Stdout, cmd.Stderr = log, log
	if err = cmd.Start(); err != nil {
		t.Fatal("actual database analyst process failed to start")
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	processStopped := false
	defer func() {
		if !processStopped {
			_ = cmd.Process.Signal(syscall.SIGTERM)
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				_ = cmd.Process.Kill()
				<-done
			}
		}
	}()
	validator, err := auth.New(ctx, "http://localhost:8081/realms/finops", "finops", "http://keycloak:8080/realms/finops/protocol/openid-connect/certs")
	if err != nil {
		t.Fatal("normal OIDC validator unavailable")
	}
	listener, err := net.Listen("tcp", ":8097")
	if err != nil {
		t.Fatal("private normal API listener unavailable")
	}
	server := &http.Server{Handler: &API{Store: f.roles["api"], Auth: validator, Config: Config{Fixture: true}}, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 40 * time.Second, WriteTimeout: 40 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	apiDone := make(chan error, 1)
	go func() { apiDone <- server.Serve(listener) }()
	defer func() {
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
		if e := <-apiDone; e != nil && !errors.Is(e, http.ErrServerClosed) {
			t.Error("normal OIDC API stopped unexpectedly")
		}
	}()
	ids := []string{}
	for _, resource := range resources {
		ids = append(ids, model.String(resource, "id"))
	}
	ready, err := fleetCapacityBrowserWrite("/results/database-native-ready.json", model.Document{"schema_version": "1", "tenant_id": f.tenant, "resource_ids": ids})
	if err != nil {
		t.Fatal("native browser READY publication failed")
	}
	var proof struct {
		SchemaVersion string   `json:"schema_version"`
		TenantID      string   `json:"tenant_id"`
		ReadySHA256   string   `json:"ready_sha256"`
		AssessmentIDs []string `json:"assessment_ids"`
	}
	if err = fleetCapacityBrowserWait(ctx, "/results/database-native-browser-done.json", &proof); err != nil {
		t.Fatal("normal database browser deadline")
	}
	if proof.SchemaVersion != "1" || proof.TenantID != f.tenant || proof.ReadySHA256 != source.BytesHash(ready) || len(proof.AssessmentIDs) != len(resources) {
		t.Fatal("normal database browser result binding differs")
	}
	seen := map[string]bool{}
	for index, id := range proof.AssessmentIDs {
		if id == "" || seen[id] {
			t.Fatal("browser assessment IDs repeated")
		}
		seen[id] = true
		for _, old := range componentIDs {
			if old == id {
				t.Fatal("browser reused component assessment")
			}
		}
		code, record := fleetNativeHTTPGet(t, f, "database-assessments/"+id, f.token(f.tenant, "database-independent-verifier", "FINOPS_ADMIN"))
		assessment := databaseInputObject(record["assessment"])
		want := []string{"RECOMMENDED", "BLOCKED", "NO_CHANGE"}[index]
		if code != 200 || model.String(record, "resource_id") != ids[index] || model.String(assessment, "status") != want || model.String(assessment, "model_assessment_hash") == "" || index != 1 && !model.Bool(record, "current") {
			t.Fatal("actual browser publication differs from stored native result")
		}
		var actor string
		if err = f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
			return tx.QueryRow(ctx, "SELECT created_by FROM database_assessments WHERE tenant_id=$1 AND id=$2", f.tenant, id).Scan(&actor)
		}); err != nil || actor == "" || actor == "database-component-requester" {
			t.Fatal("normal OIDC browser requester was not independently persisted")
		}
	}
	if err = cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal("actual analyst shutdown signal failed")
	}
	select {
	case err = <-done:
		processStopped = true
		if err != nil {
			t.Fatal("actual analyst process did not stop cleanly")
		}
	case <-ctx.Done():
		t.Fatal("actual analyst shutdown deadline")
	}
}

func databaseAssessmentTestCoverage(t *testing.T, f *mutationReplayFixture, token string, records []model.Document, complete, hasAnalysed bool) {
	t.Helper()
	code, out := fleetNativeHTTPGet(t, f, "coverage", token)
	if code != 200 {
		t.Fatal("actual coverage route failed", code)
	}
	groups := databaseInputRows(out["groups"])
	if len(groups) != 1 || groups[0]["currency"] != "USD" {
		t.Fatal("actual coverage currency groups changed")
	}
	group := groups[0]
	period := databaseInputObject(out["period"])
	start, ok := databaseUTC(period, "start")
	end, eok := databaseUTC(period, "end")
	if !ok || !eok {
		t.Fatal("actual coverage window invalid")
	}
	detected, credits, net := new(big.Rat), new(big.Rat), new(big.Rat)
	for _, record := range records {
		at, e := time.Parse(time.RFC3339Nano, model.String(record, "line_item_usage_start_date"))
		if e != nil {
			t.Fatal(e)
		}
		if at.Before(start) || !at.Before(end) {
			continue
		}
		cost, ok := databaseDecimal(record["line_item_net_unblended_cost"])
		if !ok {
			t.Fatal("fixture exact native cost missing")
		}
		net.Add(net, cost)
		if cost.Sign() > 0 {
			detected.Add(detected, cost)
		} else if cost.Sign() < 0 {
			credits.Add(credits, cost)
		}
	}
	for key, want := range map[string]*big.Rat{"detected_spend": detected, "credits": credits, "net_spend": net} {
		got, ok := databaseDecimal(group[key])
		if !ok || got.Cmp(want) != 0 {
			t.Fatal("actual coverage omitted/deducted native charges", key, group[key])
		}
	}
	partition := new(big.Rat)
	for _, key := range []string{"analysed_spend", "observation_only_spend", "blocked_spend", "unsupported_spend"} {
		got, ok := databaseDecimal(group[key])
		if !ok || got.Sign() < 0 {
			t.Fatal("actual coverage category unavailable", key)
		}
		partition.Add(partition, got)
	}
	if partition.Cmp(detected) != 0 {
		t.Fatal("actual coverage partition differs from positive denominator")
	}
	analysed, _ := databaseDecimal(group["analysed_spend"])
	if hasAnalysed && analysed.Sign() <= 0 || !hasAnalysed && analysed.Sign() != 0 {
		t.Fatal("actual coverage analysed stale/unselected/manual facts", group["analysed_spend"])
	}
	if model.Bool(group, "complete") != complete {
		t.Fatal("actual coverage completeness mismatch", out["blockers"])
	}
	if !complete && group["analysed_percent"] != nil {
		t.Fatal("incomplete coverage became known percentage")
	}
	if complete {
		for _, key := range []string{"observation_only_spend", "blocked_spend", "unsupported_spend"} {
			value, _ := databaseDecimal(group[key])
			if value.Sign() <= 0 {
				t.Fatal("unowned/blocked/unsupported charges disappeared", key)
			}
		}
		if group["basis"] != "POSITIVE_BILLED_CHARGES" || credits.Sign() >= 0 {
			t.Fatal("credit/positive denominator basis changed")
		}
	}
}

func databaseAssessmentTestAdmin(t *testing.T, ctx context.Context, f *mutationReplayFixture) *store.Store {
	t.Helper()
	u, e := url.Parse(os.Getenv("TEST_DATABASE_URL"))
	if e != nil {
		t.Fatal(e)
	}
	u.Path = "/" + f.roles["api"].Pool.Config().ConnConfig.Database
	admin, e := store.Open(ctx, u.String())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(admin.Pool.Close)
	return admin
}
func databaseAssessmentTestRuntime(t *testing.T, ctx context.Context, admin *store.Store, runtime, group string) *store.Store {
	t.Helper()
	login := "rds_" + strings.ReplaceAll(model.ID(), "-", "")
	password := model.ID() + model.ID()
	marker := "owned-rds-assessment:" + login
	if _, e := admin.Pool.Exec(ctx, "CREATE ROLE "+pgx.Identifier{login}.Sanitize()+" LOGIN PASSWORD '"+password+"' IN ROLE "+pgx.Identifier{group}.Sanitize()); e != nil {
		t.Fatal(e)
	}
	if _, e := admin.Pool.Exec(ctx, "COMMENT ON ROLE "+pgx.Identifier{login}.Sanitize()+" IS '"+marker+"'"); e != nil {
		t.Fatal(e)
	}
	u, e := url.Parse(admin.Pool.Config().ConnConfig.ConnString())
	if e != nil {
		t.Fatal(e)
	}
	u.User = url.UserPassword(login, password)
	db, e := store.OpenRuntime(ctx, u.String(), runtime)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		db.Pool.Close()
		var actual string
		if e := admin.Pool.QueryRow(context.Background(), "SELECT coalesce(shobj_description(oid,'pg_authid'),'') FROM pg_roles WHERE rolname=$1", login).Scan(&actual); e != nil || actual != marker {
			t.Error("owned RDS analytical LOGIN changed")
			return
		}
		if _, e := admin.Pool.Exec(context.Background(), "DROP ROLE "+pgx.Identifier{login}.Sanitize()); e != nil {
			t.Error(e)
		}
	})
	var session, current string
	if e = db.Pool.QueryRow(ctx, "SELECT session_user,current_user").Scan(&session, &current); e != nil || session != login || current != group {
		t.Fatal("dedicated analytical identity mismatch", e)
	}
	return db
}

func databaseAssessmentTestArchive(t *testing.T, ctx context.Context, s *native.Storage, tenant, kind, id string, raw []byte) model.Document {
	t.Helper()
	ref, e := s.Archive(ctx, tenant, kind, id, raw)
	if e != nil {
		t.Fatal(e)
	}
	back, e := s.Read(ctx, tenant, ref)
	if e != nil || !bytes.Equal(raw, back) {
		t.Fatal("actual versioned native readback differs", e)
	}
	return ref
}

func databaseAssessmentTestBilling(t *testing.T, ctx context.Context, f *mutationReplayFixture, storage *native.Storage, normalizer *API, id string, rows []model.Document, now time.Time, versions map[string]provider.BillingObject, executions map[string]*source.FixtureReader) {
	t.Helper()
	registration := source.FixtureRegistration(f.tenant, id)
	if e := f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		current, e := tx.SourceGet(ctx, id)
		if errors.Is(e, pgx.ErrNoRows) {
			_, e = tx.SourceCreate(ctx, registration)
			return e
		}
		if e == nil {
			registration = current
		}
		return e
	}); e != nil {
		t.Fatal(e)
	}
	r, e := source.ParseRegistration(registration)
	if e != nil {
		t.Fatal(e)
	}
	byMonth := map[string][]model.Document{}
	for _, row := range rows {
		at, e := time.Parse(time.RFC3339Nano, model.String(row, "line_item_usage_start_date"))
		if e != nil {
			t.Fatal(e)
		}
		key := time.Date(at.Year(), at.Month(), 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
		byMonth[key] = append(byMonth[key], row)
	}
	keys := []string{}
	for key := range byMonth {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var combined *source.FixtureReader
	for index, key := range keys {
		month, _ := time.Parse(time.RFC3339, key)
		frame, e := source.NewFixtureReaderForBillingPeriod(r, byMonth[key], month)
		if e != nil {
			t.Fatal(e)
		}
		oldID := model.String(frame.Execution, "ExecutionId")
		execution := "rds-component-" + month.Format("200601") + "-" + source.Hash(byMonth[key])[:12] + fmt.Sprintf("-%x", now.UnixNano())
		objects := map[string]provider.BillingObject{}
		manifestKeys := []string{}
		for key, obj := range frame.Objects {
			next := strings.ReplaceAll(key, "-"+oldID+"/", "-"+execution+"/")
			obj.Key = next
			obj.LastModified = now.Add(-time.Second)
			if strings.HasSuffix(key, "Manifest.json") {
				var manifest model.Document
				if json.Unmarshal(obj.Data, &manifest) != nil {
					t.Fatal("fixture manifest invalid")
				}
				parts := model.Strings(manifest, "reportKeys")
				for j := range parts {
					parts[j] = strings.ReplaceAll(parts[j], "-"+oldID+"/", "-"+execution+"/")
				}
				manifest["reportKeys"] = parts
				obj.Data, _ = json.Marshal(manifest)
				manifestKeys = append(manifestKeys, next)
			}
			obj.VersionID = "rds-component-" + source.BytesHash(obj.Data)
			obj.ETag = source.BytesHash(obj.Data)
			objects[next] = obj
		}
		frame.Execution["ExecutionId"] = execution
		frame.Execution["ExecutionStatus"] = model.Document{"StatusCode": "DELIVERY_SUCCESS", "CreatedAt": now.Add(-time.Duration(len(keys)-index) * time.Second).Format(time.RFC3339Nano)}
		frame.Objects = objects
		frame.ManifestKeys = manifestKeys
		// An open export is complete to its observed end, not an issued invoice.
		// Do not manufacture a monthly invoice before its billing period closes.
		if month.AddDate(0, 1, 0).After(now) {
			frame.Invoices = []model.Document{}
		}
		for _, invoice := range frame.Invoices {
			invoice["IssuedDate"] = now.Add(-time.Second).Format(time.RFC3339Nano)
			amount := databaseInputObject(invoice["BaseCurrencyAmount"])
			amount["CurrencyCode"] = "USD"
			invoice["BaseCurrencyAmount"] = amount
		}
		// Native GetExecution and immutable manifests remain addressable after a
		// correction. Keep their exact original frame; never alias an old ID to
		// the replacement delivery's definition, manifest or versioned body.
		if executions[execution] != nil {
			t.Fatal("synthetic native execution identity repeated")
		}
		executions[execution] = frame
		if combined == nil {
			combined = frame
			combined.Executions = []model.Document{frame.Execution}
		} else {
			combined.Executions = append(combined.Executions, frame.Execution)
			combined.ManifestKeys = append(combined.ManifestKeys, frame.ManifestKeys...)
			combined.Invoices = append(combined.Invoices, frame.Invoices...)
			for key, obj := range frame.Objects {
				combined.Objects[key] = obj
			}
		}
	}
	if combined == nil {
		t.Fatal("native billing population empty")
	}
	for _, object := range combined.Objects {
		versions[object.Key+"\x00"+object.VersionID] = object
	}
	facts := []model.Document{}
	pipeline := source.Pipeline{Store: f.roles["ingester"], ProviderFactory: func(context.Context, source.Registration) (source.Reader, error) {
		return databaseAssessmentBillingReader{combined, versions, executions}, nil
	}, Normalize: normalizer.NormalizeTrustedSource, Persist: func(ctx context.Context, tenant, id string, raw, canonical model.Document) error {
		if e := PersistEvidence(ctx, tenant, id, raw, canonical); e != nil {
			return e
		}
		rows, e := billingFactRows(tenant, id, canonical)
		if e == nil {
			facts = append(facts, rows...)
		}
		return e
	}, ArchiveObject: func(ctx context.Context, tenant, _, key string, raw []byte) error {
		databaseAssessmentTestArchive(t, ctx, storage, tenant, "wire", "billing-"+source.BytesHash([]byte(key)), raw)
		return nil
	}}
	if e = pipeline.Sync(ctx, f.tenant, id); e != nil {
		t.Fatal("real native-shaped billing pipeline failed", e)
	}
	if len(facts) != len(rows) {
		t.Fatal("pipeline changed full native billing population", len(facts), len(rows))
	}
	databaseAssessmentReadbackBilling(t, ctx, storage, f.tenant, id, facts)
	if e = f.roles["ingester"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		r, e := tx.SourceGet(ctx, id)
		if e != nil {
			return e
		}
		if model.String(r, "status") != "HEALTHY" {
			return errors.New("native-shaped export not healthy")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
}

type databaseAssessmentBillingReader struct {
	*source.FixtureReader
	versions   map[string]provider.BillingObject
	executions map[string]*source.FixtureReader
}

func (r databaseAssessmentBillingReader) BillingExecution(ctx context.Context, arn, id string) (model.Document, error) {
	if original := r.executions[id]; original != nil {
		return original.BillingExecution(ctx, arn, id)
	}
	return r.FixtureReader.BillingExecution(ctx, arn, id)
}

func (r databaseAssessmentBillingReader) BillingManifestKeys(ctx context.Context, bucket, prefix, execution string) ([]string, error) {
	if original := r.executions[execution]; original != nil {
		return original.BillingManifestKeys(ctx, bucket, prefix, execution)
	}
	return r.FixtureReader.BillingManifestKeys(ctx, bucket, prefix, execution)
}

func (r databaseAssessmentBillingReader) BillingObject(ctx context.Context, bucket, key, version string) (provider.BillingObject, error) {
	if bucket == r.Registration.Bucket && version != "" {
		if object, ok := r.versions[key+"\x00"+version]; ok {
			object.Data = append([]byte{}, object.Data...)
			return object, nil
		}
	}
	if bucket == r.Registration.Bucket {
		for _, original := range r.executions {
			if _, ok := original.Objects[key]; ok {
				return original.BillingObject(ctx, bucket, key, version)
			}
		}
	}
	return r.FixtureReader.BillingObject(ctx, bucket, key, version)
}
func (r databaseAssessmentBillingReader) BillingInvoices(_ context.Context, _ string, year, month int) ([]model.Document, error) {
	out := []model.Document{}
	for _, invoice := range r.Invoices {
		p := databaseInputObject(invoice["BillingPeriod"])
		if model.Number(p, "Year") == int64(year) && model.Number(p, "Month") == int64(month) {
			out = append(out, invoice)
		}
	}
	return out, nil
}

func databaseAssessmentReadbackBilling(t *testing.T, ctx context.Context, s *native.Storage, tenant, sourceID string, facts []model.Document) {
	t.Helper()
	if len(facts) == 0 || len(facts) > 100000 {
		t.Fatal("native billing readback population invalid")
	}
	wanted := map[string]model.Document{}
	for _, f := range facts {
		key := model.String(f, "source_version") + "\x00" + model.String(f, "source_record_id")
		if wanted[key] != nil {
			t.Fatal("native billing input duplicated")
		}
		wanted[key] = f
	}
	versions := map[string]bool{}
	for _, f := range facts {
		version := model.String(f, "source_version")
		if len(version) != 64 || strings.Trim(version, "0123456789abcdef") != "" {
			t.Fatal("native billing version is not canonical digest")
		}
		versions[version] = true
	}
	literalVersions := []string{}
	for version := range versions {
		literalVersions = append(literalVersions, "'"+version+"'")
	}
	sort.Strings(literalVersions)
	u, e := url.Parse(s.AnalyticsURL)
	if e != nil {
		t.Fatal(e)
	}
	q := u.Query()
	q.Set("database", s.Database)
	q.Set("query", "SELECT source_version,source_record_id,resource_id,currency,toString(billed_cost) AS billed_cost,toString(effective_cost) AS effective_cost,toString(toUnixTimestamp64Nano(source_time)) AS source_time_ns,payload FROM billing_facts FINAL WHERE tenant_id={tenant:String} AND source_id={source:String} AND source_version IN ("+strings.Join(literalVersions, ",")+") ORDER BY source_version,source_record_id FORMAT JSONEachRow")
	q.Set("param_tenant", tenant)
	q.Set("param_source", sourceID)
	u.RawQuery = q.Encode()
	request, e := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), nil)
	if e != nil {
		t.Fatal(e)
	}
	request.Header.Set("X-ClickHouse-User", s.AnalyticsUser)
	request.Header.Set("X-ClickHouse-Key", s.AnalyticsSecret)
	response, e := s.Client.Do(request)
	if e != nil {
		t.Fatal(e)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal("native billing actual readback rejected", response.StatusCode)
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, (64<<20)+1))
	count := 0
	for {
		var got model.Document
		e := decoder.Decode(&got)
		if e == io.EOF {
			break
		}
		if e != nil {
			t.Fatal(e)
		}
		count++
		key := model.String(got, "source_version") + "\x00" + model.String(got, "source_record_id")
		want := wanted[key]
		if count > len(facts) || want == nil || got["payload"] != want["payload"] || got["resource_id"] != want["resource_id"] || got["currency"] != want["currency"] {
			t.Fatal("actual full billing payload/scope differs")
		}
		for _, field := range []string{"billed_cost", "effective_cost"} {
			if want[field] == nil {
				if got[field] != nil {
					t.Fatal("unknown cost became zero")
				}
				continue
			}
			a, aok := new(big.Rat).SetString(model.String(got, field))
			b, bok := new(big.Rat).SetString(model.String(want, field))
			if !aok || !bok || a.Cmp(b) != 0 {
				t.Fatal("actual billing exact decimal differs")
			}
		}
		at, e := time.Parse(time.RFC3339, model.String(want, "source_time"))
		if e != nil || model.String(got, "source_time_ns") != fmt.Sprintf("%d", at.UnixNano()) {
			t.Fatal("actual billing source time differs")
		}
		delete(wanted, key)
	}
	if count != len(facts) || len(wanted) != 0 {
		t.Fatal("actual billing readback population incomplete", count, len(facts))
	}
}

func databaseAssessmentTestCanonical(t *testing.T, ctx context.Context, storage *native.Storage, tenant string, resource, current, target model.Document, allInstances []model.Document, start, end time.Time, unknown bool) model.Document {
	t.Helper()
	put := func(name string, v any) model.Document {
		raw, e := json.Marshal(model.Document{"observation_basis": "SYNTHETIC_COMPONENT_NATIVE_SHAPES_NOT_AWS_ORIGIN", "payload": v})
		if e != nil {
			t.Fatal(e)
		}
		return databaseAssessmentTestArchive(t, ctx, storage, tenant, "wire", "rds-"+model.ID()+"-"+name, raw)
	}
	discovery := model.Document{"instances": allInstances, "clusters": []model.Document{}, "reserved_instances": []model.Document{}, "scope": model.Document{"tenant_id": tenant, "account_id": current["account_id"], "region": current["region"]}}
	discovery["raw_ref"] = put("discovery", discovery)
	options := []model.Document{}
	capacities := []model.Document{}
	baselineAsset := databaseAssessmentTestArchive(t, ctx, storage, tenant, "wire", "rds-ebs-baseline-"+model.ID(), provider.RDSDocumentedIOBaselineAsset())
	for _, instance := range []model.Document{current, target} {
		memory, vcpu, network := int64(412316860416), int64(48), int64(2343750000)
		if instance["class"] == "db.r6i.8xlarge" {
			memory, vcpu, network = 274877906944, 32, 1562500000
		}
		var mem any = memory
		if unknown {
			mem = nil
		}
		options = append(options, model.Document{"class": instance["class"], "engine": instance["engine"], "engine_version": instance["engine_version"], "license_model": instance["license_model"], "storage_type": instance["storage_type"], "multi_az_capable": true, "availability_zones": []string{"eu-west-1a", "eu-west-1b"}, "min_storage_gib": 20, "max_storage_gib": 1000, "min_iops": 1000, "max_iops": 64000, "min_throughput_mibps": 125, "max_throughput_mibps": 1000})
		baseline, err := provider.RDSDocumentedIOBaseline(model.String(instance, "class"))
		if err != nil || baseline == nil {
			t.Fatal("fixed nonburst class IO baseline unavailable")
		}
		capacities = append(capacities, model.Document{"class": instance["class"], "vcpu": vcpu, "memory_bytes": mem, "cpu_model": "IceLake", "architecture": "x86_64", "network_bytes_per_second": network, "status": "OBSERVED_CATALOG_CAPACITY", "ebs_baseline": baseline})
	}
	catalog := model.Document{"instance": current, "options": options, "capacities": capacities, "modification_constraints_status": "OBSERVED_NATIVE_CURRENT_INSTANCE_CONSTRAINTS", "modification_constraints": databaseInputTestModificationConstraints(current)}
	catalog["ebs_baseline_asset_ref"] = baselineAsset
	catalog["raw_ref"] = put("catalog", catalog)
	parameter := model.Document{"instance": current, "connection_capacity": "200", "connection_capacity_status": "EXPLICIT_NATIVE_PARAMETER_LITERAL_ALL_GROUPS_IN_SYNC"}
	parameter["raw_ref"] = put("parameters", parameter)
	rows := []model.Document{}
	values := map[string]string{"cpu_utilization": "10", "freeable_memory": "309237645312", "connections": "20", "read_iops": "100", "write_iops": "50", "read_throughput": "1000000", "write_throughput": "500000", "network_receive": "1000000", "network_transmit": "1000000", "used_storage": "106374182400", "read_latency": "0.002", "write_latency": "0.003", "disk_queue_depth": "0.2"}
	if current["class"] == "db.r6i.8xlarge" {
		values["freeable_memory"] = "206158430208"
	}
	for at := start; at.Before(end); at = at.Add(time.Hour) {
		for _, def := range databaseMetricDefs {
			if def.name == "replica_lag" {
				continue
			}
			rows = append(rows, model.Document{"metric": def.native, "value": values[def.name], "unit": def.unit, "statistic": def.stat, "source_time": at.Format(time.RFC3339), "period_seconds": 3600, "sample_count": 60, "provider_resource_id": current["arn"], "account_id": current["account_id"], "region": current["region"]})
		}
	}
	metrics := model.Document{"selection": model.Document{"resource_arn": current["arn"], "start": start.Format(time.RFC3339), "end": end.Format(time.RFC3339), "period_seconds": 3600}, "metrics": rows}
	metrics["raw_ref"] = put("metrics", metrics)
	plans := model.Document{"status": "OBSERVED_ACCOUNT_ONLY_NOT_COMPLETE_PAYER_PORTFOLIO", "plans": []model.Document{}}
	plans["raw_ref"] = put("empty-database-plans", plans)
	return model.Document{"schema_version": "1", "observation_basis": "SYNTHETIC_COMPONENT_NATIVE_SHAPES_NOT_AWS_ORIGIN", "resource": resource, "discovery": discovery, "catalogs": model.Document{model.String(current, "arn"): catalog}, "parameters": model.Document{model.String(current, "arn"): parameter}, "metrics": []model.Document{metrics}, "commitments": model.Document{"scope_basis": "ACCOUNT_REGION_NATIVE_RDS_RESERVATION_INVENTORY", "reserved_instances": []model.Document{}}, "database_savings_plans": plans, "compute_optimizer": model.Document{"status": "UNKNOWN_NOT_COMMISSIONED"}, "collection_reason_codes": []string{}, "period": model.Document{"start": start.Format(time.RFC3339), "end": end.Format(time.RFC3339)}, "observed_at": time.Now().UTC().Format(time.RFC3339Nano)}
}
func databaseAssessmentTestRawRefs(canonical model.Document) []model.Document {
	out := []model.Document{databaseInputObject(databaseInputObject(canonical["discovery"])["raw_ref"]), databaseInputObject(databaseInputObject(canonical["database_savings_plans"])["raw_ref"])}
	for _, key := range []string{"catalogs", "parameters"} {
		for _, v := range databaseInputObject(canonical[key]) {
			out = append(out, databaseInputObject(databaseInputObject(v)["raw_ref"]))
			if key == "catalogs" {
				out = append(out, databaseInputObject(databaseInputObject(v)["ebs_baseline_asset_ref"]))
			}
		}
	}
	for _, v := range databaseInputRows(canonical["metrics"]) {
		out = append(out, databaseInputObject(v["raw_ref"]))
	}
	return out
}

func databaseAssessmentTestSLO(t *testing.T, ctx context.Context, f *mutationReplayFixture, activity *store.Store, resources []model.Document) func() {
	t.Helper()
	sources := []slo.Source{}
	for _, resource := range resources {
		var src slo.Source
		if e := f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
			objective := slo.Objective{SchemaVersion: "1", WorkloadID: model.String(resource, "workload_id"), EvaluationMinutes: 2, Limits: slo.Limits{MaxErrorRatePPM: 1000, MinAvailabilityPPM: 999000, MaxP95LatencyMS: 100, MaxP99LatencyMS: 200, MinLatencySamples: 1}, Availability: slo.Availability{Mode: "ALWAYS", Timezone: "UTC"}}
			d, e := tx.SLOObjectiveAppend(ctx, objective.WorkloadID, 0, slo.Document(objective))
			if e != nil {
				return e
			}
			src = slo.Source{SchemaVersion: "1", ID: model.ID(), TenantID: f.tenant, ObjectiveID: model.String(d, "id"), WorkloadID: objective.WorkloadID, ResourceID: model.String(resource, "id"), ProviderResourceID: model.String(resource, "provider_resource_id"), AccountID: model.String(resource, "account_id"), Region: model.String(resource, "region"), Issuer: "https://component-slo.invalid", Subject: "synthetic-independent-application-slo", Enabled: true}
			src, e = tx.SLORegister(ctx, src)
			return e
		}); e != nil {
			t.Fatal(e)
		}
		sources = append(sources, src)
	}
	appendMinute := func(src slo.Source, right time.Time) error {
		upper := int64(50)
		in := slo.Interval{SchemaVersion: "1", SourceID: src.ID, ObjectiveID: src.ObjectiveID, WorkloadID: src.WorkloadID, ResourceID: src.ResourceID, Sequence: right.Unix() / 60, IntervalStart: right.Add(-time.Minute), IntervalEnd: right, RequestCount: 100, ErrorCount: 0, AvailabilityGoodSeconds: 60, AvailabilityTotalSeconds: 60, Latency: slo.Histogram{Unit: "milliseconds", SampleCount: 100, Buckets: []slo.Bucket{{UpperBoundMS: &upper, Count: 100}, {UpperBoundMS: nil, Count: 0}}}}
		raw, _ := json.Marshal(in)
		return activity.Do(ctx, f.tenant, func(tx *store.Tx) error {
			_, _, e := tx.SLOAppend(ctx, store.SLOSubmission{Interval: in, RawBody: raw, Issuer: src.Issuer, Subject: src.Subject, IdempotencyKey: fmt.Sprintf("rds-slo-%d", in.Sequence)})
			return e
		})
	}
	// Leave real receipt-admission margin; no future interval or clock override.
	if remaining := time.Until(time.Now().UTC().Truncate(time.Minute).Add(time.Minute)); remaining < 10*time.Second {
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(remaining + 100*time.Millisecond):
		}
	}
	last := time.Now().UTC().Truncate(time.Minute)
	for _, src := range sources {
		for _, right := range []time.Time{last.Add(-time.Minute), last} {
			if e := appendMinute(src, right); e != nil {
				t.Fatal(e)
			}
		}
	}
	workerCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-workerCtx.Done():
				done <- nil
				return
			case <-ticker.C:
				next := time.Now().UTC().Truncate(time.Minute)
				if next.After(last) {
					for _, src := range sources {
						if e := appendMinute(src, next); e != nil {
							done <- e
							return
						}
					}
					last = next
				}
			}
		}
	}()
	return func() {
		cancel()
		select {
		case e := <-done:
			if e != nil {
				t.Error(e)
			}
		case <-time.After(5 * time.Second):
			t.Error("component SLO collector did not stop")
		}
	}
}
