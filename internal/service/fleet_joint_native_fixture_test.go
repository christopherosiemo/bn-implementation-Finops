package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleetassessmentworker"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleetbilling"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleetcapacity"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/telemetry"
	"github.com/jackc/pgx/v5"
)

// The native acceptance supplies the same independently versioned read-only
// archive transport as036. This helper never creates a rate or native fact;
// the production035 broker reads the actual issued current snapshot and raw
// archive versions. Missing CUR/hardware stays UNAVAILABLE.
func fleetJointIssueNativeAssessment(t *testing.T, ctx context.Context, f *mutationReplayFixture, admin *store.Store, proposals []string, capacityRequestID string, archive fleetbilling.PinnedReader, bucket string) (string, error) {
	t.Helper()
	if len(proposals) != 2 || archive == nil || bucket == "" {
		return "", errors.New("JOINT_NATIVE_ISSUER_DEPENDENCY_UNAVAILABLE")
	}
	var capacity model.Document
	if e := f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		var e error
		capacity, e = tx.FleetCapacityBatchGet(ctx, capacityRequestID)
		return e
	}); e != nil {
		return "", e
	}
	if model.String(capacity, "status") != "ASSESSED" || capacity["batch"] == nil {
		return "", errors.New("JOINT_NATIVE_CAPACITY_NOT_ISSUED")
	}
	selection := sourceDocument(capacity["selection"])
	groups := sourceDocument(selection["groups"])
	if model.String(sourceDocument(groups["old_configuration_proposal"]), "id") != proposals[0] || model.String(sourceDocument(groups["candidate_configuration_proposal"]), "id") != proposals[1] {
		return "", errors.New("JOINT_NATIVE_SELECTED_PAIR_DIFFERS")
	}
	profileVersion := model.Number(sourceDocument(selection["safety_profile"]), "version")
	finance := f.token(f.tenant, "native-joint-finance", "FINANCE")
	code, queued, _ := f.request("workloads/fixture-workload/fleet-native-assessments", `"`+strconv.FormatInt(profileVersion, 10)+`"`, "joint-native-rates-"+model.ID(), finance, model.Document{"old_configuration_proposal_id": proposals[0], "candidate_configuration_proposal_id": proposals[1]})
	if code != 202 || fleetbilling.Hash(queued["selection"]) != fleetbilling.Hash(selection) {
		return "", errors.New("JOINT_NATIVE_CURRENT_ASSESSMENT_QUEUE_REFUSED")
	}
	assessor := jointRuntime(t, admin, "finops_group_assessor", "group-assessment-reader")
	cfg := fleetNativeWorkerConfig(f.tenant)
	cfg.ArchiveBucket = bucket
	cfg.ArchiveEndpoint = "http://minio:9000"
	worker, e := fleetassessmentworker.New(ctx, cfg, assessor, archive)
	if e != nil {
		return "", e
	}
	if _, e = worker.Process(ctx, model.String(queued, "id")); e != nil {
		return "", e
	}
	// Re-read the server-issued assessment. Matching IDs alone never substitutes
	// for the repository/current-pin checks performed again by037 publication.
	var issued model.Document
	if e = f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		var e error
		issued, e = tx.FleetNativeAssessmentGet(ctx, model.String(queued, "id"))
		return e
	}); e != nil {
		return "", e
	}
	if model.String(issued, "status") != "ASSESSED" || fleetbilling.Hash(issued["selection"]) != fleetbilling.Hash(selection) {
		return "", errors.New("JOINT_NATIVE_ASSESSMENT_NOT_ISSUED")
	}
	return model.String(issued, "id"), nil
}

func fleetJointMigrateCandidate(t *testing.T, ctx context.Context, admin *store.Store) {
	t.Helper()
	dir := t.TempDir()
	name := "037_fleet_joint_decisions.sql"
	raw, e := os.ReadFile(filepath.Join("..", "..", "migrations", name))
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(dir, name), raw, 0600); e != nil {
		t.Fatal(e)
	}
	if e = admin.Migrate(ctx, dir); e != nil {
		t.Fatal(e)
	}
}

// Prepare the later conditional-rate fixture using ordinary CUR ingestion and
// actual parsed, archived hardware responses. The old036 issued records remain
// historical; callers MUST issue a NEW036 batch and035 assessment after these
// new native pins. The third member still has no telemetry, so this never turns
// incomplete population capacity or historical rates into execution authority.
func fleetJointPublishConditionalNative(t *testing.T, ctx context.Context, f *mutationReplayFixture, scope fleetcapacity.Scope, publish func(context.Context, string, model.Document, []byte), put func(context.Context, string, []byte) model.Document) error {
	t.Helper()
	if fleetcapacity.ValidateScope(scope) != nil || scope.PopulationStatus != "OBSERVED_POINT" || len(scope.CurrentMemberIDs) != 3 || publish == nil || put == nil {
		return errors.New("JOINT_CONDITIONAL_NATIVE_FIXTURE_SCOPE_REFUSED")
	}
	target := scope.Selection.Groups.Binding.Old.Target
	if target.TenantID != f.tenant || target.WorkloadID != "fixture-workload" || target.AccountID != nativeAssessmentAccount || target.Region != "eu-west-1" || scope.Selection.Groups.Binding.Old.SourceID != "assessment-native" {
		return errors.New("JOINT_CONDITIONAL_NATIVE_FIXTURE_TARGET_REFUSED")
	}
	oldIDs := append([]string{}, scope.CurrentMemberIDs...)
	candidateID := "i-eeeeeeeeeeeeeeeee"
	for _, id := range oldIDs {
		if id == candidateID {
			return errors.New("JOINT_CONDITIONAL_NATIVE_FIXTURE_CANDIDATE_COLLISION")
		}
	}
	for _, instance := range append(append([]string{}, oldIDs...), candidateID) {
		kind := "m6i.xlarge"
		if instance == candidateID {
			kind = "m6i.large"
		}
		resourceID := "actual-capacity-" + instance
		var inventory model.Document
		if e := f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
			var e error
			inventory, e = tx.Get(ctx, "resources", resourceID)
			if errors.Is(e, pgx.ErrNoRows) {
				inventory, e = tx.Create(ctx, "resources", model.Document{"id": resourceID, "workload_id": target.WorkloadID, "provider": "AWS", "provider_resource_id": instance, "account_id": target.AccountID, "region": target.Region, "instance_type": kind, "environment": "NON_PRODUCTION"})
			}
			return e
		}); e != nil {
			return e
		}
		if model.String(inventory, "provider_resource_id") != instance || model.String(inventory, "workload_id") != target.WorkloadID || model.String(inventory, "account_id") != target.AccountID || model.String(inventory, "region") != target.Region || model.String(inventory, "instance_type") != kind {
			return errors.New("JOINT_CONDITIONAL_NATIVE_FIXTURE_INVENTORY_DIFFERS")
		}
		var document model.Document
		var raw []byte
		if instance == candidateID {
			hardware, body := nativeAssessmentHardware(t, instance, kind, time.Now().UTC())
			document, raw = source.Object(hardware), body
		} else {
			hardware, body := fleetCapacityFixtureHardware(t, instance, time.Now().UTC())
			document, raw = source.Object(hardware), body
		}
		candidateTypes := []string{"m6i.large"}
		if instance == candidateID {
			candidateTypes = []string{kind}
		}
		publish(ctx, "AWS_EC2_HARDWARE", model.Document{"binding": telemetry.Binding{TenantID: f.tenant, ResourceID: resourceID, WorkloadID: target.WorkloadID, Provider: "AWS", ProviderResourceID: instance, AccountID: target.AccountID, Region: target.Region}, "resource_version": model.Number(inventory, "version"), "resource_snapshot_hash": telemetry.Hash(inventory), "inventory_snapshot": inventory, "candidate_types": candidateTypes, "native": document, "execution_authorized": false}, raw)
	}
	var registration model.Document
	if e := f.roles["ingester"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		var e error
		registration, e = tx.SourceGet(ctx, scope.Selection.Groups.Binding.Old.SourceID)
		return e
	}); e != nil {
		return e
	}
	end := time.Now().UTC().Truncate(24 * time.Hour)
	periodRows, e := fleetJointHourlyBillingRows(oldIDs, candidateID, end)
	if e != nil {
		return e
	}
	parsed, e := source.ParseRegistration(registration)
	if e != nil {
		return e
	}
	reader := &nativeAssessmentBillingReader{}
	keys := []string{}
	for key := range periodRows {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		period, e := time.Parse("2006-01", key)
		if e != nil {
			return e
		}
		reader.months = append(reader.months, nativeAssessmentExport(t, parsed, period, periodRows[key], time.Now().UTC()))
	}
	reader.FixtureReader = reader.months[0]
	normalize := func(_ context.Context, raw model.Document) (model.Document, error) {
		rows := []model.Document{}
		for _, p := range source.Rows(raw["records"]) {
			cost := p["line_item_unblended_cost"]
			if model.String(p, "line_item_net_unblended_cost") != "" {
				cost = p["line_item_net_unblended_cost"]
			}
			rows = append(rows, model.Document{"x_SourceRecordId": p["identity_line_item_id"], "x_SourceId": raw["source_id"], "x_SourceVersion": raw["source_version"], "x_ProviderFields": p, "SubAccountId": p["line_item_usage_account_id"], "ResourceId": p["line_item_resource_id"], "RegionId": p["product_region_code"], "BillingCurrency": p["line_item_currency_code"], "BillingAccountId": p["bill_payer_account_id"], "ChargePeriodStart": p["line_item_usage_start_date"], "ChargePeriodEnd": p["line_item_usage_end_date"], "BilledCost": cost})
		}
		return model.Document{"records": rows}, nil
	}
	// Only this isolated coordinator receives the owned analytics credential.
	// Neither the decision daemon nor the public API receives it.
	secret := os.Getenv("FLEET_CAPACITY_CLICKHOUSE_PASSWORD")
	if secret == "" {
		return errors.New("JOINT_OWNED_ANALYTICS_CREDENTIAL_UNAVAILABLE")
	}
	t.Setenv("CLICKHOUSE_URL", "http://clickhouse:8123/")
	t.Setenv("CLICKHOUSE_DATABASE", "finops")
	t.Setenv("CLICKHOUSE_USER", "finops")
	t.Setenv("CLICKHOUSE_PASSWORD", secret)
	expectedFacts := []model.Document{}
	pipeline := source.Pipeline{Store: f.roles["ingester"], ProviderFactory: func(context.Context, source.Registration) (source.Reader, error) { return reader, nil }, Normalize: normalize, Persist: func(c context.Context, tenant, src string, raw, canonical model.Document) error {
		encoded, e := json.Marshal(raw)
		if e != nil {
			return e
		}
		put(c, "tenant/"+tenant+"/joint-cur-source/"+source.BytesHash(encoded)+".json", encoded)
		facts, e := billingFactRows(tenant, src, canonical)
		if e != nil {
			return e
		}
		if e = persistBillingFacts(c, tenant, src, canonical); e != nil {
			return e
		}
		expectedFacts = append(expectedFacts, facts...)
		return nil
	}, ArchiveObject: func(c context.Context, tenant, src, key string, raw []byte) error {
		put(c, "tenant/"+tenant+"/source/"+src+"/"+source.BytesHash([]byte(key))+".raw", raw)
		return nil
	}}
	if e = pipeline.Sync(ctx, f.tenant, scope.Selection.Groups.Binding.Old.SourceID); e != nil {
		return e
	}
	return fleetJointReadbackBillingFacts(ctx, f.tenant, secret, expectedFacts)
}

func fleetJointReadbackBillingFacts(ctx context.Context, tenant, secret string, facts []model.Document) error {
	if !tenantKey.MatchString(tenant) || len(facts) != 1032 {
		return errors.New("JOINT_CUR_CANONICAL_POPULATION_DIFFERS")
	}
	byID := map[string]model.Document{}
	versions := map[string]bool{}
	for _, row := range facts {
		version := model.String(row, "source_version")
		if !daemonFixtureSHA.MatchString(version) || row["tenant_id"] != tenant || row["source_id"] != "assessment-native" {
			return errors.New("JOINT_CUR_CANONICAL_SCOPE_DIFFERS")
		}
		key := version + ":" + model.String(row, "source_record_id")
		if byID[key] != nil {
			return errors.New("JOINT_CUR_CANONICAL_ID_DUPLICATE")
		}
		byID[key] = row
		versions[version] = true
	}
	selected := []string{}
	for version := range versions {
		selected = append(selected, version)
	}
	sort.Strings(selected)
	if len(selected) < 1 || len(selected) > 2 {
		return errors.New("JOINT_CUR_MONTH_COUNT_DIFFERS")
	}
	quoted := []string{}
	for _, version := range selected {
		quoted = append(quoted, "'"+version+"'")
	}
	query := "SELECT source_version,source_record_id,resource_id,currency,toString(billed_cost) AS billed_cost,toString(effective_cost) AS effective_cost,toString(toUnixTimestamp64Nano(source_time)) AS source_time_ns,payload FROM billing_facts FINAL WHERE tenant_id='" + tenant + "' AND source_id='assessment-native' AND source_version IN (" + strings.Join(quoted, ",") + ") ORDER BY source_version,source_record_id FORMAT JSONEachRow"
	u := "http://clickhouse:8123/?" + url.Values{"database": {"finops"}, "query": {query}}.Encode()
	request, e := http.NewRequestWithContext(ctx, http.MethodPost, u, nil)
	if e != nil {
		return e
	}
	request.Header.Set("X-ClickHouse-User", "finops")
	request.Header.Set("X-ClickHouse-Key", secret)
	client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	response, e := client.Do(request)
	if e != nil {
		return errors.New("JOINT_CUR_ANALYTICS_READBACK_UNAVAILABLE")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return errors.New("JOINT_CUR_ANALYTICS_READBACK_REFUSED")
	}
	raw, e := io.ReadAll(io.LimitReader(response.Body, (4<<20)+1))
	if e != nil || len(raw) > 4<<20 {
		return errors.New("JOINT_CUR_ANALYTICS_READBACK_BOUND")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	count := 0
	for {
		var row model.Document
		e = decoder.Decode(&row)
		if e == io.EOF {
			break
		}
		if e != nil {
			return errors.New("JOINT_CUR_ANALYTICS_READBACK_INVALID")
		}
		count++
		if count > 1032 {
			return errors.New("JOINT_CUR_ANALYTICS_READBACK_EXCESS")
		}
		key := model.String(row, "source_version") + ":" + model.String(row, "source_record_id")
		want := byID[key]
		if want == nil || row["resource_id"] != want["resource_id"] || row["currency"] != want["currency"] || row["payload"] != want["payload"] {
			return errors.New("JOINT_CUR_ANALYTICS_COLUMN_DIFFERS")
		}
		cost, ok := new(big.Rat).SetString(model.String(row, "billed_cost"))
		expected, ok2 := new(big.Rat).SetString(model.String(want, "billed_cost"))
		at, e := time.Parse(time.RFC3339, model.String(want, "source_time"))
		if !ok || !ok2 || cost.Cmp(expected) != 0 || row["effective_cost"] != want["effective_cost"] || e != nil || model.String(row, "source_time_ns") != strconv.FormatInt(at.UnixNano(), 10) {
			return errors.New("JOINT_CUR_ANALYTICS_EXACT_FACT_DIFFERS")
		}
		delete(byID, key)
	}
	if count != 1032 || len(byID) != 0 {
		return errors.New("JOINT_CUR_ANALYTICS_POPULATION_DIFFERS")
	}
	runID := os.Getenv("FLEET_CAPACITY_BROWSER_RUN_ID")
	if !daemonFixtureUUID.MatchString(runID) {
		return errors.New("JOINT_CUR_RUN_ID_INVALID")
	}
	_, e = jointBrowserWrite("/results/joint-cur-analytics-ready.json", model.Document{"schema_version": "1", "run_id": runID, "tenant_id": tenant, "source_id": "assessment-native", "source_versions": selected, "expected_rows": 1032, "readback_rows": count, "canonical_sha256": fleetbilling.Hash(facts), "actual_clickhouse": true, "actual_source_pipeline": true, "fixture": true, "financial_execution_authorized": false})
	return e
}

// Match the provider export's declared HOURLY granularity. Three members use
// 1008 one-hour old rows plus24 historical candidate rows. The existing native
// fixture splits400 rows/CSV; the ordinary pipeline cap remains100000 rows.
func fleetJointHourlyBillingRows(oldIDs []string, candidateID string, end time.Time) (map[string][]model.Document, error) {
	if len(oldIDs) < 1 || len(oldIDs) > 256 || candidateID == "" || !end.Equal(end.UTC().Truncate(24*time.Hour)) {
		return nil, errors.New("JOINT_HOURLY_FIXTURE_SCOPE_REFUSED")
	}
	seen := map[string]bool{candidateID: true}
	for _, id := range oldIDs {
		if id == "" || seen[id] {
			return nil, errors.New("JOINT_HOURLY_FIXTURE_MEMBERS_REFUSED")
		}
		seen[id] = true
	}
	rows := map[string][]model.Document{}
	count := 0
	end = end.UTC()
	for i := 14 * 24; i > 0; i-- {
		start := end.Add(-time.Duration(i) * time.Hour)
		for _, id := range oldIDs {
			rows[start.Format("2006-01")] = append(rows[start.Format("2006-01")], nativeAssessmentUsage(id, "m6i.xlarge", "ACTUAL-FIXTURE-OLD-SKU", "0.2", "0.2", start, start.Add(time.Hour)))
			count++
		}
	}
	for i := 24; i > 0; i-- {
		start := end.Add(-time.Duration(i) * time.Hour)
		rows[start.Format("2006-01")] = append(rows[start.Format("2006-01")], nativeAssessmentUsage(candidateID, "m6i.large", "ACTUAL-FIXTURE-CANDIDATE-SKU", "0.12", "0.12", start, start.Add(time.Hour)))
		count++
	}
	if count != len(oldIDs)*14*24+24 || count > 100000 {
		return nil, errors.New("JOINT_HOURLY_FIXTURE_BOUND_REFUSED")
	}
	return rows, nil
}

func TestJointDecisionHourlyProviderFixtureHasExactCoverageAndCosts(t *testing.T) {
	old := []string{"i-11111111111111111", "i-22222222222222222", "i-33333333333333333"}
	candidate := "i-eeeeeeeeeeeeeeeee"
	end := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	periods, e := fleetJointHourlyBillingRows(old, candidate, end)
	if e != nil {
		t.Fatal(e)
	}
	count := 0
	members := map[string]int{}
	seen := map[string]bool{}
	for _, rows := range periods {
		for _, r := range rows {
			count++
			id := model.String(r, "line_item_resource_id")
			members[id]++
			key := model.String(r, "identity_line_item_id")
			if seen[key] {
				t.Fatal("duplicate hourly provider identity")
			}
			seen[key] = true
			start, e := time.Parse(time.RFC3339Nano, model.String(r, "line_item_usage_start_date"))
			if e != nil {
				t.Fatal(e)
			}
			finish, e := time.Parse(time.RFC3339Nano, model.String(r, "line_item_usage_end_date"))
			if e != nil || finish.Sub(start) != time.Hour || model.String(r, "line_item_usage_amount") != "1" || start.Before(end.Add(-14*24*time.Hour)) || finish.After(end) {
				t.Fatal("nonhourly or out-of-scope fixture row", e)
			}
			rate := "0.2"
			if id == candidate {
				rate = "0.12"
			}
			if model.String(r, "line_item_unblended_cost") != rate || model.String(r, "line_item_unblended_rate") != rate {
				t.Fatal("hourly cost/rate mismatch")
			}
		}
	}
	if count != 1032 || members[candidate] != 24 {
		t.Fatal("complete bounded hourly population differs", count)
	}
	for _, id := range old {
		if members[id] != 336 {
			t.Fatal("old member coverage truncated", id)
		}
	}
	if _, e = fleetJointHourlyBillingRows(old, candidate, end.Add(time.Hour)); e == nil {
		t.Fatal("partial UTC day admitted")
	}
	if _, e = fleetJointHourlyBillingRows(append(old, old[0]), candidate, end); e == nil {
		t.Fatal("duplicated member extrapolated")
	}
}
