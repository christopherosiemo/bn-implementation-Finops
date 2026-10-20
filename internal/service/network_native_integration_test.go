package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/auth"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/evidence"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/native"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/network"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
)

// COMPONENT evidence: native-shaped projections are visibly synthetic. The
// separate collector acceptance covers actual provider discovery/Flow parsing,
// ClickHouse and immutable archive ingestion. This check covers the ordinary
// registered billing pipeline, IDs-only API, separate analytical database
// identity, real private Python, immutable publication and optional real OIDC.
// It creates no customer resource, mutation authority or verified saving.
func TestNetworkNativeBillingPersistedAssessmentThroughActualPython(t *testing.T) {
	if os.Getenv("NETWORK_TEST_STORAGE_ENABLED") != "true" {
		t.Skip("owned PostgreSQL/object/analytics components required")
	}
	if os.Getenv("ECONOMICS_TEST_URL") == "" || os.Getenv("ECONOMICS_TEST_TOKEN") == "" {
		t.Fatal("actual private Python required")
	}
	f := newMutationReplayFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	if os.Getenv("FINOPS_NETWORK_BROWSER") == "true" {
		f.tenant = "tenant-demo"
		if e := f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error { return tx.Seed(ctx, true) }); e != nil {
			t.Fatal(e)
		}
	}
	admin := databaseAssessmentTestAdmin(t, ctx, f)
	analyst := databaseAssessmentTestRuntime(t, ctx, admin, "network-assessor", "finops_network_analyst")
	archive, e := native.StorageFromEnvironment(ctx, true)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC()
	end := now.Truncate(24 * time.Hour)
	start := end.Add(-14 * 24 * time.Hour)
	type scenario struct {
		name, want                  string
		resource, canonical, policy model.Document
	}
	cases := []scenario{{name: "gateway", want: "RECOMMENDED"}, {name: "endpoint", want: "NO_CHANGE"}, {name: "missing-flow", want: "BLOCKED"}}
	token := f.token(f.tenant, "network-component-requester", "PLATFORM_ADMIN")
	for index := range cases {
		c := &cases[index]
		r, canonical, p, _, _, _ := networkProjectionFixture()
		// Each scenario is its own coherent VPC/NAT/route/interface population;
		// no two simultaneous snapshots assign conflicting targets to one route.
		raw, _ := json.Marshal(canonical)
		for _, id := range []string{"nat-projection", "vpc-projection", "subnet-client", "subnet-nat", "eni-client", "eni-nat", "rtb-client", "pl-s3"} {
			raw = []byte(strings.ReplaceAll(string(raw), id, id+"-"+c.name))
		}
		canonical = storageObject(json.RawMessage(raw))
		config := storageRows(storageObject(canonical["topology"])["resources"])[0]
		r["id"], r["provider_resource_id"], r["network_configuration"] = "network-resource-"+c.name, config["provider_resource_id"], config
		r["name"], r["workload_id"], r["environment"] = "Synthetic network "+c.name, "network-workload-"+c.name, "NON_PRODUCTION"
		r["state"], r["eligibility"], r["hourly_effective_cost"], r["monthly_effective_cost"], r["currency"] = "AVAILABLE", "OBSERVATION_ONLY", nil, nil, nil
		r["tags"] = model.Document{"evidence_basis": "SYNTHETIC_COMPONENT_NO_PROVIDER_CAPTURE_CLAIM"}
		if e = f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
			if _, e := tx.Create(ctx, "workloads", model.Document{"id": r["workload_id"], "name": "Synthetic network workload", "owner": "network-owner", "owner_subject": "network-owner", "environment": "NON_PRODUCTION"}); e != nil {
				return e
			}
			var e error
			c.resource, e = tx.Create(ctx, "resources", r)
			return e
		}); e != nil {
			t.Fatal(e)
		}
		body := model.Document{"resource_id": r["id"], "name": "Synthetic network requirements " + c.name, "policy": p["policy"]}
		code, policy, _ := f.request("network-policies", `"0"`, "network-native-policy-"+c.name, token, body)
		if code != 201 {
			t.Fatalf("policy %d %#v", code, policy)
		}
		c.policy = policy
		canonical["resource_id"], canonical["observed_at"], canonical["config_hash"] = r["id"], now.Format(time.RFC3339Nano), NetworkConfigurationHash(c.resource)
		canonical["observation_basis"] = "SYNTHETIC_COMPONENT_NO_PROVIDER_CAPTURE_CLAIM"
		metrics := storageObject(canonical["metrics"])
		selection := storageObject(metrics["selection"])
		selection["start"], selection["end"] = start.Format(time.RFC3339), end.Format(time.RFC3339)
		metrics["selection"] = selection
		const halfBytes = int64(168) * 1073741824
		metrics["totals"] = model.Document{"BytesInFromSource": fmt.Sprint(halfBytes), "BytesInFromDestination": fmt.Sprint(halfBytes), "BytesOutToSource": fmt.Sprint(halfBytes), "BytesOutToDestination": fmt.Sprint(halfBytes)}
		canonical["metrics"] = metrics
		flows := storageObject(canonical["flows"])
		coverage := storageObject(flows["coverage"])
		coverage["start"], coverage["end"] = selection["start"], selection["end"]
		flows["coverage"] = coverage
		flowRows := storageRows(flows["cohorts"])
		for _, flow := range flowRows {
			flow["bytes"] = fmt.Sprint(halfBytes)
		}
		flows["cohorts"] = flowRows
		canonical["flows"] = flows
		if c.name == "endpoint" {
			// This synthetic projection exercises the alternative comparison; it
			// does not claim AWS supplies a service-specific managed prefix for
			// every PrivateLink service. Missing actual native destination proof
			// remains a live blocker in provider/collector acceptance.
			raw, _ = json.Marshal(canonical)
			raw = []byte(strings.ReplaceAll(string(raw), ".s3", ".secretsmanager"))
			raw = []byte(strings.ReplaceAll(string(raw), `"S3"`, `"SECRETSMANAGER"`))
			canonical = storageObject(json.RawMessage(raw))
			top := storageObject(canonical["topology"])
			facts := storageRows(top["resources"])
			for _, fact := range facts {
				if fact["resource_type"] == "VPC_ENDPOINT_SERVICE" {
					fact["service_types"] = []string{"Interface"}
					fact["availability_zones"] = []string{"eu-west-1a", "eu-west-1b"}
				}
			}
			facts = append(facts, model.Document{"provider_resource_id": "vpce-native-rate-witness", "resource_type": "VPC_ENDPOINT", "account_id": "111122223333", "region": "eu-west-1", "vpc_id": "vpc-independent-rate-witness", "endpoint_type": "Interface", "service_name": "com.amazonaws.eu-west-1.secretsmanager"})
			top["resources"] = facts
			canonical["topology"] = top
		}
		if c.name == "missing-flow" {
			flows := storageObject(canonical["flows"])
			flows["complete"] = false
			canonical["flows"] = flows
		}
		flows = storageObject(canonical["flows"])
		flows["population_hash"] = evidence.Hash(flows["cohorts"])
		flows["generation_id"] = "synthetic-component-" + model.String(flows, "population_hash")
		canonical["flows"] = flows
		// Bind the final, scenario-specific synthetic topology, rather than a
		// hash from the untouched seed projection used to construct it.
		top := storageObject(canonical["topology"])
		delete(top, "topology_hash")
		topologyHash := evidence.Hash(top)
		top["topology_hash"] = topologyHash
		canonical["topology"] = top
		if e = f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
			current, e := tx.Get(ctx, "resources", model.String(c.resource, "id"))
			if e != nil {
				return e
			}
			current["network_topology_hash"] = topologyHash
			c.resource, e = tx.Update(ctx, "resources", model.String(current, "id"), model.Number(current, "version"), current)
			return e
		}); e != nil {
			t.Fatal(e)
		}
		canonical["config_hash"] = NetworkConfigurationHash(c.resource)
		c.canonical = canonical
	}
	rows, dimensions := networkAssessmentTestCUR(cases[0].resource, cases[1].resource, cases[2].resource, start, end)
	normalizer := &API{Config: Config{Fixture: true, EconomicsURL: os.Getenv("ECONOMICS_TEST_URL"), EconomicsToken: os.Getenv("ECONOMICS_TEST_TOKEN")}, Client: &http.Client{Timeout: HTTPTimeout}}
	billingID := "network-native-billing-" + model.ID()
	versions := map[string]provider.BillingObject{}
	executions := map[string]*source.FixtureReader{}
	databaseAssessmentTestBilling(t, ctx, f, archive, normalizer, billingID, rows, now, versions, executions)
	for index := range cases {
		c := &cases[index]
		c.canonical["price_dimensions"] = dimensions
		networkAssessmentTestPublish(t, ctx, f, archive, c.resource, c.canonical, c.name, token)
	}
	workerCtx, stopWorker := context.WithCancel(ctx)
	done := make(chan error, 1)
	stopped := false
	go func() {
		done <- RunNetworkAssessor(workerCtx, Config{Fixture: true, EconomicsURL: os.Getenv("ECONOMICS_TEST_URL"), EconomicsToken: os.Getenv("ECONOMICS_TEST_TOKEN")}, analyst)
	}()
	defer func() {
		if !stopped {
			stopWorker()
			select {
			case e := <-done:
				if e != nil {
					t.Error(e)
				}
			case <-time.After(5 * time.Second):
				t.Error("network analyst did not stop")
			}
		}
	}()
	issued := map[string]string{}
	hashes := map[string]string{}
	for _, c := range cases {
		body := model.Document{"resource_id": c.resource["id"], "policy_id": c.policy["id"]}
		key := "network-native-" + c.name
		code, d, _ := f.request("network-assessments", `"0"`, key, token, body)
		if code != 202 || d["status"] != "QUEUED" {
			t.Fatalf("IDs-only queue %d %#v", code, d)
		}
		issued[c.name] = model.String(d, "id")
		code, replay, _ := f.request("network-assessments", `"0"`, key, token, body)
		if code != 202 || replay["id"] != d["id"] {
			t.Fatal("idempotent queue replay changed")
		}
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			record := networkAssessmentTestWait(t, ctx, f, issued[c.name], token)
			result := storageObject(record["assessment"])
			if result["status"] != c.want {
				t.Fatalf("persisted status=%v want=%s blockers=%v", result["status"], c.want, result["blockers"])
			}
			if result["execution_authorized"] != false || result["pre_execution_ready"] != false || result["verified_saving"] != nil {
				t.Fatal("network advice became execution or saving")
			}
			if model.String(result, "model_assessment_hash") == "" {
				t.Fatal("actual Python response missing")
			}
			if c.want != "BLOCKED" && !model.Bool(record, "current") {
				t.Fatal("fresh network assessment not current")
			}
			matched := false
			for _, candidate := range storageRows(result["candidates"]) {
				if c.name == "gateway" && candidate["family"] == "A" && candidate["status"] == "RECOMMENDED" {
					n, ok := databaseDecimal(storageObject(candidate["economics"])["estimated_monthly_saving"])
					matched = ok && n.Sign() > 0
				}
				if c.name == "endpoint" && candidate["family"] == "B" && candidate["decision"] == "DO_NOT_CREATE_ENDPOINT" {
					n, ok := databaseDecimal(storageObject(candidate["economics"])["estimated_monthly_saving"])
					matched = ok && n.Sign() < 0
				}
				if storageObject(candidate["security_impact"])["classification"] != "REVIEW_REQUIRED" {
					t.Fatal("security impact missing")
				}
			}
			if c.want != "BLOCKED" && !matched {
				t.Fatalf("customer economics decision missing %#v", result["candidates"])
			}
			hashes[c.name] = evidence.Hash(result)
			code, again := fleetNativeHTTPGet(t, f, "network-assessments/"+issued[c.name], token)
			if code != 200 || evidence.Hash(again["assessment"]) != hashes[c.name] {
				t.Fatal("independent stored result readback differs")
			}
			foreign := f.token("foreign-"+f.tenant, "network-reader", "FINOPS_ADMIN")
			if code, _ := fleetNativeHTTPGet(t, f, "network-assessments/"+issued[c.name], foreign); code != 404 {
				t.Fatal("cross-tenant assessment disclosed")
			}
			code, pub := fleetNativeHTTPGet(t, f, "recommendations/network-"+issued[c.name], token)
			if code != 200 || pub["model_kind"] != "NETWORK_ASSESSMENT_V1" || pub["pre_execution_ready"] != false {
				t.Fatal("ordinary network recommendation missing")
			}
		})
	}
	if t.Failed() {
		return
	}
	if code, _, _ := f.request("network-assessments", `"0"`, "network-browser-price-injection", token, model.Document{"resource_id": cases[0].resource["id"], "current_pricing": model.Document{"rate": "0"}}); code != 422 {
		t.Fatal("browser authoritative price accepted")
	}
	// Corrections append source revisions and stale the old immutable decision.
	corrected := storageRows(rows)
	for _, row := range corrected {
		if row["line_item_resource_id"] == cases[0].resource["provider_resource_id"] && networkChargeKind(row) == "NAT_PROCESSING" {
			row["line_item_net_unblended_rate"], row["line_item_unblended_rate"], row["line_item_net_unblended_cost"], row["line_item_unblended_cost"] = "0.04", "0.04", "0.04", "0.04"
		}
	}
	databaseAssessmentTestBilling(t, ctx, f, archive, normalizer, billingID, corrected, time.Now().UTC(), versions, executions)
	if code, old := fleetNativeHTTPGet(t, f, "network-assessments/"+issued["gateway"], token); code != 200 || model.Bool(old, "current") || evidence.Hash(old["assessment"]) != hashes["gateway"] {
		t.Fatal("source correction rewrote history or retained currentness")
	}
	if code, coverage := fleetNativeHTTPGet(t, f, "coverage", token); code != 200 || len(storageRows(coverage["network_groups"])) == 0 || len(storageRows(coverage["network_component_groups"])) == 0 {
		t.Fatal("network/allAWS coverage unavailable", code)
	}
	if os.Getenv("FINOPS_NETWORK_BROWSER") == "true" {
		stopWorker()
		select {
		case e := <-done:
			stopped = true
			if e != nil {
				t.Fatal(e)
			}
		case <-ctx.Done():
			t.Fatal("component network worker shutdown deadline")
		}
		resources, policies := []model.Document{}, []model.Document{}
		for _, c := range cases {
			resources = append(resources, c.resource)
			policies = append(policies, c.policy)
		}
		networkAssessmentTestBrowser(t, ctx, f, analyst, resources, policies, issued)
	}
}

func networkAssessmentTestCUR(a, b, c model.Document, start, end time.Time) ([]model.Document, []model.Document) {
	rows, dimensions := []model.Document{}, []model.Document{}
	type part struct{ usage, unit, rate, service string }
	parts := []part{{"EUN1-NatGateway-Hours", "Hrs", "0.045", "AmazonEC2"}, {"EUN1-NatGateway-Bytes", "GiB", "0.045", "AmazonEC2"}, {"EUN1-VpcEndpoint-Hours", "Hrs", "1", "AmazonVPC"}, {"EUN1-VpcEndpoint-Bytes", "GiB", "0.5", "AmazonVPC"}}
	for index, part := range parts {
		sku := fmt.Sprintf("SYNTHETICNETWORK%02d", index)
		dimensions = append(dimensions, model.Document{"sku": sku, "rate_code": sku + ".NATIVE.0", "unit": part.unit, "service_code": part.service, "term_type": "OnDemand", "effective_date": start.Add(-24 * time.Hour).Format(time.RFC3339), "begin_range": "0", "end_range": "Inf", "applies_to": []string{}, "attributes": model.Document{"regionCode": "eu-west-1", "usagetype": part.usage, "operation": "SyntheticNetworkUsage"}})
		for at := start; at.Before(end); at = at.Add(time.Hour) {
			resources := []model.Document{a, b, c}
			if index >= 2 {
				resources = []model.Document{{"provider_resource_id": "vpce-native-rate-witness"}}
			}
			for _, resource := range resources {
				rows = append(rows, model.Document{"identity_line_item_id": fmt.Sprintf("synthetic-network-%v-%d-%d", resource["provider_resource_id"], index, at.Unix()), "line_item_usage_account_id": "111122223333", "line_item_resource_id": resource["provider_resource_id"], "line_item_currency_code": "USD", "line_item_line_item_type": "Usage", "line_item_usage_start_date": at.Format(time.RFC3339), "line_item_usage_end_date": at.Add(time.Hour).Format(time.RFC3339), "line_item_unblended_cost": part.rate, "line_item_net_unblended_cost": part.rate, "line_item_unblended_rate": part.rate, "line_item_net_unblended_rate": part.rate, "line_item_usage_amount": "1", "line_item_usage_type": part.usage, "line_item_operation": "SyntheticNetworkUsage", "product_servicecode": part.service, "product_product_family": "Network", "product_region_code": "eu-west-1", "product_sku": sku, "pricing_term": "OnDemand", "pricing_unit": part.unit, "pricing_rate_code": sku + ".NATIVE.0"})
			}
		}
	}
	for _, item := range []struct{ id, kind, cost string }{{"resource-less", "Usage", "3"}, {"credit", "Credit", "-2"}} {
		rows = append(rows, model.Document{"identity_line_item_id": "synthetic-network-" + item.id, "line_item_usage_account_id": "111122223333", "line_item_resource_id": "", "line_item_currency_code": "USD", "line_item_line_item_type": item.kind, "line_item_usage_start_date": start.Format(time.RFC3339), "line_item_usage_end_date": end.Format(time.RFC3339), "line_item_unblended_cost": item.cost, "line_item_net_unblended_cost": item.cost, "product_servicecode": "AmazonVPC", "product_region_code": "eu-west-1", "pricing_term": "OnDemand", "line_item_operation": "SyntheticNetworkUnallocated"})
	}
	return rows, dimensions
}
func networkAssessmentTestPublish(t *testing.T, ctx context.Context, f *mutationReplayFixture, archive *native.Storage, r, canonical model.Document, name, token string) {
	t.Helper()
	config := storageObject(r["network_configuration"])
	body := model.Document{"kind": network.FlowKind, "account_id": "111122223333", "region": "eu-west-1", "read_role_binding_id": "synthetic-network-read", "flow_log_id": "fl-synthetic-" + name, "resource_ids": []string{model.String(config, "vpc_id")}, "report_bucket": "synthetic-network-reports", "report_owner": "111122223333", "report_region": "eu-west-1", "prefix": "AWSLogs/111122223333/vpcflowlogs/eu-west-1/", "fields": strings.Fields("version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status region az-id vpc-id subnet-id pkt-srcaddr pkt-dstaddr pkt-src-aws-service pkt-dst-aws-service flow-direction traffic-path"), "traffic_type": "ALL", "max_aggregation_seconds": 60}
	code, registered, _ := f.request("source-connections", `"0"`, "network-native-source-"+name, token, body)
	if code != 201 {
		t.Fatalf("commissioned source %d %#v", code, registered)
	}
	id := model.String(registered, "id")
	parsed, e := network.ParseRegistration(registered)
	if e != nil {
		t.Fatal(e)
	}
	canonical["source_version"], canonical["source_registration_version"] = "synthetic-component-1", parsed.Version
	wire, _ := json.Marshal(model.Document{"evidence_basis": "SYNTHETIC_COMPONENT_NO_PROVIDER_CAPTURE_CLAIM", "projection": canonical})
	wireRef := databaseAssessmentTestArchive(t, ctx, archive, f.tenant, "wire", "network-projection-"+model.ID(), wire)
	canonical["source_refs"] = []model.Document{storageRef("SYNTHETIC_NETWORK_PROJECTION", model.String(wireRef, "key"), model.String(wireRef, "version_id"), model.String(wireRef, "body_sha256"))}
	receipt, revision := "network-component-receipt-"+model.ID(), "network-component-revision-"+model.ID()
	canonical["source_bindings"] = []model.Document{{"source_id": id, "version": 1, "receipt_id": receipt}}
	raw, _ := json.Marshal(canonical)
	ref := databaseAssessmentTestArchive(t, ctx, archive, f.tenant, "canonical", "network-snapshot-"+model.ID(), raw)
	if e = f.roles["ingester"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		if _, e := tx.SourceRevisionCreate(ctx, model.Document{"id": revision, "source_id": id, "revision_hash": evidence.Hash(canonical), "kind": network.FlowKind, "config_hash": network.Hash(parsed), "source_version": "synthetic-component-1", "source_refs": canonical["source_refs"]}); e != nil {
			return e
		}
		if _, e := tx.SourceReceiptCreate(ctx, model.Document{"id": receipt, "source_id": id, "revision_id": revision, "kind": network.FlowKind, "registration_version": 1, "config_hash": network.Hash(parsed), "source_version": "synthetic-component-1", "complete": true, "complete_traffic_census": false, "evidence_basis": "SYNTHETIC_COMPONENT_NO_PROVIDER_CAPTURE_CLAIM", "snapshot_archive": ref}); e != nil {
			return e
		}
		if e := tx.SourceCheckpointSet(ctx, id, "status", model.Document{"status": "HEALTHY", "latest_revision_id": revision, "latest_receipt_id": receipt}); e != nil {
			return e
		}
		_, e := tx.NetworkEvidenceCreate(ctx, model.String(r, "id"), id, canonical, ref)
		return e
	}); e != nil {
		t.Fatal(e)
	}
}
func networkAssessmentTestWait(t *testing.T, ctx context.Context, f *mutationReplayFixture, id, token string) model.Document {
	t.Helper()
	for {
		code, d := fleetNativeHTTPGet(t, f, "network-assessments/"+id, token)
		if code != 200 {
			t.Fatalf("network persisted read %d %#v", code, d)
		}
		switch d["status"] {
		case "ASSESSED", "BLOCKED":
			return d
		case "FAILED":
			t.Fatal("network analyst failed")
		}
		select {
		case <-ctx.Done():
			t.Fatal("network assessment original deadline")
			return nil
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// Normal-console handoff retains the same original 120-second parent budget,
// existing loopback/JWKS API plumbing and a separate compiled analytical process.
func networkAssessmentTestBrowser(t *testing.T, ctx context.Context, f *mutationReplayFixture, analyst *store.Store, resources, policies []model.Document, componentIDs map[string]string) {
	t.Helper()
	const binary = "/tmp/network-finops"
	if os.Getenv("FINOPS_NETWORK_ASSESSOR_BINARY") != binary {
		t.Fatal("actual compiled network analyst required")
	}
	info, e := os.Lstat(binary)
	if e != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode()&0111 == 0 {
		t.Fatal("network executable unavailable")
	}
	log, e := os.OpenFile("/results/network-analyst.log", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		t.Fatal(e)
	}
	defer log.Close()
	cmd := exec.CommandContext(ctx, binary, "--mode", "network-assessor")
	cmd.Env = []string{"FIXTURE_MODE=true", "PORT=8098", "DATABASE_URL=" + analyst.Pool.Config().ConnConfig.ConnString(), "ECONOMICS_URL=" + os.Getenv("ECONOMICS_TEST_URL"), "ECONOMICS_TOKEN=" + os.Getenv("ECONOMICS_TEST_TOKEN")}
	for _, key := range []string{"OBJECT_REGION", "OBJECT_ENDPOINT", "OBJECT_BUCKET_RAW"} {
		value := os.Getenv(key)
		if value == "" {
			t.Fatal("object binding incomplete")
		}
		cmd.Env = append(cmd.Env, key+"="+value)
	}
	for _, pair := range [][2]string{{"OBJECT_ACCESS_KEY", "FINOPS_NETWORK_READER_ACCESS_KEY"}, {"OBJECT_SECRET_KEY", "FINOPS_NETWORK_READER_SECRET_KEY"}} {
		value := os.Getenv(pair[1])
		if value == "" {
			t.Fatal("version-only reader required")
		}
		cmd.Env = append(cmd.Env, pair[0]+"="+value)
	}
	cmd.Stdout, cmd.Stderr = log, log
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	stopped := false
	defer func() {
		if !stopped {
			_ = cmd.Process.Signal(syscall.SIGTERM)
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				_ = cmd.Process.Kill()
				<-done
			}
		}
	}()
	validator, e := auth.New(ctx, "http://localhost:8081/realms/finops", "finops", "http://keycloak:8080/realms/finops/protocol/openid-connect/certs")
	if e != nil {
		t.Fatal(e)
	}
	listener, e := net.Listen("tcp", ":8097")
	if e != nil {
		t.Fatal(e)
	}
	server := &http.Server{Handler: &API{Store: f.roles["api"], Auth: validator, Config: Config{Fixture: true}}, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 40 * time.Second, WriteTimeout: 40 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	apiDone := make(chan error, 1)
	go func() { apiDone <- server.Serve(listener) }()
	defer func() {
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
		if e := <-apiDone; e != nil && !errors.Is(e, http.ErrServerClosed) {
			t.Error(e)
		}
	}()
	ids, policyIDs := []string{}, []string{}
	for index, r := range resources {
		ids = append(ids, model.String(r, "id"))
		policyIDs = append(policyIDs, model.String(policies[index], "id"))
	}
	ready, e := fleetCapacityBrowserWrite("/results/network-native-ready.json", model.Document{"schema_version": "1", "tenant_id": f.tenant, "resource_ids": ids, "policy_ids": policyIDs})
	if e != nil {
		t.Fatal(e)
	}
	var proof struct {
		SchemaVersion string   `json:"schema_version"`
		TenantID      string   `json:"tenant_id"`
		ReadySHA256   string   `json:"ready_sha256"`
		AssessmentIDs []string `json:"assessment_ids"`
	}
	if e = fleetCapacityBrowserWait(ctx, "network-native-browser-done.json", &proof); e != nil {
		t.Fatal("normal network browser deadline")
	}
	if proof.SchemaVersion != "1" || proof.TenantID != f.tenant || proof.ReadySHA256 != source.BytesHash(ready) || len(proof.AssessmentIDs) != len(ids) {
		t.Fatal("browser result binding differs")
	}
	seen := map[string]bool{}
	for index, id := range proof.AssessmentIDs {
		if id == "" || seen[id] {
			t.Fatal("browser reused ID")
		}
		seen[id] = true
		for _, old := range componentIDs {
			if old == id {
				t.Fatal("browser reused component assessment")
			}
		}
		code, record := fleetNativeHTTPGet(t, f, "network-assessments/"+id, f.token(f.tenant, "network-independent-verifier", "FINOPS_ADMIN"))
		assessment := storageObject(record["assessment"])
		if code != 200 || record["resource_id"] != ids[index] || assessment["status"] != []string{"RECOMMENDED", "NO_CHANGE", "BLOCKED"}[index] {
			t.Fatal("browser publication differs from actual stored result")
		}
		var actor string
		if e = f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
			return tx.QueryRow(ctx, "SELECT created_by FROM network_assessments WHERE tenant_id=$1 AND id=$2", f.tenant, id).Scan(&actor)
		}); e != nil || actor == "" || actor == "network-component-requester" {
			t.Fatal("browser OIDC actor not independently retained")
		}
	}
	if e = cmd.Process.Signal(syscall.SIGTERM); e != nil {
		t.Fatal(e)
	}
	select {
	case e = <-done:
		stopped = true
		if e != nil {
			t.Fatal(e)
		}
	case <-ctx.Done():
		t.Fatal("network analyst shutdown deadline")
	}
}
