package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/auth"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/configuration"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/native"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/workload"
)

// COMPONENT evidence only. The billing transport double enters the ordinary
// registered source pipeline and actual private normalizer, SQL, versioned
// object store and analytics readback. Native EBS projections below are visibly
// synthetic component inputs; the workflow test independently exercises the
// actual provider adapter/parser. This test creates no AWS resources and grants
// no execution authority, customer-history claim or verified saving.
func TestStorageNativeBillingPersistedAssessmentThroughActualPython(t *testing.T) {
	if os.Getenv("EBS_TEST_STORAGE_ENABLED") != "true" {
		t.Skip("existing owned PostgreSQL/object/analytics components required")
	}
	if os.Getenv("ECONOMICS_TEST_URL") == "" || os.Getenv("ECONOMICS_TEST_TOKEN") == "" {
		t.Fatal("actual private Python endpoint required")
	}
	f := newMutationReplayFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	if os.Getenv("FINOPS_STORAGE_BROWSER") == "true" {
		f.tenant = "tenant-demo"
		if e := f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error { return tx.Seed(ctx, true) }); e != nil {
			t.Fatal(e)
		}
	}
	admin := databaseAssessmentTestAdmin(t, ctx, f)
	analyst := databaseAssessmentTestRuntime(t, ctx, admin, "storage-assessor", "finops_storage_analyst")
	activity := databaseAssessmentTestRuntime(t, ctx, admin, "activity-ingress", "finops_activity")
	archive, e := native.StorageFromEnvironment(ctx, true)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC()
	end := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	start := end.AddDate(0, 0, -14)
	type scenario struct {
		name, want, kind string
		native, resource model.Document
	}
	cases := []scenario{{name: "gp2-positive", want: "RECOMMENDED", kind: "STORAGE_GP2_TO_GP3"}, {name: "gp3-iops", want: "RECOMMENDED", kind: "STORAGE_GP3_IOPS_RIGHTSIZE"}, {name: "gp3-throughput", want: "RECOMMENDED", kind: "STORAGE_GP3_THROUGHPUT_RIGHTSIZE"}, {name: "missing-telemetry", want: "BLOCKED"}, {name: "unattached-review", want: "OBSERVATION_ONLY", kind: "STORAGE_UNATTACHED_REVIEW"}, {name: "snapshot-unknown-review", want: "OBSERVATION_ONLY", kind: "STORAGE_SNAPSHOT_RETENTION_REVIEW"}}
	volumes := []model.Document{}
	for j := range cases {
		c := &cases[j]
		id := fmt.Sprintf("vol-%017x", 0xeb5000000000100+j)
		c.native = storageAssessmentNativeVolume(id, start)
		attachment := databaseInputRows(c.native["attachments"])[0]
		attachment["device"] = fmt.Sprintf("/dev/sd%c", 'f'+rune(j))
		c.native["attachments"] = []model.Document{attachment}
		if c.name == "gp3-iops" {
			c.native["volume_type"], c.native["iops"], c.native["throughput_mibps"] = "gp3", 9000, 125
		}
		if c.name == "gp3-throughput" {
			c.native["volume_type"], c.native["iops"], c.native["throughput_mibps"] = "gp3", 3000, 500
		}
		if c.name == "unattached-review" {
			c.native["state"] = "available"
			c.native["attachments"] = []model.Document{}
		}
		typ := "EBS_VOLUME"
		if c.name == "snapshot-unknown-review" {
			typ = "EBS_SNAPSHOT"
			id = "snap-0eb50000000000100"
			c.native = model.Document{"snapshot_id": id, "provider_resource_id": id, "volume_id": cases[0].native["volume_id"], "account_id": "111122223333", "region": "eu-west-1", "state": "completed", "start_time": start.AddDate(0, 0, -90).Format(time.RFC3339), "storage_tier": "standard", "encrypted": true, "kms_key_id": nil, "volume_size_gib": 1000, "create_volume_permissions": nil, "create_volume_permissions_status": "UNKNOWN_COMPONENT_NOT_COMMISSIONED"}
		}
		if e = f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
			wid, rid := "storage-workload-"+c.name, "storage-resource-"+c.name
			if _, e := tx.Create(ctx, "workloads", model.Document{"id": wid, "name": "Synthetic EBS " + c.name, "owner_subject": "storage-component-owner", "environment": "NON_PRODUCTION"}); e != nil {
				return e
			}
			no := false
			p := workload.Profile{SchemaVersion: "1", Criticality: "NON_PRODUCTION", Statefulness: "STATEFUL", Timezone: "UTC", MinReplicas: 1, MinZones: 1, Headroom: workload.Headroom{CPUFreePPM: 200000, MemoryFreePPM: 200000, ReserveAboveForecastPPM: 100000}, Saturation: workload.Saturation{CPUP99PPM: 700000, MemoryP99PPM: 800000}, RTOSeconds: 300, MaxSimultaneousChangePPM: 100000, VMCooldownSeconds: 86400, Storage: &workload.StorageLimits{IOPSMaxFraction: "0.8", ThroughputMaxFraction: "0.8", MaxReadLatencySeconds: "0.02", MaxWriteLatencySeconds: "0.02", MaxDiskQueueDepth: "2", MinBurstBalancePercent: "20", SnapshotRetentionDays: 30, QuarantineDays: 14, BackupRequired: &no, AllowDurabilityReduction: &no, RequireMultiAttach: &no, FilesystemReviewRequired: &no}}
			if _, e := tx.WorkloadSafetyAppend(ctx, wid, 0, p); e != nil {
				return e
			}
			var e error
			c.resource, e = tx.Create(ctx, "resources", model.Document{"id": rid, "name": "Synthetic provider-shaped EBS " + c.name, "resource_type": typ, "provider": "AWS", "provider_resource_id": id, "account_id": "111122223333", "region": "eu-west-1", "workload_id": wid, "owner": "storage-component-owner", "environment": "NON_PRODUCTION", "configuration_authority": "TERRAFORM", "storage_configuration": c.native, "tags": model.Document{"evidence_basis": "SYNTHETIC_COMPONENT_NATIVE_SHAPES_NO_LIVE_CUSTOMER_CLAIM"}})
			if e != nil {
				return e
			}
			address := fmt.Sprintf("aws_ebs_volume.fixture_%d", j)
			if typ == "EBS_SNAPSHOT" {
				address = "aws_ebs_snapshot.fixture"
			}
			d := configuration.Declaration{SchemaVersion: "1", Authority: "TERRAFORM", Repository: configuration.Repository{URL: "https://github.com/example/synthetic-component-infrastructure.git", Ref: "main", Directory: "storage"}, Pipeline: configuration.Pipeline{System: "GITHUB_ACTIONS", Identity: configuration.PipelineIdentity{Issuer: "https://token.actions.githubusercontent.com", Audience: configuration.ObserverAudience, Subject: "repo:example/synthetic-component-infrastructure:ref:refs/heads/main", PipelineID: ".github/workflows/deploy.yml"}}, Terraform: configuration.Terraform{Workspace: "component-eu-" + c.name, StateLineage: model.ID(), Addresses: []string{address}}}
			_, e = tx.ConfigurationAuthorityAppend(ctx, rid, 0, "storage-component-owner", d)
			return e
		}); e != nil {
			t.Fatal(e)
		}
		if typ == "EBS_VOLUME" {
			volumes = append(volumes, c.native)
		}
	}
	// An actual native gp3 peer has both billed performance components. It stays
	// outside the owned resources and therefore inside the coverage denominator.
	peer := storageAssessmentNativeVolume("vol-0eb50000000000999", start)
	peer["volume_type"], peer["iops"], peer["throughput_mibps"] = "gp3", 9000, 500
	peerAttachment := databaseInputRows(peer["attachments"])[0]
	peerAttachment["device"] = "/dev/sdz"
	peer["attachments"] = []model.Document{peerAttachment}
	volumes = append(volumes, peer)
	snapshots := []model.Document{cases[len(cases)-1].native}
	rows := storageAssessmentNativeCUR(volumes, snapshots, end.Add(-24*time.Hour), end, "0.08")
	for _, extra := range []struct{ id, service, kind, account, resource, cost string }{{"payer-fee", "AWSSupport", "Fee", "", "", "3"}, {"payer-credit", "AWSSupport", "Credit", "", "", "-2"}, {"unregistered-service", "AmazonS3", "Usage", "111122223333", "arn:aws:s3:::synthetic-storage-coverage", "7"}} {
		rows = append(rows, model.Document{"identity_line_item_id": extra.id, "line_item_usage_account_id": extra.account, "line_item_resource_id": extra.resource, "line_item_currency_code": "USD", "line_item_line_item_type": extra.kind, "line_item_usage_start_date": end.Add(-time.Hour).Format(time.RFC3339), "line_item_usage_end_date": end.Format(time.RFC3339), "line_item_unblended_cost": extra.cost, "line_item_net_unblended_cost": extra.cost, "pricing_term": "OnDemand", "line_item_operation": "SyntheticComponentCharge", "product_servicecode": extra.service, "product_product_family": "Service Charge", "product_region_code": "eu-west-1"})
	}
	normalizer := &API{Config: Config{Fixture: true, EconomicsURL: os.Getenv("ECONOMICS_TEST_URL"), EconomicsToken: os.Getenv("ECONOMICS_TEST_TOKEN")}, Client: &http.Client{Timeout: HTTPTimeout}}
	sourceID := "storage-native-billing-" + model.ID()
	versions := map[string]provider.BillingObject{}
	executions := map[string]*source.FixtureReader{}
	databaseAssessmentTestBilling(t, ctx, f, archive, normalizer, sourceID, rows, now, versions, executions)
	resources := []model.Document{}
	for _, c := range cases {
		resources = append(resources, c.resource)
	}
	stopSLO := databaseAssessmentTestSLO(t, ctx, f, activity, resources[:4])
	defer stopSLO()
	token := f.token(f.tenant, "storage-component-requester", "PLATFORM_ADMIN")
	// The operator explicitly acknowledges discovered and external dependencies
	// against the real current tenant graph. A stop-action readiness BLOCKED
	// status is not recast as execution approval for these analytical records.
	var graph model.Document
	if e = f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error { var e error; graph, e = dependencyGraph(ctx, tx); return e }); e != nil {
		t.Fatal(e)
	}
	if code, _, _ := f.request("resource-graph", fmt.Sprintf(`"%d"`, model.Number(graph, "version")), "storage-graph-declaration", token, model.Document{"edges": []any{}, "reason": "Synthetic component operator explicitly declares reviewed storage dependencies"}); code != 201 {
		t.Fatal("actual resource graph declaration", code)
	}
	for _, c := range cases {
		storageAssessmentDependencyReview(t, ctx, f, c.resource, token)
	}
	for _, c := range cases {
		canonical := storageInputTestCanonical(c.resource, start, end)
		inv := databaseInputObject(canonical["inventory"])
		inv["volumes"], inv["snapshots"] = volumes, snapshots
		// Complete native instance mappings retain every currently attached volume;
		// per-resource selection must not pretend this shared instance is exclusive.
		instances := databaseInputRows(inv["instances"])
		mappings := []model.Document{}
		for _, volume := range volumes {
			for _, a := range databaseInputRows(volume["attachments"]) {
				mappings = append(mappings, model.Document{"volume_id": volume["volume_id"], "device_name": a["device"], "delete_on_termination": a["delete_on_termination"]})
			}
		}
		for _, instance := range instances {
			instance["block_device_mappings"] = mappings
		}
		inv["instances"] = instances
		canonical["inventory"] = inv
		events := databaseInputRows(canonical["metrics"])
		for _, event := range events {
			points := databaseInputRows(event["metrics"])
			for _, point := range points {
				if model.String(point, "namespace") != "AWS/EC2" {
					continue
				}
				var rate int64
				switch model.String(point, "metric") {
				case "EBSReadOps":
					rate = 1000
				case "EBSWriteOps":
					rate = 500
				case "EBSReadBytes":
					rate = 30 << 20
				case "EBSWriteBytes":
					rate = 20 << 20
				}
				if rate > 0 {
					point["value"] = fmt.Sprint(rate * 3600)
					point["native_maximum"] = fmt.Sprint(rate * 60)
				}
			}
			event["metrics"] = points
		}
		canonical["metrics"] = events
		if c.name == "missing-telemetry" {
			events := databaseInputRows(canonical["metrics"])
			if len(events) == 0 {
				t.Fatal("native fixture metrics unavailable")
			}
			points := databaseInputRows(events[0]["metrics"])
			removed := false
			next := []model.Document{}
			for _, point := range points {
				if !removed && model.String(point, "metric") == "VolumeReadOps" {
					removed = true
					continue
				}
				next = append(next, point)
			}
			if !removed {
				t.Fatal("required native point not found")
			}
			events[0]["metrics"] = next
			canonical["metrics"] = events
		}
		refs := storageAssessmentArchiveCanonical(t, ctx, archive, f.tenant, canonical)
		raw, e := json.Marshal(canonical)
		if e != nil {
			t.Fatal(e)
		}
		ref := databaseAssessmentTestArchive(t, ctx, archive, f.tenant, "canonical", "ebs-snapshot-"+model.ID(), raw)
		if e = f.roles["ingester"].Do(ctx, f.tenant, func(tx *store.Tx) error {
			_, e := tx.StorageEvidenceAppend(ctx, model.Document{"id": model.ID(), "schema_version": "1", "resource_id": c.resource["id"], "account_id": c.resource["account_id"], "region": c.resource["region"], "config_hash": StorageConfigurationHash(c.resource), "content_hash": ref["body_sha256"], "archive": ref, "source_refs": refs, "observed_at": time.Now().UTC().Format(time.RFC3339Nano), "period": canonical["period"], "observation_basis": "SYNTHETIC_COMPONENT_NATIVE_SHAPES_NO_PROVIDER_CAPTURE_CLAIM"})
			return e
		}); e != nil {
			t.Fatal(e)
		}
	}
	workerCtx, stopWorker := context.WithCancel(ctx)
	defer stopWorker()
	workerDone := make(chan error, 1)
	stopped := false
	go func() {
		workerDone <- RunStorageAssessor(workerCtx, Config{Fixture: true, EconomicsURL: os.Getenv("ECONOMICS_TEST_URL"), EconomicsToken: os.Getenv("ECONOMICS_TEST_TOKEN")}, analyst)
	}()
	t.Cleanup(func() {
		if stopped {
			return
		}
		stopWorker()
		select {
		case e := <-workerDone:
			if e != nil {
				t.Error(e)
			}
		case <-time.After(5 * time.Second):
			t.Error("storage analyst did not stop")
		}
	})
	issued := map[string]string{}
	hashes := map[string]string{}
	// Queue all requests through real JWT/JWKS HTTP before polling, so the one
	// ordinary worker can drain them within the unchanged component deadline.
	for _, c := range cases {
		code, d, _ := f.request("storage-assessments", `"0"`, "storage-native-"+c.name, token, model.Document{"resource_id": c.resource["id"]})
		if code != 202 || model.String(d, "status") != "QUEUED" {
			t.Fatal("IDs-only queue", code, d)
		}
		issued[c.name] = model.String(d, "id")
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			persisted := storageAssessmentWait(t, ctx, f, issued[c.name], token)
			assessment := databaseInputObject(persisted["assessment"])
			if model.String(assessment, "status") != c.want {
				t.Fatalf("actual persisted status %s want %s; blockers=%v", model.String(assessment, "status"), c.want, assessment["blockers"])
			}
			if c.kind != "" && model.String(assessment, "recommendation_kind") != c.kind {
				t.Fatal("recommendation family changed", assessment["recommendation_kind"])
			}
			if model.String(assessment, "model_version") != "storage-observed-demand-v1" || model.String(assessment, "model_assessment_hash") == "" {
				t.Fatal("actual Python result missing")
			}
			proposal := databaseInputObject(assessment["proposal"])
			if proposal["risk_class"] != "R3" || proposal["executable"] != false || proposal["execution_authorized"] != false || assessment["verified_saving"] != nil {
				t.Fatal("read-only boundary changed")
			}
			if c.want == "RECOMMENDED" {
				cost := databaseInputObject(assessment["economics"])
				saving, ok := databaseDecimal(cost["estimated_monthly_saving"])
				if !ok || saving.Sign() <= 0 || cost["currency"] != "USD" {
					t.Fatal("customer native economics missing", cost)
				}
				candidate := databaseInputObject(assessment["candidate_configuration"])
				if model.String(candidate, "size_gib") != "1000.000000000000" {
					t.Fatal("native GiB changed")
				}
				if !model.Bool(persisted, "current") {
					t.Fatal("fresh source not current")
				}
				found := false
				for _, r := range databaseInputRows(assessment["source_refs"]) {
					if model.String(r, "kind") == "AWS_CUR2_CONNECTION" && len(model.Strings(r, "economic_record_ids")) >= 24 {
						found = true
					}
				}
				if !found {
					t.Fatal("authenticated native billing records not retained")
				}
			}
			if c.name == "unattached-review" {
				review := databaseInputObject(assessment["unattached_review"])
				if review["deletion_recommended"] != false {
					t.Fatal("unattached became delete authority")
				}
			}
			if c.name == "snapshot-unknown-review" {
				found := false
				for _, review := range databaseInputRows(assessment["snapshot_reviews"]) {
					if model.String(review, "classification") == "UNKNOWN_DEPENDENCY" && review["deletion_recommended"] == false {
						found = true
					}
				}
				if !found {
					t.Fatal("unknown snapshot dependencies lost", assessment["snapshot_reviews"])
				}
			}
			hashes[c.name] = source.Hash(assessment)
			code, again := fleetNativeHTTPGet(t, f, "storage-assessments/"+issued[c.name], token)
			if code != 200 || source.Hash(again["assessment"]) != hashes[c.name] {
				t.Fatal("persisted reload changed")
			}
			other := f.token("foreign-"+f.tenant, "storage-component-reader", "FINOPS_ADMIN")
			if code, _ := fleetNativeHTTPGet(t, f, "storage-assessments/"+issued[c.name], other); code != 404 {
				t.Fatal("cross-tenant read", code)
			}
			code, rec := fleetNativeHTTPGet(t, f, "recommendations/storage-"+issued[c.name], token)
			if code != 200 || model.String(rec, "model_kind") != "STORAGE_ASSESSMENT_V1" || rec["execution_authorized"] != false {
				t.Fatal("persisted recommendation projection", code)
			}
		})
	}
	if t.Failed() {
		return
	}
	if code, _, _ := f.request("storage-assessments", `"0"`, "storage-no-authoritative-price", token, model.Document{"resource_id": cases[0].resource["id"], "current_pricing": model.Document{"rate": "0"}}); code != 422 {
		t.Fatal("public authoritative price accepted", code)
	}
	if code, page := fleetNativeHTTPGet(t, f, "storage-assessments?resource_id="+model.String(cases[0].resource, "id"), token); code != 200 || len(databaseInputRows(page["items"])) != 1 {
		t.Fatal("persisted assessment history", code)
	}
	databaseAssessmentTestCoverage(t, f, token, rows, true, true)
	corrected := storageAssessmentNativeCUR(volumes, snapshots, end.Add(-24*time.Hour), end, "0.09")
	corrected = append(corrected, rows[len(rows)-3:]...)
	databaseAssessmentTestBilling(t, ctx, f, archive, normalizer, sourceID, corrected, time.Now().UTC(), versions, executions)
	for _, c := range cases {
		code, old := fleetNativeHTTPGet(t, f, "storage-assessments/"+issued[c.name], token)
		if code != 200 || model.Bool(old, "current") || source.Hash(old["assessment"]) != hashes[c.name] {
			t.Fatal("source correction did not retain immutable stale advice", c.name, code)
		}
	}
	databaseAssessmentTestCoverage(t, f, token, corrected, true, false)
	if os.Getenv("FINOPS_STORAGE_BROWSER") == "true" {
		stopWorker()
		select {
		case e := <-workerDone:
			stopped = true
			if e != nil {
				t.Fatal(e)
			}
		case <-ctx.Done():
			t.Fatal("component worker shutdown deadline")
		}
		storageAssessmentTestBrowser(t, ctx, f, analyst, []model.Document{cases[0].resource, cases[3].resource, cases[4].resource}, issued)
	}
}

func storageAssessmentNativeVolume(id string, start time.Time) model.Document {
	return model.Document{"volume_id": id, "provider_resource_id": id, "account_id": "111122223333", "region": "eu-west-1", "availability_zone": "eu-west-1a", "volume_type": "gp2", "size_gib": 1000, "iops": 3000, "throughput_mibps": nil, "state": "in-use", "encrypted": true, "kms_key_id": nil, "multi_attach_enabled": false, "create_time": start.AddDate(0, 0, -30).Format(time.RFC3339), "attachments": []model.Document{{"volume_id": id, "instance_id": "i-0eb50000000000001", "device": "/dev/sdf", "state": "attached", "delete_on_termination": false, "attach_time": start.AddDate(0, 0, -30).Format(time.RFC3339)}}}
}

func storageAssessmentNativeCUR(volumes, snapshots []model.Document, start, end time.Time, gp3Rate string) []model.Document {
	out := []model.Document{}
	appendPart := func(id, kind, component, unit string, units int64, rate string, at time.Time) {
		if units <= 0 {
			return
		}
		q := new(big.Rat).SetFrac64(units, 730)
		quantity := q.FloatString(6)
		qr, _ := new(big.Rat).SetString(quantity)
		r, _ := new(big.Rat).SetString(rate)
		amount := databaseInputMoney(new(big.Rat).Mul(qr, r))
		usage := map[string]string{"storage": "EBS:VolumeUsage.", "iops": "EBS:VolumeP-IOPS.", "throughput": "EBS:VolumeP-Throughput."}[component] + kind
		if component == "snapshots" {
			usage = "EBS:SnapshotUsage"
		}
		row := model.Document{"identity_line_item_id": fmt.Sprintf("synthetic-ebs-%s-%s-%d", id, component, at.Unix()), "line_item_usage_account_id": "111122223333", "line_item_resource_id": id, "line_item_currency_code": "USD", "line_item_line_item_type": "Usage", "line_item_usage_start_date": at.Format(time.RFC3339), "line_item_usage_end_date": at.Add(time.Hour).Format(time.RFC3339), "line_item_unblended_cost": amount, "line_item_net_unblended_cost": amount, "line_item_unblended_rate": rate, "line_item_net_unblended_rate": rate, "line_item_usage_amount": quantity, "line_item_usage_type": "EU-" + usage, "line_item_operation": "CreateVolume-" + kind, "product_servicecode": "AmazonEC2", "product_product_family": "Storage", "product_volume_api_name": kind, "product_region_code": "eu-west-1", "product_sku": "SYNTHETIC-COMPONENT-EBS-" + kind + "-" + component, "pricing_term": "OnDemand", "pricing_unit": unit, "pricing_rate_code": "SYNTHETIC-COMPONENT-NET-" + kind + "-" + component}
		out = append(out, row)
	}
	for at := start; at.Before(end); at = at.Add(time.Hour) {
		for _, v := range volumes {
			kind, id := model.String(v, "volume_type"), model.String(v, "volume_id")
			rate := "0.10"
			if kind == "gp3" {
				rate = gp3Rate
			}
			appendPart(id, kind, "storage", "GB-Mo", model.Number(v, "size_gib"), rate, at)
			if kind == "gp3" {
				appendPart(id, kind, "iops", "IOPS-Mo", model.Number(v, "iops")-3000, "0.005", at)
				appendPart(id, kind, "throughput", "MiBps-Mo", model.Number(v, "throughput_mibps")-125, "0.04", at)
			}
		}
		for _, s := range snapshots {
			appendPart(model.String(s, "snapshot_id"), "snapshot", "snapshots", "GB-Mo", 10, "0.05", at)
		}
	}
	return out
}

func storageAssessmentDependencyReview(t *testing.T, ctx context.Context, f *mutationReplayFixture, r model.Document, token string) {
	t.Helper()
	var graph model.Document
	if e := f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error { var e error; graph, e = dependencyGraph(ctx, tx); return e }); e != nil {
		t.Fatal(e)
	}
	code, _, _ := f.request("resources/"+model.String(r, "id")+"/dependency-reviews", fmt.Sprintf(`"%d"`, model.Number(r, "version")), "storage-dependency-"+model.String(r, "id"), token, model.Document{"graph_version": graph["version"], "valid_until": time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano), "acknowledgement": "REVIEWED_DISCOVERED_AND_EXTERNAL_DEPENDENCIES", "note": "Synthetic component operator explicitly reviewed discovered storage and external dependencies"})
	if code != 201 && code != 200 {
		t.Fatal("actual dependency review", code)
	}
}

func storageAssessmentArchiveCanonical(t *testing.T, ctx context.Context, s *native.Storage, tenant string, c model.Document) []model.Document {
	t.Helper()
	refs := []model.Document{}
	archive := func(kind string, d model.Document) model.Document {
		raw, e := json.Marshal(model.Document{"evidence_basis": "SYNTHETIC_COMPONENT_NATIVE_SHAPES_NO_LIVE_CUSTOMER_CLAIM", "native_projection": d})
		if e != nil {
			t.Fatal(e)
		}
		ref := databaseAssessmentTestArchive(t, ctx, s, tenant, "wire", kind+"-"+model.ID(), raw)
		refs = append(refs, ref)
		return ref
	}
	inventory := databaseInputObject(c["inventory"])
	delete(inventory, "raw_ref")
	inventory["raw_ref"] = archive("ebs-inventory", inventory)
	c["inventory"] = inventory
	asset := provider.EBSCapabilityAsset()
	capabilities := provider.EBSCapabilities()
	assetRef := databaseAssessmentTestArchive(t, ctx, s, tenant, "wire", "ebs-capability-"+model.ID(), asset)
	if model.String(assetRef, "body_sha256") != source.BytesHash(asset) {
		t.Fatal("documented capability hash differs")
	}
	refs = append(refs, assetRef)
	capabilities["asset_ref"] = assetRef
	c["capabilities"] = capabilities
	events := databaseInputRows(c["metrics"])
	for _, event := range events {
		delete(event, "raw_ref")
		event["raw_ref"] = archive("ebs-cloudwatch", event)
	}
	c["metrics"] = events
	history := databaseInputRows(c["configuration_history"])
	for _, h := range history {
		delete(h, "raw_ref")
		h["raw_ref"] = archive("ebs-recorded-configuration", h)
	}
	c["configuration_history"] = history
	return refs
}

func storageAssessmentWait(t *testing.T, ctx context.Context, f *mutationReplayFixture, id, token string) model.Document {
	t.Helper()
	for {
		code, d := fleetNativeHTTPGet(t, f, "storage-assessments/"+id, token)
		if code != 200 {
			t.Fatal("persisted storage read", code)
		}
		switch model.String(d, "status") {
		case "ASSESSED", "BLOCKED":
			return d
		case "FAILED":
			t.Fatal("storage analyst terminal failure")
		}
		select {
		case <-ctx.Done():
			t.Fatal("storage assessment deadline", id)
			return nil
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// Optional normal-console handoff uses the same original 120-second context.
// The analyst is the actual compiled CLI with its dedicated LOGIN and existing
// version-only object reader, separate from the component ingester/writer.
func storageAssessmentTestBrowser(t *testing.T, ctx context.Context, f *mutationReplayFixture, analyst *store.Store, resources []model.Document, componentIDs map[string]string) {
	t.Helper()
	const binary = "/tmp/ebs-finops"
	if os.Getenv("FINOPS_STORAGE_ASSESSOR_BINARY") != binary {
		t.Fatal("actual compiled storage analyst required")
	}
	info, err := os.Lstat(binary)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode()&0111 == 0 {
		t.Fatal("actual storage analyst executable unavailable")
	}
	log, err := os.OpenFile("/results/storage-analyst.log", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal("private analyst log unavailable")
	}
	defer log.Close()
	cmd := exec.CommandContext(ctx, binary, "--mode", "storage-assessor")
	cmd.Env = []string{"FIXTURE_MODE=true", "PORT=8098", "DATABASE_URL=" + analyst.Pool.Config().ConnConfig.ConnString(), "ECONOMICS_URL=" + os.Getenv("ECONOMICS_TEST_URL"), "ECONOMICS_TOKEN=" + os.Getenv("ECONOMICS_TEST_TOKEN")}
	for _, key := range []string{"OBJECT_REGION", "OBJECT_ENDPOINT", "OBJECT_BUCKET_RAW"} {
		value := os.Getenv(key)
		if value == "" {
			t.Fatal("fixture analyst object binding incomplete")
		}
		cmd.Env = append(cmd.Env, key+"="+value)
	}
	for _, pair := range [][2]string{{"OBJECT_ACCESS_KEY", "FINOPS_STORAGE_READER_ACCESS_KEY"}, {"OBJECT_SECRET_KEY", "FINOPS_STORAGE_READER_SECRET_KEY"}} {
		value := os.Getenv(pair[1])
		if value == "" {
			t.Fatal("version-only assessment object reader required")
		}
		cmd.Env = append(cmd.Env, pair[0]+"="+value)
	}
	cmd.Stdout, cmd.Stderr = log, log
	if err = cmd.Start(); err != nil {
		t.Fatal("actual storage analyst process failed to start")
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
	ready, err := fleetCapacityBrowserWrite("/results/storage-native-ready.json", model.Document{"schema_version": "1", "tenant_id": f.tenant, "resource_ids": ids})
	if err != nil {
		t.Fatal("native browser READY publication failed")
	}
	var proof struct {
		SchemaVersion string   `json:"schema_version"`
		TenantID      string   `json:"tenant_id"`
		ReadySHA256   string   `json:"ready_sha256"`
		AssessmentIDs []string `json:"assessment_ids"`
	}
	if err = fleetCapacityBrowserWait(ctx, "storage-native-browser-done.json", &proof); err != nil {
		t.Fatal("normal storage browser deadline")
	}
	if proof.SchemaVersion != "1" || proof.TenantID != f.tenant || proof.ReadySHA256 != source.BytesHash(ready) || len(proof.AssessmentIDs) != len(resources) {
		t.Fatal("normal storage browser result binding differs")
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
		code, record := fleetNativeHTTPGet(t, f, "storage-assessments/"+id, f.token(f.tenant, "storage-independent-verifier", "FINOPS_ADMIN"))
		assessment := databaseInputObject(record["assessment"])
		want := []string{"RECOMMENDED", "BLOCKED", "OBSERVATION_ONLY"}[index]
		if code != 200 || model.String(record, "resource_id") != ids[index] || model.String(assessment, "status") != want || model.String(assessment, "model_assessment_hash") == "" || index != 1 && !model.Bool(record, "current") {
			t.Fatal("actual browser publication differs from stored native result")
		}
		var actor string
		if err = f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
			return tx.QueryRow(ctx, "SELECT created_by FROM storage_assessments WHERE tenant_id=$1 AND id=$2", f.tenant, id).Scan(&actor)
		}); err != nil || actor == "" || actor == "storage-component-requester" {
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
