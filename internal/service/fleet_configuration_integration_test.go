package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
)

// Real signed JWT/JWKS, restricted PostgreSQL logins and public selectors. The
// group has no fabricated historical observations, prices or action authority.
func TestFleetConfigurationAuthenticatedGroupReviewNeverBorrowsMemberAuthority(t *testing.T) {
	f := newMutationReplayFixture(t)
	ctx := context.Background()
	platform := f.token(f.tenant, "fleet-operator", "PLATFORM_ADMIN")
	viewer := f.token(f.tenant, "viewer", "VIEWER")
	assigned := f.token(f.tenant, "application-user", "APPLICATION_OWNER")
	foreign := f.token(f.tenant+"-foreign", "fleet-operator", "PLATFORM_ADMIN")
	activity := store.ActivitySource{ID: "external-work", WorkloadID: "replay-workload", ResourceID: "external-system", ProviderResourceID: "i-aaaaaaaaaaaaaaaaa", AccountID: "111122223333", Region: "eu-west-1", Issuer: "https://independent-machine.invalid", Subject: "business-collector", MetricDefinition: store.ActivityMetric{ID: "committed-orders", Version: "1", Unit: "completed_orders"}, Enabled: true}
	src := source.FixtureRegistration(f.tenant, "fleet-native")
	if err := f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		if _, err := tx.Create(ctx, "resources", model.Document{"id": activity.ResourceID, "workload_id": activity.WorkloadID, "provider": "AWS", "provider_resource_id": activity.ProviderResourceID, "account_id": activity.AccountID, "region": activity.Region}); err != nil {
			return err
		}
		if _, err := tx.SourceCreate(ctx, src); err != nil {
			return err
		}
		_, err := tx.ActivityRegister(ctx, activity)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.roles["ingester"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		return tx.SourceCheckpointSet(ctx, "fleet-native", "status", model.Document{"status": "HEALTHY", "config_hash": source.ConfigurationHash(src), "last_sync_at": time.Now().UTC().Format(time.RFC3339Nano)})
	}); err != nil {
		t.Fatal(err)
	}
	get := func(path, bearer string) (int, model.Document) {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, "/v1/"+path, nil)
		r.Header.Set("Authorization", "Bearer "+bearer)
		w := httptest.NewRecorder()
		f.api.ServeHTTP(w, r)
		out := model.Document{}
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal("non-JSON group response", w.Code)
		}
		return w.Code, out
	}
	registrationInput := model.Document{"workload_id": activity.WorkloadID, "fleet_id": "orders", "asg_arn": "arn:aws:autoscaling:eu-west-1:111122223333:autoScalingGroup:12345678-1234-1234-1234-123456789abc:autoScalingGroupName/orders", "source_connection_id": "fleet-native", "cadence_seconds": 60, "max_gap_seconds": 90}
	code, registration, _ := f.request("fleet-history-registrations", `"0"`, "fleet-registration", platform, registrationInput)
	if code != 201 {
		t.Fatal("group registration", code, registration)
	}
	regID := model.String(registration, "id")
	base := "fleet-history-registrations/" + regID
	declarations, proposals := base+"/configuration-authorities", base+"/configuration-proposals"
	if code, page := get(declarations, assigned); code != 200 || page["latest"] != nil || model.Number(page, "version") != 0 {
		t.Fatal("initial scoped declaration page", code, page)
	}
	metadata := model.Document{"schema_version": "1", "authority": "TERRAFORM", "repository": model.Document{"url": "https://github.com/example/infrastructure.git", "ref": "main", "directory": "envs/development"}, "pipeline": model.Document{"system": "GITHUB_ACTIONS", "identity": model.Document{"issuer": "https://token.actions.githubusercontent.com", "audience": "finops-deployment-observer", "subject": "repo:example/infrastructure:ref:refs/heads/main", "pipeline_id": ".github/workflows/deploy.yml"}}, "terraform": model.Document{"workspace": "dev-eu", "state_lineage": "0f5a34b0-a480-4cda-9f6a-9b205ced7937", "asg_address": "aws_autoscaling_group.orders", "launch_template_address": "aws_launch_template.orders"}}
	if code, _, _ := f.request(declarations, "", "fleet-missing-cas", platform, metadata); code != 428 {
		t.Fatal("missing declaration version", code)
	}
	code, declaration, tag := f.request(declarations, `"0"`, "fleet-declare-once", platform, metadata)
	if code != 201 || tag != `"1"` || model.String(declaration, "status") != "DECLARED_NOT_ATTESTED" || declaration["execution_authorized"] != false || declaration["estimated_saving"] != nil || declaration["verified_saving"] != nil {
		t.Fatal("metadata became authority", code, declaration, tag)
	}
	binding := source.Object(declaration["binding"])
	if binding["resource_id"] != nil || model.String(declaration, "asg_arn") != model.String(registrationInput, "asg_arn") || model.String(declaration, "registration_hash") != model.String(registration, "hash") {
		t.Fatal("declaration borrowed an individual member", declaration)
	}
	audit, events := f.counts()
	for _, role := range []string{"FINOPS_ADMIN", "FINANCE", "APPROVER", "APPLICATION_OWNER", "VIEWER", "AUDITOR"} {
		if code, _, _ := f.request(declarations, `"0"`, "fleet-declare-once", f.token(f.tenant, "fleet-operator", role), metadata); code != 403 {
			t.Fatal("cached group declaration escaped current role", role, code)
		}
	}
	if code, again, againTag := f.request(declarations, `"0"`, "fleet-declare-once", platform, metadata); code != 201 || model.String(again, "id") != model.String(declaration, "id") || againTag != tag {
		t.Fatal("authorized metadata replay mutated CAS", code, again)
	}
	if gotAudit, gotEvents := f.counts(); gotAudit != audit || gotEvents != events {
		t.Fatal("metadata replay repeated audit/outbox")
	}
	for _, field := range []string{"resource_id", "proof_set_id", "observed_commit", "observed_state_serial", "execution_authorized", "estimated_saving", "saved_plan"} {
		bad := model.Clone(metadata)
		bad[field] = "caller-claim"
		if code, _, _ := f.request(declarations, `"1"`, "fleet-forged-"+field, platform, bad); code != 422 {
			t.Fatal("accepted authoritative field", field, code)
		}
	}
	badURL := model.Clone(metadata)
	badURL["repository"] = model.Document{"url": "http://insecure.invalid/repo", "ref": "main", "directory": "."}
	if code, _, _ := f.request(declarations, `"1"`, "fleet-invalid-repository", platform, badURL); code != 422 {
		t.Fatal("metadata validation escaped its public error contract", code)
	}
	definitionInput := model.Document{"registration_id": regID, "activity_source_id": activity.ID, "business_operation": "order_committed", "semantic_contract_id": "orders-v1", "semantic_contract_hash": strings.Repeat("a", 64)}
	code, definition, _ := f.request("fleet-demand-definitions", `"0"`, "fleet-demand-once", platform, definitionInput)
	if code != 201 {
		t.Fatal("independent demand definition", code, definition)
	}
	code, scope, _ := f.request("fleet-history-scopes", `"1"`, "fleet-scope-once", platform, model.Document{"registration_id": regID, "definition_id": definition["id"], "definition_version": 1})
	if code != 201 || model.String(scope, "status") != "BLOCKED" {
		t.Fatal("genuine missing history", code, scope)
	}
	selection := model.Document{"declaration_id": declaration["id"], "scope_id": scope["id"]}
	code, proposal, _ := f.request(proposals, `"1"`, "fleet-proposal-once", platform, selection)
	if code != 201 || model.String(proposal, "status") != "BLOCKED" || proposal["execution_authorized"] != false || proposal["change_plan_id"] != nil || proposal["estimated_saving"] != nil || proposal["verified_saving"] != nil || model.String(proposal, "scope_reference_root") != model.String(scope, "reference_root") {
		t.Fatal("blocked scope promoted into a plan or money", code, proposal)
	}
	for _, field := range []string{"amount", "currency", "capacity_assessment_id", "change_plan_id", "source_states", "binding", "patch"} {
		bad := model.Clone(selection)
		bad[field] = "caller-claim"
		if code, _, _ := f.request(proposals, `"1"`, "fleet-proposal-forged-"+field, platform, bad); code != 422 {
			t.Fatal("proposal accepted non-selector field", field, code)
		}
	}
	if code, _, _ := f.request(proposals, `"1"`, "fleet-proposal-once", f.token(f.tenant, "fleet-operator", "FINOPS_ADMIN"), selection); code != 403 {
		t.Fatal("cached proposal escaped role downgrade", code)
	}
	if code, _, _ := f.request(declarations, `"0"`, "fleet-stale-declaration", platform, metadata); code != 409 {
		t.Fatal("concurrent declaration was not guarded", code)
	}
	if code, second, _ := f.request(declarations, `"1"`, "fleet-declare-second", platform, metadata); code != 201 || model.Number(second, "version") != 2 {
		t.Fatal("second immutable declaration", code, second)
	}
	if code, _, _ := f.request(proposals, `"2"`, "fleet-old-declaration", platform, selection); code != 409 {
		t.Fatal("old declaration became current proposal", code)
	}
	code, page := get(declarations+"?limit=1", viewer)
	if code != 200 || model.String(page, "next_cursor") == "" || model.Number(page, "version") != 2 {
		t.Fatal("bounded declaration history", code, page)
	}
	if code, older := get(declarations+"?limit=1&cursor="+url.QueryEscape(model.String(page, "next_cursor")), viewer); code != 200 || model.Number(source.Object(older["latest"]), "version") != 2 {
		t.Fatal("cursor lost latest CAS context", code, older)
	}
	if code, _ := get(proposals+"?cursor="+url.QueryEscape(model.String(page, "next_cursor")), viewer); code != 422 {
		t.Fatal("cross-collection cursor was accepted", code)
	}
	if code, _ := get(declarations, foreign); code != 404 {
		t.Fatal("foreign tenant read group configuration", code)
	}
	f.update("workloads", activity.WorkloadID, func(w model.Document) { w["owner"] = "new-owner" })
	if code, _ := get(declarations, assigned); code != 403 {
		t.Fatal("former workload owner retained group access", code)
	}
	if err := f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		s, err := tx.SourceGet(ctx, "fleet-native")
		if err != nil {
			return err
		}
		s["enabled"] = false
		_, err = tx.SourceUpdate(ctx, "fleet-native", model.Number(s, "version"), s)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := f.request(declarations, `"2"`, "fleet-revoked-new", platform, metadata); code != 422 {
		t.Fatal("revoked source authorized new metadata", code)
	}
	if code, historical := get(proposals+"/"+model.String(proposal, "id"), viewer); code != 200 || model.String(historical, "hash") != model.String(proposal, "hash") {
		t.Fatal("revocation rewrote immutable review", code, historical)
	}
	if err := f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		for _, table := range []string{"signed_plans", "savings_ledger", "fleet_observer_sources", "fleet_plans"} {
			var count int
			if err := tx.QueryRow(ctx, "SELECT count(*) FROM "+table+" WHERE tenant_id=$1", f.tenant).Scan(&count); err != nil {
				return err
			}
			if count != 0 {
				t.Fatal("metadata enrolled action or money authority", table, count)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
