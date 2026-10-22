package service

import (
	"context"
	"net/http"
	"os"
	"strings"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/auth"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
)

const fixtureAWSAccountBinding = "fixture-aws-readonly"

func (a *API) approvedAccountBindings(tenant string) ([]source.AWSAccountApprovedBinding, error) {
	if a.Config.Fixture {
		return []source.AWSAccountApprovedBinding{{ID: fixtureAWSAccountBinding, AccountID: "FIXTURE_ACCOUNT_SCOPE", Regions: []string{"eu-west-1"}, RoleARN: "FIXTURE_READ_ONLY_ROLE", ScopeMode: "ACCOUNT", ExternalIDConfigured: false}}, nil
	}
	return source.AWSAccountApprovedBindings(os.Getenv("AWS_ACCOUNT_APPROVED_BINDINGS_JSON"), tenant)
}
func (a *API) accountBindingAllowed(tenant, binding, account, region string) error {
	rows, e := a.approvedAccountBindings(tenant)
	if e != nil {
		return problem(503, "AWS_ACCOUNT_BINDINGS_UNAVAILABLE", "approved account binding metadata is unavailable")
	}
	for _, b := range rows {
		if b.ID == binding && (b.AccountID == account || a.Config.Fixture && b.AccountID == "FIXTURE_ACCOUNT_SCOPE") {
			for _, r := range b.Regions {
				if r == region {
					return nil
				}
			}
		}
	}
	return problem(422, "AWS_ACCOUNT_BINDING_NOT_APPROVED", "select an operator-approved binding for this tenant, account and region")
}

func (a *API) createCommissioningAccount(ctx context.Context, t *store.Tx, i auth.Identity, in model.Document) (model.Document, int, error) {
	if e := requireRole(i, "PLATFORM_ADMIN"); e != nil {
		return nil, 0, e
	}
	for k := range in {
		if _, ok := in[k].(string); !ok {
			return nil, 0, problem(422, "AWS_ACCOUNT_METADATA_INVALID", "account metadata values must be strings")
		}
		switch k {
		case "provider", "name", "account_id", "region", "read_role_binding_id":
		default:
			return nil, 0, problem(422, "AWS_ACCOUNT_METADATA_ONLY", "account registration accepts safe metadata and an approved binding ID only")
		}
	}
	if model.String(in, "provider") != "AWS" {
		return nil, 0, problem(422, "UNSUPPORTED_PROVIDER", "this pilot supports AWS only")
	}
	if !a.Config.Fixture {
		if e := ValidateAWSTenant(i.Tenant); e != nil {
			return nil, 0, e
		}
	}
	account, region, binding := model.String(in, "account_id"), model.String(in, "region"), model.String(in, "read_role_binding_id")
	if region == "" {
		region = a.Config.AWSRegion
	}
	if region == "" && a.Config.Fixture {
		region = "eu-west-1"
	}
	if account == "" && a.Config.Fixture {
		account = "111122223333"
	}
	if binding == "" && a.Config.Fixture {
		binding = fixtureAWSAccountBinding
	}
	if len(account) != 12 {
		return nil, 0, problem(422, "INVALID_ACCOUNT", "AWS account_id must contain 12 digits")
	}
	for _, c := range account {
		if c < '0' || c > '9' {
			return nil, 0, problem(422, "INVALID_ACCOUNT", "AWS account_id must contain 12 digits")
		}
	}
	if len(model.String(in, "name")) > 200 || len(binding) > 128 {
		return nil, 0, problem(422, "AWS_ACCOUNT_METADATA_INVALID", "account metadata exceeds supported bounds")
	}
	if e := a.accountBindingAllowed(i.Tenant, binding, account, region); e != nil {
		return nil, 0, e
	}
	status := "CONNECTED"
	if !a.Config.Fixture {
		status = "DISCOVERY_PENDING"
	}
	d, e := t.Create(ctx, "cloud_accounts", model.Document{"provider": "AWS", "name": model.String(in, "name"), "account_id": account, "region": region, "read_role_binding_id": binding, "connection_mode": "READ_ONLY", "status": status, "fixture": a.Config.Fixture, "last_synced_at": model.Now()})
	if e != nil {
		return nil, 0, e
	}
	if !a.Config.Fixture {
		if _, e = t.Create(ctx, "discovery_jobs", model.Document{"cloud_account_id": d["id"], "status": "PENDING", "created_at": model.Now()}); e != nil {
			return nil, 0, e
		}
	}
	if e = t.Audit(ctx, i.Subject, "cloud_account.connected", model.String(d, "id"), d); e != nil {
		return nil, 0, e
	}
	return d, 201, nil
}

func (a *API) accountCommissioningMutate(ctx context.Context, t *store.Tx, i auth.Identity, r *http.Request, in model.Document) (model.Document, int, bool, error) {
	p := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/"), "/")
	if len(p) != 3 || p[0] != "cloud-accounts" || p[2] != "preflights" {
		return nil, 0, false, nil
	}
	if e := requireRole(i, "PLATFORM_ADMIN", "FINOPS_ADMIN"); e != nil {
		return nil, 0, true, e
	}
	if len(in) != 0 {
		return nil, 0, true, problem(422, "AWS_PREFLIGHT_SERVER_SELECTED", "preflight accepts an empty body; evidence and access checks are server-selected")
	}
	account, e := t.Get(ctx, "cloud_accounts", p[1])
	if e != nil {
		return nil, 0, true, e
	}
	if e = match(r, account); e != nil {
		return nil, 0, true, e
	}
	if account["provider"] != "AWS" || account["connection_mode"] != "READ_ONLY" {
		return nil, 0, true, problem(422, "AWS_ACCOUNT_READ_ONLY_BINDING_REQUIRED", "register an approved read-only account binding before preflight")
	}
	if e = a.accountBindingAllowed(i.Tenant, model.String(account, "read_role_binding_id"), model.String(account, "account_id"), model.String(account, "region")); e != nil {
		return nil, 0, true, e
	}
	d, e := t.AWSAccountPreflightCreate(ctx, account, i.Subject)
	if e == nil {
		e = t.Audit(ctx, i.Subject, "cloud_account.preflight.requested", model.String(d, "id"), model.Document{"cloud_account_id": p[1], "execution_authorized": false})
	}
	return d, 202, true, e
}

func (a *API) accountCommissioningGet(ctx context.Context, t *store.Tx, i auth.Identity, r *http.Request) (any, bool, error) {
	p := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/"), "/")
	bindings := len(p) == 1 && p[0] == "aws-read-bindings"
	preflight := len(p) >= 3 && p[0] == "cloud-accounts" && p[2] == "preflights"
	if !bindings && !preflight {
		return nil, false, nil
	}
	if scopedOwner(i) {
		return nil, true, problem(403, "WORKLOAD_SCOPE_DENIED", "account commissioning requires an organization-wide role")
	}
	if bindings {
		rows, e := a.approvedAccountBindings(i.Tenant)
		return model.Document{"items": rows}, true, e
	}
	if _, e := t.Get(ctx, "cloud_accounts", p[1]); e != nil {
		return nil, true, e
	}
	if len(p) == 3 {
		after, n, e := storagePage(r, t.Tenant, i.Subject)
		if e != nil {
			return nil, true, e
		}
		rows, e := t.AWSAccountPreflightPage(ctx, p[1], after, n+1)
		if e != nil {
			return nil, true, e
		}
		next := ""
		if len(rows) > n {
			rows = rows[:n]
			next = model.String(rows[n-1], "id")
		}
		for _, row := range rows {
			if e := a.accountPreflightBindingCurrentness(ctx, t, i, row); e != nil {
				return nil, true, e
			}
		}
		return model.Document{"items": rows, "next_cursor": storageNextCursor(r, t.Tenant, i.Subject, next)}, true, nil
	}
	if len(p) == 4 || len(p) == 5 && p[4] == "report" {
		d, e := t.AWSAccountPreflightGet(ctx, p[1], p[3])
		if e != nil {
			return nil, true, e
		}
		if len(p) == 5 {
			report, e := t.AWSAccountCommissioningReport(ctx, p[1], p[3])
			return report, true, e
		}
		d["report"] = nil
		if model.String(d, "report_id") != "" {
			report, e := t.AWSAccountCommissioningReport(ctx, p[1], p[3])
			if e != nil {
				return nil, true, e
			}
			d["report"] = report
		}
		if e := a.accountPreflightBindingCurrentness(ctx, t, i, d); e != nil {
			return nil, true, e
		}
		return d, true, nil
	}
	return nil, true, problem(404, "NOT_FOUND", "unknown account preflight route")
}

// Binding approval is a current annotation on a historical preflight record.
// It deliberately does not revalidate financial/telemetry evidence or rewrite
// the immutable report/export. A new preflight is needed for a new as-of view.
func (a *API) accountPreflightBindingCurrentness(ctx context.Context, t *store.Tx, i auth.Identity, d model.Document) error {
	d["binding_current"] = nil
	d["currentness_reason_codes"] = []string{"IMMUTABLE_AS_OF_EVIDENCE_REQUIRES_NEW_PREFLIGHT"}
	if model.String(d, "report_id") == "" {
		return nil
	}
	account, e := t.Get(ctx, "cloud_accounts", model.String(d, "cloud_account_id"))
	if e != nil {
		return e
	}
	blocked := func(reason string) {
		d["binding_current"] = false
		d["currentness_reason_codes"] = []string{reason, "IMMUTABLE_AS_OF_EVIDENCE_REQUIRES_NEW_PREFLIGHT"}
	}
	for _, key := range []string{"account_id", "region", "read_role_binding_id"} {
		if account[key] != d[key] {
			blocked("AWS_ACCOUNT_BINDING_CHANGED")
			return nil
		}
	}
	if account["provider"] != "AWS" || account["connection_mode"] != "READ_ONLY" {
		blocked("AWS_ACCOUNT_BINDING_CHANGED")
		return nil
	}
	report, e := t.AWSAccountCommissioningReport(ctx, model.String(d, "cloud_account_id"), model.String(d, "id"))
	if e != nil {
		return e
	}
	if a.Config.Fixture {
		if !model.Bool(report, "fixture") || d["read_role_binding_id"] != fixtureAWSAccountBinding {
			blocked("AWS_ACCOUNT_APPROVED_BINDING_CHANGED")
			return nil
		}
		d["binding_current"] = true
		return nil
	}
	rows, e := a.approvedAccountBindings(i.Tenant)
	if e != nil {
		blocked("AWS_ACCOUNT_APPROVED_BINDING_UNAVAILABLE")
		return nil
	}
	for _, binding := range rows {
		if binding.ID == d["read_role_binding_id"] && binding.AccountID == d["account_id"] {
			if model.Bool(report, "fixture") || binding.RoleARN != model.String(storageObject(report["identity"]), "configured_role_arn") || !binding.ExternalIDConfigured {
				blocked("AWS_ACCOUNT_APPROVED_BINDING_CHANGED")
				return nil
			}
			for _, region := range binding.Regions {
				if region == d["region"] {
					d["binding_current"] = true
					return nil
				}
			}
			blocked("AWS_ACCOUNT_APPROVED_BINDING_CHANGED")
			return nil
		}
	}
	blocked("AWS_ACCOUNT_APPROVED_BINDING_REVOKED")
	return nil
}
