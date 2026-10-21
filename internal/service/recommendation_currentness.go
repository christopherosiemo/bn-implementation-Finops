package service

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/evidence"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
)

var recommendationDimensions = []struct{ name, reason string }{
	{"resource_configuration", "RESOURCE_CONFIGURATION_CHANGED"},
	{"workload_mapping", "WORKLOAD_MAPPING_CHANGED"},
	{"ownership", "OWNERSHIP_OR_CRITICALITY_CHANGED"},
	{"safety_profile", "WORKLOAD_SAFETY_PROFILE_CHANGED"},
	{"slo", "SLO_PROFILE_CHANGED"},
	{"policy", "RECOMMENDATION_POLICY_CHANGED"},
	{"configuration_authority", "CONFIGURATION_AUTHORITY_CHANGED"},
	{"telemetry", "TELEMETRY_REVISION_CHANGED_OR_REVOKED"},
	{"financial_sources", "BILLING_SOURCE_CHANGED_OR_REVOKED"},
	{"fixture_generation", "FIXTURE_GENERATION_CHANGED"},
}

// Only private assessor code can mark its in-transaction prospective result.
// The publication trigger captures context immediately after these existing
// family checks; HTTP input cannot grandfather a completed legacy analysis.
type recommendationPublicationPending struct{}
func recommendationPendingContext(ctx context.Context) context.Context {
	return context.WithValue(ctx,recommendationPublicationPending{},true)
}

func (a *API) recommendationCurrentnessRows(ctx context.Context, t *store.Tx, family string, rows []model.Document) ([]model.Document,error) {
	out:=make([]model.Document,0,len(rows))
	for _, d:=range rows { current,e:=a.recommendationCurrentness(ctx,t,family,d);if e!=nil{return nil,e};out=append(out,current) }
	return out,nil
}

// recommendationCurrentness adds a current read projection without changing the
// historical assessment, money, signatures or owned recovery capabilities.
func (a *API) recommendationCurrentness(ctx context.Context, t *store.Tx, family string, d model.Document) (model.Document, error) {
	if d == nil || d["status"] == "QUEUED" || d["status"] == "RUNNING" {
		return d, nil
	}
	selected, e := t.RecommendationCurrentnessContext(ctx, family, model.String(d, "id"))
	if e != nil {
		return nil, e
	}
	reasons := append([]string{}, model.Strings(d, "currentness_blockers")...)
	if d["current"] == false && len(reasons) == 0 {
		reasons = append(reasons, "FAMILY_EVIDENCE_NOT_CURRENT")
	}
	gitReason := ""
	if selected==nil {
		var installed bool
		if e:=t.QueryRow(ctx,"SELECT to_regclass('public.recommendation_currentness_contexts') IS NOT NULL").Scan(&installed); e!=nil{return nil,e}
		if installed && ctx.Value(recommendationPublicationPending{})!=true { reasons=append(reasons,"LEGACY_RECOMMENDATION_CONTEXT_UNAVAILABLE") }
		if installed && (a.Config.Role=="" || a.Config.Role=="api") && model.String(d,"resource_id")!="" {
			authority,err:=t.ConfigurationAuthorityLatest(ctx,model.String(d,"resource_id"))
			if err!=nil && !errors.Is(err,pgx.ErrNoRows) { return nil,err }
			if authority!=nil { gitReason="IAC_REVISION_UNAVAILABLE" }
		}
	}
	if selected != nil {
		old := storageObject(storageObject(selected["baseline"])["iac"])
		current := storageObject(storageObject(selected["current"])["iac"])
		if authorityID := model.String(old, "authority_id"); authorityID != "" {
			commit := model.String(old, "commit")
			if commit == "" || current["active"] != true || model.String(current, "authority_id") != authorityID {
				gitReason = "IAC_REVISION_UNAVAILABLE"
			} else if expires, parseError := time.Parse(time.RFC3339Nano, model.String(current, "expires_at")); parseError != nil || !a.now().Before(expires) {
				gitReason = "IAC_REVISION_UNAVAILABLE"
			} else {
				// Only the API can read private declaration metadata. Reporting
				// identities still get hashes and conservatively unavailable Git.
				if a.Config.Role != "" && a.Config.Role != "api" {
					gitReason = "IAC_REVISION_UNAVAILABLE"
				} else {
					authority, err := t.ConfigurationAuthorityGet(ctx, authorityID)
					if err != nil {
						if !errors.Is(err, pgx.ErrNoRows) { return nil, err }
						gitReason = "IAC_REVISION_UNAVAILABLE"
					} else {
						repository := storageObject(authority["repository"])
						resolved, err := a.resolveConfigurationRevision(ctx, t.Tenant, authorityID, model.String(repository,"url"), model.String(repository,"ref"), model.String(repository,"directory"))
						if err != nil || resolved == "" { gitReason = "IAC_REVISION_UNAVAILABLE" } else if resolved != commit { gitReason = "IAC_REVISION_CHANGED" }
					}
				}
			}
		}
	}
	return recommendationCurrentnessProjection(d, selected, reasons, gitReason, a.now()), nil
}

func recommendationCurrentnessProjection(d, selected model.Document, familyReasons []string, gitReason string, now time.Time) model.Document {
	out := model.Clone(d)
	reasons := append([]string{}, familyReasons...)
	changes := []model.Document{}
	version := "LEGACY_FAMILY_REFERENCES"
	baseline, current := storageObject(selected["baseline"]), storageObject(selected["current"])
	if selected != nil {
		version = "1"
		if baseline["context_complete"] == false || current["context_complete"] == false { reasons=append(reasons,"CURRENTNESS_CONTEXT_BOUND_EXCEEDED") }
		if selected["current"] == nil {
			reasons = append(reasons, "RESOURCE_REMOVED_OR_SCOPE_CHANGED")
		}
		for _, dimension := range recommendationDimensions {
			if evidence.Hash(baseline[dimension.name]) != evidence.Hash(current[dimension.name]) {
				reasons = append(reasons, dimension.reason)
				changes = append(changes, model.Document{"dimension":dimension.name,"reason_code":dimension.reason,"detected_at":now.Format(time.RFC3339Nano)})
			}
		}
	}
	if gitReason != "" {
		reasons = append(reasons, gitReason)
		changes = append(changes, model.Document{"dimension":"iac","reason_code":gitReason,"detected_at":now.Format(time.RFC3339Nano)})
	}
	state := "CURRENT"
	if len(reasons) > 0 { state = "STALE" }
	if len(reasons)>0 {
		onlyUnavailable:=true
		for _,reason:=range reasons { if reason!="IAC_REVISION_UNAVAILABLE" && reason!="LEGACY_RECOMMENDATION_CONTEXT_UNAVAILABLE" && reason!="CURRENTNESS_CONTEXT_BOUND_EXCEEDED" {onlyUnavailable=false} }
		if onlyUnavailable {state="BLOCKED"}
	}
	historical := storageObject(d["assessment"])
	if state == "CURRENT" && (d["status"] == "BLOCKED" || d["status"] == "FAILED" || historical["status"] == "BLOCKED") { state = "BLOCKED" }
	if expires := model.String(d, "expires_at"); expires != "" {
		at, e := time.Parse(time.RFC3339Nano, expires)
		if e != nil || !now.Before(at) { state = "EXPIRED"; reasons = append(reasons,"RECOMMENDATION_EXPIRED") }
	}
	economics, telemetryChanged, iac := false, false, false
	for _, reason := range reasons {
		if reason == "FIXTURE_GENERATION_CHANGED" { economics,telemetryChanged=true,true }
		if strings.Contains(reason,"BILLING") || strings.Contains(reason,"FINANCIAL") || strings.Contains(reason,"CONFIGURATION") || strings.Contains(reason,"WORKLOAD") || strings.Contains(reason,"OWNERSHIP") { economics = true }
		if strings.Contains(reason,"TELEMETRY") || strings.Contains(reason,"SOURCE") || strings.Contains(reason,"INVENTORY_STALE") || strings.Contains(reason,"TOPOLOGY_STALE") { telemetryChanged = true }
		if strings.Contains(reason,"IAC_") || strings.Contains(reason,"AUTHORITY") { iac = true }
	}
	next := "No evidence changes detected; read the family-specific constraints before review."
	if state != "CURRENT" { next = "Refresh the affected trusted evidence and request a new assessment; preserve this historical result." }
	if gitReason == "IAC_REVISION_UNAVAILABLE" { next = "Commission the configured repository revision reader and refresh its attested analysis context; execution remains blocked." }
	if state == "STALE" { reasons = append(reasons,"STALE_RECOMMENDATION") }
	for _, reason := range familyReasons { changes = append(changes,model.Document{"dimension":"family_evidence","reason_code":reason,"detected_at":now.Format(time.RFC3339Nano)}) }
	out["currentness"] = model.Document{"schema_version":"1","status":state,"checked_at":now.Format(time.RFC3339Nano),"reason_codes":databaseSortedReasons(reasons),"changes":changes,"economics_recompute":economics,"telemetry_recollect":telemetryChanged,"iac_changed":iac,"next_action":next,"context_version":version,"execution_ready":false}
	out["historical_status"] = d["status"]
	out["current"] = state == "CURRENT"
	if state != "CURRENT" {
		out["pre_execution_ready"],out["execution_authorized"] = false,false
		out["currentness_blockers"] = databaseSortedReasons(reasons)
	}
	return out
}

// Publications retain their immutable result status; the explicit envelope is
// the status of that result's assumptions at the time of this read.
func recommendationCurrentnessCopy(publication, assessment model.Document) model.Document {
	out:=model.Clone(publication)
	out["historical_status"]=publication["status"]
	for _, key:=range []string{"current","currentness","currentness_blockers"} { if value,ok:=assessment[key];ok { out[key]=value } }
	if out["current"]==false { out["pre_execution_ready"],out["execution_authorized"]=false,false }
	return out
}

func (a *API) commissioningRecommendationCurrentness(ctx context.Context,t *store.Tx,account,region string)(model.Document,error) {
	rows,e:=t.RecommendationCurrentnessSummary(ctx,account,region)
	if e!=nil{return nil,e}
	complete:=len(rows)<=256
	if !complete { rows=rows[:256] }
	counts:=map[string]int{"CURRENT":0,"STALE":0,"BLOCKED":0,"EXPIRED":0}
	reasons:=map[string]int{}
	for _,selected:=range rows {
		gitReason:=""
		if storageObject(storageObject(selected["baseline"])["iac"])["authority_id"]!=nil { gitReason="IAC_REVISION_UNAVAILABLE" }
		out:=recommendationCurrentnessProjection(model.Document{},selected,nil,gitReason,a.now())
		currentness:=storageObject(out["currentness"])
		counts[model.String(currentness,"status")]++
		for _,reason:=range model.Strings(currentness,"reason_codes") { reasons[reason]++ }
	}
	return model.Document{"assumption_context_counts":counts,"reason_counts":reasons,"evaluated_contexts":len(rows),"complete":complete,"scope":"LATEST_CAPTURED_CONTEXT_PER_FAMILY_RESOURCE","legacy_family_validation":"EXISTING_FAMILY_ASSESSOR_REQUIRED","execution_authorized":false},nil
}
