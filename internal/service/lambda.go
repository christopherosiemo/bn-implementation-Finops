package service

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/lambdacost"
	"math/big"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/auth"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/evidence"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
)

func lambdaResource(r model.Document) bool {
	return model.String(r, "provider") == "AWS" && model.String(r, "resource_type") == "LAMBDA_FUNCTION"
}
func LambdaConfigurationHash(r model.Document) string {
	return lambdacost.ConfigurationHash(storageObject(r["lambda_configuration"]))
}
func lambdaPolicyHash(d model.Document) string {
	return evidence.Hash(model.Document{"id": d["id"], "version": d["version"], "resource_id": d["resource_id"], "policy": d["policy"]})
}
func validateLambdaPolicy(d model.Document) error {
	bad := func() error {
		return problem(422, "LAMBDA_POLICY_INVALID", "provide bounded business and safety declarations; observations are server-selected")
	}
	if model.String(d, "resource_id") == "" || model.String(d, "name") == "" || len(model.String(d, "name")) > 200 {
		return bad()
	}
	p := storageObject(d["policy"])
	if p == nil {
		return bad()
	}
	for k, v := range p {
		if v == nil {
			continue
		}
		switch k {
		case "owner", "timezone":
			s, ok := v.(string)
			if !ok || len(s) > 256 || strings.ContainsAny(s, "\x00\r\n") {
				return bad()
			}
			if k == "timezone" {
				if _, e := time.LoadLocation(s); e != nil {
					return bad()
				}
			}
		case "configuration_authority":
			switch v {
			case "UNKNOWN", "TERRAFORM", "CLOUDFORMATION", "SAM", "CDK", "MANUAL":
			default:
				return bad()
			}
		case "criticality":
			if v != "PRODUCTION" && v != "NON_PRODUCTION" {
				return bad()
			}
		case "latency_sensitive", "bursts_known", "off_hours_warm_required", "performance_improvement_required", "seasonal", "cold_start_sensitive", "requires_warm_capacity", "architecture_compatibility_known", "arm64_compatible", "off_hours_slo_known":
			if _, ok := v.(bool); !ok {
				return bad()
			}
		case "max_duration_ms", "available_concurrency", "minimum_provisioned_concurrency", "performance_review_duration_ms", "latency_slo_ms", "max_error_rate", "max_throttle_rate", "max_queue_age_ms", "throughput_minimum", "memory_headroom_fraction", "concurrency_headroom_fraction":
			s, ok := v.(string)
			if !ok || len(s) > 40 || !lambdaDecimal.MatchString(s) {
				return bad()
			}
			n, ok := new(big.Rat).SetString(s)
			if !ok || n.Sign() < 0 {
				return bad()
			}
			if strings.Contains(k, "fraction") || strings.HasSuffix(k, "rate") {
				if n.Cmp(big.NewRat(1, 1)) > 0 {
					return bad()
				}
			}
		case "architecture_compatibility":
			m := storageObject(v)
			if len(m) > 7 {
				return bad()
			}
			for key, state := range m {
				switch key {
				case "runtime", "package", "native_dependencies", "layers", "extensions", "container_image", "customer_declaration":
				default:
					return bad()
				}
				switch state {
				case "COMPATIBLE", "INCOMPATIBLE", "NOT_APPLICABLE", "UNKNOWN":
				default:
					return bad()
				}
			}
		case "active_windows":
			raw, _ := json.Marshal(v)
			if len(raw) > 4096 {
				return bad()
			}
			var windows []struct {
				Days  []int  `json:"days"`
				Start string `json:"start"`
				End   string `json:"end"`
			}
			if json.Unmarshal(raw, &windows) != nil || len(windows) > 14 {
				return bad()
			}
			for _, w := range windows {
				if len(w.Days) == 0 || len(w.Days) > 7 {
					return bad()
				}
				for _, day := range w.Days {
					if day < 0 || day > 6 {
						return bad()
					}
				}
				if _, e := time.Parse("15:04", w.Start); e != nil {
					return bad()
				}
				if _, e := time.Parse("15:04", w.End); e != nil {
					return bad()
				}
			}
		default:
			return bad()
		}
	}
	return nil
}

var lambdaDecimal = regexp.MustCompile(`^(0|[1-9][0-9]*)(\.[0-9]{1,12})?$`)
var lambdaQualifier = regexp.MustCompile(`^(\$LATEST(?:\.PUBLISHED)?|[A-Za-z0-9_-]{1,128})$`)

func (a *API) lambdaMutate(ctx context.Context, t *store.Tx, i auth.Identity, r *http.Request, in model.Document) (model.Document, int, bool, error) {
	p := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/"), "/")
	if p[0] != "lambda-assessments" && p[0] != "lambda-policies" {
		return nil, 0, false, nil
	}
	if e := requireRole(i, "FINOPS_ADMIN", "PLATFORM_ADMIN", "APPLICATION_OWNER"); e != nil {
		return nil, 0, true, e
	}
	if p[0] == "lambda-assessments" {
		if len(p) != 1 {
			return nil, 0, true, problem(404, "NOT_FOUND", "unknown lambda operation")
		}
		for k := range in {
			if k != "resource_id" && k != "policy_id" && k != "qualifier" {
				return nil, 0, true, problem(422, "LAMBDA_IDS_ONLY", "observations, topology and economics are server-selected")
			}
		}
		if model.String(in, "resource_id") == "" || !lambdaQualifier.MatchString(model.String(in, "qualifier")) {
			return nil, 0, true, problem(422, "LAMBDA_IDS_ONLY", "select resource_id and optional registered policy_id")
		}
		if e := match(r, model.Document{"version": 0}); e != nil {
			return nil, 0, true, e
		}
		if e := storageReadScope(ctx, t, i, model.String(in, "resource_id")); e != nil {
			return nil, 0, true, e
		}
		res, e := t.Get(ctx, "resources", model.String(in, "resource_id"))
		if e != nil {
			return nil, 0, true, e
		}
		if !lambdaResource(res) {
			return nil, 0, true, problem(422, "LAMBDA_RESOURCE_REQUIRED", "select a discovered AWS lambda resource")
		}
		out, e := t.LambdaAssessmentCreate(ctx, model.String(in, "resource_id"), model.String(in, "qualifier"), model.String(in, "policy_id"), i.Subject)
		if e == nil {
			e = t.Audit(ctx, i.Subject, "lambda.assessment.requested", model.String(out, "id"), model.Document{"resource_id": in["resource_id"], "execution_authorized": false})
		}
		return out, 202, true, e
	}
	if len(p) != 1 && (len(p) != 3 || p[2] != "revisions") {
		return nil, 0, true, problem(404, "NOT_FOUND", "unknown lambda policy operation")
	}
	d := model.Clone(in)
	for k := range d {
		if k != "resource_id" && k != "name" && k != "policy" {
			return nil, 0, true, problem(422, "LAMBDA_POLICY_FIELDS_INVALID", "only declaration fields are accepted")
		}
	}
	if len(p) == 3 {
		if _, e := t.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", t.Tenant+":lambda-policy:"+p[1]); e != nil {
			return nil, 0, true, e
		}
		old, e := t.LambdaPolicyGet(ctx, p[1])
		if e != nil {
			return nil, 0, true, e
		}
		if e = match(r, old); e != nil {
			return nil, 0, true, e
		}
		if model.String(d, "resource_id") != "" && d["resource_id"] != old["resource_id"] {
			return nil, 0, true, problem(422, "LAMBDA_POLICY_RESOURCE_IMMUTABLE", "policy resource is immutable")
		}
		d["id"], d["version"], d["resource_id"] = old["id"], model.Number(old, "version")+1, old["resource_id"]
	} else {
		if e := match(r, model.Document{"version": 0}); e != nil {
			return nil, 0, true, e
		}
		d["id"], d["version"] = model.ID(), 1
	}
	if e := storageReadScope(ctx, t, i, model.String(d, "resource_id")); e != nil {
		return nil, 0, true, e
	}
	res, e := t.Get(ctx, "resources", model.String(d, "resource_id"))
	if e != nil {
		return nil, 0, true, e
	}
	if !lambdaResource(res) {
		return nil, 0, true, problem(422, "LAMBDA_RESOURCE_REQUIRED", "select a discovered lambda resource")
	}
	if e = validateLambdaPolicy(d); e != nil {
		return nil, 0, true, e
	}
	out, e := t.LambdaPolicyAppend(ctx, d, i.Subject)
	if e == nil {
		e = t.Audit(ctx, i.Subject, "lambda.policy.declared", model.String(out, "id"), model.Document{"resource_id": d["resource_id"], "version": d["version"], "execution_authorized": false})
	}
	return out, 201, true, e
}
func (a *API) lambdaGet(ctx context.Context, t *store.Tx, i auth.Identity, r *http.Request) (any, bool, error) {
	p := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/"), "/")
	policy := p[0] == "lambda-policies"
	assessment := p[0] == "lambda-assessments"
	if policy || assessment {
		if len(p) == 2 {
			var d model.Document
			var e error
			if policy {
				d, e = t.LambdaPolicyGet(ctx, p[1])
			} else {
				d, e = t.LambdaAssessmentGet(ctx, p[1])
			}
			if e == nil {
				e = storageReadScope(ctx, t, i, model.String(d, "resource_id"))
			}
			if e == nil && !policy {
				d, e = a.lambdaCurrent(ctx, t, d)
			}
			return d, true, e
		}
		if len(p) != 1 {
			return nil, true, problem(404, "NOT_FOUND", "unknown lambda resource")
		}
		rid := r.URL.Query().Get("resource_id")
		if e := storageReadScope(ctx, t, i, rid); e != nil {
			return nil, true, e
		}
		after, n, e := storagePage(r, t.Tenant, i.Subject)
		if e != nil {
			return nil, true, e
		}
		var rows []model.Document
		if policy {
			rows, e = t.LambdaPolicyPage(ctx, after, rid, n+1)
		} else {
			rows, e = t.LambdaAssessmentPage(ctx, after, rid, n+1)
		}
		if e != nil {
			return nil, true, e
		}
		next := ""
		if len(rows) > n {
			rows = rows[:n]
			next = model.String(rows[n-1], "id")
		}
		if assessment {
			for j := range rows {
				rows[j], e = a.lambdaCurrent(ctx, t, rows[j])
				if e != nil {
					return nil, true, e
				}
			}
		}
		return model.Document{"items": rows, "next_cursor": storageNextCursor(r, t.Tenant, i.Subject, next)}, true, nil
	}
	if p[0] == "recommendations" && len(p) == 2 && strings.HasPrefix(p[1], "lambda-") {
		d, e := a.lambdaRecommendation(ctx, t, strings.TrimPrefix(p[1], "lambda-"))
		if e == nil {
			e = storageReadScope(ctx, t, i, model.String(d, "resource_id"))
		}
		return d, true, e
	}
	if p[0] == "recommendations" && len(p) == 1 && r.URL.Query().Get("model_kind") == "LAMBDA_ASSESSMENT_V1" {
		rid := r.URL.Query().Get("resource_id")
		if e := storageReadScope(ctx, t, i, rid); e != nil {
			return nil, true, e
		}
		after, n, e := storagePage(r, t.Tenant, i.Subject)
		if e != nil {
			return nil, true, e
		}
		rows, e := t.LambdaAssessmentPage(ctx, after, rid, n+1)
		if e != nil {
			return nil, true, e
		}
		next := ""
		if len(rows) > n {
			rows = rows[:n]
			next = model.String(rows[n-1], "id")
		}
		out := []model.Document{}
		for _, row := range rows {
			d, e := a.lambdaRecommendation(ctx, t, model.String(row, "id"))
			if errors.Is(e, pgx.ErrNoRows) {
				continue
			}
			if e != nil {
				return nil, true, e
			}
			out = append(out, d)
		}
		return model.Document{"items": out, "next_cursor": storageNextCursor(r, t.Tenant, i.Subject, next)}, true, nil
	}
	if p[0] == "resources" && len(p) == 1 && r.URL.Query().Get("resource_type") != "" && lambdaResource(model.Document{"provider": "AWS", "resource_type": r.URL.Query().Get("resource_type")}) {
		after, n, e := storagePage(r, t.Tenant, i.Subject)
		if e != nil {
			return nil, true, e
		}
		rows, e := t.Query(ctx, `SELECT document||jsonb_build_object('id',id,'version',version) FROM entities r WHERE tenant_id=$1 AND kind='resources' AND document->>'resource_type'=$2 AND id>$3 AND (NOT $4 OR EXISTS(SELECT FROM entities w WHERE w.tenant_id=r.tenant_id AND w.kind='workloads' AND w.id=r.document->>'workload_id' AND w.document->>'owner_subject'=$5)) ORDER BY id LIMIT $6`, t.Tenant, r.URL.Query().Get("resource_type"), after, scopedOwner(i), i.Subject, n+1)
		if e != nil {
			return nil, true, e
		}
		out := []model.Document{}
		for rows.Next() {
			var raw []byte
			if e = rows.Scan(&raw); e != nil {
				break
			}
			out = append(out, storageObject(json.RawMessage(raw)))
		}
		if e == nil {
			e = rows.Err()
		}
		rows.Close()
		if e != nil {
			return nil, true, e
		}
		next := ""
		if len(out) > n {
			out = out[:n]
			next = model.String(out[n-1], "id")
		}
		return model.Document{"items": out, "next_cursor": storageNextCursor(r, t.Tenant, i.Subject, next)}, true, nil
	}
	return nil, false, nil
}
func (a *API) lambdaRecommendation(ctx context.Context, t *store.Tx, id string) (model.Document, error) {
	var raw []byte
	if e := t.QueryRow(ctx, "SELECT document FROM lambda_recommendation_publications WHERE tenant_id=$1 AND assessment_id=$2", t.Tenant, id).Scan(&raw); e != nil {
		return nil, e
	}
	d := storageObject(json.RawMessage(raw))
	row, e := t.LambdaAssessmentGet(ctx, id)
	if e != nil {
		return nil, e
	}
	row, e = a.lambdaCurrent(ctx, t, row)
	if e != nil {
		return nil, e
	}
	return recommendationCurrentnessCopy(d, row), nil
}
