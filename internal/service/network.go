package service

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/auth"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/evidence"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
)

func networkResource(r model.Document) bool {
	if model.String(r, "provider") != "AWS" {
		return false
	}
	switch model.String(r, "resource_type") {
	case "AVAILABILITY_ZONE", "SECURITY_GROUP", "VPC_ENDPOINT_SERVICE", "FLOW_LOG", "AWS_SERVICE_PREFIX_LIST", "NAT_GATEWAY", "ELASTIC_IP", "PUBLIC_IPV4", "VPC", "SUBNET", "ROUTE_TABLE", "VPC_ENDPOINT", "NETWORK_INTERFACE", "INTERNET_GATEWAY", "EGRESS_ONLY_INTERNET_GATEWAY", "VPC_PEERING", "TRANSIT_GATEWAY_ATTACHMENT", "LOAD_BALANCER":
		return true
	}
	return false
}
func NetworkConfigurationHash(r model.Document) string {
	return evidence.Hash(model.Document{"binding": storageBinding("", r), "owner": r["owner"], "configuration_authority": r["configuration_authority"], "environment": r["environment"], "configuration": r["network_configuration"], "topology_hash": r["network_topology_hash"]})
}
func networkPolicyHash(d model.Document) string {
	return evidence.Hash(model.Document{"id": d["id"], "version": d["version"], "resource_id": d["resource_id"], "policy": d["policy"]})
}
func validateNetworkPolicy(d model.Document) error {
	bad := func() error {
		return problem(422, "NETWORK_POLICY_INVALID", "provide a named, bounded safety declaration; unknown fields remain null")
	}
	if model.String(d, "resource_id") == "" || model.String(d, "name") == "" || len(model.String(d, "name")) > 200 {
		return bad()
	}
	p, ok := d["policy"].(map[string]any)
	if !ok {
		if m, yes := d["policy"].(model.Document); yes {
			p = m
		} else {
			return bad()
		}
	}
	for k, v := range p {
		if v == nil {
			continue
		}
		switch k {
		case "owner", "traffic_purpose":
			s, ok := v.(string)
			if !ok || len(s) > 256 || strings.ContainsAny(s, "\x00\r\n") {
				return bad()
			}
		case "configuration_authority":
			switch v {
			case "TERRAFORM", "CLOUDFORMATION", "MANUAL", "OTHER", "UNKNOWN":
			default:
				return bad()
			}
		case "criticality":
			if v != "NON_PRODUCTION" && v != "PRODUCTION" {
				return bad()
			}
		case "required_azs":
			var n float64
			switch x := v.(type) {
			case float64:
				n = x
			case int:
				n = float64(x)
			case int64:
				n = float64(x)
			default:
				return bad()
			}
			if n < 1 || n > 16 || n != float64(int(n)) {
				return bad()
			}
		case "seasonal", "security_reviewed", "network_policy_known", "dependencies_known", "recovery_known", "resilience_known", "allow_topology_change", "ha_required", "on_premises_required", "cross_vpc_required", "dns_change_approved", "public_access_required", "endpoint_policy_reviewed":
			if _, ok := v.(bool); !ok {
				return bad()
			}
		default:
			return bad()
		}
	}
	return nil
}
func (a *API) networkMutate(ctx context.Context, t *store.Tx, i auth.Identity, r *http.Request, in model.Document) (model.Document, int, bool, error) {
	p := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/"), "/")
	if p[0] != "network-assessments" && p[0] != "network-policies" {
		return nil, 0, false, nil
	}
	if e := requireRole(i, "FINOPS_ADMIN", "PLATFORM_ADMIN", "APPLICATION_OWNER"); e != nil {
		return nil, 0, true, e
	}
	if p[0] == "network-assessments" {
		if len(p) != 1 {
			return nil, 0, true, problem(404, "NOT_FOUND", "unknown network operation")
		}
		for k := range in {
			if k != "resource_id" && k != "policy_id" {
				return nil, 0, true, problem(422, "NETWORK_IDS_ONLY", "observations, topology and economics are server-selected")
			}
		}
		if model.String(in, "resource_id") == "" {
			return nil, 0, true, problem(422, "NETWORK_IDS_ONLY", "select resource_id and optional registered policy_id")
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
		if !networkResource(res) {
			return nil, 0, true, problem(422, "NETWORK_RESOURCE_REQUIRED", "select a discovered AWS network resource")
		}
		out, e := t.NetworkAssessmentCreate(ctx, model.String(in, "resource_id"), model.String(in, "policy_id"), i.Subject)
		if e == nil {
			e = t.Audit(ctx, i.Subject, "network.assessment.requested", model.String(out, "id"), model.Document{"resource_id": in["resource_id"], "execution_authorized": false})
		}
		return out, 202, true, e
	}
	if len(p) != 1 && (len(p) != 3 || p[2] != "revisions") {
		return nil, 0, true, problem(404, "NOT_FOUND", "unknown network policy operation")
	}
	d := model.Clone(in)
	for k := range d {
		if k != "resource_id" && k != "name" && k != "policy" {
			return nil, 0, true, problem(422, "NETWORK_POLICY_FIELDS_INVALID", "only declaration fields are accepted")
		}
	}
	if len(p) == 3 {
		if _, e := t.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", t.Tenant+":network-policy:"+p[1]); e != nil {
			return nil, 0, true, e
		}
		old, e := t.NetworkPolicyGet(ctx, p[1])
		if e != nil {
			return nil, 0, true, e
		}
		if e = match(r, old); e != nil {
			return nil, 0, true, e
		}
		if model.String(d, "resource_id") != "" && d["resource_id"] != old["resource_id"] {
			return nil, 0, true, problem(422, "NETWORK_POLICY_RESOURCE_IMMUTABLE", "policy resource is immutable")
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
	if !networkResource(res) {
		return nil, 0, true, problem(422, "NETWORK_RESOURCE_REQUIRED", "select a discovered network resource")
	}
	if e = validateNetworkPolicy(d); e != nil {
		return nil, 0, true, e
	}
	out, e := t.NetworkPolicyAppend(ctx, d, i.Subject)
	if e == nil {
		e = t.Audit(ctx, i.Subject, "network.policy.declared", model.String(out, "id"), model.Document{"resource_id": d["resource_id"], "version": d["version"], "execution_authorized": false})
	}
	return out, 201, true, e
}
func (a *API) networkGet(ctx context.Context, t *store.Tx, i auth.Identity, r *http.Request) (any, bool, error) {
	p := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/"), "/")
	policy := p[0] == "network-policies"
	assessment := p[0] == "network-assessments"
	if policy || assessment {
		if len(p) == 2 {
			var d model.Document
			var e error
			if policy {
				d, e = t.NetworkPolicyGet(ctx, p[1])
			} else {
				d, e = t.NetworkAssessmentGet(ctx, p[1])
			}
			if e == nil {
				e = storageReadScope(ctx, t, i, model.String(d, "resource_id"))
			}
			if e == nil && !policy {
				d, e = a.networkCurrent(ctx, t, d)
			}
			return d, true, e
		}
		if len(p) != 1 {
			return nil, true, problem(404, "NOT_FOUND", "unknown network resource")
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
			rows, e = t.NetworkPolicyPage(ctx, after, rid, n+1)
		} else {
			rows, e = t.NetworkAssessmentPage(ctx, after, rid, n+1)
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
				rows[j], e = a.networkCurrent(ctx, t, rows[j])
				if e != nil {
					return nil, true, e
				}
			}
		}
		return model.Document{"items": rows, "next_cursor": storageNextCursor(r, t.Tenant, i.Subject, next)}, true, nil
	}
	if p[0] == "recommendations" && len(p) == 2 && strings.HasPrefix(p[1], "network-") {
		d, e := a.networkRecommendation(ctx, t, strings.TrimPrefix(p[1], "network-"))
		if e == nil {
			e = storageReadScope(ctx, t, i, model.String(d, "resource_id"))
		}
		return d, true, e
	}
	if p[0] == "recommendations" && len(p) == 1 && r.URL.Query().Get("model_kind") == "NETWORK_ASSESSMENT_V1" {
		rid := r.URL.Query().Get("resource_id")
		if e := storageReadScope(ctx, t, i, rid); e != nil {
			return nil, true, e
		}
		after, n, e := storagePage(r, t.Tenant, i.Subject)
		if e != nil {
			return nil, true, e
		}
		rows, e := t.NetworkAssessmentPage(ctx, after, rid, n+1)
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
			d, e := a.networkRecommendation(ctx, t, model.String(row, "id"))
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
	if p[0] == "resources" && len(p) == 1 && r.URL.Query().Get("resource_type") != "" && networkResource(model.Document{"provider": "AWS", "resource_type": r.URL.Query().Get("resource_type")}) {
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
func (a *API) networkRecommendation(ctx context.Context, t *store.Tx, id string) (model.Document, error) {
	var raw []byte
	if e := t.QueryRow(ctx, "SELECT document FROM network_recommendation_publications WHERE tenant_id=$1 AND assessment_id=$2", t.Tenant, id).Scan(&raw); e != nil {
		return nil, e
	}
	d := storageObject(json.RawMessage(raw))
	row, e := t.NetworkAssessmentGet(ctx, id)
	if e != nil {
		return nil, e
	}
	row, e = a.networkCurrent(ctx, t, row)
	if e != nil {
		return nil, e
	}
	d["current"], d["currentness_blockers"] = row["current"], row["currentness_blockers"]
	return d, nil
}
