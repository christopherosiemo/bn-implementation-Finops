package service

import (
	"context"
	"errors"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/auth"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/dependency"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/evidence"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
)

func dependencyGraph(ctx context.Context, t *store.Tx) (model.Document, error) {
	resources, e := t.List(ctx, "resources")
	if e != nil {
		return nil, e
	}
	workloads, e := t.List(ctx, "workloads")
	if e != nil {
		return nil, e
	}
	head, e := t.DependencyGraph(ctx)
	if e != nil {
		return nil, e
	}
	nodes := dependency.Inventory(resources, workloads)
	edges, edgeErr := dependency.Edges(nodes, evidence.Rows(head["edges"]))
	d := model.Document{"version": head["version"], "nodes": nodes, "edges": edges, "inventory_hash": dependency.InventoryHash(nodes), "status": "DECLARED", "reasons": []string{}}
	if model.Number(head, "version") == 0 {
		d["status"], d["reasons"] = "UNKNOWN", []string{"DEPENDENCY_GRAPH_REQUIRED"}
	}
	if edgeErr != nil {
		d["status"], d["reasons"], d["edges"] = "BLOCKED", []string{edgeErr.Error()}, head["edges"]
	}
	d["graph_hash"] = evidence.Hash(model.Document{"version": head["version"], "inventory_hash": d["inventory_hash"], "edges": d["edges"]})
	reviews, e := t.DependencyReviewList(ctx, "")
	if e != nil {
		return nil, e
	}
	d["reviews"] = reviews
	return d, nil
}

// DependencyPlanReady is also used by durable observation. It can request
// restoration; it never grants or revokes an executor's existing START duty.
func DependencyPlanReady(ctx context.Context, t *store.Tx, resource, reviewID, graphHash string, now time.Time) error {
	if reviewID == "" || graphHash == "" {
		return errors.New("DEPENDENCY_REVIEW_REQUIRED")
	}
	if _, e := t.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", t.Tenant+":dependency-graph"); e != nil {
		return e
	}
	_, e := currentDependencyReview(ctx, t, resource, reviewID, graphHash, now)
	return e
}

func currentDependencyReview(ctx context.Context, t *store.Tx, resource, reviewID, graphHash string, now time.Time) (model.Document, error) {
	var review model.Document
	var e error
	if reviewID == "" {
		review, e = t.DependencyReviewLatest(ctx, resource)
	} else {
		review, e = t.DependencyReviewGet(ctx, reviewID)
	}
	if e != nil {
		return nil, errors.New("DEPENDENCY_REVIEW_REQUIRED")
	}
	if model.String(review, "writer_role") != "finops_api" || model.String(review, "resource_id") != resource || model.String(review, "reviewed_by") == "" {
		return nil, errors.New("DEPENDENCY_REVIEW_BINDING_INVALID")
	}
	expires, e1 := time.Parse(time.RFC3339Nano, model.String(review, "expires_at"))
	reviewed, e2 := time.Parse(time.RFC3339Nano, model.String(review, "reviewed_at"))
	if e1 != nil || e2 != nil || !expires.After(now) || reviewed.After(now.Add(30*time.Second)) || expires.Sub(reviewed) > 24*time.Hour || !expires.After(reviewed) {
		return nil, errors.New("DEPENDENCY_REVIEW_EXPIRED")
	}
	g, e := dependencyGraph(ctx, t)
	if e != nil {
		return nil, e
	}
	if model.String(g, "status") != "DECLARED" {
		return nil, errors.New("DEPENDENCY_GRAPH_UNRESOLVED")
	}
	if model.Number(review, "graph_version") != model.Number(g, "version") || model.String(review, "graph_hash") != model.String(g, "graph_hash") || model.String(review, "inventory_hash") != model.String(g, "inventory_hash") || graphHash != "" && graphHash != model.String(g, "graph_hash") {
		return nil, errors.New("DEPENDENCY_GRAPH_CHANGED")
	}
	reasons := dependency.Assess(evidence.Rows(g["nodes"]), evidence.Rows(g["edges"]), resource)
	if len(reasons) > 0 {
		return nil, errors.New(reasons[0])
	}
	if model.String(review, "status") != "READY" {
		return nil, errors.New("DEPENDENCY_REVIEW_BLOCKED")
	}
	return review, nil
}

func dependencyReviews(ctx context.Context, t *store.Tx, resource string, now time.Time) (model.Document, error) {
	if _, e := t.Get(ctx, "resources", resource); e != nil {
		return nil, e
	}
	rows, e := t.DependencyReviewList(ctx, resource)
	if e != nil {
		return nil, e
	}
	g, e := t.DependencyGraph(ctx)
	if e != nil {
		return nil, e
	}
	d := model.Document{"resource_id": resource, "reviews": rows, "latest": nil, "status": "UNKNOWN", "reasons": []string{"DEPENDENCY_REVIEW_REQUIRED"}, "current_graph_version": g["version"]}
	if len(rows) > 0 {
		d["latest"] = rows[len(rows)-1]
		if _, e = currentDependencyReview(ctx, t, resource, "", "", now); e == nil {
			d["status"], d["reasons"] = "READY", []string{}
		} else {
			d["status"], d["reasons"] = "BLOCKED", []string{e.Error()}
		}
	}
	return d, nil
}

func (a *API) dependencyMutate(ctx context.Context, t *store.Tx, i auth.Identity, r *http.Request, in model.Document, parts []string) (model.Document, int, bool, error) {
	isGraph := len(parts) == 1 && parts[0] == "resource-graph"
	isReview := len(parts) == 3 && parts[0] == "resources" && parts[2] == "dependency-reviews"
	if !isGraph && !isReview {
		return nil, 0, false, nil
	}
	if e := requireRole(i, "PLATFORM_ADMIN"); e != nil {
		return nil, 0, true, e
	}
	if _, e := t.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", t.Tenant+":dependency-graph"); e != nil {
		return nil, 0, true, e
	}
	if isGraph {
		for k := range in {
			if k != "edges" && k != "reason" {
				return nil, 0, true, problem(422, "GRAPH_FIELDS_INVALID", "submit typed edges and a review reason")
			}
		}
		if strings.TrimSpace(model.String(in, "reason")) == "" || len(model.String(in, "reason")) > 2000 {
			return nil, 0, true, problem(422, "GRAPH_REASON_REQUIRED", "a bounded graph change reason is required")
		}
		submitted, ok := in["edges"].([]any)
		if !ok || len(submitted) > 1024 {
			return nil, 0, true, problem(422, "GRAPH_EDGES_REQUIRED", "supply an explicit edge array of at most 1024 edges")
		}
		for _, raw := range submitted {
			edge, ok := raw.(map[string]any)
			if !ok {
				return nil, 0, true, problem(422, "GRAPH_EDGE_INVALID", "each edge requires from,to,type")
			}
			for k := range edge {
				if k != "from" && k != "to" && k != "type" {
					return nil, 0, true, problem(422, "GRAPH_EDGE_INVALID", "edge authority and node metadata are server selected")
				}
			}
		}
		g, e := dependencyGraph(ctx, t)
		if e != nil {
			return nil, 0, true, e
		}
		if e = match(r, g); e != nil {
			return nil, 0, true, e
		}
		edges, e := dependency.Edges(evidence.Rows(g["nodes"]), evidence.Rows(in["edges"]))
		if e != nil {
			return nil, 0, true, problem(422, e.Error(), "graph endpoints,types and cycles must resolve")
		}
		_, e = t.DependencyGraphAppend(ctx, model.Number(g, "version"), model.Document{"edges": edges, "reason": in["reason"], "changed_by": i.Subject, "inventory_hash": g["inventory_hash"]})
		if e != nil {
			return nil, 0, true, e
		}
		if e = t.Audit(ctx, i.Subject, "dependency_graph.revised", i.Tenant, model.Document{"previous_version": g["version"], "reason": in["reason"]}); e != nil {
			return nil, 0, true, e
		}
		out, e := dependencyGraph(ctx, t)
		return out, 201, true, e
	}
	for k := range in {
		if k != "graph_version" && k != "valid_until" && k != "acknowledgement" && k != "note" {
			return nil, 0, true, problem(422, "DEPENDENCY_REVIEW_FIELDS_INVALID", "review binds server selected graph and inventory")
		}
	}
	if v, ok := in["graph_version"].(float64); !ok || v < 1 || v > 9007199254740991 || math.Trunc(v) != v {
		return nil, 0, true, problem(422, "DEPENDENCY_GRAPH_VERSION_INVALID", "an exact positive graph version is required")
	}
	res, e := t.Get(ctx, "resources", parts[1])
	if e != nil {
		return nil, 0, true, e
	}
	if e = match(r, res); e != nil {
		return nil, 0, true, e
	}
	if model.String(in, "acknowledgement") != "REVIEWED_DISCOVERED_AND_EXTERNAL_DEPENDENCIES" || strings.TrimSpace(model.String(in, "note")) == "" || len(model.String(in, "note")) > 2000 {
		return nil, 0, true, problem(422, "DEPENDENCY_REVIEW_ACK_REQUIRED", "explicit external dependency review and a bounded note are required")
	}
	now := time.Now().UTC()
	expires, e := time.Parse(time.RFC3339Nano, model.String(in, "valid_until"))
	if e != nil || !expires.After(now) || expires.After(now.Add(24*time.Hour)) {
		return nil, 0, true, problem(422, "DEPENDENCY_REVIEW_EXPIRY_INVALID", "review expires within 24 hours")
	}
	g, e := dependencyGraph(ctx, t)
	if e != nil {
		return nil, 0, true, e
	}
	if model.Number(g, "version") < 1 || model.Number(in, "graph_version") != model.Number(g, "version") {
		return nil, 0, true, problem(409, "DEPENDENCY_GRAPH_CHANGED", "declare and inspect the current graph before reviewing")
	}
	if model.String(g, "status") != "DECLARED" {
		return nil, 0, true, problem(422, "DEPENDENCY_GRAPH_UNRESOLVED", "resolve graph endpoints before reviewing")
	}
	reasons := dependency.Assess(evidence.Rows(g["nodes"]), evidence.Rows(g["edges"]), parts[1])
	status := "READY"
	if len(reasons) > 0 {
		status = "BLOCKED"
	}
	d := model.Document{"resource_id": parts[1], "graph_version": g["version"], "graph_hash": g["graph_hash"], "inventory_hash": g["inventory_hash"], "reviewed_by": i.Subject, "reviewed_at": now.Format(time.RFC3339Nano), "expires_at": expires.Format(time.RFC3339Nano), "acknowledgement": in["acknowledgement"], "note": in["note"], "status": status, "reasons": reasons}
	out, e := t.DependencyReviewCreate(ctx, d)
	if e == nil {
		e = t.Audit(ctx, i.Subject, "dependency_review.recorded", parts[1], model.Document{"review_id": out["id"], "status": status, "graph_hash": g["graph_hash"]})
	}
	return out, 201, true, e
}
