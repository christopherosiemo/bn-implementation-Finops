package kubernetes

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Reader uses a server-selected Kubernetes endpoint and a dedicated read-only
// identity. It has no mutating verbs and rejects redirects even on injected clients.
type Reader struct {
	URL, Token string
	Client     *http.Client
	Now        func() time.Time
}

func (r Reader) get(ctx context.Context, path string) (Document, string, error) {
	u, err := url.Parse(r.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
		return nil, "", errors.New("K8S_ENDPOINT_INVALID")
	}
	if r.Client == nil || strings.TrimSpace(r.Token) == "" || strings.ContainsAny(r.Token, "\r\n") {
		return nil, "", errors.New("K8S_READ_IDENTITY_REQUIRED")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.URL+path, nil)
	if err != nil {
		return nil, "", errors.New("K8S_REQUEST_INVALID")
	}
	req.Header.Set("Authorization", "Bearer "+r.Token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Encoding", "identity")
	client := *r.Client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", errors.New("K8S_READ_UNAVAILABLE")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, "", fmt.Errorf("K8S_READ_STATUS_%d", resp.StatusCode)
	}
	if v := resp.Header.Get("Content-Encoding"); v != "" && v != "identity" {
		return nil, "", errors.New("K8S_READ_ENCODING_UNSUPPORTED")
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8*1024*1024+1))
	if err != nil || len(raw) > 8*1024*1024 {
		return nil, "", errors.New("K8S_READ_LIMIT")
	}
	var d Document
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if dec.Decode(&d) != nil || dec.Decode(new(any)) != io.EOF {
		return nil, "", errors.New("K8S_READ_INVALID_JSON")
	}
	if str(object(d["metadata"]), "continue") != "" {
		return nil, "", errors.New("K8S_INVENTORY_PAGINATION_UNSUPPORTED")
	}
	return d, HashBytes(raw), nil
}
func (r Reader) Collect(ctx context.Context, b Binding) (Snapshot, error) {
	if err := ValidateBinding(b); err != nil {
		return Snapshot{}, err
	}
	now := time.Now().UTC()
	if r.Now != nil {
		now = r.Now().UTC()
	}
	s := Snapshot{SchemaVersion: "1", Binding: b, CollectedAt: now, RawHashes: map[string]string{}, Problems: []string{}, Pods: []Pod{}, Nodes: []Node{}, PDBs: []PDB{}, HPAs: []HPA{}, VPAs: []VPA{}, NodeAutoscalers: []string{}}
	read := func(key, path string) (Document, error) {
		d, h, e := r.get(ctx, path)
		if e == nil {
			s.RawHashes[key] = h
		}
		return d, e
	}
	cluster, err := read("cluster", "/api/v1/namespaces/kube-system")
	if err != nil {
		return s, err
	}
	s.ClusterID = str(object(cluster["metadata"]), "uid")
	ns, err := read("namespace", "/api/v1/namespaces/"+b.Namespace)
	if err != nil {
		return s, err
	}
	m := object(ns["metadata"])
	s.NamespaceUID = str(m, "uid")
	labels := stringMap(m["labels"])
	s.Environment = labels["finops.autopilot/environment"]
	s.Owner = labels["finops.autopilot/owner"]
	base := "/apis/apps/v1/namespaces/" + b.Namespace
	d, err := read("deployment", base+"/deployments/"+b.Deployment)
	if err != nil {
		return s, err
	}
	s.Deployment, err = ParseDeployment(d)
	if err != nil {
		return s, err
	}
	nodes, err := read("nodes", "/api/v1/nodes")
	if err != nil {
		return s, err
	}
	nodeZones := map[string]string{}
	for _, x := range items(nodes) {
		m, spec, status := object(x["metadata"]), object(x["spec"]), object(x["status"])
		labels := stringMap(m["labels"])
		alloc := object(status["allocatable"])
		cpu, e := CPUQuantity(str(alloc, "cpu"))
		if e != nil {
			s.Problems = append(s.Problems, "K8S_NODE_CAPACITY_UNKNOWN")
		}
		mem, e := MemoryQuantity(str(alloc, "memory"))
		if e != nil {
			s.Problems = append(s.Problems, "K8S_NODE_CAPACITY_UNKNOWN")
		}
		n := Node{UID: str(m, "uid"), Name: str(m, "name"), Zone: labels["topology.kubernetes.io/zone"], Ready: condition(status, "Ready"), Unschedulable: boolean(spec, "unschedulable"), CPUAllocatableMilli: cpu, MemoryAllocatableBytes: mem, ProviderID: str(spec, "providerID")}
		s.Nodes = append(s.Nodes, n)
		nodeZones[n.Name] = n.Zone
	}
	sets, err := read("replicasets", base+"/replicasets")
	if err != nil {
		return s, err
	}
	owners := map[string]bool{}
	for _, x := range items(sets) {
		if ownedBy(x, b.DeploymentUID, "Deployment") {
			owners[str(object(x["metadata"]), "uid")] = true
		}
	}
	pods, err := read("pods", "/api/v1/namespaces/"+b.Namespace+"/pods")
	if err != nil {
		return s, err
	}
	for _, x := range items(pods) {
		m := object(x["metadata"])
		ours := false
		for _, o := range array(m["ownerReferences"]) {
			v := object(o)
			if str(v, "kind") == "ReplicaSet" && owners[str(v, "uid")] && boolean(v, "controller") {
				ours = true
			}
		}
		if !ours {
			continue
		}
		spec, status := object(x["spec"]), object(x["status"])
		p := Pod{UID: str(m, "uid"), Node: str(spec, "nodeName"), Ready: condition(status, "Ready"), Terminating: str(m, "deletionTimestamp") != ""}
		p.Zone = nodeZones[p.Node]
		for _, c := range array(status["containerStatuses"]) {
			v := object(c)
			if id := str(v, "imageID"); id != "" {
				p.ImageIDs = append(p.ImageIDs, id)
			}
			p.Restarts += num(v, "restartCount")
			if str(object(object(v["lastState"])["terminated"]), "reason") == "OOMKilled" {
				p.OOMKilled = true
			}
		}
		s.Pods = append(s.Pods, p)
	}
	pdbs, err := read("pdbs", "/apis/policy/v1/namespaces/"+b.Namespace+"/poddisruptionbudgets")
	if err != nil {
		return s, err
	}
	for _, x := range items(pdbs) {
		m, spec, status := object(x["metadata"]), object(x["spec"]), object(x["status"])
		match, known := selectorMatches(object(spec["selector"]), s.Deployment.TemplateLabels)
		s.PDBs = append(s.PDBs, PDB{UID: str(m, "uid"), Name: str(m, "name"), Generation: num(m, "generation"), ObservedGeneration: num(status, "observedGeneration"), Matches: match, SelectorKnown: known, DisruptionsAllowed: num(status, "disruptionsAllowed"), CurrentHealthy: num(status, "currentHealthy"), DesiredHealthy: num(status, "desiredHealthy")})
	}
	hpas, err := read("hpas", "/apis/autoscaling/v2/namespaces/"+b.Namespace+"/horizontalpodautoscalers")
	if err != nil {
		return s, err
	}
	for _, x := range items(hpas) {
		spec := object(x["spec"])
		target := object(spec["scaleTargetRef"])
		if str(target, "kind") != "Deployment" || str(target, "name") != b.Deployment {
			continue
		}
		h := HPA{Name: str(object(x["metadata"]), "name"), MinReplicas: num(spec, "minReplicas"), MaxReplicas: num(spec, "maxReplicas"), MetricsKnown: true, UtilizationResources: []string{}}
		if h.MinReplicas == 0 {
			h.MinReplicas = 1
		}
		for _, z := range array(spec["metrics"]) {
			v := object(z)
			kind := str(v, "type")
			if kind != "Resource" && kind != "ContainerResource" {
				h.MetricsKnown = false
				continue
			}
			var metric Document
			if kind == "Resource" {
				metric = object(v["resource"])
			} else {
				metric = object(v["containerResource"])
			}
			t := object(metric["target"])
			if str(t, "type") == "Utilization" {
				h.UtilizationResources = append(h.UtilizationResources, str(metric, "name"))
			} else {
				h.MetricsKnown = false
			}
		}
		s.HPAs = append(s.HPAs, h)
	}
	crds, err := read("crds", "/apis/apiextensions.k8s.io/v1/customresourcedefinitions")
	if err != nil {
		return s, err
	}
	vpa := false
	for _, x := range items(crds) {
		name := str(object(x["metadata"]), "name")
		if name == "verticalpodautoscalers.autoscaling.k8s.io" {
			vpa = true
		}
		if strings.HasSuffix(name, ".karpenter.sh") || strings.HasSuffix(name, ".karpenter.k8s.aws") {
			s.NodeAutoscalers = append(s.NodeAutoscalers, "KARPENTER")
		}
	}
	if vpa {
		vs, err := read("vpas", "/apis/autoscaling.k8s.io/v1/namespaces/"+b.Namespace+"/verticalpodautoscalers")
		if err != nil {
			return s, err
		}
		for _, x := range items(vs) {
			spec := object(x["spec"])
			target := object(spec["targetRef"])
			if str(target, "kind") == "Deployment" && str(target, "name") == b.Deployment {
				mode := str(object(spec["updatePolicy"]), "updateMode")
				if mode == "" {
					mode = "Auto"
				}
				s.VPAs = append(s.VPAs, VPA{Name: str(object(x["metadata"]), "name"), Mode: mode})
			}
		}
	}
	system, err := read("system_deployments", "/apis/apps/v1/namespaces/kube-system/deployments")
	if err != nil {
		return s, err
	}
	for _, x := range items(system) {
		raw, _ := json.Marshal(x)
		if strings.Contains(string(raw), "cluster-autoscaler") {
			s.NodeAutoscalers = append(s.NodeAutoscalers, "CLUSTER_AUTOSCALER")
		}
	}
	// Supported controller detection is not proof that an arbitrary hosted
	// controller is absent. The local KIND authority has a bounded known scope.
	s.AutoscalerDiscoveryComplete = b.Provider == "LOCAL_KIND"
	s.NodeAutoscalers = stable(s.NodeAutoscalers)
	s.Git, err = r.git(ctx, b, read)
	if b.Git.Engine != "FLUX" {
		s.Git.RawHash = s.RawHashes["git_ack"]
	}
	if err != nil {
		s.Problems = append(s.Problems, err.Error())
	}
	final, err := read("deployment_after", base+"/deployments/"+b.Deployment)
	if err != nil {
		return s, err
	}
	if str(object(final["metadata"]), "resourceVersion") != str(object(d["metadata"]), "resourceVersion") {
		s.Problems = append(s.Problems, "K8S_INVENTORY_CHANGED_DURING_COLLECTION")
	}
	if s.ClusterID != b.ClusterID || s.NamespaceUID != b.NamespaceUID || s.Deployment.UID != b.DeploymentUID {
		s.Problems = append(s.Problems, "K8S_IDENTITY_CHANGED")
	}
	sort.Slice(s.Nodes, func(i, j int) bool { return s.Nodes[i].Name < s.Nodes[j].Name })
	sort.Slice(s.Pods, func(i, j int) bool { return s.Pods[i].UID < s.Pods[j].UID })
	s.Problems = stable(s.Problems)
	s.Hash = SnapshotHash(s)
	return s, nil
}
func (r Reader) git(ctx context.Context, b Binding, read func(string, string) (Document, error)) (GitObservation, error) {
	g := GitObservation{Engine: b.Git.Engine, Repository: b.Git.Repository, Path: b.Git.Path}
	prefix := "/api/v1/namespaces/" + b.Git.ControllerNamespace
	if b.Git.Engine == "LOCAL_GITOPS_TEST_DOUBLE" {
		d, e := read("git_ack", prefix+"/configmaps/"+b.Git.ControllerName)
		if e != nil {
			return g, e
		}
		data := stringMap(d["data"])
		g.Engine = data["engine"]
		g.Repository = data["repository"]
		g.Path = data["path"]
		g.Revision = data["revision"]
		g.Ready = data["ready"] == "true"
		g.Synced = data["synced"] == "true"
		g.DeploymentSpecHash = data["deployment_spec_hash"]
		g.ObservedAt, _ = time.Parse(time.RFC3339Nano, data["observed_at"])
		g.ObservedGeneration, _ = strconv.ParseInt(data["observed_generation"], 10, 64)
		g.Generation = num(object(d["metadata"]), "generation")
		g.RawHash = Hash(d)
		return g, nil
	}
	if b.Git.Engine == "ARGOCD" {
		d, e := read("git_ack", "/apis/argoproj.io/v1alpha1/namespaces/"+b.Git.ControllerNamespace+"/applications/"+b.Git.ControllerName)
		if e != nil {
			return g, e
		}
		spec, status := object(d["spec"]), object(d["status"])
		source := object(spec["source"])
		g.Repository = str(source, "repoURL")
		g.Path = str(source, "path")
		g.Revision = str(object(status["sync"]), "revision")
		g.Synced = str(object(status["sync"]), "status") == "Synced"
		g.Ready = str(object(status["health"]), "status") == "Healthy"
		g.ObservedAt, _ = time.Parse(time.RFC3339Nano, str(status, "reconciledAt"))
		g.RawHash = Hash(d)
		return g, nil
	}
	return r.flux(ctx, b, read)
}

func ParseDeployment(d Document) (Deployment, error) {
	m, spec, status := object(d["metadata"]), object(d["spec"]), object(d["status"])
	template := object(spec["template"])
	ps := object(template["spec"])
	strategy := object(spec["strategy"])
	rolling := object(strategy["rollingUpdate"])
	x := Deployment{UID: str(m, "uid"), Name: str(m, "name"), Generation: num(m, "generation"), ObservedGeneration: num(status, "observedGeneration"), Replicas: num(spec, "replicas"), ReadyReplicas: num(status, "readyReplicas"), UpdatedReplicas: num(status, "updatedReplicas"), UnavailableReplicas: num(status, "unavailableReplicas"), Paused: boolean(spec, "paused"), Deleting: str(m, "deletionTimestamp") != "", Labels: stringMap(m["labels"]), TemplateLabels: stringMap(object(template["metadata"])["labels"]), Strategy: str(strategy, "type"), MaxUnavailableZero: scalar(rolling["maxUnavailable"]) == "0" || scalar(rolling["maxUnavailable"]) == "0%", MaxSurgeOne: scalar(rolling["maxSurge"]) == "1", Spec: spec, SpecHash: SpecHash(spec), Containers: []Container{}}
	for _, z := range array(ps["topologySpreadConstraints"]) {
		v := object(z)
		match, known := selectorMatches(object(v["labelSelector"]), x.TemplateLabels)
		if str(v, "topologyKey") == "topology.kubernetes.io/zone" && str(v, "whenUnsatisfiable") == "DoNotSchedule" && num(v, "maxSkew") == 1 && match && known {
			x.ZoneSpread = true
		}
	}
	if len(array(ps["initContainers"])) > 0 || len(array(ps["ephemeralContainers"])) > 0 {
		return x, errors.New("K8S_INIT_OR_EPHEMERAL_CAPACITY_UNSUPPORTED")
	}
	for _, z := range array(ps["containers"]) {
		v := object(z)
		res := object(v["resources"])
		req, lim := object(res["requests"]), object(res["limits"])
		cpu, e := CPUQuantity(str(req, "cpu"))
		if e != nil {
			return x, e
		}
		mem, e := MemoryQuantity(str(req, "memory"))
		if e != nil {
			return x, e
		}
		lc, lm := int64(0), int64(0)
		if str(lim, "cpu") != "" {
			lc, e = CPUQuantity(str(lim, "cpu"))
			if e != nil {
				return x, e
			}
		}
		if str(lim, "memory") != "" {
			lm, e = MemoryQuantity(str(lim, "memory"))
			if e != nil {
				return x, e
			}
		}
		x.Containers = append(x.Containers, Container{Name: str(v, "name"), CPURequestMilli: cpu, MemoryRequestBytes: mem, CPULimitMilli: lc, MemoryLimitBytes: lm, ReadinessProbe: len(object(v["readinessProbe"])) > 0})
	}
	if x.UID == "" || x.Name == "" || len(x.Containers) == 0 {
		return x, errors.New("K8S_DEPLOYMENT_INVALID")
	}
	return x, nil
}
func object(v any) Document {
	switch d := v.(type) {
	case Document:
		return d
	case map[string]any:
		return Document(d)
	}
	return Document{}
}
func array(v any) []any { a, _ := v.([]any); return a }
func items(d Document) []Document {
	out := []Document{}
	for _, x := range array(d["items"]) {
		out = append(out, object(x))
	}
	return out
}
func str(d Document, k string) string { s, _ := d[k].(string); return s }
func num(d Document, k string) int64 {
	switch v := d[k].(type) {
	case json.Number:
		n, _ := v.Int64()
		return n
	case float64:
		return int64(v)
	case int:
		return int64(v)
	case int64:
		return v
	}
	return 0
}
func boolean(d Document, k string) bool { v, _ := d[k].(bool); return v }
func scalar(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case json.Number:
		return string(x)
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case int:
		return strconv.Itoa(x)
	}
	return ""
}
func stringMap(v any) map[string]string {
	out := map[string]string{}
	for k, x := range object(v) {
		if s, ok := x.(string); ok {
			out[k] = s
		}
	}
	return out
}
func condition(d Document, name string) bool {
	for _, x := range array(d["conditions"]) {
		v := object(x)
		if str(v, "type") == name {
			return str(v, "status") == "True"
		}
	}
	return false
}
func ownedBy(d Document, uid, kind string) bool {
	for _, x := range array(object(d["metadata"])["ownerReferences"]) {
		v := object(x)
		if str(v, "uid") == uid && str(v, "kind") == kind && boolean(v, "controller") {
			return true
		}
	}
	return false
}
func selectorMatches(sel Document, labels map[string]string) (bool, bool) {
	if sel == nil {
		return false, false
	}
	for k, v := range stringMap(sel["matchLabels"]) {
		if labels[k] != v {
			return false, true
		}
	}
	for _, x := range array(sel["matchExpressions"]) {
		e := object(x)
		key := str(e, "key")
		value, exists := labels[key]
		has := false
		for _, v := range array(e["values"]) {
			if v == value {
				has = true
			}
		}
		switch str(e, "operator") {
		case "In":
			if !exists || !has {
				return false, true
			}
		case "NotIn":
			if exists && has {
				return false, true
			}
		case "Exists":
			if !exists {
				return false, true
			}
		case "DoesNotExist":
			if exists {
				return false, true
			}
		default:
			return false, false
		}
	}
	return true, true
}

var quantity = regexp.MustCompile(`^([0-9]+(?:\.[0-9]+)?)([a-zA-Z]*)$`)

func CPUQuantity(s string) (int64, error)    { return parseQuantity(s, true) }
func MemoryQuantity(s string) (int64, error) { return parseQuantity(s, false) }
func parseQuantity(s string, cpu bool) (int64, error) {
	m := quantity.FindStringSubmatch(s)
	if m == nil {
		return 0, errors.New("K8S_QUANTITY_UNSUPPORTED")
	}
	v, ok := new(big.Rat).SetString(m[1])
	if !ok {
		return 0, errors.New("K8S_QUANTITY_UNSUPPORTED")
	}
	factor := int64(1)
	if cpu {
		switch m[2] {
		case "":
			factor = 1000
		case "m":
			factor = 1
		case "u":
			v.Quo(v, big.NewRat(1000, 1))
		case "n":
			v.Quo(v, big.NewRat(1000000, 1))
		default:
			return 0, errors.New("K8S_QUANTITY_UNSUPPORTED")
		}
	} else {
		switch m[2] {
		case "":
		case "Ki":
			factor = 1 << 10
		case "Mi":
			factor = 1 << 20
		case "Gi":
			factor = 1 << 30
		case "Ti":
			factor = 1 << 40
		case "K":
			factor = 1000
		case "M":
			factor = 1000000
		case "G":
			factor = 1000000000
		default:
			return 0, errors.New("K8S_QUANTITY_UNSUPPORTED")
		}
	}
	v.Mul(v, big.NewRat(factor, 1))
	if !v.IsInt() || !v.Num().IsInt64() || v.Sign() < 0 {
		return 0, errors.New("K8S_QUANTITY_PRECISION_UNSUPPORTED")
	}
	return v.Num().Int64(), nil
}
func formatMilli(n int64) string { return strconv.FormatInt(n, 10) + "m" }
func formatBytes(n int64) string { return strconv.FormatInt(n, 10) }

// SpecHash normalizes only semantically equivalent resource quantity spelling.
// The complete remaining Deployment spec, including health/topology/security,
// stays bound. Kubernetes may serialize an integer byte request as Mi or Gi.
func SpecHash(spec Document) string {
	d := clone(spec)
	cs := array(object(object(d["template"])["spec"])["containers"])
	for _, x := range cs {
		c := object(x)
		res := object(c["resources"])
		for _, field := range []string{"requests", "limits"} {
			v := object(res[field])
			if s := str(v, "cpu"); s != "" {
				n, e := CPUQuantity(s)
				if e == nil {
					v["cpu"] = formatMilli(n)
				}
			}
			if s := str(v, "memory"); s != "" {
				n, e := MemoryQuantity(s)
				if e == nil {
					v["memory"] = formatBytes(n)
				}
			}
		}
	}
	return Hash(d)
}
