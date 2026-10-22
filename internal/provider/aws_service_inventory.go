package provider

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/awsservice"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

type serviceCursor struct {
	Phase      int    `json:"phase"`
	Pages      int    `json:"pages"`
	Token      string `json:"token"`
	SourceHash string `json:"source_hash"`
	Family     string `json:"family"`
}
type serviceInventory struct {
	r        *serviceRead
	reg      awsservice.Registration
	out      awsservice.Collection
	seen     map[string]int
	selected map[string]bool
}

// ServiceInventory collects one bounded native root page. A continuation is an
// opaque, registration-bound page cursor. Child collection gaps are retained on
// each resource; a point read never claims a continuously current census.
func (a *AWS) ServiceInventory(ctx context.Context, reg awsservice.Registration, family, cursor string) (awsservice.Collection, error) {
	out := awsservice.Collection{SchemaVersion: "1", Scope: awsservice.Scope{TenantID: reg.TenantID, AccountID: reg.AccountID, Region: reg.Region}, Family: family, Resources: []model.Document{}, Reasons: []string{}, CollectedAt: time.Now().UTC()}
	if awsservice.ValidateRegistration(reg) != nil || !reg.Enabled || !awsservice.Contains(reg.ServiceFamilies, family) || len(cursor) > 8192 {
		return out, awsservice.ErrEvidence
	}
	r, e := newServiceRead(a, out.Scope)
	if e != nil {
		return out, e
	}
	c := serviceCursor{SourceHash: awsservice.Hash(reg), Family: family}
	if cursor != "" {
		b, e := base64.RawURLEncoding.DecodeString(cursor)
		if e != nil || len(b) > 6144 || json.Unmarshal(b, &c) != nil || c.SourceHash != awsservice.Hash(reg) || c.Family != family || len(c.Token) > 4096 || c.Phase < 0 || c.Phase > 4 || c.Pages < 0 || c.Pages >= 1000 {
			return out, awsservice.ErrEvidence
		}
	}
	i := &serviceInventory{r: r, reg: reg, out: out, seen: map[string]int{}, selected: map[string]bool{}}
	for _, arn := range reg.RootResourceARNs {
		i.selected[arn] = true
	}
	var next string
	var done bool
	switch family {
	case "ECS":
		next, done, e = i.ecs(ctx, c)
	case "EKS":
		next, done, e = i.eks(ctx, c)
	case "ELASTICACHE":
		next, done, e = i.cache(ctx, c)
	case "DYNAMODB":
		next, done, e = i.dynamodb(ctx, c)
	case "ELB":
		next, done, e = i.elb(ctx, c)
	default:
		e = awsservice.ErrEvidence
	}
	if e != nil {
		return i.out, e
	}
	i.out.NextCursor = next
	i.out.Complete = done && len(i.out.Reasons) == 0
	i.out.Raw, _ = json.Marshal(model.Document{"schema_version": "AWS_SERVICE_SANITIZED_NATIVE_V1", "scope": out.Scope, "source_id": reg.ID, "source_version": reg.Version, "family": family, "frames": r.frames})
	if len(i.out.Raw) > awsservice.MaxCaptureBytes+1<<20 {
		return out, awsservice.ErrEvidence
	}
	i.out.RawSHA256 = awsservice.BytesHash(i.out.Raw)
	sort.Strings(i.out.Reasons)
	return i.out, nil
}
func (i *serviceInventory) accepts(arn string) bool {
	return i.reg.ScopeMode == "ACCOUNT" || i.selected[arn]
}
func (i *serviceInventory) next(c serviceCursor, token string, phases int) (string, bool, error) {
	if len(token) > 4096 || token != "" && token == c.Token {
		return "", false, awsservice.ErrEvidence
	}
	c.Pages++
	c.Token = token
	if token == "" {
		c.Phase++
		if c.Phase >= phases {
			return "", true, nil
		}
	}
	b, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(b), false, nil
}
func (i *serviceInventory) problem(resource model.Document, field string, e error) {
	code := "UNAVAILABLE"
	if v, ok := e.(*QueryRejection); ok {
		switch v.Code {
		case "AccessDenied", "AccessDeniedException", "UnauthorizedOperation":
			code = "DENIED"
		case "ResourceNotFoundException", "CacheClusterNotFound", "ReplicationGroupNotFoundFault", "LoadBalancerNotFound":
			code = "ABSENT_AT_READ"
		case "InvalidAction", "UnknownOperationException", "UnsupportedOperation":
			code = "UNSUPPORTED"
		default:
			code = "UNAVAILABLE_" + v.Code
		}
	}
	cfg := awsservice.Document(resource["aws_service_configuration"])
	status := awsservice.Document(cfg["collection_status"])
	status[field] = model.Document{"status": code, "reason_code": "AWS_SERVICE_" + strings.ToUpper(field) + "_" + code}
	cfg["collection_status"] = status
	cfg["collection_complete"] = false
	resource["aws_service_configuration"] = cfg
	i.out.Reasons = append(i.out.Reasons, "AWS_SERVICE_"+strings.ToUpper(field)+"_"+code)
}
func (i *serviceInventory) put(kind, arn, name string, config model.Document) (model.Document, error) {
	if !awsservice.Contains(awsservice.ResourceTypes, kind) || !awsservice.BoundARN(i.out.Scope, arn) {
		return nil, awsservice.ErrEvidence
	}
	key := kind + "\x00" + arn
	if n, ok := i.seen[key]; ok {
		return i.out.Resources[n], nil
	}
	if len(i.out.Resources) >= awsservice.MaxRows {
		return nil, awsservice.ErrEvidence
	}
	config["collection_complete"] = true
	config["observation_basis"] = "BOUNDED_NON_ATOMIC_SANITIZED_NATIVE_POINT_READ"
	config["sanitizer_version"] = "AWS_SERVICE_SECRET_MINIMIZATION_V1"
	config["unknown_is_zero"] = false
	config["collection_status"] = model.Document{}
	d := model.Document{"provider": "AWS", "resource_type": kind, "provider_resource_id": arn, "name": name, "account_id": i.out.Scope.AccountID, "region": i.out.Scope.Region, "service_family": i.out.Family, "aws_service_configuration": config, "configuration_authority": "UNKNOWN", "owner": nil, "workload_id": nil, "eligibility": "OBSERVE_ONLY", "last_seen_at": i.out.CollectedAt.UTC().Format(time.RFC3339Nano), "hourly_effective_cost": nil, "monthly_effective_cost": nil, "currency": nil, "provider_relationships": []model.Document{}}
	i.seen[key] = len(i.out.Resources)
	i.out.Resources = append(i.out.Resources, d)
	return d, nil
}
func serviceRel(d model.Document, kind, arn string) {
	if arn == "" {
		return
	}
	rows := awsservice.Rows(d["provider_relationships"])
	for _, x := range rows {
		if x["type"] == kind && x["target_provider_resource_id"] == arn {
			return
		}
	}
	d["provider_relationships"] = append(rows, model.Document{"type": kind, "target_provider_resource_id": arn, "basis": "NATIVE_AWS_SERVICE_POINT_RELATIONSHIP", "analytical": true})
}
func (i *serviceInventory) set(d model.Document, key string, value any) {
	cfg := awsservice.Document(d["aws_service_configuration"])
	cfg[key] = value
	d["aws_service_configuration"] = cfg
}
func (i *serviceInventory) unavailable(kind, arn, name, field string, e error) (model.Document, error) {
	d, err := i.put(kind, arn, name, model.Document{"native_identifier": arn, "configuration_status": "UNKNOWN"})
	if err != nil {
		return nil, err
	}
	i.problem(d, field, e)
	return d, nil
}
func (i *serviceInventory) jsonOptional(ctx context.Context, d model.Document, key, service, action, path string, p model.Document) model.Document {
	v, e := i.r.json(ctx, service, action, path, p)
	if e != nil {
		i.problem(d, key, e)
		return nil
	}
	i.set(d, key, v)
	return v
}
func (i *serviceInventory) queryOptional(ctx context.Context, d model.Document, key, service, action, version string, p url.Values) model.Document {
	v, e := i.r.query(ctx, service, action, version, p)
	if e != nil {
		i.problem(d, key, e)
		return nil
	}
	i.set(d, key, v)
	return v
}

func (i *serviceInventory) jsonPages(ctx context.Context, service, action, path, key, tokenKey, requestToken string, p model.Document) ([]model.Document, error) {
	out := []model.Document{}
	seen := map[string]bool{}
	for n := 0; n < 32; n++ {
		v, e := i.r.json(ctx, service, action, path, p)
		if e != nil {
			return out, e
		}
		if _, exists := v[key]; !exists {
			return out, awsservice.ErrEvidence
		}
		rows := awsservice.Rows(v[key])
		if rows == nil {
			return out, awsservice.ErrEvidence
		}
		out = append(out, rows...)
		if len(out) > awsservice.MaxRows {
			return out, awsservice.ErrEvidence
		}
		token := model.String(v, tokenKey)
		if token == "" {
			return out, nil
		}
		if seen[token] || len(token) > 4096 {
			return out, awsservice.ErrEvidence
		}
		seen[token] = true
		p[requestToken] = token
	}
	return out, awsservice.ErrEvidence
}
func (i *serviceInventory) scaling(ctx context.Context, d model.Document, namespace, id string) {
	for _, spec := range []struct{ action, key string }{{"DescribeScalableTargets", "scalable_targets"}, {"DescribeScalingPolicies", "scaling_policies"}, {"DescribeScheduledActions", "scheduled_actions"}} {
		p := model.Document{"ServiceNamespace": namespace, "MaxResults": 50}
		if spec.action == "DescribeScalableTargets" {
			p["ResourceIds"] = []string{id}
		} else {
			p["ResourceId"] = id
		}
		rows, e := i.jsonPages(ctx, "application-autoscaling", spec.action, "/", map[string]string{"DescribeScalableTargets": "ScalableTargets", "DescribeScalingPolicies": "ScalingPolicies", "DescribeScheduledActions": "ScheduledActions"}[spec.action], "NextToken", "NextToken", p)
		i.set(d, spec.key, rows)
		if e != nil {
			i.problem(d, spec.key, e)
		}
	}
}
