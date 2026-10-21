package provider

import (
	"context"
	"net/url"
	"strings"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/awsservice"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

const serviceELBV2 = "2015-12-01"
const serviceELBClassic = "2012-06-01"

func (i *serviceInventory) elbPages(ctx context.Context, action, version, key string, p url.Values) ([]model.Document, error) {
	out := []model.Document{}
	seen := map[string]bool{}
	for n := 0; n < 32; n++ {
		d, e := i.r.query(ctx, "elasticloadbalancing", action, version, p)
		if e != nil {
			return out, e
		}
		v, ok := d[key]
		if !ok {
			return out, awsservice.ErrEvidence
		}
		out = append(out, serviceList(v)...)
		if len(out) > awsservice.MaxRows {
			return out, awsservice.ErrEvidence
		}
		next := model.String(d, "NextMarker")
		if next == "" {
			return out, nil
		}
		if seen[next] || len(next) > 4096 {
			return out, awsservice.ErrEvidence
		}
		seen[next] = true
		p.Set("Marker", next)
	}
	return out, awsservice.ErrEvidence
}

func (i *serviceInventory) elb(ctx context.Context, c serviceCursor) (string, bool, error) {
	if c.Phase > 1 {
		return "", false, awsservice.ErrEvidence
	}
	version, key := serviceELBV2, "LoadBalancers"
	if c.Phase == 1 {
		version, key = serviceELBClassic, "LoadBalancerDescriptions"
	}
	p := url.Values{"PageSize": {"5"}}
	if c.Token != "" {
		p.Set("Marker", c.Token)
	}
	page, e := i.r.query(ctx, "elasticloadbalancing", "DescribeLoadBalancers", version, p)
	if e != nil {
		return "", false, e
	}
	v, ok := page[key]
	if !ok {
		return "", false, awsservice.ErrEvidence
	}
	for _, cfg := range serviceList(v) {
		arn, name := model.String(cfg, "LoadBalancerArn"), model.String(cfg, "LoadBalancerName")
		subtype := strings.ToUpper(model.String(cfg, "Type"))
		if subtype == "APPLICATION" {
			subtype = "ALB"
		}
		if subtype == "NETWORK" {
			subtype = "NLB"
		}
		if c.Phase == 1 {
			if name == "" || len(name) > 32 || strings.ContainsAny(name, "/:\x00\r\n") {
				return "", false, awsservice.ErrEvidence
			}
			arn = "arn:aws:elasticloadbalancing:" + i.out.Scope.Region + ":" + i.out.Scope.AccountID + ":loadbalancer/" + name
			subtype = "CLASSIC"
			cfg["native_identity_basis"] = "CALLER_ACCOUNT_REGION_AND_NATIVE_LOAD_BALANCER_NAME"
		}
		if !awsservice.BoundARN(i.out.Scope, arn) {
			return "", false, awsservice.ErrEvidence
		}
		if !i.accepts(arn) {
			continue
		}
		cfg["subtype"] = subtype
		cfg["target_ownership"] = "UNKNOWN_UNLESS_EXACT_NATIVE_BINDING"
		cfg["workload_purpose"] = "UNKNOWN"
		lb, e := i.put("LOAD_BALANCER", arn, name, cfg)
		if e != nil {
			return "", false, e
		}
		if subtype != "ALB" && subtype != "NLB" && subtype != "CLASSIC" {
			i.set(lb, "model_support", "OBSERVATION_ONLY_UNSUPPORTED_SUBTYPE")
		}
		if c.Phase == 1 {
			i.classicELB(ctx, lb, name)
			continue
		}
		i.queryOptional(ctx, lb, "attributes", "elasticloadbalancing", "DescribeLoadBalancerAttributes", version, url.Values{"LoadBalancerArn": {arn}})
		i.queryOptional(ctx, lb, "tags", "elasticloadbalancing", "DescribeTags", version, url.Values{"ResourceArns.member.1": {arn}})
		listeners, err := i.elbPages(ctx, "DescribeListeners", version, "Listeners", url.Values{"LoadBalancerArn": {arn}, "PageSize": {"100"}})
		if err != nil {
			i.problem(lb, "listeners", err)
		}
		for _, row := range listeners {
			listenerARN := model.String(row, "ListenerArn")
			listener, e := i.put("ELB_LISTENER", listenerARN, listenerARN, row)
			if e != nil {
				return "", false, e
			}
			serviceRel(listener, "MEMBER_OF", arn)
			serviceRel(lb, "HAS_LISTENER", listenerARN)
			if subtype == "ALB" {
				rules, err := i.elbPages(ctx, "DescribeRules", version, "Rules", url.Values{"ListenerArn": {listenerARN}, "PageSize": {"100"}})
				i.set(listener, "rules", rules)
				if err != nil {
					i.problem(listener, "rules", err)
				}
				for _, rule := range rules {
					for _, action := range serviceList(rule["Actions"]) {
						serviceRel(listener, "ROUTES_TO", model.String(action, "TargetGroupArn"))
						for _, tg := range serviceList(awsservice.Document(action["ForwardConfig"])["TargetGroups"]) {
							serviceRel(listener, "ROUTES_TO", model.String(tg, "TargetGroupArn"))
						}
					}
				}
			}
			for _, action := range serviceList(row["DefaultActions"]) {
				serviceRel(listener, "ROUTES_TO", model.String(action, "TargetGroupArn"))
			}
		}
		targets, err := i.elbPages(ctx, "DescribeTargetGroups", version, "TargetGroups", url.Values{"LoadBalancerArn": {arn}, "PageSize": {"100"}})
		if err != nil {
			i.problem(lb, "target_groups", err)
		}
		for _, row := range targets {
			targetARN := model.String(row, "TargetGroupArn")
			groups := serviceStrings(row["LoadBalancerArns"])
			if !awsservice.Contains(groups, arn) {
				return "", false, awsservice.ErrEvidence
			}
			tg, e := i.put("ELB_TARGET_GROUP", targetARN, model.String(row, "TargetGroupName"), row)
			if e != nil {
				return "", false, e
			}
			serviceRel(tg, "MEMBER_OF", arn)
			serviceRel(lb, "ROUTES_TO", targetARN)
			i.queryOptional(ctx, tg, "attributes", "elasticloadbalancing", "DescribeTargetGroupAttributes", version, url.Values{"TargetGroupArn": {targetARN}})
			i.queryOptional(ctx, tg, "tags", "elasticloadbalancing", "DescribeTags", version, url.Values{"ResourceArns.member.1": {targetARN}})
			health := i.queryOptional(ctx, tg, "target_health", "elasticloadbalancing", "DescribeTargetHealth", version, url.Values{"TargetGroupArn": {targetARN}})
			for _, h := range serviceList(health["TargetHealthDescriptions"]) {
				target := awsservice.Document(h["Target"])
				id := model.String(target, "Id")
				if strings.HasPrefix(id, "arn:") && !awsservice.BoundARN(i.out.Scope, id) {
					i.problem(tg, "foreign_target_identity", awsservice.ErrEvidence)
					continue
				}
				serviceRel(tg, "TARGET_POTENTIAL_RELATIONSHIP", id)
			}
		}
	}
	return i.next(c, model.String(page, "NextMarker"), 2)
}

func (i *serviceInventory) classicELB(ctx context.Context, lb model.Document, name string) {
	i.set(lb, "target_groups", model.Document{"status": "NOT_APPLICABLE", "reason_code": "CLASSIC_ELB_HAS_NO_TARGET_GROUPS"})
	i.queryOptional(ctx, lb, "attributes", "elasticloadbalancing", "DescribeLoadBalancerAttributes", serviceELBClassic, url.Values{"LoadBalancerName": {name}})
	i.queryOptional(ctx, lb, "tags", "elasticloadbalancing", "DescribeTags", serviceELBClassic, url.Values{"LoadBalancerNames.member.1": {name}})
	i.queryOptional(ctx, lb, "target_health", "elasticloadbalancing", "DescribeInstanceHealth", serviceELBClassic, url.Values{"LoadBalancerName": {name}})
	cfg := awsservice.Document(lb["aws_service_configuration"])
	for _, instance := range serviceList(cfg["Instances"]) {
		serviceRel(lb, "TARGET_POTENTIAL_RELATIONSHIP", model.String(instance, "InstanceId"))
	}
	// Native Classic listeners/policies are retained inside the root description;
	// a listener port is not promoted to a fabricated provider ARN.
}
