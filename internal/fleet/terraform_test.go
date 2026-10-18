package fleet

import (
	"encoding/json"
	"testing"
	"time"
)

func terraformFixture(p FleetPlanV4, c ChildPlan) map[string]any {
	asg := func(id string, count int, version string) map[string]any {
		return map[string]any{"id": id, "name": "asg-" + id, "desired_capacity": count, "min_size": count, "max_size": count, "launch_template": []any{map[string]any{"id": "lt-" + id, "version": version}}, "suspended_processes": []string{"ReplaceUnhealthy", "AZRebalance", "InstanceRefresh", "ScheduledActions", "AlarmNotification"}, "instance_refresh": []any{}, "mixed_instances_policy": []any{}, "capacity_rebalance": false}
	}
	traffic := func(percent int) map[string]any {
		return map[string]any{"action": []any{map[string]any{"type": "forward", "forward": []any{map[string]any{"target_group": []any{map[string]any{"arn": p.Traffic.OldTargetGroupARN, "weight": 100 - percent}, map[string]any{"arn": p.Traffic.CandidateTargetGroupARN, "weight": percent}}}}}}}
	}
	changes, resources := []any{}, []any{}
	add := func(address, kind string, before, after map[string]any) {
		action := "no-op"
		if !sameJSON(before, after) {
			action = "update"
		}
		changes = append(changes, map[string]any{"address": address, "type": kind, "provider_name": "registry.terraform.io/hashicorp/aws", "mode": "managed", "change": map[string]any{"actions": []string{action}, "before": before, "after": after, "after_unknown": map[string]any{}}})
		resources = append(resources, map[string]any{"address": address, "type": kind, "mode": "managed", "values": after})
	}
	add(p.Old.ASGAddress, "aws_autoscaling_group", asg("blue", c.Transition.OldBefore, "1"), asg("blue", c.Transition.OldAfter, "1"))
	add(p.Candidate.ASGAddress, "aws_autoscaling_group", asg("green", c.Transition.CandidateBefore, "2"), asg("green", c.Transition.CandidateAfter, "2"))
	add(p.Traffic.Address, "aws_lb_listener_rule", traffic(c.Transition.TrafficBefore), traffic(c.Transition.TrafficAfter))
	add(p.Candidate.LaunchTemplateAddress, "aws_launch_template", map[string]any{"instance_type": p.Candidate.InstanceType, "latest_version": 2}, map[string]any{"instance_type": p.Candidate.InstanceType, "latest_version": 2})
	resources = append(resources, map[string]any{"address": "data.aws_caller_identity.target", "type": "aws_caller_identity", "mode": "data", "values": map[string]any{"account_id": p.Binding.AccountID}})
	return map[string]any{"format_version": "1.2", "terraform_version": p.IaC.TerraformVersion, "complete": true, "errored": false, "variables": map[string]any{"expected_account_id": map[string]any{"value": p.Binding.AccountID}, "region": map[string]any{"value": p.Binding.Region}}, "configuration": map[string]any{"provider_config": map[string]any{"aws": map[string]any{"name": "aws", "full_name": "registry.terraform.io/hashicorp/aws", "expressions": map[string]any{"region": map[string]any{"references": []string{"var.region"}}, "allowed_account_ids": map[string]any{"references": []string{"var.expected_account_id"}}}}}}, "planned_values": map[string]any{"root_module": map[string]any{"resources": resources}}, "resource_changes": changes, "resource_drift": []any{}}
}
func terraformChild(p FleetPlanV4, stage int, now time.Time) ChildPlan {
	c := fixtureChild(p, stage, now)
	if stage == 0 {
		c.Transition = Transition{20, 20, 0, 0, 0, 0, 0, 0}
		return c
	}
	c.Changes = []AllowedChange{{Address: p.Candidate.ASGAddress, Type: "aws_autoscaling_group", Action: "update", Fields: []FieldChange{{"/desired_capacity", CanonicalJSON(0), CanonicalJSON(2)}, {"/min_size", CanonicalJSON(0), CanonicalJSON(2)}, {"/max_size", CanonicalJSON(0), CanonicalJSON(2)}}, ComputedPaths: []string{}}}
	return c
}
func reviewFixture(t *testing.T, plan map[string]any, c ChildPlan, p FleetPlanV4, now time.Time) (PlanReview, error) {
	t.Helper()
	raw, _ := json.Marshal(plan)
	c.PlanJSONSHA256 = BytesDigest(raw)
	return ValidateTerraformPlan(raw, []byte("binary-plan"), c, p, c.IaC, now)
}
func TestFleetExactTerraformPlanAndInitialNoopPreserveScopeAndArtifactDigests(t *testing.T) {
	now := time.Now().UTC()
	p := fixturePlan(now)
	c := terraformChild(p, 1, now)
	plan := terraformFixture(p, c)
	review, e := reviewFixture(t, plan, c, p, now)
	if e != nil || review.Changes != 1 || review.NoOp {
		t.Fatal(review, e)
	}
	c = terraformChild(p, 0, now)
	plan = terraformFixture(p, c)
	review, e = reviewFixture(t, plan, c, p, now)
	if e != nil || !review.NoOp || review.Changes != 0 {
		t.Fatal("zero candidate preparation was not noop", review, e)
	}
	raw, _ := json.Marshal(plan)
	c.PlanJSONSHA256 = BytesDigest(raw)
	_, e = ValidateTerraformPlan(raw, []byte("different-binary"), c, p, c.IaC, now)
	requireRejected(t, e)
	provenance := c.IaC
	provenance.StateSerial++
	_, e = ValidateTerraformPlan(raw, []byte("binary-plan"), c, p, provenance, now)
	requireRejected(t, e)
}
func TestFleetTerraformRejectsUnknownUnrelatedDestructiveAndHiddenCapacityChanges(t *testing.T) {
	now := time.Now().UTC()
	p := fixturePlan(now)
	base := terraformChild(p, 1, now)
	tests := map[string]func(map[string]any, *ChildPlan){
		"wrong account": func(m map[string]any, c *ChildPlan) {
			object(object(m["variables"])["expected_account_id"])["value"] = "999988887777"
		},
		"provider lacks account guard": func(m map[string]any, c *ChildPlan) {
			object(object(object(object(m["configuration"])["provider_config"])["aws"])["expressions"])["allowed_account_ids"] = map[string]any{}
		},
		"delete volume": func(m map[string]any, c *ChildPlan) {
			m["resource_changes"] = append(array(m["resource_changes"]), map[string]any{"address": "aws_ebs_volume.data", "type": "aws_ebs_volume", "mode": "managed", "change": map[string]any{"actions": []string{"delete"}}})
		},
		"replace ASG": func(m map[string]any, c *ChildPlan) {
			object(object(array(m["resource_changes"])[1])["change"])["actions"] = []string{"delete", "create"}
		},
		"unknown desired": func(m map[string]any, c *ChildPlan) {
			object(object(array(m["resource_changes"])[1])["change"])["after_unknown"] = map[string]any{"desired_capacity": true}
		},
		"unreviewed drift": func(m map[string]any, c *ChildPlan) {
			m["resource_drift"] = []any{map[string]any{"change": map[string]any{"actions": []string{"update"}}}}
		},
		"autoscaling policy exists": func(m map[string]any, c *ChildPlan) {
			root := object(object(m["planned_values"])["root_module"])
			root["resources"] = append(array(root["resources"]), map[string]any{"address": "aws_autoscaling_policy.independent", "type": "aws_autoscaling_policy", "mode": "managed", "values": map[string]any{}})
		},
		"native replacement enabled": func(m map[string]any, c *ChildPlan) {
			r := array(object(object(m["planned_values"])["root_module"])["resources"])
			object(object(r[1])["values"])["suspended_processes"] = []string{}
		},
		"latest launch template": func(m map[string]any, c *ChildPlan) {
			r := array(object(object(m["planned_values"])["root_module"])["resources"])
			object(array(object(object(r[1])["values"])["launch_template"])[0])["version"] = "$Latest"
		},
		"unknown zero-weight target": func(m map[string]any, c *ChildPlan) {
			r := array(object(object(m["planned_values"])["root_module"])["resources"])
			g := array(object(array(object(array(object(object(r[2])["values"])["action"])[0])["forward"])[0])["target_group"])
			object(g[1])["arn"] = "arn:aws:elasticloadbalancing:eu-west-1:111122223333:targetgroup/unknown/id"
		},
		"hidden oversized prior capacity": func(m map[string]any, c *ChildPlan) {
			before := object(object(object(array(m["resource_changes"])[1])["change"])["before"])
			for _, k := range []string{"desired_capacity", "min_size", "max_size"} {
				before[k] = 7
			}
			for i := range c.Changes[0].Fields {
				c.Changes[0].Fields[i].Before = CanonicalJSON(7)
			}
		},
		"changed state lineage":      func(m map[string]any, c *ChildPlan) { c.IaC.StateLineage = "foreign-state" },
		"expected field wrong after": func(m map[string]any, c *ChildPlan) { c.Changes[0].Fields[0].After = CanonicalJSON(3) },
		"incomplete plan":            func(m map[string]any, c *ChildPlan) { m["complete"] = false },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			c := clone(base)
			m := terraformFixture(p, c)
			mutate(m, &c)
			_, e := reviewFixture(t, m, c, p, now)
			requireRejected(t, e)
		})
	}
}

func TestFleetTrafficTypeSetReorderingUsesExactARNIdentityAndRejectsUnrelatedChanges(t *testing.T) {
	now := time.Now().UTC()
	p := fixturePlan(now)
	c := fixtureChild(p, 1, now)
	c.Transition = Transition{OldBefore: 20, OldAfter: 20, CandidateBefore: 2, CandidateAfter: 2, TrafficAfter: 10}
	c.Changes = []AllowedChange{{Address: p.Traffic.Address, Type: "aws_lb_listener_rule", Action: "update", Fields: []FieldChange{{Path: "/action/0/forward/0/target_group/0/weight", Before: CanonicalJSON(100), After: CanonicalJSON(90)}, {Path: "/action/0/forward/0/target_group/1/weight", Before: CanonicalJSON(0), After: CanonicalJSON(10)}}}}
	m := terraformFixture(p, c)
	change := object(object(array(m["resource_changes"])[2])["change"])
	groups := array(object(array(object(array(object(change["after"])["action"])[0])["forward"])[0])["target_group"])
	groups[0], groups[1] = groups[1], groups[0]
	if _, e := reviewFixture(t, m, c, p, now); e != nil {
		t.Fatal("legitimate TypeSet weight reorder rejected", e)
	}
	wrong := clone(m)
	changed := object(object(array(wrong["resource_changes"])[2])["change"])
	targets := array(object(array(object(array(object(changed["after"])["action"])[0])["forward"])[0])["target_group"])
	object(targets[0])["arn"] = "arn:aws:elasticloadbalancing:eu-west-1:111122223333:targetgroup/unapproved/id"
	if _, e := reviewFixture(t, wrong, c, p, now); e == nil {
		t.Fatal("changed ARN set accepted by canonicalizer")
	}
	unrelated := clone(m)
	other := object(object(array(unrelated["resource_changes"])[2])["change"])
	object(other["after"])["priority"] = 999
	if _, e := reviewFixture(t, unrelated, c, p, now); e == nil {
		t.Fatal("unrelated listener change accepted")
	}
}
