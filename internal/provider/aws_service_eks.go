package provider

import (
	"context"
	"net/url"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/awsservice"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

func (i *serviceInventory) eks(ctx context.Context, c serviceCursor) (string, bool, error) {
	if c.Phase != 0 {
		return "", false, awsservice.ErrEvidence
	}
	q := url.Values{"maxResults": {"5"}}
	if c.Token != "" {
		q.Set("nextToken", c.Token)
	}
	page, e := i.r.json(ctx, "eks", "ListClusters", "/clusters?"+q.Encode(), nil)
	if e != nil {
		return "", false, e
	}
	if _, ok := page["clusters"]; !ok {
		return "", false, awsservice.ErrEvidence
	}
	for _, name := range serviceStrings(page["clusters"]) {
		arn := "arn:aws:eks:" + i.out.Scope.Region + ":" + i.out.Scope.AccountID + ":cluster/" + name
		if !i.accepts(arn) {
			continue
		}
		base := "/clusters/" + url.PathEscape(name)
		v, e := i.r.json(ctx, "eks", "DescribeCluster", base, nil)
		if e != nil {
			if _, err := i.unavailable("EKS_CLUSTER", arn, name, "cluster_description", e); err != nil {
				return "", false, err
			}
			continue
		}
		cfg := awsservice.Document(v["cluster"])
		if model.String(cfg, "arn") != arn {
			return "", false, awsservice.ErrEvidence
		}
		cluster, e := i.put("EKS_CLUSTER", arn, name, cfg)
		if e != nil {
			return "", false, e
		}
		cluster["state"] = cfg["status"]
		i.set(cluster, "kubernetes_association_status", "UNBOUND_UNTIL_OBSERVED_KUBE_SYSTEM_UID_AND_PROVIDER_IDS")
		i.set(cluster, "kubernetes_optimiser", "EXISTING_SHARED_KUBERNETES_ONLY")
		for _, spec := range []struct{ list, describe, path, listKey, resultKey, kind, arnKey string }{{"ListNodegroups", "DescribeNodegroup", "node-groups", "nodegroups", "nodegroup", "EKS_NODE_GROUP", "nodegroupArn"}, {"ListFargateProfiles", "DescribeFargateProfile", "fargate-profiles", "fargateProfileNames", "fargateProfile", "EKS_FARGATE_PROFILE", "fargateProfileArn"}, {"ListAddons", "DescribeAddon", "addons", "addons", "addon", "EKS_ADDON", "addonArn"}} {
			names, err := i.eksNames(ctx, spec.list, base+"/"+spec.path, spec.listKey)
			if err != nil {
				i.problem(cluster, spec.listKey, err)
			}
			for _, childName := range names {
				d, e := i.r.json(ctx, "eks", spec.describe, base+"/"+spec.path+"/"+url.PathEscape(childName), nil)
				if e != nil {
					i.problem(cluster, spec.path+"_description", e)
					continue
				}
				native := awsservice.Document(d[spec.resultKey])
				if model.String(native, "clusterName") != "" && model.String(native, "clusterName") != name {
					return "", false, awsservice.ErrEvidence
				}
				child, e := i.put(spec.kind, model.String(native, spec.arnKey), childName, native)
				if e != nil {
					return "", false, e
				}
				serviceRel(child, "MEMBER_OF", arn)
				if spec.kind == "EKS_NODE_GROUP" {
					i.set(child, "economic_role", "EC2_CAPACITY_RELATIONSHIP_NOT_ADDITIONAL_HOST_CHARGE")
					i.set(child, "instance_type_absence_semantics", "UNKNOWN_WHEN_LAUNCH_TEMPLATE_SUPPLIES_CONFIGURATION")
					for _, asg := range awsservice.Rows(awsservice.Document(native["resources"])["autoScalingGroups"]) {
						i.set(child, "native_auto_scaling_group_names", append(serviceStrings(awsservice.Document(child["aws_service_configuration"])["native_auto_scaling_group_names"]), model.String(asg, "name")))
					}
				}
			}
		}
	}
	return i.next(c, model.String(page, "nextToken"), 1)
}
func (i *serviceInventory) eksNames(ctx context.Context, action, path, key string) ([]string, error) {
	out := []string{}
	tokens := map[string]bool{}
	q := url.Values{"maxResults": {"100"}}
	for p := 0; p < 32; p++ {
		v, e := i.r.json(ctx, "eks", action, path+"?"+q.Encode(), nil)
		if e != nil {
			return out, e
		}
		if _, ok := v[key]; !ok {
			return out, awsservice.ErrEvidence
		}
		out = append(out, serviceStrings(v[key])...)
		if len(out) > awsservice.MaxRows {
			return out, awsservice.ErrEvidence
		}
		next := model.String(v, "nextToken")
		if next == "" {
			return out, nil
		}
		if len(next) > 4096 || tokens[next] {
			return out, awsservice.ErrEvidence
		}
		tokens[next] = true
		q.Set("nextToken", next)
	}
	return out, awsservice.ErrEvidence
}
