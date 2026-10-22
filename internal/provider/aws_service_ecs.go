package provider

import (
	"context"
	"strings"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/awsservice"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

func (i *serviceInventory) ecsIDs(ctx context.Context, action, key string, p model.Document) ([]string, error) {
	out := []string{}
	seen := map[string]bool{}
	for n := 0; n < 32; n++ {
		d, e := i.r.json(ctx, "ecs", action, "/", p)
		if e != nil {
			return out, e
		}
		if _, ok := d[key]; !ok {
			return out, awsservice.ErrEvidence
		}
		ids := serviceStrings(d[key])
		out = append(out, ids...)
		if len(out) > awsservice.MaxRows {
			return out, awsservice.ErrEvidence
		}
		next := model.String(d, "nextToken")
		if next == "" {
			return out, nil
		}
		if seen[next] || len(next) > 4096 {
			return out, awsservice.ErrEvidence
		}
		seen[next] = true
		p["nextToken"] = next
	}
	return out, awsservice.ErrEvidence
}
func (i *serviceInventory) ecs(ctx context.Context, c serviceCursor) (string, bool, error) {
	if c.Phase > 1 {
		return "", false, awsservice.ErrEvidence
	}
	if c.Phase == 1 {
		if i.reg.ScopeMode == "RESOURCE" {
			return i.next(c, "", 2)
		}
		p := model.Document{"maxResults": 5, "status": "ACTIVE"}
		if c.Token != "" {
			p["nextToken"] = c.Token
		}
		d, e := i.r.json(ctx, "ecs", "ListTaskDefinitions", "/", p)
		if e != nil {
			return "", false, e
		}
		if _, ok := d["taskDefinitionArns"]; !ok {
			return "", false, awsservice.ErrEvidence
		}
		for _, arn := range serviceStrings(d["taskDefinitionArns"]) {
			if _, e = i.ecsDefinition(ctx, arn); e != nil {
				i.out.Reasons = append(i.out.Reasons, "ECS_TASK_DEFINITION_UNAVAILABLE")
			}
		}
		return i.next(c, model.String(d, "nextToken"), 2)
	}
	p := model.Document{"maxResults": 5}
	if c.Token != "" {
		p["nextToken"] = c.Token
	}
	page, e := i.r.json(ctx, "ecs", "ListClusters", "/", p)
	if e != nil {
		return "", false, e
	}
	if _, ok := page["clusterArns"]; !ok {
		return "", false, awsservice.ErrEvidence
	}
	for _, arn := range serviceStrings(page["clusterArns"]) {
		if !awsservice.BoundARN(i.out.Scope, arn) {
			return "", false, awsservice.ErrEvidence
		}
		if !i.accepts(arn) {
			continue
		}
		d, e := i.r.json(ctx, "ecs", "DescribeClusters", "/", model.Document{"clusters": []string{arn}, "include": []string{"ATTACHMENTS", "CONFIGURATIONS", "SETTINGS", "STATISTICS", "TAGS"}})
		if e != nil {
			if _, err := i.unavailable("ECS_CLUSTER", arn, arn, "cluster_description", e); err != nil {
				return "", false, err
			}
			continue
		}
		rows := awsservice.Rows(d["clusters"])
		if len(rows) != 1 || model.String(rows[0], "clusterArn") != arn {
			return "", false, awsservice.ErrEvidence
		}
		cluster, e := i.put("ECS_CLUSTER", arn, model.String(rows[0], "clusterName"), rows[0])
		if e != nil {
			return "", false, e
		}
		cluster["state"] = rows[0]["status"]
		if len(awsservice.Rows(d["failures"])) > 0 {
			i.problem(cluster, "cluster_partial_response", awsservice.ErrEvidence)
		}
		providers := serviceStrings(rows[0]["capacityProviders"])
		if len(providers) > 0 {
			pd := i.jsonOptional(ctx, cluster, "capacity_providers", "ecs", "DescribeCapacityProviders", "/", model.Document{"capacityProviders": providers, "include": []string{"TAGS"}})
			for _, v := range awsservice.Rows(pd["capacityProviders"]) {
				a := model.String(v, "capacityProviderArn")
				if awsservice.BoundARN(i.out.Scope, a) {
					child, e := i.put("ECS_CAPACITY_PROVIDER", a, model.String(v, "name"), v)
					if e != nil {
						return "", false, e
					}
					serviceRel(child, "MEMBER_OF", arn)
					asg := awsservice.Document(v["autoScalingGroupProvider"])
					serviceRel(child, "RUNS_ON", model.String(asg, "autoScalingGroupArn"))
				}
			}
		}
		services, err := i.ecsIDs(ctx, "ListServices", "serviceArns", model.Document{"cluster": arn, "maxResults": 10})
		if err != nil {
			i.problem(cluster, "services", err)
		}
		for _, serviceARN := range services {
			if !awsservice.BoundARN(i.out.Scope, serviceARN) {
				return "", false, awsservice.ErrEvidence
			}
			if e = i.ecsService(ctx, cluster, serviceARN); e != nil {
				i.problem(cluster, "service_description", e)
			}
		}
		containers, err := i.ecsIDs(ctx, "ListContainerInstances", "containerInstanceArns", model.Document{"cluster": arn, "maxResults": 100})
		if err != nil {
			i.problem(cluster, "container_instances", err)
		}
		for first := 0; first < len(containers); first += 100 {
			last := min(first+100, len(containers))
			v, e := i.r.json(ctx, "ecs", "DescribeContainerInstances", "/", model.Document{"cluster": arn, "containerInstances": containers[first:last], "include": []string{"TAGS", "CONTAINER_INSTANCE_HEALTH"}})
			if e != nil {
				i.problem(cluster, "container_instance_descriptions", e)
				break
			}
			for _, row := range awsservice.Rows(v["containerInstances"]) {
				child, e := i.put("ECS_CONTAINER_INSTANCE", model.String(row, "containerInstanceArn"), model.String(row, "ec2InstanceId"), row)
				if e != nil {
					return "", false, e
				}
				serviceRel(child, "MEMBER_OF", arn)
				if native := model.String(row, "ec2InstanceId"); native != "" {
					serviceRel(child, "RUNS_ON", native)
				}
			}
			if len(awsservice.Rows(v["failures"])) > 0 {
				i.problem(cluster, "container_instance_partial_response", awsservice.ErrEvidence)
			}
		}
		tasks, err := i.ecsIDs(ctx, "ListTasks", "taskArns", model.Document{"cluster": arn, "desiredStatus": "RUNNING", "maxResults": 100})
		if err != nil {
			i.problem(cluster, "tasks", err)
		}
		for first := 0; first < len(tasks); first += 100 {
			last := min(first+100, len(tasks))
			v, e := i.r.json(ctx, "ecs", "DescribeTasks", "/", model.Document{"cluster": arn, "tasks": tasks[first:last], "include": []string{"TAGS"}})
			if e != nil {
				i.problem(cluster, "task_descriptions", e)
				break
			}
			for _, row := range awsservice.Rows(v["tasks"]) {
				taskARN := model.String(row, "taskArn")
				if model.String(row, "clusterArn") != arn {
					return "", false, awsservice.ErrEvidence
				}
				child, e := i.put("ECS_TASK", taskARN, taskARN, row)
				if e != nil {
					return "", false, e
				}
				child["state"] = row["lastStatus"]
				i.set(child, "economic_role", "EPHEMERAL_PLACEMENT_OBSERVATION_NOT_ADDITIONAL_SERVICE_COST")
				serviceRel(child, "MEMBER_OF", arn)
				serviceRel(child, "USES_TASK_DEFINITION", model.String(row, "taskDefinitionArn"))
				serviceRel(child, "RUNS_ON", model.String(row, "containerInstanceArn"))
				if group := model.String(row, "group"); strings.HasPrefix(group, "service:") {
					for _, svc := range i.out.Resources {
						cfg := awsservice.Document(svc["aws_service_configuration"])
						if svc["resource_type"] == "ECS_SERVICE" && cfg["serviceName"] == strings.TrimPrefix(group, "service:") && cfg["clusterArn"] == arn {
							serviceRel(child, "MEMBER_OF", model.String(svc, "provider_resource_id"))
						}
					}
				}
				if def := model.String(row, "taskDefinitionArn"); def != "" {
					if _, e = i.ecsDefinition(ctx, def); e != nil {
						i.problem(child, "task_definition", e)
					}
				}
			}
			if len(awsservice.Rows(v["failures"])) > 0 {
				i.problem(cluster, "task_partial_response", awsservice.ErrEvidence)
			}
		}
	}
	return i.next(c, model.String(page, "nextToken"), 2)
}
func (i *serviceInventory) ecsDefinition(ctx context.Context, arn string) (model.Document, error) {
	if n, ok := i.seen["ECS_TASK_DEFINITION\x00"+arn]; ok {
		return i.out.Resources[n], nil
	}
	if !awsservice.BoundARN(i.out.Scope, arn) {
		return nil, awsservice.ErrEvidence
	}
	d, e := i.r.json(ctx, "ecs", "DescribeTaskDefinition", "/", model.Document{"taskDefinition": arn, "include": []string{"TAGS"}})
	if e != nil {
		return nil, e
	}
	cfg := awsservice.Document(d["taskDefinition"])
	if model.String(cfg, "taskDefinitionArn") != arn {
		return nil, awsservice.ErrEvidence
	}
	cfg["tags"] = d["tags"]
	cfg["cpu_unit"] = "ECS_CPU_UNIT_1024_PER_VCPU"
	cfg["memory_unit"] = "MiB"
	cfg["ephemeral_storage_unit"] = "GiB"
	return i.put("ECS_TASK_DEFINITION", arn, model.String(cfg, "family"), cfg)
}
func (i *serviceInventory) ecsService(ctx context.Context, cluster model.Document, arn string) error {
	clusterARN := model.String(cluster, "provider_resource_id")
	d, e := i.r.json(ctx, "ecs", "DescribeServices", "/", model.Document{"cluster": clusterARN, "services": []string{arn}, "include": []string{"TAGS"}})
	if e != nil {
		return e
	}
	rows := awsservice.Rows(d["services"])
	if len(rows) != 1 || model.String(rows[0], "serviceArn") != arn || model.String(rows[0], "clusterArn") != clusterARN {
		return awsservice.ErrEvidence
	}
	cfg := rows[0]
	service, e := i.put("ECS_SERVICE", arn, model.String(cfg, "serviceName"), cfg)
	if e != nil {
		return e
	}
	service["state"] = cfg["status"]
	serviceRel(service, "MEMBER_OF", clusterARN)
	serviceRel(service, "USES_TASK_DEFINITION", model.String(cfg, "taskDefinition"))
	i.set(service, "economic_role", "STABLE_SERVICE")
	for _, lb := range awsservice.Rows(cfg["loadBalancers"]) {
		serviceRel(service, "ROUTES_TO", model.String(lb, "targetGroupArn"))
	}
	if def := model.String(cfg, "taskDefinition"); def != "" {
		if _, e = i.ecsDefinition(ctx, def); e != nil {
			i.problem(service, "task_definition", e)
		}
	}
	i.scaling(ctx, service, "ecs", "service/"+strings.TrimPrefix(clusterARN, "arn:aws:ecs:"+i.out.Scope.Region+":"+i.out.Scope.AccountID+":cluster/")+"/"+model.String(cfg, "serviceName"))
	if len(awsservice.Rows(d["failures"])) > 0 {
		i.problem(service, "service_partial_response", awsservice.ErrEvidence)
	}
	return nil
}
