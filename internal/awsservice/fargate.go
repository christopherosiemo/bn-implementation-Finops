package awsservice

import (
	"fmt"
	"math/big"
	"sort"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

const FargateCohortVersion = "ECS_FARGATE_SERVICE_COHORT_V1"

// NativeTime preserves explicit AWS JSON epoch timestamps or RFC3339 strings.
// An absent or invalid timestamp never becomes evidence of an old task.
func NativeTime(value any) (time.Time, error) {
	if s, ok := value.(string); ok {
		if at, e := time.Parse(time.RFC3339Nano, s); e == nil {
			return at.UTC(), nil
		}
	}
	n, ok := new(big.Rat).SetString(fmt.Sprint(value))
	if !ok || n.Sign() <= 0 {
		return time.Time{}, ErrEvidence
	}
	n.Mul(n, big.NewRat(1000000000, 1))
	if !n.IsInt() || !n.Num().IsInt64() {
		return time.Time{}, ErrEvidence
	}
	return time.Unix(0, n.Num().Int64()).UTC(), nil
}

// FargateCohort captures only this complete native point collection. Historical
// membership still requires the AWS-managed tags on each authenticated CUR row.
func FargateCohort(resources []model.Document, service model.Document, observed time.Time) model.Document {
	cfg := Document(service["aws_service_configuration"])
	out := model.Document{"schema_version": FargateCohortVersion, "account_id": service["account_id"], "region": service["region"], "service_arn": service["provider_resource_id"], "cluster_arn": cfg["clusterArn"], "service_name": cfg["serviceName"], "task_definition_arn": cfg["taskDefinition"], "observed_at": observed.UTC().Format(time.RFC3339Nano), "tasks": []model.Document{}, "reason_codes": []string{}}
	reasons := []string{}
	if cfg["collection_complete"] != true || cfg["launchType"] != "FARGATE" {
		reasons = append(reasons, "ECS_COMPLETE_ON_DEMAND_FARGATE_SERVICE_REQUIRED")
	}
	clusterKnown := false
	tasks := []model.Document{}
	for _, resource := range resources {
		c := Document(resource["aws_service_configuration"])
		if resource["resource_type"] == "ECS_CLUSTER" && resource["provider_resource_id"] == cfg["clusterArn"] {
			clusterKnown = c["collection_complete"] == true
		}
		if resource["resource_type"] != "ECS_TASK" || c["clusterArn"] != cfg["clusterArn"] || c["group"] != "service:"+model.String(cfg, "serviceName") {
			continue
		}
		at, e := NativeTime(c["startedAt"])
		if e != nil || at.After(observed) || c["collection_complete"] != true || c["launchType"] != "FARGATE" || c["lastStatus"] != "RUNNING" || c["desiredStatus"] != "RUNNING" || c["taskDefinitionArn"] != cfg["taskDefinition"] || c["capacityProviderName"] != nil && c["capacityProviderName"] != "FARGATE" {
			reasons = append(reasons, "ECS_NATIVE_TASK_COHORT_INCOMPLETE")
			continue
		}
		tasks = append(tasks, model.Document{"task_arn": resource["provider_resource_id"], "cluster_arn": c["clusterArn"], "group": c["group"], "task_definition_arn": c["taskDefinitionArn"], "launch_type": c["launchType"], "capacity_provider_name": c["capacityProviderName"], "started_at": at.Format(time.RFC3339Nano), "last_status": c["lastStatus"], "desired_status": c["desiredStatus"], "cpu": c["cpu"], "memory": c["memory"]})
	}
	if !clusterKnown {
		reasons = append(reasons, "ECS_COMPLETE_NATIVE_CLUSTER_TASK_ENUMERATION_REQUIRED")
	}
	if len(tasks) == 0 || int64(len(tasks)) != model.Number(cfg, "runningCount") || model.Number(cfg, "desiredCount") != int64(len(tasks)) || model.Number(cfg, "pendingCount") != 0 {
		reasons = append(reasons, "ECS_NATIVE_TASK_POPULATION_UNRESOLVED")
	}
	sort.Slice(tasks, func(i, j int) bool { return model.String(tasks[i], "task_arn") < model.String(tasks[j], "task_arn") })
	out["tasks"], out["reason_codes"] = tasks, reasons
	out["population_hash"] = Hash(tasks)
	return out
}

// FargateHistoricalCohort is deliberately limited to unchanged, long-lived
// Linux/x86 tasks spanning the complete measurement window. It makes no claim
// about replaced or stopped tasks absent from this native point read.
func FargateHistoricalCohort(binding, configuration model.Document, start, end time.Time) (map[string]model.Document, error) {
	c := Document(configuration["fargate_cohort"])
	definition := Document(configuration["task_definition"])
	runtime := Document(definition["runtimePlatform"])
	if c["schema_version"] != FargateCohortVersion || c["account_id"] != binding["account_id"] || c["region"] != binding["region"] || c["service_arn"] != binding["provider_resource_id"] || c["cluster_arn"] != configuration["clusterArn"] || c["service_name"] != configuration["serviceName"] || c["task_definition_arn"] != configuration["taskDefinition"] || definition["taskDefinitionArn"] != configuration["taskDefinition"] || configuration["launchType"] != "FARGATE" || runtime["cpuArchitecture"] != "X86_64" || runtime["operatingSystemFamily"] != "LINUX" || definition["networkMode"] != "awsvpc" || !Contains(model.Strings(definition, "requiresCompatibilities"), "FARGATE") || len(model.Strings(c, "reason_codes")) != 0 || !end.After(start) {
		return nil, ErrEvidence
	}
	rows := Rows(c["tasks"])
	if len(Rows(definition["containerDefinitions"])) == 0 {
		return nil, ErrEvidence
	}
	if len(rows) == 0 || len(rows) > MaxRows || c["population_hash"] != Hash(rows) || int64(len(rows)) != model.Number(configuration, "runningCount") || model.Number(configuration, "desiredCount") != int64(len(rows)) || model.Number(configuration, "pendingCount") != 0 {
		return nil, ErrEvidence
	}
	deployments := Rows(configuration["deployments"])
	if len(deployments) != 1 || deployments[0]["rolloutState"] != "COMPLETED" || deployments[0]["taskDefinition"] != configuration["taskDefinition"] {
		return nil, ErrEvidence
	}
	created, err := NativeTime(deployments[0]["createdAt"])
	if err != nil || created.After(start) {
		return nil, ErrEvidence
	}
	result := map[string]model.Document{}
	scope := Scope{AccountID: model.String(binding, "account_id"), Region: model.String(binding, "region")}
	prefix := "arn:aws:ecs:" + scope.Region + ":" + scope.AccountID + ":task/" + strings.TrimPrefix(model.String(c, "cluster_arn"), "arn:aws:ecs:"+scope.Region+":"+scope.AccountID+":cluster/") + "/"
	for _, task := range rows {
		id := model.String(task, "task_arn")
		at, e := NativeTime(task["started_at"])
		if e != nil || at.After(start) || !strings.HasPrefix(id, prefix) || strings.TrimPrefix(id, prefix) == "" || strings.Contains(strings.TrimPrefix(id, prefix), "/") || result[id] != nil || task["cluster_arn"] != c["cluster_arn"] || task["group"] != "service:"+model.String(c, "service_name") || task["task_definition_arn"] != c["task_definition_arn"] || task["launch_type"] != "FARGATE" || task["last_status"] != "RUNNING" || task["desired_status"] != "RUNNING" || fmt.Sprint(task["cpu"]) != fmt.Sprint(definition["cpu"]) || fmt.Sprint(task["memory"]) != fmt.Sprint(definition["memory"]) {
			return nil, ErrEvidence
		}
		result[id] = task
	}
	return result, nil
}
