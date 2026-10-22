package awsservice

import (
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

func fargateNativeCase() (model.Document, []model.Document, time.Time, time.Time) {
	end := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	start := end.Add(-14 * 24 * time.Hour)
	cluster := "arn:aws:ecs:eu-west-1:111122223333:cluster/orders"
	service := "arn:aws:ecs:eu-west-1:111122223333:service/orders/web"
	definition := "arn:aws:ecs:eu-west-1:111122223333:task-definition/orders:7"
	cfg := model.Document{"collection_complete": true, "launchType": "FARGATE", "clusterArn": cluster, "serviceName": "web", "taskDefinition": definition, "runningCount": 2, "desiredCount": 2, "pendingCount": 0, "deployments": []model.Document{{"rolloutState": "COMPLETED", "taskDefinition": definition, "createdAt": start.Add(-time.Hour).Unix()}}}
	svc := model.Document{"resource_type": "ECS_SERVICE", "account_id": "111122223333", "region": "eu-west-1", "provider_resource_id": service, "aws_service_configuration": cfg}
	resources := []model.Document{svc, {"resource_type": "ECS_CLUSTER", "provider_resource_id": cluster, "aws_service_configuration": model.Document{"collection_complete": true}}}
	for _, id := range []string{"a", "b"} {
		resources = append(resources, model.Document{"resource_type": "ECS_TASK", "provider_resource_id": "arn:aws:ecs:eu-west-1:111122223333:task/orders/" + id, "aws_service_configuration": model.Document{"collection_complete": true, "clusterArn": cluster, "group": "service:web", "taskDefinitionArn": definition, "launchType": "FARGATE", "lastStatus": "RUNNING", "desiredStatus": "RUNNING", "startedAt": start.Add(-time.Hour).Unix(), "cpu": "1024", "memory": "2048"}})
	}
	cfg["task_definition"] = model.Document{"taskDefinitionArn": definition, "cpu": "1024", "memory": "2048", "networkMode": "awsvpc", "requiresCompatibilities": []string{"FARGATE"}, "runtimePlatform": model.Document{"cpuArchitecture": "X86_64", "operatingSystemFamily": "LINUX"}, "containerDefinitions": []model.Document{{"name": "app", "cpu": 128, "memoryReservation": 256}}}
	cfg["fargate_cohort"] = FargateCohort(resources, svc, end.Add(time.Hour))
	return svc, resources, start, end
}

func TestFargateNativeCohortRequiresCompleteLongLivedIdentity(t *testing.T) {
	svc, _, start, end := fargateNativeCase()
	configuration := Document(svc["aws_service_configuration"])
	if tasks, e := FargateHistoricalCohort(svc, configuration, start, end); e != nil || len(tasks) != 2 {
		t.Fatal("native cohort rejected", e)
	}
	for name, change := range map[string]func(model.Document){
		"late task": func(c model.Document) {
			tasks := Rows(Document(c["fargate_cohort"])["tasks"])
			tasks[0]["started_at"] = start.Add(time.Hour).Format(time.RFC3339)
			cohort := Document(c["fargate_cohort"])
			cohort["tasks"], cohort["population_hash"] = tasks, Hash(tasks)
			c["fargate_cohort"] = cohort
		},
		"changed definition": func(c model.Document) { c["taskDefinition"] = "another" },
		"foreign cluster":    func(c model.Document) { c["clusterArn"] = "arn:aws:ecs:eu-west-1:999900001111:cluster/orders" },
		"spot":               func(c model.Document) { c["launchType"] = "FARGATE_SPOT" },
		"incomplete enumeration": func(c model.Document) {
			cohort := Document(c["fargate_cohort"])
			cohort["reason_codes"] = []string{"DENIED"}
			c["fargate_cohort"] = cohort
		},
		"new deployment": func(c model.Document) {
			c["deployments"] = []model.Document{{"rolloutState": "COMPLETED", "taskDefinition": c["taskDefinition"], "createdAt": start.Add(time.Hour).Unix()}}
		},
		"unsupported OS": func(c model.Document) {
			def := Document(c["task_definition"])
			def["runtimePlatform"] = model.Document{"cpuArchitecture": "X86_64", "operatingSystemFamily": "WINDOWS_SERVER_2022_CORE"}
			c["task_definition"] = def
		},
	} {
		t.Run(name, func(t *testing.T) {
			c := Document(configuration)
			change(c)
			if _, e := FargateHistoricalCohort(svc, c, start, end); e == nil {
				t.Fatal("unproved cohort accepted")
			}
		})
	}
}

func TestFargateDeniedTaskEnumerationCannotBecomeComplete(t *testing.T) {
	svc, resources, _, end := fargateNativeCase()
	resources[1]["aws_service_configuration"] = model.Document{"collection_complete": false, "collection_status": model.Document{"tasks": "DENIED"}}
	cohort := FargateCohort(resources, svc, end)
	if len(model.Strings(cohort, "reason_codes")) == 0 {
		t.Fatal("denied enumeration hidden")
	}
}
