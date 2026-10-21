package provider

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/awsservice"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

type serviceTestTransport struct {
	handle   func(*http.Request, model.Document, url.Values) (string, int)
	calls    []string
	account  string
	throttle int
}

func (s *serviceTestTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	raw, _ := io.ReadAll(req.Body)
	p := model.Document{}
	_ = json.Unmarshal(raw, &p)
	v, _ := url.ParseQuery(string(raw))
	action := req.Header.Get("X-Amz-Target")
	if action == "" {
		action = v.Get("Action")
	}
	s.calls = append(s.calls, action+req.URL.Path)
	body := ""
	status := 200
	if strings.HasPrefix(req.URL.Host, "sts.") {
		account := s.account
		if account == "" {
			account = "111122223333"
		}
		body = `<GetCallerIdentityResponse><GetCallerIdentityResult><Account>` + account + `</Account><Arn>arn:aws:sts::` + account + `:assumed-role/read/collector</Arn><UserId>local-read:collector</UserId></GetCallerIdentityResult></GetCallerIdentityResponse>`
	} else if s.throttle > 0 {
		s.throttle--
		body = `{"__type":"ThrottlingException","message":"private"}`
		status = 429
	} else {
		body, status = s.handle(req, p, v)
	}
	return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
}
func serviceTestAWS(tr *serviceTestTransport) *AWS {
	return &AWS{cfg: aws.Config{Region: "eu-west-1", Credentials: credentials.NewStaticCredentialsProvider("LOCAL_ONLY", "LOCAL_ONLY", "")}, client: &http.Client{Transport: tr}}
}
func serviceTestRegistration() awsservice.Registration {
	return awsservice.Registration{ID: "local-test", TenantID: "tenant-a", AccountID: "111122223333", Region: "eu-west-1", ReadRoleBindingID: "approved", Version: 1, Enabled: true, ServiceFamilies: awsservice.Families, ScopeMode: "ACCOUNT"}
}
func serviceTestJSON(d model.Document) (string, int) { b, _ := json.Marshal(d); return string(b), 200 }
func serviceTestXML(action string, d string) (string, int) {
	return "<" + action + "Response><" + action + "Result>" + d + "</" + action + "Result></" + action + "Response>", 200
}

func TestAWSServiceECSNativeSanitizationPlacementAndPagination(t *testing.T) {
	cluster := "arn:aws:ecs:eu-west-1:111122223333:cluster/cluster"
	service := "arn:aws:ecs:eu-west-1:111122223333:service/cluster/service"
	definition := "arn:aws:ecs:eu-west-1:111122223333:task-definition/api:7"
	task := "arn:aws:ecs:eu-west-1:111122223333:task/cluster/task"
	tr := &serviceTestTransport{throttle: 1}
	tr.handle = func(req *http.Request, p model.Document, v url.Values) (string, int) {
		action := req.Header.Get("X-Amz-Target")
		switch {
		case strings.HasSuffix(action, ".ListClusters"):
			if p["nextToken"] == "page-two" {
				return serviceTestJSON(model.Document{"clusterArns": []string{}})
			}
			return serviceTestJSON(model.Document{"clusterArns": []string{cluster}, "nextToken": "page-two"})
		case strings.HasSuffix(action, ".DescribeClusters"):
			return serviceTestJSON(model.Document{"clusters": []model.Document{{"clusterArn": cluster, "clusterName": "cluster", "capacityProviders": []string{"FARGATE"}}}, "failures": []any{}})
		case strings.HasSuffix(action, ".DescribeCapacityProviders"):
			return serviceTestJSON(model.Document{"capacityProviders": []model.Document{{"name": "FARGATE"}}})
		case strings.HasSuffix(action, ".ListServices"):
			return serviceTestJSON(model.Document{"serviceArns": []string{service}})
		case strings.HasSuffix(action, ".DescribeServices"):
			return serviceTestJSON(model.Document{"services": []model.Document{{"serviceArn": service, "clusterArn": cluster, "serviceName": "service", "taskDefinition": definition, "launchType": "FARGATE", "desiredCount": 2, "runningCount": 2, "pendingCount": 0}}})
		case strings.HasSuffix(action, ".DescribeTaskDefinition"):
			return serviceTestJSON(model.Document{"taskDefinition": model.Document{"taskDefinitionArn": definition, "family": "api", "revision": 7, "cpu": "1024", "memory": "2048", "containerDefinitions": []model.Document{{"name": "api", "environment": []model.Document{{"name": "PASSWORD", "value": "DO_NOT_ARCHIVE_ENV_SECRET"}}, "command": []string{"DO_NOT_ARCHIVE_COMMAND_SECRET"}, "secrets": []model.Document{{"valueFrom": "DO_NOT_ARCHIVE_SECRET_REF"}}, "logConfiguration": model.Document{"options": model.Document{"token": "DO_NOT_ARCHIVE_LOG_SECRET"}}}}}})
		case strings.HasSuffix(action, ".ListContainerInstances"):
			return serviceTestJSON(model.Document{"containerInstanceArns": []string{}})
		case strings.HasSuffix(action, ".ListTasks"):
			if p["desiredStatus"] != "RUNNING" {
				t.Fatal("incorrect pending-task query")
			}
			return serviceTestJSON(model.Document{"taskArns": []string{task}})
		case strings.HasSuffix(action, ".DescribeTasks"):
			return serviceTestJSON(model.Document{"tasks": []model.Document{{"taskArn": task, "clusterArn": cluster, "taskDefinitionArn": definition, "group": "service:service", "lastStatus": "RUNNING", "launchType": "FARGATE", "overrides": model.Document{"containerOverrides": []model.Document{{"environment": []model.Document{{"value": "DO_NOT_ARCHIVE_OVERRIDE_SECRET"}}}}}}}})
		case strings.HasSuffix(action, ".DescribeScalableTargets"):
			return serviceTestJSON(model.Document{"ScalableTargets": []any{}})
		case strings.HasSuffix(action, ".DescribeScalingPolicies"):
			return serviceTestJSON(model.Document{"ScalingPolicies": []any{}})
		case strings.HasSuffix(action, ".DescribeScheduledActions"):
			return serviceTestJSON(model.Document{"ScheduledActions": []any{}})
		case strings.HasSuffix(action, ".ListTaskDefinitions"):
			return serviceTestJSON(model.Document{"taskDefinitionArns": []string{definition}})
		}
		t.Fatalf("unexpected metadata request %s", action)
		return "", 500
	}
	a := serviceTestAWS(tr)
	reg := serviceTestRegistration()
	first, e := a.ServiceInventory(context.Background(), reg, "ECS", "")
	if e != nil {
		t.Fatal(e)
	}
	if first.NextCursor == "" || first.Complete || len(first.Resources) != 4 {
		t.Fatalf("missing page/native resources: %+v", first)
	}
	if strings.Contains(string(first.Raw), "DO_NOT_ARCHIVE") {
		t.Fatal("secret reached retained archive")
	}
	for _, r := range first.Resources {
		if r["resource_type"] == "ECS_TASK" && len(awsservice.Rows(r["provider_relationships"])) < 3 {
			t.Fatal("task lost evidenced topology")
		}
	}
	second, e := a.ServiceInventory(context.Background(), reg, "ECS", first.NextCursor)
	if e != nil || second.NextCursor == "" {
		t.Fatalf("resume failed: %v", e)
	}
	last, e := a.ServiceInventory(context.Background(), reg, "ECS", second.NextCursor)
	if e != nil || !last.Complete {
		t.Fatalf("definition revision phase failed %v %+v", e, last)
	}
	reg.Version++
	if _, e = a.ServiceInventory(context.Background(), reg, "ECS", first.NextCursor); e == nil {
		t.Fatal("old registration cursor accepted")
	}
}

func TestAWSServiceEKSAndDynamoDBDeniedReadsPreserveInventory(t *testing.T) {
	for _, family := range []string{"EKS", "DYNAMODB"} {
		t.Run(family, func(t *testing.T) {
			tr := &serviceTestTransport{}
			tr.handle = func(req *http.Request, p model.Document, v url.Values) (string, int) {
				if strings.HasPrefix(req.URL.Host, "eks.") {
					if req.URL.Path == "/clusters" {
						return serviceTestJSON(model.Document{"clusters": []string{"observed"}})
					}
					return `{"__type":"AccessDeniedException","message":"private"}`, 403
				}
				action := req.Header.Get("X-Amz-Target")
				if strings.HasSuffix(action, ".ListTables") {
					return serviceTestJSON(model.Document{"TableNames": []string{"observed"}})
				}
				return `{"__type":"AccessDeniedException","message":"private"}`, 403
			}
			got, e := serviceTestAWS(tr).ServiceInventory(context.Background(), serviceTestRegistration(), family, "")
			if e != nil {
				t.Fatal(e)
			}
			if len(got.Resources) != 1 || got.Complete || len(got.Reasons) == 0 {
				t.Fatalf("denied description erased root: %+v", got)
			}
			if strings.Contains(string(got.Raw), "private") {
				t.Fatal("provider diagnostic retained")
			}
		})
	}
}

func TestAWSServiceIdentityRegionScopeAndReadOnlyBoundary(t *testing.T) {
	tr := &serviceTestTransport{account: "999900001111", handle: func(*http.Request, model.Document, url.Values) (string, int) {
		t.Fatal("unbound identity read metadata")
		return "", 500
	}}
	a := serviceTestAWS(tr)
	reg := serviceTestRegistration()
	if _, e := a.ServiceInventory(context.Background(), reg, "DYNAMODB", ""); e == nil {
		t.Fatal("wrong caller account accepted")
	}
	reg.Region = "us-east-1"
	if _, e := a.ServiceInventory(context.Background(), reg, "DYNAMODB", ""); e == nil {
		t.Fatal("reader region mismatch accepted")
	}
	r, e := newServiceRead(a, awsservice.Scope{TenantID: "tenant-a", AccountID: "111122223333", Region: "eu-west-1"})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = r.json(context.Background(), "ecs", "UpdateService", "/", nil); e == nil {
		t.Fatal("mutation accepted")
	}
	if _, e = r.query(context.Background(), "elasticache", "ModifyCacheCluster", "2015-02-02", url.Values{}); e == nil {
		t.Fatal("cache mutation accepted")
	}
}

func TestAWSServiceCacheQueryTopologyAndAbsentServerless(t *testing.T) {
	tr := &serviceTestTransport{}
	tr.handle = func(req *http.Request, p model.Document, v url.Values) (string, int) {
		action := v.Get("Action")
		switch action {
		case "DescribeReplicationGroups":
			return serviceTestXML(action, `<ReplicationGroups><ReplicationGroup><ReplicationGroupId>rg</ReplicationGroupId><ARN>arn:aws:elasticache:eu-west-1:111122223333:replicationgroup:rg</ARN><AutomaticFailover>enabled</AutomaticFailover><MultiAZ>enabled</MultiAZ><NodeGroups><NodeGroup><NodeGroupId>0001</NodeGroupId><NodeGroupMembers><NodeGroupMember><CacheClusterId>rg-001</CacheClusterId><CurrentRole>primary</CurrentRole></NodeGroupMember></NodeGroupMembers></NodeGroup></NodeGroups></ReplicationGroup></ReplicationGroups>`)
		case "ListTagsForResource":
			return serviceTestXML(action, `<TagList/>`)
		case "DescribeCacheClusters":
			return serviceTestXML(action, `<CacheClusters><CacheCluster><CacheClusterId>rg-001</CacheClusterId><ReplicationGroupId>rg</ReplicationGroupId><ARN>arn:aws:elasticache:eu-west-1:111122223333:cluster:rg-001</ARN><Engine>valkey</Engine><CacheNodeType>cache.r7g.large</CacheNodeType><CacheClusterStatus>available</CacheClusterStatus></CacheCluster></CacheClusters>`)
		case "DescribeSnapshots":
			return serviceTestXML(action, `<Snapshots/>`)
		case "DescribeServerlessCaches":
			return serviceTestXML(action, `<ServerlessCaches/>`)
		}
		action = req.Header.Get("X-Amz-Target")
		for _, key := range []string{"ScalableTargets", "ScalingPolicies", "ScheduledActions"} {
			if strings.HasSuffix(action, ".Describe"+key) {
				return serviceTestJSON(model.Document{key: []any{}})
			}
		}
		t.Fatalf("unexpected read %s", action)
		return "", 500
	}
	a := serviceTestAWS(tr)
	reg := serviceTestRegistration()
	got, e := a.ServiceInventory(context.Background(), reg, "ELASTICACHE", "")
	if e != nil || len(got.Resources) != 1 {
		t.Fatalf("native cache failed %v %+v", e, got)
	}
	if len(awsservice.Rows(got.Resources[0]["provider_relationships"])) != 1 {
		t.Fatal("replication topology flattened")
	}
	second, e := a.ServiceInventory(context.Background(), reg, "ELASTICACHE", got.NextCursor)
	if e != nil || len(second.Resources) != 1 {
		t.Fatalf("cluster phase %v", e)
	}
	last, e := a.ServiceInventory(context.Background(), reg, "ELASTICACHE", second.NextCursor)
	if e != nil || !last.Complete || len(last.Resources) != 0 {
		t.Fatalf("empty is not unknown or zero cost: %v %+v", e, last)
	}
}
