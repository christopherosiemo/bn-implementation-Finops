package service

import (
	"context"
	"errors"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"testing"
)

// Authenticated persisted refusal is a component gate. No synthetic measurements
// or financial rows are passed off as collected native/customer acceptance.
func TestAWSServiceFourFamiliesPersistedRestrictedAssessments(t *testing.T) {
	f := newMutationReplayFixture(t)
	ctx := context.Background()
	admin := databaseAssessmentTestAdmin(t, ctx, f)
	analyst := databaseAssessmentTestRuntime(t, ctx, admin, "aws-service-assessor", "finops_service_analyst")
	token := f.token(f.tenant, "service-reviewer", "PLATFORM_ADMIN")
	for _, spec := range []struct{ family, kind, arn string }{{"ECS", "ECS_SERVICE", "arn:aws:ecs:eu-west-1:111122223333:service/test/stable"}, {"DYNAMODB", "DYNAMODB_TABLE", "arn:aws:dynamodb:eu-west-1:111122223333:table/table"}, {"ELASTICACHE", "ELASTICACHE_REPLICATION_GROUP", "arn:aws:elasticache:eu-west-1:111122223333:replicationgroup:cache"}, {"ELB", "LOAD_BALANCER", "arn:aws:elasticloadbalancing:eu-west-1:111122223333:loadbalancer/app/test/0000000000000000"}} {
		t.Run(spec.family, func(t *testing.T) {
			var resource model.Document
			if e := f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
				var e error
				resource, e = tx.Create(ctx, "resources", model.Document{"provider": "AWS", "name": "Synthetic persisted service refusal", "resource_type": spec.kind, "provider_resource_id": spec.arn, "account_id": "111122223333", "region": "eu-west-1", "service_family": spec.family, "aws_service_configuration": model.Document{}, "workload_id": "replay-workload", "configuration_authority": "UNKNOWN"})
				return e
			}); e != nil {
				t.Fatal(e)
			}
			rid := model.String(resource, "id")
			path := "aws-service-assessments"
			key := "aws-service-" + spec.family
			if code, _, _ := f.request(path, `"0"`, key+"-authority", token, model.Document{"resource_id": rid, "observations": model.Document{"complete": true}, "monthly_saving": "1"}); code != 422 {
				t.Fatalf("caller evidence accepted %d", code)
			}
			code, record, _ := f.request(path, `"0"`, key, token, model.Document{"resource_id": rid})
			if code != 202 {
				t.Fatalf("queue %d %#v", code, record)
			}
			if code, replay, _ := f.request(path, `"0"`, key, token, model.Document{"resource_id": rid}); code != 202 || replay["id"] != record["id"] {
				t.Fatal("request replay created another assessment")
			}
			a := &API{Store: analyst, Config: Config{Fixture: true}}
			if e := analyst.Do(ctx, f.tenant, func(tx *store.Tx) error {
				return awsServiceAssessmentOne(ctx, a, tx, func(context.Context, string, model.Document) ([]byte, error) {
					return nil, errors.New("missing evidence must not read an invented archive")
				})
			}); e != nil {
				t.Fatal(e)
			}
			id := model.String(record, "id")
			status, detail := fleetNativeHTTPGet(t, f, path+"/"+id, token)
			if status != 200 || detail["status"] != "BLOCKED" {
				t.Fatalf("persisted refusal %d %#v", status, detail)
			}
			result := storageObject(detail["assessment"])
			if result["execution_authorized"] != false || result["verified_saving"] != nil || storageObject(result["economics"])["estimated_window_saving"] != nil {
				t.Fatal("missing evidence created a saving or mutation authority")
			}
			status, pub := fleetNativeHTTPGet(t, f, "recommendations/aws-service-"+id, token)
			if status != 200 || pub["model_kind"] != "AWS_SERVICE_ASSESSMENT_V1" {
				t.Fatalf("normal recommendation %d %#v", status, pub)
			}
			for _, query := range []string{path + "?resource_id=" + rid + "&limit=1", "recommendations?model_kind=AWS_SERVICE_ASSESSMENT_V1&resource_id=" + rid + "&limit=1"} {
				if status, _ := fleetNativeHTTPGet(t, f, query, token); status != 200 {
					t.Fatalf("scoped ordinary page %d", status)
				}
			}
			foreign := f.token("foreign-"+f.tenant, "foreign", "FINOPS_ADMIN")
			if status, _ := fleetNativeHTTPGet(t, f, path+"/"+id, foreign); status != 404 {
				t.Fatal("foreign assessment disclosed")
			}
			if e := analyst.Do(ctx, f.tenant, func(tx *store.Tx) error {
				_, e := tx.Exec(ctx, "UPDATE aws_service_assessments SET document='{}' WHERE tenant_id=$1 AND id=$2", f.tenant, id)
				return e
			}); e == nil {
				t.Fatal("terminal analytical assessment overwritten")
			}
			if e := f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
				_, e := tx.Exec(ctx, "UPDATE aws_service_recommendation_publications SET document='{}' WHERE tenant_id=$1 AND assessment_id=$2", f.tenant, id)
				return e
			}); e == nil {
				t.Fatal("immutable review changed")
			}
			if e := analyst.Do(ctx, f.tenant, func(tx *store.Tx) error {
				_, e := tx.Exec(ctx, "UPDATE entities SET document='{}' WHERE tenant_id=$1 AND kind='resources' AND id=$2", f.tenant, rid)
				return e
			}); e == nil {
				t.Fatal("analyst acquired resource mutation rights")
			}
		})
	}
}
