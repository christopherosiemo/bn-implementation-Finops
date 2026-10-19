package fleetcapacity

import (
	"context"
	"testing"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/native"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/telemetry"
)

func TestFleetCapacityBaselineMarkerSurvivesResealedCatalogTampering(t *testing.T) {
	scope, now := capacityScope()
	cpu := "2"
	binding := telemetry.Binding{TenantID: "tenant", WorkloadID: "workload", ResourceID: "resource", Provider: "AWS", ProviderResourceID: scope.CurrentMemberIDs[0], AccountID: "111122223333", Region: "eu-west-1"}
	catalog := native.CapacityModelCatalog{ID: "m6i.large", Count: 1, Capacity: native.PhysicalCapacity{CPU: &cpu}}
	request := &native.CapacityModelRequest{Binding: binding, AsOf: now, Current: catalog, Candidates: []native.CapacityModelCatalog{catalog}}
	result := MemberResult{BatchID: "baseline-test", Scope: scope, InstanceID: scope.CurrentMemberIDs[0], Binding: &binding, ObservedAt: now, CandidateTemplate: &CandidateTemplate{InstanceType: catalog.ID}, InputKind: "CURRENT_CONFIGURATION_BASELINE_MODEL_REQUEST", InputHash: telemetry.Hash(request), ModelRequested: true, Status: "BLOCKED", ReasonCodes: []string{"CURRENT_CONFIGURATION_BASELINE_ONLY"}}
	result, err := finish(result)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := Evaluate(context.Background(), Plan{Result: result, Request: request}, nil, now)
	if err != nil || accepted.ModelEvaluated || accepted.ExecutionAuthorized || accepted.GroupCapacityAuthorized || accepted.ChangePlanID != nil || accepted.VerifiedSaving != nil {
		t.Fatal("read-only baseline gained authority", err)
	}
	changed := "4"
	request.Candidates[0].Capacity.CPU = &changed
	result.InputHash = telemetry.Hash(request)
	result, err = finish(result)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Evaluate(context.Background(), Plan{Result: result, Request: request}, nil, now); err == nil {
		t.Fatal("resealed counterfactual became current baseline")
	}
	request.Candidates[0] = request.Current
	result.InputKind = "MODEL_REQUEST"
	result.ReasonCodes = []string{}
	result.InputHash = telemetry.Hash(request)
	result, err = finish(result)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Evaluate(context.Background(), Plan{Result: result, Request: request}, nil, now); err == nil {
		t.Fatal("baseline marker was stripped")
	}
}
