package service

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/auth"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

func TestJointDecisionIDsOnlyRouteRefusesProofMoneyAndReadOnlyActor(t *testing.T) {
	api := new(API)
	path := []string{"workloads", "workload", "fleet-joint-decisions"}
	r := httptest.NewRequest(http.MethodPost, "/v1/workloads/workload/fleet-joint-decisions", nil)
	finance := auth.Identity{Tenant: "tenant", Subject: "finance-subject", Roles: map[string]bool{"FINANCE": true}}
	for _, body := range []model.Document{
		{}, {"assessment_request_id": "a"}, {"assessment_request_id": "a", "capacity_batch_request_id": "b", "estimated_saving": "1"},
		{"assessment_request_id": "a", "capacity_batch_request_id": "b", "evidence": model.Document{"verified": true}},
		{"assessment_request_id": "a", "capacity_batch_request_id": "b", "execution_authorized": true},
	} {
		_, _, handled, e := api.fleetJointDecisionMutate(context.Background(), nil, finance, r, body, path)
		var p *Problem
		if !handled || !errors.As(e, &p) || p.Status != 422 {
			t.Fatal("non-ID payload reached database or accepted", e)
		}
	}
	auditor := finance
	auditor.Roles = map[string]bool{"AUDITOR": true}
	_, _, handled, e := api.fleetJointDecisionMutate(context.Background(), nil, auditor, r, model.Document{"assessment_request_id": "a", "capacity_batch_request_id": "b"}, path)
	var p *Problem
	if !handled || !errors.As(e, &p) || p.Status != 403 {
		t.Fatal("read actor admitted write", e)
	}
	if _, _, handled, _ = api.fleetJointDecisionMutate(context.Background(), nil, finance, r, model.Document{}, []string{"fleet-native-assessments", "a"}); handled {
		t.Fatal("joint route captured legacy035")
	}
}
