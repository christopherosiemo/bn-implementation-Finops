package service

import (
	"github.com/christopherosiemo/bn-implementation-Finops/internal/auth"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

func scopedOwner(i auth.Identity) bool {
	return i.Roles["APPLICATION_OWNER"] && !i.Can("PLATFORM_ADMIN", "FINOPS_ADMIN", "FINANCE", "VIEWER", "AUDITOR")
}
func owns(i auth.Identity, w model.Document) bool {
	return model.String(w, "owner") == i.Subject || i.Email != "" && model.String(w, "owner") == i.Email || model.String(w, "owner_subject") == i.Subject
}
func workloadAccess(i auth.Identity, w model.Document) error {
	if scopedOwner(i) && !owns(i, w) {
		return problem(403, "WORKLOAD_SCOPE_DENIED", "application owner is not assigned to this workload")
	}
	return nil
}
func restrictDashboard(i auth.Identity, d model.Document) {
	if !scopedOwner(i) {
		return
	}
	allowed := map[string]bool{}
	if rows, ok := d["workloads"].([]model.Document); ok {
		filtered := []model.Document{}
		for _, w := range rows {
			if owns(i, w) {
				allowed[model.String(w, "id")] = true
				filtered = append(filtered, w)
			}
		}
		d["workloads"] = filtered
	}
	for _, k := range []string{"resources", "recommendations", "schedules", "change_plans", "executions", "readiness"} {
		filtered := []model.Document{}
		if rows, ok := d[k].([]model.Document); ok {
			for _, row := range rows {
				if allowed[model.String(row, "workload_id")] {
					filtered = append(filtered, row)
				}
			}
		}
		d[k] = filtered
	}
	d["audit"] = []model.Document{}
	d["savings"] = []model.Document{}
	d["cloud_accounts"] = []model.Document{}
}
