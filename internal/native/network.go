package native

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/network"
	"strconv"
)

func (s *Storage) WriteNetworkRows(ctx context.Context, scope network.Scope, generation, batch string, rows []network.FlowRow) (model.Document, error) {
	if network.ValidateScope(scope) != nil || !safeKey.MatchString(scope.TenantID) || !safeKey.MatchString(generation) || !safeKey.MatchString(batch) || len(rows) == 0 || len(rows) > network.FlowBatchRows {
		return nil, errors.New("NETWORK_ANALYTICS_BINDING_INVALID")
	}
	digest := network.Hash(rows)
	var body bytes.Buffer
	enc := json.NewEncoder(&body)
	seen := map[string]bool{}
	for _, row := range rows {
		if len(row.ID) != 64 || len(row.CohortID) != 64 || seen[row.ID] {
			return nil, errors.New("NETWORK_DUPLICATE_OR_INVALID_ROW")
		}
		seen[row.ID] = true
		raw, _ := json.Marshal(row)
		if e := enc.Encode(model.Document{"tenant_id": scope.TenantID, "account_id": scope.AccountID, "region": scope.Region, "generation_id": generation, "batch_id": batch, "batch_hash": digest, "row_id": row.ID, "cohort_id": row.CohortID, "payload": string(raw)}); e != nil {
			return nil, e
		}
	}
	if _, e := s.objectQuery(ctx, "INSERT INTO network_flow_records FORMAT JSONEachRow", body.Bytes()); e != nil {
		return nil, e
	}
	query := "SELECT toString(uniqExact(row_id)) AS rows,toString(uniqExact(tuple(row_id,batch_hash))) AS variants FROM network_flow_records WHERE tenant_id='" + scope.TenantID + "' AND account_id='" + scope.AccountID + "' AND region='" + scope.Region + "' AND generation_id='" + generation + "' AND batch_id='" + batch + "' FORMAT JSONEachRow"
	raw, e := s.objectQuery(ctx, query, nil)
	if e != nil {
		return nil, e
	}
	var got struct {
		Rows     string `json:"rows"`
		Variants string `json:"variants"`
	}
	if json.Unmarshal(bytes.TrimSpace(raw), &got) != nil || got.Rows != strconv.Itoa(len(rows)) || got.Variants != got.Rows {
		return nil, errors.New("NETWORK_ANALYTICS_READBACK_DIFFERS")
	}
	return model.Document{"rows": len(rows), "row_digest": digest, "generation_id": generation, "batch_id": batch}, nil
}
func (s *Storage) ValidateNetworkGeneration(ctx context.Context, scope network.Scope, id string, rows int64) error {
	if network.ValidateScope(scope) != nil || !safeKey.MatchString(scope.TenantID) || !safeKey.MatchString(id) || rows < 0 {
		return errors.New("NETWORK_GENERATION_BINDING_INVALID")
	}
	q := "SELECT toString(uniqExact(row_id)) AS rows,toString(uniqExact(tuple(row_id,payload))) AS variants FROM network_flow_records WHERE tenant_id='" + scope.TenantID + "' AND account_id='" + scope.AccountID + "' AND region='" + scope.Region + "' AND generation_id='" + id + "' FORMAT JSONEachRow"
	raw, e := s.objectQuery(ctx, q, nil)
	if e != nil {
		return e
	}
	var got struct {
		Rows     string `json:"rows"`
		Variants string `json:"variants"`
	}
	if json.Unmarshal(bytes.TrimSpace(raw), &got) != nil || got.Rows != strconv.FormatInt(rows, 10) || got.Rows != got.Variants {
		return errors.New("NETWORK_GENERATION_DUPLICATE_OR_INCOMPLETE")
	}
	return nil
}
func (s *Storage) WriteNetworkMetrics(ctx context.Context, scope network.Scope, version string, rows []model.Document) error {
	if network.ValidateScope(scope) != nil || !safeKey.MatchString(scope.TenantID) || !safeKey.MatchString(version) || len(rows) > 150000 {
		return errors.New("NETWORK_METRIC_BOUND_INVALID")
	}
	for start := 0; start < len(rows); start += 2000 {
		var body bytes.Buffer
		enc := json.NewEncoder(&body)
		for _, r := range rows[start:min(start+2000, len(rows))] {
			raw, _ := json.Marshal(r)
			if e := enc.Encode(model.Document{"tenant_id": scope.TenantID, "account_id": scope.AccountID, "region": scope.Region, "source_version": version, "row_id": network.Hash(r), "payload": string(raw)}); e != nil {
				return e
			}
		}
		if _, e := s.objectQuery(ctx, "INSERT INTO network_metric_observations FORMAT JSONEachRow", body.Bytes()); e != nil {
			return e
		}
	}
	return nil
}
