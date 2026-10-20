package native

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/objectstorage"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

func (s *Storage) objectQuery(ctx context.Context, query string, body []byte) ([]byte, error) {
	u, e := url.Parse(s.AnalyticsURL)
	if e != nil || u.Host == "" || u.User != nil || !safeKey.MatchString(s.Database) {
		return nil, errors.New("S3_ANALYTICS_ENDPOINT_INVALID")
	}
	q := u.Query()
	q.Set("database", s.Database)
	q.Set("query", query)
	if strings.HasPrefix(query, "INSERT") {
		q.Set("insert_deduplicate", "1")
	}
	u.RawQuery = q.Encode()
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if e != nil {
		return nil, e
	}
	req.Header.Set("X-ClickHouse-User", s.AnalyticsUser)
	req.Header.Set("X-ClickHouse-Key", s.AnalyticsSecret)
	req.Header.Set("Content-Type", "application/x-ndjson")
	response, e := s.Client.Do(req)
	if e != nil {
		return nil, errors.New("S3_ANALYTICS_TRANSPORT_UNAVAILABLE")
	}
	defer response.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if e != nil || response.StatusCode != 200 {
		return nil, errors.New("S3_ANALYTICS_QUERY_FAILED")
	}
	return raw, nil
}
func (s *Storage) WriteObjectRows(ctx context.Context, scope objectstorage.Scope, generation, batch string, rows []objectstorage.InventoryRow) (model.Document, error) {
	if objectstorage.ValidateScope(scope) != nil || !safeKey.MatchString(scope.TenantID) || !safeKey.MatchString(generation) || !safeKey.MatchString(batch) || len(rows) > objectstorage.InventoryBatchRows {
		return nil, errors.New("S3_ANALYTICS_BINDING_INVALID")
	}
	canonical := objectstorage.Hash(rows)
	var body bytes.Buffer
	encoder := json.NewEncoder(&body)
	seen := map[string]bool{}
	for _, row := range rows {
		if len(row.ID) != 64 || len(row.ObjectIdentity) != 64 || seen[row.ID] || row.Bucket == "" {
			return nil, errors.New("S3_ANALYTICS_ROW_INVALID")
		}
		seen[row.ID] = true
		payload, _ := json.Marshal(row)
		if e := encoder.Encode(model.Document{"tenant_id": scope.TenantID, "account_id": scope.AccountID, "region": scope.Region, "generation_id": generation, "batch_id": batch, "canonical_hash": canonical, "row_id": row.ID, "object_identity": row.ObjectIdentity, "bucket": row.Bucket, "cohort_id": row.CohortID, "payload": string(payload)}); e != nil {
			return nil, e
		}
	}
	if _, e := s.objectQuery(ctx, "INSERT INTO object_storage_objects FORMAT JSONEachRow", body.Bytes()); e != nil {
		return nil, e
	}
	// Every request interpoland is a validated identifier or content hash.
	query := "SELECT toString(uniqExact(row_id)) AS rows,toString(uniqExact(tuple(row_id,canonical_hash))) AS variants FROM object_storage_objects WHERE tenant_id='" + scope.TenantID + "' AND generation_id='" + generation + "' AND batch_id='" + batch + "' FORMAT JSONEachRow"
	raw, e := s.objectQuery(ctx, query, nil)
	if e != nil {
		return nil, e
	}
	var result struct {
		Rows     string `json:"rows"`
		Variants string `json:"variants"`
	}
	if json.Unmarshal(bytes.TrimSpace(raw), &result) != nil || result.Rows != strconv.Itoa(len(rows)) || result.Variants != result.Rows {
		return nil, errors.New("S3_ANALYTICS_READBACK_DIFFERS")
	}
	return model.Document{"row_count": len(rows), "canonical_hash": canonical, "table": "object_storage_objects", "batch_id": batch, "generation_id": generation}, nil
}
func (s *Storage) ValidateObjectGeneration(ctx context.Context, scope objectstorage.Scope, generation string, rows int64) error {
	if objectstorage.ValidateScope(scope) != nil || !safeKey.MatchString(scope.TenantID) || !safeKey.MatchString(generation) || rows < 0 {
		return errors.New("S3_GENERATION_ANALYTICS_BINDING_INVALID")
	}
	query := "SELECT toString(uniqExact(row_id)) AS rows,toString(uniqExact(object_identity)) AS objects,toString(uniqExact(tuple(row_id,object_identity,canonical_hash))) AS variants FROM object_storage_objects WHERE tenant_id='" + scope.TenantID + "' AND generation_id='" + generation + "' FORMAT JSONEachRow"
	raw, e := s.objectQuery(ctx, query, nil)
	if e != nil {
		return e
	}
	var result struct {
		Rows     string `json:"rows"`
		Objects  string `json:"objects"`
		Variants string `json:"variants"`
	}
	if json.Unmarshal(bytes.TrimSpace(raw), &result) != nil || result.Rows != strconv.FormatInt(rows, 10) || result.Objects != result.Rows || result.Variants != result.Rows {
		return errors.New("S3_GENERATION_DUPLICATE_OR_INCOMPLETE_OBJECTS")
	}
	return nil
}
func (s *Storage) WriteObjectAccess(ctx context.Context, scope objectstorage.Scope, version string, rows []model.Document) error {
	if objectstorage.ValidateScope(scope) != nil || !safeKey.MatchString(scope.TenantID) || !safeKey.MatchString(version) || len(rows) > 100000 {
		return errors.New("S3_ACCESS_FACT_BINDING_INVALID")
	}
	for start := 0; start < len(rows); start += 2000 {
		var body bytes.Buffer
		enc := json.NewEncoder(&body)
		for _, row := range rows[start:min(start+2000, len(rows))] {
			raw, _ := json.Marshal(row)
			if e := enc.Encode(model.Document{"tenant_id": scope.TenantID, "account_id": scope.AccountID, "region": scope.Region, "source_version": version, "row_id": objectstorage.Hash(row), "payload": string(raw)}); e != nil {
				return e
			}
		}
		if _, e := s.objectQuery(ctx, "INSERT INTO object_storage_access_observations FORMAT JSONEachRow", body.Bytes()); e != nil {
			return e
		}
	}
	query := "SELECT toString(uniqExact(row_id)) AS rows,toString(uniqExact(tuple(row_id,payload))) AS variants FROM object_storage_access_observations WHERE tenant_id='" + scope.TenantID + "' AND source_version='" + version + "' FORMAT JSONEachRow"
	raw, e := s.objectQuery(ctx, query, nil)
	if e != nil {
		return e
	}
	var result struct {
		Rows     string `json:"rows"`
		Variants string `json:"variants"`
	}
	if json.Unmarshal(bytes.TrimSpace(raw), &result) != nil || result.Rows != strconv.Itoa(len(rows)) || result.Rows != result.Variants {
		return errors.New("S3_ACCESS_FACT_READBACK_DIFFERS")
	}
	return nil
}
