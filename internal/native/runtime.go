package native

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/auth"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/telemetry"
	"github.com/jackc/pgx/v5"
)

type Server struct {
	Store    *store.Store
	Pipeline *Pipeline
	Auth     interface {
		Validate(*http.Request) (auth.Identity, error)
	}
	Issuer      string
	ReaderToken string
	Bindings    map[string]ReadBinding
	Fixture     bool
	Now         func() time.Time
	readerMu    sync.Mutex
	readers     map[string]telemetry.PromReader
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}
func (s *Server) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	m.HandleFunc("POST /v1/metrics", s.ingress)
	m.HandleFunc("POST /evaluate", s.evaluate)
	m.HandleFunc("POST /capacity-input", s.capacityInput)
	return m
}
func nativeError(w http.ResponseWriter, status int, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(model.Document{"error": reason, "reason_code": reason})
}
func (s *Server) connection(ctx context.Context, tenant, id string) (telemetry.Connection, error) {
	var c telemetry.Connection
	if s.Store == nil || tenant == "" || id == "" {
		return c, errors.New("TELEMETRY_CONNECTION_REQUIRED")
	}
	e := s.Store.Do(ctx, tenant, func(t *store.Tx) error {
		d, e := t.TelemetryConnection(ctx, id)
		if e != nil {
			return e
		}
		if !model.Bool(d, "enabled") || model.Bool(d, "revoked") {
			return store.ErrTelemetrySource
		}
		c, e = telemetry.ParseConnection(d)
		if e != nil {
			return e
		}
		resource, e := t.Get(ctx, "resources", c.Binding.ResourceID)
		if e != nil {
			return e
		}
		if c.Binding.TenantID != tenant || c.Binding.WorkloadID != model.String(resource, "workload_id") || c.Binding.Provider != model.String(resource, "provider") || c.Binding.ProviderResourceID != model.String(resource, "provider_resource_id") || c.Binding.AccountID != model.String(resource, "account_id") || c.Binding.Region != model.String(resource, "region") {
			return store.ErrTelemetrySource
		}
		return nil
	})
	return c, e
}
func consoleIdentity(i auth.Identity) bool {
	for _, role := range []string{"ORGANISATION_OWNER", "FINOPS_ADMIN", "PLATFORM_ADMIN", "FINANCE", "APPLICATION_OWNER", "APPROVER", "VIEWER", "AUDITOR"} {
		if i.Roles[role] {
			return true
		}
	}
	return false
}
func (s *Server) ingress(w http.ResponseWriter, r *http.Request) {
	if s.Auth == nil || s.Pipeline == nil || s.Store == nil {
		nativeError(w, 503, "TELEMETRY_INGRESS_UNAVAILABLE")
		return
	}
	i, e := s.Auth.Validate(r)
	if e != nil || i.Tenant == "" || i.Subject == "" || consoleIdentity(i) {
		nativeError(w, 401, "TELEMETRY_MACHINE_IDENTITY_REQUIRED")
		return
	}
	if strings.Split(r.Header.Get("Content-Type"), ";")[0] != "application/x-protobuf" || r.Header.Get("Content-Encoding") != "" && r.Header.Get("Content-Encoding") != "identity" {
		nativeError(w, 415, "TELEMETRY_PROTOBUF_REQUIRED")
		return
	}
	c, e := s.connection(r.Context(), i.Tenant, r.Header.Get("X-Finops-Connection-ID"))
	if e != nil || c.Kind != "OTLP" || c.Issuer != s.Issuer || c.Subject != i.Subject {
		nativeError(w, 403, "TELEMETRY_MACHINE_SOURCE_MISMATCH")
		return
	}
	config := telemetry.ConfigHash(c)
	if expected := r.Header.Get("X-Finops-Config-Hash"); expected != "" && expected != config {
		nativeError(w, 409, "TELEMETRY_CONFIG_CHANGED")
		return
	}
	raw, e := io.ReadAll(io.LimitReader(r.Body, telemetry.MaxBodyBytes+1))
	if e != nil || len(raw) == 0 || len(raw) > telemetry.MaxBodyBytes {
		nativeError(w, 413, "TELEMETRY_BODY_LIMIT")
		return
	}
	key := r.Header.Get("Idempotency-Key")
	if key == "" {
		key = telemetry.Hash(model.Document{"raw_sha256": telemetry.BytesHash(raw), "config_hash": config, "subject": i.Subject})
	}
	if len(key) > 200 {
		nativeError(w, 400, "TELEMETRY_IDEMPOTENCY_KEY_INVALID")
		return
	}
	at := s.now()
	var old model.Document
	e = s.Store.Do(r.Context(), i.Tenant, func(t *store.Tx) error {
		var e error
		old, e = t.TelemetryBatchByKey(r.Context(), c.ID, key)
		if e == pgx.ErrNoRows {
			return nil
		}
		return e
	})
	if e != nil {
		nativeError(w, 503, "TELEMETRY_RECEIPT_UNAVAILABLE")
		return
	}
	if old != nil {
		if model.String(old, "raw_sha256") != telemetry.BytesHash(raw) || model.String(old, "config_hash") != config {
			nativeError(w, 409, "TELEMETRY_REPLAY_CONFLICT")
			return
		}
		if first, e := time.Parse(time.RFC3339Nano, model.String(old, "collected_at")); e == nil {
			at = first
		} else {
			nativeError(w, 409, "TELEMETRY_RECEIPT_INVALID")
			return
		}
	}
	b, e := telemetry.DecodeOTLP(raw, c, at)
	if e != nil {
		nativeError(w, 400, "TELEMETRY_PROTOBUF_INVALID")
		return
	}
	receipt, _, e := s.Pipeline.Publish(r.Context(), c, b, key, time.Time{}, time.Time{})
	if e != nil {
		if errors.Is(e, store.ErrTelemetryConflict) {
			nativeError(w, 409, "TELEMETRY_REPLAY_CONFLICT")
		} else {
			nativeError(w, 503, "TELEMETRY_PUBLICATION_INCOMPLETE")
		}
		return
	}
	w.Header().Set("Content-Type", "application/x-protobuf")
	w.Header().Set("X-Finops-Receipt-ID", model.String(receipt, "id"))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(telemetry.OTLPResponse(b))
}

type evaluationRequest struct {
	TenantID     string `json:"tenant_id"`
	ConnectionID string `json:"connection_id"`
	Mode         string `json:"mode"`
	Days         int    `json:"days"`
	Timezone     string `json:"timezone"`
	Minutes      int    `json:"minutes"`
}

func (s *Server) evaluate(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if s.ReaderToken == "" || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") || subtle.ConstantTimeCompare([]byte(token), []byte(s.ReaderToken)) != 1 {
		nativeError(w, 401, "TELEMETRY_READER_IDENTITY_REQUIRED")
		return
	}
	var input evaluationRequest
	d := json.NewDecoder(io.LimitReader(r.Body, 8193))
	d.DisallowUnknownFields()
	if d.Decode(&input) != nil || d.Decode(&struct{}{}) != io.EOF {
		nativeError(w, 400, "TELEMETRY_EVALUATION_INVALID")
		return
	}
	if input.Mode != "history" && input.Mode != "window" || input.Mode == "history" && (input.Days != 14 && input.Days != 30 && input.Days != 90) || input.Mode == "window" && (input.Minutes < 2 || input.Minutes > 60) {
		nativeError(w, 400, "TELEMETRY_EVALUATION_INVALID")
		return
	}
	c, e := s.connection(r.Context(), input.TenantID, input.ConnectionID)
	if e != nil || s.Pipeline == nil {
		nativeError(w, 403, "TELEMETRY_SOURCE_INACTIVE")
		return
	}
	if c.Kind == "PROMETHEUS" {
		binding, ok := s.Bindings[c.ReadBindingID]
		if !ok || binding.connection(c) != nil {
			nativeError(w, 403, "TELEMETRY_READ_BINDING_MISMATCH")
			return
		}
	}
	start, end := s.now().Add(-time.Duration(input.Minutes+20)*time.Minute), s.now().Add(5*time.Second)
	if input.Mode == "history" {
		loc, e := time.LoadLocation(input.Timezone)
		if e != nil {
			nativeError(w, 400, "TELEMETRY_TIMEZONE_INVALID")
			return
		}
		now := s.now().In(loc)
		end = time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc).UTC()
		start = end.In(loc).AddDate(0, 0, -input.Days).UTC()
	}
	samples, receiptIDs, problems, e := s.samples(r.Context(), c, start, end)
	if e != nil {
		if code := safeTelemetryReason(e); strings.Contains(code, "LIMIT") {
			nativeError(w, 413, code)
			return
		}
		nativeError(w, 503, "TELEMETRY_EVIDENCE_UNAVAILABLE")
		return
	}
	var result telemetry.Evaluation
	if input.Mode == "history" {
		result = telemetry.EvaluateHistory(telemetry.HistoryInput{Now: s.now(), Definitions: c.Definitions, Samples: samples, Days: input.Days, Timezone: input.Timezone})
	} else {
		result = telemetry.EvaluateWindow(telemetry.WindowInput{Now: s.now(), Definitions: c.Definitions, Segments: telemetry.Segments(samples, c.Definitions), Minutes: input.Minutes})
	}
	if len(problems) > 0 {
		result.Status = "BLOCKED"
		result.ReasonCodes = sortedUnique(append(result.ReasonCodes, problems...))
		result.Hash = ""
		result.Hash = telemetry.Hash(result)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(model.Document{"connection_id": c.ID, "config_hash": telemetry.ConfigHash(c), "receipt_ids": receiptIDs, "evaluation": result})
}
func sortedUnique(values []string) []string {
	m := map[string]bool{}
	for _, s := range values {
		if s != "" {
			m[s] = true
		}
	}
	out := []string{}
	for s := range m {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
func (s *Server) samples(ctx context.Context, c telemetry.Connection, start, end time.Time) ([]telemetry.Sample, []string, []string, error) {
	var receipts []model.Document
	e := s.Store.Do(ctx, c.Binding.TenantID, func(t *store.Tx) error { var e error; receipts, e = t.TelemetryReceipts(ctx, c.ID); return e })
	if e != nil {
		return nil, nil, nil, e
	}
	points := map[string]telemetry.Sample{}
	slots := map[string]string{}
	ids, problems := []string{}, []string{}
	receipts = selectHistoryReceipts(receipts, c.Kind)
	for _, r := range receipts {
		if !model.Bool(r, "active_source") || model.String(r, "config_hash") != telemetry.ConfigHash(c) {
			continue
		}
		from, err1 := time.Parse(time.RFC3339Nano, model.String(r, "start"))
		to, err2 := time.Parse(time.RFC3339Nano, model.String(r, "end"))
		if err1 != nil || err2 != nil {
			from, err1 = time.Parse(time.RFC3339Nano, model.String(r, "query_start"))
			to, err2 = time.Parse(time.RFC3339Nano, model.String(r, "query_end"))
		}
		if err1 != nil || err2 != nil || to.Before(start) || from.After(end) {
			continue
		}
		b, e := s.Pipeline.ReadBatch(ctx, c.Binding.TenantID, r)
		if e != nil {
			return nil, nil, nil, e
		}
		if b.Binding != c.Binding {
			return nil, nil, nil, store.ErrTelemetrySource
		}
		ids = append(ids, model.String(r, "id"))
		if len(ids) > 2048 {
			return nil, nil, nil, errors.New("TELEMETRY_EVALUATION_RECEIPT_LIMIT")
		}
		if len(b.Rejections) > 0 {
			problems = append(problems, "TELEMETRY_SOURCE_PARTIAL_REJECTIONS")
		}
		if len(b.Warnings) > 0 {
			problems = append(problems, "TELEMETRY_SOURCE_WARNINGS")
		}
		for _, p := range b.Samples {
			if p.Time.Before(start.Add(-10*time.Minute)) || p.Time.After(end) {
				continue
			}
			key := p.StreamID + "/" + p.Time.UTC().Format(time.RFC3339Nano)
			if id, ok := slots[key]; ok && id != p.ID {
				problems = append(problems, "TELEMETRY_SAMPLE_CONFLICT")
				continue
			}
			slots[key] = p.ID
			if existing, ok := points[p.ID]; ok {
				existing.SourceHashes = sortedUnique(append(append(existing.SourceHashes, existing.RawSHA256), append(p.SourceHashes, p.RawSHA256)...))
				points[p.ID] = existing
			} else {
				p.SourceHashes = sortedUnique(append(p.SourceHashes, p.RawSHA256))
				points[p.ID] = p
			}
			if len(points) > telemetry.MaxSamples {
				return nil, nil, nil, errors.New("TELEMETRY_EVALUATION_SAMPLE_LIMIT")
			}
		}
	}
	out := []telemetry.Sample{}
	for _, p := range points {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].StreamID != out[j].StreamID {
			return out[i].StreamID < out[j].StreamID
		}
		return out[i].Time.Before(out[j].Time)
	})
	return out, sortedUnique(ids), sortedUnique(problems), nil
}

// Historical daily query snapshots dominate overlapping current-poll chunks.
// This reduces repeated proof references without claiming that a successful
// range query proves actual observation coverage. Every retained point is still
// evaluated. Multiple historical revisions remain and conflicting values block.
func selectHistoryReceipts(receipts []model.Document, kind string) []model.Document {
	if kind != "PROMETHEUS" {
		return receipts
	}
	type span struct{ start, end time.Time }
	historical := []span{}
	for _, r := range receipts {
		from, e := time.Parse(time.RFC3339Nano, model.String(r, "query_start"))
		to, other := time.Parse(time.RFC3339Nano, model.String(r, "query_end"))
		if e == nil && other == nil && to.Sub(from) > 10*time.Minute && model.Bool(r, "active_source") && model.Number(r, "sample_count") > 0 && model.Number(r, "rejection_count") == 0 && model.Number(r, "warning_count") == 0 {
			historical = append(historical, span{from, to})
		}
	}
	out := []model.Document{}
	for _, r := range receipts {
		from, e := time.Parse(time.RFC3339Nano, model.String(r, "query_start"))
		to, other := time.Parse(time.RFC3339Nano, model.String(r, "query_end"))
		skip := false
		if e == nil && other == nil && to.Sub(from) <= 10*time.Minute && model.Number(r, "rejection_count") == 0 && model.Number(r, "warning_count") == 0 {
			for _, h := range historical {
				if !from.Before(h.start) && !to.After(h.end) {
					skip = true
					break
				}
			}
		}
		if !skip {
			out = append(out, r)
		}
	}
	return out
}

// Run keeps current collection independent of the bounded historical queue.
// An unavailable source is retried without terminating the transport process.
func (s *Server) Run(ctx context.Context) error {
	if s.Store == nil || s.Pipeline == nil {
		return errors.New("TELEMETRY_RUNTIME_UNAVAILABLE")
	}
	go s.currentLoop(ctx)
	for {
		_ = s.syncTick(ctx)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
}
func (s *Server) currentLoop(ctx context.Context) {
	for {
		_ = s.currentTick(ctx)
		select {
		case <-ctx.Done():
			return
		case <-time.After(15 * time.Second):
		}
	}
}
func (s *Server) Tick(ctx context.Context) error {
	if e := s.currentTick(ctx); e != nil {
		return e
	}
	return s.syncTick(ctx)
}
func (s *Server) currentTick(ctx context.Context) error {
	tenants, e := s.Store.TelemetryTenants(ctx)
	if e != nil {
		return e
	}
	for _, tenant := range tenants {
		var connections []model.Document
		e = s.Store.Do(ctx, tenant, func(t *store.Tx) error { var e error; connections, e = t.TelemetryConnections(ctx); return e })
		if e != nil {
			continue
		}
		for _, d := range connections {
			if !model.Bool(d, "enabled") || model.Bool(d, "revoked") || model.String(d, "kind") != "PROMETHEUS" {
				continue
			}
			c, e := s.connection(ctx, tenant, model.String(d, "id"))
			if e != nil {
				continue
			}
			end := s.now().Truncate(time.Minute)
			start := end.Add(-3 * time.Minute)
			key := "current:" + telemetry.ConfigHash(c) + ":" + end.Format("20060102T1504")
			_, _ = s.collect(ctx, c, key, start, end)
		}
	}
	return nil
}
func (s *Server) collect(ctx context.Context, c telemetry.Connection, key string, start, end time.Time) (model.Document, error) {
	var previous model.Document
	e := s.Store.Do(ctx, c.Binding.TenantID, func(t *store.Tx) error {
		var e error
		previous, e = t.TelemetryBatchByKey(ctx, c.ID, key)
		if e == pgx.ErrNoRows {
			return nil
		}
		return e
	})
	if e != nil {
		return nil, e
	}
	if previous != nil && model.Bool(previous, "published") {
		var receipt model.Document
		e = s.Store.Do(ctx, c.Binding.TenantID, func(t *store.Tx) error {
			var e error
			receipt, e = t.TelemetryReceiptByBatch(ctx, model.String(previous, "id"))
			return e
		})
		if e != nil {
			return nil, e
		}
		if !model.Bool(receipt, "active_source") || model.String(receipt, "config_hash") != telemetry.ConfigHash(c) {
			return nil, store.ErrTelemetrySource
		}
		return receipt, nil
	}
	binding, ok := s.Bindings[c.ReadBindingID]
	if !ok || binding.connection(c) != nil {
		return nil, errors.New("TELEMETRY_READ_BINDING_MISMATCH")
	}
	reader, e := s.reader(binding)
	if e != nil {
		return nil, e
	}
	reader.Now = s.Now
	b, e := reader.Read(ctx, c, start, end)
	if e != nil {
		return nil, e
	}
	receipt, _, e := s.Pipeline.Publish(ctx, c, b, key, start, end)
	return receipt, e
}
func (s *Server) reader(binding ReadBinding) (telemetry.PromReader, error) {
	s.readerMu.Lock()
	defer s.readerMu.Unlock()
	if s.readers == nil {
		s.readers = map[string]telemetry.PromReader{}
	}
	key := telemetry.Hash(binding)
	if reader, ok := s.readers[key]; ok {
		return reader, nil
	}
	reader, e := binding.Reader(s.Fixture)
	if e == nil {
		s.readers[key] = reader
	}
	return reader, e
}
func (s *Server) syncTick(ctx context.Context) error {
	tenants, e := s.Store.TelemetryTenants(ctx)
	if e != nil {
		return e
	}
	for _, tenant := range tenants {
		var job model.Document
		e = s.Store.Do(ctx, tenant, func(t *store.Tx) error { var e error; job, e = t.TelemetrySyncClaim(ctx, "", 15*time.Minute); return e })
		if e == pgx.ErrNoRows {
			continue
		}
		if e != nil {
			continue
		}
		s.runJob(ctx, tenant, job)
	}
	return nil
}
func (s *Server) runJob(ctx context.Context, tenant string, job model.Document) {
	budget, cancel := context.WithTimeout(ctx, 8*time.Minute)
	defer cancel()
	status, reason := "COMPLETED", "TELEMETRY_QUERY_RANGE_PERSISTED"
	ids := []string{}
	c, e := s.connection(budget, tenant, model.String(job, "connection_id"))
	if e == nil && c.Kind != "PROMETHEUS" {
		e = store.ErrTelemetrySource
	}
	if e == nil {
		var rev model.Document
		e = s.Store.Do(budget, tenant, func(t *store.Tx) error {
			var e error
			rev, e = t.TelemetryRevision(budget, model.String(job, "revision_id"))
			return e
		})
		if e == nil && (model.Bool(rev, "revoked") || model.Bool(rev, "superseded") || model.String(rev, "config_hash") != telemetry.ConfigHash(c)) {
			e = store.ErrTelemetrySource
		}
	}
	start, first := time.Parse(time.RFC3339Nano, model.String(job, "start"))
	end, last := time.Parse(time.RFC3339Nano, model.String(job, "end"))
	if first != nil || last != nil || !end.After(start) || end.Sub(start) > 91*24*time.Hour {
		e = errors.New("TELEMETRY_RANGE_INVALID")
	}
	if e == nil {
		index := 0
		for cursor := start; cursor.Before(end); index++ {
			next := cursor.Add(24 * time.Hour)
			if next.After(end) {
				next = end
			}
			key := "sync:" + model.String(job, "id") + ":" + telemetry.Hash(model.Document{"index": index, "start": cursor, "end": next})
			var receipt model.Document
			receipt, e = s.collect(budget, c, key, cursor, next)
			if e != nil {
				break
			}
			ids = append(ids, model.String(receipt, "id"))
			cursor = next
		}
	}
	if e != nil {
		status, reason = "RETRY", "TELEMETRY_SOURCE_UNAVAILABLE"
		if errors.Is(e, store.ErrTelemetrySource) || errors.Is(e, store.ErrTelemetryConflict) || strings.Contains(e.Error(), "BINDING") || strings.Contains(e.Error(), "INVALID") || strings.Contains(e.Error(), "LIMIT") || strings.Contains(e.Error(), "UNSUPPORTED") || strings.Contains(e.Error(), "MISMATCH") || strings.Contains(e.Error(), "FORBIDDEN") {
			status, reason = "BLOCKED", "TELEMETRY_SOURCE_OR_QUERY_INVALID"
		}
		if code := safeTelemetryReason(e); code != "" {
			reason = code
		}
	}
	// Finish under the parent context so an expired collection budget can still
	// durably schedule its retry. The lease token prevents a stale worker finish.
	retry := int64(30 + len(model.String(job, "id"))%17)
	attempt := model.Number(job, "attempts")
	for i := int64(1); i < attempt && retry < 1800; i++ {
		retry *= 2
	}
	if retry > 3600 {
		retry = 3600
	}
	_ = s.Store.Do(ctx, tenant, func(t *store.Tx) error {
		_, e := t.TelemetrySyncFinish(ctx, model.String(job, "id"), model.String(job, "lease_token"), model.Document{"status": status, "reason_code": reason, "receipt_ids": ids, "retry_after_seconds": retry})
		return e
	})
}
func safeTelemetryReason(e error) string {
	if e == nil {
		return ""
	}
	v := e.Error()
	if len(v) > 128 || !strings.HasPrefix(v, "TELEMETRY_") {
		return ""
	}
	for _, c := range v {
		if c != '_' && (c < 'A' || c > 'Z') {
			return ""
		}
	}
	return v
}
