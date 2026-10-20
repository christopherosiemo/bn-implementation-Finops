package activity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/native"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"io"
	"math/big"
	"net/http"
	"regexp"
	"strconv"
	"time"
)

type LambdaPerformance struct {
	Auth             Validator
	Issuer, Audience string
	Archive          *native.Storage
}

var lambdaQuantity = regexp.MustCompile(`^(0|[1-9][0-9]*)(\.[0-9]{1,12})?$`)
var lambdaHash = regexp.MustCompile(`^[a-f0-9]{64}$`)
var lambdaCount = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)

// A historical benchmark is explicitly customer-attested. It never creates
// activity/SLO minute receipts or claims that the service received it earlier.
func decodeLambdaPerformance(raw []byte) (model.Document, error) {
	unique := json.NewDecoder(bytes.NewReader(raw))
	unique.UseNumber()
	if objectStorageUniqueJSON(unique) != nil {
		return nil, errors.New("LAMBDA_PERFORMANCE_INVALID")
	}
	d := model.Document{}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if dec.Decode(&d) != nil || d == nil || dec.Decode(new(any)) != io.EOF {
		return nil, errors.New("LAMBDA_PERFORMANCE_INVALID")
	}
	for k := range d {
		switch k {
		case "schema_version", "source_id", "source_version", "sequence", "point":
		default:
			return nil, errors.New("LAMBDA_PERFORMANCE_INVALID")
		}
	}
	if model.String(d, "schema_version") != "1" || model.String(d, "source_id") == "" {
		return nil, errors.New("LAMBDA_PERFORMANCE_INVALID")
	}
	n, e := strconv.ParseInt(model.String(d, "sequence"), 10, 64)
	if e != nil || n < 1 {
		return nil, errors.New("LAMBDA_PERFORMANCE_INVALID")
	}
	b, e := json.Marshal(d["point"])
	if e != nil {
		return nil, e
	}
	p := model.Document{}
	if json.Unmarshal(b, &p) != nil || p == nil {
		return nil, errors.New("LAMBDA_PERFORMANCE_INVALID")
	}
	for k, v := range p {
		switch k {
		case "binding":
			m, ok := v.(map[string]any)
			if !ok {
				return nil, errors.New("LAMBDA_PERFORMANCE_INVALID")
			}
			for key := range m {
				switch key {
				case "tenant_id", "resource_id", "workload_id", "provider", "provider_resource_id", "account_id", "region":
				default:
					return nil, errors.New("LAMBDA_PERFORMANCE_INVALID")
				}
			}
		case "qualifier", "executed_version", "code_sha256", "comparison_fingerprint", "workload_definition_id", "workload_definition_version", "workload_mix_hash", "load_profile_hash", "architecture", "measurement_start", "measurement_end":
			if str, ok := v.(string); !ok || len(str) == 0 || len(str) > 256 {
				return nil, errors.New("LAMBDA_PERFORMANCE_INVALID")
			}
		case "memory_size_mb", "invocations", "successful_work", "errors", "throttles", "total_duration_ms", "total_billed_duration_ms", "p95_duration_ms", "p99_duration_ms", "max_memory_used_mb", "peak_concurrent_executions", "p95_application_latency_ms", "cold_start_p95_ms":
			if v == nil {
				continue
			}
			str, ok := v.(string)
			if !ok || len(str) > 40 || !lambdaQuantity.MatchString(str) {
				return nil, errors.New("LAMBDA_PERFORMANCE_INVALID")
			}
			if k == "invocations" || k == "successful_work" || k == "errors" || k == "throttles" || k == "memory_size_mb" {
				if !lambdaCount.MatchString(str) {
					return nil, errors.New("LAMBDA_PERFORMANCE_INVALID")
				}
			}
		default:
			return nil, errors.New("LAMBDA_PERFORMANCE_INVALID")
		}
	}
	for _, k := range []string{"qualifier", "executed_version", "code_sha256", "comparison_fingerprint", "workload_definition_id", "workload_definition_version", "workload_mix_hash", "load_profile_hash", "architecture", "memory_size_mb", "invocations", "successful_work", "errors", "throttles", "total_duration_ms", "total_billed_duration_ms", "p95_duration_ms", "p99_duration_ms", "max_memory_used_mb", "peak_concurrent_executions", "measurement_start", "measurement_end"} {
		if model.String(p, k) == "" {
			return nil, errors.New("LAMBDA_PERFORMANCE_INVALID")
		}
	}
	for _, k := range []string{"comparison_fingerprint", "workload_mix_hash", "load_profile_hash"} {
		if !lambdaHash.MatchString(model.String(p, k)) {
			return nil, errors.New("LAMBDA_PERFORMANCE_INVALID")
		}
	}
	code := model.String(p, "code_sha256")
	decoded, decodeErr := base64.StdEncoding.DecodeString(code)
	if !lambdaHash.MatchString(code) && (decodeErr != nil || len(decoded) != 32) {
		return nil, errors.New("LAMBDA_PERFORMANCE_CODE_IDENTITY_INVALID")
	}
	if p["architecture"] != "x86_64" && p["architecture"] != "arm64" {
		return nil, errors.New("LAMBDA_PERFORMANCE_INVALID")
	}
	start, e := time.Parse(time.RFC3339Nano, model.String(p, "measurement_start"))
	end, e2 := time.Parse(time.RFC3339Nano, model.String(p, "measurement_end"))
	now := time.Now().UTC()
	if e != nil || e2 != nil || !end.After(start) || end.After(now.Add(5*time.Minute)) || start.Before(now.Add(-366*24*time.Hour)) {
		return nil, errors.New("LAMBDA_PERFORMANCE_WINDOW_INVALID")
	}
	inv, _ := new(big.Rat).SetString(model.String(p, "invocations"))
	errs, _ := new(big.Rat).SetString(model.String(p, "errors"))
	billed, _ := new(big.Rat).SetString(model.String(p, "total_billed_duration_ms"))
	duration, _ := new(big.Rat).SetString(model.String(p, "total_duration_ms"))
	success, _ := new(big.Rat).SetString(model.String(p, "successful_work"))
	p95, _ := new(big.Rat).SetString(model.String(p, "p95_duration_ms"))
	p99, _ := new(big.Rat).SetString(model.String(p, "p99_duration_ms"))
	used, _ := new(big.Rat).SetString(model.String(p, "max_memory_used_mb"))
	memory, _ := strconv.Atoi(model.String(p, "memory_size_mb"))
	if memory < 128 || memory > 10240 || inv.Sign() <= 0 || success.Sign() <= 0 || p95.Cmp(p99) > 0 || used.Cmp(big.NewRat(int64(memory), 1)) > 0 || errs.Cmp(inv) > 0 || billed.Cmp(duration) < 0 {
		return nil, errors.New("LAMBDA_PERFORMANCE_QUANTITIES_INVALID")
	}
	d["point"] = p
	return d, nil
}
func lambdaPointBinding(p model.Document) model.Document {
	raw, _ := json.Marshal(p["binding"])
	d := model.Document{}
	_ = json.Unmarshal(raw, &d)
	return d
}

func (s *Server) lambdaPerformance(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		failure(w, 405, "METHOD_NOT_ALLOWED")
		return
	}
	cfg := s.LambdaPerformance
	if cfg == nil || cfg.Auth == nil || cfg.Archive == nil {
		failure(w, 503, "LAMBDA_PERFORMANCE_INGRESS_NOT_COMMISSIONED")
		return
	}
	identity, e := cfg.Auth.Validate(r)
	if e != nil || identity.Tenant == "" || identity.Subject == "" {
		failure(w, 401, "LAMBDA_MACHINE_AUTHENTICATION_REQUIRED")
		return
	}
	key := r.Header.Get("Idempotency-Key")
	if len(key) < 1 || len(key) > 200 {
		failure(w, 400, "IDEMPOTENCY_KEY_REQUIRED")
		return
	}
	if r.Header.Get("Content-Type") != "application/json" {
		failure(w, 415, "JSON_REQUIRED")
		return
	}
	raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 16<<10))
	if e != nil {
		failure(w, 413, "LAMBDA_PERFORMANCE_BODY_TOO_LARGE")
		return
	}
	d, e := decodeLambdaPerformance(raw)
	if e != nil {
		failure(w, 422, e.Error())
		return
	}
	point := d["point"].(model.Document)
	binding := lambdaPointBinding(point)
	resource := model.String(binding, "resource_id")
	source := model.String(d, "source_id")
	hash := sha256.Sum256(raw)
	digest := hex.EncodeToString(hash[:])
	var old model.Document
	var replay bool
	validate := func(ctx context.Context, t *store.Tx) error {
		src, e := t.LambdaPerformanceSource(ctx, source)
		if e != nil {
			return e
		}
		version := model.Number(d, "source_version")
		if v, ok := d["source_version"].(json.Number); ok {
			version, _ = v.Int64()
		}
		if !model.Bool(src, "enabled") || model.String(src, "kind") != "AWS_LAMBDA_PERFORMANCE_CURVE_V1" || model.Number(src, "version") != version || src["issuer"] != cfg.Issuer || src["audience"] != cfg.Audience || src["subject"] != identity.Subject || binding["tenant_id"] != identity.Tenant || binding["provider"] != "AWS" || src["account_id"] != binding["account_id"] || src["region"] != binding["region"] || src["function_arn"] != binding["provider_resource_id"] || src["qualifier"] != point["qualifier"] {
			return errors.New("LAMBDA_PERFORMANCE_SOURCE_NOT_AUTHORIZED")
		}
		res, e := t.LambdaPerformanceResource(ctx, resource)
		if e != nil {
			return e
		}
		if model.String(res, "resource_type") != "LAMBDA_FUNCTION" || res["provider_resource_id"] != binding["provider_resource_id"] || res["account_id"] != binding["account_id"] || res["region"] != binding["region"] || res["workload_id"] != binding["workload_id"] {
			return errors.New("LAMBDA_PERFORMANCE_SOURCE_NOT_AUTHORIZED")
		}
		d["source_version"] = version
		old, replay, e = t.LambdaPerformanceReplay(ctx, source, key, model.String(d, "sequence"), digest)
		return e
	}
	e = s.Store.Do(r.Context(), identity.Tenant, func(t *store.Tx) error { return validate(r.Context(), t) })
	if e != nil {
		if errors.Is(e, store.ErrConflict) {
			failure(w, 409, "LAMBDA_PERFORMANCE_REPLAY_CONFLICT")
		} else {
			failure(w, 403, "LAMBDA_PERFORMANCE_SOURCE_NOT_AUTHORIZED")
		}
		return
	}
	if replay {
		response(w, 200, old)
		return
	}
	archive, e := cfg.Archive.Archive(r.Context(), identity.Tenant, "wire", "lambda-performance-"+digest, raw)
	if e != nil {
		failure(w, 503, "LAMBDA_PERFORMANCE_ARCHIVE_UNAVAILABLE")
		return
	}
	again, e := cfg.Archive.Read(r.Context(), identity.Tenant, archive)
	if e != nil || !bytes.Equal(again, raw) {
		failure(w, 503, "LAMBDA_PERFORMANCE_ARCHIVE_READBACK_FAILED")
		return
	}
	analytics, e := cfg.Archive.WriteLambdaPerformance(r.Context(), identity.Tenant, source, digest, []model.Document{point})
	if e != nil {
		failure(w, 503, "LAMBDA_PERFORMANCE_ANALYTICS_UNAVAILABLE")
		return
	}
	receipt := model.Document{"schema_version": "1", "id": model.ID(), "resource_id": resource, "qualifier": point["qualifier"], "source_id": source, "source_version": d["source_version"], "sequence": d["sequence"], "body_hash": digest, "idempotency_key": key, "issuer": cfg.Issuer, "audience": cfg.Audience, "subject": identity.Subject, "point": point, "archive": archive, "analytics": analytics}
	e = s.Store.Do(r.Context(), identity.Tenant, func(t *store.Tx) error {
		if e := validate(r.Context(), t); e != nil {
			return e
		}
		var e error
		receipt, e = t.LambdaPerformanceAppend(r.Context(), receipt)
		return e
	})
	if e != nil {
		if errors.Is(e, store.ErrConflict) {
			failure(w, 409, "LAMBDA_PERFORMANCE_REPLAY_CONFLICT")
		} else {
			failure(w, 503, "LAMBDA_PERFORMANCE_RECEIPT_UNAVAILABLE")
		}
		return
	}
	response(w, 201, receipt)
}
