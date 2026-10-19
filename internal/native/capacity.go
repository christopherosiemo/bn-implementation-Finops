package native

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/telemetry"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/workload"
)

// CapacityInputRequest is private control-plane input. Neither observations,
// source URLs, provider capacities nor prices can be supplied through it.
type CapacityInputRequest struct {
	TenantID             string `json:"tenant_id"`
	ConnectionID         string `json:"connection_id"`
	ConfigHash           string `json:"config_hash"`
	SafetyProfileID      string `json:"safety_profile_id"`
	SafetyProfileVersion int64  `json:"safety_profile_version"`
}

type CapacityReceiptRef struct {
	ReceiptID     string `json:"receipt_id"`
	BatchID       string `json:"batch_id"`
	ConfigHash    string `json:"config_hash"`
	RawSHA256     string `json:"raw_sha256"`
	CanonicalHash string `json:"canonical_hash"`
}

// CapacityPopulation preserves actual native intervals. A SUM value remains
// its interval delta, a gauge remains an observed sample, and UNKNOWN/RESET
// intervals remain visible. A later server adapter needs registered physical
// denominators before converting ratios to absolute resource demand.
type CapacityPopulation struct {
	SchemaVersion        string                 `json:"schema_version"`
	Binding              telemetry.Binding      `json:"binding"`
	ConnectionID         string                 `json:"connection_id"`
	ConnectionVersion    int64                  `json:"connection_version"`
	ConfigHash           string                 `json:"config_hash"`
	SafetyProfileID      string                 `json:"safety_profile_id"`
	SafetyProfileVersion int64                  `json:"safety_profile_version"`
	SafetyProfileHash    string                 `json:"safety_profile_hash"`
	AsOf                 time.Time              `json:"as_of"`
	Start                time.Time              `json:"start"`
	End                  time.Time              `json:"end"`
	HistoryDays          int                    `json:"history_days"`
	Timezone             string                 `json:"timezone"`
	Environment          string                 `json:"environment"`
	Definitions          []telemetry.Definition `json:"definitions"`
	Segments             []telemetry.Segment    `json:"segments"`
	ReceiptIDs           []string               `json:"receipt_ids"`
	SourceRefs           []CapacityReceiptRef   `json:"source_refs"`
	ReasonCodes          []string               `json:"reason_codes"`
	Evaluation           telemetry.Evaluation   `json:"evaluation"`
	PopulationHash       string                 `json:"population_hash"`
}

func CapacityPopulationHash(population CapacityPopulation) string {
	population.PopulationHash = ""
	return telemetry.Hash(population)
}

// capacityPopulationWire hashes one encoding of the freshly resolved population,
// then reuses those exact bytes for the response. The hash field is last in the
// typed wire contract; its empty value is the existing PopulationHash preimage.
// No derived proof is accepted from callers or cached between requests.
func capacityPopulationWire(population CapacityPopulation) ([]byte, error) {
	population.PopulationHash = ""
	raw, err := json.Marshal(population)
	if err != nil {
		return nil, err
	}
	if !bytes.HasSuffix(raw, []byte(`,"population_hash":""}`)) {
		return nil, errors.New("CAPACITY_POPULATION_WIRE_INVALID")
	}
	digest := telemetry.BytesHash(raw)
	raw = append(raw[:len(raw)-2], digest...)
	raw = append(raw, '"', '}', '\n')
	return raw, nil
}

func capacityProfile(d model.Document) (workload.Profile, error) {
	d = model.Clone(d)
	for _, key := range []string{"tenant_id", "hash", "created_at", "writer_role"} {
		delete(d, key)
	}
	raw, err := json.Marshal(d)
	if err != nil {
		return workload.Profile{}, err
	}
	return workload.Decode(raw)
}

func capacityHistory(now time.Time, profile workload.Profile) (time.Time, time.Time, int, error) {
	loc, err := time.LoadLocation(profile.Timezone)
	if err != nil {
		return time.Time{}, time.Time{}, 0, err
	}
	days := 30
	if profile.Criticality == "NON_PRODUCTION" {
		days = 14
	}
	if profile.HighSeasonality {
		days = 90
	}
	local := now.In(loc)
	end := time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, loc)
	return end.AddDate(0, 0, -days).UTC(), end.UTC(), days, nil
}

// Both wire intervals and the history summary come from one derivation of the
// request's freshly authenticated samples. No supplied or cached segment proof
// bypasses the native archive/current-source checks above this calculation.
func capacityHistoryEvidence(in telemetry.HistoryInput, start, end time.Time) ([]telemetry.Segment, telemetry.Evaluation) {
	evaluation, derived := telemetry.EvaluateHistoryWithSegments(in)
	segments := []telemetry.Segment{}
	for _, segment := range derived {
		if segment.End.After(start) && segment.Start.Before(end) {
			segments = append(segments, segment)
		}
	}
	return segments, evaluation
}

func (s *Server) capacityInput(w http.ResponseWriter, r *http.Request) {
	header := r.Header.Get("Authorization")
	token := strings.TrimPrefix(header, "Bearer ")
	if s.ReaderToken == "" || !strings.HasPrefix(header, "Bearer ") || subtle.ConstantTimeCompare([]byte(token), []byte(s.ReaderToken)) != 1 {
		nativeError(w, 401, "TELEMETRY_READER_IDENTITY_REQUIRED")
		return
	}
	var input CapacityInputRequest
	raw, err := io.ReadAll(io.LimitReader(r.Body, 8193))
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err != nil || len(raw) > 8192 || decoder.Decode(&input) != nil || decoder.Decode(&struct{}{}) != io.EOF || input.TenantID == "" || input.ConnectionID == "" || input.ConfigHash == "" || input.SafetyProfileID == "" || input.SafetyProfileVersion < 1 {
		nativeError(w, 400, "CAPACITY_SELECTION_INVALID")
		return
	}
	c, err := s.connection(r.Context(), input.TenantID, input.ConnectionID)
	if err != nil || s.Pipeline == nil || telemetry.ConfigHash(c) != input.ConfigHash {
		nativeError(w, 409, "CAPACITY_SOURCE_CHANGED")
		return
	}
	if c.Kind == "PROMETHEUS" {
		binding, ok := s.Bindings[c.ReadBindingID]
		if !ok || binding.connection(c) != nil {
			nativeError(w, 403, "TELEMETRY_READ_BINDING_MISMATCH")
			return
		}
	}
	var profileDoc model.Document
	var workloadDoc, resourceDoc model.Document
	err = s.Store.Do(r.Context(), input.TenantID, func(tx *store.Tx) error {
		var err error
		profileDoc, err = tx.WorkloadSafetyLatest(r.Context(), c.Binding.WorkloadID)
		if err != nil {
			return err
		}
		workloadDoc, err = tx.Get(r.Context(), "workloads", c.Binding.WorkloadID)
		if err != nil {
			return err
		}
		resourceDoc, err = tx.Get(r.Context(), "resources", c.Binding.ResourceID)
		return err
	})
	profile, parseErr := capacityProfile(profileDoc)
	if err != nil || parseErr != nil || profile.ID != input.SafetyProfileID || profile.Version != input.SafetyProfileVersion || profile.WorkloadID != c.Binding.WorkloadID {
		nativeError(w, 409, "CAPACITY_SAFETY_PROFILE_CHANGED")
		return
	}
	now := s.now()
	environment := "UNKNOWN"
	if model.String(workloadDoc, "environment") == "NON_PRODUCTION" && model.String(resourceDoc, "environment") == "NON_PRODUCTION" {
		environment = "NON_PRODUCTION"
	}
	if model.String(workloadDoc, "environment") == "PRODUCTION" || model.String(resourceDoc, "environment") == "PRODUCTION" {
		environment = "PRODUCTION"
	}
	historyProfile := profile
	classificationReasons := []string{}
	if environment != "NON_PRODUCTION" && profile.Criticality == "NON_PRODUCTION" {
		historyProfile.Criticality = "TIER_3"
		classificationReasons = append(classificationReasons, "CAPACITY_ENVIRONMENT_CLASSIFICATION_CONFLICT")
	}
	if environment == "UNKNOWN" {
		classificationReasons = append(classificationReasons, "CAPACITY_ENVIRONMENT_CLASSIFICATION_REQUIRED")
	}
	start, end, days, err := capacityHistory(now, historyProfile)
	if err != nil {
		nativeError(w, 422, "CAPACITY_HISTORY_POLICY_INVALID")
		return
	}
	samples, ids, reasons, err := s.samples(r.Context(), c, start, end)
	if err != nil {
		if code := safeTelemetryReason(err); strings.Contains(code, "LIMIT") {
			nativeError(w, 413, code)
		} else {
			nativeError(w, 503, "TELEMETRY_EVIDENCE_UNAVAILABLE")
		}
		return
	}
	reasons = append(reasons, classificationReasons...)
	refs := []CapacityReceiptRef{}
	err = s.Store.Do(r.Context(), input.TenantID, func(tx *store.Tx) error {
		current, err := tx.TelemetryConnection(r.Context(), c.ID)
		if err != nil || model.String(current, "config_hash") != input.ConfigHash || model.Bool(current, "revoked") || !model.Bool(current, "enabled") {
			return store.ErrTelemetrySource
		}
		latest, err := tx.WorkloadSafetyLatest(r.Context(), c.Binding.WorkloadID)
		if err != nil || model.String(latest, "id") != profile.ID || model.Number(latest, "version") != profile.Version || model.String(latest, "hash") != model.String(profileDoc, "hash") {
			return store.ErrConflict
		}
		for _, id := range ids {
			receipt, err := tx.TelemetryReceipt(r.Context(), id)
			if err != nil || !model.Bool(receipt, "active_source") || model.String(receipt, "config_hash") != input.ConfigHash {
				return store.ErrTelemetrySource
			}
			refs = append(refs, CapacityReceiptRef{ReceiptID: id, BatchID: model.String(receipt, "batch_id"), ConfigHash: input.ConfigHash, RawSHA256: model.String(receipt, "raw_sha256"), CanonicalHash: model.String(receipt, "canonical_hash")})
		}
		return nil
	})
	if err != nil {
		nativeError(w, 409, "CAPACITY_SELECTION_CHANGED")
		return
	}
	segments, evaluation := capacityHistoryEvidence(telemetry.HistoryInput{Now: now, Definitions: c.Definitions, Samples: samples, Days: days, Timezone: profile.Timezone}, start, end)
	if len(reasons) > 0 {
		evaluation.Status = "BLOCKED"
		evaluation.ReasonCodes = sortedUnique(append(evaluation.ReasonCodes, reasons...))
		evaluation.Hash = ""
		evaluation.Hash = telemetry.Hash(evaluation)
	}
	out := CapacityPopulation{SchemaVersion: "1", Binding: c.Binding, ConnectionID: c.ID, ConnectionVersion: c.Version, ConfigHash: input.ConfigHash, SafetyProfileID: profile.ID, SafetyProfileVersion: profile.Version, SafetyProfileHash: model.String(profileDoc, "hash"), AsOf: now, Start: start, End: end, HistoryDays: days, Timezone: profile.Timezone, Environment: environment, Definitions: c.Definitions, Segments: segments, ReceiptIDs: ids, SourceRefs: refs, ReasonCodes: sortedUnique(reasons), Evaluation: evaluation}
	wire, err := capacityPopulationWire(out)
	if err != nil {
		nativeError(w, 500, "CAPACITY_POPULATION_ENCODING_FAILED")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(wire)
}
