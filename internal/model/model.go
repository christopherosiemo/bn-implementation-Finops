package model

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

type Document map[string]any

func ID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	b[6], b[8] = (b[6]&0x0f)|0x40, (b[8]&0x3f)|0x80
	h := hex.EncodeToString(b)
	return fmt.Sprintf("%s-%s-%s-%s-%s", h[:8], h[8:12], h[12:16], h[16:20], h[20:])
}
func String(d Document, k string) string { s, _ := d[k].(string); return s }
func Bool(d Document, k string) bool     { v, _ := d[k].(bool); return v }
func Number(d Document, k string) int64 {
	switch v := d[k].(type) {
	case float64:
		return int64(v)
	case int:
		return int64(v)
	case int64:
		return v
	case json.Number:
		n, _ := v.Int64()
		return n
	}
	return 0
}
func Strings(d Document, k string) []string {
	var r []string
	switch v := d[k].(type) {
	case []string:
		return v
	case []any:
		for _, x := range v {
			if s, ok := x.(string); ok {
				r = append(r, s)
			}
		}
	}
	return r
}
func Clone(d Document) Document {
	b, _ := json.Marshal(d)
	var c Document
	_ = json.Unmarshal(b, &c)
	return c
}
func Now() string { return time.Now().UTC().Format(time.RFC3339Nano) }

type Operation struct {
	Type               string `json:"type"`
	ResourceID         string `json:"resource_id"`
	ProviderResourceID string `json:"provider_resource_id"`
	Region             string `json:"region"`
	AccountID          string `json:"account_id"`
}
type Plan struct {
	SchemaVersion        string      `json:"schema_version,omitempty"`
	ReadinessID          string      `json:"readiness_id,omitempty"`
	BaselineID           string      `json:"baseline_id,omitempty"`
	MeasurementID        string      `json:"measurement_id,omitempty"`
	ActivationAt         string      `json:"activation_at,omitempty"`
	ProofSetID           string      `json:"proof_set_id,omitempty"`
	DependencyReviewID   string      `json:"dependency_review_id,omitempty"`
	DependencyGraphHash  string      `json:"dependency_graph_hash,omitempty"`
	ID                   string      `json:"id"`
	TenantID             string      `json:"tenant_id"`
	RecommendationID     string      `json:"recommendation_id"`
	ScheduleID           string      `json:"schedule_id"`
	WorkloadID           string      `json:"workload_id"`
	PolicyID             string      `json:"policy_id"`
	PolicyVersion        int64       `json:"policy_version"`
	ResourceVersion      int64       `json:"resource_version"`
	ResourceSnapshotHash string      `json:"resource_snapshot_hash"`
	RiskClass            string      `json:"risk_class"`
	Nonce                string      `json:"nonce"`
	Operations           []Operation `json:"operations"`
	CreatedAt            time.Time   `json:"created_at"`
	ExpiresAt            time.Time   `json:"expires_at"`
	StopAt               time.Time   `json:"stop_at"`
	RestoreAt            time.Time   `json:"restore_at"`
	HealthURL            string      `json:"health_url"`
	Fixture              bool        `json:"fixture"`
}
type Envelope struct {
	Plan      Plan   `json:"plan"`
	Signature string `json:"signature"`
	Algorithm string `json:"algorithm"`
}
type WorkflowInput struct {
	TenantID    string `json:"tenant_id"`
	ExecutionID string `json:"execution_id"`
	PlanID      string `json:"plan_id"`
}
type Dispatch struct {
	Envelope    Envelope `json:"envelope"`
	ExecutionID string   `json:"execution_id"`
	Operation   string   `json:"operation"`
}
type ProviderState struct {
	State   string `json:"state"`
	Healthy bool   `json:"healthy"`
	Reason  string `json:"reason,omitempty"`
}
