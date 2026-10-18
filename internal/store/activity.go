package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/jackc/pgx/v5"
)

var ErrActivityConflict = errors.New("activity replay conflicts with immutable evidence")
var ErrActivityOrder = errors.New("activity sequence or interval is not newer")
var ErrActivitySource = errors.New("activity source identity or binding is invalid")

type ActivityMetric struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	Unit    string `json:"unit"`
}
type ActivitySource struct {
	ID                 string         `json:"id"`
	WorkloadID         string         `json:"workload_id"`
	ResourceID         string         `json:"resource_id"`
	ProviderResourceID string         `json:"provider_resource_id"`
	AccountID          string         `json:"account_id"`
	Region             string         `json:"region"`
	Issuer             string         `json:"issuer"`
	Subject            string         `json:"subject"`
	MetricDefinition   ActivityMetric `json:"metric_definition"`
	Enabled            bool           `json:"enabled"`
}
type ActivityInterval struct {
	SchemaVersion    string         `json:"schema_version"`
	SourceID         string         `json:"source_id"`
	WorkloadID       string         `json:"workload_id"`
	ResourceID       string         `json:"resource_id"`
	Sequence         int64          `json:"sequence"`
	IntervalStart    time.Time      `json:"interval_start"`
	IntervalEnd      time.Time      `json:"interval_end"`
	MetricDefinition ActivityMetric `json:"metric_definition"`
	Accepted         int64          `json:"accepted"`
	Completed        int64          `json:"completed"`
	Rejected         int64          `json:"rejected"`
	Backlog          int64          `json:"backlog"`
	Inflight         int64          `json:"inflight"`
	Heartbeat        bool           `json:"heartbeat"`
	Incident         string         `json:"incident"`
	Deployment       string         `json:"deployment"`
	Job              string         `json:"job"`
}
type ActivityReceipt struct {
	ActivityInterval
	ID                  string         `json:"id"`
	TenantID            string         `json:"tenant_id"`
	Subject             string         `json:"subject"`
	ReceivedAt          time.Time      `json:"received_at"`
	BodySHA256          string         `json:"body_sha256"`
	IdempotencyKey      string         `json:"idempotency_key"`
	PreviousIntervalEnd *time.Time     `json:"previous_interval_end,omitempty"`
	PreviousSequence    int64          `json:"previous_sequence,omitempty"`
	PreviousIdle        bool           `json:"previous_idle"`
	Binding             model.Document `json:"binding"`
}
type ActivitySubmission struct {
	Interval                        ActivityInterval
	RawBody                         []byte
	Issuer, Subject, IdempotencyKey string
}

func (t *Tx) ActivityRegister(ctx context.Context, source ActivitySource) (ActivitySource, error) {
	if source.ID == "" {
		source.ID = model.ID()
	}
	if source.WorkloadID == "" || source.ResourceID == "" || source.ProviderResourceID == "" || len(source.AccountID) != 12 || source.Region != "eu-west-1" || source.Issuer == "" || source.Subject == "" || source.MetricDefinition.ID == "" || source.MetricDefinition.Version == "" || source.MetricDefinition.Unit == "" {
		return source, ErrActivitySource
	}
	for _, c := range source.AccountID {
		if c < '0' || c > '9' {
			return source, ErrActivitySource
		}
	}
	data, err := json.Marshal(source)
	if err != nil {
		return source, err
	}
	_, err = t.Exec(ctx, `INSERT INTO activity_sources(tenant_id,id,resource_id,workload_id,issuer,subject,document) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(tenant_id,id) DO NOTHING`, t.Tenant, source.ID, source.ResourceID, source.WorkloadID, source.Issuer, source.Subject, data)
	if err != nil {
		return source, err
	}
	existing, err := t.ActivitySource(ctx, source.ID)
	if err == nil && existing != source {
		return source, ErrActivityConflict
	}
	return existing, err
}
func (t *Tx) ActivitySource(ctx context.Context, id string) (ActivitySource, error) {
	var source ActivitySource
	var raw []byte
	err := t.QueryRow(ctx, `SELECT document FROM activity_sources WHERE tenant_id=$1 AND id=$2`, t.Tenant, id).Scan(&raw)
	if err != nil {
		return source, err
	}
	err = json.Unmarshal(raw, &source)
	return source, err
}
func (t *Tx) ActivitySources(ctx context.Context) ([]ActivitySource, error) {
	rows, err := t.Query(ctx, `SELECT document FROM activity_sources WHERE tenant_id=$1 ORDER BY created_at,id`, t.Tenant)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ActivitySource{}
	for rows.Next() {
		var raw []byte
		var source ActivitySource
		if err = rows.Scan(&raw); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(raw, &source); err != nil {
			return nil, err
		}
		out = append(out, source)
	}
	return out, rows.Err()
}

// ActivityAppend takes the receive timestamp from PostgreSQL, never the sender.
// A source lock makes ordering, sequence replay and interval replay atomic.
func (t *Tx) ActivityAppend(ctx context.Context, submission ActivitySubmission) (ActivityReceipt, bool, error) {
	var receipt ActivityReceipt
	in := submission.Interval
	var bodyInterval ActivityInterval
	if err := json.Unmarshal(submission.RawBody, &bodyInterval); err != nil {
		return receipt, false, ErrActivitySource
	}
	canonicalBody, _ := json.Marshal(bodyInterval)
	canonicalInput, _ := json.Marshal(in)
	if !bytes.Equal(canonicalBody, canonicalInput) {
		return receipt, false, ErrActivitySource
	}
	if submission.IdempotencyKey == "" || len(submission.IdempotencyKey) > 200 {
		return receipt, false, ErrActivityConflict
	}
	if _, err := t.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, t.Tenant+":activity:"+in.SourceID); err != nil {
		return receipt, false, err
	}
	source, err := t.ActivitySource(ctx, in.SourceID)
	if err != nil {
		return receipt, false, err
	}
	if !source.Enabled || source.Subject != submission.Subject || source.Issuer != submission.Issuer || source.ResourceID != in.ResourceID || source.WorkloadID != in.WorkloadID || source.MetricDefinition != in.MetricDefinition {
		return receipt, false, ErrActivitySource
	}
	hash := sha256.Sum256(submission.RawBody)
	digest := hex.EncodeToString(hash[:])
	var raw []byte
	err = t.QueryRow(ctx, `SELECT document FROM activity_receipts WHERE tenant_id=$1 AND source_id=$2 AND (sequence=$3 OR interval_start=$4 OR idempotency_key=$5) ORDER BY sequence DESC LIMIT 1`, t.Tenant, in.SourceID, in.Sequence, in.IntervalStart, submission.IdempotencyKey).Scan(&raw)
	if err == nil {
		if err = json.Unmarshal(raw, &receipt); err != nil {
			return receipt, false, err
		}
		if receipt.BodySHA256 != digest || receipt.Sequence != in.Sequence || receipt.IdempotencyKey != submission.IdempotencyKey {
			return receipt, false, ErrActivityConflict
		}
		return receipt, true, nil
	}
	if err != pgx.ErrNoRows {
		return receipt, false, err
	}
	var received time.Time
	if err = t.QueryRow(ctx, `SELECT activity_receive_time()`).Scan(&received); err != nil {
		return receipt, false, err
	}
	if in.SchemaVersion != "1" || in.Sequence < 1 || in.IntervalEnd.Sub(in.IntervalStart) != time.Minute || in.IntervalStart.Second() != 0 || in.IntervalStart.Nanosecond() != 0 || in.IntervalEnd.After(received.Add(5*time.Second)) || received.Sub(in.IntervalEnd) > 2*time.Minute {
		return receipt, false, ErrActivityOrder
	}
	if in.Accepted < 0 || in.Completed < 0 || in.Rejected < 0 || in.Backlog < 0 || in.Inflight < 0 {
		return receipt, false, ErrActivitySource
	}
	for _, state := range []string{in.Incident, in.Deployment, in.Job} {
		if state != "CLEAR" && state != "ACTIVE" && state != "UNKNOWN" {
			return receipt, false, ErrActivitySource
		}
	}
	receipt = ActivityReceipt{ActivityInterval: in, ID: model.ID(), TenantID: t.Tenant, Subject: submission.Subject, ReceivedAt: received, BodySHA256: digest, IdempotencyKey: submission.IdempotencyKey, Binding: model.Document{"tenant_id": t.Tenant, "resource_id": source.ResourceID, "provider_resource_id": source.ProviderResourceID, "account_id": source.AccountID, "region": source.Region}}
	var previousEnd time.Time
	var previousSequence int64
	var previousRaw []byte
	err = t.QueryRow(ctx, `SELECT interval_end,sequence,document FROM activity_receipts WHERE tenant_id=$1 AND source_id=$2 ORDER BY sequence DESC LIMIT 1`, t.Tenant, in.SourceID).Scan(&previousEnd, &previousSequence, &previousRaw)
	if err == nil {
		if in.Sequence <= previousSequence || in.IntervalStart.Before(previousEnd) {
			return receipt, false, ErrActivityOrder
		}
		receipt.PreviousIntervalEnd = &previousEnd
		receipt.PreviousSequence = previousSequence
		var previous ActivityReceipt
		if err = json.Unmarshal(previousRaw, &previous); err != nil {
			return receipt, false, err
		}
		receipt.PreviousIdle = previous.Heartbeat && previous.Incident == "CLEAR" && previous.Deployment == "CLEAR" && previous.Job == "CLEAR" && previous.Accepted == 0 && previous.Completed == 0 && previous.Rejected == 0 && previous.Backlog == 0 && previous.Inflight == 0
	} else if err != pgx.ErrNoRows {
		return receipt, false, err
	}
	data, err := json.Marshal(receipt)
	if err != nil {
		return receipt, false, err
	}
	_, err = t.Exec(ctx, `INSERT INTO activity_receipts(tenant_id,id,source_id,resource_id,sequence,interval_start,interval_end,received_at,body_sha256,idempotency_key,document,raw_body) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, t.Tenant, receipt.ID, in.SourceID, in.ResourceID, in.Sequence, in.IntervalStart, in.IntervalEnd, received, digest, submission.IdempotencyKey, data, submission.RawBody)
	return receipt, false, err
}
func (t *Tx) ActivityLatest(ctx context.Context, resourceID string) (ActivityReceipt, error) {
	var receipt ActivityReceipt
	var raw []byte
	err := t.QueryRow(ctx, `SELECT r.document FROM activity_receipts r JOIN activity_sources s ON s.tenant_id=r.tenant_id AND s.id=r.source_id WHERE r.tenant_id=$1 AND r.resource_id=$2 AND (s.document->>'enabled')::boolean ORDER BY r.interval_end DESC,r.received_at DESC LIMIT 1`, t.Tenant, resourceID).Scan(&raw)
	if err != nil {
		return receipt, err
	}
	err = json.Unmarshal(raw, &receipt)
	return receipt, err
}
func (t *Tx) ActivitySamples(ctx context.Context, resourceID string, start, end time.Time) ([]model.Document, error) {
	rows, err := t.Query(ctx, `SELECT document FROM activity_receipts WHERE tenant_id=$1 AND resource_id=$2 AND interval_start >= $3 AND interval_end <= $4 ORDER BY interval_start,received_at`, t.Tenant, resourceID, start, end)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Document{}
	for rows.Next() {
		var raw []byte
		var receipt ActivityReceipt
		if err = rows.Scan(&raw); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(raw, &receipt); err != nil {
			return nil, err
		}
		d := model.Document{}
		if err = json.Unmarshal(raw, &d); err != nil {
			return nil, err
		}
		d["start"], d["end"], d["units"], d["receipt_id"], d["source_provenance"] = receipt.IntervalStart.UTC().Format(time.RFC3339), receipt.IntervalEnd.UTC().Format(time.RFC3339), strconv.FormatInt(receipt.Accepted, 10), receipt.ID, "INDEPENDENT_ACTIVITY"
		d["accepted"], d["completed"], d["rejected"], d["backlog"], d["inflight"] = strconv.FormatInt(receipt.Accepted, 10), strconv.FormatInt(receipt.Completed, 10), strconv.FormatInt(receipt.Rejected, 10), strconv.FormatInt(receipt.Backlog, 10), strconv.FormatInt(receipt.Inflight, 10)
		for k, v := range receipt.Binding {
			d[k] = v
		}
		out = append(out, d)
	}
	return out, rows.Err()
}
func ActivityConflict(err error) bool {
	return errors.Is(err, ErrActivityConflict) || errors.Is(err, ErrActivityOrder) || errors.Is(err, ErrActivitySource)
}
func (s ActivitySource) String() string { return fmt.Sprintf("%s/%s", s.ResourceID, s.ID) }
