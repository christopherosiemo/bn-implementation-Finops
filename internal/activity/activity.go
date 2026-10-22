// Package activity accepts current observations from a separately authenticated,
// off-instance workload collector. It has no approval or execution authority.
package activity

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
)

func Decode(raw []byte) (store.ActivityInterval, error) {
	var interval store.ActivityInterval
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return interval, errors.New("invalid activity JSON")
	}
	for _, key := range []string{"schema_version", "source_id", "resource_id", "workload_id", "sequence", "interval_start", "interval_end", "metric_definition", "accepted", "completed", "rejected", "backlog", "inflight", "heartbeat", "incident", "deployment", "job"} {
		if value, ok := fields[key]; !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return interval, errors.New("every activity observation field is required")
		}
	}
	var definition map[string]json.RawMessage
	if err := json.Unmarshal(fields["metric_definition"], &definition); err != nil {
		return interval, errors.New("metric definition required")
	}
	for _, key := range []string{"id", "version", "unit"} {
		if _, ok := definition[key]; !ok {
			return interval, errors.New("metric definition identity,version and unit required")
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&interval); err != nil {
		return interval, errors.New("invalid activity observation types or fields")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return interval, errors.New("one activity object required")
	}
	return interval, Validate(interval)
}

// Temporal freshness is checked after replay lookup. Old exact retries must
// return their original receipt, but cannot introduce historical evidence.
func Validate(in store.ActivityInterval) error {
	if in.SchemaVersion != "1" || in.SourceID == "" || in.ResourceID == "" || in.WorkloadID == "" || in.Sequence < 1 || in.MetricDefinition.ID == "" || in.MetricDefinition.Version == "" || in.MetricDefinition.Unit == "" {
		return errors.New("complete versioned activity binding required")
	}
	if in.IntervalEnd.Sub(in.IntervalStart) != time.Minute || in.IntervalStart.Second() != 0 || in.IntervalStart.Nanosecond() != 0 {
		return errors.New("activity interval must be one complete UTC minute")
	}
	_, startOffset := in.IntervalStart.Zone()
	_, endOffset := in.IntervalEnd.Zone()
	if startOffset != 0 || endOffset != 0 {
		return errors.New("activity timestamps must use UTC")
	}
	for _, value := range []int64{in.Accepted, in.Completed, in.Rejected, in.Backlog, in.Inflight} {
		if value < 0 {
			return errors.New("activity counts and gauges must be nonnegative integers")
		}
	}
	for _, state := range []string{in.Incident, in.Deployment, in.Job} {
		if state != "CLEAR" && state != "ACTIVE" && state != "UNKNOWN" {
			return errors.New("incident,deployment and job states must be CLEAR,ACTIVE or UNKNOWN")
		}
	}
	return nil
}

type Signal struct {
	Status      string    `json:"status"`
	ReasonCode  string    `json:"reason_code"`
	ReceiptID   string    `json:"receipt_id"`
	SourceID    string    `json:"source_id"`
	ReceivedAt  time.Time `json:"received_at"`
	IntervalEnd time.Time `json:"interval_end"`
}

// FreshActivity requires two contiguous source intervals. Missing observations,
// source failure or unknown safety inputs are never interpreted as zero demand.
// ACTIVE always remains visible, even if the previous observation was a gap.
func FreshActivity(now time.Time, receipt store.ActivityReceipt, maxAge time.Duration) Signal {
	result := Signal{Status: "UNKNOWN", ReasonCode: "ACTIVITY_MISSING", ReceiptID: receipt.ID, SourceID: receipt.SourceID, ReceivedAt: receipt.ReceivedAt, IntervalEnd: receipt.IntervalEnd}
	if receipt.ID == "" {
		return result
	}
	if maxAge <= 0 || maxAge > 2*time.Minute {
		maxAge = 2 * time.Minute
	}
	if now.Before(receipt.IntervalEnd.Add(-5*time.Second)) || now.Before(receipt.ReceivedAt.Add(-5*time.Second)) || now.Sub(receipt.IntervalEnd) > maxAge || now.Sub(receipt.ReceivedAt) > maxAge {
		result.ReasonCode = "ACTIVITY_STALE"
		return result
	}
	if !receipt.Heartbeat {
		result.ReasonCode = "ACTIVITY_HEARTBEAT_MISSING"
		return result
	}
	for _, state := range []string{receipt.Incident, receipt.Deployment, receipt.Job} {
		if state == "ACTIVE" {
			result.Status = "ACTIVE"
			result.ReasonCode = "ACTIVITY_OPERATION_ACTIVE"
			return result
		}
		if state != "CLEAR" {
			result.ReasonCode = "ACTIVITY_OPERATION_UNKNOWN"
			return result
		}
	}
	if receipt.Accepted > 0 || receipt.Completed > 0 || receipt.Rejected > 0 || receipt.Backlog > 0 || receipt.Inflight > 0 {
		result.Status = "ACTIVE"
		result.ReasonCode = "WORKLOAD_ACTIVITY_PRESENT"
		return result
	}
	if receipt.PreviousIntervalEnd == nil || !receipt.PreviousIntervalEnd.Equal(receipt.IntervalStart) || receipt.PreviousSequence+1 != receipt.Sequence {
		result.ReasonCode = "ACTIVITY_COVERAGE_GAP"
		return result
	}
	if !receipt.PreviousIdle {
		result.ReasonCode = "ACTIVITY_IDLE_WINDOW_INCOMPLETE"
		return result
	}
	result.Status = "CLEAR"
	result.ReasonCode = "RECENT_WORKLOAD_IDLE"
	return result
}
