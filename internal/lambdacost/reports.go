package lambdacost

import (
	"encoding/json"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"math/big"
	"regexp"
	"strings"
	"time"
)

var reportLine = regexp.MustCompile(`^REPORT\s+RequestId:\s+([A-Za-z0-9-]{1,128})\s+Duration:\s+([0-9]+(?:\.[0-9]+)?)\s+ms\s+Billed Duration:\s+([0-9]+(?:\.[0-9]+)?)\s+ms\s+Memory Size:\s+([0-9]+)\s+MB\s+Max Memory Used:\s+([0-9]+)\s+MB(?:\s|$)`)
var reportInit = regexp.MustCompile(`(?:^|\s)Init Duration:\s+([0-9]+(?:\.[0-9]+)?)\s+ms(?:\s|$)`)
var streamVersion = regexp.MustCompile(`(?:^|/)\[([^\]]+)\][A-Za-z0-9_-]+$`)

func decimal(v any) (string, bool) {
	s := ""
	switch n := v.(type) {
	case string:
		s = n
	case json.Number:
		s = string(n)
	}
	if len(s) > 64 {
		return "", false
	}
	n, ok := new(big.Rat).SetString(s)
	return s, ok && n.Sign() >= 0 && n.Num().BitLen() < 256 && n.Denom().BitLen() < 256
}

// ParseReport keeps an allowlisted system-report projection only. Application
// log bodies, trace payloads and free-form error messages are never returned.
func ParseReport(scope Scope, qualifiedARN, version, format, message, stream, eventID string, at time.Time) (model.Document, error) {
	_, _, e := FunctionARN(scope, qualifiedARN)
	match := streamVersion.FindStringSubmatch(stream)
	if e != nil || len(match) != 2 || match[1] != version || at.IsZero() || len(message) > 64<<10 || eventID == "" {
		return nil, ErrEvidence
	}
	row := model.Document{"event_time": at.UTC().Format(time.RFC3339Nano), "event_time_semantics": "REPORT_COMPLETION_NOT_PROVED_INVOCATION_START", "qualified_arn": qualifiedARN, "version": version, "memory_semantics": "EXECUTION_ENVIRONMENT_HIGH_WATER_MARK", "log_event_id_hash": Hash(model.Document{"tenant": scope.TenantID, "event_id": eventID}), "log_stream_hash": Hash(model.Document{"tenant": scope.TenantID, "stream": stream}), "source_kind": format}
	request := ""
	switch format {
	case "REPORT_TEXT":
		m := reportLine.FindStringSubmatch(strings.TrimSpace(message))
		if len(m) != 6 {
			return nil, ErrEvidence
		}
		request = m[1]
		row["duration_ms"], row["billed_duration_ms"], row["memory_size_mb"], row["max_memory_used_mb"] = m[2], m[3], m[4], m[5]
		if init := reportInit.FindStringSubmatch(message); len(init) == 2 {
			row["init_duration_ms"] = init[1]
		}
	case "PLATFORM_REPORT_JSON":
		var doc model.Document
		if DecodeJSON([]byte(message), &doc) != nil || model.String(doc, "type") != "platform.report" {
			return nil, ErrEvidence
		}
		record := Document(doc["record"])
		metrics := Document(record["metrics"])
		request = model.String(record, "requestId")
		for native, key := range map[string]string{"durationMs": "duration_ms", "billedDurationMs": "billed_duration_ms", "memorySizeMB": "memory_size_mb", "maxMemoryUsedMB": "max_memory_used_mb"} {
			n, ok := decimal(metrics[native])
			if !ok {
				return nil, ErrEvidence
			}
			row[key] = n
		}
		for native, key := range map[string]string{"initDurationMs": "init_duration_ms", "restoreDurationMs": "restore_duration_ms"} {
			if v, exists := metrics[native]; exists {
				n, ok := decimal(v)
				if !ok {
					return nil, ErrEvidence
				}
				row[key] = n
			}
		}
		if observed := model.String(doc, "time"); observed != "" {
			nativeTime, err := time.Parse(time.RFC3339Nano, observed)
			if err != nil || nativeTime.Sub(at) > time.Second || at.Sub(nativeTime) > time.Second {
				return nil, ErrEvidence
			}
			row["platform_event_time"] = observed
		}
		row["status"] = record["status"]
	default:
		return nil, ErrEvidence
	}
	if request == "" || len(request) > 128 {
		return nil, ErrEvidence
	}
	for _, key := range []string{"duration_ms", "billed_duration_ms", "memory_size_mb", "max_memory_used_mb"} {
		if _, ok := decimal(row[key]); !ok {
			return nil, ErrEvidence
		}
	}
	memory, _ := new(big.Rat).SetString(row["memory_size_mb"].(string))
	used, _ := new(big.Rat).SetString(row["max_memory_used_mb"].(string))
	if !memory.IsInt() || memory.Cmp(big.NewRat(128, 1)) < 0 || memory.Cmp(big.NewRat(32768, 1)) > 0 || used.Cmp(memory) > 0 {
		return nil, ErrEvidence
	}
	row["request_id_hash"] = Hash(model.Document{"tenant": scope.TenantID, "function": qualifiedARN, "version": version, "request_id": request})
	row["row_id"] = Hash(row)
	return row, nil
}
