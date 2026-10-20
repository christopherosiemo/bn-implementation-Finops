package objectstorage

// Historical collector reports are not activity-ingress receipts. They are
// accepted only behind the independently commissioned versioned archive and
// private approved writer/definition boundary. Full minute accounting is
// derived here; the report cannot assert completeness, coldness or tier shares.
import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/big"
	"regexp"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

const AppAccessReportType = "APP_ACCESS"
const AppAccessReportUnit = "s3-get-requests-and-bytes"

type appAccessDefinition struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	Unit    string `json:"unit"`
}

type appAccessHeader struct {
	SchemaVersion            string              `json:"schema_version"`
	Kind                     string              `json:"kind"`
	AccountID                string              `json:"account_id"`
	Region                   string              `json:"region"`
	Bucket                   string              `json:"bucket"`
	DatasetID                string              `json:"dataset_id"`
	DatasetVersion           int64               `json:"dataset_version"`
	MetricDefinition         appAccessDefinition `json:"metric_definition"`
	PopulationSHA256         string              `json:"population_sha256"`
	IntervalStart            time.Time           `json:"interval_start"`
	IntervalEnd              time.Time           `json:"interval_end"`
	AuthoritativeAccessScope bool                `json:"authoritative_access_scope"`
}

type appAccessMinute struct {
	Sequence       int64     `json:"sequence"`
	IntervalStart  time.Time `json:"interval_start"`
	IntervalEnd    time.Time `json:"interval_end"`
	GetRequests    string    `json:"get_requests"`
	RetrievedBytes string    `json:"retrieved_bytes"`
	Heartbeat      bool      `json:"heartbeat"`
}

type appAccessDay struct {
	requests, bytes      *big.Int
	minutes, first, last int64
	hash                 hash.Hash
}

func appAccessUnique(d *json.Decoder, depth int) error {
	if depth > 16 {
		return errors.New("S3_APP_ACCESS_JSON_DEPTH")
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || seen[name] {
				return errors.New("S3_APP_ACCESS_DUPLICATE_FIELD")
			}
			seen[name] = true
			if err = appAccessUnique(d, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for d.More() {
			if err := appAccessUnique(d, depth+1); err != nil {
				return err
			}
		}
	default:
		return errors.New("S3_APP_ACCESS_JSON_INVALID")
	}
	_, err = d.Token()
	return err
}

func appAccessDecode(raw []byte, out any, required []string) error {
	if len(raw) == 0 || len(raw) > 16<<10 {
		return errors.New("S3_APP_ACCESS_LINE_BOUND")
	}
	unique := json.NewDecoder(bytes.NewReader(raw))
	unique.UseNumber()
	if err := appAccessUnique(unique, 0); err != nil {
		return err
	}
	if _, err := unique.Token(); err != io.EOF {
		return errors.New("S3_APP_ACCESS_ONE_JSON_OBJECT_REQUIRED")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return errors.New("S3_APP_ACCESS_OBJECT_REQUIRED")
	}
	for _, key := range required {
		value, ok := fields[key]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return errors.New("S3_APP_ACCESS_EXPLICIT_FIELDS_REQUIRED")
		}
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return errors.New("S3_APP_ACCESS_TYPED_FIELDS_INVALID")
	}
	return nil
}

// ParseAppAccess streams up to366complete days. It emits bounded daily facts
// with the hash of the actual minute population. An independently inventoried
// population must match dataset/version/hash before the caller attaches these
// observations to any cohort. No raw object identities enter PostgreSQL.
func ParseAppAccess(reader io.Reader, registration Registration, now time.Time, approvedDefinitionID string, approvedDefinitionVersions ...string) (model.Document, error) {
	if reader == nil || approvedDefinitionID == "" || len(approvedDefinitionVersions) != 1 || approvedDefinitionVersions[0] == "" || ValidateScope(Scope{registration.TenantID, registration.AccountID, registration.Region}) != nil || registration.ReportType != AppAccessReportType {
		return nil, errors.New("S3_APP_ACCESS_APPROVED_DEFINITION_REQUIRED")
	}
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), 16<<10)
	if !scanner.Scan() {
		return nil, errors.New("S3_APP_ACCESS_HEADER_REQUIRED")
	}
	var header appAccessHeader
	if err := appAccessDecode(scanner.Bytes(), &header, []string{"schema_version", "kind", "account_id", "region", "bucket", "dataset_id", "dataset_version", "metric_definition", "population_sha256", "interval_start", "interval_end", "authoritative_access_scope"}); err != nil {
		return nil, err
	}
	knownDataset := false
	for _, dataset := range registration.Datasets {
		knownDataset = knownDataset || dataset.ID == header.DatasetID
	}
	if header.SchemaVersion != "1" || header.Kind != "S3_APPLICATION_ACCESS_HISTORY" || header.AccountID != registration.AccountID || header.Region != registration.Region || header.Bucket != registration.Bucket || !knownDataset || header.DatasetVersion < 1 || !header.AuthoritativeAccessScope || header.MetricDefinition.ID != approvedDefinitionID || header.MetricDefinition.Version != approvedDefinitionVersions[0] || header.MetricDefinition.Unit != AppAccessReportUnit || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(header.PopulationSHA256) {
		return nil, errors.New("S3_APP_ACCESS_SCOPE_OR_DEFINITION_MISMATCH")
	}
	leftOffset, rightOffset := 0, 0
	_, leftOffset = header.IntervalStart.Zone()
	_, rightOffset = header.IntervalEnd.Zone()
	span := header.IntervalEnd.Sub(header.IntervalStart)
	if leftOffset != 0 || rightOffset != 0 || !header.IntervalStart.Equal(header.IntervalStart.UTC().Truncate(24*time.Hour)) || !header.IntervalEnd.Equal(header.IntervalEnd.UTC().Truncate(24*time.Hour)) || span < 24*time.Hour || span > 366*24*time.Hour || header.IntervalEnd.After(now.UTC().Truncate(24*time.Hour)) || now.Sub(header.IntervalEnd) > 48*time.Hour {
		return nil, errors.New("S3_APP_ACCESS_COMPLETE_CURRENT_DAYS_REQUIRED")
	}
	countPattern := regexp.MustCompile(`^(0|[1-9][0-9]{0,25})$`)
	requests, retrieved := new(big.Int), new(big.Int)
	quantityLimit := new(big.Int).Exp(big.NewInt(10), big.NewInt(26), nil)
	minuteHash, cursor, previous, count := sha256.New(), header.IntervalStart, int64(0), int64(0)
	dayKeys := []string{}
	days := map[string]*appAccessDay{}
	for scanner.Scan() {
		var row appAccessMinute
		if err := appAccessDecode(scanner.Bytes(), &row, []string{"sequence", "interval_start", "interval_end", "get_requests", "retrieved_bytes", "heartbeat"}); err != nil {
			return nil, err
		}
		_, leftOffset = row.IntervalStart.Zone()
		_, rightOffset = row.IntervalEnd.Zone()
		if row.Sequence < 1 || previous != 0 && row.Sequence != previous+1 || !row.IntervalStart.Equal(cursor) || row.IntervalEnd.Sub(row.IntervalStart) != time.Minute || row.IntervalEnd.After(header.IntervalEnd) || leftOffset != 0 || rightOffset != 0 || !row.Heartbeat || !countPattern.MatchString(row.GetRequests) || !countPattern.MatchString(row.RetrievedBytes) || row.GetRequests == "0" && row.RetrievedBytes != "0" {
			return nil, errors.New("S3_APP_ACCESS_GAP_CONFLICT_OR_UNKNOWN_MINUTE")
		}
		q, _ := new(big.Int).SetString(row.GetRequests, 10)
		b, _ := new(big.Int).SetString(row.RetrievedBytes, 10)
		requests.Add(requests, q)
		retrieved.Add(retrieved, b)
		if requests.Cmp(quantityLimit) >= 0 || retrieved.Cmp(quantityLimit) >= 0 {
			return nil, errors.New("S3_APP_ACCESS_DECIMAL_STORAGE_BOUND")
		}
		date := row.IntervalStart.UTC().Format("2006-01-02")
		day := days[date]
		if day == nil {
			day = &appAccessDay{requests: new(big.Int), bytes: new(big.Int), hash: sha256.New(), first: row.Sequence}
			days[date] = day
			dayKeys = append(dayKeys, date)
		}
		canonical, _ := json.Marshal(row)
		fmt.Fprintf(minuteHash, "%d:", len(canonical))
		_, _ = minuteHash.Write(canonical)
		fmt.Fprintf(day.hash, "%d:", len(canonical))
		_, _ = day.hash.Write(canonical)
		day.requests.Add(day.requests, q)
		day.bytes.Add(day.bytes, b)
		day.minutes++
		day.last = row.Sequence
		cursor, previous = row.IntervalEnd, row.Sequence
		count++
		if count > 366*1440 {
			return nil, errors.New("S3_APP_ACCESS_MINUTE_BOUND")
		}
	}
	if scanner.Err() != nil || !cursor.Equal(header.IntervalEnd) || count != int64(span/time.Minute) {
		return nil, errors.New("S3_APP_ACCESS_REPORT_INCOMPLETE")
	}
	observations := []model.Document{}
	for _, date := range dayKeys {
		day := days[date]
		if day.minutes != 1440 {
			return nil, errors.New("S3_APP_ACCESS_DAY_INCOMPLETE")
		}
		observations = append(observations, model.Document{"date": date, "bucket": registration.Bucket, "dataset_id": header.DatasetID, "dataset_version": header.DatasetVersion,
			"get_requests": day.requests.String(), "retrieved_bytes": day.bytes.String(), "native_period_seconds": 60, "aggregate_period_seconds": 86400,
			"statistic": "SUM_OF_AUTHENTICATED_ONE_MINUTE_OBSERVATIONS", "observed_minutes": day.minutes, "sequence_first": day.first, "sequence_last": day.last,
			"minute_population_sha256": hex.EncodeToString(day.hash.Sum(nil))})
	}
	var cold, tiers any
	if requests.Sign() == 0 && retrieved.Sign() == 0 {
		// This is a whole independently matched dataset zero, not an inferred
		// zero for unobserved prefixes or an age-based coldness assertion.
		cold = "1"
		selected := "FREQUENT"
		if span >= 90*24*time.Hour {
			selected = "ARCHIVE_INSTANT"
		} else if span >= 30*24*time.Hour {
			selected = "INFREQUENT"
		}
		tierMap := model.Document{}
		for _, tier := range []string{"FREQUENT", "INFREQUENT", "ARCHIVE_INSTANT", "ARCHIVE", "DEEP_ARCHIVE"} {
			if tier == selected {
				tierMap[tier] = "1"
			} else {
				tierMap[tier] = "0"
			}
		}
		tiers = tierMap
	}
	return model.Document{"state": "ACCESS_PATTERN_OBSERVED", "source_type": AppAccessReportType, "complete": true, "request_accounting_complete": true,
		"start": header.IntervalStart, "end": header.IntervalEnd, "observed_days": int64(span / (24 * time.Hour)), "observed_minutes": count,
		"requests": requests.String(), "retrieved_bytes": retrieved.String(), "eligible_cold_bytes_fraction": cold, "it_tier_fractions": tiers,
		"dataset_id": header.DatasetID, "dataset_version": header.DatasetVersion, "population_sha256": header.PopulationSHA256, "metric_definition": header.MetricDefinition,
		"minute_population_sha256": hex.EncodeToString(minuteHash.Sum(nil)), "observations": observations,
		"authority_boundary":                  "PRIVATE_APPROVED_COLLECTOR_WRITER_AND_REGISTERED_DEFINITION_CUSTOMER_ADMIN_TRUST_BOUNDARY",
		"requires_inventory_population_match": true, "unknown_nonzero_object_access_distribution": requests.Sign() > 0}, nil
}
