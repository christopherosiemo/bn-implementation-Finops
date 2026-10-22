// Package lambdacost preserves read-only Lambda evidence without conferring
// deployment authority or treating sparse observations as a workload census.
package lambdacost

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"io"
	"regexp"
	"strings"
	"time"
)

const NativeKind = "AWS_LAMBDA_NATIVE_V1"
const ReportsKind = "AWS_LAMBDA_REPORTS_V1"
const CurveKind = "AWS_LAMBDA_PERFORMANCE_CURVE_V1"
const MaxPageBytes = 4 << 20
const MaxCaptureBytes = 32 << 20
const MaxRows = 10000

var ErrEvidence = errors.New("LAMBDA_SCOPE_OR_EVIDENCE_UNAVAILABLE")
var part = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
var account = regexp.MustCompile(`^[0-9]{12}$`)
var region = regexp.MustCompile(`^[a-z]{2}-[a-z]+-[0-9]+$`)
var functionName = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
var qualifier = regexp.MustCompile(`^(\$LATEST(?:\.PUBLISHED)?|[A-Za-z0-9_-]{1,128})$`)

type Scope struct {
	TenantID  string `json:"tenant_id"`
	AccountID string `json:"account_id"`
	Region    string `json:"region"`
}

func ValidateScope(s Scope) error {
	if !part.MatchString(s.TenantID) || !account.MatchString(s.AccountID) || !region.MatchString(s.Region) || strings.HasPrefix(s.Region, "cn-") || strings.HasPrefix(s.Region, "us-gov-") {
		return ErrEvidence
	}
	return nil
}
func FunctionARN(s Scope, arn string) (string, string, error) {
	prefix := "arn:aws:lambda:" + s.Region + ":" + s.AccountID + ":function:"
	if ValidateScope(s) != nil || !strings.HasPrefix(arn, prefix) {
		return "", "", ErrEvidence
	}
	pieces := strings.Split(strings.TrimPrefix(arn, prefix), ":")
	if len(pieces) < 1 || len(pieces) > 2 || !functionName.MatchString(pieces[0]) {
		return "", "", ErrEvidence
	}
	q := ""
	if len(pieces) == 2 {
		q = pieces[1]
		if !qualifier.MatchString(q) {
			return "", "", ErrEvidence
		}
	}
	return prefix + pieces[0], q, nil
}
func Hash(v any) string         { b, _ := json.Marshal(v); return BytesHash(b) }
func BytesHash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func Document(v any) model.Document {
	b, _ := json.Marshal(v)
	d := model.Document{}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	_ = dec.Decode(&d)
	return d
}
func Rows(v any) []model.Document {
	b, _ := json.Marshal(v)
	out := []model.Document{}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	_ = dec.Decode(&out)
	return out
}

// DecodeJSON rejects duplicate object keys and trailing values before decoding
// numbers losslessly. Native counts must not pass through float64.
func DecodeJSON(raw []byte, out any) error {
	if len(raw) > MaxPageBytes {
		return ErrEvidence
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 64 {
			return ErrEvidence
		}
		t, e := d.Token()
		if e != nil {
			return ErrEvidence
		}
		if p, ok := t.(json.Delim); ok {
			switch p {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					k, e := d.Token()
					key, ok := k.(string)
					if e != nil || !ok || seen[key] {
						return ErrEvidence
					}
					seen[key] = true
					if e = walk(depth + 1); e != nil {
						return e
					}
				}
			case '[':
				for d.More() {
					if e = walk(depth + 1); e != nil {
						return e
					}
				}
			default:
				return ErrEvidence
			}
			_, e = d.Token()
			if e != nil {
				return ErrEvidence
			}
		}
		return nil
	}
	if walk(0) != nil || d.Decode(new(any)) != io.EOF {
		return ErrEvidence
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if d.Decode(out) != nil {
		return ErrEvidence
	}
	return nil
}

type Frame struct {
	Action           string          `json:"action"`
	Selector         string          `json:"selector"`
	RequestID        string          `json:"request_id,omitempty"`
	StatusCode       int             `json:"status_code"`
	Body             json.RawMessage `json:"body"`
	SanitizerVersion string          `json:"sanitizer_version"`
}
type Evidence struct {
	SchemaVersion    string    `json:"schema_version"`
	Scope            Scope     `json:"scope"`
	CollectedAt      time.Time `json:"collected_at"`
	RawSHA256        string    `json:"raw_sha256"`
	Raw              []byte    `json:"-"`
	ObservationBasis string    `json:"observation_basis"`
}
type Discovery struct {
	Evidence
	Functions  []model.Document `json:"functions"`
	NextMarker string           `json:"next_marker"`
	Complete   bool             `json:"complete"`
	Coverage   []model.Document `json:"coverage"`
}
type DiscoverySelection struct {
	Marker       string
	MaxFunctions int
	FunctionARN  string
}
type MetricSelection struct {
	QualifiedARN  string
	Version       string
	Start, End    time.Time
	PeriodSeconds int
	EventSources  []string
}
type Metrics struct {
	Evidence
	Selection MetricSelection  `json:"selection"`
	Rows      []model.Document `json:"rows"`
	Coverage  []model.Document `json:"coverage"`
}
type Reports struct {
	Evidence
	Rows      []model.Document `json:"rows"`
	Coverage  model.Document   `json:"coverage"`
	NextToken string           `json:"next_token"`
}
type Registration struct {
	ID                string `json:"id"`
	TenantID          string `json:"tenant_id"`
	Kind              string `json:"kind"`
	AccountID         string `json:"account_id"`
	Region            string `json:"region"`
	ReadRoleBindingID string `json:"read_role_binding_id"`
	FunctionARN       string `json:"function_arn"`
	Qualifier         string `json:"qualifier"`
	LogGroupARN       string `json:"log_group_arn,omitempty"`
	LogGroupName      string `json:"log_group_name,omitempty"`
	Format            string `json:"format,omitempty"`
	Version           int64  `json:"version"`
	Enabled           bool   `json:"enabled"`
}

func ParseRegistration(d model.Document) (Registration, error) {
	var r Registration
	b, _ := json.Marshal(d)
	if json.Unmarshal(b, &r) != nil {
		return r, ErrEvidence
	}
	return r, ValidateRegistration(d)
}
func ValidateRegistration(v any) error {
	d := Document(v)
	var r Registration
	b, _ := json.Marshal(d)
	if json.Unmarshal(b, &r) != nil {
		return ErrEvidence
	}
	s := Scope{r.TenantID, r.AccountID, r.Region}
	base, q, e := FunctionARN(s, r.FunctionARN)
	if e != nil || base != r.FunctionARN || q != "" || r.ID == "" || r.Version < 1 || !qualifier.MatchString(r.Qualifier) {
		return ErrEvidence
	}
	if r.Kind == CurveKind {
		if model.String(d, "issuer") == "" || model.String(d, "audience") == "" || model.String(d, "subject") == "" {
			return ErrEvidence
		}
		return nil
	}
	if r.Kind != NativeKind && r.Kind != ReportsKind || r.ReadRoleBindingID == "" {
		return ErrEvidence
	}
	if r.Kind == ReportsKind {
		prefix := "arn:aws:logs:" + r.Region + ":" + r.AccountID + ":log-group:"
		if !strings.HasPrefix(r.LogGroupARN, prefix) || strings.TrimSuffix(strings.TrimPrefix(r.LogGroupARN, prefix), ":*") != r.LogGroupName || r.LogGroupName == "" || strings.ContainsAny(r.LogGroupName, "\x00\r\n") || (r.Format != "REPORT_TEXT" && r.Format != "PLATFORM_REPORT_JSON") {
			return ErrEvidence
		}
	}
	return nil
}
func ConfigurationHash(configuration model.Document) string {
	d := Document(configuration)
	delete(d, "last_seen_at")
	return Hash(d)
}

// Ordinary default-compute Event Function capability, deliberately separate
// from the generic API's mixed-model memory bound.
func Model(c model.Document) string {
	if len(Document(c["CapacityProviderConfig"])) > 0 || model.String(c, "Version") == "$LATEST.PUBLISHED" {
		return "EVENT_MANAGED_INSTANCES"
	}
	if len(Document(c["DurableConfig"])) > 0 {
		return "EVENT_DURABLE"
	}
	if model.Number(c, "MemorySize") > 10240 {
		return "EVENT_CAPABILITY_UNSUPPORTED"
	}
	return "EVENT_DEFAULT"
}
