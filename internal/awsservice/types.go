// Package awsservice contains the shared, read-only AWS service inventory contract.
// Native observations do not confer configuration, execution or financial authority.
package awsservice

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

const NativeKind = "AWS_SERVICE_NATIVE_V1"
const MaxPageBytes = 4 << 20
const MaxCaptureBytes = 32 << 20
const MaxReads = 256
const MaxRows = 10000

var ErrEvidence = errors.New("AWS_SERVICE_SCOPE_OR_EVIDENCE_UNAVAILABLE")
var account = regexp.MustCompile(`^[0-9]{12}$`)
var part = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
var region = regexp.MustCompile(`^[a-z]{2}-[a-z]+-[0-9]+$`)

var Families = []string{"ECS", "EKS", "ELASTICACHE", "DYNAMODB", "ELB"}
var ResourceTypes = []string{"ECS_CLUSTER", "ECS_SERVICE", "ECS_TASK_DEFINITION", "ECS_TASK", "ECS_CAPACITY_PROVIDER", "ECS_CONTAINER_INSTANCE", "EKS_CLUSTER", "EKS_NODE_GROUP", "EKS_FARGATE_PROFILE", "EKS_ADDON", "ELASTICACHE_REPLICATION_GROUP", "ELASTICACHE_CLUSTER", "ELASTICACHE_SERVERLESS_CACHE", "DYNAMODB_TABLE", "DYNAMODB_GSI", "LOAD_BALANCER", "ELB_LISTENER", "ELB_TARGET_GROUP"}

type Scope struct {
	TenantID  string `json:"tenant_id"`
	AccountID string `json:"account_id"`
	Region    string `json:"region"`
}
type Registration struct {
	ID                string   `json:"id"`
	TenantID          string   `json:"tenant_id"`
	AccountID         string   `json:"account_id"`
	Region            string   `json:"region"`
	ReadRoleBindingID string   `json:"read_role_binding_id"`
	Version           int64    `json:"version"`
	Enabled           bool     `json:"enabled"`
	ServiceFamilies   []string `json:"service_families"`
	ScopeMode         string   `json:"scope_mode"`
	RootResourceARNs  []string `json:"root_resource_arns"`
}
type Frame struct {
	Service          string `json:"service"`
	Action           string `json:"action"`
	Selector         string `json:"selector"`
	StatusCode       int    `json:"status_code"`
	SanitizerVersion string `json:"sanitizer_version"`
	Body             any    `json:"body"`
}
type Collection struct {
	SchemaVersion string           `json:"schema_version"`
	Scope         Scope            `json:"scope"`
	Family        string           `json:"family"`
	Resources     []model.Document `json:"resources"`
	Complete      bool             `json:"complete"`
	NextCursor    string           `json:"next_cursor"`
	Reasons       []string         `json:"reason_codes"`
	CollectedAt   time.Time        `json:"collected_at"`
	RawSHA256     string           `json:"raw_sha256"`
	Raw           []byte           `json:"-"`
}

func ValidateScope(s Scope) error {
	if !part.MatchString(s.TenantID) || !account.MatchString(s.AccountID) || !region.MatchString(s.Region) || strings.HasPrefix(s.Region, "cn-") || strings.HasPrefix(s.Region, "us-gov-") {
		return ErrEvidence
	}
	return nil
}
func ParseRegistration(d model.Document) (Registration, error) {
	r := Registration{}
	if model.String(d, "kind") != NativeKind {
		return r, ErrEvidence
	}
	b, e := json.Marshal(d)
	if e != nil {
		return r, ErrEvidence
	}
	if json.Unmarshal(b, &r) != nil {
		return r, ErrEvidence
	}
	return r, ValidateRegistration(r)
}
func ValidateRegistration(r Registration) error {
	if ValidateScope(Scope{r.TenantID, r.AccountID, r.Region}) != nil || !part.MatchString(r.ID) || r.ReadRoleBindingID == "" || len(r.ReadRoleBindingID) > 128 || r.Version < 1 || len(r.ServiceFamilies) == 0 || len(r.ServiceFamilies) > 5 || r.ScopeMode != "ACCOUNT" && r.ScopeMode != "RESOURCE" {
		return ErrEvidence
	}
	seen := map[string]bool{}
	for _, f := range r.ServiceFamilies {
		if !Contains(Families, f) || seen[f] {
			return ErrEvidence
		}
		seen[f] = true
	}
	if len(r.RootResourceARNs) > 256 || r.ScopeMode == "RESOURCE" && len(r.RootResourceARNs) == 0 || r.ScopeMode == "ACCOUNT" && len(r.RootResourceARNs) > 0 {
		return ErrEvidence
	}
	seen = map[string]bool{}
	for _, arn := range r.RootResourceARNs {
		if !BoundARN(Scope{r.TenantID, r.AccountID, r.Region}, arn) || seen[arn] {
			return ErrEvidence
		}
		p := strings.SplitN(arn, ":", 6)
		family := map[string]string{"ecs": "ECS", "eks": "EKS", "elasticache": "ELASTICACHE", "dynamodb": "DYNAMODB", "elasticloadbalancing": "ELB"}[p[2]]
		if !Contains(r.ServiceFamilies, family) || !RootARN(family, p[5]) {
			return ErrEvidence
		}
		seen[arn] = true
	}
	return nil
}
func RootARN(family, resource string) bool {
	prefixes := map[string][]string{"ECS": {"cluster/"}, "EKS": {"cluster/"}, "DYNAMODB": {"table/"}, "ELASTICACHE": {"replicationgroup:", "cluster:", "serverlesscache:"}, "ELB": {"loadbalancer/"}}
	for _, prefix := range prefixes[family] {
		if strings.HasPrefix(resource, prefix) {
			name := strings.TrimPrefix(resource, prefix)
			if name == "" || len(name) > 1024 {
				return false
			}
			if family != "ELB" && strings.ContainsAny(name, "/:") {
				return false
			}
			for _, c := range name {
				if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' || family == "ELB" && c == '/') {
					return false
				}
			}
			return true
		}
	}
	return false
}
func Contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}
func BoundARN(s Scope, arn string) bool {
	p := strings.SplitN(arn, ":", 6)
	return len(p) == 6 && p[0] == "arn" && p[1] == "aws" && p[3] == s.Region && p[4] == s.AccountID && p[5] != "" && len(arn) <= 2048 && !strings.ContainsAny(arn, "*?\x00\r\n")
}
func BytesHash(raw []byte) string { x := sha256.Sum256(raw); return hex.EncodeToString(x[:]) }
func Hash(v any) string           { b, _ := json.Marshal(v); return BytesHash(b) }
func ConfigurationHash(resource model.Document) string {
	return Hash(model.Document{"provider_resource_id": resource["provider_resource_id"], "account_id": resource["account_id"], "region": resource["region"], "service_family": resource["service_family"], "configuration": resource["aws_service_configuration"]})
}
func Document(v any) model.Document {
	b, _ := json.Marshal(v)
	d := model.Document{}
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.UseNumber()
	_ = decoder.Decode(&d)
	if d == nil {
		d = model.Document{}
	}
	return d
}
func Rows(v any) []model.Document {
	b, _ := json.Marshal(v)
	d := []model.Document{}
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.UseNumber()
	_ = decoder.Decode(&d)
	return d
}
