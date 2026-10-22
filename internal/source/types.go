// Package source validates authenticated AWS billing deliveries and issues
// immutable provenance receipts. It never carries execution credentials.
package source

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"regexp"
	"strings"
	"time"
)

type Registration struct {
	ID, TenantID, Kind, PayerAccountID, Region, ExportARN, Bucket, BucketOwner, Prefix, ReadRoleBindingID string
	UsageAccountIDs                                                                                       []string
	Version                                                                                               int64
	Enabled                                                                                               bool
}
type ReadBinding struct{ TenantID, PayerAccountID, RoleARN, ExternalID, Region string }
type Reader interface {
	ListBillingExecutions(context.Context, string) ([]model.Document, error)
	BillingExecution(context.Context, string, string) (model.Document, error)
	BillingManifestKeys(context.Context, string, string, string) ([]string, error)
	BillingObject(context.Context, string, string, string) (provider.BillingObject, error)
	BillingBucket(context.Context, string) (model.Document, error)
	BillingInvoices(context.Context, string, int, int) ([]model.Document, error)
	BillingCommitments(context.Context, string) (model.Document, error)
}
type Pipeline struct {
	Store           *store.Store
	ProviderFactory func(context.Context, Registration) (Reader, error)
	Normalize       func(context.Context, model.Document) (model.Document, error)
	Persist         func(context.Context, string, string, model.Document, model.Document) error
	ArchiveObject   func(context.Context, string, string, string, []byte) error
	Now             func() time.Time
}

func Object(v any) model.Document {
	b, _ := json.Marshal(v)
	d := model.Document{}
	_ = json.Unmarshal(b, &d)
	if d == nil {
		return model.Document{}
	}
	return d
}
func Rows(v any) []model.Document {
	b, _ := json.Marshal(v)
	d := []model.Document{}
	_ = json.Unmarshal(b, &d)
	return d
}
func ParseRegistration(d model.Document) (Registration, error) {
	r := Registration{ID: model.String(d, "id"), TenantID: model.String(d, "tenant_id"), Kind: model.String(d, "kind"), PayerAccountID: model.String(d, "payer_account_id"), Region: model.String(d, "region"), ExportARN: model.String(d, "export_arn"), Bucket: model.String(d, "bucket"), BucketOwner: model.String(d, "bucket_owner"), Prefix: model.String(d, "prefix"), ReadRoleBindingID: model.String(d, "read_role_binding_id"), UsageAccountIDs: model.Strings(d, "usage_account_ids"), Version: model.Number(d, "version"), Enabled: model.Bool(d, "enabled")}
	return r, ValidateRegistration(d)
}

var accountPattern = regexp.MustCompile(`^[0-9]{12}$`)
var bucketPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)

func ValidateRegistration(d model.Document) error {
	if model.String(d, "kind") != "AWS_CUR2" {
		return errors.New("UNSUPPORTED_SOURCE_KIND")
	}
	if !accountPattern.MatchString(model.String(d, "payer_account_id")) || !accountPattern.MatchString(model.String(d, "bucket_owner")) {
		return errors.New("SOURCE_ACCOUNT_INVALID")
	}
	if model.String(d, "region") != "eu-west-1" || !bucketPattern.MatchString(model.String(d, "bucket")) {
		return errors.New("SOURCE_DESTINATION_INVALID")
	}
	prefix := model.String(d, "prefix")
	if prefix == "" || strings.HasPrefix(prefix, "/") || !strings.HasSuffix(prefix, "/") || strings.Contains(prefix, "..") || strings.ContainsAny(prefix, "\\\x00") {
		return errors.New("SOURCE_PREFIX_INVALID")
	}
	if model.String(d, "read_role_binding_id") == "" {
		return errors.New("SOURCE_READ_BINDING_REQUIRED")
	}
	ids := model.Strings(d, "usage_account_ids")
	if len(ids) == 0 {
		return errors.New("SOURCE_USAGE_SCOPE_REQUIRED")
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if !accountPattern.MatchString(id) || seen[id] {
			return errors.New("SOURCE_USAGE_SCOPE_INVALID")
		}
		seen[id] = true
	}
	arn := model.String(d, "export_arn")
	if !strings.HasPrefix(arn, "arn:aws:bcm-data-exports:us-east-1:"+model.String(d, "payer_account_id")+":export/") || strings.ContainsAny(arn, "*?\x00") {
		return errors.New("SOURCE_EXPORT_ARN_INVALID")
	}
	return nil
}
