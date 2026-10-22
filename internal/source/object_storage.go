package source

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/objectstorage"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
	"io"
	"strings"
)

// ObjectStorageAWSFactory consumes private ingestion-only bindings. A public
// source registration cannot choose a role, credentials or external ID.
func ObjectStorageAWSFactory(encoded string) (func(context.Context, objectstorage.Registration) (*provider.ObjectStorageAWS, error), error) {
	type binding struct {
		AWSReadBinding
		ApprovedWriterPrincipal string `json:"approved_writer_principal_arn"`
		MetricDefinitionID      string `json:"metric_definition_id"`
		MetricDefinitionVersion string `json:"metric_definition_version"`
	}
	bindings := map[string]binding{}
	d := json.NewDecoder(strings.NewReader(encoded))
	d.DisallowUnknownFields()
	if strings.TrimSpace(encoded) != "" {
		if d.Decode(&bindings) != nil || d.Decode(new(any)) != io.EOF {
			return nil, errors.New("S3_READ_BINDINGS_INVALID")
		}
	}
	return func(ctx context.Context, r objectstorage.Registration) (*provider.ObjectStorageAWS, error) {
		b, ok := bindings[r.ReadRoleBindingID]
		account := b.AccountID
		if account == "" {
			account = b.PayerAccountID
		}
		match := readRolePattern.FindStringSubmatch(b.RoleARN)
		if !ok || b.TenantID != r.TenantID || account != r.AccountID || b.Region != r.Region || len(match) != 2 || match[1] != r.AccountID || len(b.ExternalID) < 32 || objectstorage.ValidateScope(objectstorage.Scope{TenantID: r.TenantID, AccountID: r.AccountID, Region: r.Region}) != nil {
			return nil, errors.New("S3_READ_BINDING_NOT_CONFIGURED")
		}
		if r.ReportType == "APP_ACCESS" && (b.ApprovedWriterPrincipal == b.RoleARN || !readRolePattern.MatchString(b.ApprovedWriterPrincipal) || b.MetricDefinitionID == "" || b.MetricDefinitionVersion == "") {
			return nil, errors.New("S3_APP_COLLECTOR_BINDING_REQUIRED")
		}
		a, e := provider.NewAWS(ctx, r.Region, b.RoleARN, b.ExternalID)
		if e != nil {
			return nil, e
		}
		return &provider.ObjectStorageAWS{AWS: a, ApprovedWriterPrincipal: b.ApprovedWriterPrincipal, MetricDefinitionID: b.MetricDefinitionID, MetricDefinitionVersion: b.MetricDefinitionVersion}, nil
	}, nil
}
