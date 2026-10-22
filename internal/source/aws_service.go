package source

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/awsservice"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
	"io"
	"strings"
)

// AWSServiceFactory resolves an ingester-only configured binding. A public
// registration cannot name a role ARN, external ID or credentials.
func AWSServiceFactory(encoded string) (func(context.Context, awsservice.Registration) (*provider.AWS, error), error) {
	bindings := map[string]AWSReadBinding{}
	if strings.TrimSpace(encoded) != "" {
		d := json.NewDecoder(strings.NewReader(encoded))
		d.DisallowUnknownFields()
		if d.Decode(&bindings) != nil || d.Decode(new(any)) != io.EOF {
			return nil, errors.New("AWS_SERVICE_READ_BINDINGS_INVALID")
		}
	}
	return func(ctx context.Context, r awsservice.Registration) (*provider.AWS, error) {
		b, ok := bindings[r.ReadRoleBindingID]
		if b.AccountID == "" {
			b.AccountID = b.PayerAccountID
		}
		match := readRolePattern.FindStringSubmatch(b.RoleARN)
		if !ok || awsservice.ValidateRegistration(r) != nil || b.TenantID != r.TenantID || b.AccountID != r.AccountID || b.Region != r.Region || len(match) != 2 || match[1] != r.AccountID || len(b.ExternalID) < 32 {
			return nil, errors.New("AWS_SERVICE_READ_BINDING_NOT_CONFIGURED")
		}
		return provider.NewAWS(ctx, b.Region, b.RoleARN, b.ExternalID)
	}, nil
}
