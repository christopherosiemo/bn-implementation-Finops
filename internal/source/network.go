package source

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/network"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
)

// NetworkAWSFactory consumes only private ingester role bindings. It has no
// fallback to execution credentials and a registration cannot choose a role.
func NetworkAWSFactory(encoded string) (func(context.Context, network.Registration) (*provider.AWS, error), error) {
	bindings := map[string]AWSReadBinding{}
	if strings.TrimSpace(encoded) != "" {
		decoder := json.NewDecoder(strings.NewReader(encoded))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&bindings) != nil || decoder.Decode(new(any)) != io.EOF {
			return nil, errors.New("NETWORK_READ_BINDINGS_INVALID")
		}
	}
	return func(ctx context.Context, r network.Registration) (*provider.AWS, error) {
		b, ok := bindings[r.ReadRoleBindingID]
		if b.AccountID == "" {
			b.AccountID = b.PayerAccountID
		}
		match := readRolePattern.FindStringSubmatch(b.RoleARN)
		if !ok || network.ValidateRegistration(r) != nil || b.TenantID != r.TenantID || b.AccountID != r.AccountID || b.Region != r.Region || len(match) != 2 || match[1] != r.AccountID || len(b.ExternalID) < 32 {
			return nil, errors.New("NETWORK_READ_BINDING_NOT_CONFIGURED")
		}
		return provider.NewAWS(ctx, b.Region, b.RoleARN, b.ExternalID)
	}, nil
}
