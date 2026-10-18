package source

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
)

// Binding configuration is an ingester-only secret, never an API registration
// field. Every organization member needs its own exact read-role binding.
type AWSReadBinding struct {
	TenantID           string            `json:"tenant_id"`
	PayerAccountID     string            `json:"payer_account_id"`
	AccountID          string            `json:"account_id"`
	RoleARN            string            `json:"role_arn"`
	ExternalID         string            `json:"external_id"`
	Region             string            `json:"region"`
	MemberRoleBindings map[string]string `json:"member_role_bindings,omitempty"`
}

var readRolePattern = regexp.MustCompile(`^arn:aws:iam::([0-9]{12}):role/[A-Za-z0-9+=,.@_/-]+$`)

// AWSFactory parses AWS_SOURCE_READ_BINDINGS_JSON once. Merely registering a
// source cannot select another customer's role or supply AWS credentials.
func AWSFactory(encoded string) (func(context.Context, Registration) (Reader, error), error) {
	bindings, err := ParseAWSBindings(encoded)
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context, r Registration) (Reader, error) {
		b, ok := bindings[r.ReadRoleBindingID]
		if !ok || b.TenantID != r.TenantID || b.PayerAccountID != r.PayerAccountID || b.AccountID != r.PayerAccountID || b.Region != r.Region {
			return nil, errors.New("SOURCE_READ_BINDING_NOT_CONFIGURED")
		}
		reader, err := provider.NewBillingAWS(ctx, b.Region, b.RoleARN, b.ExternalID, r.BucketOwner)
		if err != nil {
			return nil, err
		}
		reader.MemberReader = func(ctx context.Context, account string) (*provider.BillingAWS, error) {
			id, ok := b.MemberRoleBindings[account]
			member, configured := bindings[id]
			if !ok || !configured || member.TenantID != r.TenantID || member.PayerAccountID != r.PayerAccountID || member.AccountID != account || member.Region != r.Region {
				return nil, errors.New("COMMITMENT_MEMBER_READ_BINDING_REQUIRED")
			}
			return provider.NewBillingAWS(ctx, member.Region, member.RoleARN, member.ExternalID, r.BucketOwner)
		}
		return reader, nil
	}, nil
}

func ParseAWSBindings(encoded string) (map[string]AWSReadBinding, error) {
	bindings := map[string]AWSReadBinding{}
	if strings.TrimSpace(encoded) == "" {
		return bindings, nil
	}
	decoder := json.NewDecoder(strings.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&bindings); err != nil {
		return nil, errors.New("SOURCE_READ_BINDINGS_INVALID")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, errors.New("SOURCE_READ_BINDINGS_INVALID")
	}
	for id, b := range bindings {
		match := readRolePattern.FindStringSubmatch(b.RoleARN)
		if b.AccountID == "" {
			b.AccountID = b.PayerAccountID
			bindings[id] = b
		}
		if id == "" || b.TenantID == "" || !accountPattern.MatchString(b.PayerAccountID) || !accountPattern.MatchString(b.AccountID) || len(match) != 2 || match[1] != b.AccountID || b.Region != "eu-west-1" || len(b.ExternalID) < 32 {
			return nil, errors.New("SOURCE_READ_BINDINGS_INVALID")
		}
		for account, memberID := range b.MemberRoleBindings {
			if !accountPattern.MatchString(account) || memberID == "" {
				return nil, errors.New("SOURCE_READ_BINDINGS_INVALID")
			}
		}
	}
	for _, b := range bindings {
		for account, id := range b.MemberRoleBindings {
			member, ok := bindings[id]
			if !ok || member.AccountID != account || member.TenantID != b.TenantID || member.PayerAccountID != b.PayerAccountID {
				return nil, errors.New("SOURCE_MEMBER_BINDINGS_INVALID")
			}
		}
	}
	return bindings, nil
}
