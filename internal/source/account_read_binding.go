package source

import (
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strings"
)

// AWSAccountApprovedBinding is deliberately safe API metadata. External IDs and
// credentials belong only to the separate ingester binding map.
type AWSAccountApprovedBinding struct {
	ID                   string   `json:"id"`
	TenantID             string   `json:"tenant_id,omitempty"`
	AccountID            string   `json:"account_id"`
	Regions              []string `json:"regions"`
	RoleARN              string   `json:"role_arn"`
	ScopeMode            string   `json:"scope_mode"`
	ExternalIDConfigured bool     `json:"external_id_configured"`
}

func AWSAccountApprovedBindings(encoded, tenant string) ([]AWSAccountApprovedBinding, error) {
	rows := map[string]AWSAccountApprovedBinding{}
	if strings.TrimSpace(encoded) != "" {
		d := json.NewDecoder(strings.NewReader(encoded))
		d.DisallowUnknownFields()
		if d.Decode(&rows) != nil || d.Decode(new(any)) != io.EOF {
			return nil, errors.New("AWS_ACCOUNT_APPROVED_BINDINGS_INVALID")
		}
	}
	out := []AWSAccountApprovedBinding{}
	for id, b := range rows {
		role := readRolePattern.FindStringSubmatch(b.RoleARN)
		if id == "" || len(id) > 128 || b.ID != "" && b.ID != id || b.TenantID == "" || !accountPattern.MatchString(b.AccountID) || len(role) != 2 || role[1] != b.AccountID || b.ScopeMode != "ACCOUNT" || len(b.Regions) != 1 || b.Regions[0] != "eu-west-1" {
			return nil, errors.New("AWS_ACCOUNT_APPROVED_BINDINGS_INVALID")
		}
		if b.TenantID == tenant {
			b.ID = id
			b.TenantID = ""
			out = append(out, b)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func ResolveAWSAccountReadBinding(encoded, id, tenant, account, region string) (AWSReadBinding, error) {
	rows, e := ParseAWSBindings(encoded)
	if e != nil {
		return AWSReadBinding{}, errors.New("AWS_ACCOUNT_READ_BINDING_INVALID")
	}
	b, ok := rows[id]
	if !ok || id == "" || b.TenantID != tenant || b.AccountID != account || b.Region != region || region != "eu-west-1" {
		return AWSReadBinding{}, errors.New("AWS_ACCOUNT_READ_BINDING_NOT_CONFIGURED")
	}
	return b, nil
}

// A private role is usable only while its safe approval exists with the same
// role ARN and account/region scope. Private secrets cannot enlarge approval.
func ResolveApprovedAWSAccountReadBinding(private, approved, id, tenant, account, region string) (AWSReadBinding, error) {
	b, e := ResolveAWSAccountReadBinding(private, id, tenant, account, region)
	if e != nil {
		return AWSReadBinding{}, e
	}
	rows, e := AWSAccountApprovedBindings(approved, tenant)
	if e != nil {
		return AWSReadBinding{}, errors.New("AWS_ACCOUNT_APPROVED_BINDING_UNAVAILABLE")
	}
	for _, row := range rows {
		if row.ID == id && row.AccountID == account && row.RoleARN == b.RoleARN && row.ExternalIDConfigured {
			for _, r := range row.Regions {
				if r == region {
					return b, nil
				}
			}
		}
	}
	return AWSReadBinding{}, errors.New("AWS_ACCOUNT_APPROVED_BINDING_UNAVAILABLE")
}
