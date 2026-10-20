package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"
)

// NewMachine preserves ordinary console validation while requiring a single,
// dedicated audience and a non-human identity for authoritative batch ingress.
type MachineValidator struct {
	validator *Validator
	audience  string
}

func NewMachine(ctx context.Context, issuer, audience, jwks string) (*MachineValidator, error) {
	v, e := New(ctx, issuer, audience, jwks)
	if e != nil {
		return nil, e
	}
	return &MachineValidator{v, audience}, nil
}
func (v *MachineValidator) Validate(r *http.Request) (Identity, error) {
	tok, e := v.validator.verifier.Verify(r.Context(), strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if e != nil || len(tok.Audience) != 1 || tok.Audience[0] != v.audience {
		return Identity{}, errors.New("dedicated machine token required")
	}
	identity, e := v.validator.Validate(r)
	if e != nil {
		return Identity{}, e
	}
	for _, role := range []string{"ORGANISATION_OWNER", "FINOPS_ADMIN", "PLATFORM_ADMIN", "APPLICATION_OWNER", "APPROVER", "FINANCE", "VIEWER", "AUDITOR", "FLEET_APPROVER"} {
		if identity.Roles[role] {
			return Identity{}, errors.New("human token cannot author observations")
		}
	}
	return identity, nil
}
