package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
)

type Identity struct {
	Tenant  string
	Subject string
	Email   string
	Roles   map[string]bool
}

func (i Identity) Can(roles ...string) bool {
	for _, r := range roles {
		if i.Roles[r] || i.Roles["ORGANISATION_OWNER"] {
			return true
		}
	}
	return false
}

type Validator struct {
	verifier *oidc.IDTokenVerifier
	audience string
}

func New(ctx context.Context, issuer, audience, jwks string) (*Validator, error) {
	if issuer == "" || audience == "" {
		return nil, errors.New("OIDC_ISSUER and OIDC_AUDIENCE required")
	}
	if jwks == "" {
		jwks = strings.TrimRight(issuer, "/") + "/protocol/openid-connect/certs"
	}
	return &Validator{verifier: oidc.NewVerifier(issuer, oidc.NewRemoteKeySet(ctx, jwks), &oidc.Config{ClientID: audience}), audience: audience}, nil
}
func (v *Validator) Validate(r *http.Request) (Identity, error) {
	var i Identity
	a := r.Header.Get("Authorization")
	if !strings.HasPrefix(a, "Bearer ") {
		return i, errors.New("bearer token required")
	}
	tok, e := v.verifier.Verify(r.Context(), strings.TrimPrefix(a, "Bearer "))
	if e != nil {
		return i, errors.New("invalid access token")
	}
	var c struct {
		Subject string   `json:"sub"`
		Email   string   `json:"email"`
		Tenant  string   `json:"tenant_id"`
		Roles   []string `json:"roles"`
		Realm   struct {
			Roles []string `json:"roles"`
		} `json:"realm_access"`
		Client map[string]struct {
			Roles []string `json:"roles"`
		} `json:"resource_access"`
	}
	if e = tok.Claims(&c); e != nil || c.Tenant == "" || c.Subject == "" {
		return i, errors.New("tenant_id and subject required")
	}
	i = Identity{Tenant: c.Tenant, Subject: c.Subject, Email: c.Email, Roles: map[string]bool{}}
	for _, role := range append(c.Roles, c.Realm.Roles...) {
		i.Roles[strings.ToUpper(role)] = true
	}
	for client, app := range c.Client {
		if client != v.audience {
			continue
		}
		for _, role := range app.Roles {
			i.Roles[strings.ToUpper(role)] = true
		}
	}
	return i, nil
}
