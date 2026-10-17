package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func TestOIDCSignatureIssuerAudienceTenantAndClientRoles(t *testing.T) {
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	signer, e := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "test"))
	if e != nil {
		t.Fatal(e)
	}
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "test", Algorithm: "RS256", Use: "sig"}}})
	}))
	defer jwks.Close()
	v, e := New(context.Background(), "https://issuer.example/realms/finops", "finops", jwks.URL)
	if e != nil {
		t.Fatal(e)
	}
	makeToken := func(issuer, audience, tenant string, expired bool) string {
		expires := time.Now().Add(time.Hour)
		if expired {
			expires = time.Now().Add(-time.Hour)
		}
		token, e := jwt.Signed(signer).Claims(map[string]any{"iss": issuer, "sub": "subject", "aud": audience, "exp": expires.Unix(), "iat": time.Now().Add(-2 * time.Hour).Unix(), "tenant_id": tenant, "realm_access": map[string]any{"roles": []string{"VIEWER"}}, "resource_access": map[string]any{"unrelated-app": map[string]any{"roles": []string{"PLATFORM_ADMIN"}}}}).Serialize()
		if e != nil {
			t.Fatal(e)
		}
		return token
	}
	cases := []struct {
		name, issuer, audience, tenant string
		expired, valid                 bool
	}{{"valid", "https://issuer.example/realms/finops", "finops", "tenant-a", false, true}, {"issuer", "https://other", "finops", "tenant-a", false, false}, {"audience", "https://issuer.example/realms/finops", "other", "tenant-a", false, false}, {"tenant", "https://issuer.example/realms/finops", "finops", "", false, false}, {"expired", "https://issuer.example/realms/finops", "finops", "tenant-a", true, false}}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/v1/dashboard", nil)
			r.Header.Set("Authorization", "Bearer "+makeToken(c.issuer, c.audience, c.tenant, c.expired))
			i, e := v.Validate(r)
			if (e == nil) != c.valid {
				t.Fatalf("valid=%v,error=%v", c.valid, e)
			}
			if c.valid && i.Can("PLATFORM_ADMIN") {
				t.Fatal("unrelated client elevated role")
			}
		})
	}
}
