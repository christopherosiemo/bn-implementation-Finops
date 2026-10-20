package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestMachineAudienceCannotAcceptConsoleOrMixedPurposeTokens(t *testing.T) {
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	signer, e := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "machine"))
	if e != nil {
		t.Fatal(e)
	}
	keys := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "machine", Algorithm: "RS256", Use: "sig"}}})
	}))
	defer keys.Close()
	issuer := "https://issuer.example/realms/finops"
	v, e := NewMachine(context.Background(), issuer, "finops-lambda-performance", keys.URL)
	if e != nil {
		t.Fatal(e)
	}
	for _, c := range []struct {
		name  string
		aud   []string
		roles []string
		valid bool
	}{{"machine", []string{"finops-lambda-performance"}, nil, true}, {"console", []string{"finops"}, nil, false}, {"mixed-purpose", []string{"finops", "finops-lambda-performance"}, nil, false}, {"human-role", []string{"finops-lambda-performance"}, []string{"FINOPS_ADMIN"}, false}, {"activity", []string{"finops-activity"}, nil, false}} {
		t.Run(c.name, func(t *testing.T) {
			token, e := jwt.Signed(signer).Claims(map[string]any{"iss": issuer, "sub": "registered-collector", "aud": c.aud, "exp": time.Now().Add(time.Hour).Unix(), "tenant_id": "tenant", "roles": c.roles}).Serialize()
			if e != nil {
				t.Fatal(e)
			}
			r := httptest.NewRequest(http.MethodPost, "/v1/lambda-performance/batches", nil)
			r.Header.Set("Authorization", "Bearer "+token)
			_, e = v.Validate(r)
			if (e == nil) != c.valid {
				t.Fatalf("accepted=%v expected=%v", e == nil, c.valid)
			}
		})
	}
}
