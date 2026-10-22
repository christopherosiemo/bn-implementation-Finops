package deploymentobserver

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/auth"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

type receiptRepository struct {
	calls                int
	err                  error
	replay               bool
	input                store.FleetCallbackSubmission
	tenant, command, key string
}

func (r *receiptRepository) Ping(context.Context) error { return r.err }
func (r *receiptRepository) Append(_ context.Context, tenant, command, key string, in store.FleetCallbackSubmission) (model.Document, bool, error) {
	r.calls++
	r.input, r.tenant, r.command, r.key = in, tenant, command, key
	return model.Document{"id": "immutable-receipt"}, r.replay, r.err
}

func TestDedicatedOIDCCannotAcceptConsoleOrAnotherAudience(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "observer-test"))
	if err != nil {
		t.Fatal(err)
	}
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "observer-test", Algorithm: "RS256", Use: "sig"}}})
	}))
	defer jwks.Close()
	const issuer, audience = "https://pipeline.example.invalid", "finops-deployment-observer"
	v, err := auth.New(context.Background(), issuer, audience, jwks.URL)
	if err != nil {
		t.Fatal(err)
	}
	repo := &receiptRepository{}
	s := &Server{Repository: repo, Auth: v, Issuer: issuer, Audience: audience}
	for _, tc := range []struct {
		name, iss, aud, tenant string
		roles                  []string
		status                 int
	}{
		{"machine", issuer, audience, "tenant-a", nil, 201},
		{"console-audience", issuer, "finops", "tenant-a", nil, 401},
		{"activity-audience", issuer, "finops-activity", "tenant-a", nil, 401},
		{"native-audience", issuer, "finops-telemetry", "tenant-a", nil, 401},
		{"wrong-issuer", "https://other.invalid", audience, "tenant-a", nil, 401},
		{"missing-tenant", issuer, audience, "", nil, 401},
		{"console-token-with-machine-audience", issuer, audience, "tenant-a", []string{"PLATFORM_ADMIN"}, 401},
		{"approval-token", issuer, audience, "tenant-a", []string{"FLEET_APPROVER"}, 401},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := map[string]any{"iss": tc.iss, "aud": tc.aud, "sub": "registered-pipeline", "tenant_id": tc.tenant, "exp": time.Now().Add(time.Minute).Unix(), "iat": time.Now().Add(-time.Minute).Unix(), "roles": tc.roles}
			token, e := jwt.Signed(signer).Claims(claims).Serialize()
			if e != nil {
				t.Fatal(e)
			}
			const raw = "{\n  \"schema_version\": \"4\", \"outcome\": \"UNKNOWN\"\n}\n"
			r := httptest.NewRequest(http.MethodPost, "/v1/deployment-callbacks/command-1", strings.NewReader(raw))
			r.Header.Set("Authorization", "Bearer "+token)
			r.Header.Set("Content-Type", "application/json; charset=utf-8")
			r.Header.Set("Idempotency-Key", "original-request")
			r.Header.Set("X-Finops-Source-ID", "registered-source")
			before := repo.calls
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			if w.Code != tc.status {
				t.Fatalf("%d: %s", w.Code, w.Body.String())
			}
			if tc.status != 201 && repo.calls != before {
				t.Fatal("rejected token reached persistence")
			}
			if tc.status == 201 && (string(repo.input.RawBody) != raw || repo.tenant != "tenant-a" || repo.input.Subject != "registered-pipeline" || repo.input.Issuer != issuer || repo.input.Audience != audience) {
				t.Fatal("authenticated identity or original bytes lost")
			}
		})
	}
}

type machineValidator struct{}

func (machineValidator) Validate(*http.Request) (auth.Identity, error) {
	return auth.Identity{Tenant: "tenant-a", Subject: "pipeline"}, nil
}

func TestObserverConfigurationRequiresDistinctMachineAudienceAndTLS(t *testing.T) {
	for _, tc := range []struct {
		issuer, audience string
		fixture          bool
		others           []string
	}{
		{"http://machine.invalid", "observer", false, nil},
		{"https://machine.invalid", "finops", false, nil},
		{"https://machine.invalid", "finops-activity", false, nil},
		{"https://machine.invalid", "finops-telemetry", false, nil},
		{"https://machine.invalid", "custom-console", false, []string{"custom-console"}},
		{"https://user:secret@machine.invalid", "observer", false, nil},
		{"https://machine.invalid?secret=hidden", "observer", false, nil},
	} {
		if _, err := New(context.Background(), nil, tc.issuer, tc.audience, "https://keys.invalid", tc.fixture, tc.others...); err == nil {
			t.Fatal("unsafe observer identity configuration accepted")
		}
	}
	if _, err := New(context.Background(), nil, "http://keycloak:8080/realms/finops", "finops-deployment-observer", "http://keycloak:8080/realms/finops/protocol/openid-connect/certs", true); err != nil {
		t.Fatal(err)
	}
}

func TestTransportLimitsAndOpaquePersistenceErrors(t *testing.T) {
	for _, tc := range []struct {
		name, body, media, encoding, source, key string
		err                                      error
		replay                                   bool
		status                                   int
		calls                                    int
	}{
		{"exact-replay", "{}", "application/json", "", "source", "original-key", nil, true, 200, 1},
		{"wrong-source", "{}", "application/json", "", "source", "original-key", store.ErrFleetSource, false, 403, 1},
		{"conflicting-replay", "{}", "application/json", "", "source", "original-key", store.ErrFleetConflict, false, 409, 1},
		{"invalid-observation", "{}", "application/json", "", "source", "original-key", store.ErrFleetInvalid, false, 422, 1},
		{"outage", "{}", "application/json", "", "source", "original-key", errors.New("secret database address and password"), false, 503, 1},
		{"body-limit", strings.Repeat("x", (64<<10)+1), "application/json", "", "source", "original-key", nil, false, 413, 0},
		{"compression", "{}", "application/json", "gzip", "source", "original-key", nil, false, 415, 0},
		{"lookalike-type", "{}", "application/jsonp", "", "source", "original-key", nil, false, 415, 0},
		{"missing-source", "{}", "application/json", "", "", "original-key", nil, false, 400, 0},
		{"missing-idempotency", "{}", "application/json", "", "source", "", nil, false, 400, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := &receiptRepository{err: tc.err, replay: tc.replay}
			s := &Server{Repository: repo, Auth: machineValidator{}, Issuer: "https://machine.invalid", Audience: "dedicated-observer"}
			r := httptest.NewRequest(http.MethodPost, "/v1/deployment-callbacks/command", strings.NewReader(tc.body))
			r.Header.Set("Content-Type", tc.media)
			r.Header.Set("Content-Encoding", tc.encoding)
			r.Header.Set("X-Finops-Source-ID", tc.source)
			r.Header.Set("Idempotency-Key", tc.key)
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			if w.Code != tc.status || repo.calls != tc.calls {
				t.Fatalf("status=%d calls=%d body=%s", w.Code, repo.calls, w.Body.String())
			}
			if strings.Contains(w.Body.String(), "password") {
				t.Fatal("persistence detail leaked")
			}
		})
	}
}
