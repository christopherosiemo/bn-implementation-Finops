// Package deploymentobserver accepts customer-pipeline attestations under a
// dedicated machine identity. It cannot approve, sign, apply or release a
// disruption reservation. An APPLIED receipt establishes ownership; independent
// membership and health evidence are still required before expansion.
package deploymentobserver

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/auth"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type Validator interface {
	Validate(*http.Request) (auth.Identity, error)
}

type Repository interface {
	Ping(context.Context) error
	Append(context.Context, string, string, string, store.FleetCallbackSubmission) (model.Document, bool, error)
}

type Database struct{ Store *store.Store }

func (d Database) Ping(ctx context.Context) error {
	if d.Store == nil || d.Store.Pool == nil {
		return errors.New("DEPLOYMENT_DATABASE_UNAVAILABLE")
	}
	return d.Store.Pool.Ping(ctx)
}
func (d Database) Append(ctx context.Context, tenant, command, key string, in store.FleetCallbackSubmission) (out model.Document, replay bool, err error) {
	err = d.Store.Do(ctx, tenant, func(tx *store.Tx) error {
		out, replay, err = tx.FleetCallbackAppend(ctx, command, key, in)
		return err
	})
	return
}

type Server struct {
	Repository Repository
	Auth       Validator
	Issuer     string
	Audience   string
}

// New binds the verifier to one deployment-only audience. The OIDC provider
// must issue the tenant claim itself; request bodies and headers cannot select
// a tenant or impersonate an observer registered in another organization.
func New(ctx context.Context, db *store.Store, issuer, audience, jwks string, fixture bool, otherAudiences ...string) (*Server, error) {
	u, err := url.Parse(issuer)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Scheme != "https" && !(fixture && u.Scheme == "http") || strings.TrimSpace(audience) != audience || audience == "" {
		return nil, errors.New("DEPLOYMENT_OIDC_CONFIGURATION_INVALID")
	}
	if jwks != "" {
		keys, err := url.Parse(jwks)
		if err != nil || keys.Host == "" || keys.User != nil || keys.RawQuery != "" || keys.Fragment != "" || keys.Scheme != "https" && !(fixture && keys.Scheme == "http") {
			return nil, errors.New("DEPLOYMENT_JWKS_CONFIGURATION_INVALID")
		}
	}
	for _, other := range append([]string{"finops", "finops-activity", "finops-telemetry"}, otherAudiences...) {
		if audience == other {
			return nil, errors.New("DEPLOYMENT_DEDICATED_AUDIENCE_REQUIRED")
		}
	}
	v, err := auth.New(ctx, issuer, audience, jwks)
	if err != nil {
		return nil, errors.New("DEPLOYMENT_OIDC_CONFIGURATION_INVALID")
	}
	return &Server{Repository: Database{Store: db}, Auth: v, Issuer: issuer, Audience: audience}, nil
}

func human(i auth.Identity) bool {
	for _, role := range []string{"ORGANISATION_OWNER", "FINOPS_ADMIN", "PLATFORM_ADMIN", "FINANCE", "APPLICATION_OWNER", "APPROVER", "VIEWER", "AUDITOR", "FLEET_APPROVER"} {
		if i.Roles[role] {
			return true
		}
	}
	return false
}
func response(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func failure(w http.ResponseWriter, status int, code string) {
	response(w, status, model.Document{"reason_code": code})
}

func (s *Server) Handler() http.Handler { return http.HandlerFunc(s.serve) }
func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" && r.Method == http.MethodGet {
		if s.Repository == nil || s.Repository.Ping(r.Context()) != nil {
			failure(w, 503, "DEPLOYMENT_OBSERVER_UNAVAILABLE")
			return
		}
		response(w, 200, model.Document{"status": "ok", "role": "deployment-observer"})
		return
	}
	const prefix = "/v1/deployment-callbacks/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		http.NotFound(w, r)
		return
	}
	command := strings.TrimPrefix(r.URL.Path, prefix)
	if command == "" || len(command) > 200 || strings.Contains(command, "/") || r.URL.RawQuery != "" {
		failure(w, 400, "DEPLOYMENT_COMMAND_ID_INVALID")
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		failure(w, 405, "METHOD_NOT_ALLOWED")
		return
	}
	if s.Repository == nil || s.Auth == nil || s.Issuer == "" || s.Audience == "" {
		failure(w, 503, "DEPLOYMENT_OBSERVER_UNAVAILABLE")
		return
	}
	i, err := s.Auth.Validate(r)
	if err != nil || i.Tenant == "" || i.Subject == "" || human(i) {
		failure(w, 401, "DEPLOYMENT_MACHINE_IDENTITY_REQUIRED")
		return
	}
	key, source := r.Header.Get("Idempotency-Key"), r.Header.Get("X-Finops-Source-ID")
	if len(key) < 8 || len(key) > 200 || source == "" || len(source) > 200 {
		failure(w, 400, "DEPLOYMENT_RECEIPT_HEADERS_REQUIRED")
		return
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" || r.Header.Get("Content-Encoding") != "" && r.Header.Get("Content-Encoding") != "identity" {
		failure(w, 415, "DEPLOYMENT_JSON_REQUIRED")
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
	if err != nil || len(raw) == 0 {
		failure(w, 413, "DEPLOYMENT_RECEIPT_BODY_LIMIT")
		return
	}
	// Retain the exact authenticated body. Caller-supplied identity, ownership or
	// trust flags are rejected by the strict store decoder, never merged here.
	out, replay, err := s.Repository.Append(r.Context(), i.Tenant, command, key, store.FleetCallbackSubmission{SourceID: source, Issuer: s.Issuer, Subject: i.Subject, Audience: s.Audience, RawBody: raw})
	if errors.Is(err, store.ErrFleetSource) || errors.Is(err, pgx.ErrNoRows) {
		failure(w, 403, "DEPLOYMENT_SOURCE_NOT_AUTHORIZED")
		return
	}
	if errors.Is(err, store.ErrFleetConflict) {
		failure(w, 409, "DEPLOYMENT_REPLAY_CONFLICT")
		return
	}
	if errors.Is(err, store.ErrFleetInvalid) {
		failure(w, 422, "DEPLOYMENT_RECEIPT_INVALID")
		return
	}
	if err != nil {
		var pg *pgconn.PgError
		var syntax *json.SyntaxError
		var typed *json.UnmarshalTypeError
		if errors.As(err, &syntax) || errors.As(err, &typed) || strings.HasPrefix(err.Error(), "json: unknown field") || errors.As(err, &pg) && (pg.Code == "P0001" || strings.HasPrefix(pg.Code, "22") || strings.HasPrefix(pg.Code, "23")) {
			failure(w, 422, "DEPLOYMENT_RECEIPT_INVALID")
		} else {
			failure(w, 503, "DEPLOYMENT_RECEIPT_PERSISTENCE_FAILED")
		}
		return
	}
	status := http.StatusCreated
	if replay {
		status = http.StatusOK
	}
	response(w, status, model.Document{"receipt": out, "replayed": replay})
}
