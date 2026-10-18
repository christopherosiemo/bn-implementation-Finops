package activity

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/auth"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
)

type Validator interface {
	Validate(*http.Request) (auth.Identity, error)
}
type Server struct {
	Store  *store.Store
	Auth   Validator
	Issuer string
}

func NewServer(db *store.Store, validator Validator, issuer string) *Server {
	return &Server{Store: db, Auth: validator, Issuer: issuer}
}
func response(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}
func failure(w http.ResponseWriter, status int, code string) {
	response(w, status, map[string]string{"reason_code": code})
}
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" && r.Method == http.MethodGet {
			if s.Store == nil || s.Store.Pool.Ping(r.Context()) != nil {
				failure(w, 503, "DATABASE_UNAVAILABLE")
				return
			}
			response(w, 200, map[string]string{"status": "ok", "role": "activity-ingress"})
			return
		}
		if r.URL.Path != "/v1/activity/intervals" && r.URL.Path != "/v1/slo/intervals" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			failure(w, 405, "METHOD_NOT_ALLOWED")
			return
		}
		identity, err := s.Auth.Validate(r)
		if err != nil || identity.Tenant == "" || identity.Subject == "" {
			failure(w, 401, "MACHINE_AUTHENTICATION_REQUIRED")
			return
		}
		key := r.Header.Get("Idempotency-Key")
		if key == "" || len(key) > 200 {
			failure(w, 400, "IDEMPOTENCY_KEY_REQUIRED")
			return
		}
		if !strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/json") {
			failure(w, 415, "JSON_REQUIRED")
			return
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16<<10))
		if err != nil {
			failure(w, 413, "ACTIVITY_BODY_TOO_LARGE")
			return
		}
		if r.URL.Path == "/v1/slo/intervals" {
			s.sloInterval(w, r, identity, raw, key)
			return
		}
		interval, err := Decode(raw)
		if err != nil {
			failure(w, 422, "ACTIVITY_INVALID")
			return
		}
		var receipt store.ActivityReceipt
		var replayed bool
		err = s.Store.Do(r.Context(), identity.Tenant, func(tx *store.Tx) error {
			var e error
			receipt, replayed, e = tx.ActivityAppend(r.Context(), store.ActivitySubmission{Interval: interval, RawBody: raw, Issuer: s.Issuer, Subject: identity.Subject, IdempotencyKey: key})
			return e
		})
		if errors.Is(err, store.ErrActivitySource) || errors.Is(err, pgx.ErrNoRows) {
			failure(w, 403, "ACTIVITY_SOURCE_NOT_AUTHORIZED")
			return
		}
		if store.ActivityConflict(err) {
			failure(w, 409, "ACTIVITY_REPLAY_OR_WINDOW_CONFLICT")
			return
		}
		if err != nil {
			failure(w, 503, "ACTIVITY_PERSISTENCE_FAILED")
			return
		}
		status := http.StatusCreated
		if replayed {
			status = http.StatusOK
		}
		response(w, status, map[string]any{"receipt": receipt, "replayed": replayed})
	})
}
