package deploymentobserver

import (
	"context"
	"errors"
	"io"
	"mime"
	"net/http"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/commitmentportfolio"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
)

type ownershipRepository interface {
	AppendOwnership(context.Context, string, string, string, string, string, []byte) (commitmentportfolio.DecisionOwnershipStoredEnvelope, bool, error)
}

func (d Database) AppendOwnership(ctx context.Context, tenant, issuer, subject, audience, kind string, raw []byte) (out commitmentportfolio.DecisionOwnershipStoredEnvelope, replay bool, err error) {
	if d.Store == nil {
		return out, false, errors.New("OWNERSHIP_DATABASE_UNAVAILABLE")
	}
	err = d.Store.Do(ctx, tenant, func(tx *store.Tx) error {
		var e error
		out, replay, e = commitmentportfolio.AppendDecisionOwnership(ctx, tx.Tx, tenant, issuer, subject, audience, kind, raw)
		return e
	})
	return
}

func (s *Server) serveOwnership(w http.ResponseWriter, r *http.Request) bool {
	kind, limit := "", int64(16<<10)
	switch r.URL.Path {
	case "/v1/deployment-ownership/deployments":
		kind = "DEPLOYMENT"
	case "/v1/deployment-ownership/journals":
		kind = "JOURNAL"
	case "/v1/deployment-ownership/reviews":
		kind = "REVIEW"
		limit = 64 << 10
	default:
		return false
	}
	if r.Method != http.MethodPost {
		failure(w, 405, "OWNERSHIP_POST_REQUIRED")
		return true
	}
	repository, ok := s.Repository.(ownershipRepository)
	if !ok || s.Auth == nil || s.Audience != "finops-deployment-observer" || s.Issuer == "" {
		failure(w, 503, "OWNERSHIP_INGRESS_UNAVAILABLE")
		return true
	}
	identity, err := s.Auth.Validate(r)
	if err != nil || identity.Tenant == "" || identity.Subject == "" || human(identity) {
		failure(w, 401, "OWNERSHIP_MACHINE_IDENTITY_REQUIRED")
		return true
	}
	content, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || content != "application/json" || r.URL.RawQuery != "" {
		failure(w, 415, "OWNERSHIP_CANONICAL_JSON_REQUIRED")
		return true
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil || int64(len(raw)) > limit {
		failure(w, 413, "OWNERSHIP_ENVELOPE_LIMIT")
		return true
	}
	stored, replay, err := repository.AppendOwnership(r.Context(), identity.Tenant, s.Issuer, identity.Subject, s.Audience, kind, raw)
	if err != nil {
		failure(w, 409, "OWNERSHIP_APPEND_REFUSED")
		return true
	}
	status := http.StatusCreated
	if replay {
		status = http.StatusOK
	}
	response(w, status, map[string]any{"reference": stored.Reference, "server_recorded_at": stored.ServerRecordedAt, "replay": replay, "execution_authorized": false})
	return true
}
