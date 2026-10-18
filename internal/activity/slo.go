package activity

import (
	"errors"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/auth"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/slo"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
	"net/http"
)

func (s *Server) sloInterval(w http.ResponseWriter, r *http.Request, identity auth.Identity, raw []byte, key string) {
	interval, err := slo.DecodeInterval(raw)
	if err != nil {
		failure(w, 422, "SLO_INVALID")
		return
	}
	var receipt slo.Receipt
	var replay bool
	err = s.Store.Do(r.Context(), identity.Tenant, func(tx *store.Tx) error {
		var e error
		receipt, replay, e = tx.SLOAppend(r.Context(), store.SLOSubmission{Interval: interval, RawBody: raw, Issuer: s.Issuer, Subject: identity.Subject, IdempotencyKey: key})
		return e
	})
	if errors.Is(err, store.ErrSLOSource) || errors.Is(err, pgx.ErrNoRows) {
		failure(w, 403, "SLO_SOURCE_NOT_AUTHORIZED")
		return
	}
	if errors.Is(err, store.ErrSLOConflict) || errors.Is(err, store.ErrSLOOrder) {
		failure(w, 409, "SLO_REPLAY_OR_WINDOW_CONFLICT")
		return
	}
	if err != nil {
		failure(w, 503, "SLO_PERSISTENCE_FAILED")
		return
	}
	status := http.StatusCreated
	if replay {
		status = http.StatusOK
	}
	response(w, status, map[string]any{"receipt": receipt, "replayed": replay})
}
