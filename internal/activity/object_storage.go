package activity

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/auth"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
)

// objectStorageUniqueJSON rejects duplicate keys at every depth before a typed
// decode. Missing numeric observations and heartbeat cannot become zero/false.
func objectStorageUniqueJSON(d *json.Decoder) error {
	token, err := d.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || seen[name] {
				return errors.New("duplicate object storage observation field")
			}
			seen[name] = true
			if err = objectStorageUniqueJSON(d); err != nil {
				return err
			}
		}
	case '[':
		for d.More() {
			if err := objectStorageUniqueJSON(d); err != nil {
				return err
			}
		}
	default:
		return errors.New("invalid object storage observation JSON")
	}
	_, err = d.Token()
	return err
}

func DecodeObjectStorageAccess(raw []byte) (store.ObjectStorageAccessInterval, error) {
	var interval store.ObjectStorageAccessInterval
	if len(raw) > 16<<10 {
		return interval, errors.New("object storage observation too large")
	}
	unique := json.NewDecoder(bytes.NewReader(raw))
	unique.UseNumber()
	if err := objectStorageUniqueJSON(unique); err != nil {
		return interval, err
	}
	if _, err := unique.Token(); err != io.EOF {
		return interval, errors.New("one object storage observation required")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return interval, errors.New("object storage observation must be object")
	}
	for _, key := range []string{"schema_version", "source_id", "resource_id", "dataset_id", "dataset_version", "sequence", "interval_start", "interval_end", "metric_definition", "get_requests", "retrieved_bytes", "heartbeat"} {
		value, ok := fields[key]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return interval, errors.New("all object storage observation fields required")
		}
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&interval); err != nil {
		return interval, err
	}
	if err := d.Decode(&struct{}{}); err != io.EOF {
		return interval, errors.New("one object storage observation required")
	}
	return interval, store.ValidateObjectStorageAccessInterval(interval)
}

func (s *Server) objectStorageInterval(w http.ResponseWriter, r *http.Request, identity auth.Identity, raw []byte, key string) {
	interval, err := DecodeObjectStorageAccess(raw)
	if err != nil {
		failure(w, 422, "OBJECT_STORAGE_ACCESS_INVALID")
		return
	}
	var receipt store.ObjectStorageAccessReceipt
	var replay bool
	err = s.Store.Do(r.Context(), identity.Tenant, func(tx *store.Tx) error {
		var e error
		receipt, replay, e = tx.ObjectStorageAccessAppend(r.Context(), store.ObjectStorageAccessSubmission{Interval: interval, RawBody: raw, Issuer: s.Issuer, Subject: identity.Subject, IdempotencyKey: key})
		return e
	})
	if errors.Is(err, store.ErrObjectStorageAccessSource) || errors.Is(err, pgx.ErrNoRows) {
		failure(w, 403, "OBJECT_STORAGE_ACCESS_SOURCE_NOT_AUTHORIZED")
		return
	}
	if errors.Is(err, store.ErrObjectStorageAccessConflict) {
		failure(w, 409, "OBJECT_STORAGE_ACCESS_REPLAY_OR_WINDOW_CONFLICT")
		return
	}
	if err != nil {
		failure(w, 503, "OBJECT_STORAGE_ACCESS_PERSISTENCE_FAILED")
		return
	}
	status := http.StatusCreated
	if replay {
		status = http.StatusOK
	}
	response(w, status, map[string]any{"receipt": receipt, "replayed": replay})
}
