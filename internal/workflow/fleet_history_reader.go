package workflow

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/native"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/service"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
)

type fleetHistoryTarget struct {
	TenantID       string `json:"tenant_id"`
	RegistrationID string `json:"registration_id"`
}
type fleetHistoryCapturer interface {
	Capture(context.Context, string, string) (model.Document, error)
}
type fleetHistoryReader struct {
	Store   *store.Store
	Targets []fleetHistoryTarget
	Capture fleetHistoryCapturer
	Now     func() time.Time
}

func fleetHistoryTargets(encoded, tenant string, fixture bool) ([]fleetHistoryTarget, error) {
	if fixture {
		return nil, errors.New("HISTORY_NATIVE_READ_DISABLED_IN_FIXTURE_MODE")
	}
	var targets []fleetHistoryTarget
	d := json.NewDecoder(strings.NewReader(encoded))
	d.DisallowUnknownFields()
	if len(encoded) > 64<<10 || d.Decode(&targets) != nil || d.Decode(new(any)) != io.EOF || len(targets) < 1 || len(targets) > 128 || tenant == "" {
		return nil, errors.New("HISTORY_COMMISSIONED_REGISTRATIONS_REQUIRED")
	}
	id := regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
	seen := map[string]bool{}
	for _, target := range targets {
		if target.TenantID != tenant || !id.MatchString(target.TenantID) || !id.MatchString(target.RegistrationID) || seen[target.RegistrationID] {
			return nil, errors.New("HISTORY_COMMISSIONED_REGISTRATION_INVALID")
		}
		seen[target.RegistrationID] = true
	}
	return targets, nil
}

// RunFleetHistoryReader is explicitly commissioned as a separate read-only
// ingestion process. It has no Temporal mutation queue, signer, execution
// credentials or financial-verification route. Nothing starts it by default.
func RunFleetHistoryReader(ctx context.Context, cfg service.Config, db *store.Store) error {
	targets, err := fleetHistoryTargets(os.Getenv("AWS_FLEET_HISTORY_REGISTRATIONS_JSON"), os.Getenv("AWS_TENANT_ID"), cfg.Fixture)
	if err != nil {
		return err
	}
	if os.Getenv("OBJECT_ACCESS_KEY") != "" || os.Getenv("OBJECT_SECRET_KEY") != "" || os.Getenv("AWS_ACCESS_KEY_ID") != "" || os.Getenv("AWS_SECRET_ACCESS_KEY") != "" || os.Getenv("AWS_ROLE_ARN") == "" || os.Getenv("AWS_WEB_IDENTITY_TOKEN_FILE") == "" {
		return errors.New("HISTORY_RENEWABLE_WORKLOAD_IDENTITY_REQUIRED")
	}
	if endpoint := os.Getenv("OBJECT_ENDPOINT"); endpoint != "" && !hardwareStorageEndpoint(endpoint) {
		return errors.New("HISTORY_IRELAND_STORAGE_ENDPOINT_REQUIRED")
	}
	factory, err := source.FleetAWSFactory(os.Getenv("AWS_SOURCE_READ_BINDINGS_JSON"))
	if err != nil {
		return err
	}
	storage, err := native.StorageFromEnvironment(ctx, false)
	if err != nil {
		return err
	}
	archive := &source.FleetS3Archive{Client: storage.S3, Bucket: storage.Bucket}
	reader := &fleetHistoryReader{Store: db, Targets: targets, Capture: &source.FleetHistoryPipeline{Store: db, ReaderFactory: factory, Archive: archive.Archive}}
	timer := time.NewTicker(15 * time.Second)
	defer timer.Stop()
	for {
		for _, target := range reader.Targets {
			if err := reader.capture(ctx, target); err != nil && ctx.Err() == nil {
				// Native response bodies, role/external IDs and credentials are not
				// included in logs or workflow histories.
				slog.Error("native fleet history unavailable", "reason_code", "HISTORY_CAPTURE_UNAVAILABLE")
			}
			if ctx.Err() != nil {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
		}
	}
}
func (r *fleetHistoryReader) now() time.Time {
	if r.Now != nil {
		return r.Now().UTC()
	}
	return time.Now().UTC()
}
func (r *fleetHistoryReader) capture(ctx context.Context, target fleetHistoryTarget) error {
	if r.Store == nil || r.Capture == nil {
		return errors.New("HISTORY_READER_DEPENDENCIES_REQUIRED")
	}
	lock, err := r.Store.Pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer lock.Release()
	key := target.TenantID + ":fleet-history-poll:" + target.RegistrationID
	var held bool
	if err = lock.QueryRow(ctx, "SELECT pg_try_advisory_lock(hashtextextended($1,0))", key).Scan(&held); err != nil || !held {
		return err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if _, err := lock.Exec(cleanup, "SELECT pg_advisory_unlock(hashtextextended($1,0))", key); err != nil {
			_ = lock.Conn().Close(cleanup)
		}
	}()
	checkpointKey := "history-poll:" + target.RegistrationID
	var failures int64
	var sourceID, registrationHash string
	var cadence time.Duration
	var due bool
	err = r.Store.Do(ctx, target.TenantID, func(tx *store.Tx) error {
		doc, err := tx.FleetHistoryRegistrationGet(ctx, target.RegistrationID)
		if err != nil {
			return err
		}
		registered, err := store.FleetHistoryRegistrationDocument(doc)
		if err != nil || registered.Binding.TenantID != target.TenantID {
			return errors.New("HISTORY_POLL_REGISTRATION_INVALID")
		}
		if registered.CadenceSeconds < 15 {
			return errors.New("HISTORY_NATIVE_CADENCE_UNSUPPORTED")
		}
		sourceID, registrationHash, cadence = registered.SourceID, model.String(doc, "hash"), time.Duration(registered.CadenceSeconds)*time.Second
		previous, err := tx.SourceCheckpointGet(ctx, sourceID, checkpointKey)
		if err != nil && err != pgx.ErrNoRows {
			return err
		}
		if err == nil && model.String(previous, "registration_hash") == registrationHash {
			next, parse := time.Parse(time.RFC3339Nano, model.String(previous, "next_poll_at"))
			if parse != nil {
				return errors.New("HISTORY_POLL_CHECKPOINT_INVALID")
			}
			if r.now().Before(next) {
				return nil
			}
			failures = model.Number(previous, "consecutive_failures")
		}
		due = true
		return tx.SourceCheckpointSet(ctx, sourceID, checkpointKey, model.Document{"status": "OBSERVING", "registration_hash": registrationHash, "attempted_at": r.now(), "next_poll_at": r.now().Add(3 * time.Minute), "consecutive_failures": failures})
	})
	if err != nil || !due {
		return err
	}
	observeContext, cancel := context.WithTimeout(ctx, 150*time.Second)
	observation, captureErr := r.Capture.Capture(observeContext, target.TenantID, target.RegistrationID)
	cancel()
	status, reason := "OBSERVED_ONLY", ""
	if captureErr != nil {
		status, reason = "UNAVAILABLE", "HISTORY_CAPTURE_UNAVAILABLE"
		if failures < 4 {
			failures++
		}
		cadence = hardwareBackoff(failures)
	} else {
		failures = 0
	}
	if err = r.Store.Do(ctx, target.TenantID, func(tx *store.Tx) error {
		return tx.SourceCheckpointSet(ctx, sourceID, checkpointKey, model.Document{"status": status, "reason_code": reason, "registration_hash": registrationHash, "observation_id": model.String(observation, "id"), "completed_at": r.now(), "next_poll_at": r.now().Add(cadence), "consecutive_failures": failures})
	}); err != nil {
		return err
	}
	return captureErr
}
