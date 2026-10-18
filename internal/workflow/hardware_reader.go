package workflow

import (
	"context"
	"errors"
	"log/slog"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/native"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/service"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
)

type hardwareCapturer interface {
	Capture(context.Context, string, string) (model.Document, error)
}
type hardwareReader struct {
	Store   *store.Store
	Targets map[string]source.HardwareTarget
	Capture hardwareCapturer
	Now     func() time.Time
}

func (r *hardwareReader) now() time.Time {
	if r.Now != nil {
		return r.Now().UTC()
	}
	return time.Now().UTC()
}
func hardwareBackoff(failures int64) time.Duration {
	if failures <= 1 {
		return time.Minute
	}
	if failures == 2 {
		return 2 * time.Minute
	}
	if failures == 3 {
		return 4 * time.Minute
	}
	return 5 * time.Minute
}

func hardwareConfiguration(encoded string, fixture bool) (map[string]source.HardwareTarget, error) {
	targets, err := source.HardwareTargets(encoded)
	if err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		return nil, errors.New("HARDWARE_APPROVED_TARGET_REQUIRED")
	}
	if fixture {
		return nil, errors.New("HARDWARE_NATIVE_READ_DISABLED_IN_FIXTURE_MODE")
	}
	return targets, nil
}

// RunHardwareReader is an explicitly enabled, read-only ingestion process. It
// has no Temporal task queue, signing key, financial ledger writer or mutation
// role. Slow regional reads cannot delay the main billing/audit ingestion loop.
func RunHardwareReader(ctx context.Context, cfg service.Config, db *store.Store) error {
	targets, err := hardwareConfiguration(os.Getenv("AWS_HARDWARE_TARGETS_JSON"), cfg.Fixture)
	if err != nil {
		return err
	}
	if os.Getenv("OBJECT_ACCESS_KEY") != "" || os.Getenv("OBJECT_SECRET_KEY") != "" || os.Getenv("AWS_ACCESS_KEY_ID") != "" || os.Getenv("AWS_SECRET_ACCESS_KEY") != "" || os.Getenv("AWS_ROLE_ARN") == "" || os.Getenv("AWS_WEB_IDENTITY_TOKEN_FILE") == "" {
		return errors.New("HARDWARE_RENEWABLE_WORKLOAD_IDENTITY_REQUIRED")
	}
	if os.Getenv("AWS_TENANT_ID") == "" {
		return errors.New("HARDWARE_COMMISSIONED_TENANT_REQUIRED")
	}
	for _, target := range targets {
		if target.Binding.TenantID != os.Getenv("AWS_TENANT_ID") {
			return errors.New("HARDWARE_COMMISSIONED_TENANT_MISMATCH")
		}
	}
	if endpoint := os.Getenv("OBJECT_ENDPOINT"); endpoint != "" && !hardwareStorageEndpoint(endpoint) {
		return errors.New("HARDWARE_IRELAND_STORAGE_ENDPOINT_REQUIRED")
	}
	factory, err := source.HardwareAWSFactory(os.Getenv("AWS_SOURCE_READ_BINDINGS_JSON"))
	if err != nil {
		return err
	}
	storage, err := native.StorageFromEnvironment(ctx, false)
	if err != nil {
		return err
	}
	archive := &source.HardwareS3Archive{Client: storage.S3, Bucket: storage.Bucket}
	reader := &hardwareReader{Store: db, Targets: targets, Capture: &source.HardwarePipeline{Store: db, Targets: targets, ReaderFactory: factory, Archive: archive.Archive}}
	timer := time.NewTicker(15 * time.Second)
	defer timer.Stop()
	for {
		if err := reader.tick(ctx); err != nil && ctx.Err() == nil {
			// Native response bodies, role/external IDs and credentials stay private.
			slog.Error("native hardware observation unavailable", "reason_code", "HARDWARE_CAPTURE_UNAVAILABLE")
		}
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
		}
	}
}
func hardwareStorageEndpoint(endpoint string) bool {
	u, err := url.Parse(endpoint)
	return err == nil && u.Scheme == "https" && u.User == nil && u.Port() == "" && u.RawQuery == "" && u.Fragment == "" && (u.Path == "" || u.Path == "/") && (u.Host == "s3.eu-west-1.amazonaws.com" || strings.HasSuffix(u.Host, ".s3.eu-west-1.vpce.amazonaws.com"))
}
func (r *hardwareReader) tick(ctx context.Context) error {
	keys := make([]string, 0, len(r.Targets))
	for key := range r.Targets {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var first error
	for _, key := range keys {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := r.capture(ctx, r.Targets[key]); err != nil && first == nil {
			first = err
		}
	}
	return first
}
func (r *hardwareReader) capture(ctx context.Context, target source.HardwareTarget) error {
	if r.Store == nil || r.Capture == nil {
		return errors.New("HARDWARE_READER_DEPENDENCIES_REQUIRED")
	}
	b := target.Binding
	lock, err := r.Store.Pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer lock.Release()
	var held bool
	key := b.TenantID + ":native-hardware-poll:" + b.ResourceID
	if err = lock.QueryRow(ctx, "SELECT pg_try_advisory_lock(hashtextextended($1,0))", key).Scan(&held); err != nil {
		return err
	}
	if !held {
		return nil
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if _, err := lock.Exec(cleanup, "SELECT pg_advisory_unlock(hashtextextended($1,0))", key); err != nil {
			_ = lock.Conn().Close(cleanup)
		}
	}()
	checkpointKey := "hardware-poll:" + b.ResourceID
	var failures int64
	var due bool
	err = r.Store.Do(ctx, b.TenantID, func(tx *store.Tx) error {
		previous, e := tx.SourceCheckpointGet(ctx, target.SourceID, checkpointKey)
		if e != nil && e != pgx.ErrNoRows {
			return e
		}
		if e == nil {
			next, parse := time.Parse(time.RFC3339Nano, model.String(previous, "next_poll_at"))
			if parse != nil {
				return errors.New("HARDWARE_POLL_CHECKPOINT_INVALID")
			}
			if r.now().Before(next) {
				return nil
			}
			failures = model.Number(previous, "consecutive_failures")
		}
		due = true
		// Persist a bounded lease before any provider I/O. A process death cannot
		// cause every replica to immediately repeat the same native request.
		return tx.SourceCheckpointSet(ctx, target.SourceID, checkpointKey, model.Document{"status": "OBSERVING", "attempted_at": r.now(), "next_poll_at": r.now().Add(3 * time.Minute), "consecutive_failures": failures})
	})
	if err != nil || !due {
		return err
	}
	observeCtx, cancel := context.WithTimeout(ctx, 150*time.Second)
	receipt, captureErr := r.Capture.Capture(observeCtx, b.TenantID, b.ResourceID)
	cancel()
	status, reason, delay := "OBSERVED_ONLY", "", time.Minute
	if captureErr != nil {
		status = "UNAVAILABLE"
		reason = "HARDWARE_CAPTURE_UNAVAILABLE"
		if failures < 4 {
			failures++
		}
		delay = hardwareBackoff(failures)
	} else {
		failures = 0
	}
	if err = r.Store.Do(ctx, b.TenantID, func(tx *store.Tx) error {
		return tx.SourceCheckpointSet(ctx, target.SourceID, checkpointKey, model.Document{"status": status, "reason_code": reason, "receipt_id": model.String(receipt, "id"), "completed_at": r.now(), "next_poll_at": r.now().Add(delay), "consecutive_failures": failures})
	}); err != nil {
		return err
	}
	return captureErr
}
