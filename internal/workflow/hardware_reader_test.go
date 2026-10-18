package workflow

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/service"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/telemetry"
	"github.com/jackc/pgx/v5"
)

type hardwareCaptureFunc func(context.Context, string, string) (model.Document, error)

func (f hardwareCaptureFunc) Capture(c context.Context, t, r string) (model.Document, error) {
	return f(c, t, r)
}

func TestHardwareRuntimeRequiresExplicitLiveTargetsAndNeverCallsAWSInFixtures(t *testing.T) {
	target := source.HardwareTarget{SourceID: "source-a", Binding: telemetry.Binding{TenantID: "tenant-a", ResourceID: "resource-a", WorkloadID: "workload-a", Provider: "AWS", ProviderResourceID: "i-0123456789abcdef0", AccountID: "111122223333", Region: "eu-west-1"}, CandidateTypes: []string{"m7i.large"}}
	raw, _ := json.Marshal([]source.HardwareTarget{target})
	if _, err := hardwareConfiguration(string(raw), false); err != nil {
		t.Fatal(err)
	}
	for _, input := range []struct {
		raw     string
		fixture bool
	}{{"", false}, {"[]", false}, {string(raw), true}, {`[{"trusted":true}]`, false}, {strings.Replace(string(raw), "eu-west-1", "us-east-1", 1), false}} {
		if _, err := hardwareConfiguration(input.raw, input.fixture); err == nil {
			t.Fatal("unapproved native configuration accepted")
		}
	}
}

func TestHardwareRuntimeRejectsNonIrishObjectsAndStaticCredentialStartup(t *testing.T) {
	for _, endpoint := range []string{"https://s3.eu-west-1.amazonaws.com", "https://vpce-1234.s3.eu-west-1.vpce.amazonaws.com/"} {
		if !hardwareStorageEndpoint(endpoint) {
			t.Fatal("regional endpoint rejected")
		}
	}
	for _, endpoint := range []string{"http://s3.eu-west-1.amazonaws.com", "https://s3.us-east-1.amazonaws.com", "https://s3.eu-west-1.amazonaws.com.evil.invalid", "https://user@s3.eu-west-1.amazonaws.com", "https://s3.eu-west-1.amazonaws.com/foreign", "https://s3.eu-west-1.amazonaws.com?token=fixture"} {
		if hardwareStorageEndpoint(endpoint) {
			t.Fatal("unapproved storage endpoint accepted")
		}
	}
	for _, key := range []string{"AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE", "OBJECT_ACCESS_KEY", "OBJECT_SECRET_KEY", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"} {
		t.Setenv(key, "")
	}
	target := source.HardwareTarget{SourceID: "source-a", Binding: telemetry.Binding{TenantID: "tenant-a", ResourceID: "resource-a", WorkloadID: "workload-a", Provider: "AWS", ProviderResourceID: "i-0123456789abcdef0", AccountID: "111122223333", Region: "eu-west-1"}, CandidateTypes: []string{"m7i.large"}}
	raw, _ := json.Marshal([]source.HardwareTarget{target})
	t.Setenv("AWS_HARDWARE_TARGETS_JSON", string(raw))
	if err := RunHardwareReader(context.Background(), service.Config{}, nil); err == nil || err.Error() != "HARDWARE_RENEWABLE_WORKLOAD_IDENTITY_REQUIRED" {
		t.Fatal("native reader started without renewable commissioned identity")
	}
	previous := time.Duration(0)
	for _, failures := range []int64{1, 2, 3, 4, 100, 1 << 62} {
		delay := hardwareBackoff(failures)
		if delay < time.Minute || delay > 5*time.Minute || delay < previous {
			t.Fatal("unbounded native retry or quota retry storm")
		}
		previous = delay
	}
}

// The runtime adapter uses actual restricted PostgreSQL sessions. The fake
// capturer models a native read only; it cannot create a trusted source receipt.
func TestHardwareRuntimeDurablePollingCrossReplicaLocksAndDedicatedIdentity(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("disposable PostgreSQL administrator required")
	}
	ctx := context.Background()
	root, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal("test database unavailable")
	}
	t.Cleanup(root.Pool.Close)
	suffix := strings.ReplaceAll(model.ID(), "-", "")
	database, login := "hardware_runtime_"+suffix, "hardware_login_"+suffix
	if _, err = root.Pool.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{database}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, e := root.Pool.Exec(context.Background(), "DROP DATABASE "+pgx.Identifier{database}.Sanitize()); e != nil {
			t.Error("test-owned database cleanup failed", e)
		}
	})
	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	parsed.Path = "/" + database
	admin, err := store.Open(ctx, parsed.String())
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Pool.Close()
	dir := t.TempDir()
	files, err := filepath.Glob("../../migrations/*.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if filepath.Base(file) > "017_native_hardware.sql" {
			continue
		}
		b, e := os.ReadFile(file)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(dir, filepath.Base(file)), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	if err = admin.Migrate(ctx, dir); err != nil {
		t.Fatal(err)
	}
	password := strings.ReplaceAll(model.ID(), "-", "")
	if _, err = admin.Pool.Exec(ctx, "CREATE ROLE "+pgx.Identifier{login}.Sanitize()+" LOGIN PASSWORD '"+password+"' IN ROLE finops_hardware_reader"); err != nil {
		t.Fatal("cannot create restricted test login")
	}
	t.Cleanup(func() {
		if _, e := root.Pool.Exec(context.Background(), "DROP ROLE "+pgx.Identifier{login}.Sanitize()); e != nil {
			t.Error("test-owned login cleanup failed", e)
		}
	})
	loginConfig := *parsed
	loginConfig.User = url.UserPassword(login, password)
	undersized := loginConfig
	query := undersized.Query()
	query.Set("pool_max_conns", "1")
	undersized.RawQuery = query.Encode()
	if blocked, e := store.OpenHardwareReader(ctx, undersized.String()); e == nil {
		blocked.Pool.Close()
		t.Fatal("single-connection pool could deadlock the durable lock and tenant transaction")
	}
	readerDB, err := store.OpenHardwareReader(ctx, loginConfig.String())
	if err != nil {
		t.Fatal(err)
	}
	defer readerDB.Pool.Close()
	if unauthorized, e := store.OpenHardwareReader(ctx, parsed.String()); e == nil {
		unauthorized.Pool.Close()
		t.Fatal("administrator accepted as hardware identity")
	}
	var current, session string
	if err = readerDB.Pool.QueryRow(ctx, "SELECT current_user,session_user").Scan(&current, &session); err != nil || current != "finops_ingester" || session != login {
		t.Fatal("hardware login/group separation lost")
	}
	tenant, sourceID := "hardware-tenant-"+suffix, "hardware-source-"+suffix
	if err = admin.Do(ctx, tenant, func(tx *store.Tx) error {
		_, e := tx.SourceCreate(ctx, model.Document{"id": sourceID, "kind": "AWS_CUR2", "enabled": true})
		return e
	}); err != nil {
		t.Fatal(err)
	}
	target := source.HardwareTarget{SourceID: sourceID, Binding: telemetry.Binding{TenantID: tenant, ResourceID: "resource-a"}}
	now := time.Now().UTC()
	var calls atomic.Int32
	entered, release := make(chan struct{}), make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	read := hardwareCaptureFunc(func(context.Context, string, string) (model.Document, error) {
		calls.Add(1)
		close(entered)
		<-release
		return model.Document{"id": "private-read-result"}, nil
	})
	runner := &hardwareReader{Store: readerDB, Capture: read, Now: func() time.Time { return now }}
	first := make(chan error, 1)
	go func() { first <- runner.capture(ctx, target) }()
	select {
	case <-entered:
	case e := <-first:
		t.Fatal("native read did not start", e)
	case <-time.After(10 * time.Second):
		t.Fatal("native read did not acquire its scoped lease")
	}
	if err = runner.capture(ctx, target); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatal("overlapping replicas repeated native read")
	}
	close(release)
	if err = <-first; err != nil {
		t.Fatal(err)
	}
	restarted := &hardwareReader{Store: readerDB, Capture: hardwareCaptureFunc(func(context.Context, string, string) (model.Document, error) {
		calls.Add(1)
		return nil, errors.New("private provider error must not be checkpointed")
	}), Now: func() time.Time { return now }}
	if err = restarted.capture(ctx, target); err != nil || calls.Load() != 1 {
		t.Fatal("restart lost successful poll throttle")
	}
	now = now.Add(61 * time.Second)
	if err = restarted.capture(ctx, target); err == nil || calls.Load() != 2 {
		t.Fatal("due native read was not attempted")
	}
	if err = restarted.capture(ctx, target); err != nil || calls.Load() != 2 {
		t.Fatal("failure backoff did not survive runner selection")
	}
	var checkpoint model.Document
	if err = readerDB.Do(ctx, tenant, func(tx *store.Tx) error {
		var e error
		checkpoint, e = tx.SourceCheckpointGet(ctx, sourceID, "hardware-poll:resource-a")
		return e
	}); err != nil {
		t.Fatal(err)
	}
	if model.String(checkpoint, "status") != "UNAVAILABLE" || model.String(checkpoint, "reason_code") != "HARDWARE_CAPTURE_UNAVAILABLE" || model.Number(checkpoint, "consecutive_failures") != 1 {
		t.Fatal("missing/error observation became a receipt")
	}
	foreign := target
	foreign.Binding.TenantID = "foreign-" + tenant
	if err = restarted.capture(ctx, foreign); err == nil || calls.Load() != 2 {
		t.Fatal("foreign source reached provider")
	}
	if _, err = admin.Pool.Exec(ctx, "GRANT finops_api TO "+pgx.Identifier{login}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	if confused, e := store.OpenHardwareReader(ctx, loginConfig.String()); e == nil {
		confused.Pool.Close()
		t.Fatal("mixed approval/API membership accepted")
	}
	if _, err = admin.Pool.Exec(ctx, "REVOKE finops_api FROM "+pgx.Identifier{login}.Sanitize()); err != nil {
		t.Fatal(err)
	}
}
