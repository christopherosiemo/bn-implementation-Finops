package source

import (
	"context"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleethistory"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
)

func historyFactoryDatabase(t *testing.T) (*store.Store, *store.Store) {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("disposable PostgreSQL administrator required")
	}
	ctx := context.Background()
	root, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal("test PostgreSQL unavailable")
	}
	t.Cleanup(root.Pool.Close)
	name := "history_factory_" + strings.ReplaceAll(model.ID(), "-", "")
	marker := "owned-history-factory-" + model.ID()
	if _, err = root.Pool.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	if _, err = root.Pool.Exec(ctx, "COMMENT ON DATABASE "+pgx.Identifier{name}.Sanitize()+" IS '"+marker+"'"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		var actual string
		if err := root.Pool.QueryRow(context.Background(), "SELECT shobj_description(oid,'pg_database') FROM pg_database WHERE datname=$1", name).Scan(&actual); err != nil || actual != marker || !strings.HasPrefix(name, "history_factory_") {
			t.Error("owned history factory database cleanup identity mismatch")
			return
		}
		if _, err := root.Pool.Exec(context.Background(), "DROP DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
			t.Error("owned history factory database cleanup failed", err)
		}
	})
	configuration, err := url.Parse(dsn)
	if err != nil || configuration.Scheme != "postgres" && configuration.Scheme != "postgresql" {
		t.Fatal("test database URL configuration invalid")
	}
	configuration.Path = "/" + name
	admin, err := store.Open(ctx, configuration.String())
	if err != nil {
		t.Fatal("owned test database unavailable")
	}
	t.Cleanup(admin.Pool.Close)
	if err = admin.Migrate(ctx, "../../migrations"); err != nil {
		t.Fatal(err)
	}
	login := "hf_" + strings.ReplaceAll(model.ID(), "-", "")
	password := model.ID()
	if _, err = root.Pool.Exec(ctx, "CREATE ROLE "+pgx.Identifier{login}.Sanitize()+" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '"+password+"' IN ROLE finops_ingester"); err != nil {
		t.Fatal("restricted factory login setup failed")
	}
	t.Cleanup(func() {
		if _, err := root.Pool.Exec(context.Background(), "DROP ROLE "+pgx.Identifier{login}.Sanitize()); err != nil {
			t.Error("owned factory login cleanup failed", err)
		}
	})
	configuration.User = url.UserPassword(login, password)
	ingester, err := store.OpenRuntime(ctx, configuration.String(), "fleet-history-reader")
	if err != nil {
		t.Fatal("restricted factory ingestion identity unavailable", err)
	}
	t.Cleanup(ingester.Pool.Close)
	return admin, ingester
}

type historyFixtureReader struct {
	evidence provider.FleetInventoryEvidence
}

func (r *historyFixtureReader) FleetInventory(ctx context.Context, region, account string, names []string) (provider.FleetInventoryEvidence, error) {
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > 45*time.Second || region != r.evidence.Region || account != r.evidence.AccountID || len(names) != 1 || names[0] != "asg-blue" {
		return provider.FleetInventoryEvidence{}, errors.New("history fixture read scope or deadline changed")
	}
	return r.evidence, nil
}

// Native transport and archive are explicit doubles here. The separate storage
// acceptance must exercise versioned S3 readback; this test proves the factory's
// actual PostgreSQL publication ordering, source recheck and atomic projection.
func TestFleetHistoryFactoryPublishesAtomicNativePointsWithOriginalReceiptTime(t *testing.T) {
	admin, ingester := historyFactoryDatabase(t)
	ctx := context.Background()
	for _, mode := range []string{"success", "failed archive", "unversioned archive", "revoked source", "changed registration"} {
		t.Run(mode, func(t *testing.T) {
			tenant := "history-factory-" + model.ID()
			registered, native := historyNativeFixture(t, time.Now().UTC())
			registered.Binding.TenantID = tenant
			src := FixtureRegistration(tenant, registered.SourceID)
			registered.SourceConfigHash = ConfigurationHash(src)
			if err := admin.Do(ctx, tenant, func(tx *store.Tx) error {
				if _, err := tx.Exec(ctx, "SET LOCAL ROLE finops_api"); err != nil {
					return err
				}
				if _, err := tx.Create(ctx, "workloads", model.Document{"id": registered.Binding.WorkloadID, "name": "Read-only history fixture"}); err != nil {
					return err
				}
				if _, err := tx.SourceCreate(ctx, src); err != nil {
					return err
				}
				_, err := tx.FleetHistoryRegistrationAppend(ctx, 0, registered)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			reader := &historyFixtureReader{native}
			archives := 0
			pipeline := FleetHistoryPipeline{Store: ingester, ReaderFactory: func(_ context.Context, r Registration, account string) (FleetReader, error) {
				if r.TenantID != tenant || r.ID != registered.SourceID || account != registered.Binding.AccountID {
					return nil, errors.New("history credential binding changed")
				}
				return reader, nil
			}, Archive: func(_ context.Context, actualTenant, target string, raw []byte) (model.Document, error) {
				archives++
				if actualTenant != tenant || target != "history-"+fleethistory.RegistrationHash(registered) || BytesHash(raw) != native.RawSHA256 {
					return nil, errors.New("history archive scope changed")
				}
				if mode == "failed archive" {
					return nil, errors.New("fixture archive unavailable")
				}
				if mode == "revoked source" || mode == "changed registration" {
					if err := admin.Do(ctx, tenant, func(tx *store.Tx) error {
						if _, err := tx.Exec(ctx, "SET LOCAL ROLE finops_api"); err != nil {
							return err
						}
						if mode == "changed registration" {
							next := registered
							next.Version++
							next.MaxGapSeconds++
							_, err := tx.FleetHistoryRegistrationAppend(ctx, 1, next)
							return err
						}
						current, err := tx.SourceGet(ctx, registered.SourceID)
						if err != nil {
							return err
						}
						current["revoked"] = true
						_, err = tx.SourceUpdate(ctx, registered.SourceID, model.Number(current, "version"), current)
						return err
					}); err != nil {
						return nil, err
					}
				}
				version := "fixture-version-" + model.ID()
				if mode == "unversioned archive" {
					version = "null"
				}
				return model.Document{"bucket": "raw-fixture", "key": "tenant/" + tenant + "/fleet/" + target + "/" + BytesHash(raw) + ".bin", "version_id": version, "body_sha256": BytesHash(raw)}, nil
			}}
			result, err := pipeline.Capture(ctx, tenant, registered.ID)
			if archives != 1 {
				t.Fatal("capture did not archive exactly once before publication", archives)
			}
			if mode != "success" {
				if err == nil {
					t.Fatal("failed or changed capture was published")
				}
				if err := ingester.Do(ctx, tenant, func(tx *store.Tx) error {
					rows, e := tx.SourceReceiptList(ctx, "AWS_FLEET_MEMBERSHIP", registered.SourceID)
					if e == nil && len(rows) != 0 {
						return errors.New("failed capture left native authority visible")
					}
					return e
				}); err != nil {
					t.Fatal(err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			observation, err := store.FleetHistoryObservationDocument(registered, result)
			if err != nil || len(observation.Members) != 2 || observation.Source.Kind != "AWS_FLEET_MEMBERSHIP" || observation.Source.SourceSystem != "AWS_SOURCE_CONNECTION" || observation.Source.Archive == nil {
				t.Fatal("native observation not source-bound", err)
			}
			if !observation.ObservedAt.Equal(native.CollectedAt) || observation.ReceivedAt.Before(observation.ObservedAt) || observation.Members[0].LaunchTime != nil || observation.Members[0].Hardware != nil {
				t.Fatal("projection manufactured timestamps or incarnation")
			}
			replay, err := pipeline.Capture(ctx, tenant, registered.ID)
			if err != nil || model.String(replay, "id") != model.String(result, "id") || model.String(replay, "hash") != model.String(result, "hash") {
				t.Fatal("native replay changed immutable history", err)
			}
			// Identical native bytes at a later real capture are a new point, not
			// a new configuration/data revision or proof of the intervening time.
			reader.evidence.CollectedAt = time.Now().UTC()
			next, err := pipeline.Capture(ctx, tenant, registered.ID)
			if err != nil || model.String(next, "id") == model.String(result, "id") {
				t.Fatal("genuine later point lost because native bytes were unchanged", err)
			}
			if err := ingester.Do(ctx, "unrelated-"+tenant, func(tx *store.Tx) error {
				rows, e := tx.FleetHistoryObservationPage(ctx, registered.ID, "", 100)
				if e == nil && len(rows) != 0 {
					return errors.New("foreign tenant saw native history")
				}
				return e
			}); err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(observation.Source.Archive.Key, "tenant/"+tenant+"/fleet/") {
				t.Fatal("archive escaped tenant prefix")
			}
		})
	}
}
