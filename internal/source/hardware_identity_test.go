package source

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestHardwareIdentityPublicationClosesIssuedParentReplayAndRevocation(t *testing.T) {
	admin, ingester := historyFactoryDatabase(t)
	ctx := context.Background()
	raw, err := os.ReadFile("../provider/testdata/hardware_capture.bin")
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"success", "source-revoked-during-read", "source-config-changed-during-read", "mapping-changed-during-read", "pinned-bytes-changed"} {
		t.Run(mode, func(t *testing.T) {
			tenant := "identity-" + model.ID()
			target := hardwareSourceFixture(t, admin, tenant)
			now := time.Now().UTC()
			capture := &HardwarePipeline{Store: ingester, Targets: map[string]HardwareTarget{tenant + ":" + target.Binding.ResourceID: target}, ReaderFactory: func(context.Context, Registration, string) (HardwareReader, error) {
				return hardwareFixtureReader{raw: raw, now: now}, nil
			}, Archive: func(_ context.Context, actualTenant, resource string, body []byte) (model.Document, error) {
				return model.Document{"bucket": "identity-fixture", "key": "tenant/" + actualTenant + "/hardware/" + resource + "/" + BytesHash(body) + ".bin", "version_id": "original-version", "body_sha256": BytesHash(body)}, nil
			}}
			parent, err := capture.Capture(ctx, tenant, target.Binding.ResourceID)
			if err != nil {
				t.Fatal("issued hardware parent unavailable", err)
			}
			parentHash := hardwareIdentityParentHash(parent)
			pipeline := &HardwareIdentityPipeline{Store: ingester, ReadObject: func(_ context.Context, actualTenant string, ref model.Document) ([]byte, error) {
				if actualTenant != tenant || Hash(ref) != Hash(parent["raw_object"]) {
					return nil, errors.New("derivation did not request issued object version")
				}
				if mode == "source-revoked-during-read" || mode == "source-config-changed-during-read" || mode == "mapping-changed-during-read" {
					if err := admin.Do(ctx, tenant, func(tx *store.Tx) error {
						if _, err := tx.Exec(ctx, "SET LOCAL ROLE finops_api"); err != nil {
							return err
						}
						if mode == "mapping-changed-during-read" {
							r, err := tx.Get(ctx, "resources", target.Binding.ResourceID)
							if err != nil {
								return err
							}
							r["workload_id"] = "different-workload"
							_, err = tx.Update(ctx, "resources", target.Binding.ResourceID, model.Number(r, "version"), r)
							return err
						}
						src, err := tx.SourceGet(ctx, target.SourceID)
						if err != nil {
							return err
						}
						if mode == "source-revoked-during-read" {
							src["enabled"] = false
						} else {
							src["prefix"] = "changed-prefix/"
						}
						_, err = tx.SourceUpdate(ctx, target.SourceID, model.Number(src, "version"), src)
						return err
					}); err != nil {
						return nil, err
					}
				}
				if mode == "pinned-bytes-changed" {
					return []byte("different"), nil
				}
				return append([]byte{}, raw...), nil
			}}
			result, err := pipeline.Derive(ctx, tenant, model.String(parent, "id"))
			if mode != "success" {
				if err == nil {
					t.Fatal("new derivation ignored current identity or pinned bytes", mode)
				}
				if err := ingester.Do(ctx, tenant, func(tx *store.Tx) error {
					var count int
					if err := tx.QueryRow(ctx, "SELECT count(*) FROM hardware_identity_derivations WHERE tenant_id=$1", tenant).Scan(&count); err != nil {
						return err
					}
					if count != 0 {
						return errors.New("failed derivation left immutable publication")
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				return
			}
			if err != nil || model.String(result, "status") != "OBSERVED_ONLY" || model.String(result, "incarnation_status") != "UNKNOWN" || model.String(result, "interval_ownership") != "UNPROVEN" || model.Bool(result, "execution_authorized") || result["verified_saving"] != nil || model.String(result, "parent_received_at") != model.String(parent, "created_at") {
				t.Fatal("new identity publication lost truthful authority/time boundaries", result, err)
			}
			identity := Object(result["identity"])
			if identity["primary_eni"] != nil || identity["last_start_time"] != nil {
				t.Fatal("old parent omitted native identity fields but derivation invented them")
			}
			if err := admin.Do(ctx, tenant, func(tx *store.Tx) error {
				if _, err := tx.Exec(ctx, "SET LOCAL ROLE finops_api"); err != nil {
					return err
				}
				src, err := tx.SourceGet(ctx, target.SourceID)
				if err != nil {
					return err
				}
				src["sync_requested"] = true
				_, err = tx.SourceUpdate(ctx, target.SourceID, model.Number(src, "version"), src)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			replay, err := pipeline.Derive(ctx, tenant, model.String(parent, "id"))
			if err != nil || model.String(replay, "id") != model.String(result, "id") || model.String(replay, "created_at") != model.String(result, "created_at") {
				t.Fatal("benign source version bump rewrote historical identity", err)
			}
			payload := model.Clone(result)
			for _, key := range []string{"id", "hash", "created_at", "writer_role"} {
				delete(payload, key)
			}
			for _, bad := range []string{"parent-hash", "parent-time", "object-version", "binding", "decoder-instance", "authority", "unknown-field"} {
				d := model.Clone(payload)
				switch bad {
				case "parent-hash":
					d["parent_canonical_hash"] = BytesHash([]byte("different"))
				case "parent-time":
					d["parent_received_at"] = now.Add(-time.Hour).Format(time.RFC3339Nano)
				case "object-version":
					ref := Object(d["raw_object"])
					ref["version_id"] = "new-version"
					d["raw_object"] = ref
				case "binding":
					b := Object(d["binding"])
					b["workload_id"] = "different"
					d["binding"] = b
				case "decoder-instance":
					n := Object(d["identity"])
					n["instance_id"] = "i-aaaaaaaaaaaaaaaaa"
					d["identity"] = n
				case "authority":
					d["execution_authorized"] = true
				case "unknown-field":
					d["complete"] = true
				}
				if err := ingester.Do(ctx, tenant, func(tx *store.Tx) error { _, _, err := tx.HardwareIdentityAppend(ctx, d); return err }); err == nil {
					t.Fatal("issued-parent guard accepted forged binding/authority", bad)
				}
			}
			if err := ingester.Do(ctx, tenant, func(tx *store.Tx) error {
				current, err := tx.SourceReceiptGet(ctx, model.String(parent, "id"))
				if err != nil {
					return err
				}
				if hardwareIdentityParentHash(current) != parentHash {
					return errors.New("identity derivation rewrote issued v1 parent")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			// A final authority transaction excludes both source synchronization
			// and a committed revocation until its issued-parent selection ends.
			if err := ingester.Do(ctx, tenant, func(tx *store.Tx) error {
				if err := tx.HardwareIdentitySourceLock(ctx, target.SourceID); err != nil {
					return err
				}
				other, err := admin.Pool.Acquire(ctx)
				if err != nil {
					return err
				}
				defer other.Release()
				var held bool
				if err := other.QueryRow(ctx, "SELECT pg_try_advisory_lock(hashtextextended($1,0))", tenant+":trusted-source:"+target.SourceID).Scan(&held); err != nil {
					return err
				}
				if held {
					_, _ = other.Exec(ctx, "SELECT pg_advisory_unlock(hashtextextended($1,0))", tenant+":trusted-source:"+target.SourceID)
					return errors.New("source sync escaped derivation snapshot")
				}
				err = admin.Do(ctx, tenant, func(api *store.Tx) error {
					if _, err := api.Exec(ctx, "SET LOCAL ROLE finops_api"); err != nil {
						return err
					}
					if _, err := api.Exec(ctx, "SET LOCAL lock_timeout='200ms'"); err != nil {
						return err
					}
					src, err := api.SourceGet(ctx, target.SourceID)
					if err != nil {
						return err
					}
					src["enabled"] = false
					_, err = api.SourceUpdate(ctx, target.SourceID, model.Number(src, "version"), src)
					return err
				})
				var blocked *pgconn.PgError
				if !errors.As(err, &blocked) || blocked.Code != "55P03" {
					return fmt.Errorf("source revoke escaped derivation row lock: %v", err)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			func() {
				holder, err := admin.Pool.Acquire(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer holder.Release()
				var held bool
				if err = holder.QueryRow(ctx, "SELECT pg_try_advisory_lock(hashtextextended($1,0))", tenant+":trusted-source:"+target.SourceID).Scan(&held); err != nil || !held {
					t.Fatal("owned source sync guard unavailable", err)
				}
				defer func() {
					_, _ = holder.Exec(context.Background(), "SELECT pg_advisory_unlock(hashtextextended($1,0))", tenant+":trusted-source:"+target.SourceID)
				}()
				if _, err = pipeline.Derive(ctx, tenant, model.String(parent, "id")); !errors.Is(err, store.ErrHardwareIdentitySource) {
					t.Fatal("in-flight source sync did not block writer replay", err)
				}
			}()
			if err := ingester.Do(ctx, tenant, func(tx *store.Tx) error {
				if err := tx.HardwareIdentitySourceLock(ctx, "missing-source"); !errors.Is(err, store.ErrHardwareIdentitySource) {
					return errors.New("missing source did not remain a typed error")
				}
				var usable bool
				if err := tx.QueryRow(ctx, "SELECT true").Scan(&usable); err != nil || !usable {
					return errors.New("missing source aborted transaction")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			// Even an exact store-level replay must not skip the mapped-resource
			// closure enforced by the INSERT trigger.
			if err := admin.Do(ctx, tenant, func(tx *store.Tx) error {
				if _, err := tx.Exec(ctx, "SET LOCAL ROLE finops_api"); err != nil {
					return err
				}
				r, err := tx.Get(ctx, "resources", target.Binding.ResourceID)
				if err != nil {
					return err
				}
				r["workload_id"] = "changed-after-publication"
				_, err = tx.Update(ctx, "resources", target.Binding.ResourceID, model.Number(r, "version"), r)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if err := ingester.Do(ctx, tenant, func(tx *store.Tx) error { _, _, err := tx.HardwareIdentityAppend(ctx, payload); return err }); err == nil {
				t.Fatal("exact writer replay bypassed current mapping")
			}
			if err := admin.Do(ctx, tenant, func(tx *store.Tx) error {
				if _, err := tx.Exec(ctx, "SET LOCAL ROLE finops_api"); err != nil {
					return err
				}
				old, err := tx.HardwareIdentityGet(ctx, model.String(result, "id"))
				if err != nil || model.String(old, "hash") != model.String(result, "hash") {
					return errors.New("immutable historical read changed after mapping update")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			for _, role := range []string{"finops_api", "finops_worker", "finops_signer", "finops_executor"} {
				err := admin.Do(ctx, tenant, func(tx *store.Tx) error {
					if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+pgx.Identifier{role}.Sanitize()); err != nil {
						return err
					}
					_, _, err := tx.HardwareIdentityAppend(ctx, payload)
					return err
				})
				var denied *pgconn.PgError
				if !errors.As(err, &denied) || denied.Code != "42501" {
					t.Fatal("identity writer crossed process boundary", role, err)
				}
			}
			if err := ingester.Do(ctx, tenant+"-foreign", func(tx *store.Tx) error {
				_, err := tx.HardwareIdentityGet(ctx, model.String(result, "id"))
				if err != pgx.ErrNoRows {
					return fmt.Errorf("cross-tenant immutable read returned %v", err)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
