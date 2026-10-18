package source

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/telemetry"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func hardwareTestDB(t *testing.T) (*store.Store, *store.Store) {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("disposable PostgreSQL required")
	}
	ctx := context.Background()
	db, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Pool.Close)
	// Another delivery may have later draft migrations in this shared checkout.
	// Own acceptance applies exactly the prerequisites through this increment.
	dir := t.TempDir()
	files, err := os.ReadDir("../../migrations")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".sql") || len(file.Name()) < 3 || file.Name()[:3] > "017" {
			continue
		}
		raw, e := os.ReadFile(filepath.Join("../../migrations", file.Name()))
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(dir, file.Name()), raw, 0600); e != nil {
			t.Fatal(e)
		}
	}
	if err = db.Migrate(ctx, dir); err != nil {
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
		_, e := c.Exec(ctx, "SET ROLE finops_ingester")
		return e
	}
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return db, &store.Store{Pool: pool}
}

type hardwareFixtureReader struct {
	raw []byte
	now time.Time
}

func (f hardwareFixtureReader) HardwareInventory(ctx context.Context, region, account, instance string, candidates []string) (provider.HardwareEvidence, error) {
	if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 2*time.Minute {
		return provider.HardwareEvidence{}, errors.New("hardware reader deadline missing")
	}
	return provider.ParseHardwareEvidence(f.raw, account, region, instance, candidates, f.now)
}
func hardwareSourceFixture(t *testing.T, db *store.Store, tenant string) HardwareTarget {
	t.Helper()
	ctx := context.Background()
	target := HardwareTarget{SourceID: "hardware-source", CandidateTypes: []string{"m6i.large"}}
	if err := db.Do(ctx, tenant, func(tx *store.Tx) error {
		if _, e := tx.Exec(ctx, "SET LOCAL ROLE finops_api"); e != nil {
			return e
		}
		if e := tx.Seed(ctx, true); e != nil {
			return e
		}
		r, e := tx.Get(ctx, "resources", "resource-dev-api")
		if e != nil {
			return e
		}
		r["instance_type"] = "m6i.xlarge"
		r, e = tx.Update(ctx, "resources", "resource-dev-api", model.Number(r, "version"), r)
		if e != nil {
			return e
		}
		target.Binding = hardwareResourceBinding(tenant, r)
		_, e = tx.SourceCreate(ctx, FixtureRegistration(tenant, target.SourceID))
		return e
	}); err != nil {
		t.Fatal(err)
	}
	return target
}

func TestHardwareTargetConfigRejectsPublicPricesCredentialsAndScopeWildcards(t *testing.T) {
	b := telemetry.Binding{TenantID: "tenant", ResourceID: "resource", WorkloadID: "workload", Provider: "AWS", ProviderResourceID: "i-0123456789abcdef0", AccountID: "111122223333", Region: "eu-west-1"}
	target := HardwareTarget{Binding: b, SourceID: "source", CandidateTypes: []string{"m6i.large"}}
	raw, _ := json.Marshal([]HardwareTarget{target})
	if rows, e := HardwareTargets(string(raw)); e != nil || len(rows) != 1 {
		t.Fatal(e)
	}
	for _, field := range []string{`"prices":[]`, `"role_arn":"arn:aws:iam::111122223333:role/execute"`, `"credentials":{}`, `"execution_authorized":true`} {
		invalid := strings.TrimSuffix(string(raw), "}]") + "," + field + "}]"
		if _, e := HardwareTargets(invalid); e == nil {
			t.Fatal("private target accepted unrelated authority", field)
		}
	}
	for _, bad := range []string{"m6i.*", "*", "m6i.large\n"} {
		target.CandidateTypes = []string{bad}
		raw, _ = json.Marshal([]HardwareTarget{target})
		if _, e := HardwareTargets(string(raw)); e == nil {
			t.Fatal("candidate wildcard accepted")
		}
	}
}

func TestHardwarePipelinePublishesOnlyAfterArchiveAndCurrentInventoryRegistration(t *testing.T) {
	db, ingester := hardwareTestDB(t)
	ctx := context.Background()
	raw, err := os.ReadFile("../provider/testdata/hardware_capture.bin")
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"archive-failed", "unversioned", "source-revoked", "inventory-changed", "success"} {
		t.Run(mode, func(t *testing.T) {
			tenant := "hardware-" + model.ID()
			target := hardwareSourceFixture(t, db, tenant)
			now := time.Now().UTC()
			archived := false
			pipeline := HardwarePipeline{Store: ingester, Targets: map[string]HardwareTarget{tenant + ":" + target.Binding.ResourceID: target}, Now: func() time.Time { return now }, ReaderFactory: func(_ context.Context, r Registration, account string) (HardwareReader, error) {
				if r.TenantID != tenant || r.ID != target.SourceID || account != target.Binding.AccountID {
					return nil, errors.New("reader identity changed")
				}
				return hardwareFixtureReader{raw, now}, nil
			}, Archive: func(_ context.Context, actualTenant, resource string, body []byte) (model.Document, error) {
				if actualTenant != tenant || resource != target.Binding.ResourceID || !bytes.Equal(body, raw) {
					return nil, errors.New("archive scope or raw bytes changed")
				}
				if e := ingester.Do(ctx, tenant, func(tx *store.Tx) error {
					rows, e := tx.SourceReceiptList(ctx, HardwareKind, target.SourceID)
					if e == nil && len(rows) != 0 {
						return errors.New("source published before archive")
					}
					return e
				}); e != nil {
					return nil, e
				}
				archived = true
				if mode == "archive-failed" {
					return nil, errors.New("object unavailable")
				}
				version := "v1"
				if mode == "unversioned" {
					version = "null"
				}
				if mode == "source-revoked" || mode == "inventory-changed" {
					if e := db.Do(ctx, tenant, func(tx *store.Tx) error {
						if _, e := tx.Exec(ctx, "SET LOCAL ROLE finops_api"); e != nil {
							return e
						}
						if mode == "source-revoked" {
							d, e := tx.SourceGet(ctx, target.SourceID)
							if e != nil {
								return e
							}
							d["enabled"] = false
							_, e = tx.SourceUpdate(ctx, target.SourceID, model.Number(d, "version"), d)
							return e
						}
						r, e := tx.Get(ctx, "resources", target.Binding.ResourceID)
						if e != nil {
							return e
						}
						r["instance_type"] = "m6i.large"
						_, e = tx.Update(ctx, "resources", target.Binding.ResourceID, model.Number(r, "version"), r)
						return e
					}); e != nil {
						return nil, e
					}
				}
				return model.Document{"bucket": "raw", "key": "tenant/" + tenant + "/hardware/" + resource + "/native.bin", "version_id": version, "body_sha256": BytesHash(body)}, nil
			}}
			result, e := pipeline.Capture(ctx, tenant, target.Binding.ResourceID)
			if !archived {
				t.Fatal("native evidence did not reach archive")
			}
			if mode == "success" {
				if e != nil || model.String(result, "kind") != HardwareKind || model.String(result, "writer_role") != "finops_ingester" || model.Bool(result, "execution_authorized") {
					t.Fatal("native source receipt invalid", e, result)
				}
				pipeline.Archive = func(_ context.Context, tenant, resource string, body []byte) (model.Document, error) {
					return model.Document{"bucket": "raw", "key": "tenant/" + tenant + "/hardware/" + resource + "/native.bin", "version_id": "v1", "body_sha256": BytesHash(body)}, nil
				}
				replay, e := pipeline.Capture(ctx, tenant, target.Binding.ResourceID)
				if e != nil || model.String(replay, "id") != model.String(result, "id") {
					t.Fatal("exact native replay added an observation", e)
				}
				for name, mutate := range map[string]func(model.Document){
					"stale native observation": func(d model.Document) {
						d["collected_at"] = now.Add(-3 * time.Minute).Format(time.RFC3339Nano)
						n := telemetry.Document(d["native"])
						n["collected_at"] = d["collected_at"]
						d["native"] = n
					},
					"missing receive-bound time": func(d model.Document) { delete(d, "collected_at") },
					"future native observation": func(d model.Document) {
						d["collected_at"] = now.Add(time.Minute).Format(time.RFC3339Nano)
						n := telemetry.Document(d["native"])
						n["collected_at"] = d["collected_at"]
						d["native"] = n
					},
					"account substitution": func(d model.Document) {
						b := telemetry.Document(d["binding"])
						b["account_id"] = "999900001111"
						d["binding"] = b
					},
					"unversioned native object": func(d model.Document) {
						r := telemetry.Document(d["raw_object"])
						r["version_id"] = "null"
						d["raw_object"] = r
					},
					"native object hash substitution": func(d model.Document) {
						n := telemetry.Document(d["native"])
						n["raw_sha256"] = strings.Repeat("f", 64)
						d["native"] = n
					},
					"execution grant":         func(d model.Document) { d["execution_authorized"] = true },
					"operator supplied price": func(d model.Document) { d["prices"] = []any{model.Document{"amount": "0.01", "currency": "GBP"}} },
				} {
					t.Run(name, func(t *testing.T) {
						d := model.Clone(result)
						delete(d, "writer_role")
						delete(d, "created_at")
						d["id"] = model.ID()
						mutate(d)
						if e := ingester.Do(ctx, tenant, func(tx *store.Tx) error { _, e := tx.SourceReceiptCreate(ctx, d); return e }); e == nil {
							t.Fatal("SQL accepted unsafe native source receipt")
						}
					})
				}
				if e := db.Do(ctx, tenant, func(tx *store.Tx) error {
					if _, e := tx.Exec(ctx, "SET LOCAL ROLE finops_api"); e != nil {
						return e
					}
					d := model.Clone(result)
					d["id"] = model.ID()
					delete(d, "writer_role")
					delete(d, "created_at")
					_, e := tx.SourceReceiptCreate(ctx, d)
					return e
				}); e == nil {
					t.Fatal("API role published native hardware evidence")
				}
				var foreignCount int
				if e := ingester.Do(ctx, "unrelated-tenant", func(tx *store.Tx) error {
					return tx.QueryRow(ctx, "SELECT count(*) FROM source_receipts WHERE id=$1", result["id"]).Scan(&foreignCount)
				}); e != nil || foreignCount != 0 {
					t.Fatal("cross-tenant hardware evidence visible", e)
				}
			} else if e == nil {
				t.Fatal("failed/stale native evidence published")
			}
			if e = ingester.Do(ctx, tenant, func(tx *store.Tx) error {
				rows, e := tx.SourceReceiptList(ctx, HardwareKind, target.SourceID)
				want := 0
				if mode == "success" {
					want = 1
				}
				if e == nil && len(rows) != want {
					t.Fatalf("receipt count=%d want=%d", len(rows), want)
				}
				billing, e := tx.SourceReceiptList(ctx, "AWS_CUR2", target.SourceID)
				if len(billing) != 0 {
					t.Fatal("hardware became billing proof")
				}
				return e
			}); e != nil {
				t.Fatal(e)
			}
		})
	}
}

func TestHardwareS3ArchiveRequiresVersionedExactReadback(t *testing.T) {
	for _, mode := range []string{"success", "unversioned", "wrong-version", "altered-bytes"} {
		t.Run(mode, func(t *testing.T) {
			raw := []byte("offline native hardware response bytes")
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") || !strings.HasPrefix(r.URL.Path, "/raw/tenant/tenant/hardware/resource/") {
					t.Error("archive signature/scope missing")
				}
				if r.Method == "PUT" {
					body, _ := io.ReadAll(r.Body)
					if !bytes.Equal(body, raw) {
						t.Error("raw bytes changed")
					}
					if mode != "unversioned" {
						w.Header().Set("X-Amz-Version-Id", "v1")
					}
					w.WriteHeader(200)
					return
				}
				if r.Method != "GET" || r.URL.Query().Get("versionId") != "v1" {
					t.Error("archive readback version not pinned")
				}
				version := "v1"
				if mode == "wrong-version" {
					version = "v2"
				}
				w.Header().Set("X-Amz-Version-Id", version)
				if mode == "altered-bytes" {
					_, _ = w.Write([]byte("different"))
				} else {
					_, _ = w.Write(raw)
				}
			}))
			defer server.Close()
			client := s3.NewFromConfig(aws.Config{Region: "eu-west-1", Credentials: credentials.NewStaticCredentialsProvider("offline-fixture", "offline-fixture", ""), HTTPClient: server.Client()}, func(o *s3.Options) { o.BaseEndpoint = aws.String(server.URL); o.UsePathStyle = true })
			archive := HardwareS3Archive{client, "raw"}
			ref, e := archive.Archive(context.Background(), "tenant", "resource", raw)
			if mode == "success" {
				if e != nil || calls != 2 || model.String(ref, "body_sha256") != BytesHash(raw) {
					t.Fatal("exact archive failed", e)
				}
			} else if e == nil {
				t.Fatal("unversioned or altered raw evidence accepted")
			}
		})
	}
}
