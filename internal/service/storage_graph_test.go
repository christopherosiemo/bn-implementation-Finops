package service

import (
	"context"
	"errors"
	"fmt"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/configuration"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/dependency"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/evidence"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"strings"
	"testing"
	"time"
)

func TestStorageIssuedAuthorityRetainsOriginalTypedBindingHash(t *testing.T) {
	r := model.Document{"id": "storage-resource", "version": 1, "resource_type": "EBS_VOLUME", "provider": "AWS", "provider_resource_id": "vol-0eb50000000000001", "account_id": "111122223333", "region": "eu-west-1", "workload_id": "storage-workload", "storage_configuration": model.Document{"size_gib": 1000, "volume_type": "gp2"}}
	b, e := configuration.NewBinding("tenant", r)
	if e != nil {
		t.Fatal(e)
	}
	d := configuration.Declaration{SchemaVersion: "1", Authority: "TERRAFORM", Repository: configuration.Repository{URL: "https://github.com/example/storage.git", Ref: "main", Directory: "storage"}, Pipeline: configuration.Pipeline{System: "GITHUB_ACTIONS", Identity: configuration.PipelineIdentity{Issuer: "https://token.actions.githubusercontent.com", Audience: configuration.ObserverAudience, Subject: "repo:example/storage:ref:refs/heads/main", PipelineID: ".github/workflows/deploy.yml"}}, Terraform: configuration.Terraform{Workspace: "storage", StateLineage: "00000000-0000-4000-8000-000000000001", Addresses: []string{"module.disk.aws_ebs_volume.data[0]"}}}
	issued := configuration.DeclarationDocument(d)
	issued["id"], issued["version"], issued["binding"] = "authority", 1, b
	issued["status"], issued["reason_codes"], issued["execution_authorized"] = "DECLARED_NOT_ATTESTED", configuration.Reasons(b), false
	issued["observed_commit"], issued["observed_state_serial"], issued["declared_by"] = nil, nil, "operator"
	hash := evidence.Hash(issued)
	loaded := storageObject(issued)
	loaded["tenant_id"], loaded["writer_role"], loaded["created_at"], loaded["hash"] = "tenant", "finops_api", "2026-10-20T00:00:00Z", hash
	loaded["_resource_snapshot"], loaded["_column_content_hash"] = storageObject(r), hash
	if !storageBoundAuthority(loaded, r, "tenant") {
		t.Fatal("authentic issued declaration rejected after JSONB-shaped roundtrip")
	}
	for _, mutate := range []func(model.Document){func(a model.Document) { a["_column_content_hash"] = "altered" }, func(a model.Document) {
		b := storageObject(a["binding"])
		b["account_id"] = "999988887777"
		a["binding"] = b
	}, func(a model.Document) {
		tf := storageObject(a["terraform"])
		tf["addresses"] = []string{"aws_instance.wrong"}
		a["terraform"] = tf
	}} {
		bad := storageObject(loaded)
		mutate(bad)
		if storageBoundAuthority(bad, r, "tenant") {
			t.Fatal("altered declaration accepted")
		}
	}
}

// Restricted-role/SQL fixture only. Native shapes and immutable object pointers
// are explicit component doubles; this test makes no live-native or STOP claim.
func TestStorageStopGraphRestrictedReadersAndTenantProof(t *testing.T) {
	f := newMutationReplayFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	proof, resource := storageStopProofFixture(time.Now().UTC())
	var volume model.Document
	if err := f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		if _, e := tx.Create(ctx, "workloads", model.Document{"id": "storage-stop-workload", "owner": "storage-owner", "owner_subject": "storage-subject", "environment": "NON_PRODUCTION"}); e != nil {
			return e
		}
		instance, e := tx.Create(ctx, "resources", model.Document{"id": "storage-stop-instance", "provider": "AWS", "provider_resource_id": "i-0eb50000000000001", "account_id": resource["account_id"], "region": resource["region"], "resource_type": "EC2", "workload_id": "storage-stop-workload", "environment": "NON_PRODUCTION"})
		if e != nil {
			return e
		}
		resource["id"], resource["workload_id"], resource["environment"] = "storage-stop-volume", "storage-stop-workload", "NON_PRODUCTION"
		resource["provider_relationships"] = []model.Document{{"type": "ATTACHED_TO", "target_resource_id": instance["id"], "target_provider_resource_id": instance["provider_resource_id"], "basis": "NATIVE_EBS_POINT_RELATIONSHIP"}}
		volume, e = tx.Create(ctx, "resources", resource)
		return e
	}); err != nil {
		t.Fatal(err)
	}
	proof["resource_id"], proof["config_hash"] = volume["id"], StorageConfigurationHash(volume)
	proof["id"] = model.ID()
	proof["observed_at"] = time.Now().UTC().Format(time.RFC3339Nano)
	for key := range proof {
		if strings.HasPrefix(key, "_row_") {
			delete(proof, key)
		}
	}
	if err := f.roles["ingester"].Do(ctx, f.tenant, func(tx *store.Tx) error { _, e := tx.StorageEvidenceAppend(ctx, proof); return e }); err != nil {
		t.Fatal(err)
	}
	var expected string
	for _, role := range []string{"api", "worker", "signer", "executor"} {
		t.Run(role, func(t *testing.T) {
			if err := f.roles[role].Do(ctx, f.tenant, func(tx *store.Tx) error {
				graph, e := dependencyGraph(ctx, tx)
				if e != nil {
					return e
				}
				nodes, edges := storageRows(graph["nodes"]), storageRows(graph["edges"])
				if reasons := dependency.AssessEC2Stop(nodes, edges, "storage-stop-instance"); len(reasons) != 0 {
					return fmt.Errorf("restricted graph failed: %v", reasons)
				}
				h := model.String(graph, "inventory_hash")
				if expected == "" {
					expected = h
				} else if h != expected {
					return errors.New("role changed server-selected physical context")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if err := f.roles[role].Do(ctx, f.tenant+"-foreign", func(tx *store.Tx) error {
				_, e := storageGraphPhysicalProof(ctx, tx, volume)
				if !errors.Is(e, pgx.ErrNoRows) {
					return fmt.Errorf("foreign native proof not isolated: %v", e)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			err := f.roles[role].Do(ctx, f.tenant, func(tx *store.Tx) error {
				attempt := storageObject(proof)
				attempt["id"] = model.ID()
				_, e := tx.StorageEvidenceAppend(ctx, attempt)
				if e == nil {
					return errors.New("read-only role inserted native proof")
				}
				return e
			})
			var pg *pgconn.PgError
			if !errors.As(err, &pg) || pg.Code != "42501" {
				t.Fatal("native proof write not permission denied", err)
			}
		})
	}
}

func storageStopProofFixture(now time.Time) (model.Document, model.Document) {
	r := model.Document{"id": "volume", "tenant_id": "tenant", "provider": "AWS", "account_id": "111122223333", "region": "eu-west-1", "resource_type": "EBS_VOLUME", "provider_resource_id": "vol-0eb50000000000001", "workload_id": "dev", "storage_configuration": model.Document{"volume_id": "vol-0eb50000000000001", "provider_resource_id": "vol-0eb50000000000001", "account_id": "111122223333", "region": "eu-west-1", "state": "in-use", "multi_attach_enabled": false, "operator": model.Document{"managed": false}, "attachments": []model.Document{{"volume_id": "vol-0eb50000000000001", "instance_id": "i-0eb50000000000001", "state": "attached", "device": "/dev/sdf"}}}}
	h := StorageConfigurationHash(r)
	body := strings.Repeat("a", 64)
	p := model.Document{"schema_version": "1", "resource_id": r["id"], "account_id": r["account_id"], "region": r["region"], "config_hash": h, "content_hash": body, "archive": model.Document{"bucket": "private-fixture", "key": "tenant/immutable/canonical", "version_id": "v1", "body_sha256": body}, "observed_at": now.Add(-time.Minute).Format(time.RFC3339Nano), "_row_writer_role": "finops_ingester", "_row_id": "issued-proof", "_row_config_hash": h, "_row_content_hash": body, "_row_created_at": now.Add(-30 * time.Second).Format(time.RFC3339Nano)}
	return p, r
}

func TestStorageStopContextRequiresCurrentNativeIssuerAndBinding(t *testing.T) {
	now := time.Now().UTC()
	proof, r := storageStopProofFixture(now)
	before := evidence.Hash(proof)
	context := storageGraphStopContext(proof, r, "tenant", now)
	if context == nil || context["basis"] != "CURRENT_INGESTER_EBS_CONFIGURATION_V1" || evidence.Hash(proof) != before {
		t.Fatal("valid immutable native proof unavailable or mutated")
	}
	for _, name := range []string{"stale", "future", "wrong-role", "foreign-tenant", "wrong-resource", "wrong-account", "wrong-region", "wrong-config", "wrong-content", "mutable-archive", "native-account"} {
		t.Run(name, func(t *testing.T) {
			p, resource := storageStopProofFixture(now)
			tenant := "tenant"
			switch name {
			case "stale":
				p["observed_at"] = now.Add(-10*time.Minute - time.Nanosecond).Format(time.RFC3339Nano)
			case "future":
				p["observed_at"] = now.Add(time.Second).Format(time.RFC3339Nano)
			case "wrong-role":
				p["_row_writer_role"] = "finops_api"
			case "foreign-tenant":
				tenant = "foreign"
			case "wrong-resource":
				p["resource_id"] = "other"
			case "wrong-account":
				p["account_id"] = "999988887777"
			case "wrong-region":
				p["region"] = "us-east-1"
			case "wrong-config":
				p["_row_config_hash"] = strings.Repeat("f", 64)
			case "wrong-content":
				p["_row_content_hash"] = strings.Repeat("f", 64)
			case "mutable-archive":
				a := storageObject(p["archive"])
				a["version_id"] = "null"
				p["archive"] = a
			case "native-account":
				n := storageObject(resource["storage_configuration"])
				n["account_id"] = "999988887777"
				resource["storage_configuration"] = n
			}
			if storageGraphStopContext(p, resource, tenant, now) != nil {
				t.Fatal("stale/foreign/mismatched native proof commissioned STOP context")
			}
		})
	}
	// A newly read immutable object with identical physical configuration renews
	// only freshness. It cannot change the reviewed dependency semantics.
	renewed := storageObject(proof)
	renewed["_row_id"] = "new-issued-proof"
	renewed["_row_created_at"] = now.Format(time.RFC3339Nano)
	renewed["observed_at"] = now.Add(-time.Second).Format(time.RFC3339Nano)
	if evidence.Hash(storageGraphStopContext(renewed, r, "tenant", now)) != evidence.Hash(context) {
		t.Fatal("acquisition-only renewal rewrote physical graph facts")
	}
}
