package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/configuration"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// These tests create marked child databases and independently authenticated
// restricted logins using the existing isolated Fleet-history harness. Empty,
// genuinely sealed scopes are deliberately NOT native ownership/coverage proof.
func newFleetConfigurationTest(t *testing.T) *fleetHistoryDBTest {
	t.Helper()
	f := newFleetHistoryDBTest(t)
	dir := t.TempDir()
	raw, err := os.ReadFile(filepath.Join("..", "..", "migrations", "027_fleet_configuration.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "027_fleet_configuration.sql"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err = f.admin.Migrate(f.ctx, dir); err != nil {
		t.Fatal(err)
	}
	f.register()
	return f
}

func fleetConfigurationFixture(t *testing.T, ref string) configuration.FleetDeclaration {
	t.Helper()
	raw := fmt.Sprintf(`{"schema_version":"1","authority":"TERRAFORM","repository":{"url":"https://git.example.test/owner/fleet.git","ref":%q,"directory":"infra/fleet"},"pipeline":{"system":"GITHUB_ACTIONS","identity":{"issuer":"https://token.actions.githubusercontent.com","audience":"finops-deployment-observer","subject":"repo:owner/fleet:environment:sandbox","pipeline_id":"reviewed-fleet-pipeline"}},"terraform":{"workspace":"sandbox","state_lineage":"12345678-1234-1234-1234-123456789abc","asg_address":"module.fleet.aws_autoscaling_group.old","launch_template_address":"module.fleet.aws_launch_template.old","traffic":{"listener_rule_address":"module.fleet.aws_lb_listener_rule.app","target_group_addresses":["module.fleet.aws_lb_target_group.old","module.fleet.aws_lb_target_group.candidate"]}}}`, ref)
	d, err := configuration.DecodeFleetDeclaration([]byte(raw))
	if err != nil {
		t.Fatal("independent declaration fixture invalid", err)
	}
	return d
}

func fleetConfigurationCreate(t *testing.T, f *fleetHistoryDBTest) (model.Document, model.Document) {
	t.Helper()
	var declaration, scope model.Document
	f.must("finops_api", func(tx *Tx) error {
		var err error
		declaration, err = tx.FleetConfigurationAppend(f.ctx, f.registration.ID, 0, "platform-operator", fleetConfigurationFixture(t, "refs/heads/finops"))
		if err != nil {
			return err
		}
		scope, err = tx.FleetHistoryScopeCapture(f.ctx, f.registration.ID, f.definition.ID)
		return err
	})
	return declaration, scope
}

func TestFleetConfigurationRestrictedRolesCASAndScopedHistory(t *testing.T) {
	f := newFleetConfigurationTest(t)
	metadata := fleetConfigurationFixture(t, "refs/heads/finops")
	var first, second model.Document
	f.must("finops_api", func(tx *Tx) error {
		var err error
		first, err = tx.FleetConfigurationAppend(f.ctx, f.registration.ID, 0, "platform-operator", metadata)
		return err
	})
	if model.String(first, "status") != "DECLARED_NOT_ATTESTED" || model.Number(first, "version") != 1 || model.String(first, "asg_arn") != f.registration.ASGARN || model.String(first, "registration_id") != f.registration.ID || model.String(first, "fleet_id") != f.registration.FleetID || model.Bool(first, "execution_authorized") || first["estimated_saving"] != nil || first["verified_saving"] != nil {
		t.Fatal("declaration acquired observed authority or lost registered group binding")
	}
	binding := fleetHistoryDocument(first["binding"])
	if _, exists := binding["resource_id"]; exists || model.String(binding, "workload_id") != f.registration.Binding.WorkloadID {
		t.Fatal("group declaration invented a representative instance resource")
	}
	for _, role := range []string{"finops_ingester", "finops_activity", "finops_worker", "finops_signer", "finops_executor"} {
		f.denied(role, func(tx *Tx) error {
			_, err := tx.FleetConfigurationAppend(f.ctx, f.registration.ID, 1, "forbidden", metadata)
			return err
		})
	}
	f.must("finops_ingester", func(tx *Tx) error { _, err := tx.FleetConfigurationGet(f.ctx, model.String(first, "id")); return err })
	for _, role := range []string{"finops_activity", "finops_worker", "finops_signer", "finops_executor"} {
		f.denied(role, func(tx *Tx) error { _, err := tx.FleetConfigurationGet(f.ctx, model.String(first, "id")); return err })
	}
	if err := f.run("finops_api", func(tx *Tx) error {
		_, err := tx.FleetConfigurationAppend(f.ctx, f.registration.ID, 0, "operator", metadata)
		return err
	}); !errors.Is(err, ErrConflict) {
		t.Fatal("stale declaration CAS was not rejected", err)
	}
	metadata.Repository.Ref = "refs/heads/reviewed-update"
	f.must("finops_api", func(tx *Tx) error {
		var err error
		second, err = tx.FleetConfigurationAppend(f.ctx, f.registration.ID, 1, "platform-operator", metadata)
		if err != nil {
			return err
		}
		old, err := tx.FleetConfigurationGet(f.ctx, model.String(first, "id"))
		if err != nil || fleetHistoryHash(old) != fleetHistoryHash(first) {
			return errors.New("new declaration rewrote immutable prior revision")
		}
		latest, err := tx.FleetConfigurationLatest(f.ctx, f.registration.ID)
		if err != nil || model.String(latest, "id") != model.String(second, "id") || model.Number(second, "version") != 2 || model.String(second, "hash") == model.String(first, "hash") {
			return errors.New("declaration head/version/hash did not advance")
		}
		page, err := tx.FleetConfigurationPage(f.ctx, f.registration.ID, "", 1)
		if err != nil || len(page) != 1 || model.String(page[0], "id") != model.String(second, "id") {
			return errors.New("newest declaration page incorrect")
		}
		page, err = tx.FleetConfigurationPage(f.ctx, f.registration.ID, model.String(second, "id"), 1)
		if err != nil || len(page) != 1 || model.String(page[0], "id") != model.String(first, "id") {
			return errors.New("declaration cursor dropped or repeated a revision")
		}
		page, err = tx.FleetConfigurationPage(f.ctx, "different-registration", model.String(second, "id"), 1)
		if err != nil || len(page) != 0 {
			return errors.New("declaration cursor escaped registered group")
		}
		return nil
	})
	for _, limit := range []int{0, 102} {
		if err := f.run("finops_api", func(tx *Tx) error {
			_, err := tx.FleetConfigurationPage(f.ctx, f.registration.ID, "", limit)
			return err
		}); err == nil {
			t.Fatal("unbounded declaration page accepted", limit)
		}
	}
	for _, table := range []string{"fleet_configuration_declarations", "fleet_configuration_proposals"} {
		for _, operation := range []string{"UPDATE " + table + " SET document=document", "DELETE FROM " + table} {
			f.denied("finops_api", func(tx *Tx) error { _, err := tx.Exec(f.ctx, operation+" WHERE tenant_id=$1", f.tenant); return err })
		}
	}
	if err := f.roles["finops_api"].Do(f.ctx, f.tenant+"-foreign", func(tx *Tx) error {
		if _, err := tx.FleetConfigurationGet(f.ctx, model.String(first, "id")); !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("foreign declaration read did not hide row: %v", err)
		}
		page, err := tx.FleetConfigurationPage(f.ctx, f.registration.ID, "", 100)
		if err != nil || len(page) != 0 {
			return errors.New("foreign declaration history leaked")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestFleetConfigurationProposalUsesSealedScopeWithoutPromotingMissingHistory(t *testing.T) {
	f := newFleetConfigurationTest(t)
	declaration, scope := fleetConfigurationCreate(t, f)
	var first, second model.Document
	f.must("finops_api", func(tx *Tx) error {
		var err error
		first, err = tx.FleetConfigurationProposalCreate(f.ctx, f.registration.ID, model.String(declaration, "id"), model.String(scope, "id"), 1, "platform-operator")
		return err
	})
	if model.String(first, "status") != "BLOCKED" || model.Bool(first, "execution_authorized") || first["estimated_saving"] != nil || first["verified_saving"] != nil || first["change_plan_id"] != nil || model.String(first, "scope_id") != model.String(scope, "id") || model.String(first, "scope_hash") != model.String(scope, "hash") || model.String(first, "scope_reference_root") != model.String(scope, "reference_root") || model.String(first, "declaration_hash") != model.String(declaration, "hash") {
		t.Fatal("proposal lost sealed selection or acquired money/action authority")
	}
	reasons := map[string]bool{}
	for _, reason := range model.Strings(first, "reason_codes") {
		reasons[reason] = true
	}
	for _, required := range []string{"GROUP_MEMBERSHIP_UNOBSERVED", "FLEET_OWNERSHIP_UNPROVEN", "FLEET_CAPACITY_UNPROVEN", "FLEET_ECONOMICS_UNPROVEN", "WORK_PRESERVATION_UNPROVEN", "PIPELINE_ATTESTATION_REQUIRED"} {
		if !reasons[required] {
			t.Fatal("empty scope was promoted or required blocker omitted", required)
		}
	}
	for _, role := range []string{"finops_ingester", "finops_activity", "finops_worker", "finops_signer", "finops_executor"} {
		f.denied(role, func(tx *Tx) error {
			_, err := tx.FleetConfigurationProposalCreate(f.ctx, f.registration.ID, model.String(declaration, "id"), model.String(scope, "id"), 1, "forbidden")
			return err
		})
	}
	f.must("finops_api", func(tx *Tx) error {
		var err error
		second, err = tx.FleetConfigurationProposalCreate(f.ctx, f.registration.ID, model.String(declaration, "id"), model.String(scope, "id"), 1, "second-operator")
		if err != nil {
			return err
		}
		page, err := tx.FleetConfigurationProposalPage(f.ctx, f.registration.ID, "", 1)
		if err != nil || len(page) != 1 || model.String(page[0], "id") != model.String(second, "id") {
			return errors.New("proposal head pagination incorrect")
		}
		page, err = tx.FleetConfigurationProposalPage(f.ctx, f.registration.ID, model.String(second, "id"), 1)
		if err != nil || len(page) != 1 || model.String(page[0], "id") != model.String(first, "id") {
			return errors.New("proposal pagination skipped or repeated immutable history")
		}
		return nil
	})
	if err := f.roles["finops_api"].Do(f.ctx, f.tenant+"-foreign", func(tx *Tx) error {
		_, err := tx.FleetConfigurationProposalGet(f.ctx, model.String(first, "id"))
		if !errors.Is(err, pgx.ErrNoRows) {
			return errors.New("foreign proposal was readable")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []struct {
		declaration, scope string
		version            int64
	}{{model.String(declaration, "id"), model.String(scope, "id"), 2}, {"unknown-declaration", model.String(scope, "id"), 1}, {model.String(declaration, "id"), "unknown-scope", 1}} {
		f.denied("finops_api", func(tx *Tx) error {
			_, err := tx.FleetConfigurationProposalCreate(f.ctx, f.registration.ID, bad.declaration, bad.scope, bad.version, "operator")
			return err
		})
	}
}

func TestFleetConfigurationNewProposalsRejectCurrentBindingChanges(t *testing.T) {
	f := newFleetConfigurationTest(t)
	for _, change := range []string{"source-revoked", "source-config", "registration-revision", "definition-revision", "activity-resource-moved"} {
		t.Run(change, func(t *testing.T) {
			parentTest := f.t
			f.t = t
			defer func() { f.t = parentTest }()
			// Reuse the isolated cluster/role harness with a fresh tenant. These
			// are ordinary authorized metadata changes, never trigger bypasses.
			f.tenant = "fleet-config-change-" + model.ID()
			f.register()
			declaration, scope := fleetConfigurationCreate(t, f)
			f.must("finops_api", func(tx *Tx) error {
				switch change {
				case "source-revoked", "source-config":
					source, err := tx.SourceGet(f.ctx, f.registration.SourceID)
					if err != nil {
						return err
					}
					if change == "source-revoked" {
						source["enabled"] = false
					} else {
						source["prefix"] = "different/"
					}
					_, err = tx.SourceUpdate(f.ctx, f.registration.SourceID, model.Number(source, "version"), source)
					return err
				case "registration-revision":
					next := f.registration
					next.Version++
					next.MaxGapSeconds++
					_, err := tx.FleetHistoryRegistrationAppend(f.ctx, 1, next)
					return err
				case "definition-revision":
					next := f.definition
					next.Version++
					next.BusinessOperation = "new-reviewed-operation"
					_, err := tx.FleetDemandDefinitionAppend(f.ctx, f.registration.ID, 1, next)
					return err
				case "activity-resource-moved":
					resource, err := tx.Get(f.ctx, "resources", f.activity.ResourceID)
					if err != nil {
						return err
					}
					resource["workload_id"] = "different-workload"
					_, err = tx.Update(f.ctx, "resources", f.activity.ResourceID, model.Number(resource, "version"), resource)
					return err
				}
				return errors.New("unknown binding change")
			})
			f.denied("finops_api", func(tx *Tx) error {
				_, err := tx.FleetConfigurationProposalCreate(f.ctx, f.registration.ID, model.String(declaration, "id"), model.String(scope, "id"), 1, "operator")
				return err
			})
			f.must("finops_api", func(tx *Tx) error {
				old, err := tx.FleetConfigurationGet(f.ctx, model.String(declaration, "id"))
				if err != nil || fleetHistoryHash(old) != fleetHistoryHash(declaration) {
					return errors.New("current binding change rewrote immutable declaration")
				}
				return nil
			})
		})
	}
}

func TestFleetConfigurationCurrentSourceStateIsResolvedWithoutRewritingScope(t *testing.T) {
	f := newFleetConfigurationTest(t)
	declaration, scope := fleetConfigurationCreate(t, f)
	// A benign source metadata revision keeps the configuration binding, but
	// the new proposal must report the actual current registration version.
	f.must("finops_api", func(tx *Tx) error {
		source, err := tx.SourceGet(f.ctx, f.registration.SourceID)
		if err != nil {
			return err
		}
		source["name"] = "reviewed metadata update"
		_, err = tx.SourceUpdate(f.ctx, f.registration.SourceID, 1, source)
		return err
	})
	var prior model.Document
	f.must("finops_api", func(tx *Tx) error {
		var err error
		prior, err = tx.FleetConfigurationProposalCreate(f.ctx, f.registration.ID, model.String(declaration, "id"), model.String(scope, "id"), 1, "operator")
		return err
	})
	checkAWS := func(d model.Document, expected string) {
		t.Helper()
		states, ok := d["source_states"].([]any)
		if !ok {
			t.Fatal("proposal omitted selected current source states")
		}
		seen := false
		for _, item := range states {
			state := fleetHistoryDocument(item)
			if model.String(state, "source_system") != "AWS_SOURCE_CONNECTION" {
				continue
			}
			seen = true
			if model.Number(state, "source_registration_version") != 2 || model.String(state, "status") != expected || model.String(state, "config_hash") != f.registration.SourceConfigHash {
				t.Fatal("proposal reused old source state or invented healthy coverage")
			}
		}
		if !seen {
			t.Fatal("proposal omitted required native source")
		}
	}
	checkAWS(prior, "ACTIVE")
	// A HEALTHY label from the wrong configuration cannot be borrowed. This
	// remains an honest blocked proposal, not rejection or missing-as-zero.
	f.must("finops_ingester", func(tx *Tx) error {
		return tx.SourceCheckpointSet(f.ctx, f.registration.SourceID, "status", model.Document{"status": "HEALTHY", "config_hash": strings.Repeat("f", 64), "last_sync_at": time.Now().UTC().Format(time.RFC3339Nano)})
	})
	f.must("finops_api", func(tx *Tx) error {
		current, err := tx.FleetConfigurationProposalCreate(f.ctx, f.registration.ID, model.String(declaration, "id"), model.String(scope, "id"), 1, "operator")
		if err != nil {
			return err
		}
		checkAWS(current, "DEGRADED")
		if !strings.Contains(strings.Join(model.Strings(current, "reason_codes"), ","), "FLEET_CONFIGURATION_SOURCE_NOT_HEALTHY") || model.String(current, "status") != "BLOCKED" || current["verified_saving"] != nil {
			return errors.New("unhealthy current source acquired authority")
		}
		old, err := tx.FleetConfigurationProposalGet(f.ctx, model.String(prior, "id"))
		if err != nil || fleetHistoryHash(old) != fleetHistoryHash(prior) {
			return errors.New("current source state rewrote old proposal")
		}
		frozen, err := tx.FleetHistoryScopeGet(f.ctx, model.String(scope, "id"))
		if err != nil || fleetHistoryHash(frozen) != fleetHistoryHash(scope) {
			return errors.New("current source state rewrote sealed scope")
		}
		return nil
	})
}

func TestFleetConfigurationPointCorrectionRequiresNewSealedScope(t *testing.T) {
	f := newFleetConfigurationTest(t)
	// These are explicit provider-shaped dependency fixtures. Their immutable
	// receipt timestamps are actual database wallclock. A point in a selected
	// historical window never claims continuous ASG ownership or backfills work.
	observed := time.Now().UTC().Truncate(24 * time.Hour).Add(-time.Hour)
	firstPoint := f.nativeObservation("config-original", observed, true)
	f.must("finops_ingester", func(tx *Tx) error {
		_, _, err := tx.FleetHistoryObservationAppend(f.ctx, firstPoint)
		return err
	})
	declaration, originalScope := fleetConfigurationCreate(t, f)
	if model.Number(originalScope, "selected_observation_count") != 1 {
		t.Fatal("scope did not freeze the actual selected point")
	}
	var originalProposal model.Document
	f.must("finops_api", func(tx *Tx) error {
		var err error
		originalProposal, err = tx.FleetConfigurationProposalCreate(f.ctx, f.registration.ID, model.String(declaration, "id"), model.String(originalScope, "id"), 1, "operator")
		return err
	})
	if model.String(originalProposal, "status") != "BLOCKED" || originalProposal["verified_saving"] != nil {
		t.Fatal("single point became continuous ownership or financial authority")
	}
	correction := f.nativeObservation("config-correction", observed, false)
	f.must("finops_ingester", func(tx *Tx) error {
		_, _, err := tx.FleetHistoryObservationAppend(f.ctx, correction)
		return err
	})
	err := f.run("finops_api", func(tx *Tx) error {
		_, err := tx.FleetConfigurationProposalCreate(f.ctx, f.registration.ID, model.String(declaration, "id"), model.String(originalScope, "id"), 1, "operator")
		return err
	})
	if !errors.Is(err, ErrFleetConfigurationBinding) {
		t.Fatal("new native correction did not invalidate old scope for new proposals", err)
	}
	f.must("finops_api", func(tx *Tx) error {
		old, err := tx.FleetConfigurationProposalGet(f.ctx, model.String(originalProposal, "id"))
		if err != nil || fleetHistoryHash(old) != fleetHistoryHash(originalProposal) {
			return errors.New("correction rewrote old immutable proposal")
		}
		scope, err := tx.FleetHistoryScopeCapture(f.ctx, f.registration.ID, f.definition.ID)
		if err != nil {
			return err
		}
		if model.String(scope, "hash") == model.String(originalScope, "hash") {
			return errors.New("new scope omitted actual correction")
		}
		proposal, err := tx.FleetConfigurationProposalCreate(f.ctx, f.registration.ID, model.String(declaration, "id"), model.String(scope, "id"), 1, "operator")
		if err != nil {
			return err
		}
		if model.String(proposal, "status") != "BLOCKED" || proposal["estimated_saving"] != nil || proposal["verified_saving"] != nil || model.Bool(proposal, "execution_authorized") {
			return errors.New("corrected point promoted authority")
		}
		return nil
	})
}

func TestFleetConfigurationConcurrentCASAndSourceSerialization(t *testing.T) {
	f := newFleetConfigurationTest(t)
	metadata := fleetConfigurationFixture(t, "refs/heads/finops")
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, actor := range []string{"operator-a", "operator-b"} {
		go func(actor string) {
			<-start
			results <- f.run("finops_api", func(tx *Tx) error {
				_, err := tx.FleetConfigurationAppend(f.ctx, f.registration.ID, 0, actor, metadata)
				return err
			})
		}(actor)
	}
	close(start)
	won, conflicted := 0, 0
	for i := 0; i < 2; i++ {
		err := <-results
		if err == nil {
			won++
		} else if errors.Is(err, ErrConflict) {
			conflicted++
		} else {
			t.Fatal("concurrent CAS returned unexpected error", err)
		}
	}
	if won != 1 || conflicted != 1 {
		t.Fatal("concurrent declaration revisions did not enforce one CAS winner", won, conflicted)
	}
	f.must("finops_api", func(tx *Tx) error {
		if _, err := tx.FleetConfigurationAppend(f.ctx, f.registration.ID, 1, "operator", metadata); err != nil {
			return err
		}
		other, err := f.admin.Pool.Acquire(f.ctx)
		if err != nil {
			return err
		}
		defer other.Release()
		var acquired bool
		if err = other.QueryRow(f.ctx, "SELECT pg_try_advisory_lock(hashtextextended($1,0))", f.tenant+":trusted-source:"+f.registration.SourceID).Scan(&acquired); err != nil {
			return err
		}
		if acquired {
			_, _ = other.Exec(f.ctx, "SELECT pg_advisory_unlock(hashtextextended($1,0))", f.tenant+":trusted-source:"+f.registration.SourceID)
			return errors.New("exclusive source synchronization escaped declaration transaction")
		}
		err = f.run("finops_api", func(revoke *Tx) error {
			if _, err := revoke.Exec(f.ctx, "SET LOCAL lock_timeout='200ms'"); err != nil {
				return err
			}
			source, err := revoke.SourceGet(f.ctx, f.registration.SourceID)
			if err != nil {
				return err
			}
			source["enabled"] = false
			_, err = revoke.SourceUpdate(f.ctx, f.registration.SourceID, model.Number(source, "version"), source)
			return err
		})
		var blocked *pgconn.PgError
		if !errors.As(err, &blocked) || blocked.Code != "55P03" {
			return fmt.Errorf("source revocation escaped declaration row guard: %v", err)
		}
		return nil
	})
}

func fleetConfigurationDirectInsert(ctx context.Context, tx *Tx, proposal bool, d model.Document, badHash bool) error {
	raw, h, err := fleetHistoryBytes(d)
	if err != nil {
		return err
	}
	if badHash {
		h = strings.Repeat("f", 64)
	}
	if proposal {
		_, err = tx.Exec(ctx, `INSERT INTO public.fleet_configuration_proposals(tenant_id,id,registration_id,registration_version,workload_id,declaration_id,scope_id,content_hash,document,raw_document) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, tx.Tenant, d["id"], d["registration_id"], d["registration_version"], fleetHistoryDocument(d["binding"])["workload_id"], d["declaration_id"], d["scope_id"], h, raw, raw)
	} else {
		_, err = tx.Exec(ctx, `INSERT INTO public.fleet_configuration_declarations(tenant_id,id,registration_id,registration_version,workload_id,version,content_hash,document,raw_document) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, tx.Tenant, d["id"], d["registration_id"], d["registration_version"], fleetHistoryDocument(d["binding"])["workload_id"], d["version"], h, raw, raw)
	}
	return err
}

func TestFleetConfigurationSQLCannotForgeAuthorityOrParentClosure(t *testing.T) {
	f := newFleetConfigurationTest(t)
	for _, proposal := range []bool{false, true} {
		t.Run(fmt.Sprint("proposal=", proposal), func(t *testing.T) {
			parentTest := f.t
			f.t = t
			defer func() { f.t = parentTest }()
			f.tenant = "fleet-config-sql-" + model.ID()
			f.register()
			declaration, scope := fleetConfigurationCreate(t, f)
			original := declaration
			if proposal {
				f.must("finops_api", func(tx *Tx) error {
					var err error
					original, err = tx.FleetConfigurationProposalCreate(f.ctx, f.registration.ID, model.String(declaration, "id"), model.String(scope, "id"), 1, "operator")
					return err
				})
			}
			payload := model.Clone(original)
			for _, key := range []string{"hash", "created_at", "writer_role"} {
				delete(payload, key)
			}
			payload["id"] = model.ID()
			if !proposal {
				payload["version"] = 2
			}
			// Positive direct-SQL control proves the following denials are not
			// merely caused by an unusable reconstructed envelope.
			f.must("finops_api", func(tx *Tx) error { return fleetConfigurationDirectInsert(f.ctx, tx, proposal, payload, false) })
			attacks := []string{"status", "execution", "money", "registration-hash", "representative-resource", "extra-proof", "payload-hash", "schema-version-type"}
			if !proposal {
				attacks = append(attacks, "metadata-schema-type", "null-pipeline-system", "null-target-groups", "invalid-address-prefix", "directory-traversal", "invalid-ref")
			} else {
				attacks = append(attacks, "scope-hash", "declaration-hash", "source-states", "missing-history-reason")
			}
			for _, attack := range attacks {
				d := model.Clone(payload)
				d["id"] = model.ID()
				if !proposal {
					d["version"] = 3
				}
				switch attack {
				case "status":
					d["status"] = "READY"
				case "execution":
					d["execution_authorized"] = true
				case "money":
					d["verified_saving"] = "100.00"
				case "registration-hash":
					d["registration_hash"] = strings.Repeat("a", 64)
				case "representative-resource":
					binding := fleetHistoryDocument(d["binding"])
					binding["resource_id"] = f.activity.ResourceID
					d["binding"] = binding
				case "extra-proof":
					d["signed_plan"] = model.Document{"approved": true}
				case "schema-version-type":
					d["schema_version"] = 1
				case "scope-hash":
					d["scope_hash"] = strings.Repeat("a", 64)
				case "declaration-hash":
					d["declaration_hash"] = strings.Repeat("a", 64)
				case "source-states":
					d["source_states"] = []any{}
				case "missing-history-reason":
					filtered := []string{}
					for _, reason := range model.Strings(d, "reason_codes") {
						if reason != "GROUP_MEMBERSHIP_UNOBSERVED" {
							filtered = append(filtered, reason)
						}
					}
					d["reason_codes"] = filtered
				case "metadata-schema-type":
					metadata := fleetHistoryDocument(d["metadata"])
					metadata["schema_version"] = 1
					d["metadata"] = metadata
				case "null-pipeline-system":
					metadata := fleetHistoryDocument(d["metadata"])
					pipeline := fleetHistoryDocument(metadata["pipeline"])
					pipeline["system"] = nil
					metadata["pipeline"] = pipeline
					d["metadata"] = metadata
				case "null-target-groups", "invalid-address-prefix":
					metadata := fleetHistoryDocument(d["metadata"])
					tf := fleetHistoryDocument(metadata["terraform"])
					if attack == "null-target-groups" {
						traffic := fleetHistoryDocument(tf["traffic"])
						traffic["target_group_addresses"] = []any{nil, nil}
						tf["traffic"] = traffic
					} else {
						tf["asg_address"] = "garbage.aws_autoscaling_group.old"
					}
					metadata["terraform"] = tf
					d["metadata"] = metadata
				case "directory-traversal", "invalid-ref":
					metadata := fleetHistoryDocument(d["metadata"])
					repository := fleetHistoryDocument(metadata["repository"])
					if attack == "directory-traversal" {
						repository["directory"] = "../fleet"
					} else {
						repository["ref"] = "refs/heads/../unsafe"
					}
					metadata["repository"] = repository
					d["metadata"] = metadata
				}
				err := f.run("finops_api", func(tx *Tx) error {
					return fleetConfigurationDirectInsert(f.ctx, tx, proposal, d, attack == "payload-hash")
				})
				if err == nil {
					t.Fatal("direct SQL forgery was accepted", attack)
				}
			}
		})
	}
}
