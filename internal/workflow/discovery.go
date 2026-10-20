package workflow

import (
	"context"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/service"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
)

func discoverTenant(ctx context.Context, a *Activities, t *store.Tx) error {
	if a.Config.Fixture {
		return nil
	}
	if e := service.ValidateAWSTenant(t.Tenant); e != nil {
		return nil
	}
	accounts, e := t.List(ctx, "cloud_accounts")
	if e != nil {
		return e
	}
	for _, account := range accounts {
		last, _ := time.Parse(time.RFC3339Nano, model.String(account, "last_discovered_at"))
		if !last.IsZero() && time.Since(last) < 10*time.Minute {
			continue
		}
		id := model.String(account, "account_id")
		if !strings.Contains(a.Config.AWSReadRole, ":"+id+":") {
			account["status"], account["error"] = "DEGRADED", "configured read role account mismatch"
		} else {
			aws, e := provider.NewAWS(ctx, model.String(account, "region"), a.Config.AWSReadRole, a.Config.AWSExternalID)
			if e != nil {
				return e
			}
			rows, e := aws.Inventory(ctx, model.String(account, "region"), id)
			// Optional database reads have their own rollback boundary; EC2 inventory
			// and the ordinary schedule path retain their existing contracts.
			if _, databaseError := t.Exec(ctx, "SAVEPOINT rds_optional_discovery"); databaseError != nil {
				return databaseError
			}
			databaseError := discoverRDSAccount(ctx, a, t, aws, account)
			if databaseError != nil {
				if _, rollbackError := t.Exec(ctx, "ROLLBACK TO SAVEPOINT rds_optional_discovery"); rollbackError != nil {
					return rollbackError
				}
			}
			if _, releaseError := t.Exec(ctx, "RELEASE SAVEPOINT rds_optional_discovery"); releaseError != nil {
				return releaseError
			}
			if databaseError != nil {
				if qualityError := databaseQuality(ctx, t, "quality-rds-"+id+"-"+model.String(account, "region"), "DEGRADED", "NATIVE_RDS_OPTIONAL_COLLECTION_UNAVAILABLE"); qualityError != nil {
					return qualityError
				}
			}
			if e != nil {
				account["status"], account["error"] = "DEGRADED", e.Error()
			} else {
				rows, e = discoverOperationalEvidence(ctx, a, t, aws, rows, model.String(account, "region"), id)
				if e != nil {
					return e
				}
				for _, d := range rows {
					d["cloud_account_id"] = account["id"]
					var existingID string
					e := t.QueryRow(ctx, "SELECT id FROM entities WHERE tenant_id=$1 AND kind='resources' AND document->>'provider'='AWS' AND document->>'account_id'=$2 AND document->>'region'=$3 AND document->>'provider_resource_id'=$4", t.Tenant, id, account["region"], d["provider_resource_id"]).Scan(&existingID)
					if e == nil {
						old, e := t.Get(ctx, "resources", existingID)
						if e != nil {
							return e
						}
						for _, key := range []string{"workload_id", "configuration_authority", "runtime_stop_start_delegated", "stable_network", "commitment_known", "uncovered_on_demand", "observation_days", "currency", "hourly_effective_cost", "monthly_effective_cost", "billing_source_version", "unknown_drift", "blocking_dependencies"} {
							if v, ok := old[key]; ok {
								d[key] = v
							}
						}
						if _, e = t.Update(ctx, "resources", existingID, model.Number(old, "version"), d); e != nil {
							return e
						}
					} else if e == pgx.ErrNoRows {
						if _, e = t.Create(ctx, "resources", d); e != nil {
							return e
						}
					} else {
						return e
					}
				}
				account["status"], account["discovered_resources"], account["error"] = "CONNECTED", len(rows), ""
			}
			// EBS follows the EC2 upserts so exact native attachment endpoints
			// already exist. Its optional read/archive boundary cannot discard
			// those rows or the independent RDS discovery above.
			if _, storageError := t.Exec(ctx, "SAVEPOINT ebs_optional_discovery"); storageError != nil {
				return storageError
			}
			storageError := discoverBlockStorageAccount(ctx, a, t, aws, account)
			if storageError != nil {
				if _, rollbackError := t.Exec(ctx, "ROLLBACK TO SAVEPOINT ebs_optional_discovery"); rollbackError != nil {
					return rollbackError
				}
			}
			if _, releaseError := t.Exec(ctx, "RELEASE SAVEPOINT ebs_optional_discovery"); releaseError != nil {
				return releaseError
			}
			if storageError != nil {
				if qualityError := blockStorageQuality(ctx, t, "quality-ebs-"+id+"-"+model.String(account, "region"), "DEGRADED", "EBS_SCOPE_OPTIONAL_COLLECTION_UNAVAILABLE"); qualityError != nil {
					return qualityError
				}
			}
		}
		account["last_discovered_at"] = model.Now()
		if _, e = t.Update(ctx, "cloud_accounts", model.String(account, "id"), model.Number(account, "version"), account); e != nil {
			return e
		}
		if e = t.Audit(ctx, "connector-worker", "cloud_account.discovered", model.String(account, "id"), model.Document{"status": account["status"], "resource_count": account["discovered_resources"]}); e != nil {
			return e
		}
	}
	return nil
}
