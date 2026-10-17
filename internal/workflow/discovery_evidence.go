package workflow

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
	"time"
)

// Inventory and operational telemetry use the ingestion identity only. Missing
// CloudWatch series stay missing and never imply an idle or healthy workload.
func discoverOperationalEvidence(ctx context.Context, a *Activities, t *store.Tx, aws *provider.AWS, instances []model.Document, region, account string) ([]model.Document, error) {
	volumes, e := aws.Volumes(ctx, region, account)
	if e != nil {
		return nil, e
	}
	for _, instance := range instances {
		instance["memory_data_missing"] = true
		native := model.String(instance, "provider_resource_id")
		source := "cloudwatch/" + account + "/" + region + "/" + native
		version := time.Now().UTC().Truncate(time.Hour).Format("20060102T15")
		hash := sha256.Sum256([]byte(source + "/" + version))
		jobID := "metrics-" + hex.EncodeToString(hash[:])
		if _, e = t.Get(ctx, "ingestion_jobs", jobID); e == nil {
			continue
		} else if e != pgx.ErrNoRows {
			return nil, e
		}
		samples, e := aws.Metrics(ctx, region, native)
		if e != nil {
			return nil, e
		}
		raw := model.Document{"provider": "AWS", "account_id": account, "region": region, "resource_id": native, "source_id": source, "source_version": version, "records": samples, "memory_data_missing": true}
		_, e = t.Create(ctx, "ingestion_jobs", model.Document{"id": jobID, "source_id": source, "source_version": version, "resource_id": native, "status": "PENDING", "raw": raw, "canonical": model.Document{"metric_facts": samples}})
		if e != nil {
			return nil, e
		}
	}
	return append(instances, volumes...), nil
}
