package workflow

import (
	"context"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/service"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
	"log/slog"
	"net/http"
	"time"
)

// RunIngester has no Temporal mutation queue, signing capability or customer
// execution role. It only discovers inventory and persists financial/audit facts.
func RunIngester(ctx context.Context, cfg service.Config, db *store.Store) error {
	a := &Activities{Store: db, Config: cfg, HTTP: &http.Client{Timeout: 35 * time.Second}}
	tick := time.NewTicker(3 * time.Second)
	defer tick.Stop()
	for {
		if e := ingestionTick(ctx, a); e != nil {
			slog.Error("ingestion tick failed", "error", e)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}

func ingestionTick(ctx context.Context, a *Activities) error {
	rows, e := a.Store.Pool.Query(ctx, "SELECT tenant_id FROM tenant_registry")
	if e != nil {
		return e
	}
	tenants := []string{}
	for rows.Next() {
		var tenant string
		if e = rows.Scan(&tenant); e != nil {
			rows.Close()
			return e
		}
		tenants = append(tenants, tenant)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	for _, tenant := range tenants {
		e = a.Store.Do(ctx, tenant, func(t *store.Tx) error {
			// Several replicas can route tenants, but only one persists a given tenant's
			// ingestion jobs at a time. This also prevents duplicate audit markers.
			if _, e := t.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", tenant+":ingestion"); e != nil {
				return e
			}
			if e := discoverTenant(ctx, a, t); e != nil {
				return e
			}
			return ingestTenant(ctx, a, t)
		})
		if e != nil {
			slog.Error("tenant ingestion failed", "tenant", tenant, "error", e)
		}
		if e == nil {
			e = trustedSourceTick(ctx, a, tenant)
			if e != nil {
				slog.Error("trusted source ingestion unavailable", "tenant", tenant)
			}
		}
		// S3 report ingestion is independently bounded and never holds the
		// ordinary EC2 discovery/ingestion transaction across object-scale reads.
		if objectError := objectStorageTick(ctx, a, tenant); objectError != nil && e == nil {
			e = objectError
		}
		// Network reads have their own short persistence transactions and bounded
		// source reads. An optional denial never suppresses EC2 or S3 ingestion.
		if networkError := networkTick(ctx, a, tenant); networkError != nil && e == nil {
			e = networkError
		}
		// Lambda metadata, metrics and commissioned reports use bounded native
		// reads outside the ordinary inventory transaction. A denied optional
		// source cannot discard existing inventory or restoration ownership.
		if lambdaError := lambdaTick(ctx, a, tenant); lambdaError != nil && e == nil {
			e = lambdaError
		}
		// Optional AWS GA service inventory has independent bounded reads and
		// short publication transactions; EC2 failures do not suppress it.
		if serviceError := awsServiceTick(ctx, a, tenant); serviceError != nil && e == nil {
			e = serviceError
		}
		status := "HEALTHY"
		if e != nil {
			status = "DEGRADED"
		}
		if err := a.Store.Do(ctx, tenant, func(tx *store.Tx) error { return recordIngestionQuality(ctx, tx, status) }); err != nil {
			slog.Error("ingestion quality update failed", "tenant", tenant, "error", err)
		}
	}
	return nil
}
func recordIngestionQuality(ctx context.Context, tx *store.Tx, status string) error {
	message := "Raw evidence, canonical facts and audit archive are synchronized."
	if status == "DEGRADED" {
		message = "Evidence ingestion is retrying; inspect the ingestion service before trusting source completeness."
	}
	if _, e := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", tx.Tenant+":integration-quality"); e != nil {
		return e
	}
	quality, e := tx.Get(ctx, "data_quality", "quality-ingestion")
	previous := ""
	if e == nil {
		previous = model.String(quality, "status")
		if previous == status {
			return nil
		}
		quality["status"], quality["message"] = status, message
		if _, e = tx.Update(ctx, "data_quality", "quality-ingestion", model.Number(quality, "version"), quality); e != nil {
			return e
		}
	} else if e == pgx.ErrNoRows {
		if _, e = tx.Create(ctx, "data_quality", mapDocument("quality-ingestion", status, message)); e != nil {
			return e
		}
	} else {
		return e
	}
	event := "integration.failed"
	if status == "HEALTHY" {
		if previous == "" {
			return nil
		}
		event = "integration.recovered"
	}
	payload := model.Document{"integration": "evidence_ingestion", "status": status, "message": message, "observed_at": model.Now()}
	if e = tx.Audit(ctx, "ingestion-worker", event, "quality-ingestion", payload); e != nil {
		return e
	}
	return tx.Event(ctx, event, payload)
}

func mapDocument(id, status, message string) model.Document {
	return model.Document{"id": id, "name": "Immutable evidence ingestion", "status": status, "message": message}
}
