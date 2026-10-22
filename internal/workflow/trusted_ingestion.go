package workflow

import (
	"context"
	"os"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/service"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
)

func trustedSourceTick(ctx context.Context, a *Activities, tenant string) error {
	// An empty registry is normal for read-only discovery. Binding configuration
	// is held exclusively by this ingestion process; the API receives no keys.
	var registered []model.Document
	if e := a.Store.Do(ctx, tenant, func(t *store.Tx) error { var e error; registered, e = t.SourceList(ctx); return e }); e != nil {
		return e
	}
	if len(registered) == 0 {
		return commitmentEvidenceTick(ctx, a, tenant)
	}
	factory, e := source.AWSFactory(os.Getenv("AWS_SOURCE_READ_BINDINGS_JSON"))
	if e != nil {
		return e
	}
	producer := &service.API{Config: a.Config, Client: a.HTTP}
	pipeline := source.Pipeline{Store: a.Store, ProviderFactory: factory, Normalize: func(ctx context.Context, raw model.Document) (model.Document, error) {
		return producer.NormalizeTrustedSource(ctx, raw)
	}, Persist: service.PersistEvidence, ArchiveObject: service.ArchiveSourceObject}
	if err := pipeline.Tick(ctx, tenant); err != nil {
		return err
	}
	return commitmentEvidenceTick(ctx, a, tenant)
}
