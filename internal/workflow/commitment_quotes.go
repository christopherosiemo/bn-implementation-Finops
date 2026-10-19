package workflow

import (
	"context"
	"errors"
	"os"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/native"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
)

// The optional target set is private ingester configuration. It is empty by
// default; neither the analyst process nor a public registration carries AWS
// credentials, offer selectors, existing-plan IDs or new API permissions.
func commitmentQuoteTick(ctx context.Context, a *Activities, tenant string) error {
	encoded := os.Getenv("AWS_SAVINGS_PLAN_QUOTE_TARGETS_JSON")
	if encoded == "" {
		return nil
	}
	targets, err := source.SavingsPlanQuoteTargets(encoded)
	if err != nil {
		return err
	}
	if a.Config.Fixture {
		return errors.New("SAVINGS_PLAN_QUOTES_NATIVE_MODE_REQUIRED")
	}
	selected := []source.SavingsPlanQuoteTarget{}
	for _, target := range targets {
		if target.TenantID == tenant {
			selected = append(selected, target)
		}
	}
	if len(selected) == 0 {
		return nil
	}
	factory, err := source.AWSFactory(os.Getenv("AWS_SOURCE_READ_BINDINGS_JSON"))
	if err != nil {
		return err
	}
	storage, err := native.StorageFromEnvironment(ctx, false)
	if err != nil {
		return err
	}
	archive := &source.SavingsPlanQuoteArchive{Client: storage.S3, Bucket: storage.Bucket}
	pipeline := source.SavingsPlanQuotePipeline{Store: a.Store, ReaderFactory: factory, Archive: archive.Archive}
	for _, target := range selected {
		if _, err = pipeline.CaptureIfDue(ctx, target); err != nil {
			return err
		}
	}
	return nil
}
