package workflow

import (
	"context"
	"errors"
	"os"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/commitmentarchive"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/native"
)

// Opt-in read-only historical ingestion. Empty configuration has no storage,
// credentials, SQL or AWS side effects. Authoritative registration and original
// object metadata are resolved by the ingester, never an analyst or console.
func commitmentArchiveTick(ctx context.Context, a *Activities, tenant string) error {
	targets, err := commitmentarchive.Targets(os.Getenv("AWS_OWNERSHIP_ARCHIVE_TARGETS_JSON"))
	if err != nil {
		return err
	}
	selected := []commitmentarchive.Target{}
	for _, target := range targets {
		if target.TenantID == tenant {
			selected = append(selected, target)
		}
	}
	if len(selected) == 0 {
		return nil
	}
	if a.Config.Fixture {
		return errors.New("OWNERSHIP_ARCHIVE_NATIVE_MODE_REQUIRED")
	}
	storage, err := native.StorageFromEnvironment(ctx, false)
	if err != nil {
		return err
	}
	pipeline := commitmentarchive.Pipeline{Store: a.Store, Bindings: os.Getenv("AWS_SOURCE_READ_BINDINGS_JSON"), Storage: &commitmentarchive.ImmutableArchive{Client: storage.S3, Bucket: storage.Bucket}}
	for _, target := range selected {
		if _, err = pipeline.Capture(ctx, target); err != nil {
			return err
		}
	}
	return nil
}
