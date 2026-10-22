package workflow

import (
	"context"
	"errors"
	"os"
	"sort"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/native"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
)

func commitmentControllerTick(ctx context.Context, a *Activities, tenant string) error {
	bindings, err := source.ControllerDiscoveryBindings(os.Getenv("AWS_CONTROLLER_DISCOVERY_BINDINGS_JSON"))
	if err != nil {
		return err
	}
	ids := []string{}
	for id, target := range bindings {
		if target.Binding.TenantID == tenant {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	if len(ids) == 0 {
		return nil
	}
	if a.Config.Fixture {
		return errors.New("CONTROLLER_DISCOVERY_NATIVE_MODE_REQUIRED")
	}
	factory, err := source.ControllerDiscoveryAWSFactory(os.Getenv("AWS_SOURCE_READ_BINDINGS_JSON"))
	if err != nil {
		return err
	}
	storage, err := native.StorageFromEnvironment(ctx, false)
	if err != nil {
		return err
	}
	archive := &source.FleetS3Archive{Client: storage.S3, Bucket: storage.Bucket}
	pipeline := source.ControllerDiscoveryPipeline{Store: a.Store, Bindings: bindings, ReaderFactory: factory, Archive: archive.Archive}
	for _, id := range ids {
		if _, err = pipeline.CaptureIfDue(ctx, tenant, id); err != nil {
			return err
		}
	}
	return nil
}

func commitmentEvidenceTick(ctx context.Context, a *Activities, tenant string) error {
	if err := commitmentArchiveTick(ctx, a, tenant); err != nil {
		return err
	}
	if err := commitmentControllerTick(ctx, a, tenant); err != nil {
		return err
	}
	// Offer observation comes last so an initial historical import cannot turn
	// the local five-minute quote-read policy into a fictitious provider expiry.
	return commitmentQuoteTick(ctx, a, tenant)
}
