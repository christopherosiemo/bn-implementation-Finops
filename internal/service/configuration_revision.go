package service

import (
	"context"
	"os"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/configuration"
)

// resolveConfigurationRevision is a metadata-only, read-only authority check.
// Registry entries and roots are private process configuration; public
// repository declarations are matched exactly before any Git read happens.
func (a *API) resolveConfigurationRevision(ctx context.Context, tenant, authority, repositoryURL, ref, directory string) (string, error) {
	if a.ConfigurationRevision != nil {
		return a.ConfigurationRevision(ctx, tenant, authority, repositoryURL, ref, directory)
	}
	bindings, err := configuration.ParseRevisionBindings(os.Getenv("CONFIGURATION_REVISION_BINDINGS_JSON"))
	if err != nil {
		return "", configuration.ErrRevisionUnavailable
	}
	resolver := configuration.LocalRevisionResolver{Bindings: bindings}
	return resolver.Resolve(ctx, tenant, authority, configuration.Repository{URL: repositoryURL, Ref: ref, Directory: directory})
}
