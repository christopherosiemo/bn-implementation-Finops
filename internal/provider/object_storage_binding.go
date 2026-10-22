package provider

import (
	"context"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/objectstorage"
)

// ObjectStorageAWS retains private commissioned collector authority only in the
// ingestion process. Public registrations cannot set either field.
type ObjectStorageAWS struct {
	*AWS
	ApprovedWriterPrincipal string
	MetricDefinitionID      string
	MetricDefinitionVersion string
}

func (a *ObjectStorageAWS) ReportBoundary(ctx context.Context, r objectstorage.Registration) (model.Document, error) {
	r.ApprovedWriterPrincipal = a.ApprovedWriterPrincipal
	r.MetricDefinitionID = a.MetricDefinitionID
	r.MetricDefinitionVersion = a.MetricDefinitionVersion
	return a.AWS.ReportBoundary(ctx, r)
}
