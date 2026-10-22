package workflow

import (
	"context"
	"encoding/json"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/awsservice"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/native"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/service"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
)

type awsServicePriceReader interface {
	AWSServicePriceDimensions(context.Context, awsservice.Scope, []string) (model.Document, error)
}

// Native dimensions are collected by the existing ingester, never by the
// analytical identity. Prices from the public catalogue are not customer rates.
func enrichAWSServicePricing(ctx context.Context, db *store.Store, reader AWSServiceReader, reg awsservice.Registration, collection awsservice.Collection, storage *native.Storage) (awsservice.Collection, error) {
	if collection.Family != "ECS" {
		return collection, nil
	}
	priceReader, ok := reader.(awsServicePriceReader)
	if !ok {
		return collection, nil
	}
	var skus []string
	err := db.Do(ctx, reg.TenantID, func(tx *store.Tx) error {
		var e error
		skus, e = service.CurrentAWSServiceSKUs(ctx, tx, reg.AccountID, reg.Region)
		return e
	})
	if err != nil || len(skus) == 0 {
		return collection, nil
	}
	prices, err := priceReader.AWSServicePriceDimensions(ctx, collection.Scope, skus)
	if err != nil {
		return collection, nil
	}
	wire, ok := prices["raw"].([]byte)
	if !ok || awsservice.BytesHash(wire) != prices["raw_sha256"] {
		return collection, awsservice.ErrEvidence
	}
	ref, err := awsServiceArchive(ctx, storage, reg.TenantID, "wire", wire)
	if err != nil {
		return collection, err
	}
	for _, resource := range collection.Resources {
		if resource["resource_type"] != "ECS_SERVICE" {
			continue
		}
		descriptor := awsservice.Document(resource["aws_service_assessment_evidence"])
		if descriptor["status"] != "OBSERVED_NATIVE_METRICS" {
			continue
		}
		raw, e := storage.Read(ctx, reg.TenantID, awsservice.Document(descriptor["archive"]))
		if e != nil {
			return collection, e
		}
		if awsservice.BytesHash(raw) != model.String(awsservice.Document(descriptor["archive"]), "body_sha256") {
			return collection, awsservice.ErrEvidence
		}
		data := awsservice.Document(json.RawMessage(raw))
		data["price_dimensions"], data["price_source_ref"], data["pricing_basis"] = prices["dimensions"], ref, prices["basis"]
		updated, e := json.Marshal(data)
		if e != nil {
			return collection, e
		}
		archive, e := awsServiceArchive(ctx, storage, reg.TenantID, "canonical", updated)
		if e != nil {
			return collection, e
		}
		descriptor["archive"], descriptor["pricing_source_ref"] = archive, ref
		resource["aws_service_assessment_evidence"] = descriptor
	}
	return collection, nil
}
