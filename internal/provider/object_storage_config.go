package provider

import (
	"context"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/objectstorage"
	"strconv"
)

func objectPages(ctx context.Context, read func(context.Context, *string) ([]model.Document, *string, error)) objectstorage.Observation {
	rows := []model.Document{}
	seen := map[string]bool{}
	var token *string
	for page := 0; page < 100; page++ {
		part, next, e := read(ctx, token)
		if e != nil {
			return objectObservation(nil, e)
		}
		if len(rows)+len(part) > 10000 {
			return objectstorage.Observation{Status: "UNAVAILABLE", ReasonCode: "S3_CONFIGURATION_LIMIT", Value: nil}
		}
		rows = append(rows, part...)
		n := aws.ToString(next)
		if n == "" {
			return objectstorage.Observation{Status: "OBSERVED", Value: model.Document{"Configurations": rows, "complete": true}}
		}
		if seen[n] {
			return objectstorage.Observation{Status: "UNAVAILABLE", ReasonCode: "S3_CONFIGURATION_PAGINATION_CYCLE", Value: nil}
		}
		seen[n] = true
		token = next
	}
	return objectstorage.Observation{Status: "UNAVAILABLE", ReasonCode: "S3_CONFIGURATION_INCOMPLETE", Value: nil}
}
func s3ITConfigs(ctx context.Context, c *s3.Client, b, o *string) objectstorage.Observation {
	return objectPages(ctx, func(ctx context.Context, t *string) ([]model.Document, *string, error) {
		p, e := c.ListBucketIntelligentTieringConfigurations(objectContext(ctx, "ListBucketIntelligentTieringConfigurations"), &s3.ListBucketIntelligentTieringConfigurationsInput{Bucket: b, ExpectedBucketOwner: o, ContinuationToken: t})
		if e != nil {
			return nil, nil, e
		}
		rows := []model.Document{}
		for _, v := range p.IntelligentTieringConfigurationList {
			rows = append(rows, nativeDocument(v))
		}
		if aws.ToBool(p.IsTruncated) && aws.ToString(p.NextContinuationToken) == "" {
			return nil, nil, errors.New("S3_CONFIGURATION_INCOMPLETE")
		}
		return rows, p.NextContinuationToken, nil
	})
}
func s3InventoryConfigs(ctx context.Context, c *s3.Client, b, o *string) objectstorage.Observation {
	return objectPages(ctx, func(ctx context.Context, t *string) ([]model.Document, *string, error) {
		p, e := c.ListBucketInventoryConfigurations(objectContext(ctx, "ListBucketInventoryConfigurations"), &s3.ListBucketInventoryConfigurationsInput{Bucket: b, ExpectedBucketOwner: o, ContinuationToken: t})
		if e != nil {
			return nil, nil, e
		}
		rows := []model.Document{}
		for _, v := range p.InventoryConfigurationList {
			rows = append(rows, nativeDocument(v))
		}
		if aws.ToBool(p.IsTruncated) && aws.ToString(p.NextContinuationToken) == "" {
			return nil, nil, errors.New("S3_CONFIGURATION_INCOMPLETE")
		}
		return rows, p.NextContinuationToken, nil
	})
}
func s3AnalyticsConfigs(ctx context.Context, c *s3.Client, b, o *string) objectstorage.Observation {
	return objectPages(ctx, func(ctx context.Context, t *string) ([]model.Document, *string, error) {
		p, e := c.ListBucketAnalyticsConfigurations(objectContext(ctx, "ListBucketAnalyticsConfigurations"), &s3.ListBucketAnalyticsConfigurationsInput{Bucket: b, ExpectedBucketOwner: o, ContinuationToken: t})
		if e != nil {
			return nil, nil, e
		}
		rows := []model.Document{}
		for _, v := range p.AnalyticsConfigurationList {
			rows = append(rows, nativeDocument(v))
		}
		if aws.ToBool(p.IsTruncated) && aws.ToString(p.NextContinuationToken) == "" {
			return nil, nil, errors.New("S3_CONFIGURATION_INCOMPLETE")
		}
		return rows, p.NextContinuationToken, nil
	})
}
func s3MetricConfigs(ctx context.Context, c *s3.Client, b, o *string) objectstorage.Observation {
	return objectPages(ctx, func(ctx context.Context, t *string) ([]model.Document, *string, error) {
		p, e := c.ListBucketMetricsConfigurations(objectContext(ctx, "ListBucketMetricsConfigurations"), &s3.ListBucketMetricsConfigurationsInput{Bucket: b, ExpectedBucketOwner: o, ContinuationToken: t})
		if e != nil {
			return nil, nil, e
		}
		rows := []model.Document{}
		for _, v := range p.MetricsConfigurationList {
			rows = append(rows, nativeDocument(v))
		}
		if aws.ToBool(p.IsTruncated) && aws.ToString(p.NextContinuationToken) == "" {
			return nil, nil, errors.New("S3_CONFIGURATION_INCOMPLETE")
		}
		return rows, p.NextContinuationToken, nil
	})
}

func s3Multipart(ctx context.Context, c *s3.Client, b, o *string) objectstorage.Observation {
	rows := []model.Document{}
	var key, upload *string
	seen := map[string]bool{}
	total := int64(0)
	for page := 0; page < 10; page++ {
		p, e := c.ListMultipartUploads(objectContext(ctx, "ListMultipartUploads"), &s3.ListMultipartUploadsInput{Bucket: b, ExpectedBucketOwner: o, MaxUploads: aws.Int32(100), KeyMarker: key, UploadIdMarker: upload})
		if e != nil {
			return objectObservation(nil, e)
		}
		for _, u := range p.Uploads {
			if len(rows) >= 256 {
				return objectstorage.Observation{Status: "UNAVAILABLE", ReasonCode: "S3_MULTIPART_REVIEW_LIMIT", Value: nil}
			}
			bytes := int64(0)
			parts := int64(0)
			var marker *string
			partSeen := map[string]bool{}
			complete := false
			for pi := 0; pi < 100; pi++ {
				q, e := c.ListParts(objectContext(ctx, "ListParts"), &s3.ListPartsInput{Bucket: b, ExpectedBucketOwner: o, Key: u.Key, UploadId: u.UploadId, MaxParts: aws.Int32(1000), PartNumberMarker: marker})
				if e != nil {
					return objectObservation(nil, e)
				}
				for _, part := range q.Parts {
					size := aws.ToInt64(part.Size)
					if size < 0 || bytes > int64(^uint64(0)>>1)-size {
						return objectstorage.Observation{Status: "UNAVAILABLE", ReasonCode: "S3_MULTIPART_SIZE_INVALID", Value: nil}
					}
					bytes += size
					parts++
				}
				if !aws.ToBool(q.IsTruncated) {
					complete = true
					break
				}
				next := aws.ToString(q.NextPartNumberMarker)
				if next == "" || partSeen[next] {
					return objectstorage.Observation{Status: "UNAVAILABLE", ReasonCode: "S3_MULTIPART_PARTS_INCOMPLETE", Value: nil}
				}
				partSeen[next] = true
				marker = q.NextPartNumberMarker
			}
			if !complete {
				return objectstorage.Observation{Status: "UNAVAILABLE", ReasonCode: "S3_MULTIPART_PARTS_INCOMPLETE", Value: nil}
			}
			if total > int64(^uint64(0)>>1)-bytes {
				return objectstorage.Observation{Status: "UNAVAILABLE", ReasonCode: "S3_MULTIPART_SIZE_INVALID", Value: nil}
			}
			total += bytes
			rows = append(rows, model.Document{"upload_identity": objectstorage.Hash(model.Document{"bucket": *b, "key": aws.ToString(u.Key), "upload_id": aws.ToString(u.UploadId)}), "initiated": u.Initiated, "storage_class": u.StorageClass, "size_bytes": strconv.FormatInt(bytes, 10), "part_count": strconv.FormatInt(parts, 10), "scope": "NATIVE_BOUNDED_NON_ATOMIC_METADATA_READ", "execution_authorized": false})
		}
		if !aws.ToBool(p.IsTruncated) {
			return objectstorage.Observation{Status: "OBSERVED", Value: model.Document{"uploads": rows, "total_bytes": strconv.FormatInt(total, 10), "complete": true, "observation_basis": "NON_ATOMIC_METADATA_NOT_FINANCIAL_FINALITY"}}
		}
		next := aws.ToString(p.NextKeyMarker) + "\x00" + aws.ToString(p.NextUploadIdMarker)
		if next == "\x00" || seen[next] {
			return objectstorage.Observation{Status: "UNAVAILABLE", ReasonCode: "S3_MULTIPART_PAGINATION_CYCLE", Value: nil}
		}
		seen[next] = true
		key, upload = p.NextKeyMarker, p.NextUploadIdMarker
	}
	return objectstorage.Observation{Status: "UNAVAILABLE", ReasonCode: "S3_MULTIPART_INCOMPLETE", Value: nil}
}
