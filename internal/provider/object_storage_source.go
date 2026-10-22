package provider

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/objectstorage"
	"net/http"
	"strings"
	"time"
)

// OpenObject reads only the approved report destination prefix, never workload
// payload. The caller streams the body; no full-file read is made here.
func (a *AWS) OpenObject(ctx context.Context, r objectstorage.Registration, key, version string) (objectstorage.Object, error) {
	out := objectstorage.Object{}
	if objectstorage.ValidateScope(objectstorage.Scope{TenantID: r.TenantID, AccountID: r.AccountID, Region: r.Region}) != nil || !strings.HasPrefix(key, r.Prefix) || strings.Contains(key, "..") || r.ReportBucket == "" || r.ReportOwner == "" {
		return out, errors.New("S3_REPORT_OBJECT_SCOPE_DENIED")
	}
	reportRegion := r.ReportRegion
	if reportRegion == "" {
		reportRegion = r.Region
	}
	cfg, capture, e := objectSDK(a, objectstorage.Scope{TenantID: r.TenantID, AccountID: r.AccountID, Region: reportRegion})
	if e != nil {
		return out, e
	}
	if e = objectIdentity(ctx, cfg, capture.scope); e != nil {
		return out, e
	}
	// The metadata capturer intentionally never buffers a report body.
	h := a.client
	if h == nil {
		h = &http.Client{Timeout: 30 * time.Second}
	}
	safe := *h
	safe.Timeout = 0
	safe.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	cfg.HTTPClient = &safe
	in := &s3.GetObjectInput{Bucket: aws.String(r.ReportBucket), Key: aws.String(key), ExpectedBucketOwner: aws.String(r.ReportOwner)}
	if version != "" {
		in.VersionId = aws.String(version)
	}
	response, e := objectClient(cfg).GetObject(ctx, in)
	if e != nil {
		return out, errors.New("S3_REPORT_OBJECT_UNAVAILABLE")
	}
	v := aws.ToString(response.VersionId)
	if v == "" || v == "null" || version != "" && v != version {
		response.Body.Close()
		return out, errors.New("S3_REPORT_VERSION_REQUIRED")
	}
	return objectstorage.Object{Bucket: r.ReportBucket, Key: key, VersionID: v, ETag: aws.ToString(response.ETag), Length: aws.ToInt64(response.ContentLength), LastModified: aws.ToTime(response.LastModified), Body: response.Body}, nil
}

func (a *AWS) ReportBoundary(ctx context.Context, r objectstorage.Registration) (model.Document, error) {
	reportRegion := r.ReportRegion
	if reportRegion == "" {
		reportRegion = r.Region
	}
	scope := objectstorage.Scope{TenantID: r.TenantID, AccountID: r.AccountID, Region: reportRegion}
	cfg, capture, e := objectSDK(a, scope)
	if e != nil {
		return nil, e
	}
	if e = objectIdentity(ctx, cfg, scope); e != nil {
		return nil, e
	}
	c := objectClient(cfg)
	version, e := c.GetBucketVersioning(objectContext(ctx, "GetBucketVersioning"), &s3.GetBucketVersioningInput{Bucket: aws.String(r.ReportBucket), ExpectedBucketOwner: aws.String(r.ReportOwner)})
	if e != nil || string(version.Status) != "Enabled" {
		return nil, errors.New("S3_REPORT_VERSIONED_DESTINATION_REQUIRED")
	}
	loc, e := c.GetBucketLocation(objectContext(ctx, "GetBucketLocation"), &s3.GetBucketLocationInput{Bucket: aws.String(r.ReportBucket), ExpectedBucketOwner: aws.String(r.ReportOwner)})
	if e != nil {
		return nil, errors.New("S3_REPORT_REGION_UNAVAILABLE")
	}
	actual := string(loc.LocationConstraint)
	if actual == "EU" {
		actual = "eu-west-1"
	}
	if actual == "" {
		actual = "us-east-1"
	}
	if actual != reportRegion {
		return nil, errors.New("S3_REPORT_REGION_MISMATCH")
	}
	policy, e := c.GetBucketPolicy(objectContext(ctx, "GetBucketPolicy"), &s3.GetBucketPolicyInput{Bucket: aws.String(r.ReportBucket), ExpectedBucketOwner: aws.String(r.ReportOwner)})
	if e != nil {
		return nil, errors.New("S3_REPORT_WRITER_POLICY_UNAVAILABLE")
	}
	p := model.Document{}
	if json.Unmarshal([]byte(aws.ToString(policy.Policy)), &p) != nil || objectstorage.ValidateReportWriterPolicy(r, p) != nil {
		return nil, errors.New("S3_REPORT_WRITER_POLICY_UNAPPROVED")
	}
	var configuration model.Document
	if r.Kind == objectstorage.InventoryKind {
		v, e := c.GetBucketInventoryConfiguration(objectContext(ctx, "GetBucketInventoryConfiguration"), &s3.GetBucketInventoryConfigurationInput{Bucket: aws.String(r.Bucket), ExpectedBucketOwner: aws.String(r.AccountID), Id: aws.String(r.InventoryID)})
		if e != nil {
			return nil, errors.New("S3_INVENTORY_CONFIGURATION_UNAVAILABLE")
		}
		configuration = nativeDocument(v.InventoryConfiguration)
	} else if r.ReportType == "APP_ACCESS" {
		configuration = model.Document{"Id": r.InventoryID, "kind": "APP_ACCESS", "approved_writer_principal_arn": r.ApprovedWriterPrincipal, "metric_definition_id": r.MetricDefinitionID, "metric_definition_version": r.MetricDefinitionVersion, "source_bucket": r.Bucket, "report_bucket": r.ReportBucket, "report_prefix": r.Prefix}
	} else if r.ReportType == "S3_STORAGE_LENS" {
		configuration, e = a.S3StorageLensConfiguration(ctx, r)
		if e != nil {
			return nil, e
		}
	} else {
		v, e := c.GetBucketAnalyticsConfiguration(objectContext(ctx, "GetBucketAnalyticsConfiguration"), &s3.GetBucketAnalyticsConfigurationInput{Bucket: aws.String(r.Bucket), ExpectedBucketOwner: aws.String(r.AccountID), Id: aws.String(r.InventoryID)})
		if e != nil {
			return nil, errors.New("S3_ANALYTICS_CONFIGURATION_UNAVAILABLE")
		}
		configuration = nativeDocument(v.AnalyticsConfiguration)
	}
	if e = objectstorage.ValidateReportConfiguration(r, configuration); e != nil {
		return nil, e
	}
	if r.Kind == objectstorage.InventoryKind {
		tags, e := c.GetBucketTagging(objectContext(ctx, "GetBucketTagging"), &s3.GetBucketTaggingInput{Bucket: aws.String(r.Bucket), ExpectedBucketOwner: aws.String(r.AccountID)})
		observation := objectObservation(tags, e)
		configuration["source_bucket_tags"] = observation
	}
	lensFrames := configuration["native_frames"]
	delete(configuration, "native_frames")
	raw, _ := json.Marshal(model.Document{"scope": scope, "frames": capture.frames, "lens_frames": lensFrames})
	return model.Document{"bucket": r.ReportBucket, "owner": r.ReportOwner, "region": actual, "versioning": "Enabled", "configuration": configuration, "configuration_hash": objectstorage.Hash(configuration), "writer_policy": p, "writer_policy_hash": objectstorage.Hash(p), "observed_at": time.Now().UTC(), "raw": raw, "raw_sha256": objectstorage.BytesHash(raw)}, nil
}

// S3ManifestKeys enumerates only the commissioned report namespace. It never
// traverses the customer workload bucket with ListObjectsV2.
func (a *AWS) S3ManifestKeys(ctx context.Context, r objectstorage.Registration) ([]string, error) {
	reportRegion := r.ReportRegion
	if reportRegion == "" {
		reportRegion = r.Region
	}
	cfg, _, e := objectSDK(a, objectstorage.Scope{TenantID: r.TenantID, AccountID: r.AccountID, Region: reportRegion})
	if e != nil {
		return nil, e
	}
	c := objectClient(cfg)
	out := []string{}
	var token *string
	seen := map[string]bool{}
	prefix := r.Prefix + r.Bucket + "/" + r.InventoryID + "/"
	if r.ReportType == "S3_STORAGE_LENS" {
		prefix = r.Prefix + "StorageLens/" + r.AccountID + "/" + r.InventoryID + "/V_1/manifests/"
	} else if r.Kind == objectstorage.AccessKind {
		prefix = r.Prefix
	}
	for page := 0; page < 100; page++ {
		p, e := c.ListObjectsV2(objectContext(ctx, "ListObjectsV2Reports"), &s3.ListObjectsV2Input{Bucket: aws.String(r.ReportBucket), ExpectedBucketOwner: aws.String(r.ReportOwner), Prefix: aws.String(prefix), ContinuationToken: token, MaxKeys: aws.Int32(1000)})
		if e != nil {
			return nil, errors.New("S3_REPORT_ENUMERATION_UNAVAILABLE")
		}
		for _, v := range p.Contents {
			k := aws.ToString(v.Key)
			if strings.HasSuffix(k, "/manifest.json") || r.ReportType == "S3_STORAGE_CLASS_ANALYSIS" && strings.HasSuffix(k, ".csv") || r.ReportType == "APP_ACCESS" && strings.HasSuffix(k, ".jsonl") {
				out = append(out, k)
				if len(out) > 1000 {
					return nil, errors.New("S3_REPORT_MANIFEST_LIMIT")
				}
			}
		}
		if !aws.ToBool(p.IsTruncated) {
			return out, nil
		}
		next := aws.ToString(p.NextContinuationToken)
		if next == "" || seen[next] {
			return nil, errors.New("S3_REPORT_ENUMERATION_INCOMPLETE")
		}
		seen[next] = true
		token = p.NextContinuationToken
	}
	return nil, errors.New("S3_REPORT_ENUMERATION_INCOMPLETE")
}
