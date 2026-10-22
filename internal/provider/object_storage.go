package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/objectstorage"
)

const objectMetadataLimit = 4 << 20
const objectCaptureLimit = 64 << 20

type objectActionKey struct{}
type objectCapture struct {
	client *http.Client
	scope  objectstorage.Scope
	frames []objectstorage.RawFrame
	bytes  int
	mu     sync.Mutex
}

func (c *objectCapture) Do(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "https" || req.URL.Port() != "" || req.URL.User != nil || !strings.HasSuffix(req.URL.Host, ".amazonaws.com") {
		return nil, errors.New("S3_NATIVE_ENDPOINT_INVALID")
	}
	selector := req.URL.Path + "?" + req.URL.RawQuery
	if req.Body != nil {
		body, e := io.ReadAll(io.LimitReader(req.Body, 65537))
		if e != nil || len(body) > 65536 {
			return nil, errors.New("S3_METADATA_REQUEST_LIMIT")
		}
		req.Body = io.NopCloser(bytes.NewReader(body))
		selector += "\n" + string(body)
	}
	response, e := c.client.Do(req)
	if e != nil {
		return nil, errors.New("S3_NATIVE_TRANSPORT_UNAVAILABLE")
	}
	raw, e := io.ReadAll(io.LimitReader(response.Body, objectMetadataLimit+1))
	response.Body.Close()
	if e != nil || len(raw) > objectMetadataLimit {
		return nil, errors.New("S3_METADATA_LIMIT")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.bytes += len(raw)
	if c.bytes > objectCaptureLimit || len(c.frames) >= 4096 {
		return nil, errors.New("S3_CAPTURE_LIMIT")
	}
	action, _ := req.Context().Value(objectActionKey{}).(string)
	service := "s3"
	if strings.HasPrefix(req.URL.Host, "sts.") {
		service = "sts"
	} else if strings.HasPrefix(req.URL.Host, "monitoring.") {
		service = "monitoring"
	} else if strings.Contains(req.URL.Host, ".s3-control.") {
		service = "s3-control"
	} else if req.URL.Host == "api.pricing.us-east-1.amazonaws.com" {
		service = "pricing"
	}
	region := c.scope.Region
	if service == "pricing" {
		region = "us-east-1"
	}
	c.frames = append(c.frames, objectstorage.RawFrame{Service: service, Region: region, Action: action, Selector: selector, StatusCode: response.StatusCode, Body: raw})
	response.Body = io.NopCloser(bytes.NewReader(raw))
	return response, nil
}
func objectContext(ctx context.Context, action string) context.Context {
	return context.WithValue(ctx, objectActionKey{}, action)
}
func objectObservation(value any, e error) objectstorage.Observation {
	if e == nil {
		return objectstorage.Observation{Status: "OBSERVED", Value: nativeDocument(value)}
	}
	var api smithy.APIError
	code := "NATIVE_READ_UNAVAILABLE"
	if errors.As(e, &api) {
		code = awsErrorCode(api.ErrorCode())
	}
	switch code {
	case "NoSuchLifecycleConfiguration", "ReplicationConfigurationNotFoundError", "NoSuchTagSet", "NoSuchBucketPolicy", "ObjectLockConfigurationNotFoundError":
		return objectstorage.Observation{Status: "ABSENT", ReasonCode: code, Value: nil}
	}
	return objectstorage.Observation{Status: "UNAVAILABLE", ReasonCode: code, Value: nil}
}
func objectSDK(a *AWS, scope objectstorage.Scope) (aws.Config, *objectCapture, error) {
	if a == nil || a.cfg.Credentials == nil || objectstorage.ValidateScope(scope) != nil {
		return aws.Config{}, nil, errors.New("S3_SCOPE_INVALID")
	}
	h := a.client
	if h == nil {
		h = &http.Client{Timeout: 30 * time.Second}
	}
	safe := *h
	safe.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	capture := &objectCapture{client: &safe, scope: scope, frames: []objectstorage.RawFrame{}}
	cfg := a.cfg
	cfg.Region = scope.Region
	cfg.HTTPClient = capture
	cfg.RetryMaxAttempts = 3
	return cfg, capture, nil
}
func objectIdentity(ctx context.Context, cfg aws.Config, scope objectstorage.Scope) error {
	caller, e := sts.NewFromConfig(cfg, func(o *sts.Options) { o.BaseEndpoint = aws.String("https://sts." + scope.Region + ".amazonaws.com") }).GetCallerIdentity(objectContext(ctx, "GetCallerIdentity"), &sts.GetCallerIdentityInput{})
	if e != nil || aws.ToString(caller.Account) != scope.AccountID || !strings.HasPrefix(aws.ToString(caller.Arn), "arn:aws:sts::"+scope.AccountID+":assumed-role/") || aws.ToString(caller.UserId) == "" {
		return errors.New("S3_CALLER_ACCOUNT_MISMATCH")
	}
	return nil
}

// S3Discover inventories general-purpose buckets in the registered region.
// Missing component permission is retained, never interpreted as empty config.
func (a *AWS) S3Discover(ctx context.Context, scope objectstorage.Scope) (objectstorage.Discovery, error) {
	out := objectstorage.Discovery{SchemaVersion: "1", Scope: scope, StartedAt: time.Now().UTC(), Buckets: []objectstorage.Bucket{}, Coverage: []model.Document{}}
	cfg, capture, e := objectSDK(a, scope)
	if e != nil {
		return out, e
	}
	if e = objectIdentity(ctx, cfg, scope); e != nil {
		return out, e
	}
	client := objectClient(cfg)
	var token *string
	seen := map[string]bool{}
	names := map[string]bool{}
	for pages := 0; pages < 100; pages++ {
		page, e := client.ListBuckets(objectContext(ctx, "ListBuckets"), &s3.ListBucketsInput{BucketRegion: aws.String(scope.Region), MaxBuckets: aws.Int32(100), ContinuationToken: token})
		if e != nil {
			return out, errors.New("S3_BUCKET_DISCOVERY_INCOMPLETE")
		}
		for _, item := range page.Buckets {
			name := aws.ToString(item.Name)
			if name == "" || names[name] || len(out.Buckets) >= 10000 {
				return out, errors.New("S3_BUCKET_DISCOVERY_LIMIT_OR_DUPLICATE")
			}
			names[name] = true
			region := aws.ToString(item.BucketRegion)
			if region != "" && region != scope.Region {
				return out, errors.New("S3_BUCKET_REGION_MISMATCH")
			}
			b, e := a.s3Bucket(ctx, client, scope, name, aws.ToTime(item.CreationDate))
			if e != nil {
				return out, e
			}
			out.Buckets = append(out.Buckets, b)
		}
		next := aws.ToString(page.ContinuationToken)
		if next == "" {
			out.Complete = true
			break
		}
		if seen[next] {
			return out, errors.New("S3_PAGINATION_CYCLE")
		}
		seen[next] = true
		token = aws.String(next)
	}
	if !out.Complete {
		return out, errors.New("S3_BUCKET_DISCOVERY_INCOMPLETE")
	}
	out.CollectedAt = time.Now().UTC()
	out.Frames = capture.frames
	out.Raw, e = json.Marshal(model.Document{"schema_version": "1", "scope": scope, "frames": capture.frames})
	if e != nil {
		return out, e
	}
	out.RawSHA256 = objectstorage.BytesHash(out.Raw)
	return out, nil
}
func objectClient(cfg aws.Config) *s3.Client {
	return s3.NewFromConfig(cfg, func(o *s3.Options) { o.BaseEndpoint = aws.String("https://s3." + cfg.Region + ".amazonaws.com") })
}

// S3DescribeBucket commissions only the exact registered bucket. Completeness
// here describes that bucket's metadata collection, never all account buckets.
// Component failures remain explicit unavailable observations.
func (a *AWS) S3DescribeBucket(ctx context.Context, scope objectstorage.Scope, name string) (objectstorage.Discovery, error) {
	out := objectstorage.Discovery{SchemaVersion: "1", Scope: scope, StartedAt: time.Now().UTC(), Buckets: []objectstorage.Bucket{}, Coverage: []model.Document{}}
	if name == "" || strings.ContainsAny(name, "/\\*?\x00\r\n") {
		return out, errors.New("S3_BUCKET_SELECTOR_INVALID")
	}
	cfg, capture, e := objectSDK(a, scope)
	if e != nil {
		return out, e
	}
	if e = objectIdentity(ctx, cfg, scope); e != nil {
		return out, e
	}
	b, e := a.s3Bucket(ctx, objectClient(cfg), scope, name, time.Time{})
	if e != nil {
		return out, e
	}
	if b.Configurations["location"].Status != "OBSERVED" {
		return out, errors.New("S3_BUCKET_OWNERSHIP_AND_REGION_UNPROVEN")
	}
	out.Buckets = append(out.Buckets, b)
	out.Complete = true
	out.CollectedAt = time.Now().UTC()
	out.Coverage = append(out.Coverage, model.Document{"scope": "REGISTERED_BUCKET", "bucket": name, "account_inventory_complete": false})
	out.Frames = capture.frames
	out.Raw, e = json.Marshal(model.Document{"schema_version": "1", "scope": scope, "registered_bucket": name, "frames": capture.frames})
	if e != nil {
		return out, e
	}
	out.RawSHA256 = objectstorage.BytesHash(out.Raw)
	return out, nil
}
func (a *AWS) s3Bucket(ctx context.Context, c *s3.Client, s objectstorage.Scope, name string, created time.Time) (objectstorage.Bucket, error) {
	b := objectstorage.Bucket{Name: name, ARN: "arn:aws:s3:::" + name, AccountID: s.AccountID, Region: s.Region, CreatedAt: created, ObservedAt: time.Now().UTC(), Configurations: map[string]objectstorage.Observation{}, Tags: map[string]string{}}
	bucket, owner := aws.String(name), aws.String(s.AccountID)
	loc, e := c.GetBucketLocation(objectContext(ctx, "GetBucketLocation"), &s3.GetBucketLocationInput{Bucket: bucket, ExpectedBucketOwner: owner})
	if e != nil {
		b.Configurations["location"] = objectObservation(nil, e)
	} else {
		b.Configurations["location"] = objectObservation(loc, nil)
		r := string(loc.LocationConstraint)
		if r == "EU" {
			r = "eu-west-1"
		}
		if r == "" {
			r = "us-east-1"
		}
		if r != s.Region {
			return b, errors.New("S3_BUCKET_REGION_MISMATCH")
		}
	}
	v, e := c.GetBucketVersioning(objectContext(ctx, "GetBucketVersioning"), &s3.GetBucketVersioningInput{Bucket: bucket, ExpectedBucketOwner: owner})
	b.Configurations["versioning"] = objectObservation(v, e)
	enc, e := c.GetBucketEncryption(objectContext(ctx, "GetBucketEncryption"), &s3.GetBucketEncryptionInput{Bucket: bucket, ExpectedBucketOwner: owner})
	b.Configurations["encryption"] = objectObservation(enc, e)
	lock, e := c.GetObjectLockConfiguration(objectContext(ctx, "GetObjectLockConfiguration"), &s3.GetObjectLockConfigurationInput{Bucket: bucket, ExpectedBucketOwner: owner})
	b.Configurations["object_lock"] = objectObservation(lock, e)
	life, e := c.GetBucketLifecycleConfiguration(objectContext(ctx, "GetBucketLifecycleConfiguration"), &s3.GetBucketLifecycleConfigurationInput{Bucket: bucket, ExpectedBucketOwner: owner})
	b.Configurations["lifecycle"] = objectObservation(life, e)
	rep, e := c.GetBucketReplication(objectContext(ctx, "GetBucketReplication"), &s3.GetBucketReplicationInput{Bucket: bucket, ExpectedBucketOwner: owner})
	b.Configurations["replication"] = objectObservation(rep, e)
	pab, e := c.GetPublicAccessBlock(objectContext(ctx, "GetPublicAccessBlock"), &s3.GetPublicAccessBlockInput{Bucket: bucket, ExpectedBucketOwner: owner})
	b.Configurations["public_access_block"] = objectObservation(pab, e)
	tags, e := c.GetBucketTagging(objectContext(ctx, "GetBucketTagging"), &s3.GetBucketTaggingInput{Bucket: bucket, ExpectedBucketOwner: owner})
	b.Configurations["tags"] = objectObservation(tags, e)
	if e == nil {
		for _, t := range tags.TagSet {
			b.Tags[aws.ToString(t.Key)] = aws.ToString(t.Value)
		}
	}
	log, e := c.GetBucketLogging(objectContext(ctx, "GetBucketLogging"), &s3.GetBucketLoggingInput{Bucket: bucket, ExpectedBucketOwner: owner})
	b.Configurations["logging"] = objectObservation(log, e)
	own, e := c.GetBucketOwnershipControls(objectContext(ctx, "GetBucketOwnershipControls"), &s3.GetBucketOwnershipControlsInput{Bucket: bucket, ExpectedBucketOwner: owner})
	b.Configurations["ownership_controls"] = objectObservation(own, e)
	b.Configurations["intelligent_tiering"] = s3ITConfigs(ctx, c, bucket, owner)
	b.Configurations["inventory"] = s3InventoryConfigs(ctx, c, bucket, owner)
	b.Configurations["analytics"] = s3AnalyticsConfigs(ctx, c, bucket, owner)
	b.Configurations["metrics"] = s3MetricConfigs(ctx, c, bucket, owner)
	b.Configurations["storage_lens"] = objectstorage.Observation{Status: "UNAVAILABLE", ReasonCode: "ACCOUNT_LENS_RELATIONSHIP_NOT_COMMISSIONED", Value: nil}
	b.Configurations["multipart_uploads"] = s3Multipart(ctx, c, bucket, owner)
	return b, nil
}
