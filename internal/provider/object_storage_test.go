package provider

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/objectstorage"
	"io"
	"net/http"
	"strings"
	"testing"
)

func s3TestAWS(handler func(*http.Request) (string, int)) *AWS {
	return &AWS{cfg: aws.Config{Region: "eu-west-1", Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: "offline-s3", SecretAccessKey: "synthetic-not-a-live-secret", SessionToken: "offline"}, nil
	})}, client: &http.Client{Transport: objectTransport(func(r *http.Request) (*http.Response, error) {
		body, status := handler(r)
		return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}, nil
	})}}
}
func s3TestResponse(r *http.Request) (string, int) {
	if strings.HasPrefix(r.URL.Host, "sts.") {
		return rdsTestIdentity(), 200
	}
	q := r.URL.Query()
	if q.Has("max-buckets") {
		return "<ListAllMyBucketsResult><Owner><ID>native-canonical-owner</ID></Owner><Buckets><Bucket><Name>data-bucket</Name><BucketRegion>eu-west-1</BucketRegion><CreationDate>2020-01-01T00:00:00Z</CreationDate></Bucket></Buckets></ListAllMyBucketsResult>", 200
	}
	if q.Has("location") {
		return "<LocationConstraint>eu-west-1</LocationConstraint>", 200
	}
	if q.Has("versioning") {
		return "<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>", 200
	}
	if q.Has("encryption") {
		return "<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>aws:kms</SSEAlgorithm><KMSMasterKeyID>arn:aws:kms:eu-west-1:111122223333:key/example</KMSMasterKeyID></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>", 200
	}
	if q.Has("lifecycle") {
		return "<LifecycleConfiguration><Rule><ID>archive</ID><Filter><Prefix>logs/</Prefix></Filter><Status>Enabled</Status><Transition><Days>90</Days><StorageClass>GLACIER</StorageClass></Transition></Rule></LifecycleConfiguration>", 200
	}
	if q.Has("replication") {
		return "<ReplicationConfiguration><Role>arn:aws:iam::111122223333:role/replicate</Role><Rule><ID>recover</ID><Status>Enabled</Status><Destination><Bucket>arn:aws:s3:::backup</Bucket><StorageClass>STANDARD</StorageClass></Destination></Rule></ReplicationConfiguration>", 200
	}
	if q.Has("uploads") {
		return "<ListMultipartUploadsResult><Bucket>data-bucket</Bucket><IsTruncated>false</IsTruncated></ListMultipartUploadsResult>", 200
	}
	if q.Has("intelligent-tiering") {
		return "<ListBucketIntelligentTieringConfigurationsResult><IsTruncated>false</IsTruncated></ListBucketIntelligentTieringConfigurationsResult>", 200
	}
	if q.Has("inventory") {
		return "<ListInventoryConfigurationsResult><IsTruncated>false</IsTruncated></ListInventoryConfigurationsResult>", 200
	}
	if q.Has("analytics") {
		return "<ListBucketAnalyticsConfigurationsResult><IsTruncated>false</IsTruncated></ListBucketAnalyticsConfigurationsResult>", 200
	}
	if q.Has("metrics") {
		return "<ListMetricsConfigurationsResult><IsTruncated>false</IsTruncated></ListMetricsConfigurationsResult>", 200
	}
	return "<Error><Code>AccessDenied</Code><Message>PRIVATE_PROVIDER_DETAIL</Message></Error>", 403
}
func TestS3NativeDiscoveryConfigurationsAndDeniedUnknown(t *testing.T) {
	s := objectstorage.Scope{TenantID: "tenant-s3", AccountID: "111122223333", Region: "eu-west-1"}
	a := s3TestAWS(func(r *http.Request) (string, int) {
		if !strings.Contains(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256") {
			t.Fatal("unsigned native read")
		}
		if r.Method != "GET" && !(r.Method == "POST" && strings.HasPrefix(r.URL.Host, "sts.")) {
			t.Fatal("mutation method")
		}
		if !strings.HasPrefix(r.URL.Host, "sts.") && !r.URL.Query().Has("max-buckets") && r.Header.Get("x-amz-expected-bucket-owner") != s.AccountID {
			t.Fatal("owner fence absent")
		}
		return s3TestResponse(r)
	})
	out, e := a.S3Discover(context.Background(), s)
	if e != nil {
		t.Fatal(e)
	}
	if !out.Complete || len(out.Buckets) != 1 || len(out.Frames) < 10 || out.RawSHA256 != objectstorage.BytesHash(out.Raw) {
		t.Fatal("native capture incomplete")
	}
	b := out.Buckets[0]
	if b.Configurations["versioning"].Status != "OBSERVED" || b.Configurations["object_lock"].Status != "UNAVAILABLE" || b.Configurations["lifecycle"].Status != "OBSERVED" || b.Configurations["replication"].Status != "OBSERVED" {
		t.Fatal("native read states collapsed")
	}
}
func TestS3NativeCallerRegionAndPaginationFailClosed(t *testing.T) {
	for _, name := range []string{"caller", "region", "pagination"} {
		t.Run(name, func(t *testing.T) {
			a := s3TestAWS(func(r *http.Request) (string, int) {
				if name == "caller" && strings.HasPrefix(r.URL.Host, "sts.") {
					return strings.ReplaceAll(rdsTestIdentity(), "111122223333", "999900001111"), 200
				}
				if name == "region" && r.URL.Query().Has("location") {
					return "<LocationConstraint>us-east-1</LocationConstraint>", 200
				}
				if name == "pagination" && r.URL.Query().Has("max-buckets") {
					return "<ListAllMyBucketsResult><Buckets></Buckets><ContinuationToken>same</ContinuationToken></ListAllMyBucketsResult>", 200
				}
				return s3TestResponse(r)
			})
			out, e := a.S3Discover(context.Background(), objectstorage.Scope{TenantID: "tenant-s3", AccountID: "111122223333", Region: "eu-west-1"})
			if e == nil || out.Complete {
				t.Fatal("confused native scope accepted")
			}
		})
	}
}
