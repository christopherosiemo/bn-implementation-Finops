package activity

import (
	"context"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/native"
	"net/http"
	"net/url"
	"os"
	"time"
)

// Optional ingress credentials are independent of every source reader/analyst.
// Hosted workload credentials may renew through IRSA; customer role assumption
// and generic static object credentials are deliberately not selected here.
func LambdaPerformanceStorageFromEnvironment(ctx context.Context, fixture bool) (*native.Storage, error) {
	region := os.Getenv("OBJECT_REGION")
	if region == "" {
		region = "eu-west-1"
	}
	if region != "eu-west-1" {
		return nil, errors.New("LAMBDA_EU_STORAGE_REQUIRED")
	}
	options := []func(*awsconfig.LoadOptions) error{awsconfig.WithRegion(region)}
	key, secret := os.Getenv("LAMBDA_PERFORMANCE_ACCESS_KEY"), os.Getenv("LAMBDA_PERFORMANCE_SECRET_KEY")
	if key != "" || secret != "" {
		if key == "" || secret == "" {
			return nil, errors.New("LAMBDA_INGRESS_STORAGE_IDENTITY_INCOMPLETE")
		}
		options = append(options, awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(key, secret, "")))
	} else if os.Getenv("AWS_ACCESS_KEY_ID") != "" || os.Getenv("AWS_SECRET_ACCESS_KEY") != "" {
		return nil, errors.New("LAMBDA_INGRESS_UNSCOPED_STATIC_CREDENTIALS_FORBIDDEN")
	} else if os.Getenv("AWS_WEB_IDENTITY_TOKEN_FILE") == "" || os.Getenv("AWS_ROLE_ARN") == "" {
		return nil, errors.New("LAMBDA_INGRESS_DEDICATED_STORAGE_IDENTITY_REQUIRED")
	}
	endpoint := os.Getenv("OBJECT_ENDPOINT")
	if endpoint == "" {
		endpoint = "https://s3.eu-west-1.amazonaws.com"
	}
	u, e := url.Parse(endpoint)
	if e != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || (u.Scheme != "https" && !(fixture && u.Scheme == "http")) {
		return nil, errors.New("LAMBDA_INGRESS_STORAGE_ENDPOINT_INVALID")
	}
	analytics, err := url.Parse(os.Getenv("CLICKHOUSE_URL"))
	if err != nil || analytics.Host == "" || analytics.User != nil || (analytics.Scheme != "https" && !(fixture && analytics.Scheme == "http")) {
		return nil, errors.New("LAMBDA_INGRESS_ANALYTICS_ENDPOINT_INVALID")
	}
	bucket := os.Getenv("OBJECT_BUCKET_RAW")
	user := os.Getenv("LAMBDA_PERFORMANCE_CLICKHOUSE_USER")
	password := os.Getenv("LAMBDA_PERFORMANCE_CLICKHOUSE_PASSWORD")
	if bucket == "" || user == "" || password == "" || os.Getenv("CLICKHOUSE_URL") == "" {
		return nil, errors.New("LAMBDA_INGRESS_ANALYTICS_IDENTITY_REQUIRED")
	}
	cfg, e := awsconfig.LoadDefaultConfig(ctx, options...)
	if e != nil {
		return nil, errors.New("LAMBDA_INGRESS_STORAGE_IDENTITY_UNAVAILABLE")
	}
	client := &http.Client{Timeout: 35 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}
	cfg.HTTPClient = client
	s := s3.NewFromConfig(cfg, func(o *s3.Options) { o.BaseEndpoint = aws.String(endpoint); o.UsePathStyle = true })
	db := os.Getenv("CLICKHOUSE_DATABASE")
	if db == "" {
		db = "finops"
	}
	return &native.Storage{S3: s, Bucket: bucket, Database: db, AnalyticsURL: os.Getenv("CLICKHOUSE_URL"), AnalyticsUser: user, AnalyticsSecret: password, Client: client}, nil
}
