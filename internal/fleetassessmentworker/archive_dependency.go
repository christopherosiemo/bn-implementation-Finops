package fleetassessmentworker

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	b "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetbilling"
)

// OpenReadOnlyArchive shares the installed endpoint/file/credential policy with
// other dedicated analytical workers. It returns only exact-version readback;
// it neither opens a database nor exposes SDK credentials or write methods.
// DatabaseFile is validated as a configuration path but is never read here.
func OpenReadOnlyArchive(ctx context.Context, c Config) (b.PinnedReader, func(), error) {
	if c.Validate() != nil || checkEnvironment(os.Environ(), c) != nil {
		return nil, nil, ErrConfiguration
	}
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 10 * time.Second}).DialContext}
	close := transport.CloseIdleConnections
	clientHTTP := &http.Client{Timeout: 30 * time.Second, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	options := s3.Options{Region: c.ArchiveRegion, HTTPClient: clientHTTP, RetryMaxAttempts: 2}
	if c.ArchiveMode == LocalArchive {
		access, e := secretFile(c.ArchiveAccessKeyFile, 256)
		if e != nil {
			return nil, nil, e
		}
		secret, e := secretFile(c.ArchiveSecretKeyFile, 256)
		if e != nil {
			clear(access)
			return nil, nil, e
		}
		accessText, secretText := strings.TrimSpace(string(access)), strings.TrimSpace(string(secret))
		clear(access)
		clear(secret)
		if accessText == "" || secretText == "" || strings.ContainsAny(accessText+secretText, "\x00\r\n\t ") || strings.HasPrefix(accessText, "AKIA") || strings.HasPrefix(accessText, "ASIA") {
			return nil, nil, ErrConfiguration
		}
		u, _ := url.Parse(c.ArchiveEndpoint)
		ip, e := privateHost(ctx, u.Hostname())
		if e != nil {
			return nil, nil, e
		}
		target, pinned := u.Host, net.JoinHostPort(ip, u.Port())
		transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			if address != target {
				return nil, ErrConfiguration
			}
			return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, pinned)
		}
		options.BaseEndpoint = aws.String(c.ArchiveEndpoint)
		options.UsePathStyle = true
		options.Credentials = credentials.NewStaticCredentialsProvider(accessText, secretText, "")
	} else {
		options.Credentials = aws.NewCredentialsCache(stscreds.NewWebIdentityRoleProvider(sts.New(sts.Options{Region: c.ArchiveRegion, HTTPClient: clientHTTP, RetryMaxAttempts: 2}), c.RoleARN, stscreds.IdentityTokenFile(c.WebIdentityTokenFile)))
	}
	client := s3.New(options)
	if c.ArchiveMode == IRSAArchive {
		location, e := client.GetBucketLocation(ctx, &s3.GetBucketLocationInput{Bucket: aws.String(c.ArchiveBucket), ExpectedBucketOwner: aws.String(c.ArchiveBucketOwner)})
		if e != nil || location == nil || string(location.LocationConstraint) != "eu-west-1" {
			close()
			return nil, nil, ErrConfiguration
		}
	}
	return archiveReader{client, c.ArchiveBucket, c.ArchiveBucketOwner}, close, nil
}
