package commitmentarchive

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
)

var archivePart = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
var archiveBucket = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)

// Uses the existing ingestion S3 client and immutable version/readback contract.
// This object is never constructed in the analytical worker or public API.
type ImmutableArchive struct {
	Client source.FleetS3Client
	Bucket string
}

func (a *ImmutableArchive) Witness(ctx context.Context, tenant, id string, raw []byte) (model.Document, error) {
	return a.write(ctx, tenant, id, raw, 64<<10)
}
func (a *ImmutableArchive) Review(ctx context.Context, tenant, id string, raw []byte) (model.Document, error) {
	return a.write(ctx, tenant, id, raw, 24<<20)
}
func (a *ImmutableArchive) write(ctx context.Context, tenant, id string, raw []byte, limit int) (model.Document, error) {
	if a == nil || a.Client == nil || !archiveBucket.MatchString(a.Bucket) || !archivePart.MatchString(tenant) || !archivePart.MatchString(id) || len(raw) == 0 || len(raw) > limit {
		return nil, errors.New("OWNERSHIP_ARCHIVE_STORAGE_BINDING_INVALID")
	}
	digest := source.BytesHash(raw)
	sum := sha256.Sum256(raw)
	key := "tenant/" + tenant + "/commitment-ownership-archive/" + id + "/" + digest + ".json"
	put, err := a.Client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(a.Bucket), Key: aws.String(key), Body: bytes.NewReader(raw), ContentType: aws.String("application/json"), ChecksumSHA256: aws.String(base64.StdEncoding.EncodeToString(sum[:]))})
	if err != nil || put == nil || aws.ToString(put.VersionId) == "" || aws.ToString(put.VersionId) == "null" {
		return nil, errors.New("OWNERSHIP_ARCHIVE_IMMUTABLE_VERSION_REQUIRED")
	}
	version := aws.ToString(put.VersionId)
	get, err := a.Client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(a.Bucket), Key: aws.String(key), VersionId: aws.String(version)})
	if err != nil || get == nil || get.Body == nil {
		return nil, errors.New("OWNERSHIP_ARCHIVE_READBACK_FAILED")
	}
	defer get.Body.Close()
	if get.ContentLength != nil && *get.ContentLength > int64(limit) {
		return nil, errors.New("OWNERSHIP_ARCHIVE_READBACK_LIMIT")
	}
	back, err := io.ReadAll(io.LimitReader(get.Body, int64(limit)+1))
	if err != nil || len(back) != len(raw) || len(back) > limit || aws.ToString(get.VersionId) != version || source.BytesHash(back) != digest {
		return nil, errors.New("OWNERSHIP_ARCHIVE_READBACK_CHANGED")
	}
	return model.Document{"bucket": a.Bucket, "key": key, "version_id": version, "body_sha256": digest}, nil
}

func (a *ImmutableArchive) ReadWitness(ctx context.Context, tenant string, ref model.Document) ([]byte, error) {
	key := model.String(ref, "key")
	version := model.String(ref, "version_id")
	if a == nil || a.Client == nil || !archivePart.MatchString(tenant) || model.String(ref, "bucket") != a.Bucket || !strings.HasPrefix(key, "tenant/"+tenant+"/commitment-ownership-archive/") || strings.Contains(key, "..") || version == "" || version == "null" {
		return nil, errors.New("OWNERSHIP_ARCHIVE_READ_SCOPE_INVALID")
	}
	get, err := a.Client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(a.Bucket), Key: aws.String(key), VersionId: aws.String(version)})
	if err != nil || get == nil || get.Body == nil {
		return nil, errors.New("OWNERSHIP_ARCHIVE_READBACK_FAILED")
	}
	defer get.Body.Close()
	if get.ContentLength != nil && *get.ContentLength > 64<<10 {
		return nil, errors.New("OWNERSHIP_ARCHIVE_READBACK_LIMIT")
	}
	raw, err := io.ReadAll(io.LimitReader(get.Body, (64<<10)+1))
	if err != nil || len(raw) == 0 || len(raw) > 64<<10 || aws.ToString(get.VersionId) != version || source.BytesHash(raw) != model.String(ref, "body_sha256") {
		return nil, errors.New("OWNERSHIP_ARCHIVE_READBACK_CHANGED")
	}
	return raw, nil
}
