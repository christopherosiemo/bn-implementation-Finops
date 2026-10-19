package source

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

type SavingsPlanQuoteArchive struct {
	Client FleetS3Client
	Bucket string
}

func (a *SavingsPlanQuoteArchive) Archive(ctx context.Context, tenant, source string, raw []byte) (model.Document, error) {
	if a == nil || a.Client == nil || !bucketPattern.MatchString(a.Bucket) || !fleetObjectPart.MatchString(tenant) || !fleetObjectPart.MatchString(source) || len(raw) == 0 || len(raw) > 16<<20 {
		return nil, errors.New("SAVINGS_PLAN_QUOTE_ARCHIVE_SCOPE_INVALID")
	}
	digest := BytesHash(raw)
	key := "tenant/" + tenant + "/commitment-quotes/" + source + "/" + digest + ".json"
	sum := sha256.Sum256(raw)
	put, err := a.Client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(a.Bucket), Key: aws.String(key), Body: bytes.NewReader(raw), ContentType: aws.String("application/json"), ChecksumSHA256: aws.String(base64.StdEncoding.EncodeToString(sum[:]))})
	if err != nil || put == nil {
		return nil, errors.New("SAVINGS_PLAN_QUOTE_ARCHIVE_FAILED")
	}
	version := aws.ToString(put.VersionId)
	if version == "" || version == "null" {
		return nil, errors.New("SAVINGS_PLAN_QUOTE_VERSION_REQUIRED")
	}
	get, err := a.Client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(a.Bucket), Key: aws.String(key), VersionId: aws.String(version)})
	if err != nil || get == nil || get.Body == nil {
		return nil, errors.New("SAVINGS_PLAN_QUOTE_READBACK_FAILED")
	}
	defer get.Body.Close()
	body, err := io.ReadAll(io.LimitReader(get.Body, (16<<20)+1))
	if err != nil || len(body) > 16<<20 || len(body) != len(raw) || aws.ToString(get.VersionId) != version || BytesHash(body) != digest {
		return nil, errors.New("SAVINGS_PLAN_QUOTE_READBACK_MISMATCH")
	}
	return model.Document{"bucket": a.Bucket, "key": key, "version_id": version, "body_sha256": digest}, nil
}
