package configuration

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// Key generation/decryption is a private credential boundary. Live capture has
// no local-key fallback. A commissioned KMS implementation must bind this exact
// encryption context and approved regional key; this package has no AWS discovery.
type ArtifactKeyProvider interface {
	Class() string
	Generate(context.Context, map[string]string) ([]byte, []byte, string, error)
	Decrypt(context.Context, string, []byte, map[string]string) ([]byte, error)
}
type ArtifactKMSClient interface {
	GenerateDataKey(context.Context, string, map[string]string) ([]byte, []byte, error)
	DecryptDataKey(context.Context, string, []byte, map[string]string) ([]byte, error)
}
type ArtifactKMSKeys struct {
	Client ArtifactKMSClient
	KeyARN string
}

func (*ArtifactKMSKeys) Class() string { return "AWS_KMS" }
func (k *ArtifactKMSKeys) valid() bool {
	return k != nil && k.Client != nil && regexp.MustCompile(`^arn:aws:kms:eu-west-1:[0-9]{12}:key/[a-f0-9-]{36}$`).MatchString(k.KeyARN)
}
func (k *ArtifactKMSKeys) Generate(ctx context.Context, c map[string]string) ([]byte, []byte, string, error) {
	if !k.valid() {
		return nil, nil, "", errors.New("CONFIGURATION_ARTIFACT_KMS_REQUIRED")
	}
	key, wrapped, e := k.Client.GenerateDataKey(ctx, k.KeyARN, c)
	if e != nil || len(key) != 32 || len(wrapped) == 0 {
		return nil, nil, "", errors.New("CONFIGURATION_ARTIFACT_KMS_UNAVAILABLE")
	}
	return key, wrapped, k.KeyARN, nil
}
func (k *ArtifactKMSKeys) Decrypt(ctx context.Context, id string, wrapped []byte, c map[string]string) ([]byte, error) {
	if !k.valid() || id != k.KeyARN {
		return nil, errors.New("CONFIGURATION_ARTIFACT_KMS_REQUIRED")
	}
	key, e := k.Client.DecryptDataKey(ctx, id, wrapped, c)
	if e != nil || len(key) != 32 {
		return nil, errors.New("CONFIGURATION_ARTIFACT_KMS_UNAVAILABLE")
	}
	return key, nil
}

type artifactFixtureKeys struct{ key []byte }

func NewArtifactFixtureKeys(key []byte) (ArtifactKeyProvider, error) {
	if len(key) != 32 {
		return nil, errors.New("CONFIGURATION_ARTIFACT_FIXTURE_KEY_INVALID")
	}
	return &artifactFixtureKeys{append([]byte{}, key...)}, nil
}
func (*artifactFixtureKeys) Class() string { return "LOCAL_FIXTURE" }
func artifactGCM(key []byte) (cipher.AEAD, error) {
	block, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	return cipher.NewGCM(block)
}
func (k *artifactFixtureKeys) Generate(_ context.Context, c map[string]string) ([]byte, []byte, string, error) {
	key := make([]byte, 32)
	if _, e := rand.Read(key); e != nil {
		return nil, nil, "", e
	}
	g, e := artifactGCM(k.key)
	if e != nil {
		return nil, nil, "", e
	}
	nonce := make([]byte, g.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return nil, nil, "", e
	}
	aad, _ := json.Marshal(c)
	wrapped := append(nonce, g.Seal(nil, nonce, key, aad)...)
	return key, wrapped, "fixture-only", nil
}
func (k *artifactFixtureKeys) Decrypt(_ context.Context, id string, wrapped []byte, c map[string]string) ([]byte, error) {
	g, e := artifactGCM(k.key)
	if e != nil || id != "fixture-only" || len(wrapped) <= g.NonceSize() {
		return nil, errors.New("CONFIGURATION_ARTIFACT_DECRYPT_FAILED")
	}
	aad, _ := json.Marshal(c)
	key, e := g.Open(nil, wrapped[:g.NonceSize()], wrapped[g.NonceSize():], aad)
	if e != nil || len(key) != 32 {
		return nil, errors.New("CONFIGURATION_ARTIFACT_DECRYPT_FAILED")
	}
	return key, nil
}

type artifactEnvelope struct {
	SchemaVersion, Algorithm, KeyClass, KeyID, PlainSHA256 string
	WrappedKey, Nonce, Ciphertext                          []byte
}

func artifactEncryptionContext(tenant, job, sha string) map[string]string {
	return map[string]string{"finops.tenant_id": tenant, "finops.artifact_job_id": job, "finops.artifact_kind": "terraform-sensitive-bundle", "finops.plain_sha256": sha}
}
func artifactSeal(ctx context.Context, keys ArtifactKeyProvider, fixture bool, tenant, job string, raw []byte) ([]byte, error) {
	if keys == nil || !fixture && keys.Class() != "AWS_KMS" || fixture && keys.Class() != "AWS_KMS" && keys.Class() != "LOCAL_FIXTURE" {
		return nil, errors.New("CONFIGURATION_ARTIFACT_KMS_REQUIRED")
	}
	sha := artifactBytesHash(raw)
	c := artifactEncryptionContext(tenant, job, sha)
	key, wrapped, id, e := keys.Generate(ctx, c)
	if e != nil {
		return nil, e
	}
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()
	if len(key) != 32 || len(wrapped) == 0 || len(wrapped) > 16384 {
		return nil, errors.New("CONFIGURATION_ARTIFACT_KEY_INVALID")
	}
	g, e := artifactGCM(key)
	if e != nil {
		return nil, e
	}
	nonce := make([]byte, g.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return nil, e
	}
	aad, _ := json.Marshal(c)
	return json.Marshal(artifactEnvelope{"1", "AES-256-GCM", keys.Class(), id, sha, wrapped, nonce, g.Seal(nil, nonce, raw, aad)})
}
func artifactOpen(ctx context.Context, keys ArtifactKeyProvider, fixture bool, tenant, job, sha string, raw []byte) ([]byte, error) {
	var envelope artifactEnvelope
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if keys == nil || dec.Decode(&envelope) != nil || dec.Decode(new(any)) != io.EOF || envelope.SchemaVersion != "1" || envelope.Algorithm != "AES-256-GCM" || envelope.KeyClass != keys.Class() || envelope.PlainSHA256 != sha || !fixture && envelope.KeyClass != "AWS_KMS" || len(envelope.WrappedKey) > 16384 {
		return nil, errors.New("CONFIGURATION_ARTIFACT_ENVELOPE_INVALID")
	}
	c := artifactEncryptionContext(tenant, job, sha)
	key, e := keys.Decrypt(ctx, envelope.KeyID, envelope.WrappedKey, c)
	if e != nil {
		return nil, e
	}
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()
	g, e := artifactGCM(key)
	if e != nil || len(envelope.Nonce) != g.NonceSize() {
		return nil, errors.New("CONFIGURATION_ARTIFACT_ENVELOPE_INVALID")
	}
	aad, _ := json.Marshal(c)
	plain, e := g.Open(nil, envelope.Nonce, envelope.Ciphertext, aad)
	if e != nil || len(plain) > ArtifactMaxBytes || artifactBytesHash(plain) != sha {
		return nil, errors.New("CONFIGURATION_ARTIFACT_DECRYPT_FAILED")
	}
	return plain, nil
}

type ArtifactS3 interface {
	PutObject(context.Context, *s3.PutObjectInput, ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error)
}

// Only encrypted envelopes are handed to this private archive by Pipeline.
// Bucket encryption/retention/IAM still need commissioning independently.
type S3ArtifactArchive struct {
	Client ArtifactS3
	Bucket string
}

func (a *S3ArtifactArchive) Put(ctx context.Context, tenant, job string, body []byte) (ArtifactArchiveRef, error) {
	if a == nil || a.Client == nil || !artifactID.MatchString(a.Bucket) || !artifactID.MatchString(tenant) || !artifactID.MatchString(job) || len(body) == 0 || len(body) > 2*ArtifactMaxBytes {
		return ArtifactArchiveRef{}, errors.New("CONFIGURATION_ARTIFACT_ARCHIVE_INVALID")
	}
	sha := artifactBytesHash(body)
	key := "tenant/" + tenant + "/configuration-artifacts/" + job + "/" + sha + ".encrypted"
	out, e := a.Client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(a.Bucket), Key: aws.String(key), Body: bytes.NewReader(body), ContentLength: aws.Int64(int64(len(body))), ContentType: aws.String("application/octet-stream")})
	if e != nil || out == nil {
		return ArtifactArchiveRef{}, errors.New("CONFIGURATION_ARTIFACT_ARCHIVE_WRITE_FAILED")
	}
	version := aws.ToString(out.VersionId)
	if version == "" || version == "null" {
		return ArtifactArchiveRef{}, errors.New("CONFIGURATION_ARTIFACT_ARCHIVE_VERSION_REQUIRED")
	}
	return ArtifactArchiveRef{a.Bucket, key, version, sha, int64(len(body))}, nil
}
func artifactRefValid(ref ArtifactArchiveRef, tenant, job string) bool {
	return artifactID.MatchString(ref.Bucket) && strings.HasPrefix(ref.Key, "tenant/"+tenant+"/configuration-artifacts/"+job+"/") && !strings.Contains(ref.Key, "..") && !strings.ContainsAny(ref.Key, "\\\x00\r\n") && artifactSHA.MatchString(ref.SHA256) && ref.VersionID != "" && ref.VersionID != "null" && len(ref.VersionID) <= 1024 && ref.Bytes > 0 && ref.Bytes <= 2*ArtifactMaxBytes
}
func (a *S3ArtifactArchive) Read(ctx context.Context, tenant string, ref ArtifactArchiveRef) ([]byte, error) {
	if a == nil || a.Client == nil || ref.Bucket != a.Bucket || !artifactID.MatchString(tenant) || !strings.HasPrefix(ref.Key, "tenant/"+tenant+"/configuration-artifacts/") || strings.Contains(ref.Key, "..") || strings.ContainsAny(ref.Key, "\\\x00\r\n") || !artifactSHA.MatchString(ref.SHA256) || ref.VersionID == "" || ref.VersionID == "null" || ref.Bytes < 1 || ref.Bytes > 2*ArtifactMaxBytes {
		return nil, errors.New("CONFIGURATION_ARTIFACT_ARCHIVE_REFERENCE_INVALID")
	}
	out, e := a.Client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(a.Bucket), Key: aws.String(ref.Key), VersionId: aws.String(ref.VersionID)})
	if e != nil || out == nil || out.Body == nil {
		return nil, errors.New("CONFIGURATION_ARTIFACT_ARCHIVE_READ_FAILED")
	}
	defer out.Body.Close()
	if aws.ToString(out.VersionId) != ref.VersionID || aws.ToInt64(out.ContentLength) != ref.Bytes {
		return nil, errors.New("CONFIGURATION_ARTIFACT_ARCHIVE_VERSION_CHANGED")
	}
	raw, e := io.ReadAll(io.LimitReader(out.Body, ref.Bytes+1))
	if e != nil || int64(len(raw)) != ref.Bytes || artifactBytesHash(raw) != ref.SHA256 {
		return nil, errors.New("CONFIGURATION_ARTIFACT_ARCHIVE_READBACK_CHANGED")
	}
	return raw, nil
}
