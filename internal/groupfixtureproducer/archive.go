package groupfixtureproducer

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
	"github.com/christopherosiemo/bn-implementation-Finops/internal/configuration"
	ff "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetfixture"
	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

const maxArchivePlain = 16 << 20
const maxArchiveEnvelope = 24 << 20

var archiveID = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,255}$`)
var archiveSHA = regexp.MustCompile(`^[a-f0-9]{64}$`)
var ErrArchive = errors.New("GROUP_FIXTURE_ARCHIVE_INVALID")

// EncryptedArchive publishes ciphertext only and requires exact-version
// authenticated readback before returning an immutable plaintext reference.
// Storage IAM/retention and the private key provider remain commissioning gates.
type EncryptedArchive struct {
	Client configuration.ArtifactS3
	Bucket string
	Keys   configuration.ArtifactKeyProvider
}
type archiveBinding struct {
	TenantID            string `json:"tenant_id"`
	ProposalID          string `json:"proposal_id"`
	ProfileID           string `json:"profile_id"`
	Generation          string `json:"generation"`
	RealmSHA256         string `json:"realm_sha256"`
	ProducerImageSHA256 string `json:"producer_image_sha256"`
	ID                  string `json:"id"`
	Kind                string `json:"kind"`
	PlainSHA256         string `json:"plain_sha256"`
	PlainSize           int64  `json:"plain_size"`
}
type archiveEnvelope struct {
	SchemaVersion string         `json:"schema_version"`
	Algorithm     string         `json:"algorithm"`
	Binding       archiveBinding `json:"binding"`
	KeyClass      string         `json:"key_class"`
	KeyID         string         `json:"key_id"`
	WrappedKey    []byte         `json:"wrapped_key"`
	Nonce         []byte         `json:"nonce"`
	Ciphertext    []byte         `json:"ciphertext"`
}

func archiveKind(kind string) bool {
	switch kind {
	case "NATIVE_OPERATION_PROOF", "NATIVE_ARTIFACT_REVIEW", "NATIVE_CAPTURE", "FIXTURE_CURRENT":
		return true
	case "FIXTURE_HISTORY", "FIXTURE_DEMAND", "FIXTURE_CAPACITY", "FIXTURE_CONFIGURATION", "FIXTURE_DEPENDENCY", "FIXTURE_SLO", "FIXTURE_ECONOMICS", "GIT_PROOF_SET", "BASE_NATIVE_STATE", "SAVED_PLAN", "PLAN_JSON", "BEFORE_NATIVE_STATE", "AFTER_NATIVE_STATE", "HEALTH_RECEIPT", "HEALTH_BASELINE", "HEALTH_VERDICT":
		return true
	}
	return false
}
func bindingFor(p ff.Proposal, id, kind, hash string, size int64) (archiveBinding, error) {
	tenant := p.Binding.Old.Target.TenantID
	if !archiveID.MatchString(tenant) || !archiveID.MatchString(p.ID) || !archiveID.MatchString(p.Profile.ID) || !archiveID.MatchString(p.Profile.Generation) || !archiveID.MatchString(id) || !archiveKind(kind) || size < 1 || size > maxArchivePlain || !archiveSHA.MatchString(hash) || p.Profile.Generation != p.Realm.Generation || p.Profile.ID != p.Realm.FixtureID || p.Profile.ModelSHA256 != p.Realm.ModelSHA256 || g.ValidateRealm(p.Realm) != nil || g.ValidateBinding(p.Binding) != nil || !archiveSHA.MatchString(p.Profile.Installation.ToolchainImageSHA256) {
		return archiveBinding{}, ErrArchive
	}
	return archiveBinding{TenantID: tenant, ProposalID: p.ID, ProfileID: p.Profile.ID, Generation: p.Profile.Generation, RealmSHA256: g.Digest(p.Realm), ProducerImageSHA256: p.Profile.Installation.ToolchainImageSHA256, ID: id, Kind: kind, PlainSHA256: hash, PlainSize: size}, nil
}
func archiveContext(b archiveBinding) map[string]string {
	return map[string]string{"finops.purpose": "isolated-group-artifact-v1", "finops.tenant_id": b.TenantID, "finops.proposal_id": b.ProposalID, "finops.generation": b.Generation, "finops.binding_sha256": g.Digest(b)}
}
func archiveAAD(b archiveBinding) []byte {
	raw, _ := json.Marshal(b)
	return append([]byte("finops/group-fixture/artifact/v1\x00"), raw...)
}
func archiveObjectKey(b archiveBinding) string {
	return "tenant/" + b.TenantID + "/fleet-group-fixture/" + b.ProposalID + "/" + b.Generation + "/" + b.ID + ".encrypted"
}
func archiveAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, ErrArchive
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrArchive
	}
	return cipher.NewGCM(block)
}
func wipe(key []byte) {
	for i := range key {
		key[i] = 0
	}
}
func (a *EncryptedArchive) valid() bool {
	return a != nil && a.Client != nil && archiveID.MatchString(a.Bucket) && a.Keys != nil && (a.Keys.Class() == "LOCAL_FIXTURE" || a.Keys.Class() == "AWS_KMS")
}

func (a *EncryptedArchive) Put(ctx context.Context, p ff.Proposal, kind string, raw []byte) (ff.ArtifactReference, error) {
	if !a.valid() {
		return ff.ArtifactReference{}, ErrArchive
	}
	b, err := bindingFor(p, model.ID(), kind, g.BytesDigest(raw), int64(len(raw)))
	if err != nil {
		return ff.ArtifactReference{}, err
	}
	key, wrapped, keyID, err := a.Keys.Generate(ctx, archiveContext(b))
	defer wipe(key)
	if err != nil {
		return ff.ArtifactReference{}, ErrArchive
	}
	gcm, err := archiveAEAD(key)
	if err != nil || len(wrapped) == 0 || len(wrapped) > 16<<10 || keyID == "" {
		return ff.ArtifactReference{}, ErrArchive
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return ff.ArtifactReference{}, ErrArchive
	}
	envelope := archiveEnvelope{SchemaVersion: "1", Algorithm: "AES-256-GCM", Binding: b, KeyClass: a.Keys.Class(), KeyID: keyID, WrappedKey: wrapped, Nonce: nonce, Ciphertext: gcm.Seal(nil, nonce, raw, archiveAAD(b))}
	body, err := json.Marshal(envelope)
	if err != nil || len(body) > maxArchiveEnvelope {
		return ff.ArtifactReference{}, ErrArchive
	}
	objectKey := archiveObjectKey(b)
	put, err := a.Client.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(a.Bucket), Key: aws.String(objectKey), Body: bytes.NewReader(body), ContentLength: aws.Int64(int64(len(body))), ContentType: aws.String("application/octet-stream"), IfNoneMatch: aws.String("*")})
	if err != nil || put == nil || aws.ToString(put.VersionId) == "" || aws.ToString(put.VersionId) == "null" {
		return ff.ArtifactReference{}, ErrArchive
	}
	ref := ff.ArtifactReference{ID: b.ID, Bucket: a.Bucket, Key: objectKey, VersionID: aws.ToString(put.VersionId), SHA256: b.PlainSHA256, SizeBytes: b.PlainSize}
	observed, err := a.Read(ctx, p, kind, ref)
	if err != nil || !bytes.Equal(raw, observed) {
		return ff.ArtifactReference{}, ErrArchive
	}
	return ref, nil
}

func (a *EncryptedArchive) Read(ctx context.Context, p ff.Proposal, kind string, ref ff.ArtifactReference) ([]byte, error) {
	if !a.valid() || ref.Bucket != a.Bucket || ref.VersionID == "" || ref.VersionID == "null" || len(ref.VersionID) > 1024 || strings.ContainsAny(ref.VersionID, "\x00\r\n") {
		return nil, ErrArchive
	}
	b, err := bindingFor(p, ref.ID, kind, ref.SHA256, ref.SizeBytes)
	if err != nil || ref.Key != archiveObjectKey(b) {
		return nil, ErrArchive
	}
	out, err := a.Client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(a.Bucket), Key: aws.String(ref.Key), VersionId: aws.String(ref.VersionID)})
	if err != nil || out == nil || out.Body == nil {
		return nil, ErrArchive
	}
	defer out.Body.Close()
	size := aws.ToInt64(out.ContentLength)
	if aws.ToString(out.VersionId) != ref.VersionID || size < 1 || size > maxArchiveEnvelope {
		return nil, ErrArchive
	}
	raw, err := io.ReadAll(io.LimitReader(out.Body, size+1))
	if err != nil || int64(len(raw)) != size {
		return nil, ErrArchive
	}
	var envelope archiveEnvelope
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&envelope) != nil || decoder.Decode(new(any)) != io.EOF {
		return nil, ErrArchive
	}
	canonical, _ := json.Marshal(envelope)
	if !bytes.Equal(canonical, raw) || envelope.SchemaVersion != "1" || envelope.Algorithm != "AES-256-GCM" || envelope.Binding != b || envelope.KeyClass != a.Keys.Class() || len(envelope.WrappedKey) == 0 || len(envelope.WrappedKey) > 16<<10 || len(envelope.Ciphertext) != int(b.PlainSize)+16 {
		return nil, ErrArchive
	}
	key, err := a.Keys.Decrypt(ctx, envelope.KeyID, envelope.WrappedKey, archiveContext(b))
	defer wipe(key)
	if err != nil {
		return nil, ErrArchive
	}
	gcm, err := archiveAEAD(key)
	if err != nil || len(envelope.Nonce) != gcm.NonceSize() {
		return nil, ErrArchive
	}
	plain, err := gcm.Open(nil, envelope.Nonce, envelope.Ciphertext, archiveAAD(b))
	if err != nil || int64(len(plain)) != b.PlainSize || g.BytesDigest(plain) != b.PlainSHA256 {
		return nil, ErrArchive
	}
	return plain, nil
}
