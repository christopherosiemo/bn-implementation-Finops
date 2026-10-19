package commitmentarchive

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

// Explicit storage transport double. These tests enforce binding/readback;
// real versioned storage remains a separate connected acceptance gate.
type archiveStorageDouble struct {
	raw     []byte
	key     string
	version string
	altered bool
	reads   int
}

func (s *archiveStorageDouble) PutObject(_ context.Context, in *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	s.raw, _ = io.ReadAll(in.Body)
	s.key = aws.ToString(in.Key)
	return &s3.PutObjectOutput{VersionId: aws.String(s.version)}, nil
}
func (s *archiveStorageDouble) GetObject(_ context.Context, in *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	s.reads++
	raw := s.raw
	if s.altered {
		raw = []byte("altered")
	}
	return &s3.GetObjectOutput{VersionId: aws.String(s.version), Body: io.NopCloser(bytes.NewReader(raw)), ContentLength: aws.Int64(int64(len(raw)))}, nil
}
func TestDecisionArchiveStoragePinsVersionReadbackAndTenant(t *testing.T) {
	ctx := context.Background()
	client := &archiveStorageDouble{version: "original-version"}
	storage := &ImmutableArchive{Client: client, Bucket: "app-evidence"}
	raw := []byte("original signed historical bytes")
	ref, err := storage.Witness(ctx, "tenant-one", "source-one", raw)
	if err != nil || model.String(ref, "version_id") != "original-version" || client.reads != 1 {
		t.Fatal("exact version not read back", err)
	}
	back, err := storage.ReadWitness(ctx, "tenant-one", ref)
	if err != nil || !bytes.Equal(raw, back) {
		t.Fatal("immutable raw unavailable", err)
	}
	before := client.reads
	if _, err = storage.ReadWitness(ctx, "tenant-two", ref); err == nil || client.reads != before {
		t.Fatal("foreign tenant reached storage")
	}
	client.altered = true
	if _, err = storage.Witness(ctx, "tenant-one", "source-one", raw); err == nil {
		t.Fatal("altered readback accepted")
	}
	client.altered = false
	client.version = "null"
	before = client.reads
	if _, err = storage.Witness(ctx, "tenant-one", "source-one", raw); err == nil || client.reads != before {
		t.Fatal("unversioned write accepted")
	}
}
func TestDecisionArchiveTargetsAreSelectorsNotHistoricalAuthority(t *testing.T) {
	for _, wire := range []string{"", "[]"} {
		targets, err := Targets(wire)
		if err != nil || len(targets) != 0 {
			t.Fatal("empty disabled configuration failed")
		}
	}
	good := `[{"tenant_id":"tenant-one","source_id":"source-one","review":{"key":"existing-customer-history/review.json","version_id":"original","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","bytes":42}}]`
	if _, err := Targets(good); err != nil {
		t.Fatal("existing registered customer prefix refused", err)
	}
	for _, wire := range []string{`null`, good + " {}", `[{"tenant_id":"tenant-one","source_id":"source-one","complete":true}]`} {
		if _, err := Targets(wire); err == nil {
			t.Fatal("authoritative or malformed target accepted")
		}
	}
}
