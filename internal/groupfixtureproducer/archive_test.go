package groupfixtureproducer

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/configuration"
	ff "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetfixture"
	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
)

type objectDouble struct {
	objects                      map[string][]byte
	gets                         int
	missingVersion, wrongVersion bool
	mutate                       func([]byte) []byte
}

func (s *objectDouble) PutObject(_ context.Context, in *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	if aws.ToString(in.IfNoneMatch) != "*" {
		return nil, errors.New("create-new delivery required")
	}
	key := aws.ToString(in.Key)
	if _, exists := s.objects[key]; exists {
		return nil, errors.New("object exists")
	}
	raw, err := io.ReadAll(in.Body)
	if err != nil {
		return nil, err
	}
	s.objects[key] = raw
	version := "version-one"
	if s.missingVersion {
		version = "null"
	}
	return &s3.PutObjectOutput{VersionId: aws.String(version)}, nil
}
func (s *objectDouble) GetObject(_ context.Context, in *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	s.gets++
	raw, exists := s.objects[aws.ToString(in.Key)]
	if !exists || aws.ToString(in.VersionId) != "version-one" {
		return nil, errors.New("unknown object version")
	}
	raw = append([]byte{}, raw...)
	if s.mutate != nil {
		raw = s.mutate(raw)
	}
	version := "version-one"
	if s.wrongVersion {
		version = "another-version"
	}
	return &s3.GetObjectOutput{Body: io.NopCloser(bytes.NewReader(raw)), ContentLength: aws.Int64(int64(len(raw))), VersionId: aws.String(version)}, nil
}
func archiveSelection() ff.Proposal {
	hash := g.BytesDigest([]byte("explicit unit model"))
	side := func(name, uuid string) g.Selection {
		return g.Selection{Target: g.GroupTarget{TenantID: "tenant-archive", WorkloadID: "workload-archive", Provider: "AWS", AccountID: "111122223333", Region: "eu-west-1", FleetID: "fleet-" + name, ASGARN: "arn:aws:autoscaling:eu-west-1:111122223333:autoScalingGroup:" + uuid + ":autoScalingGroupName/" + name}, Registration: g.VersionedRef{ID: "registration-" + name, Version: 1, SHA256: hash}, Declaration: g.VersionedRef{ID: "declaration-" + name, Version: 1, SHA256: hash}, Scope: g.SnapshotRef{ID: "scope-" + name, SHA256: hash}, SourceID: "source-archive", SourceRegistrationVersion: 1, SourceConfigSHA256: hash}
	}
	p := ff.Proposal{ID: "proposal-archive", Binding: g.Binding{Old: side("old", "11111111-1111-1111-1111-111111111111"), Candidate: side("candidate", "22222222-2222-2222-2222-222222222222")}, Realm: g.Realm{Kind: g.IsolatedFixture, FixtureID: "archive-profile", Generation: "11111111-2222-3333-4444-555555555555", ModelSHA256: hash}}
	p.Profile = ff.Profile{ID: p.Realm.FixtureID, Generation: p.Realm.Generation, ModelSHA256: hash, Installation: ff.Installation{ToolchainImageSHA256: hash}}
	return p
}
func newArchiveTest(t *testing.T) (*EncryptedArchive, *objectDouble) {
	t.Helper()
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatal(err)
	}
	keys, err := configuration.NewArtifactFixtureKeys(master)
	if err != nil {
		t.Fatal(err)
	}
	store := &objectDouble{objects: map[string][]byte{}}
	return &EncryptedArchive{Client: store, Bucket: "fixture-artifacts", Keys: keys}, store
}

func TestEncryptedGroupArchiveAuthenticatesVersionsAndScope(t *testing.T) {
	a, store := newArchiveTest(t)
	p := archiveSelection()
	ctx := context.Background()
	plain := []byte(strings.Repeat("sensitive-native-state-proof-", 30))
	ref, err := a.Put(ctx, p, "BASE_NATIVE_STATE", plain)
	if err != nil {
		t.Fatal(err)
	}
	if store.gets != 1 || ref.SHA256 != g.BytesDigest(plain) || ref.SizeBytes != int64(len(plain)) {
		t.Fatal("trusted receipt preceded authenticated readback")
	}
	if bytes.Contains(store.objects[ref.Key], plain) {
		t.Fatal("object store received raw native evidence")
	}
	observed, err := a.Read(ctx, p, "BASE_NATIVE_STATE", ref)
	if err != nil || !bytes.Equal(observed, plain) {
		t.Fatal("valid encrypted evidence unavailable", err)
	}
	for _, change := range []func(*ff.Proposal){
		func(p *ff.Proposal) {
			p.Binding.Old.Target.TenantID = "other-tenant"
			p.Binding.Candidate.Target.TenantID = "other-tenant"
		},
		func(p *ff.Proposal) { p.ID = "other-proposal" },
		func(p *ff.Proposal) {
			p.Profile.Generation = "55555555-4444-3333-2222-111111111111"
			p.Realm.Generation = p.Profile.Generation
		},
		func(p *ff.Proposal) {
			p.Profile.Installation.ToolchainImageSHA256 = g.BytesDigest([]byte("other producer"))
		},
	} {
		other := p
		change(&other)
		if _, err = a.Read(ctx, other, "BASE_NATIVE_STATE", ref); err == nil {
			t.Fatal("cross-scope object accepted")
		}
	}
	if _, err = a.Read(ctx, p, "GIT_PROOF_SET", ref); err == nil {
		t.Fatal("artifact kind confusion accepted")
	}
	badRef := ref
	badRef.Key = "tenant/other/fleet-group-fixture/borrow.encrypted"
	calls := store.gets
	if _, err = a.Read(ctx, p, "BASE_NATIVE_STATE", badRef); err == nil || store.gets != calls {
		t.Fatal("foreign object was fetched")
	}
	store.wrongVersion = true
	if _, err = a.Read(ctx, p, "BASE_NATIVE_STATE", ref); err == nil {
		t.Fatal("changed native object version accepted")
	}
}

func TestEncryptedGroupArchiveRejectsChangedCiphertextAndUnversionedDelivery(t *testing.T) {
	ctx := context.Background()
	p := archiveSelection()
	t.Run("unversioned", func(t *testing.T) {
		a, s := newArchiveTest(t)
		s.missingVersion = true
		if _, err := a.Put(ctx, p, "GIT_PROOF_SET", []byte("private proof")); err == nil {
			t.Fatal("unversioned write issued a trusted receipt")
		}
	})
	for _, kind := range []string{"ciphertext", "binding", "wrapped-key", "trailing"} {
		t.Run(kind, func(t *testing.T) {
			a, s := newArchiveTest(t)
			ref, err := a.Put(ctx, p, "GIT_PROOF_SET", []byte("private immutable proof"))
			if err != nil {
				t.Fatal(err)
			}
			s.mutate = func(raw []byte) []byte {
				var e archiveEnvelope
				if json.Unmarshal(raw, &e) != nil {
					t.Fatal("test envelope unavailable")
				}
				switch kind {
				case "ciphertext":
					e.Ciphertext[0] ^= 1
				case "binding":
					e.Binding.RealmSHA256 = g.BytesDigest([]byte("other realm"))
				case "wrapped-key":
					e.WrappedKey[len(e.WrappedKey)-1] ^= 1
				case "trailing":
					return append(raw, '\n')
				}
				body, _ := json.Marshal(e)
				return body
			}
			if _, err = a.Read(ctx, p, "GIT_PROOF_SET", ref); err == nil {
				t.Fatal("changed encrypted evidence accepted", kind)
			}
		})
	}
}
