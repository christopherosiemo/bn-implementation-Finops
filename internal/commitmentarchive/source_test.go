package commitmentarchive

import (
	"context"
	"errors"
	"testing"

	portfolio "github.com/christopherosiemo/bn-implementation-Finops/internal/commitmentportfolio"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
)

type archiveRegistryDouble struct{}

func (archiveRegistryDouble) ArchiveRegistration(context.Context, string) (portfolio.DecisionOwnershipArchiveRegistration, error) {
	return portfolio.DecisionOwnershipArchiveRegistration{}, errors.New("unit registry has no issued rows")
}
func (archiveRegistryDouble) ArchiveReviewRegistration(context.Context, string) (portfolio.DecisionOwnershipRegistration, error) {
	return portfolio.DecisionOwnershipRegistration{}, errors.New("unit registry has no issued rows")
}

type boundedArchiveDouble struct {
	*source.FixtureReader
	called *bool
}

func (r boundedArchiveDouble) BillingObjectBounded(_ context.Context, bucket, key, version string, max int64) (provider.BillingObject, error) {
	if bucket != "archive-bucket" || key != "tenant/unit/hour.json" || version != "original" || max != 64<<10 {
		return provider.BillingObject{}, errors.New("wrong bounded native selector")
	}
	*r.called = true
	return provider.BillingObject{Key: key, VersionID: version, Data: []byte("raw signed archive")}, nil
}

func TestDecisionArchiveIngestionAdapterRequiresBoundedTransportAndDurableRaw(t *testing.T) {
	ctx := context.Background()
	registry := archiveRegistryDouble{}
	persistCalls := 0
	persist := func(_ context.Context, _ portfolio.DecisionOwnershipArchiveRegistration, w portfolio.DecisionOwnershipArchiveWitness, raw []byte) (portfolio.Ref, error) {
		persistCalls++
		if string(raw) != "raw signed archive" {
			t.Fatal("raw source evidence was transformed")
		}
		return portfolio.Ref{Kind: "AWS_OWNERSHIP_ARCHIVE_OBJECT", ID: portfolio.Hash(w), SHA256: portfolio.Hash(w)}, nil
	}
	if _, e := NewOwnershipArchiveAWSReader("", registry, nil); e == nil {
		t.Fatal("unpersisted evidence collector constructed")
	}
	r, e := NewOwnershipArchiveAWSReader("", registry, persist)
	if e != nil {
		t.Fatal(e)
	}
	reg := portfolio.DecisionOwnershipArchiveRegistration{ID: "unit-source", Revision: 1, TenantID: "unit", AccountID: "111122223333", BucketOwner: "111122223333", Region: "eu-west-1", Bucket: "archive-bucket", ReadRoleBinding: portfolio.Ref{Kind: "APPROVED_READ_ROLE_BINDING", ID: "unit-read"}, IssuedDocumentSHA256: portfolio.Hash("issued-document")}
	called := false
	factories := 0
	r.factory = func(_ context.Context, in source.Registration) (source.Reader, error) {
		factories++
		if in.TenantID != reg.TenantID || in.PayerAccountID != reg.AccountID || in.ReadRoleBindingID != reg.ReadRoleBinding.ID || in.Region != "eu-west-1" {
			t.Fatal("archive source lost exact role binding")
		}
		return boundedArchiveDouble{FixtureReader: &source.FixtureReader{}, called: &called}, nil
	}
	pin := portfolio.DecisionOwnershipArchiveObjectPin{Key: "tenant/unit/hour.json", VersionID: "original", Bytes: int64(len("raw signed archive")), SHA256: source.BytesHash([]byte("raw signed archive"))}
	if _, e = r.ArchiveObject(ctx, reg, pin); e != nil || !called {
		t.Fatal("bounded transport unavailable", e)
	}
	if _, e = r.ArchiveObject(ctx, reg, pin); e != nil || factories != 1 {
		t.Fatal("renewable native client was recreated per object", e)
	}
	w := portfolio.DecisionOwnershipArchiveWitness{TenantID: reg.TenantID, SourceRegistrationSHA256: reg.IssuedDocumentSHA256, Pin: pin}
	if _, e = r.PersistArchiveWitness(ctx, reg, w, []byte("altered bytes")); e == nil || persistCalls != 0 {
		t.Fatal("altered source bytes reached trusted persistence")
	}
	if _, e = r.PersistArchiveWitness(ctx, reg, w, []byte("raw signed archive")); e != nil || persistCalls != 1 {
		t.Fatal("exact source bytes not persisted", e)
	}
	r.current = nil
	r.factory = func(context.Context, source.Registration) (source.Reader, error) { return &source.FixtureReader{}, nil }
	if _, e = r.ArchiveObject(ctx, reg, pin); e == nil {
		t.Fatal("unbounded transport silently accepted")
	}
	for _, change := range []func(*portfolio.DecisionOwnershipArchiveRegistration){func(v *portfolio.DecisionOwnershipArchiveRegistration) { v.Region = "us-east-1" }, func(v *portfolio.DecisionOwnershipArchiveRegistration) { v.BucketOwner = "999988887777" }, func(v *portfolio.DecisionOwnershipArchiveRegistration) { v.ReadRoleBinding.Kind = "CUSTOMER_IMPORT" }} {
		bad := reg
		change(&bad)
		if _, e = r.ArchiveObject(ctx, bad, pin); e == nil {
			t.Fatal("foreign archive binding accepted")
		}
	}
}
