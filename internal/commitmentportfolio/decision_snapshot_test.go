package commitmentportfolio

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// This is a mapper/reconstruction unit test. Actual current-financial renewal,
// currentness races and original snapshot provenance require SQL acceptance.
func TestDecisionSnapshotReconstructsOriginalWithoutRefreshingIt(t *testing.T) {
	r := issuedFixture()
	issuedAt := r.Selection.Period.End
	original, err := Prepare(r, issuedAt)
	if err != nil {
		t.Fatal(err)
	}
	later := issuedAt.Add(20 * time.Minute)
	if _, err = Prepare(r, later); err == nil {
		t.Fatal("ordinary039 accepted its stale original native point")
	}
	r.DecisionSnapshotObservedAt = issuedAt
	reconstructed, err := PrepareDecisionSnapshot(r, later)
	if err != nil || Hash(reconstructed) != Hash(original) || !reconstructed.ObservedAt.Equal(issuedAt) {
		t.Fatal("decision reconstruction changed the issued input or relabeled its time", err)
	}
	if _, err = Prepare(r, later); err == nil {
		t.Fatal("private decision anchor changed ordinary039 validation")
	}
	// A clock anchor does not excuse wrong issuer, inventory or body hashes.
	r.Commitment["writer_role"] = "finops_api"
	if _, err = PrepareDecisionSnapshot(r, later); err == nil {
		t.Fatal("historical reconstruction accepted a different source writer")
	}
}

func TestDecisionFinancialSnapshotErrorsAreTypedCurrentnessOnly(t *testing.T) {
	for _, message := range []string{"decision original financial snapshot unavailable", "decision current native inventory unavailable", "decision financial source or billing changed", "decision native financial inventory changed", "decision original financial selection differs"} {
		if !errors.Is(decisionSourceError(&pgconn.PgError{Code: "P0001", Message: message}), ErrEvidence) {
			t.Fatal("known SQL financial currentness failure was not typed")
		}
		permission := &pgconn.PgError{Code: "42501", Message: message}
		if decisionSourceError(permission) != permission {
			t.Fatal("permission failure was incorrectly made a terminal currentness refusal")
		}
	}
	unknown := &pgconn.PgError{Code: "P0001", Message: "unclassified financial failure"}
	if decisionSourceError(unknown) != unknown {
		t.Fatal("unknown SQL failures were blanket classified as source drift")
	}
}

func TestDecisionSnapshotPrivateClockCannotEnterJSONAndDefaultsAreUnchanged(t *testing.T) {
	r := issuedFixture()
	issuedAt := r.Selection.Period.End
	before, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	base, err := PrepareDecisionSnapshot(r, issuedAt)
	if err != nil {
		t.Fatal(err)
	}
	direct, err := Prepare(r, issuedAt)
	if err != nil || Hash(base) != Hash(direct) {
		t.Fatal("unanchored039 mapping semantics changed", err)
	}
	r.DecisionSnapshotObservedAt = issuedAt
	after, err := json.Marshal(r)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("private anchor changed the resolved JSON or original v5 model wire", err)
	}
	var decoded Resolved
	if err = json.Unmarshal(after, &decoded); err != nil {
		t.Fatal(err)
	}
	if !decoded.DecisionSnapshotObservedAt.IsZero() {
		t.Fatal("resolved JSON supplied an immutable observation anchor")
	}
	decoded.RequestID = r.RequestID
	if _, err = PrepareDecisionSnapshot(decoded, issuedAt.Add(20*time.Minute)); err == nil {
		t.Fatal("serialized old evidence silently retained private renewal context")
	}
	r.DecisionSnapshotObservedAt = issuedAt.Add(time.Second)
	if _, err = PrepareDecisionSnapshot(r, issuedAt); err == nil {
		t.Fatal("a future issued snapshot observation was accepted")
	}
}
