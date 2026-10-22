package commitmentportfolio

import (
	"testing"
	"time"
)

func TestDecisionControllerCurrentKeepsOriginalRefAndRequiresFreshCurrentProof(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	original := Ref{Kind: "AWS_CONTROLLER_DISCOVERY", ID: "controller-original", SHA256: Hash("original-issued-receipt")}
	current := decisionStageControllerCurrent{OriginalRef: original, LatestRef: Ref{Kind: original.Kind, ID: "controller-renewed", SHA256: Hash("renewed-issued-receipt")}, ObservedAt: now.Add(-time.Second), CheckedAt: now, SemanticSHA256: Hash("same-parsed-native-graph")}
	if validateDecisionStageControllerCurrent(&current, &original, now) != nil {
		t.Fatal("fresh independent currentness proof changed the sealed input ref")
	}
	tests := []struct {
		name   string
		change func(*decisionStageControllerCurrent)
	}{
		{"expired", func(v *decisionStageControllerCurrent) { v.ObservedAt = now.Add(-2*time.Minute - time.Nanosecond) }},
		{"future", func(v *decisionStageControllerCurrent) { v.ObservedAt = now.Add(6 * time.Second) }},
		{"unchecked", func(v *decisionStageControllerCurrent) { v.CheckedAt = time.Time{} }},
		{"stale-check", func(v *decisionStageControllerCurrent) { v.CheckedAt = now.Add(-6 * time.Second) }},
		{"ref-replaced", func(v *decisionStageControllerCurrent) { v.OriginalRef = v.LatestRef }},
		{"wrong-kind", func(v *decisionStageControllerCurrent) { v.LatestRef.Kind = "AWS_EC2_HARDWARE" }},
		{"missing-current-hash", func(v *decisionStageControllerCurrent) { v.LatestRef.SHA256 = "" }},
		{"unbound-semantics", func(v *decisionStageControllerCurrent) { v.SemanticSHA256 = "" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := current
			test.change(&value)
			if validateDecisionStageControllerCurrent(&value, &original, now) == nil {
				t.Fatal("invalid currentness proof admitted")
			}
		})
	}
	if validateDecisionStageControllerCurrent(nil, &original, now) == nil || validateDecisionStageControllerCurrent(&current, nil, now) == nil {
		t.Fatal("missing private proof admitted")
	}
}
