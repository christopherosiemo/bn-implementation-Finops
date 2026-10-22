package fleetgroup

import (
	"crypto/ed25519"
	"time"
)

// Called only after immutable parent/approvals/manifest are authenticated once
// by validateJournalAuthorization. Time and child signatures/evidence remain
// per-event checks. This does not adapt or change the frozen5.1 contract.
func journalForwardLifetime(p GitProgram, at time.Time) error {
	if !canonicalTime(at) || p.CreatedAt.After(at.Add(5*time.Second)) || !p.ExpiresAt.After(at) || !GitForwardDeadline(p).After(at) {
		return invalid("GROUP_GIT_PROGRAM_LIFETIME_INVALID")
	}
	return nil
}
func verifyJournalForwardCached(e GitChildEnvelope, parent GitEnvelope, key ed25519.PublicKey, at time.Time) error {
	p, c := parent.Program, e.Child
	if err := journalForwardLifetime(p, at); err != nil {
		return err
	}
	if e.Algorithm != gitChildAlgorithm || !journalVerify(gitChildDomain, c, e.Signature, key) {
		return invalid("GROUP_GIT_CHILD_SIGNATURE_INVALID")
	}
	if err := gitChildBinding(c, p, at); err != nil {
		return err
	}
	if c.Mode != Forward || c.CompensationFor != "" || c.OwnedReceiptSHA256 != "" || c.OwnershipSHA256 != "" || c.ExpiresAt.After(GitForwardDeadline(p)) || c.Sequence > uint64(len(p.Manifest.Entries)) {
		return invalid("GROUP_GIT_FORWARD_INVALID")
	}
	entry := p.Manifest.Entries[c.Sequence-1]
	previous := p.Manifest.Base
	if c.Sequence > 1 {
		previous = p.Manifest.Entries[c.Sequence-2].Revision
	}
	if c.StageID != entry.StageID || c.StageSHA256 != entry.StageSHA256 || c.Artifact.ManifestEntrySHA256 != Digest(entry) || c.Artifact.PreviousRevision != previous || c.Artifact.Revision != entry.Revision || c.Artifact.Before != entry.Before || c.Artifact.After != entry.After || c.MinimumObservationSeconds != entry.MinimumObservationSeconds || at.Add(time.Duration(c.MinimumObservationSeconds)*time.Second).After(GitForwardDeadline(p)) {
		return invalid("GROUP_GIT_STAGE_CONTEXT_INVALID")
	}
	return evidence(c.Evidence, childEvidence, p.Binding, p.Realm, at, c.ExpiresAt, true)
}
