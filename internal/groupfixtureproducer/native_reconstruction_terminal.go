package groupfixtureproducer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"time"

	ff "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetfixture"
	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

// ValidateNativeTerminal checks signatures and exact issued bindings only.
// The repository independently resolves this snapshot; native truth and
// authenticated archive readback remain producer boundaries, not permissions.
func ValidateNativeTerminal(s NativeReconstructionSnapshot, e NativeTerminalEnvelope, now time.Time) error {
	if s.Mode != ReconstructionObservation && s.Mode != ReconstructionTerminal {
		return ErrReconstruction
	}
	p, err := reconstructionSnapshot(s, now)
	if err != nil {
		return err
	}
	if _, err = nativeTerminalFacts(s, e, p, now); err != nil {
		return err
	}
	if s.Mode == ReconstructionObservation {
		if e.Terminal.Workspace != s.Workspace {
			return ErrReconstruction
		}
		return nil
	}
	return verifyNativeRetirement(*s.Retirement, s.RetirementKey, s, e.Terminal, now)
}

// VerifyNativeWorkspaceRetirement validates an independently issued removal
// observation against server-resolved key/generation inputs. It performs no
// runtime inspection; the commissioning controller owns that evidence boundary.
func VerifyNativeWorkspaceRetirement(e NativeRetirementEnvelope, key ed25519.PublicKey, s NativeReconstructionSnapshot, terminal NativeTerminal, now time.Time) error {
	return verifyNativeRetirement(e, key, s, terminal, now)
}

func nativeIssuedCommand(v g.JournalView, id string) (g.JournalCommand, bool) {
	var c g.JournalCommand
	found := false
	for _, r := range v.Records {
		if r.Kind == g.JournalReserved && r.Command != nil && r.Command.ID == id {
			c = *r.Command
			found = true
		}
	}
	return c, found
}

func nativeTerminalFacts(s NativeReconstructionSnapshot, e NativeTerminalEnvelope, p g.JournalProjection, now time.Time) (g.JournalCommand, error) {
	t := e.Terminal
	c, found := nativeIssuedCommand(s.View, s.CommandID)
	artifact, finalized := reconstructionArtifact(c)
	if !found || !finalized || e.Algorithm != nativeReconstructionAlgorithm || t.SchemaVersion != "1" || !archiveID.MatchString(t.ID) || t.TenantID != s.Selected.Binding.Old.Target.TenantID || t.ChainID != s.ChainID || t.ProgramSHA256 != g.Digest(s.View.Parent.Program) || t.AuthorizationSHA256 != g.Digest(s.View.Authorization) || t.CommandSHA256 != g.Digest(c) || t.OperationID != c.OperationID || t.Fence != c.Fence || t.ArtifactSHA256 != g.Digest(artifact) || t.PreparationSHA256 != g.Digest(c.Preparation) || t.References != s.References || !nativeWorkspaceValid(t.Workspace) || t.Workspace.ImageSHA256 != s.Workspace.ImageSHA256 || t.Before != c.Before || t.After.Model != artifact.After || t.After.Revision != artifact.Revision || t.After.StateLineage != c.Before.StateLineage || !archiveSHA.MatchString(t.After.StateSHA256) || t.ObservedAt.IsZero() || t.ObservedAt.Before(c.CreatedAt) || t.ObservedAt.After(now.Add(5*time.Second)) {
		return c, ErrReconstruction
	}
	if artifact.Before == artifact.After {
		if t.After.StateSerial != c.Before.StateSerial || t.After.StateSHA256 != c.Before.StateSHA256 {
			return c, ErrReconstruction
		}
	} else if t.After.StateSerial <= c.Before.StateSerial {
		return c, ErrReconstruction
	}
	for _, r := range []struct {
		kind string
		ref  ff.ArtifactReference
	}{{"NATIVE_ARTIFACT_REVIEW", t.References.Review}, {"NATIVE_CAPTURE", t.References.Capture}, {"AFTER_NATIVE_STATE", t.References.After}} {
		if !reconstructionRef(s.Selected, r.kind, r.ref) {
			return c, ErrReconstruction
		}
	}
	if t.References.Review.ID != artifact.Receipt.ID || t.References.Review.SHA256 != artifact.Receipt.SHA256 || t.References.After.SHA256 != t.After.StateSHA256 {
		return c, ErrReconstruction
	}
	sig, err := base64.StdEncoding.DecodeString(e.Signature)
	if err != nil || len(s.Keys.Pipeline) != ed25519.PublicKeySize || !ed25519.Verify(s.Keys.Pipeline, reconstructionMessage(nativeTerminalDomain, t), sig) {
		return c, ErrReconstruction
	}
	// The retained old head is verified against the exact immutable prefix at
	// its original observation time. A new current head cannot rewrite it.
	count := t.Head.Head.Ref.RecordCount
	if count < 0 || count > len(s.View.Records) {
		return c, ErrReconstruction
	}
	v := s.View
	v.Records = v.Records[:count]
	v.Head = t.Head
	historical, err := g.VerifyJournal(v, s.Keys, t.Head.Head.Ref, t.ObservedAt)
	if err != nil || historical.Pending == nil || g.Digest(historical.Pending.Command) != g.Digest(c) || !historical.Pending.ApplyIntent || historical.Pending.NoApply != nil || historical.Pending.GitRepair != nil {
		return c, ErrReconstruction
	}
	if p.Pending != nil {
		if g.Digest(p.Pending.Command) != g.Digest(c) || !p.Pending.ApplyIntent || p.Pending.NoApply != nil || p.Pending.GitRepair != nil {
			return c, ErrUncertain
		}
	} else {
		if p.Current != t.After {
			return c, ErrUncertain
		}
		var last *g.JournalReceiptEnvelope
		for _, r := range s.View.Records {
			if r.Kind == g.JournalApplied && r.Receipt != nil {
				last = r.Receipt
			}
		}
		if last == nil || last.Receipt.CommandID != c.ID || last.Receipt.ArtifactSHA256 != g.Digest(artifact) || last.Receipt.After != t.After {
			return c, ErrUncertain
		}
	}
	return c, nil
}

type nativeReviewStatement struct {
	SchemaVersion        string           `json:"schema_version"`
	CommandID            string           `json:"command_id"`
	PreparationSHA256    string           `json:"preparation_sha256"`
	CaptureSHA256        string           `json:"capture_sha256"`
	Review               g.ArtifactReview `json:"review"`
	OmittedSelfReference bool             `json:"self_referential_envelope_digests_omitted"`
}

func readReconstructionObject(ctx context.Context, a ReadableArchive, s NativeReconstructionSnapshot, kind string, ref ff.ArtifactReference) ([]byte, error) {
	if a == nil || !reconstructionRef(s.Selected, kind, ref) {
		return nil, ErrReconstruction
	}
	raw, e := a.Read(ctx, s.Selected, kind, ref)
	if e != nil || int64(len(raw)) != ref.SizeBytes || g.BytesDigest(raw) != ref.SHA256 {
		return nil, ErrArchive
	}
	return raw, nil
}

func readReconstructionCapture(ctx context.Context, a ReadableArchive, s NativeReconstructionSnapshot, c g.JournalCommand, refs NativeReconstructionRefs) (g.GitTerraformArtifactCapture, error) {
	var capture g.GitTerraformArtifactCapture
	artifact, ok := reconstructionArtifact(c)
	if !ok || refs.Review.ID != artifact.Receipt.ID || refs.Review.SHA256 != artifact.Receipt.SHA256 {
		return capture, ErrReconstruction
	}
	raw, e := readReconstructionObject(ctx, a, s, "NATIVE_ARTIFACT_REVIEW", refs.Review)
	if e != nil {
		return capture, e
	}
	var statement nativeReviewStatement
	if decodeReconstruction(raw, &statement) != nil || statement.SchemaVersion != "1" || statement.CommandID != c.ID || statement.PreparationSHA256 != g.Digest(c.Preparation) || statement.CaptureSHA256 != refs.Capture.SHA256 || !statement.OmittedSelfReference {
		return capture, ErrReconstruction
	}
	raw, e = readReconstructionObject(ctx, a, s, "NATIVE_CAPTURE", refs.Capture)
	if e != nil {
		return capture, e
	}
	if decodeReconstruction(raw, &capture) != nil || g.Digest(capture) != statement.CaptureSHA256 {
		return capture, ErrReconstruction
	}
	var review g.ArtifactReview
	if c.Forward != nil {
		review, e = g.ValidateGitTerraformArtifact(s.View.Parent.Program, c.Forward.Child, capture, c.Forward.Child.CreatedAt)
	} else {
		v := s.View
		v.Head = c.Recovery.Head
		count := v.Head.Head.Ref.RecordCount
		if count < 0 || count > len(v.Records) {
			return capture, ErrReconstruction
		}
		v.Records = v.Records[:count]
		review, e = g.ValidateJournalTerraformArtifact(v, s.Keys, v.Head.Head.Ref, c.Recovery.Recovery, capture, c.Recovery.Recovery.CreatedAt)
	}
	if e != nil {
		return capture, e
	}
	review.ChildSHA256 = ""
	review.ArtifactSHA256 = ""
	if g.Digest(review) != g.Digest(statement.Review) {
		return capture, ErrReconstruction
	}
	return capture, nil
}

// ObserveNativeTerminal runs under the real repository/current-workspace fence
// while the original workspace still exists. It reads an existing fsynced
// positive Outcome; it never executes Terraform or infers success from absence.
// Its signed envelope must be archived and selected immutably before PG APPLIED.
func (n *NativeStage) ObserveNativeTerminal(ctx context.Context, authority NativeReconstructionAuthority, chain string, key ed25519.PrivateKey) (envelope NativeTerminalEnvelope, err error) {
	if n == nil || authority == nil || len(key) != ed25519.PrivateKeySize {
		return envelope, ErrReconstruction
	}
	calls := 0
	err = authority.WithCurrentNativeFence(ctx, chain, func(s NativeReconstructionSnapshot) error {
		calls++
		if calls != 1 || s.ChainID != chain || s.Mode != ReconstructionObservation || !bytes.Equal(key.Public().(ed25519.PublicKey), s.Keys.Pipeline) || g.Digest(n.prepared.Program) != g.Digest(s.Prepared.Program) || n.selected.ID != s.Selected.ID {
			return ErrReconstruction
		}
		p, e := reconstructionSnapshot(s, time.Now().UTC())
		if e != nil {
			return e
		}
		c := p.Pending.Command
		if _, e = readReconstructionCapture(ctx, n.archive, s, c, s.References); e != nil {
			return e
		}
		out, e := n.Outcome(ctx, c)
		if e != nil {
			return e
		}
		if out.Artifact != s.References.After {
			return ErrReconstruction
		}
		now := time.Now().UTC()
		envelope = NativeTerminalEnvelope{Terminal: NativeTerminal{SchemaVersion: "1", ID: model.ID(), TenantID: s.Selected.Binding.Old.Target.TenantID, ChainID: chain, ProgramSHA256: g.Digest(s.View.Parent.Program), AuthorizationSHA256: g.Digest(s.View.Authorization), CommandSHA256: g.Digest(c), OperationID: c.OperationID, Fence: c.Fence, ArtifactSHA256: g.Digest(func() g.GitArtifact { a, _ := reconstructionArtifact(c); return a }()), PreparationSHA256: g.Digest(c.Preparation), Workspace: s.Workspace, References: s.References, Before: out.Before, After: out.After, Head: s.View.Head, ObservedAt: now}, Algorithm: nativeReconstructionAlgorithm}
		envelope.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, reconstructionMessage(nativeTerminalDomain, envelope.Terminal)))
		if _, e = nativeTerminalFacts(s, envelope, p, now); e != nil {
			return e
		}
		return nil
	})
	if err == nil && calls != 1 {
		err = ErrReconstruction
	}
	return envelope, err
}

func decodeNativeTerminal(raw []byte) (NativeTerminalEnvelope, error) {
	var out NativeTerminalEnvelope
	if e := decodeReconstruction(raw, &out); e != nil {
		return out, e
	}
	canonical, _ := json.Marshal(out)
	if !bytes.Equal(canonical, raw) {
		return out, ErrReconstruction
	}
	return out, nil
}
