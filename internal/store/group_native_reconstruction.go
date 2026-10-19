package store

// Private reconstruction metadata binds independently commissioned runtimes to
// signed, version-pinned native facts. These methods never read an object,
// remove a container, run Terraform or turn an absent terminal into NO_APPLY.
import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	ff "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetfixture"
	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
	native "github.com/christopherosiemo/bn-implementation-Finops/internal/groupfixtureproducer"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/jackc/pgx/v5"
)

var ErrGroupNative = errors.New("GROUP_NATIVE_RECONSTRUCTION_BINDING_INVALID")
var ErrGroupNativeConflict = errors.New("GROUP_NATIVE_RECONSTRUCTION_CONFLICT")

type groupNativeScope struct {
	Root              FleetGroupJournalBootstrap `json:"root"`
	Keys              FleetGroupJournalKeys      `json:"keys"`
	Proposal          ff.Proposal                `json:"proposal"`
	ProgramRaw        []byte                     `json:"program_raw"`
	ReviewRaw         []byte                     `json:"journal_review_raw"`
	ProgramSHA256     string                     `json:"program_sha256"`
	AuthorizationHash string                     `json:"authorization_sha256"`
	ProofHash         string                     `json:"proof_hash"`
	Artifacts         []ff.ArtifactReference     `json:"artifact_refs"`
	ControllerKeyID   string                     `json:"controller_key_id"`
	ControllerKey     ed25519.PublicKey          `json:"controller_key"`
}
type groupNativeWorkspace struct {
	SchemaVersion string                           `json:"schema_version"`
	Workspace     native.NativeWorkspace           `json:"workspace"`
	TerminalID    string                           `json:"terminal_id"`
	Retirement    *native.NativeRetirementEnvelope `json:"retirement"`
}
type groupNativeJournal struct {
	Head    []byte `json:"head"`
	Records []struct {
		Record []byte `json:"record"`
		Head   []byte `json:"head"`
	} `json:"records"`
}

func (t *Tx) groupNativeRole(ctx context.Context, role string) error {
	var current string
	if e := t.QueryRow(ctx, `SELECT current_user`).Scan(&current); e != nil {
		return e
	}
	if current != role {
		return ErrGroupNative
	}
	return nil
}

func (t *Tx) groupNativeScope(ctx context.Context, chain string) (groupNativeScope, error) {
	var s groupNativeScope
	if !groupJournalValidID(chain) {
		return s, ErrGroupNative
	}
	var raw []byte
	if e := t.QueryRow(ctx, `SELECT public.fleet_group_reconstruction_scope($1,$2)`, t.Tenant, chain).Scan(&raw); e != nil {
		return s, e
	}
	if len(raw) == 0 || json.Unmarshal(raw, &s) != nil || s.Root.ChainID != chain || s.Proposal.Binding.Old.Target.TenantID != t.Tenant || s.Proposal.ID == "" || s.ProgramSHA256 != g.Digest(s.Root.Parent.Program) || s.AuthorizationHash != g.Digest(s.Root.Authorization) || len(s.ControllerKey) != ed25519.PublicKeySize {
		return s, ErrGroupNative
	}
	if len(s.Keys.Signer) != ed25519.PublicKeySize || len(s.Keys.Pipeline) != ed25519.PublicKeySize || len(s.Keys.Ledger) != ed25519.PublicKeySize || !bytes.Equal(s.Keys.Signer, s.Root.Keys.Signer) || !bytes.Equal(s.Keys.Pipeline, s.Root.Keys.Pipeline) || !bytes.Equal(s.Keys.Ledger, s.Root.Keys.Ledger) || bytes.Equal(s.ControllerKey, s.Keys.Signer) || bytes.Equal(s.ControllerKey, s.Keys.Pipeline) || bytes.Equal(s.ControllerKey, s.Keys.Ledger) {
		return s, ErrGroupNative
	}
	return s, nil
}

// GitProofs are not stored as samples in PostgreSQL. A private archive loader
// supplies them before entering the fence; every immutable PG pin is rechecked
// here, including its complete canonical proof population hash.
func groupNativePreparation(s groupNativeScope, prepared ff.Preparation) error {
	program, _, e := ff.ProgramBytes(prepared.Program)
	if e != nil || !bytes.Equal(program, s.ProgramRaw) {
		return ErrGroupNative
	}
	review, e := json.Marshal(prepared.JournalReview)
	if e != nil || !bytes.Equal(review, s.ReviewRaw) || g.Digest(prepared.Artifacts) != g.Digest(s.Artifacts) {
		return ErrGroupNative
	}
	proofs, e := ff.ProofBytes(prepared.GitProofs)
	if e != nil || g.BytesDigest(proofs) != s.ProofHash || ff.ValidatePreparation(s.Proposal, prepared, prepared.Program.CreatedAt) != nil {
		return ErrGroupNative
	}
	return nil
}

func (t *Tx) groupNativeLock(ctx context.Context, chain string) error {
	var locked bool
	if e := t.QueryRow(ctx, `SELECT public.fleet_group_reconstruction_lock($1,$2)`, t.Tenant, chain).Scan(&locked); e != nil {
		return e
	}
	if !locked {
		return ErrGroupNative
	}
	return nil
}

func (t *Tx) groupNativeOriginal(ctx context.Context, s groupNativeScope) (g.JournalView, error) {
	v := s.Root.View()
	var raw []byte
	if e := t.QueryRow(ctx, `SELECT public.fleet_group_reconstruction_journal($1,$2)`, t.Tenant, s.Root.ChainID).Scan(&raw); e != nil {
		return v, e
	}
	var stored groupNativeJournal
	if len(raw) == 0 || len(raw) > 48<<20 || json.Unmarshal(raw, &stored) != nil || len(stored.Records) > 512 {
		return v, ErrGroupNative
	}
	checkpoints := []g.JournalHeadEnvelope{s.Root.Head}
	for _, item := range stored.Records {
		var r g.JournalRecord
		var h g.JournalHeadEnvelope
		if groupJournalDecode(item.Record, &r) != nil || groupJournalDecode(item.Head, &h) != nil {
			return v, ErrGroupNative
		}
		v.Records = append(v.Records, r)
		checkpoints = append(checkpoints, h)
	}
	if groupJournalDecode(stored.Head, &v.Head) != nil {
		return v, ErrGroupNative
	}
	_, e := g.VerifyJournalCheckpoints(v, checkpoints, s.Root.Keys.Core(), v.Head.Head.Ref, time.Now().UTC())
	return v, e
}

func (t *Tx) groupNativeWorkspace(ctx context.Context, chain string) (groupNativeWorkspace, string, error) {
	var w groupNativeWorkspace
	var raw []byte
	var ordinal string
	e := t.QueryRow(ctx, `SELECT raw_document,ordinal::text FROM public.fleet_group_workspaces WHERE tenant_id=$1 AND chain_id=$2 ORDER BY ordinal DESC LIMIT 1`, t.Tenant, chain).Scan(&raw, &ordinal)
	if e == nil {
		e = groupJournalDecode(raw, &w)
	}
	return w, ordinal, e
}

func (t *Tx) groupNativeReference(ctx context.Context, chain, command, kind string, ref ff.ArtifactReference) error {
	d, e := t.GroupArtifactGet(ctx, chain, command, kind, ref.ID)
	if e != nil {
		return e
	}
	var actual ff.ArtifactReference
	if fleetFixtureDecode(d["artifact"], &actual) != nil || actual != ref {
		return ErrGroupNative
	}
	return nil
}

// An issued APPLY_INTENT is not evidence that a private delivery was claimed.
// Inspect the same immutable command and durable one-shot attempt under the
// graph/current fence. Expired attempts may still be reconciled; this returns
// no dispatch permission and never renews the attempt.
func (t *Tx) groupNativeApplyDelivery(ctx context.Context, chain string, command g.JournalCommand) error {
	var encoded []byte
	var stored struct {
		Raw     []byte `json:"raw"`
		State   string `json:"state"`
		Attempt string `json:"attempt"`
		Hash    string `json:"command_hash"`
	}
	if e := t.QueryRow(ctx, `SELECT public.fleet_group_reconstruction_delivery($1,$2,$3)`, t.Tenant, chain, command.ID).Scan(&encoded); e != nil {
		return e
	}
	if len(encoded) == 0 || len(encoded) > 192<<10 || json.Unmarshal(encoded, &stored) != nil {
		return ErrGroupNative
	}
	var d FleetGroupJournalDelivery
	var issued g.JournalCommand
	if groupJournalDecode(stored.Raw, &d) != nil || groupJournalDecode(d.Command, &issued) != nil || d.ChainID != chain || d.CommandID != command.ID || d.Action != "APPLY" || d.CommandHash != g.Digest(command) || stored.Hash != d.CommandHash || g.Digest(issued) != g.Digest(command) || !groupJournalValidID(stored.Attempt) || (stored.State != "ATTEMPTED" && stored.State != "RECONCILE" && stored.State != "COMPLETE") {
		return ErrGroupNative
	}
	return nil
}

func groupNativeSnapshot(s groupNativeScope, prepared ff.Preparation, v g.JournalView, w groupNativeWorkspace, mode, command string) native.NativeReconstructionSnapshot {
	snapshot := native.NativeReconstructionSnapshot{Kind: native.ReconstructionOriginal, Mode: mode, ChainID: s.Root.ChainID, Selected: s.Proposal, Prepared: prepared, View: v, Keys: s.Root.Keys.Core(), ExpectedHead: v.Head.Head.Ref, CurrentHeadSHA256: g.Digest(v.Head), Workspace: w.Workspace, RetirementKey: s.ControllerKey, CommandID: command}
	if mode == native.ReconstructionTerminal {
		snapshot.Retirement = w.Retirement
	}
	return snapshot
}

// The archive ref must already have passed exact-version AEAD readback and
// GroupArtifactAppend. The SQL role and label are not cryptographic authority:
// this method independently verifies the commissioned pipeline signature and
// exact issued prefix, then pins all four immutable registry references.
func (t *Tx) GroupNativeTerminalAppend(ctx context.Context, chain string, identity FleetGroupPipelineIdentity, prepared ff.Preparation, envelope native.NativeTerminalEnvelope, archived ff.ArtifactReference) (model.Document, bool, error) {
	type result struct {
		doc    model.Document
		replay bool
	}
	out, e := groupJournalAtomic(ctx, t, func(tx *Tx) (result, error) {
		if e := tx.groupNativeRole(ctx, "finops_group_pipeline"); e != nil {
			return result{}, e
		}
		s, e := tx.groupNativeScope(ctx, chain)
		if e != nil || groupNativePreparation(s, prepared) != nil {
			return result{}, ErrGroupNative
		}
		if e = tx.groupNativeLock(ctx, chain); e != nil {
			return result{}, e
		}
		raw, hash, e := groupJournalBytes(envelope)
		if e != nil || !groupJournalValidID(archived.ID) || archived.SHA256 != hash || archived.SizeBytes != int64(len(raw)) {
			return result{}, ErrGroupNative
		}
		var old []byte
		var writer, oldCommand, oldArtifact string
		var at time.Time
		e = tx.QueryRow(ctx, `SELECT raw_document,writer_role,created_at,command_id,artifact_id FROM public.fleet_group_native_terminals WHERE tenant_id=$1 AND chain_id=$2 AND id=$3`, tx.Tenant, chain, envelope.Terminal.ID).Scan(&old, &writer, &at, &oldCommand, &oldArtifact)
		if e == nil {
			if !bytes.Equal(old, raw) || oldArtifact != archived.ID {
				return result{}, ErrGroupNativeConflict
			}
			actual, e := tx.groupArtifactScope(ctx, chain, oldCommand)
			if e != nil || identity != (FleetGroupPipelineIdentity{actual.SourceID, actual.Issuer, actual.Subject, actual.Audience}) {
				return result{}, ErrGroupNative
			}
			if e = tx.groupNativeReference(ctx, chain, oldCommand, "NATIVE_OPERATION_PROOF", archived); e != nil {
				return result{}, e
			}
			d, e := groupArtifactProjection(old, hash, writer, at)
			return result{d, true}, e
		}
		if !errors.Is(e, pgx.ErrNoRows) {
			return result{}, e
		}
		v, e := tx.groupNativeOriginal(ctx, s)
		if e != nil {
			return result{}, e
		}
		p, e := g.VerifyJournal(v, s.Root.Keys.Core(), v.Head.Head.Ref, time.Now().UTC())
		if e != nil || p.Pending == nil {
			return result{}, ErrGroupNative
		}
		command := p.Pending.Command
		if e = tx.groupNativeApplyDelivery(ctx, chain, command); e != nil {
			return result{}, e
		}
		actual, e := tx.groupArtifactScope(ctx, chain, command.ID)
		if e != nil || identity != (FleetGroupPipelineIdentity{actual.SourceID, actual.Issuer, actual.Subject, actual.Audience}) {
			return result{}, ErrGroupNative
		}
		w, _, e := tx.groupNativeWorkspace(ctx, chain)
		if e != nil {
			return result{}, e
		}
		snapshot := groupNativeSnapshot(s, prepared, v, w, native.ReconstructionObservation, command.ID)
		snapshot.References = envelope.Terminal.References
		if e = native.ValidateNativeTerminal(snapshot, envelope, time.Now().UTC()); e != nil {
			return result{}, e
		}
		for _, selected := range []struct {
			kind string
			ref  ff.ArtifactReference
		}{{"NATIVE_ARTIFACT_REVIEW", snapshot.References.Review}, {"NATIVE_CAPTURE", snapshot.References.Capture}, {"AFTER_NATIVE_STATE", snapshot.References.After}, {"NATIVE_OPERATION_PROOF", archived}} {
			if e = tx.groupNativeReference(ctx, chain, command.ID, selected.kind, selected.ref); e != nil {
				return result{}, e
			}
		}
		e = tx.QueryRow(ctx, `INSERT INTO public.fleet_group_native_terminals(tenant_id,chain_id,id,command_id,operation_id,fence,workspace_generation,head_hash,artifact_id,review_id,capture_id,after_id,document,raw_document,content_hash) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,convert_from($13::bytea,'UTF8')::jsonb,$13,$14) RETURNING writer_role,created_at`, tx.Tenant, chain, envelope.Terminal.ID, command.ID, command.OperationID, fmt.Sprint(command.Fence), w.Workspace.Generation, g.Digest(envelope.Terminal.Head), archived.ID, snapshot.References.Review.ID, snapshot.References.Capture.ID, snapshot.References.After.ID, raw, hash).Scan(&writer, &at)
		if e != nil {
			return result{}, e
		}
		d, e := groupArtifactProjection(raw, hash, writer, at)
		return result{d, false}, e
	})
	return out.doc, out.replay, e
}

func (t *Tx) groupNativeTerminal(ctx context.Context, chain, id string) (native.NativeTerminalEnvelope, string, ff.ArtifactReference, error) {
	var envelope native.NativeTerminalEnvelope
	var raw []byte
	var command, artifact string
	e := t.QueryRow(ctx, `SELECT raw_document,command_id,artifact_id FROM public.fleet_group_native_terminals WHERE tenant_id=$1 AND chain_id=$2 AND id=$3`, t.Tenant, chain, id).Scan(&raw, &command, &artifact)
	if e != nil {
		return envelope, command, ff.ArtifactReference{}, e
	}
	if groupJournalDecode(raw, &envelope) != nil {
		return envelope, command, ff.ArtifactReference{}, ErrGroupNative
	}
	var stored []byte
	e = t.QueryRow(ctx, `SELECT public.fleet_group_reconstruction_terminal_ref($1,$2,$3,$4)`, t.Tenant, chain, command, artifact).Scan(&stored)
	var ref ff.ArtifactReference
	if e == nil {
		if len(stored) == 0 || json.Unmarshal(stored, &ref) != nil {
			e = ErrGroupNative
		}
	}
	return envelope, command, ref, e
}

// Selection is a separate ledger decision, immutable before APPLIED. It never
// picks a reference by label/time or converts an UNKNOWN operation to success.
func (t *Tx) GroupNativeTerminalSelect(ctx context.Context, chain, command, terminal string, prepared ff.Preparation) (bool, error) {
	return groupJournalAtomic(ctx, t, func(tx *Tx) (bool, error) {
		if e := tx.groupNativeRole(ctx, "finops_group_ledger"); e != nil {
			return false, e
		}
		s, e := tx.groupNativeScope(ctx, chain)
		if e != nil || groupNativePreparation(s, prepared) != nil {
			return false, ErrGroupNative
		}
		if e = tx.groupNativeLock(ctx, chain); e != nil {
			return false, e
		}
		var prior string
		e = tx.QueryRow(ctx, `SELECT terminal_id FROM public.fleet_group_native_terminal_selections WHERE tenant_id=$1 AND chain_id=$2 AND command_id=$3`, tx.Tenant, chain, command).Scan(&prior)
		if e == nil {
			if prior != terminal {
				return false, ErrGroupNativeConflict
			}
			return true, nil
		}
		if !errors.Is(e, pgx.ErrNoRows) {
			return false, e
		}
		v, e := tx.groupNativeOriginal(ctx, s)
		if e != nil {
			return false, e
		}
		envelope, actual, _, e := tx.groupNativeTerminal(ctx, chain, terminal)
		if e != nil || actual != command {
			return false, ErrGroupNative
		}
		w, _, e := tx.groupNativeWorkspace(ctx, chain)
		if e != nil {
			return false, e
		}
		snapshot := groupNativeSnapshot(s, prepared, v, w, native.ReconstructionObservation, command)
		p, e := g.VerifyJournal(v, s.Root.Keys.Core(), v.Head.Head.Ref, time.Now().UTC())
		if e != nil || p.Pending == nil || p.Pending.Command.ID != command {
			return false, ErrGroupNative
		}
		if e = tx.groupNativeApplyDelivery(ctx, chain, p.Pending.Command); e != nil {
			return false, e
		}
		snapshot.References = envelope.Terminal.References
		if e = native.ValidateNativeTerminal(snapshot, envelope, time.Now().UTC()); e != nil {
			return false, e
		}
		_, e = tx.Exec(ctx, `INSERT INTO public.fleet_group_native_terminal_selections(tenant_id,chain_id,command_id,terminal_id) VALUES($1,$2,$3,$4)`, tx.Tenant, chain, command, terminal)
		return false, e
	})
}
