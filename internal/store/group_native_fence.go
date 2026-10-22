package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"strconv"
	"time"

	ff "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetfixture"
	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
	native "github.com/christopherosiemo/bn-implementation-Finops/internal/groupfixtureproducer"
	"github.com/jackc/pgx/v5"
)

// This is private server configuration, not a request DTO. IDs select immutable
// database rows; they never supply a current head, key, native state or verdict.
type GroupNativeReconstructionRequest struct {
	Mode                string
	WorkspaceGeneration string
	CommandID           string
	DeliveryID          string
	AttemptID           string
	CaptureID           string
	AfterID             string
}

// Tx must be the authenticated ledger transaction that encloses the entire
// producer callback. A cached preparation is only a transport optimization:
// exact canonical PG pins are compared again after taking the real fence.
type GroupNativeReconstructionAuthority struct {
	Tx       *Tx
	Prepared ff.Preparation
	Request  GroupNativeReconstructionRequest
}

func (a GroupNativeReconstructionAuthority) WithCurrentNativeFence(ctx context.Context, chain string, fn func(native.NativeReconstructionSnapshot) error) error {
	if a.Tx == nil || fn == nil {
		return ErrGroupNative
	}
	_, e := groupJournalAtomic(ctx, a.Tx, func(tx *Tx) (bool, error) {
		if e := tx.groupNativeRole(ctx, "finops_group_ledger"); e != nil {
			return false, e
		}
		s, e := tx.groupNativeScope(ctx, chain)
		if e != nil || groupNativePreparation(s, a.Prepared) != nil {
			return false, ErrGroupNative
		}
		v, e := tx.groupNativeOriginal(ctx, s)
		if e != nil {
			return false, e
		}
		w, _, e := tx.groupNativeWorkspace(ctx, chain)
		if e != nil || w.Workspace.Generation != a.Request.WorkspaceGeneration {
			return false, ErrGroupNative
		}
		snapshot := groupNativeSnapshot(s, a.Prepared, v, w, a.Request.Mode, a.Request.CommandID)
		if a.Request.Mode == native.ReconstructionInitial {
			if a.Request.CommandID != "" || a.Request.DeliveryID != "" || a.Request.AttemptID != "" || a.Request.CaptureID != "" || a.Request.AfterID != "" || v.Head.Head.Ref.RecordCount != 0 || len(v.Records) != 0 {
				return false, ErrGroupNative
			}
			p, e := g.VerifyJournal(v, s.Root.Keys.Core(), v.Head.Head.Ref, time.Now().UTC())
			if e != nil || p.Pending != nil || len(p.Stack) != 0 || len(p.Consumed) != 0 || p.Current != a.Prepared.JournalReview.Base {
				return false, ErrGroupNative
			}
			return true, fn(snapshot)
		}
		if !groupJournalValidID(a.Request.CommandID) || !groupJournalValidID(a.Request.DeliveryID) || !groupJournalValidID(a.Request.AttemptID) || (a.Request.Mode != native.ReconstructionObservation && a.Request.Mode != native.ReconstructionTerminal) {
			return false, ErrGroupNative
		}
		// Expired attempts are reconciliation duties, never permission to apply.
		// Holding this exact row excludes a competing delivery while native facts
		// are inspected/materialized. No lease deadline is extended here.
		var raw []byte
		var state, attempt string
		if e = tx.QueryRow(ctx, `SELECT raw_document,state,attempt_id FROM public.fleet_group_journal_outbox WHERE tenant_id=$1 AND chain_id=$2 AND id=$3 FOR UPDATE`, tx.Tenant, chain, a.Request.DeliveryID).Scan(&raw, &state, &attempt); e != nil {
			return false, e
		}
		var delivery FleetGroupJournalDelivery
		if groupJournalDecode(raw, &delivery) != nil || delivery.ChainID != chain || delivery.CommandID != a.Request.CommandID || delivery.Action != "APPLY" || attempt != a.Request.AttemptID || (state != "ATTEMPTED" && state != "RECONCILE" && state != "COMPLETE") {
			return false, ErrGroupNative
		}
		if a.Request.Mode == native.ReconstructionObservation {
			p, e := g.VerifyJournal(v, s.Root.Keys.Core(), v.Head.Head.Ref, time.Now().UTC())
			if e != nil || p.Pending == nil || p.Pending.Command.ID != a.Request.CommandID || g.Digest(p.Pending.Command) != delivery.CommandHash || !p.Pending.ApplyIntent || p.Pending.NoApply != nil || p.Pending.GitRepair != nil || !groupArtifactID.MatchString(a.Request.CaptureID) || !groupArtifactID.MatchString(a.Request.AfterID) {
				return false, ErrGroupNative
			}
			var artifact g.GitArtifact
			if p.Pending.Command.Forward != nil {
				artifact = p.Pending.Command.Forward.Child.Artifact
			} else if p.Pending.Command.Recovery != nil {
				artifact = p.Pending.Command.Recovery.Recovery.Artifact
			} else {
				return false, ErrGroupNative
			}
			for _, part := range []struct {
				kind string
				id   string
				out  *ff.ArtifactReference
			}{{"NATIVE_ARTIFACT_REVIEW", artifact.Receipt.ID, &snapshot.References.Review}, {"NATIVE_CAPTURE", a.Request.CaptureID, &snapshot.References.Capture}, {"AFTER_NATIVE_STATE", a.Request.AfterID, &snapshot.References.After}} {
				d, e := tx.GroupArtifactGet(ctx, chain, a.Request.CommandID, part.kind, part.id)
				if e != nil || fleetFixtureDecode(d["artifact"], part.out) != nil {
					return false, ErrGroupNative
				}
			}
			if snapshot.References.Review.SHA256 != artifact.Receipt.SHA256 {
				return false, ErrGroupNative
			}
		} else {
			if a.Request.CaptureID != "" || a.Request.AfterID != "" {
				return false, ErrGroupNative
			}
			var id string
			if e = tx.QueryRow(ctx, `SELECT terminal_id FROM public.fleet_group_native_terminal_selections WHERE tenant_id=$1 AND chain_id=$2 AND command_id=$3`, tx.Tenant, chain, a.Request.CommandID).Scan(&id); e != nil {
				return false, e
			}
			terminal, command, ref, e := tx.groupNativeTerminal(ctx, chain, id)
			if e != nil || command != a.Request.CommandID || terminal.Terminal.CommandSHA256 != delivery.CommandHash {
				return false, ErrGroupNative
			}
			snapshot.References, snapshot.TerminalRef = terminal.Terminal.References, ref
			if e = native.ValidateNativeTerminal(snapshot, terminal, time.Now().UTC()); e != nil {
				return false, e
			}
			rows, e := tx.Query(ctx, `SELECT t.command_id,t.raw_document FROM public.fleet_group_native_terminal_selections x JOIN public.fleet_group_native_terminals t ON t.tenant_id=x.tenant_id AND t.chain_id=x.chain_id AND t.id=x.terminal_id WHERE x.tenant_id=$1 AND x.chain_id=$2 AND x.command_id<>$3 ORDER BY (t.document->'terminal'->'head'->'head'->'ref'->>'record_count')::integer,t.command_id LIMIT 513`, tx.Tenant, chain, command)
			if e != nil {
				return false, e
			}
			for rows.Next() {
				var ancestor native.NativeTerminalEnvelope
				var c string
				var raw []byte
				if e = rows.Scan(&c, &raw); e != nil || groupJournalDecode(raw, &ancestor) != nil || len(snapshot.Ancestors) >= 512 {
					rows.Close()
					return false, ErrGroupNative
				}
				snapshot.Ancestors = append(snapshot.Ancestors, native.NativeReconstructionAncestor{CommandID: c, References: ancestor.Terminal.References})
			}
			e = rows.Err()
			rows.Close()
			if e != nil {
				return false, e
			}
		}
		return true, fn(snapshot)
	})
	return e
}

// The independently commissioned controller has already observed exact Docker
// removal and signed that fact. SQL and this repository verify its binding;
// they cannot turn an expired lease or a missing process into removal proof.
func (t *Tx) GroupNativeWorkspaceActivate(ctx context.Context, chain, keyID, terminalID string, prepared ff.Preparation, retirement native.NativeRetirementEnvelope) (bool, error) {
	return groupJournalAtomic(ctx, t, func(tx *Tx) (bool, error) {
		if e := tx.groupNativeRole(ctx, "finops_group_workspace_controller"); e != nil {
			return false, e
		}
		s, e := tx.groupNativeScope(ctx, chain)
		if e != nil || s.ControllerKeyID != keyID || groupNativePreparation(s, prepared) != nil {
			return false, ErrGroupNative
		}
		if e = tx.groupNativeLock(ctx, chain); e != nil {
			return false, e
		}
		body := groupNativeWorkspace{"1", retirement.Retirement.New, terminalID, &retirement}
		raw, hash, e := groupJournalBytes(body)
		if e != nil {
			return false, e
		}
		var previous []byte
		e = tx.QueryRow(ctx, `SELECT raw_document FROM public.fleet_group_workspaces WHERE tenant_id=$1 AND chain_id=$2 AND generation=$3`, tx.Tenant, chain, body.Workspace.Generation).Scan(&previous)
		if e == nil {
			if !bytes.Equal(previous, raw) {
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
		old, ordinal, e := tx.groupNativeWorkspace(ctx, chain)
		if e != nil || old.Workspace != retirement.Retirement.Old {
			return false, ErrGroupNative
		}
		n, e := strconv.ParseUint(ordinal, 10, 64)
		if e != nil || n == math.MaxUint64 {
			return false, ErrGroupNative
		}
		terminal, command, ref, e := tx.groupNativeTerminal(ctx, chain, terminalID)
		if e != nil || terminal.Terminal.Workspace != old.Workspace {
			return false, ErrGroupNative
		}
		var selected string
		if e = tx.QueryRow(ctx, `SELECT terminal_id FROM public.fleet_group_native_terminal_selections WHERE tenant_id=$1 AND chain_id=$2 AND command_id=$3`, tx.Tenant, chain, command).Scan(&selected); e != nil || selected != terminalID {
			return false, ErrGroupNative
		}
		snapshot := groupNativeSnapshot(s, prepared, v, body, native.ReconstructionTerminal, command)
		snapshot.References, snapshot.TerminalRef = terminal.Terminal.References, ref
		if e = native.ValidateNativeTerminal(snapshot, terminal, time.Now().UTC()); e != nil {
			return false, e
		}
		_, e = tx.Exec(ctx, `INSERT INTO public.fleet_group_workspaces(tenant_id,chain_id,generation,ordinal,runtime_id,image_sha256,key_binding_id,previous_generation,document,raw_document,content_hash) VALUES($1,$2,$3,$4,$5,$6,$7,$8,convert_from($9::bytea,'UTF8')::jsonb,$9,$10)`, tx.Tenant, chain, body.Workspace.Generation, fmt.Sprint(n+1), body.Workspace.RuntimeID, body.Workspace.ImageSHA256, keyID, old.Workspace.Generation, raw, hash)
		return false, e
	})
}

// Make a compile-time assertion so future DTO changes cannot silently replace
// the commissioned callback fence with a snapshot supplied by a caller.
var _ native.NativeReconstructionAuthority = GroupNativeReconstructionAuthority{}
