package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	ff "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetfixture"
	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
	native "github.com/christopherosiemo/bn-implementation-Finops/internal/groupfixtureproducer"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/jackc/pgx/v5"
)

func (t *Tx) GroupRecoveryHealthSnapshot(ctx context.Context, chain, observerID, generation string) (GroupRecoveryHealthSnapshot, error) {
	var out GroupRecoveryHealthSnapshot
	var raw []byte
	if !groupJournalValidID(chain) || !groupJournalValidID(observerID) || !groupJournalValidID(generation) {
		return out, ErrGroupRecoveryHealth
	}
	if e := t.QueryRow(ctx, `SELECT public.fleet_group_recovery_health_scope($1,$2,$3),clock_timestamp()`, t.Tenant, chain, observerID).Scan(&raw, &out.Now); e != nil {
		return out, e
	}
	var s struct {
		Scope      groupNativeScope            `json:"scope"`
		Journal    groupNativeJournal          `json:"journal"`
		Workspace  groupNativeWorkspace        `json:"workspace"`
		Observer   GroupRecoveryHealthObserver `json:"observer"`
		Released   bool                        `json:"released"`
		TerminalID string                      `json:"terminal_id"`
	}
	if len(raw) == 0 || len(raw) > 48<<20 || json.Unmarshal(raw, &s) != nil || s.Scope.Root.ChainID != chain || s.Observer.ChainID != chain || s.Observer.TenantID != t.Tenant || s.Observer.ID != observerID || s.Workspace.Workspace.Generation != generation {
		return out, ErrGroupRecoveryHealth
	}
	out.Observer, out.Workspace, out.Released = s.Observer, s.Workspace.Workspace, s.Released
	out.TerminalID = s.TerminalID
	out.View = s.Scope.Root.View()
	out.Keys = s.Scope.Root.Keys.Core()
	out.Now = out.Now.UTC()
	checkpoints := []g.JournalHeadEnvelope{s.Scope.Root.Head}
	for _, item := range s.Journal.Records {
		var r g.JournalRecord
		var h g.JournalHeadEnvelope
		if groupJournalDecode(item.Record, &r) != nil || groupJournalDecode(item.Head, &h) != nil {
			return out, ErrGroupRecoveryHealth
		}
		out.View.Records = append(out.View.Records, r)
		checkpoints = append(checkpoints, h)
	}
	if groupJournalDecode(s.Journal.Head, &out.View.Head) != nil {
		return out, ErrGroupRecoveryHealth
	}
	p, e := g.VerifyJournalCheckpoints(out.View, checkpoints, out.Keys, out.View.Head.Head.Ref, out.Now)
	if e != nil {
		return out, e
	}
	commands := map[string]g.JournalCommand{}
	for _, r := range out.View.Records {
		if r.Kind == g.JournalReserved && r.Command != nil {
			commands[r.Command.ID] = *r.Command
		}
		if r.Kind == g.JournalApplied && r.Receipt != nil {
			out.Command = commands[r.Receipt.Receipt.CommandID]
		}
	}
	var baseline []byte
	e = t.QueryRow(ctx, `SELECT raw_document FROM public.fleet_group_recovery_health_baselines WHERE tenant_id=$1 AND chain_id=$2`, t.Tenant, chain).Scan(&baseline)
	if e == nil {
		var b GroupRecoveryHealthBaseline
		if groupJournalDecode(baseline, &b) != nil {
			return out, ErrGroupRecoveryHealth
		}
		out.Baseline = &b
	} else if !errors.Is(e, pgx.ErrNoRows) {
		return out, e
	}
	if p.Pending == nil && out.Command.ID != "" && out.Command.Recovery != nil && p.Current.Model != out.Command.Recovery.Recovery.Artifact.After {
		return out, ErrGroupRecoveryHealth
	}
	return out, nil
}

func (t *Tx) recoveryArtifact(ctx context.Context, chain, command, kind string, ref ff.ArtifactReference) error {
	var raw []byte
	if e := t.QueryRow(ctx, `SELECT public.fleet_group_recovery_health_artifact($1,$2,$3,$4,$5)`, t.Tenant, chain, command, kind, ref.ID).Scan(&raw); e != nil {
		return e
	}
	var actual ff.ArtifactReference
	if len(raw) == 0 || json.Unmarshal(raw, &actual) != nil || actual != ref {
		return ErrGroupRecoveryHealth
	}
	return nil
}
func (t *Tx) recoveryObserverRole(ctx context.Context, chain, id string, identity GroupRecoveryHealthIdentity) (GroupRecoveryHealthObserver, error) {
	var o GroupRecoveryHealthObserver
	var raw []byte
	if e := t.groupNativeRole(ctx, "finops_group_health_observer"); e != nil {
		return o, e
	}
	e := t.QueryRow(ctx, `SELECT jsonb_build_object('id',id,'tenant_id',tenant_id,'chain_id',chain_id,'database_login',database_login,'identity',jsonb_build_object('source_id',source_id,'issuer',issuer,'subject',subject,'audience',audience),'public_key',encode(public_key,'base64'),'limits',limits) FROM public.fleet_group_recovery_health_observers WHERE tenant_id=$1 AND chain_id=$2 AND id=$3 AND database_login=session_user`, t.Tenant, chain, id).Scan(&raw)
	if e != nil {
		return o, e
	}
	if json.Unmarshal(raw, &o) != nil || o.Identity != identity {
		return o, ErrGroupRecoveryHealth
	}
	return o, nil
}
func (t *Tx) recoveryExisting(ctx context.Context, table, chain, id string, body any) (model.Document, bool, error) {
	var old []byte
	var hash, writer string
	var at time.Time
	e := t.QueryRow(ctx, `SELECT raw_document,content_hash,writer_role,created_at FROM public.`+table+` WHERE tenant_id=$1 AND chain_id=$2 AND id=$3`, t.Tenant, chain, id).Scan(&old, &hash, &writer, &at)
	if errors.Is(e, pgx.ErrNoRows) {
		return nil, false, nil
	}
	if e != nil {
		return nil, false, e
	}
	raw, _ := json.Marshal(body)
	if !bytes.Equal(old, raw) || hash != g.BytesDigest(raw) {
		return nil, false, ErrGroupRecoveryHealthConflict
	}
	d, e := groupArtifactProjection(old, hash, writer, at)
	return d, true, e
}
func (t *Tx) recoveryDocument(ctx context.Context, table, chain, id string) (model.Document, error) {
	var raw []byte
	var hash, writer string
	var at time.Time
	e := t.QueryRow(ctx, `SELECT raw_document,content_hash,writer_role,created_at FROM public.`+table+` WHERE tenant_id=$1 AND chain_id=$2 AND id=$3`, t.Tenant, chain, id).Scan(&raw, &hash, &writer, &at)
	if e != nil {
		return nil, e
	}
	return groupArtifactProjection(raw, hash, writer, at)
}

func (t *Tx) GroupRecoveryHealthObservationAppend(ctx context.Context, identity GroupRecoveryHealthIdentity, envelope GroupRecoveryHealthObservationEnvelope) (model.Document, bool, error) {
	type result struct {
		d      model.Document
		replay bool
	}
	r, e := groupJournalAtomic(ctx, t, func(tx *Tx) (result, error) {
		b := envelope.Observation
		o, e := tx.recoveryObserverRole(ctx, b.ChainID, b.ObserverID, identity)
		if e != nil {
			return result{}, e
		}
		if b.SchemaVersion != "1" || b.TenantID != tx.Tenant || b.ChainID != o.ChainID || !groupJournalValidID(b.ID) || !groupRecoveryHealthVerify(groupRecoveryObservationDomain, b, envelope.Algorithm, envelope.Signature, o.PublicKey) {
			return result{}, ErrGroupRecoveryHealth
		}
		if d, replayed, e := tx.recoveryExisting(ctx, "fleet_group_recovery_health_observations", b.ChainID, b.ID, envelope); e != nil || replayed {
			return result{d, replayed}, e
		}
		s, e := tx.GroupRecoveryHealthSnapshot(ctx, b.ChainID, b.ObserverID, b.Workspace.Generation)
		if e != nil {
			return result{}, e
		}
		maxRawAge := time.Minute
		if b.Phase == "BASELINE" {
			maxRawAge = 5 * time.Minute
		}
		if s.Released || s.Workspace != b.Workspace || b.SignedAt.After(s.Now.Add(5*time.Second)) || b.SignedAt.Before(s.Now.Add(-time.Minute)) || b.SignedAt.Before(b.Receipt.After.CapturedAt) || b.Receipt.After.CapturedAt.After(s.Now.Add(time.Second)) || s.Now.Sub(b.Receipt.After.CapturedAt) > maxRawAge || b.Receipt.SchemaVersion != "2" || b.Receipt.SHA256 != native.HealthReceiptSHA256(b.Receipt) || b.Receipt.Binding.Binding != s.View.Parent.Program.Binding || b.Receipt.Binding.Realm != s.View.Parent.Program.Realm || b.Receipt.Binding.ProgramSHA256 != g.Digest(s.View.Parent.Program) {
			return result{}, ErrGroupRecoveryHealth
		}
		rawReceipt, _ := json.Marshal(b.Receipt)
		if b.Reference.SHA256 != g.BytesDigest(rawReceipt) || b.Reference.SizeBytes != int64(len(rawReceipt)) {
			return result{}, ErrGroupRecoveryHealth
		}
		kind := "HEALTH_RECEIPT"
		if b.Phase == "BASELINE" {
			kind = "HEALTH_BASELINE"
			if b.AttemptID != "" {
				return result{}, ErrGroupRecoveryHealth
			}
		} else if b.Phase != "RESTORATION" || !groupJournalValidID(b.AttemptID) {
			return result{}, ErrGroupRecoveryHealth
		}
		if e = tx.recoveryArtifact(ctx, b.ChainID, b.CommandID, kind, b.Reference); e != nil {
			return result{}, e
		}
		raw, hash, e := groupJournalBytes(envelope)
		if e != nil {
			return result{}, e
		}
		_, e = tx.Exec(ctx, `INSERT INTO public.fleet_group_recovery_health_observations(tenant_id,chain_id,id,observer_id,workspace_generation,phase,attempt_id,command_id,artifact_id,receipt_hash,document,raw_document,content_hash) VALUES($1,$2,$3,$4,$5,$6,nullif($7,''),$8,$9,$10,convert_from($11::bytea,'UTF8')::jsonb,$11,$12)`, tx.Tenant, b.ChainID, b.ID, b.ObserverID, b.Workspace.Generation, b.Phase, b.AttemptID, b.CommandID, b.Reference.ID, b.Receipt.SHA256, raw, hash)
		if e != nil {
			return result{}, e
		}
		d, e := tx.recoveryDocument(ctx, "fleet_group_recovery_health_observations", b.ChainID, b.ID)
		return result{d, false}, e
	})
	return r.d, r.replay, e
}

func (t *Tx) recoveryObservations(ctx context.Context, chain string, ids []string) ([]GroupRecoveryHealthObservationEnvelope, error) {
	if len(ids) > 256 {
		return nil, ErrGroupRecoveryHealth
	}
	// Bound the aggregate before decoding any population. Two such sets (the
	// immutable baseline and current attempt) may coexist during evaluation.
	var size int64
	if e := t.QueryRow(ctx, `SELECT coalesce(sum(octet_length(raw_document)),0)::bigint FROM public.fleet_group_recovery_health_observations WHERE tenant_id=$1 AND chain_id=$2 AND id=ANY($3::text[])`, t.Tenant, chain, ids).Scan(&size); e != nil {
		return nil, e
	}
	if size > 8<<20 {
		return nil, ErrGroupRecoveryHealth
	}
	seen := map[string]bool{}
	out := []GroupRecoveryHealthObservationEnvelope{}
	for _, id := range ids {
		if seen[id] || !groupJournalValidID(id) {
			return nil, ErrGroupRecoveryHealth
		}
		seen[id] = true
		var raw, key []byte
		if e := t.QueryRow(ctx, `SELECT x.raw_document,k.public_key FROM public.fleet_group_recovery_health_observations x JOIN public.fleet_group_recovery_health_observers k ON k.tenant_id=x.tenant_id AND k.chain_id=x.chain_id AND k.id=x.observer_id WHERE x.tenant_id=$1 AND x.chain_id=$2 AND x.id=$3`, t.Tenant, chain, id).Scan(&raw, &key); e != nil {
			return nil, e
		}
		var v GroupRecoveryHealthObservationEnvelope
		if groupJournalDecode(raw, &v) != nil || !groupRecoveryHealthVerify(groupRecoveryObservationDomain, v.Observation, v.Algorithm, v.Signature, key) {
			return nil, ErrGroupRecoveryHealth
		}
		out = append(out, v)
	}
	return out, nil
}
func recoveryReceiptBodies(v []GroupRecoveryHealthObservationEnvelope) []native.HealthReceipt {
	out := []native.HealthReceipt{}
	for _, x := range v {
		out = append(out, x.Observation.Receipt)
	}
	return out
}
func (t *Tx) GroupRecoveryHealthBaselineBind(ctx context.Context, chain, id string, anchor native.HealthBaselineAnchorEnvelope, ref ff.ArtifactReference, ids []string) (model.Document, bool, error) {
	type result struct {
		d      model.Document
		replay bool
	}
	r, e := groupJournalAtomic(ctx, t, func(tx *Tx) (result, error) {
		if e := tx.groupNativeRole(ctx, "finops_group_ledger"); e != nil {
			return result{}, e
		}
		body := GroupRecoveryHealthBaseline{"1", id, tx.Tenant, chain, anchor, ref, append([]string{}, ids...)}
		if !groupJournalValidID(id) {
			return result{}, ErrGroupRecoveryHealth
		}
		if d, replayed, e := tx.recoveryExisting(ctx, "fleet_group_recovery_health_baselines", chain, id, body); e != nil || replayed {
			return result{d, replayed}, e
		}
		observed, e := tx.recoveryObservations(ctx, chain, ids)
		if e != nil || len(observed) == 0 {
			return result{}, ErrGroupRecoveryHealth
		}
		first := observed[0].Observation
		s, e := tx.GroupRecoveryHealthSnapshot(ctx, chain, first.ObserverID, first.Workspace.Generation)
		if e != nil {
			return result{}, e
		}
		if s.Released || ref.SHA256 != g.Digest(anchor) {
			return result{}, ErrGroupRecoveryHealth
		}
		if e = tx.recoveryArtifact(ctx, chain, first.CommandID, "HEALTH_VERDICT", ref); e != nil {
			return result{}, e
		}
		for i, x := range observed {
			if x.Observation.Phase != "BASELINE" || x.Observation.CommandID != first.CommandID || i >= len(anchor.Anchor.Artifacts) || x.Observation.Reference != anchor.Anchor.Artifacts[i].Reference {
				return result{}, ErrGroupRecoveryHealth
			}
			var at time.Time
			if e = tx.QueryRow(ctx, `SELECT created_at FROM public.fleet_group_artifacts WHERE tenant_id=$1 AND chain_id=$2 AND command_id=$3 AND kind='HEALTH_BASELINE' AND id=$4`, tx.Tenant, chain, first.CommandID, x.Observation.Reference.ID).Scan(&at); e != nil || !at.Equal(anchor.Anchor.Artifacts[i].IssuedAt) {
				return result{}, ErrGroupRecoveryHealth
			}
		}
		window := native.EvaluateActivatedHealthWindow(s.View, s.Keys, s.View.Head.Head.Ref, anchor, native.ActivatedHealthDeployment{}, first.Receipt.Binding, recoveryReceiptBodies(observed), nil, s.Observer.Limits, s.Now)
		if len(window.ReasonCodes) != 1 || window.ReasonCodes[0] != "HEALTH_SAMPLES_INSUFFICIENT" {
			return result{}, ErrGroupRecoveryHealth
		}
		raw, hash, e := groupJournalBytes(body)
		if e != nil {
			return result{}, e
		}
		_, e = tx.Exec(ctx, `INSERT INTO public.fleet_group_recovery_health_baselines(tenant_id,chain_id,id,anchor_id,document,raw_document,content_hash) VALUES($1,$2,$3,$4,convert_from($5::bytea,'UTF8')::jsonb,$5,$6)`, tx.Tenant, chain, id, ref.ID, raw, hash)
		if e != nil {
			return result{}, e
		}
		d, e := tx.recoveryDocument(ctx, "fleet_group_recovery_health_baselines", chain, id)
		return result{d, false}, e
	})
	return r.d, r.replay, e
}

func (t *Tx) GroupRecoveryHealthAttemptStart(ctx context.Context, chain, observerID, generation, id, previousOutcomeID string) (GroupRecoveryHealthAttempt, error) {
	return groupJournalAtomic(ctx, t, func(tx *Tx) (GroupRecoveryHealthAttempt, error) {
		var a GroupRecoveryHealthAttempt
		if e := tx.groupNativeRole(ctx, "finops_group_health_observer"); e != nil {
			return a, e
		}
		if !groupJournalValidID(id) {
			return a, ErrGroupRecoveryHealth
		}
		var commissioned bool
		if e := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM public.fleet_group_recovery_health_observers WHERE tenant_id=$1 AND chain_id=$2 AND id=$3 AND database_login=session_user)`, tx.Tenant, chain, observerID).Scan(&commissioned); e != nil {
			return a, e
		}
		if !commissioned {
			return a, ErrGroupRecoveryHealth
		}
		var old []byte
		e := tx.QueryRow(ctx, `SELECT raw_document FROM public.fleet_group_recovery_health_attempts WHERE tenant_id=$1 AND chain_id=$2 AND id=$3`, tx.Tenant, chain, id).Scan(&old)
		if e == nil {
			if groupJournalDecode(old, &a) != nil || a.ObserverID != observerID || a.Workspace.Generation != generation || a.PreviousOutcomeID != previousOutcomeID {
				return a, ErrGroupRecoveryHealthConflict
			}
			return a, nil
		}
		if !errors.Is(e, pgx.ErrNoRows) {
			return a, e
		}
		s, e := tx.GroupRecoveryHealthSnapshot(ctx, chain, observerID, generation)
		if e != nil {
			return a, e
		}
		p, e := g.VerifyJournal(s.View, s.Keys, s.View.Head.Head.Ref, s.Now)
		if e != nil || s.Released || s.Baseline == nil || s.Command.ID == "" || s.Command.Recovery == nil || s.TerminalID == "" || p.Pending != nil || len(p.Stack) != 0 || !p.ForwardAborted || p.Current.Model != s.View.Authorization.Authorization.Base.Model {
			return a, ErrGroupRecoveryHealth
		}
		a = GroupRecoveryHealthAttempt{"1", id, tx.Tenant, chain, observerID, s.Baseline.ID, previousOutcomeID, s.Workspace, s.Command.ID, s.Command.OperationID, s.Command.Fence, s.TerminalID, p.Current.StateSHA256, s.View.Head.Head.Ref, s.Now}
		var ordinal string
		if e = tx.QueryRow(ctx, `SELECT (coalesce(max(ordinal),0)+1)::text FROM public.fleet_group_recovery_health_attempts WHERE tenant_id=$1 AND chain_id=$2`, tx.Tenant, chain).Scan(&ordinal); e != nil {
			return a, e
		}
		if _, e = strconv.ParseUint(ordinal, 10, 64); e != nil {
			return a, ErrGroupRecoveryHealth
		}
		raw, hash, e := groupJournalBytes(a)
		if e != nil {
			return a, e
		}
		_, e = tx.Exec(ctx, `INSERT INTO public.fleet_group_recovery_health_attempts(tenant_id,chain_id,id,observer_id,baseline_id,previous_outcome_id,workspace_generation,command_id,terminal_id,state_sha256,ordinal,document,raw_document,content_hash) VALUES($1,$2,$3,$4,$5,nullif($6,''),$7,$8,$9,$10,$11,convert_from($12::bytea,'UTF8')::jsonb,$12,$13)`, tx.Tenant, chain, id, observerID, a.BaselineID, previousOutcomeID, generation, a.CommandID, a.TerminalID, a.StateSHA256, ordinal, raw, hash)
		if e != nil {
			return a, e
		}
		return a, nil
	})
}

func (t *Tx) GroupRecoveryHealthEvaluate(ctx context.Context, chain, attemptID, outcomeID, statusOverride string) (GroupRecoveryHealthOutcome, error) {
	if e := t.groupNativeRole(ctx, "finops_group_health_observer"); e != nil {
		return GroupRecoveryHealthOutcome{}, e
	}
	return t.groupRecoveryHealthEvaluate(ctx, chain, attemptID, outcomeID, statusOverride)
}
func (t *Tx) groupRecoveryHealthEvaluate(ctx context.Context, chain, attemptID, outcomeID, statusOverride string) (GroupRecoveryHealthOutcome, error) {
	var out GroupRecoveryHealthOutcome
	var raw []byte
	if !groupJournalValidID(outcomeID) || (statusOverride != "" && statusOverride != "ABANDONED") {
		return out, ErrGroupRecoveryHealth
	}
	if e := t.QueryRow(ctx, `SELECT raw_document FROM public.fleet_group_recovery_health_attempts WHERE tenant_id=$1 AND chain_id=$2 AND id=$3`, t.Tenant, chain, attemptID).Scan(&raw); e != nil {
		return out, e
	}
	var a GroupRecoveryHealthAttempt
	if groupJournalDecode(raw, &a) != nil {
		return out, ErrGroupRecoveryHealth
	}
	s, e := t.GroupRecoveryHealthSnapshot(ctx, chain, a.ObserverID, a.Workspace.Generation)
	if e != nil || s.Released || s.Baseline == nil || s.Baseline.ID != a.BaselineID || s.Command.ID != a.CommandID || s.TerminalID != a.TerminalID {
		return out, ErrGroupRecoveryHealth
	}
	rows, e := t.Query(ctx, `SELECT id FROM public.fleet_group_recovery_health_observations WHERE tenant_id=$1 AND chain_id=$2 AND attempt_id=$3 ORDER BY (document->'observation'->'receipt'->>'sequence')::numeric,id LIMIT 257`, t.Tenant, chain, attemptID)
	if e != nil {
		return out, e
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			return out, e
		}
		ids = append(ids, id)
	}
	e = rows.Err()
	rows.Close()
	if e != nil || len(ids) > 256 {
		return out, ErrGroupRecoveryHealth
	}
	current, e := t.recoveryObservations(ctx, chain, ids)
	if e != nil {
		return out, e
	}
	baseline, e := t.recoveryObservations(ctx, chain, s.Baseline.ObservationIDs)
	if e != nil {
		return out, e
	}
	out = GroupRecoveryHealthOutcome{SchemaVersion: "1", ID: outcomeID, TenantID: t.Tenant, ChainID: chain, AttemptID: attemptID, ObserverID: a.ObserverID, ObservationIDs: ids, SignedAt: s.Now}
	if statusOverride == "ABANDONED" {
		out.Status = "ABANDONED"
		out.Window = native.HealthWindow{Status: "BLOCKED", ReasonCodes: []string{"RECOVERY_OBSERVER_ATTEMPT_ABANDONED"}}
		return out, nil
	}
	if len(current) == 0 {
		return out, ErrGroupRecoveryHealth
	}
	binding := current[0].Observation.Receipt.Binding
	out.Window = native.EvaluateActivatedHealthWindow(s.View, s.Keys, s.View.Head.Head.Ref, s.Baseline.Anchor, native.ActivatedHealthDeployment{CommandID: a.CommandID, OperationID: a.OperationID, Fence: a.Fence, Kind: native.HealthRestorationObservation}, binding, recoveryReceiptBodies(baseline), recoveryReceiptBodies(current), s.Observer.Limits, s.Now)
	out.Status = out.Window.Status
	if out.Status == "BLOCKED" {
		repairable := len(out.Window.ReasonCodes) > 0
		for _, code := range out.Window.ReasonCodes {
			if code != "STAGE_OBSERVATION_WINDOW_INCOMPLETE" && code != "MONOTONIC_OBSERVATION_WINDOW_INCOMPLETE" && code != "HEALTH_SAMPLES_INSUFFICIENT" {
				repairable = false
			}
		}
		if repairable {
			return out, ErrGroupRecoveryHealth
		}
		out.Status = "INVALID"
	}
	return out, nil
}

func (t *Tx) GroupRecoveryHealthOutcomeAppend(ctx context.Context, identity GroupRecoveryHealthIdentity, envelope GroupRecoveryHealthOutcomeEnvelope, ref ff.ArtifactReference) (model.Document, bool, error) {
	type result struct {
		d      model.Document
		replay bool
	}
	r, e := groupJournalAtomic(ctx, t, func(tx *Tx) (result, error) {
		b := envelope.Outcome
		o, e := tx.recoveryObserverRole(ctx, b.ChainID, b.ObserverID, identity)
		if e != nil {
			return result{}, e
		}
		if b.SchemaVersion != "1" || b.TenantID != tx.Tenant || b.ChainID != o.ChainID || !groupRecoveryHealthVerify(groupRecoveryOutcomeDomain, b, envelope.Algorithm, envelope.Signature, o.PublicKey) {
			return result{}, ErrGroupRecoveryHealth
		}
		if d, replayed, e := tx.recoveryExisting(ctx, "fleet_group_recovery_health_outcomes", b.ChainID, b.ID, envelope); e != nil || replayed {
			return result{d, replayed}, e
		}
		override := ""
		if b.Status == "ABANDONED" {
			override = "ABANDONED"
		}
		expected, e := tx.GroupRecoveryHealthEvaluate(ctx, b.ChainID, b.AttemptID, b.ID, override)
		if e != nil {
			return result{}, e
		}
		expected.SignedAt = b.SignedAt
		if g.Digest(expected) != g.Digest(b) {
			return result{}, ErrGroupRecoveryHealth
		}
		var a GroupRecoveryHealthAttempt
		var ar []byte
		if e = tx.QueryRow(ctx, `SELECT raw_document FROM public.fleet_group_recovery_health_attempts WHERE tenant_id=$1 AND chain_id=$2 AND id=$3`, tx.Tenant, b.ChainID, b.AttemptID).Scan(&ar); e != nil {
			return result{}, e
		}
		if groupJournalDecode(ar, &a) != nil {
			return result{}, ErrGroupRecoveryHealth
		}
		if e = tx.recoveryArtifact(ctx, b.ChainID, a.CommandID, "HEALTH_VERDICT", ref); e != nil {
			return result{}, e
		}
		raw, hash, e := groupJournalBytes(envelope)
		if e != nil || ref.SHA256 != hash || ref.SizeBytes != int64(len(raw)) {
			return result{}, ErrGroupRecoveryHealth
		}
		_, e = tx.Exec(ctx, `INSERT INTO public.fleet_group_recovery_health_outcomes(tenant_id,chain_id,id,attempt_id,observer_id,status,artifact_id,document,raw_document,content_hash) VALUES($1,$2,$3,$4,$5,$6,$7,convert_from($8::bytea,'UTF8')::jsonb,$8,$9)`, tx.Tenant, b.ChainID, b.ID, b.AttemptID, b.ObserverID, b.Status, ref.ID, raw, hash)
		if e != nil {
			return result{}, e
		}
		d, e := tx.recoveryDocument(ctx, "fleet_group_recovery_health_outcomes", b.ChainID, b.ID)
		return result{d, false}, e
	})
	return r.d, r.replay, e
}

func (t *Tx) GroupRecoveryHealthSelect(ctx context.Context, chain, outcomeID string) (bool, error) {
	return groupJournalAtomic(ctx, t, func(tx *Tx) (bool, error) {
		if e := tx.groupNativeRole(ctx, "finops_group_ledger"); e != nil {
			return false, e
		}
		var exists bool
		if e := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM public.fleet_group_recovery_health_selections WHERE tenant_id=$1 AND chain_id=$2 AND outcome_id=$3)`, tx.Tenant, chain, outcomeID).Scan(&exists); e != nil || exists {
			return exists, e
		}
		var raw, key []byte
		if e := tx.QueryRow(ctx, `SELECT x.raw_document,k.public_key FROM public.fleet_group_recovery_health_outcomes x JOIN public.fleet_group_recovery_health_observers k ON k.tenant_id=x.tenant_id AND k.chain_id=x.chain_id AND k.id=x.observer_id WHERE x.tenant_id=$1 AND x.chain_id=$2 AND x.id=$3`, tx.Tenant, chain, outcomeID).Scan(&raw, &key); e != nil {
			return false, e
		}
		var envelope GroupRecoveryHealthOutcomeEnvelope
		if groupJournalDecode(raw, &envelope) != nil || envelope.Outcome.Status != "OBSERVED" || !groupRecoveryHealthVerify(groupRecoveryOutcomeDomain, envelope.Outcome, envelope.Algorithm, envelope.Signature, key) {
			return false, ErrGroupRecoveryHealth
		}
		expected, e := tx.groupRecoveryHealthEvaluate(ctx, chain, envelope.Outcome.AttemptID, outcomeID, "")
		if e != nil {
			return false, e
		}
		expected.SignedAt = envelope.Outcome.SignedAt
		if g.Digest(expected) != g.Digest(envelope.Outcome) {
			return false, ErrGroupRecoveryHealth
		}
		_, e = tx.Exec(ctx, `INSERT INTO public.fleet_group_recovery_health_selections(tenant_id,chain_id,outcome_id) VALUES($1,$2,$3)`, tx.Tenant, chain, outcomeID)
		return false, e
	})
}

// Pre034 capped acceptance snapshots contain this additive Go code but not the
// new schema. Probe without an error (and therefore without aborting the TX).
func (t *Tx) groupRecoveryHealthReleaseGuard(ctx context.Context, chain, head string) error {
	var installed bool
	if e := t.QueryRow(ctx, `SELECT to_regclass('public.fleet_group_recovery_health_selections') IS NOT NULL`).Scan(&installed); e != nil {
		return e
	}
	if !installed {
		return nil
	}
	var allowed bool
	if e := t.QueryRow(ctx, `SELECT coalesce(public.fleet_group_recovery_health_release($1,$2,$3),false)`, t.Tenant, chain, head).Scan(&allowed); e != nil {
		return e
	}
	if !allowed {
		return fmt.Errorf("%w: restored health not selected", ErrGroupRecoveryHealth)
	}
	return nil
}
