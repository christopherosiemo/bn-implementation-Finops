package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	ff "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetfixture"
	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/jackc/pgx/v5"
)

var ErrGroupArtifactInvalid = errors.New("GROUP_ARTIFACT_REFERENCE_INVALID")
var ErrGroupArtifactConflict = errors.New("GROUP_ARTIFACT_REFERENCE_CONFLICT")
var groupArtifactID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,255}$`)
var groupArtifactHash = regexp.MustCompile(`^[a-f0-9]{64}$`)
var groupArtifactVersion = regexp.MustCompile(`^[!-~]+$`)

type groupArtifactScope struct {
	SchemaVersion       string `json:"schema_version"`
	TenantID            string `json:"tenant_id"`
	ChainID             string `json:"chain_id"`
	CommandID           string `json:"command_id"`
	OperationID         string `json:"operation_id"`
	Fence               uint64 `json:"fence"`
	PreparedProgramID   string `json:"prepared_program_id"`
	ProposalID          string `json:"proposal_id"`
	ProfileID           string `json:"profile_id"`
	ProfileGeneration   string `json:"profile_generation"`
	ProducerImageSHA256 string `json:"producer_image_sha256"`
	KeyBindingID        string `json:"key_binding_id"`
	PipelineID          string `json:"pipeline_id"`
	PipelineKeySHA256   string `json:"pipeline_key_sha256"`
	SourceID            string `json:"source_id"`
	Issuer              string `json:"issuer"`
	Subject             string `json:"subject"`
	Audience            string `json:"audience"`
}
type groupArtifactDocument struct {
	SchemaVersion string               `json:"schema_version"`
	Scope         groupArtifactScope   `json:"scope"`
	Kind          string               `json:"kind"`
	Artifact      ff.ArtifactReference `json:"artifact"`
}

func groupArtifactKind(kind string) bool {
	switch kind {
	case "SAVED_PLAN", "PLAN_JSON", "BEFORE_NATIVE_STATE", "AFTER_NATIVE_STATE", "NATIVE_CAPTURE", "NATIVE_ARTIFACT_REVIEW", "NATIVE_OPERATION_PROOF", "HEALTH_RECEIPT", "HEALTH_BASELINE", "HEALTH_VERDICT", "GIT_PROOF_SET", "FIXTURE_CURRENT", "FIXTURE_DEPENDENCY", "FIXTURE_SLO":
		return true
	}
	return false
}

func (t *Tx) groupArtifactScope(ctx context.Context, chain, command string) (groupArtifactScope, error) {
	var s groupArtifactScope
	if !groupJournalValidID(chain) || !groupJournalValidID(command) {
		return s, ErrGroupArtifactInvalid
	}
	var raw []byte
	if err := t.QueryRow(ctx, `SELECT public.fleet_group_artifact_scope($1,$2,$3)`, t.Tenant, chain, command).Scan(&raw); err != nil {
		return s, err
	}
	if len(raw) == 0 || json.Unmarshal(raw, &s) != nil || s.SchemaVersion != "1" || s.TenantID != t.Tenant || s.ChainID != chain || s.CommandID != command || s.OperationID == "" || s.Fence == 0 || !groupArtifactHash.MatchString(s.ProducerImageSHA256) || !groupArtifactHash.MatchString(s.PipelineKeySHA256) {
		return s, ErrGroupArtifactInvalid
	}
	return s, nil
}

func validateGroupArtifactReference(scope groupArtifactScope, kind string, ref ff.ArtifactReference) error {
	if !groupArtifactKind(kind) || !groupArtifactID.MatchString(ref.ID) || !groupArtifactID.MatchString(ref.Bucket) || !groupArtifactHash.MatchString(ref.SHA256) || len(ref.VersionID) > 1024 || !groupArtifactVersion.MatchString(ref.VersionID) || ref.VersionID == "null" || ref.SizeBytes < 1 || ref.SizeBytes > 16<<20 || ref.Key != "tenant/"+scope.TenantID+"/fleet-group-fixture/"+scope.ProposalID+"/"+scope.ProfileGeneration+"/"+ref.ID+".encrypted" {
		return ErrGroupArtifactInvalid
	}
	return nil
}

func groupArtifactProjection(raw []byte, hash, writer string, at time.Time) (model.Document, error) {
	var d model.Document
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&d) != nil || d == nil {
		return nil, ErrGroupArtifactInvalid
	}
	d["content_hash"], d["writer_role"], d["created_at"] = hash, writer, at
	return d, nil
}

// GroupArtifactAppend is a private, authenticated pipeline boundary. The caller
// must first archive and authenticate the exact encrypted object version. This
// method stores no plaintext and does not attest a saved plan, approve health,
// authorize delivery or publish APPLIED. Captures may precede finalization; the
// ledger must independently match the selected references to its signed body.
func (t *Tx) GroupArtifactAppend(ctx context.Context, chain, command, kind string, identity FleetGroupPipelineIdentity, ref ff.ArtifactReference) (model.Document, bool, error) {
	type result struct {
		document model.Document
		replay   bool
	}
	out, err := groupJournalAtomic(ctx, t, func(tx *Tx) (result, error) {
		scope, e := tx.groupArtifactScope(ctx, chain, command)
		if e != nil {
			return result{}, e
		}
		if identity != (FleetGroupPipelineIdentity{scope.SourceID, scope.Issuer, scope.Subject, scope.Audience}) {
			return result{}, ErrGroupArtifactInvalid
		}
		if e = validateGroupArtifactReference(scope, kind, ref); e != nil {
			return result{}, e
		}
		body := groupArtifactDocument{"1", scope, kind, ref}
		raw, hash, e := groupJournalBytes(body)
		if e != nil {
			return result{}, e
		}
		// Serialize only the exact registry tuple; this lock never authorizes I/O.
		if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, tx.Tenant+":group-artifact:"+g.Digest([]string{chain, command, kind, ref.ID})); e != nil {
			return result{}, e
		}
		var old []byte
		var oldHash, writer string
		var at time.Time
		e = tx.QueryRow(ctx, `SELECT raw_document,content_hash,writer_role,created_at FROM public.fleet_group_artifacts WHERE tenant_id=$1 AND chain_id=$2 AND command_id=$3 AND kind=$4 AND id=$5`, tx.Tenant, chain, command, kind, ref.ID).Scan(&old, &oldHash, &writer, &at)
		if e == nil {
			if !bytes.Equal(old, raw) || oldHash != hash {
				return result{}, ErrGroupArtifactConflict
			}
			d, e := groupArtifactProjection(old, oldHash, writer, at)
			return result{d, true}, e
		}
		if !errors.Is(e, pgx.ErrNoRows) {
			return result{}, e
		}
		e = tx.QueryRow(ctx, `INSERT INTO public.fleet_group_artifacts(tenant_id,chain_id,command_id,operation_id,fence,kind,id,content_hash,document,raw_document) VALUES($1,$2,$3,$4,$5,$6,$7,$8,convert_from($9::bytea,'UTF8')::jsonb,$9) RETURNING writer_role,created_at`, tx.Tenant, chain, command, scope.OperationID, fmt.Sprint(scope.Fence), kind, ref.ID, hash, raw).Scan(&writer, &at)
		if e != nil {
			return result{}, e
		}
		d, e := groupArtifactProjection(raw, hash, writer, at)
		return result{d, false}, e
	})
	return out.document, out.replay, err
}

func (t *Tx) GroupArtifactGet(ctx context.Context, chain, command, kind, id string) (model.Document, error) {
	if !groupJournalValidID(chain) || !groupJournalValidID(command) || !groupArtifactKind(kind) || !groupArtifactID.MatchString(id) {
		return nil, ErrGroupArtifactInvalid
	}
	var raw []byte
	var hash, writer string
	var at time.Time
	e := t.QueryRow(ctx, `SELECT raw_document,content_hash,writer_role,created_at FROM public.fleet_group_artifacts WHERE tenant_id=$1 AND chain_id=$2 AND command_id=$3 AND kind=$4 AND id=$5`, t.Tenant, chain, command, kind, id).Scan(&raw, &hash, &writer, &at)
	if e != nil {
		return nil, e
	}
	return groupArtifactProjection(raw, hash, writer, at)
}

// Page uses an immutable ID cursor inside the exact command/kind scope. A full
// page is not a complete history; callers continue until the page is short.
func (t *Tx) GroupArtifactPage(ctx context.Context, chain, command, kind, after string, limit int) ([]model.Document, error) {
	if !groupJournalValidID(chain) || !groupJournalValidID(command) || !groupArtifactKind(kind) || after != "" && !groupArtifactID.MatchString(after) || limit < 1 || limit > 101 {
		return nil, ErrGroupArtifactInvalid
	}
	rows, e := t.Query(ctx, `SELECT raw_document,content_hash,writer_role,created_at FROM public.fleet_group_artifacts WHERE tenant_id=$1 AND chain_id=$2 AND command_id=$3 AND kind=$4 AND id>$5 ORDER BY id LIMIT $6`, t.Tenant, chain, command, kind, after, limit)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []model.Document{}
	for rows.Next() {
		var raw []byte
		var hash, writer string
		var at time.Time
		if e = rows.Scan(&raw, &hash, &writer, &at); e != nil {
			return nil, e
		}
		d, e := groupArtifactProjection(raw, hash, writer, at)
		if e != nil {
			return nil, e
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// RequireFinalized binds four selected capture IDs to the exact currently
// issued artifact. It does not accept a caller's finalization as authority and
// does not turn an old reference into a fresh delivery permit. The caller must
// hold its current-head/fence transaction through authorization, then perform
// producer readback and native one-shot checks immediately before external I/O.
func (t *Tx) GroupArtifactRequireFinalized(ctx context.Context, chain, command string, artifact g.GitArtifact, refs map[string]string) error {
	if !groupJournalValidID(chain) || !groupJournalValidID(command) || len(refs) != 4 {
		return ErrGroupArtifactInvalid
	}
	var raw []byte
	if e := t.QueryRow(ctx, `SELECT public.fleet_group_artifact_finalized($1,$2,$3)`, t.Tenant, chain, command).Scan(&raw); e != nil {
		return e
	}
	var issued g.GitArtifact
	if len(raw) == 0 || json.Unmarshal(raw, &issued) != nil || g.Digest(issued) != g.Digest(artifact) {
		return ErrGroupArtifactInvalid
	}
	expected := map[string]string{"SAVED_PLAN": artifact.SavedPlanSHA256, "PLAN_JSON": artifact.PlanJSONSHA256, "BEFORE_NATIVE_STATE": artifact.BeforeStateSHA256, "NATIVE_ARTIFACT_REVIEW": artifact.Receipt.SHA256}
	for kind, hash := range expected {
		id, ok := refs[kind]
		if !ok || !groupArtifactHash.MatchString(hash) || kind == "NATIVE_ARTIFACT_REVIEW" && id != artifact.Receipt.ID {
			return ErrGroupArtifactInvalid
		}
		d, e := t.GroupArtifactGet(ctx, chain, command, kind, id)
		if e != nil {
			return e
		}
		raw, e := json.Marshal(d["artifact"])
		if e != nil {
			return e
		}
		var ref ff.ArtifactReference
		if json.Unmarshal(raw, &ref) != nil || ref.SHA256 != hash {
			return ErrGroupArtifactInvalid
		}
	}
	return nil
}
