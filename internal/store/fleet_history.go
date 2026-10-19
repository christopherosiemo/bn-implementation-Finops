package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleethistory"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/jackc/pgx/v5"
)

var ErrFleetHistorySource = errors.New("FLEET_HISTORY_SOURCE_UNAVAILABLE")
var ErrFleetHistorySourceBusy = errors.New("FLEET_HISTORY_SOURCE_BUSY")
var ErrFleetHistoryBounds = errors.New("FLEET_HISTORY_POPULATION_LIMIT")

const fleetHistoryLimit = 50000

func fleetHistoryBytes(v any) ([]byte, string, error) {
	b, e := json.Marshal(v)
	h := sha256.Sum256(b)
	return b, hex.EncodeToString(h[:]), e
}

// Typed payloads are deliberately separate from server metadata. The immutable
// payload hashes never include a projected writer_role or created_at field.
func FleetHistoryRegistrationDocument(d model.Document) (fleethistory.Registration, error) {
	b, e := json.Marshal(d["registration"])
	if e != nil {
		return fleethistory.Registration{}, e
	}
	return fleethistory.DecodeRegistration(b)
}
func FleetHistoryDefinitionDocument(r fleethistory.Registration, d model.Document) (fleethistory.DemandDefinition, error) {
	b, e := json.Marshal(d["definition"])
	if e != nil {
		return fleethistory.DemandDefinition{}, e
	}
	return fleethistory.DecodeDemandDefinition(r, b)
}
func FleetHistoryObservationDocument(r fleethistory.Registration, d model.Document) (fleethistory.MembershipObservation, error) {
	b, e := json.Marshal(d["observation"])
	if e != nil {
		return fleethistory.MembershipObservation{}, e
	}
	return fleethistory.DecodeObservation(r, b)
}

func (t *Tx) fleetHistoryLock(ctx context.Context, id string) error {
	_, e := t.Exec(ctx, "SELECT fleet_history_lock($1,$2)", t.Tenant, id)
	return e
}
func (t *Tx) fleetHistorySourceLock(ctx context.Context, id string) error {
	var ok bool
	// A busy source returns a typed error without aborting this transaction. The
	// SQL helper repeats the shared guard for direct callers before its row lock.
	e := t.QueryRow(ctx, "SELECT pg_try_advisory_xact_lock_shared(hashtextextended($1,0))", t.Tenant+":trusted-source:"+id).Scan(&ok)
	if e != nil {
		return e
	}
	if !ok {
		return ErrFleetHistorySourceBusy
	}
	e = t.QueryRow(ctx, "SELECT fleet_history_source_lock($1,$2)", t.Tenant, id).Scan(&ok)
	if e != nil {
		return e
	}
	if !ok {
		return ErrFleetHistorySource
	}
	return nil
}
func fleetHistoryPageLimit(limit int) (int, error) {
	// Public handlers cap their requested page at 100; one extra row is allowed
	// internally solely to compute the next cursor without dropping a reference.
	if limit < 1 || limit > 101 {
		return 0, ErrFleetHistoryBounds
	}
	return limit, nil
}

func (t *Tx) FleetHistoryRegistrationAppend(ctx context.Context, expected int64, r fleethistory.Registration) (model.Document, error) {
	if r.Binding.TenantID != t.Tenant || r.Version != expected+1 {
		return nil, ErrConflict
	}
	if e := fleethistory.ValidateRegistration(r); e != nil {
		return nil, e
	}
	if e := t.fleetHistoryLock(ctx, r.ID); e != nil {
		return nil, e
	}
	if e := t.fleetHistorySourceLock(ctx, r.SourceID); e != nil {
		return nil, e
	}
	var sourceVersion int64
	var sourceHash string
	var available bool
	if e := t.QueryRow(ctx, `SELECT version,fleet_history_source_config(document),coalesce((document->>'enabled')::boolean,false) AND NOT coalesce((document->>'revoked')::boolean,false) AND document->>'region'=$3 AND (document->>'payer_account_id'=$4 OR document->'usage_account_ids' ? $4) FROM source_registrations WHERE tenant_id=$1 AND id=$2`, t.Tenant, r.SourceID, r.Binding.Region, r.Binding.AccountID).Scan(&sourceVersion, &sourceHash, &available); e != nil {
		return nil, e
	}
	if !available || sourceVersion != r.SourceRegistrationVersion || sourceHash != r.SourceConfigHash {
		return nil, ErrFleetHistorySource
	}
	var current int64
	if e := t.QueryRow(ctx, "SELECT coalesce(max(version),0) FROM fleet_history_registrations WHERE tenant_id=$1 AND id=$2", t.Tenant, r.ID).Scan(&current); e != nil {
		return nil, e
	}
	if current != expected {
		return nil, ErrConflict
	}
	if current > 0 {
		prior, e := t.FleetHistoryRegistrationGet(ctx, r.ID)
		if e != nil {
			return nil, e
		}
		old, e := FleetHistoryRegistrationDocument(prior)
		if e != nil {
			return nil, e
		}
		if old.Binding != r.Binding || old.FleetID != r.FleetID || old.ASGARN != r.ASGARN {
			return nil, ErrConflict
		}
	}
	b, h, e := fleetHistoryBytes(r)
	if e != nil {
		return nil, e
	}
	_, e = t.Exec(ctx, `INSERT INTO fleet_history_registrations(tenant_id,id,version,workload_id,source_id,content_hash,document,raw_document) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, t.Tenant, r.ID, r.Version, r.Binding.WorkloadID, r.SourceID, h, b, b)
	if e != nil {
		return nil, e
	}
	return t.FleetHistoryRegistrationGet(ctx, r.ID)
}
func (t *Tx) FleetHistoryRegistrationGet(ctx context.Context, id string) (model.Document, error) {
	return t.sourceOne(ctx, `SELECT jsonb_build_object('id',id,'version',version,'registration',document,'hash',content_hash,'created_at',created_at,'writer_role',writer_role) FROM fleet_history_registrations WHERE tenant_id=$1 AND id=$2 ORDER BY version DESC LIMIT 1`, t.Tenant, id)
}
func (t *Tx) FleetHistoryRegistrationPage(ctx context.Context, workload, after string, limit int) ([]model.Document, error) {
	if _, e := fleetHistoryPageLimit(limit); e != nil {
		return nil, e
	}
	return t.sourceRows(ctx, `SELECT jsonb_build_object('id',id,'version',version,'registration',document,'hash',content_hash,'created_at',created_at,'writer_role',writer_role) FROM (SELECT DISTINCT ON(id) * FROM fleet_history_registrations WHERE tenant_id=$1 ORDER BY id,version DESC) r WHERE ($2='' OR workload_id=$2) AND id>$3 ORDER BY id LIMIT $4`, t.Tenant, workload, after, limit)
}
func (t *Tx) FleetDemandDefinitionAppend(ctx context.Context, registrationID string, expected int64, d fleethistory.DemandDefinition) (model.Document, error) {
	if e := t.fleetHistoryLock(ctx, registrationID); e != nil {
		return nil, e
	}
	if e := t.fleetHistoryLock(ctx, "definition:"+d.ID); e != nil {
		return nil, e
	}
	rd, e := t.FleetHistoryRegistrationGet(ctx, registrationID)
	if e != nil {
		return nil, e
	}
	r, e := FleetHistoryRegistrationDocument(rd)
	if e != nil {
		return nil, e
	}
	if d.Binding.TenantID != t.Tenant || d.Version != expected+1 {
		return nil, ErrConflict
	}
	if e = fleethistory.ValidateDemandDefinition(r, d); e != nil {
		return nil, e
	}
	if d.SourceSystem != "ACTIVITY_SOURCE" || d.Metric != "activity.Completed" || d.ValueField != "COMPLETED" || d.Temporality != "DELTA" {
		return nil, ErrFleetHistorySource
	}
	var current int64
	if e = t.QueryRow(ctx, "SELECT coalesce(max(version),0) FROM fleet_demand_definitions WHERE tenant_id=$1 AND id=$2", t.Tenant, d.ID).Scan(&current); e != nil {
		return nil, e
	}
	if current != expected {
		return nil, ErrConflict
	}
	if current > 0 {
		prior, e := t.FleetDemandDefinitionGet(ctx, d.ID)
		if e != nil {
			return nil, e
		}
		if model.String(prior, "registration_id") != registrationID {
			return nil, ErrConflict
		}
	}
	b, h, e := fleetHistoryBytes(d)
	if e != nil {
		return nil, e
	}
	_, e = t.Exec(ctx, `INSERT INTO fleet_demand_definitions(tenant_id,id,version,registration_id,registration_version,workload_id,source_id,content_hash,document,raw_document) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, t.Tenant, d.ID, d.Version, r.ID, r.Version, d.Binding.WorkloadID, d.SourceID, h, b, b)
	if e != nil {
		return nil, e
	}
	return t.FleetDemandDefinitionGet(ctx, d.ID)
}
func (t *Tx) FleetDemandDefinitionGet(ctx context.Context, id string) (model.Document, error) {
	return t.sourceOne(ctx, `SELECT jsonb_build_object('id',id,'version',version,'registration_id',registration_id,'registration_version',registration_version,'definition',document,'hash',content_hash,'created_at',created_at,'writer_role',writer_role) FROM fleet_demand_definitions WHERE tenant_id=$1 AND id=$2 ORDER BY version DESC LIMIT 1`, t.Tenant, id)
}
func (t *Tx) FleetDemandDefinitionPage(ctx context.Context, registrationID, after string, limit int) ([]model.Document, error) {
	if _, e := fleetHistoryPageLimit(limit); e != nil {
		return nil, e
	}
	return t.sourceRows(ctx, `SELECT jsonb_build_object('id',id,'version',version,'registration_id',registration_id,'registration_version',registration_version,'definition',document,'hash',content_hash,'created_at',created_at,'writer_role',writer_role) FROM (SELECT DISTINCT ON(id) * FROM fleet_demand_definitions WHERE tenant_id=$1 ORDER BY id,version DESC) d WHERE registration_id=$2 AND id>$3 ORDER BY id LIMIT $4`, t.Tenant, registrationID, after, limit)
}
func (t *Tx) FleetHistoryObservationAppend(ctx context.Context, o fleethistory.MembershipObservation) (model.Document, bool, error) {
	if e := t.fleetHistoryLock(ctx, o.RegistrationID); e != nil {
		return nil, false, e
	}
	var raw []byte
	e := t.QueryRow(ctx, `SELECT raw_document FROM fleet_history_registrations WHERE tenant_id=$1 AND id=$2 AND version=$3`, t.Tenant, o.RegistrationID, o.RegistrationVersion).Scan(&raw)
	if e != nil {
		return nil, false, e
	}
	r, e := fleethistory.DecodeRegistration(raw)
	if e != nil {
		return nil, false, e
	}
	if e = fleethistory.ValidateObservation(r, o); e != nil {
		return nil, false, e
	}
	b, h, e := fleetHistoryObservationBytes(o)
	if e != nil {
		return nil, false, e
	}
	var existingID, existingHash string
	e = t.QueryRow(ctx, `SELECT id,content_hash FROM fleet_history_observations WHERE tenant_id=$1 AND (id=$2 OR (registration_id=$3 AND registration_version=$4 AND native_receipt_id=$5)) ORDER BY id LIMIT 1`, t.Tenant, o.ID, o.RegistrationID, o.RegistrationVersion, o.Source.ReceiptID).Scan(&existingID, &existingHash)
	if e == nil {
		if existingID != o.ID || existingHash != h {
			return nil, false, ErrConflict
		}
		d, e := t.FleetHistoryObservationGet(ctx, existingID)
		return d, true, e
	}
	if !errors.Is(e, pgx.ErrNoRows) {
		return nil, false, e
	}
	var corrects any
	if o.CorrectsID != "" {
		corrects = o.CorrectsID
	}
	// PostgreSQL timestamps have microsecond precision. Derive the indexed
	// timestamp with PostgreSQL's own JSON cast, which is also used by the SQL
	// guard; pgx's binary time encoding truncates rather than rounds nanos.
	// The immutable JSON/raw body still retains the original native nanoseconds.
	_, e = t.Exec(ctx, `INSERT INTO fleet_history_observations(tenant_id,id,registration_id,registration_version,native_receipt_id,observed_at,corrects_id,content_hash,document,raw_document) VALUES($1,$2,$3,$4,$5,($8::jsonb->>'observed_at')::timestamptz,$6,$7,$8,$9)`, t.Tenant, o.ID, o.RegistrationID, o.RegistrationVersion, o.Source.ReceiptID, corrects, h, b, b)
	if e != nil {
		return nil, false, e
	}
	d, e := t.FleetHistoryObservationGet(ctx, o.ID)
	return d, false, e
}

// Match the pure domain's semantic hash while retaining every native timestamp
// and provenance field. Member ordering and equivalent UTC offsets are not a
// different observation; changed values or object versions remain conflicts.
func fleetHistoryObservationBytes(o fleethistory.MembershipObservation) ([]byte, string, error) {
	b, _ := json.Marshal(o)
	var normalized fleethistory.MembershipObservation
	_ = json.Unmarshal(b, &normalized)
	normalized.ObservedAt = normalized.ObservedAt.UTC()
	normalized.ReceivedAt = normalized.ReceivedAt.UTC()
	normalized.Source.CapturedAt = normalized.Source.CapturedAt.UTC()
	for i := range normalized.Members {
		if normalized.Members[i].LaunchTime != nil {
			v := normalized.Members[i].LaunchTime.UTC()
			normalized.Members[i].LaunchTime = &v
		}
		if normalized.Members[i].Hardware != nil {
			normalized.Members[i].Hardware.CapturedAt = normalized.Members[i].Hardware.CapturedAt.UTC()
		}
	}
	sort.Slice(normalized.Members, func(i, j int) bool { return normalized.Members[i].InstanceID < normalized.Members[j].InstanceID })
	return fleetHistoryBytes(normalized)
}
func (t *Tx) FleetHistoryObservationGet(ctx context.Context, id string) (model.Document, error) {
	return t.sourceOne(ctx, `SELECT jsonb_build_object('id',id,'registration_id',registration_id,'registration_version',registration_version,'observation',document,'hash',content_hash,'created_at',created_at,'writer_role',writer_role) FROM fleet_history_observations WHERE tenant_id=$1 AND id=$2`, t.Tenant, id)
}
func (t *Tx) FleetHistoryObservationPage(ctx context.Context, registrationID, after string, limit int) ([]model.Document, error) {
	if _, e := fleetHistoryPageLimit(limit); e != nil {
		return nil, e
	}
	return t.sourceRows(ctx, `SELECT jsonb_build_object('id',id,'registration_id',registration_id,'registration_version',registration_version,'observation',document,'hash',content_hash,'created_at',created_at,'writer_role',writer_role) FROM fleet_history_observations WHERE tenant_id=$1 AND registration_id=$2 AND id>$3 ORDER BY id LIMIT $4`, t.Tenant, registrationID, after, limit)
}

// FleetHistorySourceReference binds a real issued native receipt, not its API
// projection. Metadata added by SourceReceiptGet is excluded from CanonicalHash.
func (t *Tx) FleetHistorySourceReference(ctx context.Context, receiptID, kind, target string) (fleethistory.SourceRef, error) {
	var raw []byte
	var sourceID string
	e := t.QueryRow(ctx, "SELECT source_id FROM source_receipts WHERE tenant_id=$1 AND id=$2", t.Tenant, receiptID).Scan(&sourceID)
	if e != nil {
		return fleethistory.SourceRef{}, e
	}
	if e = t.fleetHistorySourceLock(ctx, sourceID); e != nil {
		return fleethistory.SourceRef{}, e
	}
	var hash string
	e = t.QueryRow(ctx, "SELECT document,fleet_history_json_hash(document) FROM source_receipts WHERE tenant_id=$1 AND id=$2 AND kind=$3 AND writer_role='finops_ingester'", t.Tenant, receiptID, kind).Scan(&raw, &hash)
	if e != nil {
		return fleethistory.SourceRef{}, e
	}
	var d struct {
		Binding     fleethistory.Binding `json:"binding"`
		RevisionID  string               `json:"revision_id"`
		Version     int64                `json:"registration_version"`
		ConfigHash  string               `json:"config_hash"`
		CollectedAt time.Time            `json:"collected_at"`
		Raw         struct {
			Bucket, Key string
			VersionID   string `json:"version_id"`
			SHA         string `json:"body_sha256"`
		} `json:"raw_object"`
	}
	if e = json.Unmarshal(raw, &d); e != nil {
		return fleethistory.SourceRef{}, e
	}
	ref := fleethistory.SourceRef{Kind: kind, Binding: d.Binding, SourceID: sourceID, SourceSystem: "AWS_SOURCE_CONNECTION", RevisionID: d.RevisionID, SourceRegistrationVersion: &d.Version, ConfigHash: d.ConfigHash, ReceiptID: receiptID, Target: target, RawSHA256: d.Raw.SHA, CanonicalHash: hash, CapturedAt: d.CollectedAt, StorageKind: "VERSIONED_OBJECT", Archive: &fleethistory.ArchiveRef{Bucket: d.Raw.Bucket, Key: d.Raw.Key, VersionID: d.Raw.VersionID, SHA256: d.Raw.SHA}}
	b, _ := json.Marshal(ref)
	binding, _ := json.Marshal(d.Binding)
	var verified []byte
	e = t.QueryRow(ctx, "SELECT fleet_history_native_reference($1,$2::jsonb,$3::jsonb,$4,$5)", t.Tenant, b, binding, kind, target).Scan(&verified)
	return ref, e
}

func fleetHistoryUnavailable(what string) error {
	return fmt.Errorf("%w: %s", ErrFleetHistorySource, what)
}
