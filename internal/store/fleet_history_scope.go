package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleethistory"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

// The private pure evaluator clones/hashes its resolved input. Bound source
// bytes before decoding or appending populations so compact output cannot hide
// an unbounded in-memory input. Dense histories must remain unavailable.
const fleetHistoryByteLimit int64 = 16 << 20

type fleetHistoryBudget struct{ used int64 }

func (b *fleetHistoryBudget) add(n int64) error {
	if n < 0 || n > fleetHistoryByteLimit-b.used {
		return ErrFleetHistoryBounds
	}
	b.used += n
	return nil
}

// No caller timestamps, count arrays or source states enter scope capture.
// Historical queries are fourteen complete UTC days. Today's current ingress is
// never backfilled into those days, even in a fixture deployment.
func (t *Tx) FleetHistoryDemandSamples(ctx context.Context, definitionID string, start, end time.Time) ([]fleethistory.DemandSample, error) {
	doc, e := t.FleetDemandDefinitionGet(ctx, definitionID)
	if e != nil {
		return nil, e
	}
	rd, e := t.FleetHistoryRegistrationGet(ctx, model.String(doc, "registration_id"))
	if e != nil {
		return nil, e
	}
	r, e := FleetHistoryRegistrationDocument(rd)
	if e != nil {
		return nil, e
	}
	d, e := FleetHistoryDefinitionDocument(r, doc)
	if e != nil {
		return nil, e
	}
	return t.fleetHistoryDemandSamples(ctx, r, d, start, end)
}
func (t *Tx) fleetHistoryDemandSamples(ctx context.Context, r fleethistory.Registration, d fleethistory.DemandDefinition, start, end time.Time) ([]fleethistory.DemandSample, error) {
	return t.fleetHistoryDemandBounded(ctx, r, d, start, end, &fleetHistoryBudget{})
}
func (t *Tx) fleetHistoryDemandBounded(ctx context.Context, r fleethistory.Registration, d fleethistory.DemandDefinition, start, end time.Time, budget *fleetHistoryBudget) ([]fleethistory.DemandSample, error) {
	if !start.Before(end) || end.Sub(start) > 14*24*time.Hour || d.SourceSystem != "ACTIVITY_SOURCE" || d.Metric != "activity.Completed" || d.ValueField != "COMPLETED" || d.Temporality != "DELTA" {
		return nil, ErrFleetHistorySource
	}
	rows, e := t.Query(ctx, `SELECT id,document,raw_body,body_sha256,interval_start,interval_end,received_at,fleet_history_json_hash(document) FROM activity_receipts WHERE tenant_id=$1 AND source_id=$2 AND interval_start>=$3 AND interval_end<=$4 ORDER BY interval_start,id LIMIT 50001`, t.Tenant, d.SourceID, start, end)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []fleethistory.DemandSample{}
	for rows.Next() {
		var id, bodyHash, canonical string
		var doc, raw []byte
		var a, b, received time.Time
		if e = rows.Scan(&id, &doc, &raw, &bodyHash, &a, &b, &received, &canonical); e != nil {
			return nil, e
		}
		if e = budget.add(int64(len(doc)) + int64(len(raw))); e != nil {
			return nil, e
		}
		if len(out) >= fleetHistoryLimit {
			return nil, ErrFleetHistoryBounds
		}
		h := sha256.Sum256(raw)
		if hex.EncodeToString(h[:]) != bodyHash {
			return nil, ErrFleetHistorySource
		}
		var original, mapDoc map[string]json.RawMessage
		if e = json.Unmarshal(raw, &original); e != nil {
			return nil, e
		}
		if e = json.Unmarshal(doc, &mapDoc); e != nil {
			return nil, e
		}
		var interval ActivityInterval
		if e = json.Unmarshal(doc, &interval); e != nil {
			return nil, e
		}
		if interval.SourceID != d.SourceID || interval.WorkloadID != r.Binding.WorkloadID || interval.MetricDefinition.ID != d.MetricDefinitionID || interval.MetricDefinition.Version != d.MetricDefinitionVersion || interval.MetricDefinition.Unit != d.Unit || !interval.IntervalStart.Equal(a) || !interval.IntervalEnd.Equal(b) {
			return nil, ErrFleetHistorySource
		}
		var value *string
		// A missing native field remains missing. Decode to an integer only after
		// independently checking both original body and guarded canonical receipt.
		if len(original["completed"]) > 0 && string(original["completed"]) != "null" && len(mapDoc["completed"]) > 0 {
			var rawNumber, canonicalNumber json.Number
			if json.Unmarshal(original["completed"], &rawNumber) == nil && json.Unmarshal(mapDoc["completed"], &canonicalNumber) == nil {
				n, err := rawNumber.Int64()
				if err == nil && n >= 0 && rawNumber.String() == canonicalNumber.String() {
					s := strconv.FormatInt(n, 10)
					value = &s
				}
			}
		}
		s := fleethistory.DemandSample{SchemaVersion: "1", ID: id, DefinitionID: d.ID, DefinitionVersion: d.Version, DefinitionHash: fleethistory.DefinitionHash(d), MetricDefinitionID: d.MetricDefinitionID, MetricDefinitionVersion: d.MetricDefinitionVersion, Start: a.UTC(), Time: b.UTC(), ReceivedAt: received.UTC(), Value: value, Source: fleethistory.SourceRef{Kind: "INDEPENDENT_COMPLETED_WORK", Binding: r.Binding, SourceID: d.SourceID, SourceSystem: "ACTIVITY_SOURCE", ConfigHash: d.SourceConfigHash, ReceiptID: id, Target: r.Binding.WorkloadID, RawSHA256: bodyHash, CanonicalHash: canonical, CapturedAt: received.UTC(), StorageKind: "POSTGRES_RECEIPT"}}
		if e = fleethistory.ValidateDemandSample(r, d, s); e != nil {
			return nil, e
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (t *Tx) fleetHistorySourceStates(ctx context.Context, r fleethistory.Registration, d fleethistory.DemandDefinition, observations []fleethistory.MembershipObservation, now time.Time) ([]fleethistory.SourceState, error) {
	targets := map[string]string{r.SourceID: r.SourceConfigHash}
	for _, o := range observations {
		targets[o.Source.SourceID] = o.Source.ConfigHash
		for _, m := range o.Members {
			if m.Hardware != nil {
				targets[m.Hardware.SourceID] = m.Hardware.ConfigHash
			}
		}
	}
	ids := make([]string, 0, len(targets))
	if len(targets) > 1024 {
		return nil, ErrFleetHistoryBounds
	}
	for id := range targets {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	states := []fleethistory.SourceState{}
	for _, id := range ids {
		if e := t.fleetHistorySourceLock(ctx, id); e != nil {
			return nil, e
		}
		s, e := t.SourceGet(ctx, id)
		if e != nil {
			return nil, e
		}
		var version int64
		var hash string
		if e = t.QueryRow(ctx, `SELECT version,fleet_history_source_config(document) FROM source_registrations WHERE tenant_id=$1 AND id=$2`, t.Tenant, id).Scan(&version, &hash); e != nil {
			return nil, e
		}
		status := "ACTIVE"
		if !model.Bool(s, "enabled") || model.Bool(s, "revoked") {
			status = "REVOKED"
		} else if hash != targets[id] {
			status = "SUPERSEDED"
		} else {
			last, e := time.Parse(time.RFC3339Nano, model.String(s, "last_sync_at"))
			if model.String(s, "status") != "HEALTHY" || e != nil || last.After(now.Add(5*time.Second)) || now.Sub(last) > 5*time.Minute {
				status = "DEGRADED"
			}
		}
		states = append(states, fleethistory.SourceState{SourceID: id, SourceSystem: "AWS_SOURCE_CONNECTION", SourceRegistrationVersion: &version, ConfigHash: hash, Binding: r.Binding, Status: status, CheckedAt: now})
	}
	var sourceRaw []byte
	var sourceHash string
	e := t.QueryRow(ctx, `SELECT document,fleet_history_json_hash(document) FROM activity_sources WHERE tenant_id=$1 AND id=$2`, t.Tenant, d.SourceID).Scan(&sourceRaw, &sourceHash)
	if e != nil {
		return nil, e
	}
	var source ActivitySource
	if e = json.Unmarshal(sourceRaw, &source); e != nil {
		return nil, e
	}
	status := "ACTIVE"
	if !source.Enabled {
		status = "REVOKED"
	} else if sourceHash != d.SourceConfigHash {
		status = "SUPERSEDED"
	}
	states = append(states, fleethistory.SourceState{SourceID: d.SourceID, SourceSystem: "ACTIVITY_SOURCE", ConfigHash: sourceHash, Binding: r.Binding, Status: status, CheckedAt: now})
	return states, nil
}

type fleetScopeRef struct {
	kind, id string
	document model.Document
	raw      []byte
	hash     string
}

func fleetHistoryPreview[T any](items []T) model.Document {
	b, h, _ := fleetHistoryBytes(items)
	_ = b
	preview := items
	if len(preview) > 16 {
		preview = preview[:16]
	}
	return model.Document{"count": len(items), "hash": h, "preview": preview, "truncated": len(items) > len(preview)}
}

func (t *Tx) FleetHistoryScopeCapture(ctx context.Context, registrationID, definitionID string) (model.Document, error) {
	if e := t.fleetHistoryLock(ctx, registrationID); e != nil {
		return nil, e
	}
	rdoc, e := t.FleetHistoryRegistrationGet(ctx, registrationID)
	if e != nil {
		return nil, e
	}
	r, e := FleetHistoryRegistrationDocument(rdoc)
	if e != nil {
		return nil, e
	}
	ddoc, e := t.FleetDemandDefinitionGet(ctx, definitionID)
	if e != nil {
		return nil, e
	}
	d, e := FleetHistoryDefinitionDocument(r, ddoc)
	if e != nil {
		return nil, e
	}
	if model.String(ddoc, "registration_id") != registrationID || int64(model.Number(ddoc, "registration_version")) != r.Version {
		return nil, ErrConflict
	}
	// Freeze sync and revocation BEFORE the first observation/head selection.
	if e = t.fleetHistorySourceLock(ctx, r.SourceID); e != nil {
		return nil, e
	}
	var now time.Time
	if e = t.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now); e != nil {
		return nil, e
	}
	now = now.UTC()
	end := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	start := end.AddDate(0, 0, -14)
	var observationBytes, activityBytes, observationCount, activityCount int64
	if e = t.QueryRow(ctx, `SELECT coalesce(sum(octet_length(raw_document)),0)::bigint,count(*) FROM fleet_history_observations WHERE tenant_id=$1 AND registration_id=$2 AND registration_version=$3 AND observed_at>=$4 AND observed_at<=$5`, t.Tenant, r.ID, r.Version, start, end).Scan(&observationBytes, &observationCount); e != nil {
		return nil, e
	}
	if e = t.QueryRow(ctx, `SELECT coalesce(sum(octet_length(raw_body)+octet_length(document::text)),0)::bigint,count(*) FROM activity_receipts WHERE tenant_id=$1 AND source_id=$2 AND interval_start>=$3 AND interval_end<=$4`, t.Tenant, d.SourceID, start, end).Scan(&activityBytes, &activityCount); e != nil {
		return nil, e
	}
	preflight := &fleetHistoryBudget{}
	if e = preflight.add(observationBytes); e != nil {
		return nil, e
	}
	if e = preflight.add(activityBytes); e != nil {
		return nil, e
	}
	if observationCount+activityCount+4 > fleetHistoryLimit {
		return nil, ErrFleetHistoryBounds
	}
	budget := &fleetHistoryBudget{}
	rows, e := t.Query(ctx, `SELECT raw_document,content_hash FROM fleet_history_observations WHERE tenant_id=$1 AND registration_id=$2 AND registration_version=$3 AND observed_at>=$4 AND observed_at<=$5 ORDER BY observed_at,id LIMIT 50001`, t.Tenant, r.ID, r.Version, start, end)
	if e != nil {
		return nil, e
	}
	obs := []fleethistory.MembershipObservation{}
	obsHashes := map[string]string{}
	for rows.Next() {
		var raw []byte
		var hash string
		if e = rows.Scan(&raw, &hash); e != nil {
			rows.Close()
			return nil, e
		}
		if e = budget.add(int64(len(raw))); e != nil {
			rows.Close()
			return nil, e
		}
		if len(obs) >= fleetHistoryLimit {
			rows.Close()
			return nil, ErrFleetHistoryBounds
		}
		o, err := fleethistory.DecodeObservation(r, raw)
		if err != nil {
			rows.Close()
			return nil, err
		}
		obs = append(obs, o)
		obsHashes[o.ID] = hash
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	states, e := t.fleetHistorySourceStates(ctx, r, d, obs, now)
	if e != nil {
		return nil, e
	}
	demand, e := t.fleetHistoryDemandBounded(ctx, r, d, start, end, budget)
	if e != nil {
		return nil, e
	}
	input := fleethistory.Input{Registration: r, Definition: d, Sources: states, Observations: obs, Demand: demand, Start: start, End: end, AsOf: now}
	a, e := fleethistory.Analyze(input)
	if e != nil {
		return nil, e
	}
	refs := []fleetScopeRef{{kind: "REGISTRATION", id: r.ID, document: model.Document{"id": r.ID, "version": r.Version, "hash": model.String(rdoc, "hash")}}, {kind: "DEFINITION", id: d.ID, document: model.Document{"id": d.ID, "version": d.Version, "hash": model.String(ddoc, "hash")}}}
	for _, o := range obs {
		refs = append(refs, fleetScopeRef{kind: "OBSERVATION", id: o.ID, document: model.Document{"id": o.ID, "hash": obsHashes[o.ID]}})
	}
	for _, s := range demand {
		refs = append(refs, fleetScopeRef{kind: "DEMAND_RECEIPT", id: s.ID, document: model.Document{"id": s.ID, "source_id": s.Source.SourceID, "body_sha256": s.Source.RawSHA256, "canonical_hash": s.Source.CanonicalHash, "sample_hash": fleethistory.SampleHash(s)}})
	}
	for _, s := range states {
		b, _ := json.Marshal(s)
		state := model.Document{}
		_ = json.Unmarshal(b, &state)
		refs = append(refs, fleetScopeRef{kind: "SOURCE_STATE", id: s.SourceSystem + ":" + s.SourceID, document: state})
	}
	if len(refs) > fleetHistoryLimit {
		return nil, ErrFleetHistoryBounds
	}
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].kind != refs[j].kind {
			return refs[i].kind < refs[j].kind
		}
		return refs[i].id < refs[j].id
	})
	rootParts := make([]string, len(refs))
	for i := range refs {
		refs[i].raw, refs[i].hash, e = fleetHistoryBytes(refs[i].document)
		if e != nil {
			return nil, e
		}
		rootParts[i] = strconv.Itoa(i+1) + ":" + refs[i].hash
	}
	h := sha256.Sum256([]byte(strings.Join(rootParts, ",")))
	root := hex.EncodeToString(h[:])
	id := model.ID()
	summary := model.Document{"schema_version": "1", "id": id, "purpose": a.Purpose, "status": a.Status, "binding": a.Binding, "fleet_id": a.FleetID, "asg_arn": a.ASGARN, "registration_id": r.ID, "registration_version": r.Version, "registration_hash": a.RegistrationHash, "definition_id": d.ID, "definition_version": d.Version, "definition_hash": a.DefinitionHash, "input_hash": a.InputHash, "analysis_hash": a.Hash, "start": start, "end": end, "as_of": now, "membership_status": a.MembershipStatus, "reference_root": root, "reference_count": len(refs), "observation_count": len(obs), "selected_observation_count": len(a.Observations), "demand_receipt_count": len(demand), "membership_gaps": fleetHistoryPreview(a.MembershipGaps), "observation_gaps": fleetHistoryPreview(a.ObservationGaps), "issues": fleetHistoryPreview(a.Issues), "superseded_ids": fleetHistoryPreview(a.SupersededIDs), "reason_codes": a.ReasonCodes, "demand": model.Document{"status": a.Demand.Status, "meaning_basis": a.Demand.MeaningBasis, "unit": a.Demand.Unit, "observed_units": a.Demand.ObservedUnits, "window_units": a.Demand.WindowUnits, "segments": fleetHistoryPreview(a.Demand.Segments), "gaps": fleetHistoryPreview(a.Demand.Gaps), "reason_codes": a.Demand.ReasonCodes}}
	b, hash, e := fleetHistoryBytes(summary)
	if e != nil {
		return nil, e
	}
	_, e = t.Exec(ctx, `INSERT INTO fleet_history_scopes(tenant_id,id,registration_id,registration_version,definition_id,definition_version,input_hash,analysis_hash,reference_root,reference_count,content_hash,document,raw_document) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, t.Tenant, id, r.ID, r.Version, d.ID, d.Version, a.InputHash, a.Hash, root, len(refs), hash, b, b)
	if e != nil {
		return nil, e
	}
	for i, ref := range refs {
		_, e = t.Exec(ctx, `INSERT INTO fleet_history_scope_references(tenant_id,scope_id,ordinal,kind,reference_id,content_hash,document,raw_document) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, t.Tenant, id, i+1, ref.kind, ref.id, ref.hash, ref.raw, ref.raw)
		if e != nil {
			return nil, e
		}
	}
	return t.FleetHistoryScopeGet(ctx, id)
}
func (t *Tx) FleetHistoryScopeGet(ctx context.Context, id string) (model.Document, error) {
	return t.sourceOne(ctx, `SELECT document||jsonb_build_object('hash',content_hash,'created_at',created_at,'writer_role',writer_role) FROM fleet_history_scopes WHERE tenant_id=$1 AND id=$2`, t.Tenant, id)
}
func (t *Tx) FleetHistoryScopePage(ctx context.Context, registrationID, after string, limit int) ([]model.Document, error) {
	if _, e := fleetHistoryPageLimit(limit); e != nil {
		return nil, e
	}
	return t.sourceRows(ctx, `SELECT document||jsonb_build_object('hash',content_hash,'created_at',created_at,'writer_role',writer_role) FROM fleet_history_scopes WHERE tenant_id=$1 AND registration_id=$2 AND id>$3 ORDER BY id LIMIT $4`, t.Tenant, registrationID, after, limit)
}
func (t *Tx) FleetHistoryScopeReferencePage(ctx context.Context, scopeID, kind, after string, limit int) ([]model.Document, error) {
	if _, e := fleetHistoryPageLimit(limit); e != nil {
		return nil, e
	}
	if kind != "" && kind != "REGISTRATION" && kind != "DEFINITION" && kind != "OBSERVATION" && kind != "DEMAND_RECEIPT" && kind != "SOURCE_STATE" {
		return nil, ErrFleetHistorySource
	}
	ordinal := 0
	var e error
	if after != "" {
		ordinal, e = strconv.Atoi(after)
		if e != nil || ordinal < 0 {
			return nil, ErrFleetHistoryBounds
		}
	}
	return t.sourceRows(ctx, `SELECT jsonb_build_object('id',reference_id,'ordinal',ordinal,'cursor',ordinal::text,'kind',kind,'reference',document,'hash',content_hash,'created_at',created_at) FROM fleet_history_scope_references WHERE tenant_id=$1 AND scope_id=$2 AND ($3='' OR kind=$3) AND ordinal>$4 ORDER BY ordinal LIMIT $5`, t.Tenant, scopeID, kind, ordinal, limit)
}
