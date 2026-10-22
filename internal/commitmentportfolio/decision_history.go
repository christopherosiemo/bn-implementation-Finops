package commitmentportfolio

import (
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"sort"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
)

const decisionHistoryMaxPages = 64
const decisionHistoryPageChunks = 2
const decisionHistoryPageBytes = 32 << 20
const decisionHistoryTotalBytes = 128 << 20
const decisionHistoryMaxRows = 100000
const decisionHistoryRequestBytes = 32 << 20
const decisionHistoryMinimumHours = 23376 // 2160 + 2*8760 + 168*(12+12-2).

var ErrDecisionHistory = errors.New("COMMITMENT_NATIVE_HOURLY_HISTORY_UNSUPPORTED")

// This is a private resolver contract, never an API evidence body. The adapter
// selects current month heads and their actual persisted raw/canonical jobs,
// using the same source receipt resolution as the existing portfolio reader.
// It must not accept caller-populated Resolved objects or caller-created heads.
type DecisionHistoryReader interface {
	DecisionHistoryPage(context.Context, DecisionHistoryQuery, string) (DecisionHistoryPage, error)
	RecheckDecisionHistory(context.Context, DecisionHistoryQuery, DecisionHistoryPins) error
}

type DecisionHistoryQuery struct {
	Selection      Selection
	Scope          DecisionScope
	TrainingPeriod Period
	OwnershipRef   Ref
}

// Each chunk selects at most 31 whole UTC days within one calendar month.
// Adjacent chunks tile the training period exactly; raw jobs stay unmodified.
type DecisionHistoryPage struct {
	Chunks     []Resolved
	NextCursor string
}

type DecisionHistoryRevisionPin struct {
	BillingMonth Period `json:"billing_month"`
	Receipt      Ref    `json:"receipt"`
	Revision     Ref    `json:"revision"`
	Job          Ref    `json:"job"`
}

// These are consistency/currentness pins, not a new evidence issuer. A SQL
// publisher must repeat their actual credential/source/graph/artifact and
// ownership checks under its existing publication fences in READ COMMITTED.
type DecisionHistoryPins struct {
	SourceID            string                       `json:"source_id"`
	RegistrationVersion int64                        `json:"registration_version"`
	ConfigurationSHA256 string                       `json:"configuration_sha256"`
	RegistrationSHA256  string                       `json:"registration_sha256"`
	CheckpointSHA256    string                       `json:"checkpoint_sha256"`
	CommitmentRef       Ref                          `json:"commitment_ref"`
	OwnershipRef        Ref                          `json:"ownership_ref"`
	TrainingPeriod      Period                       `json:"training_period"`
	Revisions           []DecisionHistoryRevisionPin `json:"revisions"`
	NativeRecordCount   int                          `json:"native_record_count"`
	HistoricalHourCount int                          `json:"historical_hour_count"`
}

type decisionHistoryTotal struct {
	Hour         DecisionHistoryHour
	Quantity     *big.Rat
	OrdinaryRate *big.Rat
}

// AssembleDecisionForecastHistory maps actual issued CUR observations into the
// existing forecast request. It does not produce optimization outcomes, attest
// historical ownership, authenticate an uploaded receipt, or grant authority.
// Only the first four real stage factories belong in base; the forecast
// producer itself establishes stage five.
func AssembleDecisionForecastHistory(ctx context.Context, reader DecisionHistoryReader, base DecisionForecastRequest, selection Selection, training Period, ownership DecisionResolvedOwnership, now time.Time) (DecisionForecastRequest, DecisionHistoryPins, error) {
	fail := func(err error) (DecisionForecastRequest, DecisionHistoryPins, error) {
		if err == nil {
			err = ErrDecisionHistory
		}
		return DecisionForecastRequest{}, DecisionHistoryPins{}, err
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	if reader == nil || !decisionHistoryRequest(base, selection, training, ownership, now) {
		return fail(nil)
	}
	ownershipRef := ownership.Reference
	query := DecisionHistoryQuery{Selection: selection, Scope: base.Scope, TrainingPeriod: training, OwnershipRef: ownershipRef}
	pins := DecisionHistoryPins{SourceID: selection.SourceID, OwnershipRef: ownershipRef, TrainingPeriod: training, Revisions: []DecisionHistoryRevisionPin{}}
	refs := append(append([]Ref{}, base.InputRefs...), ownership.InputRefs...)
	refs = append(refs, ownershipRef)
	resources := map[string]DecisionOwnershipResource{}
	for _, resource := range ownership.Scope.Resources {
		resources[resource.ProviderResourceID] = resource
	}
	seenCursors := map[string]bool{"": true}
	seenNative := map[string]bool{}
	seenSelected := map[string]bool{}
	monthHeads := map[string]DecisionHistoryRevisionPin{}
	selectedHeads := map[string]bool{}
	for _, id := range selection.BillingReceiptIDs {
		selectedHeads[id] = true
	}
	resourceDimensions := map[string]string{}
	resourceHours := map[string]map[int64]bool{}
	groups := map[string]*decisionHistoryTotal{}
	dimensions := map[string]Dimensions{}
	cursor, next := "", training.Start
	totalBytes, pages := 0, 0
	var snapshotObservedAt time.Time
	snapshotSelected := false
	for {
		if err := ctx.Err(); err != nil {
			return fail(err)
		}
		if pages >= decisionHistoryMaxPages {
			return fail(nil)
		}
		page, err := reader.DecisionHistoryPage(ctx, query, cursor)
		if err != nil {
			return fail(err)
		}
		pages++
		if len(page.Chunks) < 1 || len(page.Chunks) > decisionHistoryPageChunks || len(page.NextCursor) > 2048 {
			return fail(nil)
		}
		wire, err := json.Marshal(page)
		if err != nil || len(wire) > decisionHistoryPageBytes || totalBytes > decisionHistoryTotalBytes-len(wire) {
			return fail(nil)
		}
		totalBytes += len(wire)
		for _, resolved := range page.Chunks {
			if err := ctx.Err(); err != nil {
				return fail(err)
			}
			// Every page belongs to the same immutable selected039 analysis.
			// Reject a mixture of renewed/legacy clocks or another analysis clock.
			if snapshotSelected && !resolved.DecisionSnapshotObservedAt.Equal(snapshotObservedAt) {
				return fail(nil)
			}
			snapshotObservedAt = resolved.DecisionSnapshotObservedAt
			snapshotSelected = true
			span := resolved.Selection.Period
			month := time.Date(span.Start.Year(), span.Start.Month(), 1, 0, 0, 0, 0, time.UTC)
			monthEnd := month.AddDate(0, 1, 0)
			if resolved.TenantID != base.Scope.TenantID || resolved.RequestID != base.RequestID || resolved.Selection.SourceID != selection.SourceID || resolved.Selection.CommitmentReceiptID != selection.CommitmentReceiptID || !span.Start.Equal(next) || span.End.After(training.End) || span.End.After(monthEnd) || ValidateSelection(resolved.Selection, now) != nil || len(resolved.Billing) == 0 {
				return fail(nil)
			}
			if !decisionHistorySource(&pins, resolved, now) {
				return fail(nil)
			}
			chunkScope := base.Scope
			chunkScope.HistoryPeriod = span
			chunkScope.SHA256 = ""
			chunkScope.SHA256 = Hash(chunkScope)
			usage, err := PrepareDecisionUsage(resolved, chunkScope, now)
			if err != nil || usage.Status != "COMPLETE_OBSERVED_ELIGIBLE_WINDOW" || len(usage.ReasonCodes) != 0 {
				return fail(err)
			}
			refs = append(refs, usage.InputRefs...)
			native := map[string]model.Document{}
			for _, billing := range resolved.Billing {
				pin, ok := decisionHistoryBillingPin(billing, resolved, month, monthEnd, span, pins.RegistrationVersion)
				if !ok {
					return fail(nil)
				}
				key := month.Format("2006-01")
				if old, exists := monthHeads[key]; exists && Hash(old) != Hash(pin) {
					return fail(nil)
				}
				monthHeads[key] = pin
				if month.Before(selection.Period.End) && monthEnd.After(selection.Period.Start) {
					delete(selectedHeads, pin.Receipt.ID)
				}
				for _, row := range documents(document(billing.Job["raw"])["records"]) {
					id := first(row, "identity_line_item_id", "identity/LineItemId")
					key := pin.Revision.ID + ":" + id
					if id == "" {
						return fail(nil)
					}
					if !seenNative[key] {
						seenNative[key] = true
						pins.NativeRecordCount++
					}
					if pins.NativeRecordCount > decisionHistoryMaxRows {
						return fail(nil)
					}
					rowKey := pin.Receipt.ID + ":" + id
					if _, exists := native[rowKey]; exists {
						return fail(nil)
					}
					native[rowKey] = row
				}
			}
			for _, hour := range usage.Hours {
				if hour.Kind != "Usage" && hour.Kind != "SavingsPlanCoveredUsage" || hour.NetUsageCost == nil || hour.BilledCostBasis != "NATIVE_NET_UNBLENDED_COST" || hour.Dimensions.ServiceCode != "AmazonEC2" || hour.Dimensions.ProductType != "EC2" || hour.Dimensions.Unit != "Hrs" {
					return fail(nil)
				}
				rowKey := hour.NativeRef.ID + ":" + hour.ID
				row := native[rowKey]
				resourceID := first(row, "line_item_resource_id", "lineItem/ResourceId")
				resource, exists := resources[resourceID]
				if row == nil || !exists || resource.AccountID != hour.Dimensions.AccountID || resource.Region != hour.Dimensions.Region || seenSelected[rowKey] {
					return fail(nil)
				}
				seenSelected[rowKey] = true
				key := Hash(hour.Dimensions)
				if old := resourceDimensions[resourceID]; old != "" && old != key {
					return fail(nil)
				}
				resourceDimensions[resourceID] = key
				if resourceHours[resourceID] == nil {
					resourceHours[resourceID] = map[int64]bool{}
				}
				resourceHours[resourceID][hour.Period.Start.Unix()] = true
				quantity, e1 := numberValue(&hour.UsageAmount, false, false)
				cost, e2 := numberValue(hour.NetUsageCost, false, false)
				if e1 != nil || e2 != nil || quantity.Sign() == 0 && cost.Sign() != 0 {
					return fail(nil)
				}
				groupKey := key + ":" + hour.Period.Start.Format(time.RFC3339)
				total := groups[groupKey]
				if total == nil {
					total = &decisionHistoryTotal{Hour: DecisionHistoryHour{Period: hour.Period, Dimensions: hour.Dimensions, ConfigurationSHA256: base.Scope.ConfigurationSHA256, NativeRef: hour.NativeRef}, Quantity: new(big.Rat)}
					groups[groupKey] = total
				} else if total.Hour.NativeRef != hour.NativeRef {
					return fail(nil)
				} // A single model row cannot pretend to pin several receipts.
				if hour.Kind == "Usage" && quantity.Sign() > 0 {
					rate := new(big.Rat).Quo(cost, quantity)
					if total.OrdinaryRate != nil && total.OrdinaryRate.Cmp(rate) != 0 {
						return fail(nil)
					}
					total.OrdinaryRate = rate
				}
				total.Quantity.Add(total.Quantity, quantity)
				dimensions[key] = hour.Dimensions
				if len(groups) > decisionHistoryMaxRows {
					return fail(nil)
				}
			}
			for resource := range resources {
				for stamp := span.Start; stamp.Before(span.End); stamp = stamp.Add(time.Hour) {
					if !resourceHours[resource][stamp.Unix()] {
						return fail(nil)
					}
				}
			}
			next = span.End
		}
		if page.NextCursor == "" {
			break
		}
		if !next.Before(training.End) || seenCursors[page.NextCursor] {
			return fail(nil)
		}
		seenCursors[page.NextCursor] = true
		cursor = page.NextCursor
	}
	if !next.Equal(training.End) || len(dimensions) == 0 || len(selectedHeads) != 0 {
		return fail(nil)
	}
	count := int(training.End.Sub(training.Start) / time.Hour)
	for resource := range resources {
		if len(resourceHours[resource]) != count {
			return fail(nil)
		}
		for stamp := training.Start; stamp.Before(training.End); stamp = stamp.Add(time.Hour) {
			if !resourceHours[resource][stamp.Unix()] {
				return fail(nil)
			}
		}
	}
	if len(groups) != count*len(dimensions) {
		return fail(nil)
	}
	result := base
	result.History = make([]DecisionHistoryHour, 0, len(groups))
	for _, total := range groups {
		quantity, ok := decisionHistoryDecimal(total.Quantity)
		if !ok {
			return fail(nil)
		}
		total.Hour.UsageAmount = quantity
		result.History = append(result.History, total.Hour)
	}
	sort.Slice(result.History, func(i, j int) bool {
		if !result.History[i].Period.Start.Equal(result.History[j].Period.Start) {
			return result.History[i].Period.Start.Before(result.History[j].Period.Start)
		}
		return Hash(result.History[i].Dimensions) < Hash(result.History[j].Dimensions)
	})
	for _, pin := range monthHeads {
		pins.Revisions = append(pins.Revisions, pin)
		refs = append(refs, pin.Receipt, pin.Revision, pin.Job)
	}
	sort.Slice(pins.Revisions, func(i, j int) bool {
		return pins.Revisions[i].BillingMonth.Start.Before(pins.Revisions[j].BillingMonth.Start)
	})
	var err error
	result.InputRefs, err = decisionRefs(refs)
	if err != nil {
		return fail(err)
	}
	pins.HistoricalHourCount = len(result.History)
	wire, err := json.Marshal(result)
	if err != nil || len(wire) > decisionHistoryRequestBytes {
		return fail(nil)
	}
	if err = ctx.Err(); err != nil {
		return fail(err)
	}
	if err = reader.RecheckDecisionHistory(ctx, query, pins); err != nil {
		return fail(err)
	}
	if err = ctx.Err(); err != nil {
		return fail(err)
	}
	return result, pins, nil
}

func decisionHistoryRequest(base DecisionForecastRequest, selection Selection, training Period, ownership DecisionResolvedOwnership, now time.Time) bool {
	if base.SchemaVersion != "2" || !idPattern.MatchString(base.RequestID) || len(base.History) != 0 || !ownershipUTC(now) || !base.ObservedAt.Equal(now) || ValidateSelection(selection, now) != nil || len(selection.BillingReceiptIDs) == 0 || Hash(selection.Period) != Hash(base.Scope.HistoryPeriod) || !training.End.Equal(selection.Period.End) || !ownershipPeriod(training) || training.Start.Before(now.AddDate(-5, 0, 0)) || training.End.After(now) || now.Sub(training.End) > 48*time.Hour {
		return false
	}
	for _, stamp := range []time.Time{training.Start, training.End} {
		if !stamp.Equal(stamp.Truncate(24 * time.Hour)) {
			return false
		}
	}
	scope := base.Scope
	sealed := scope.SHA256
	scope.SHA256 = ""
	if !shaPattern.MatchString(sealed) || Hash(scope) != sealed || !shaPattern.MatchString(scope.ConfigurationSHA256) || !decisionHistoryCurrency(scope.Currency) || scope.Class != "COMPUTE_SAVINGS_PLAN" && scope.Class != "EC2_INSTANCE_SAVINGS_PLAN" || !ownershipUTC(scope.ProjectionPeriod.Start) || !ownershipUTC(scope.ProjectionPeriod.End) || scope.ProjectionPeriod.End.Sub(scope.ProjectionPeriod.Start) != 8760*time.Hour || scope.ProjectionPeriod.Start.Before(now) || scope.ProjectionPeriod.Start.Sub(now) >= time.Hour || !scope.ProjectionPeriod.Start.Equal(scope.ProjectionPeriod.Start.Truncate(time.Hour)) {
		return false
	}
	gap := int(scope.ProjectionPeriod.Start.Sub(training.End) / time.Hour)
	if gap < 0 || int(training.End.Sub(training.Start)/time.Hour) < decisionHistoryMinimumHours+2*gap {
		return false
	}
	if validateResolvedDecisionOwnership(ownership, ownership.Scope, training, now) != nil || ownership.Reference != scope.OwnershipRef || ownership.Scope.TenantID != scope.TenantID || ownership.Scope.WorkloadID != scope.WorkloadID || ownership.Scope.ConfigurationSHA256 != scope.ConfigurationSHA256 {
		return false
	}
	accounts, resourceIDs := map[string]bool{}, []string{}
	for _, id := range scope.UsageAccountIDs {
		if !accountPattern.MatchString(id) || accounts[id] {
			return false
		}
		accounts[id] = true
	}
	if !accounts[scope.PayerAccountID] || len(accounts) == 0 {
		return false
	}
	for _, resource := range ownership.Scope.Resources {
		if !accounts[resource.AccountID] {
			return false
		}
		resourceIDs = append(resourceIDs, resource.ProviderResourceID)
	}
	sort.Strings(resourceIDs)
	if Hash(resourceIDs) != Hash(scope.ResourceIDs) {
		return false
	}
	for i := 1; i < len(resourceIDs); i++ {
		if resourceIDs[i-1] == resourceIDs[i] {
			return false
		}
	}
	refs, err := decisionRefs(base.InputRefs)
	if err != nil || len(refs) != len(base.InputRefs) {
		return false
	}
	present := map[Ref]bool{}
	for _, ref := range refs {
		present[ref] = true
	}
	if !present[scope.OwnershipRef] || len(base.OptimizationOrder) != 4 {
		return false
	}
	stages := []string{"REMOVE_IDLE", "SCHEDULE", "RIGHTSIZE", "AUTOSCALE"}
	var last time.Time
	for i, stage := range base.OptimizationOrder {
		if stage.Stage != stages[i] || stage.Disposition != "COMPLETED" && stage.Disposition != "EVIDENCED_NO_CHANGE" || stage.ScopeSHA256 != sealed || !ownershipUTC(stage.CompletedAt) || stage.CompletedAt.After(now) || !last.IsZero() && stage.CompletedAt.Before(last) || !present[stage.DecisionRef] || !present[stage.OutcomeRef] {
			return false
		}
		last = stage.CompletedAt
	}
	return true
}

func decisionHistorySource(pins *DecisionHistoryPins, r Resolved, now time.Time) bool {
	// SQL independently rechecks *current* source/config/CUR heads and native
	// commitment equality. Only the original selected source snapshot is checked
	// at its original analysis clock; no new native timestamp is manufactured.
	if !r.DecisionSnapshotObservedAt.IsZero() {
		if !ownershipUTC(r.DecisionSnapshotObservedAt) || r.DecisionSnapshotObservedAt.After(now.Add(5*time.Second)) {
			return false
		}
		now = r.DecisionSnapshotObservedAt
	}
	version := model.Number(r.Registration, "version")
	checkpoint := r.Checkpoint
	synced := date(model.String(checkpoint, "last_sync_at"))
	config := source.ConfigurationHash(r.Registration)
	if version < 1 || synced == nil || synced.After(now.Add(5*time.Second)) || synced.Before(now.Add(-5*time.Minute)) || model.String(checkpoint, "status") != "HEALTHY" || model.String(checkpoint, "config_hash") != config || model.Number(checkpoint, "last_sync_version") != version {
		return false
	}
	current := ref("AWS_COMMITMENT", r.Commitment)
	if pins.RegistrationVersion == 0 {
		pins.RegistrationVersion, pins.ConfigurationSHA256 = version, config
		pins.RegistrationSHA256, pins.CheckpointSHA256, pins.CommitmentRef = Hash(r.Registration), Hash(checkpoint), current
	}
	return pins.RegistrationVersion == version && pins.ConfigurationSHA256 == config && pins.RegistrationSHA256 == Hash(r.Registration) && pins.CheckpointSHA256 == Hash(checkpoint) && pins.CommitmentRef == current
}

func decisionHistoryBillingPin(b BillingRevision, r Resolved, month, end time.Time, selected Period, version int64) (DecisionHistoryRevisionPin, bool) {
	pin := DecisionHistoryRevisionPin{BillingMonth: Period{month, end}, Receipt: ref("AWS_CUR2", b.Receipt), Revision: ref("AWS_CUR2_REVISION", b.Revision), Job: ref("AWS_CUR2_INGESTION_JOB", b.Job)}
	proof := document(b.Receipt["source_proof"])
	left, right := date(model.String(proof, "period_start")), date(model.String(proof, "period_end"))
	billingStart, billingEnd := date(model.String(proof, "billing_period_start")), date(model.String(proof, "billing_period_end"))
	if left == nil || right == nil || billingStart == nil || billingEnd == nil || !billingStart.Equal(month) || !billingEnd.Equal(end) || !left.Equal(month) || right.After(end) || left.After(selected.Start) || right.Before(selected.End) || model.Number(b.Receipt, "registration_version") != version || model.String(b.Receipt, "registration_id") != r.Selection.SourceID || model.String(b.Receipt, "ingestion_job_id") != pin.Job.ID || model.String(b.Revision, "ingestion_job_id") != pin.Job.ID || model.String(b.Revision, "registration_id") != r.Selection.SourceID || model.String(b.Revision, "config_hash") != source.ConfigurationHash(r.Registration) || model.String(b.Revision, "raw_hash") != model.String(b.Receipt, "raw_hash") || model.String(b.Revision, "canonical_hash") != model.String(b.Receipt, "canonical_hash") || model.String(b.Job, "source_id") != r.Selection.SourceID {
		return pin, false
	}
	for _, ref := range []Ref{pin.Receipt, pin.Revision, pin.Job} {
		if !idPattern.MatchString(ref.ID) || !shaPattern.MatchString(ref.SHA256) {
			return pin, false
		}
	}
	return pin, true
}

func decisionHistoryDecimal(value *big.Rat) (string, bool) {
	text := value.FloatString(12)
	roundtrip, err := numberValue(&text, false, false)
	return text, err == nil && roundtrip.Cmp(value) == 0
}

func decisionHistoryCurrency(value string) bool {
	if len(value) != 3 {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 'A' || value[i] > 'Z' {
			return false
		}
	}
	return true
}
