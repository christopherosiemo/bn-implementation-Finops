package commitmentportfolio

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
)

// Typed private-resolver doubles exercise mapping and bounded assembly only.
// Their forged-in-test source proofs/ownership summaries have no SQL, native
// acquisition, historical authority, or positive recommendation acceptance.
type historyReaderDouble struct {
	Base       DecisionForecastRequest
	Selection  Selection
	Training   Period
	Ownership  DecisionResolvedOwnership
	Calls      int
	Rechecks   int
	Mutate     func(int, *DecisionHistoryPage)
	RecheckErr error
}

func newHistoryDouble(resources int) *historyReaderDouble {
	now := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	training := Period{now.Add(-decisionHistoryMinimumHours * time.Hour), now}
	ownerScope := DecisionOwnershipScope{TenantID: "tenant-history", WorkloadID: "workload-history", Resources: []DecisionOwnershipResource{}}
	for i := 0; i < resources; i++ {
		ownerScope.Resources = append(ownerScope.Resources, DecisionOwnershipResource{ResourceID: fmt.Sprintf("resource-%02d", i), ProviderResourceID: fmt.Sprintf("i-history-%02d", i), AccountID: "111122223333", Region: "eu-west-1", RepositoryID: "repo-history", GitCommit: strings.Repeat("a", 40), ConfigurationSHA256: strings.Repeat("b", 64), StateLineage: "lineage-history"})
	}
	ownerScope.ConfigurationSHA256 = DecisionOwnershipConfigurationSHA256(ownerScope.Resources)
	owner := DecisionOwnershipEvidence{SchemaVersion: "1", Scope: ownerScope, ScopeSHA256: Hash(ownerScope), Period: training, Status: DecisionOwnershipObserved, Basis: DecisionOwnershipBasis, Segments: []DecisionOwnershipSegment{}, RegistrationPins: []DecisionOwnershipRegistrationPin{}, InputRefs: []Ref{{Kind: "OWNERSHIP_REVIEW", ID: "review-history", SHA256: strings.Repeat("c", 64)}}, ReasonCodes: []string{}, ObservedAt: now}
	for _, resource := range ownerScope.Resources {
		owner.Segments = append(owner.Segments, DecisionOwnershipSegment{Resource: resource, Period: training})
	}
	owner.ID = Hash(owner)
	ownerRef, _ := owner.HistoricalReference()
	selection := Selection{SourceID: "source-history", CommitmentReceiptID: "inventory-history", BillingReceiptIDs: []string{"receipt-2026-10"}, Period: Period{now.Add(-24 * time.Hour), now}}
	scope := DecisionScope{TenantID: ownerScope.TenantID, WorkloadID: ownerScope.WorkloadID, PayerAccountID: "111122223333", UsageAccountIDs: []string{"111122223333"}, ResourceIDs: []string{}, Class: "COMPUTE_SAVINGS_PLAN", Currency: "USD", ConfigurationSHA256: ownerScope.ConfigurationSHA256, OwnershipRef: ownerRef, HistoryPeriod: selection.Period, ProjectionPeriod: Period{now, now.Add(8760 * time.Hour)}}
	for _, resource := range ownerScope.Resources {
		scope.ResourceIDs = append(scope.ResourceIDs, resource.ProviderResourceID)
	}
	scope.SHA256 = Hash(scope)
	base := DecisionForecastRequest{SchemaVersion: "2", RequestID: "request-history", Scope: scope, ObservedAt: now, OptimizationOrder: []PostOptimizationStage{}, InputRefs: []Ref{ownerRef}, History: []DecisionHistoryHour{}}
	for i, stage := range []string{"REMOVE_IDLE", "SCHEDULE", "RIGHTSIZE", "AUTOSCALE"} {
		decision := Ref{Kind: "OPTIMIZATION_DECISION", ID: fmt.Sprintf("decision-%d", i), SHA256: strings.Repeat("d", 64)}
		outcome := Ref{Kind: "OPTIMIZATION_OUTCOME", ID: fmt.Sprintf("outcome-%d", i), SHA256: strings.Repeat("e", 64)}
		base.OptimizationOrder = append(base.OptimizationOrder, PostOptimizationStage{Stage: stage, Disposition: "EVIDENCED_NO_CHANGE", DecisionRef: decision, OutcomeRef: outcome, ScopeSHA256: scope.SHA256, CompletedAt: now.Add(-time.Minute), ReasonCodes: []string{}})
		base.InputRefs = append(base.InputRefs, decision, outcome)
	}
	resolvedOwnership := DecisionResolvedOwnership{Scope: owner.Scope, ScopeSHA256: owner.ScopeSHA256, Period: owner.Period, Basis: owner.Basis, Reference: ownerRef, InputRefs: owner.InputRefs, ObservedAt: now, RegistrationPins: []DecisionOwnershipRegistrationPin{{ID: "journal-registration", Revision: 1, SHA256: strings.Repeat("a", 64)}, {ID: "review-registration", Revision: 1, SHA256: strings.Repeat("b", 64)}}}
	return &historyReaderDouble{Base: base, Selection: selection, Training: training, Ownership: resolvedOwnership}
}

func (r *historyReaderDouble) DecisionHistoryPage(ctx context.Context, q DecisionHistoryQuery, cursor string) (DecisionHistoryPage, error) {
	if err := ctx.Err(); err != nil {
		return DecisionHistoryPage{}, err
	}
	if Hash(q.Selection) != Hash(r.Selection) || Hash(q.Scope) != Hash(r.Base.Scope) || Hash(q.TrainingPeriod) != Hash(r.Training) {
		return DecisionHistoryPage{}, ErrDecisionHistory
	}
	start := r.Training.Start
	if cursor != "" {
		unix, err := strconv.ParseInt(cursor, 10, 64)
		if err != nil {
			return DecisionHistoryPage{}, err
		}
		start = time.Unix(unix, 0).UTC()
	}
	end := time.Date(start.Year(), start.Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, 1, 0)
	if end.After(r.Training.End) {
		end = r.Training.End
	}
	page := DecisionHistoryPage{Chunks: []Resolved{r.resolved(Period{start, end})}}
	if end.Before(r.Training.End) {
		page.NextCursor = strconv.FormatInt(end.Unix(), 10)
	}
	r.Calls++
	if r.Mutate != nil {
		r.Mutate(r.Calls, &page)
	}
	return page, nil
}

func (r *historyReaderDouble) RecheckDecisionHistory(ctx context.Context, q DecisionHistoryQuery, pins DecisionHistoryPins) error {
	r.Rechecks++
	if err := ctx.Err(); err != nil {
		return err
	}
	if pins.SourceID != r.Selection.SourceID || pins.CommitmentRef.ID != r.Selection.CommitmentReceiptID || pins.OwnershipRef != r.Base.Scope.OwnershipRef || Hash(pins.TrainingPeriod) != Hash(q.TrainingPeriod) || pins.RegistrationVersion != 1 || len(pins.Revisions) < 30 {
		return ErrDecisionHistory
	}
	return r.RecheckErr
}

func (r *historyReaderDouble) resolved(span Period) Resolved {
	now := r.Base.ObservedAt
	reg := model.Document{"id": r.Selection.SourceID, "tenant_id": r.Base.Scope.TenantID, "version": int64(1), "kind": "AWS_CUR2", "payer_account_id": "111122223333", "usage_account_ids": []string{"111122223333"}, "region": "eu-west-1", "bucket": "billing-native", "bucket_owner": "111122223333", "prefix": "cur/", "read_role_binding_id": "read-role", "export_arn": "arn:aws:bcm-data-exports:us-east-1:111122223333:export/history", "enabled": true, "revoked": false, "status": "HEALTHY"}
	config := source.ConfigurationHash(reg)
	commitmentScope := model.Document{"receipt_id": r.Selection.CommitmentReceiptID, "payer_account_id": "111122223333", "usage_account_ids": []string{"111122223333"}, "scope": "PAYER_ALL_LINKED_ACCOUNTS_ALL_REGIONS", "complete": true, "observed_at": now.Format(time.RFC3339Nano), "reserved_instance_count": int64(0), "savings_plan_count": int64(0), "native_snapshots": []model.Document{{"account_id": "111122223333", "reserved_instances": []model.Document{}, "savings_plans": []model.Document{}}}}
	commitment := model.Document{"id": r.Selection.CommitmentReceiptID, "source_id": r.Selection.SourceID, "tenant_id": r.Base.Scope.TenantID, "kind": "AWS_COMMITMENT", "writer_role": "finops_ingester", "config_hash": config, "observed_at": now.Format(time.RFC3339Nano), "commitment_scope": commitmentScope, "native_hash": source.Hash(commitmentScope)}
	month := time.Date(span.Start.Year(), span.Start.Month(), 1, 0, 0, 0, 0, time.UTC)
	suffix := month.Format("2006-01")
	receiptID, revisionID, jobID := "receipt-"+suffix, "revision-"+suffix, "job-"+suffix
	rawRows := []model.Document{}
	for stamp := span.Start; stamp.Before(span.End); stamp = stamp.Add(time.Hour) {
		for i, resource := range r.Ownership.Scope.Resources {
			quantity, cost := strconv.Itoa(i+1), fmt.Sprintf("0.%d", 2*(i+1))
			if stamp.Equal(r.Training.Start) {
				quantity, cost = "0", "0"
			}
			rawRows = append(rawRows, model.Document{"identity_line_item_id": fmt.Sprintf("native-%d-%d", stamp.Unix(), i), "bill_payer_account_id": "111122223333", "line_item_usage_account_id": "111122223333", "line_item_resource_id": resource.ProviderResourceID, "line_item_line_item_type": "Usage", "line_item_usage_start_date": stamp.Format(time.RFC3339Nano), "line_item_usage_end_date": stamp.Add(time.Hour).Format(time.RFC3339Nano), "product_servicecode": "AmazonEC2", "product_product_family": "Compute Instance", "product_region_code": "eu-west-1", "product_instance_type": "m6i.large", "product_instance_family": "General purpose", "product_operating_system": "Linux", "product_tenancy": "Shared", "line_item_usage_type": "EUW1-BoxUsage:m6i.large", "line_item_operation": "RunInstances", "pricing_unit": "Hrs", "line_item_currency_code": "USD", "line_item_usage_amount": quantity, "line_item_unblended_cost": cost, "line_item_net_unblended_cost": cost})
		}
	}
	observedEnd := month.AddDate(0, 1, 0)
	state := "FINAL"
	if observedEnd.After(now) {
		observedEnd = now.Truncate(24 * time.Hour)
		state = "COMPLETE"
	}
	proof := model.Document{"period_start": month.Format(time.RFC3339Nano), "period_end": observedEnd.Format(time.RFC3339Nano), "billing_period_start": month.Format(time.RFC3339Nano), "billing_period_end": month.AddDate(0, 1, 0).Format(time.RFC3339Nano), "payer_account_id": "111122223333", "usage_account_ids": []string{"111122223333"}, "receipt_id": receiptID, "revision_id": revisionID, "manifest_hash": strings.Repeat("f", 64), "state": state, "object_count": int64(1), "verified_object_count": int64(1)}
	receipt := model.Document{"id": receiptID, "tenant_id": r.Base.Scope.TenantID, "kind": "AWS_CUR2", "writer_role": "finops_ingester", "source_id": r.Selection.SourceID, "config_hash": config, "revision_id": revisionID, "registration_id": r.Selection.SourceID, "registration_version": int64(1), "ingestion_job_id": jobID, "source_proof": proof}
	revision := model.Document{"id": revisionID, "source_id": r.Selection.SourceID, "writer_role": "finops_ingester", "registration_id": r.Selection.SourceID, "config_hash": config, "ingestion_job_id": jobID}
	job := model.Document{"id": jobID, "source_id": r.Selection.SourceID, "source_receipt_id": receiptID, "source_revision_id": revisionID, "status": "PERSISTED", "source_provenance": "AWS_CUR2_AUTHENTICATED", "raw": model.Document{"records": rawRows}}
	billing := BillingRevision{Receipt: receipt, Revision: revision, Job: job, CurrentReceiptID: receiptID}
	historyResealBilling(&billing)
	return Resolved{TenantID: r.Base.Scope.TenantID, RequestID: r.Base.RequestID, Selection: Selection{r.Selection.SourceID, r.Selection.CommitmentReceiptID, []string{receiptID}, span}, Registration: reg, Checkpoint: model.Document{"commitment_receipt_id": r.Selection.CommitmentReceiptID, "status": "HEALTHY", "config_hash": config, "last_sync_at": now.Format(time.RFC3339Nano), "last_sync_version": int64(1)}, Commitment: commitment, Billing: []BillingRevision{billing}}
}

func historyResealBilling(b *BillingRevision) {
	rows := documents(document(b.Job["raw"])["records"])
	canonical := []model.Document{}
	for _, row := range rows {
		canonical = append(canonical, model.Document{"x_SourceRecordId": first(row, "identity_line_item_id"), "x_ProviderFields": row})
	}
	b.Job["raw"] = model.Document{"records": rows}
	b.Job["canonical"] = model.Document{"records": canonical}
	proof := document(b.Receipt["source_proof"])
	proof["row_count"], proof["verified_row_count"] = int64(len(rows)), int64(len(rows))
	b.Receipt["source_proof"] = proof
	for _, doc := range []model.Document{b.Receipt, b.Revision} {
		doc["raw_hash"], doc["canonical_hash"] = source.Hash(b.Job["raw"]), source.Hash(b.Job["canonical"])
	}
}

func TestDecisionHistoryAssemblesPagedActualHoursAndExplicitZero(t *testing.T) {
	r := newHistoryDouble(2)
	got, pins, err := AssembleDecisionForecastHistory(context.Background(), r, r.Base, r.Selection, r.Training, r.Ownership, r.Base.ObservedAt)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.History) != decisionHistoryMinimumHours || r.Calls < 30 || r.Rechecks != 1 || pins.NativeRecordCount != 2*decisionHistoryMinimumHours || pins.HistoricalHourCount != len(got.History) {
		t.Fatal("wrong actual population or missing currentness recheck", len(got.History), pins, r.Calls, r.Rechecks)
	}
	if got.History[0].UsageAmount != "0.000000000000" || got.History[1].UsageAmount != "3.000000000000" || !got.History[0].Period.Start.Equal(r.Training.Start) || !got.History[len(got.History)-1].Period.End.Equal(r.Training.End) {
		t.Fatal("explicit zero/distinct native quantities or period changed")
	}
	if Hash(got.Scope) != Hash(r.Base.Scope) || Hash(got.OptimizationOrder) != Hash(r.Base.OptimizationOrder) || len(got.OptimizationOrder) != 4 {
		t.Fatal("selected portfolio scope/four-stage prefix was rewritten")
	}
	known := map[Ref]bool{}
	for _, ref := range got.InputRefs {
		known[ref] = true
	}
	for _, row := range got.History {
		if !known[row.NativeRef] || row.ConfigurationSHA256 != r.Base.Scope.ConfigurationSHA256 {
			t.Fatal("native history proof/config omitted")
		}
	}
	for _, pin := range pins.Revisions {
		if !known[pin.Receipt] || !known[pin.Revision] || !known[pin.Job] {
			t.Fatal("revision/job omitted from closure")
		}
	}
}

func TestDecisionHistoryProducerCurrentMonthCompleteDayCoverage(t *testing.T) {
	r := newHistoryDouble(1)
	resolved := r.resolved(r.Selection.Period)
	month := time.Date(r.Selection.Period.Start.Year(), r.Selection.Period.Start.Month(), 1, 0, 0, 0, 0, time.UTC)
	end := month.AddDate(0, 1, 0)
	proof := document(resolved.Billing[0].Receipt["source_proof"])
	observedEnd := date(model.String(proof, "period_end"))
	billingEnd := date(model.String(proof, "billing_period_end"))
	if model.String(proof, "state") != "COMPLETE" || observedEnd == nil || billingEnd == nil || !observedEnd.Equal(r.Selection.Period.End) || !observedEnd.Before(*billingEnd) {
		t.Fatal("control no longer has actual producer current-month semantics")
	}
	usage, err := PrepareDecisionUsage(resolved, r.Base.Scope, r.Base.ObservedAt)
	if err != nil || usage.Status != "COMPLETE_OBSERVED_ELIGIBLE_WINDOW" {
		t.Fatal("otherwise qualified native control failed", err)
	}
	if _, valid := decisionHistoryBillingPin(resolved.Billing[0], resolved, month, end, r.Selection.Period, 1); !valid {
		t.Fatal("complete observed days demanded invented future month-end observations")
	}
	proof["period_end"] = r.Selection.Period.Start.Format(time.RFC3339Nano)
	resolved.Billing[0].Receipt["source_proof"] = proof
	if _, valid := decisionHistoryBillingPin(resolved.Billing[0], resolved, month, end, r.Selection.Period, 1); valid {
		t.Fatal("actual current-month coverage gap became a complete selected day")
	}
}

func TestDecisionHistoryRejectsNativeCounterfeitsAndIncompatibleBasis(t *testing.T) {
	tests := []struct {
		Name   string
		Change func(*DecisionHistoryPage)
	}{
		{"missing_net", func(p *DecisionHistoryPage) {
			b := &p.Chunks[0].Billing[0]
			rows := documents(document(b.Job["raw"])["records"])
			delete(rows[1], "line_item_net_unblended_cost")
			b.Job["raw"] = model.Document{"records": rows}
			historyResealBilling(b)
		}},
		{"wrong_currency", func(p *DecisionHistoryPage) {
			b := &p.Chunks[0].Billing[0]
			rows := documents(document(b.Job["raw"])["records"])
			rows[1]["line_item_currency_code"] = "EUR"
			b.Job["raw"] = model.Document{"records": rows}
			historyResealBilling(b)
		}},
		{"wrong_unit", func(p *DecisionHistoryPage) {
			b := &p.Chunks[0].Billing[0]
			rows := documents(document(b.Job["raw"])["records"])
			rows[1]["pricing_unit"] = "Seconds"
			b.Job["raw"] = model.Document{"records": rows}
			historyResealBilling(b)
		}},
		{"counterfeit_canonical", func(p *DecisionHistoryPage) {
			b := &p.Chunks[0].Billing[0]
			rows := documents(document(b.Job["canonical"])["records"])
			raw := document(rows[0]["x_ProviderFields"])
			raw["line_item_usage_amount"] = "999"
			rows[0]["x_ProviderFields"] = raw
			b.Job["canonical"] = model.Document{"records": rows}
			b.Receipt["canonical_hash"] = source.Hash(b.Job["canonical"])
			b.Revision["canonical_hash"] = source.Hash(b.Job["canonical"])
		}},
		{"stale_current_head", func(p *DecisionHistoryPage) { p.Chunks[0].Billing[0].CurrentReceiptID = "another-head" }},
		{"same_hour_incompatible_net_rates", func(p *DecisionHistoryPage) {
			b := &p.Chunks[0].Billing[0]
			rows := documents(document(b.Job["raw"])["records"])
			rows[3]["line_item_net_unblended_cost"] = "0.6"
			b.Job["raw"] = model.Document{"records": rows}
			historyResealBilling(b)
		}},
		{"duplicate_native_record", func(p *DecisionHistoryPage) {
			b := &p.Chunks[0].Billing[0]
			rows := documents(document(b.Job["raw"])["records"])
			rows = append(rows, rows[0])
			b.Job["raw"] = model.Document{"records": rows}
			historyResealBilling(b)
		}},
		{"foreign_resource_account", func(p *DecisionHistoryPage) {
			b := &p.Chunks[0].Billing[0]
			rows := documents(document(b.Job["raw"])["records"])
			rows[1]["line_item_usage_account_id"] = "999900001111"
			b.Job["raw"] = model.Document{"records": rows}
			historyResealBilling(b)
		}},
		{"partial_acquisition", func(p *DecisionHistoryPage) {
			proof := document(p.Chunks[0].Billing[0].Receipt["source_proof"])
			proof["state"] = "PARTIAL"
			p.Chunks[0].Billing[0].Receipt["source_proof"] = proof
		}},
	}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			r := newHistoryDouble(2)
			r.Mutate = func(call int, p *DecisionHistoryPage) {
				if call == 1 {
					test.Change(p)
				}
			}
			got, pins, err := AssembleDecisionForecastHistory(context.Background(), r, r.Base, r.Selection, r.Training, r.Ownership, r.Base.ObservedAt)
			if err == nil || len(got.History) != 0 || pins.SourceID != "" || r.Rechecks != 0 {
				t.Fatal("unsupported native record acquired history", err)
			}
		})
	}
}

func TestDecisionHistoryRequiresEveryResourceHourEvenWhenAggregateSKUIsComplete(t *testing.T) {
	r := newHistoryDouble(2)
	r.Mutate = func(call int, p *DecisionHistoryPage) {
		if call == 1 {
			b := &p.Chunks[0].Billing[0]
			rows := documents(document(b.Job["raw"])["records"])
			rows = append(rows[:1], rows[2:]...)
			b.Job["raw"] = model.Document{"records": rows}
			historyResealBilling(b)
		}
	}
	if got, _, err := AssembleDecisionForecastHistory(context.Background(), r, r.Base, r.Selection, r.Training, r.Ownership, r.Base.ObservedAt); err == nil || len(got.History) != 0 {
		t.Fatal("one member's missing observation was hidden by another member's complete SKU")
	}
}

func TestDecisionHistoryRejectsPageReplaySourceMovementAndLateRevocation(t *testing.T) {
	for _, name := range []string{"cursor_replay", "oversized_cursor", "too_many_chunks", "source_version_moves", "checkpoint_moves", "final_recheck"} {
		t.Run(name, func(t *testing.T) {
			r := newHistoryDouble(1)
			r.Mutate = func(call int, p *DecisionHistoryPage) {
				if name == "cursor_replay" && call == 2 {
					p.NextCursor = strconv.FormatInt(p.Chunks[0].Selection.Period.Start.Unix(), 10)
				}
				if name == "oversized_cursor" && call == 1 {
					p.NextCursor = strings.Repeat("x", 2049)
				}
				if name == "too_many_chunks" && call == 1 {
					p.Chunks = append(p.Chunks, p.Chunks[0], p.Chunks[0])
				}
				if name == "source_version_moves" && call == 2 {
					p.Chunks[0].Registration["version"] = int64(2)
				}
				if name == "checkpoint_moves" && call == 2 {
					p.Chunks[0].Checkpoint["last_sync_at"] = r.Base.ObservedAt.Add(-time.Second).Format(time.RFC3339Nano)
				}
			}
			denied := errors.New("fixture current authority revoked")
			if name == "final_recheck" {
				r.RecheckErr = denied
			}
			got, pins, err := AssembleDecisionForecastHistory(context.Background(), r, r.Base, r.Selection, r.Training, r.Ownership, r.Base.ObservedAt)
			if err == nil || len(got.History) != 0 || pins.SourceID != "" {
				t.Fatal("pagination/source/current authority movement published history")
			}
			if name == "final_recheck" && (!errors.Is(err, denied) || r.Rechecks != 1) {
				t.Fatal("late reader revocation was hidden", err)
			}
		})
	}
}

func TestDecisionHistoryRequestRejectsShortenedHistoryOwnershipGapsAndUnissuedPrefix(t *testing.T) {
	for _, name := range []string{"short_history", "ownership_gap", "scope_configuration", "stage5", "wrong_stage_scope", "missing_stage_proof", "prepopulated_history", "invalid_scope_hash"} {
		t.Run(name, func(t *testing.T) {
			r := newHistoryDouble(1)
			switch name {
			case "short_history":
				r.Training.Start = r.Training.Start.Add(24 * time.Hour)
			case "ownership_gap":
				r.Ownership.Period.Start = r.Ownership.Period.Start.Add(time.Hour)
			case "scope_configuration":
				r.Base.Scope.ConfigurationSHA256 = strings.Repeat("f", 64)
				r.Base.Scope.SHA256 = ""
				r.Base.Scope.SHA256 = Hash(r.Base.Scope)
			case "stage5":
				r.Base.OptimizationOrder = append(r.Base.OptimizationOrder, r.Base.OptimizationOrder[3])
			case "wrong_stage_scope":
				r.Base.OptimizationOrder[0].ScopeSHA256 = strings.Repeat("f", 64)
			case "missing_stage_proof":
				r.Base.InputRefs = r.Base.InputRefs[:len(r.Base.InputRefs)-1]
			case "prepopulated_history":
				r.Base.History = []DecisionHistoryHour{{UsageAmount: "0"}}
			case "invalid_scope_hash":
				r.Base.Scope.SHA256 = strings.Repeat("f", 64)
			}
			if _, _, err := AssembleDecisionForecastHistory(context.Background(), r, r.Base, r.Selection, r.Training, r.Ownership, r.Base.ObservedAt); err == nil || r.Calls != 0 {
				t.Fatal("invalid request reached native reader", err, r.Calls)
			}
		})
	}
	r := newHistoryDouble(1)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := AssembleDecisionForecastHistory(ctx, r, r.Base, r.Selection, r.Training, r.Ownership, r.Base.ObservedAt); !errors.Is(err, context.Canceled) || r.Calls != 0 {
		t.Fatal("cancelled history read started", err)
	}
}
