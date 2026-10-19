package source

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
)

type SavingsPlanQuoteReader interface {
	BillingSavingsPlanQuotes(context.Context, string, provider.SavingsPlanQuoteSelection) (model.Document, error)
}
type SavingsPlanQuoteTarget struct {
	TenantID string `json:"tenant_id"`
	SourceID string `json:"source_id"`
	PlanType string `json:"plan_type"`
	Currency string `json:"currency"`
}

func SavingsPlanQuoteTargets(encoded string) ([]SavingsPlanQuoteTarget, error) {
	if strings.TrimSpace(encoded) == "" {
		return []SavingsPlanQuoteTarget{}, nil
	}
	if len(encoded) > 65536 {
		return nil, errors.New("SAVINGS_PLAN_QUOTE_TARGET_LIMIT")
	}
	var targets []SavingsPlanQuoteTarget
	decoder := json.NewDecoder(strings.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&targets) != nil || decoder.Decode(new(any)) != io.EOF || len(targets) > 32 {
		return nil, errors.New("SAVINGS_PLAN_QUOTE_TARGET_INVALID")
	}
	seen := map[string]bool{}
	for _, target := range targets {
		key := target.TenantID + ":" + target.SourceID
		if !fleetObjectPart.MatchString(target.TenantID) || !fleetObjectPart.MatchString(target.SourceID) || seen[key] || target.PlanType != "Compute" && target.PlanType != "EC2Instance" || target.Currency != "USD" && target.Currency != "EUR" && target.Currency != "CNY" {
			return nil, errors.New("SAVINGS_PLAN_QUOTE_TARGET_INVALID")
		}
		seen[key] = true
	}
	sort.Slice(targets, func(i, j int) bool {
		return targets[i].TenantID+":"+targets[i].SourceID < targets[j].TenantID+":"+targets[j].SourceID
	})
	return targets, nil
}

type SavingsPlanQuotePipeline struct {
	Store         *store.Store
	ReaderFactory func(context.Context, Registration) (Reader, error)
	Archive       func(context.Context, string, string, []byte) (model.Document, error)
	Now           func() time.Time
}

func (p *SavingsPlanQuotePipeline) now() time.Time {
	if p.Now != nil {
		return p.Now().UTC()
	}
	return time.Now().UTC()
}

// Capture is an optional ingester-only operation. Existing BillingCommitments
// and v5 receipt semantics are unchanged. Quotes are acquired under the same
// approved read-role account context, archived/read back, then issued as a new
// discriminator. A browser cannot supply prices, plan IDs or completeness.
func (p *SavingsPlanQuotePipeline) Capture(ctx context.Context, target SavingsPlanQuoteTarget) ([]model.Document, error) {
	rawTarget, _ := json.Marshal([]SavingsPlanQuoteTarget{target})
	if _, err := SavingsPlanQuoteTargets(string(rawTarget)); err != nil {
		return nil, err
	}
	if p.Store == nil || p.ReaderFactory == nil || p.Archive == nil {
		return nil, errors.New("SAVINGS_PLAN_QUOTE_DEPENDENCIES_REQUIRED")
	}
	var registration, inventory model.Document
	err := p.Store.Do(ctx, target.TenantID, func(tx *store.Tx) error {
		var e error
		registration, e = tx.SourceGet(ctx, target.SourceID)
		if e != nil {
			return e
		}
		status, e := tx.SourceCheckpointGet(ctx, target.SourceID, "status")
		if e != nil {
			return e
		}
		inventory, e = tx.SourceReceiptGet(ctx, model.String(status, "commitment_receipt_id"))
		return e
	})
	if err != nil {
		return nil, err
	}
	r, err := ParseRegistration(registration)
	if err != nil || !r.Enabled || model.Bool(registration, "revoked") || r.TenantID != target.TenantID {
		return nil, errors.New("SAVINGS_PLAN_QUOTE_SOURCE_REQUIRED")
	}
	scope := Object(inventory["commitment_scope"])
	observed, err := time.Parse(time.RFC3339Nano, model.String(inventory, "observed_at"))
	if err != nil || observed.Before(p.now().Add(-5*time.Minute)) || observed.After(p.now().Add(5*time.Second)) || model.String(inventory, "writer_role") != "finops_ingester" || model.String(inventory, "kind") != "AWS_COMMITMENT" || !model.Bool(scope, "complete") || model.String(scope, "payer_account_id") != r.PayerAccountID || model.String(scope, "receipt_id") != model.String(inventory, "id") || Hash(scope) != model.String(inventory, "native_hash") || model.String(inventory, "config_hash") != ConfigurationHash(registration) {
		return nil, errors.New("SAVINGS_PLAN_QUOTE_ISSUED_INVENTORY_REQUIRED")
	}
	ids := []string{}
	for _, snapshot := range Rows(scope["native_snapshots"]) {
		if model.String(snapshot, "account_id") != r.PayerAccountID {
			continue
		}
		for _, plan := range Rows(snapshot["savings_plans"]) {
			id := model.String(plan, "SavingsPlanId")
			if id == "" {
				id = model.String(plan, "savingsPlanId")
			}
			arn := model.String(plan, "SavingsPlanArn")
			if arn == "" {
				arn = model.String(plan, "savingsPlanArn")
			}
			if id == "" {
				parts := strings.SplitN(arn, ":savingsplan/", 2)
				if len(parts) == 2 {
					id = parts[1]
				}
			}
			if id == "" || !strings.Contains(arn, ":"+r.PayerAccountID+":savingsplan/"+id) {
				return nil, errors.New("SAVINGS_PLAN_QUOTE_NATIVE_PLAN_ID_REQUIRED")
			}
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	reader, err := p.ReaderFactory(ctx, r)
	if err != nil {
		return nil, err
	}
	quotes, ok := reader.(SavingsPlanQuoteReader)
	if !ok {
		return nil, errors.New("SAVINGS_PLAN_QUOTE_NATIVE_READER_REQUIRED")
	}
	call, cancel := context.WithTimeout(ctx, 2*time.Minute)
	native, err := quotes.BillingSavingsPlanQuotes(call, r.PayerAccountID, provider.SavingsPlanQuoteSelection{PlanType: target.PlanType, PaymentOption: "No Upfront", DurationSeconds: 31536000, Currency: target.Currency, ExistingPlanIDs: ids})
	cancel()
	if err != nil {
		return nil, err
	}
	collected, err := time.Parse(time.RFC3339Nano, model.String(native, "observed_at"))
	if err != nil || collected.Before(p.now().Add(-5*time.Minute)) || collected.After(p.now().Add(5*time.Second)) || model.String(native, "native_projection") != provider.SavingsPlanQuoteProjection || model.String(native, "serialization") != "SDK_PROJECTION" || !model.Bool(native, "complete") || model.String(native, "authenticated_account_id") != r.PayerAccountID {
		return nil, errors.New("SAVINGS_PLAN_QUOTE_NATIVE_PROJECTION_INVALID")
	}
	raw, err := json.Marshal(native)
	if err != nil || len(raw) > 16<<20 {
		return nil, errors.New("SAVINGS_PLAN_QUOTE_ISSUANCE_LIMIT")
	}
	// The collector's selection is typed while persisted JSONB is map-shaped.
	// Canonicalize that projection before hashing/archiving, preserving exact
	// lexical JSON numbers and all existing per-page native proof hashes.
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&native) != nil {
		return nil, errors.New("SAVINGS_PLAN_QUOTE_NATIVE_PROJECTION_INVALID")
	}
	raw, err = json.Marshal(native)
	if err != nil || len(raw) > 16<<20 {
		return nil, errors.New("SAVINGS_PLAN_QUOTE_ISSUANCE_LIMIT")
	}
	digest := BytesHash(raw)
	archive, err := p.Archive(ctx, r.TenantID, r.ID, raw)
	if err != nil {
		return nil, err
	}
	if model.String(archive, "bucket") == "" || !strings.HasPrefix(model.String(archive, "key"), "tenant/"+r.TenantID+"/commitment-quotes/"+r.ID+"/") || strings.Contains(model.String(archive, "key"), "..") || model.String(archive, "version_id") == "" || model.String(archive, "version_id") == "null" || model.String(archive, "body_sha256") != digest {
		return nil, errors.New("SAVINGS_PLAN_QUOTE_VERSIONED_READBACK_REQUIRED")
	}
	revisionID := "sp-quotes-" + digest
	config := ConfigurationHash(registration)
	results := []model.Document{}
	err = p.Store.Do(ctx, r.TenantID, func(tx *store.Tx) error {
		if _, e := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0)),pg_advisory_xact_lock_shared(hashtextextended($2,0))", r.TenantID+":dependency-graph", r.TenantID+":trusted-source:"+r.ID); e != nil {
			return e
		}
		current, e := tx.SourceGet(ctx, r.ID)
		if e != nil {
			return e
		}
		checkpoint, e := tx.SourceCheckpointGet(ctx, r.ID, "status")
		if e != nil {
			return e
		}
		if !model.Bool(current, "enabled") || model.Bool(current, "revoked") || model.Number(current, "version") != r.Version || ConfigurationHash(current) != config || model.String(checkpoint, "commitment_receipt_id") != model.String(inventory, "id") || collected.Before(p.now().Add(-5*time.Minute)) {
			return errors.New("SAVINGS_PLAN_QUOTE_SOURCE_CHANGED")
		}
		if _, e = tx.SourceRevisionGet(ctx, revisionID); e == pgx.ErrNoRows {
			if _, e = tx.SourceRevisionCreate(ctx, model.Document{"id": revisionID, "source_id": r.ID, "revision_hash": digest, "kind": "AWS_SAVINGS_PLAN_RATE_QUOTES", "projection": provider.SavingsPlanQuoteProjection, "serialization": "SDK_PROJECTION", "config_hash": config, "registration_version": r.Version, "commitment_receipt_id": model.String(inventory, "id"), "native": native, "raw_object": archive, "observed_at": collected}); e != nil {
				return e
			}
		} else if e != nil {
			return e
		}
		for _, wrapper := range Rows(native["offerings"]) {
			offering := Object(wrapper["native"])
			nativeID := model.String(offering, "offeringId")
			if nativeID == "" {
				return errors.New("SAVINGS_PLAN_QUOTE_OFFER_ID_REQUIRED")
			}
			id := "sp-offer-" + Hash(model.Document{"revision": revisionID, "native_offering_id": nativeID})
			issued, e := tx.SourceReceiptGet(ctx, id)
			if e == pgx.ErrNoRows {
				_, e = tx.SourceReceiptCreate(ctx, model.Document{"id": id, "source_id": r.ID, "revision_id": revisionID, "kind": "AWS_SAVINGS_PLAN_OFFER", "projection": provider.SavingsPlanQuoteProjection, "native_offering_id": nativeID, "config_hash": config, "registration_version": r.Version, "read_role_binding_id": r.ReadRoleBindingID, "commitment_receipt_id": model.String(inventory, "id"), "collected_at": collected, "raw_object": archive, "execution_authorized": false})
				if e != nil {
					return e
				}
				issued, e = tx.SourceReceiptGet(ctx, id)
			}
			if e != nil {
				return e
			}
			results = append(results, issued)
		}
		return tx.SourceCheckpointSet(ctx, r.ID, "savings-plan-quotes", model.Document{"revision_id": revisionID, "config_hash": config, "collected_at": collected})
	})
	return results, err
}
