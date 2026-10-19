package commitmentportfolio

import (
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

type DecisionQuotes struct {
	Offer           *Offer
	ContractRates   []ContractRate
	ContractPlanIDs []string
	ContractRefs    []Ref
	ContractStatus  string
	InputRefs       []Ref
	ReasonCodes     []string
}

// prepareDecisionQuotes consumes a database-selected, ingester-issued child
// receipt and its complete SDK-projection revision. The child pins one native
// offering UUID; neither a public quote nor existing-plan rates can replace it.
func prepareDecisionQuotes(receipt, revision model.Document, inventory Input, usage []UsageHour, now time.Time) (DecisionQuotes, error) {
	out := DecisionQuotes{ContractRates: []ContractRate{}, ContractPlanIDs: []string{}, ContractRefs: []Ref{}, InputRefs: []Ref{}, ReasonCodes: []string{}, ContractStatus: "UNAVAILABLE"}
	native := document(revision["native"])
	archive := document(revision["raw_object"])
	observed := date(first(receipt, "collected_at"))
	if first(receipt, "writer_role") != "finops_ingester" || first(revision, "writer_role") != "finops_ingester" || first(receipt, "kind") != "AWS_SAVINGS_PLAN_OFFER" || first(receipt, "revision_id") != first(revision, "id") || first(receipt, "source_id") != first(revision, "source_id") || first(receipt, "projection") != "AWS_SAVINGS_PLAN_RATE_QUOTES_V1" || first(native, "native_projection") != "AWS_SAVINGS_PLAN_RATE_QUOTES_V1" || first(native, "serialization") != "SDK_PROJECTION" || native["complete"] != true || first(native, "authenticated_account_id") != inventory.PayerAccountID || observed == nil || observed.Before(now.Add(-5*time.Minute)) || observed.After(now.Add(5*time.Second)) || first(revision, "revision_hash") != Hash(native) || first(archive, "body_sha256") != Hash(native) || first(archive, "version_id") == "" || first(archive, "version_id") == "null" {
		return out, ErrEvidence
	}
	pages := documents(native["pages"])
	if len(pages) == 0 || len(pages) > 4096 {
		return out, ErrEvidence
	}
	expectedRows := map[string]int{}
	pageByHash := map[string]model.Document{}
	hashes := []string{}
	tokens := map[string]string{}
	for i, page := range pages {
		digest := first(page, "sha256")
		plain := model.Clone(page)
		delete(plain, "sha256")
		if !shaPattern.MatchString(digest) || Hash(plain) != digest || model.Number(page, "ordinal") != int64(i+1) || pageByHash[digest] != nil {
			return out, ErrEvidence
		}
		pageByHash[digest] = page
		hashes = append(hashes, digest)
		operation := first(page, "operation")
		request, response := document(page["request"]), document(page["response"])
		group := operation
		if operation == "DescribeSavingsPlanRates" {
			group += ":" + first(request, "savingsPlanId")
			if first(request, "savingsPlanId") != first(response, "savingsPlanId") {
				return out, ErrEvidence
			}
		} else if operation != "DescribeSavingsPlansOfferings" && operation != "DescribeSavingsPlansOfferingRates" {
			return out, ErrEvidence
		}
		if first(request, "nextToken") != tokens[group] {
			return out, ErrEvidence
		}
		tokens[group] = first(response, "nextToken")
		for _, row := range documents(response["searchResults"]) {
			expectedRows[digest+":"+Hash(row)]++
		}
	}
	if Hash(hashes) != Hash(native["ordered_page_sha256s"]) {
		return out, ErrEvidence
	}
	for _, token := range tokens {
		if token != "" {
			return out, ErrEvidence
		}
	}
	take := func(wrapper model.Document, operation string) (model.Document, error) {
		row := document(wrapper["native"])
		digest := first(wrapper, "page_sha256")
		page := pageByHash[digest]
		key := digest + ":" + Hash(row)
		if first(page, "operation") != operation || expectedRows[key] != 1 {
			return nil, ErrEvidence
		}
		expectedRows[key]--
		return row, nil
	}
	offeringID := first(receipt, "native_offering_id")
	var selected model.Document
	offerings := map[string]model.Document{}
	for _, wrapper := range documents(native["offerings"]) {
		row, err := take(wrapper, "DescribeSavingsPlansOfferings")
		if err != nil {
			return out, err
		}
		id := first(row, "offeringId")
		if id == "" || offerings[id] != nil {
			return out, ErrEvidence
		}
		offerings[id] = row
		if id == offeringID {
			selected = row
		}
	}
	if selected == nil {
		return out, ErrEvidence
	}
	class := map[string]string{"Compute": "COMPUTE_SAVINGS_PLAN", "EC2Instance": "EC2_INSTANCE_SAVINGS_PLAN"}[first(selected, "planType")]
	currency := first(selected, "currency")
	if class == "" || currency == "" || first(selected, "paymentOption") != "No Upfront" || model.Number(selected, "durationSeconds") != 31536000 {
		return out, ErrEvidence
	}
	offerRef := ref("AWS_SAVINGS_PLAN_OFFER", receipt)
	offer := &Offer{ID: first(receipt, "id"), NativeOfferingID: offeringID, Class: class, Currency: currency, PaymentOption: "No Upfront", DurationSeconds: "31536000", ValidityBasis: DecisionOfferValidityBasis, EffectivePeriod: Period{Start: *observed, End: observed.Add(5 * time.Minute)}, Rates: []OfferRate{}, NativeRef: offerRef}
	dimensions := map[string]Dimensions{}
	for _, hour := range usage {
		dimensions[Hash(hour.Dimensions)] = hour.Dimensions
	}
	seenOffer := map[string]string{}
	for _, wrapper := range documents(native["offering_rates"]) {
		row, err := take(wrapper, "DescribeSavingsPlansOfferingRates")
		if err != nil {
			return out, err
		}
		parent := document(row["savingsPlanOffering"])
		parentID := first(parent, "offeringId")
		known := offerings[parentID]
		if known == nil || first(parent, "currency") != first(known, "currency") || first(parent, "paymentOption") != first(known, "paymentOption") || first(parent, "planType") != first(known, "planType") || model.Number(parent, "durationSeconds") != model.Number(known, "durationSeconds") {
			return out, ErrEvidence
		}
		if parentID != offeringID {
			continue
		}
		rate := first(row, "rate")
		value, err := numberValue(&rate, false, false)
		if err != nil || value == nil {
			return out, ErrEvidence
		}
		for key, dimension := range dimensions {
			if !quoteDimensionsMatch(row, dimension, currency) {
				continue
			}
			if previous, ok := seenOffer[key]; ok && previous != rate {
				return out, ErrEvidence
			}
			if _, ok := seenOffer[key]; ok {
				continue
			}
			seenOffer[key] = rate
			offer.Rates = append(offer.Rates, OfferRate{Dimensions: dimension, Rate: rate, NativeRef: offerRef})
		}
	}
	sort.Slice(offer.Rates, func(i, j int) bool { return Hash(offer.Rates[i].Dimensions) < Hash(offer.Rates[j].Dimensions) })
	contractRef := Ref{Kind: "AWS_SAVINGS_PLAN_RATES", ID: first(revision, "id"), SHA256: Hash(revision)}
	out.InputRefs = []Ref{offerRef, contractRef}
	out.ContractRefs = []Ref{contractRef}
	planByNative := map[string]string{}
	for _, position := range inventory.Positions {
		if position.Class != "COMPUTE_SAVINGS_PLAN" && position.Class != "EC2_INSTANCE_SAVINGS_PLAN" {
			continue
		}
		if position.AccountID != inventory.PayerAccountID {
			out.ReasonCodes = append(out.ReasonCodes, "MEMBER_CONTRACT_RATE_SET_UNAVAILABLE")
			continue
		}
		parts := strings.SplitN(position.ID, ":", 6)
		if len(parts) != 6 || parts[0] != "arn" || parts[1] != "aws" || parts[2] != "savingsplans" || parts[4] != position.AccountID || !strings.HasPrefix(parts[5], "savingsplan/") {
			return out, ErrEvidence
		}
		id := strings.TrimPrefix(parts[5], "savingsplan/")
		if !idPattern.MatchString(id) || planByNative[id] != "" {
			return out, ErrEvidence
		}
		planByNative[id] = position.ID
	}
	selection := document(native["selection"])
	// A complete empty plan set is an actual JSON array. model.Strings loses
	// that distinction by returning nil for both [] and missing/null values.
	var nativeIDs []string
	encodedIDs, encodeErr := json.Marshal(selection["existing_plan_ids"])
	if encodeErr != nil || decodeDecisionPrivate(encodedIDs, &nativeIDs, 512<<10) != nil || nativeIDs == nil {
		return out, ErrEvidence
	}
	expectedIDs := []string{}
	for id := range planByNative {
		expectedIDs = append(expectedIDs, id)
	}
	sort.Strings(expectedIDs)
	if Hash(nativeIDs) != Hash(expectedIDs) || first(selection, "currency") != currency || first(selection, "payment_option") != "No Upfront" || model.Number(selection, "duration_seconds") != 31536000 || first(selection, "plan_type") != first(selected, "planType") {
		return out, ErrEvidence
	}
	seenContract := map[string]string{}
	for _, wrapper := range documents(native["existing_plan_rates"]) {
		row, err := take(wrapper, "DescribeSavingsPlanRates")
		if err != nil {
			return out, err
		}
		nativeID := first(wrapper, "savingsPlanId")
		planID := planByNative[nativeID]
		if planID == "" {
			return out, ErrEvidence
		}
		page := pageByHash[first(wrapper, "page_sha256")]
		if first(document(page["response"]), "savingsPlanId") != nativeID {
			return out, ErrEvidence
		}
		rate := first(row, "rate")
		if _, err = numberValue(&rate, false, false); err != nil {
			return out, err
		}
		for key, dimension := range dimensions {
			if !quoteDimensionsMatch(row, dimension, first(row, "currency")) {
				continue
			}
			identity := planID + ":" + key
			if previous, ok := seenContract[identity]; ok && previous != rate {
				return out, ErrEvidence
			}
			if _, ok := seenContract[identity]; ok {
				continue
			}
			seenContract[identity] = rate
			out.ContractRates = append(out.ContractRates, ContractRate{PlanID: planID, Dimensions: dimension, Rate: rate, NativeRef: contractRef})
		}
	}
	for _, count := range expectedRows {
		if count != 0 {
			return out, ErrEvidence
		}
	}
	for _, id := range expectedIDs {
		out.ContractPlanIDs = append(out.ContractPlanIDs, planByNative[id])
	}
	sort.Strings(out.ContractPlanIDs)
	sort.Slice(out.ContractRates, func(i, j int) bool {
		return out.ContractRates[i].PlanID+":"+Hash(out.ContractRates[i].Dimensions) < out.ContractRates[j].PlanID+":"+Hash(out.ContractRates[j].Dimensions)
	})
	out.ContractStatus = "COMPLETE_NATIVE_PLAN_RATE_SETS"
	if len(out.ReasonCodes) > 0 {
		out.ContractStatus = "UNAVAILABLE"
	}
	out.Offer = offer
	if len(offer.Rates) == 0 {
		out.ReasonCodes = append(out.ReasonCodes, "NATIVE_OFFER_SKU_MAPPING_UNAVAILABLE")
	}
	return out, nil
}

// Every qualifying dimension must be supplied by the native rate row. Missing
// properties do not become wildcards or representative-instance extrapolation.
func quoteDimensionsMatch(row model.Document, d Dimensions, currency string) bool {
	if currency != d.Currency || first(row, "serviceCode") != d.ServiceCode || first(row, "productType") != d.ProductType || first(row, "usageType") != d.UsageType || first(row, "operation") != d.Operation || first(row, "unit") != d.Unit {
		return false
	}
	properties := map[string]string{}
	for _, property := range documents(row["properties"]) {
		key, value := first(property, "name"), first(property, "value")
		if key == "" || value == "" || properties[key] != "" {
			return false
		}
		properties[key] = value
	}
	if properties["region"] != d.Region {
		return false
	}
	for key, expected := range map[string]*string{"instanceType": d.InstanceType, "instanceFamily": d.InstanceFamily, "productDescription": d.ProductDescription, "tenancy": d.Tenancy} {
		if expected == nil {
			return false
		}
		if key == "productDescription" && d.ServiceCode == "AmazonEC2" && d.ProductType == "EC2" && d.Operation == "RunInstances" && *expected == "Linux" && properties[key] == "Linux/UNIX" {
			continue
		}
		if properties[key] != *expected {
			return false
		}
	}
	return true
}
