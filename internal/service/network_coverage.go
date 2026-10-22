package service

import (
	"context"
	"encoding/json"
	"math/big"
	"sort"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
)

type networkCoveragePublication struct {
	blocked  bool
	currency string
	lines    map[string]bool
}

// A native resource charge is not promoted by a partial destination cohort.
// Only current, complete, exclusive populations with supported native economics
// for every cohort can identify their exact canonical source lines as analysed.
func networkCoverageEconomicLines(assessment model.Document) map[string]bool {
	empty := func() map[string]bool { return map[string]bool{} }
	status := model.String(assessment, "status")
	if model.String(assessment, "model_kind") != "NETWORK_ASSESSMENT_V1" || (status != "RECOMMENDED" && status != "NO_CHANGE") || assessment["read_only"] != true || assessment["pre_execution_ready"] != false || assessment["execution_authorized"] != false || assessment["verified_saving"] != nil {
		return empty()
	}
	denominators := storageObject(assessment["denominators"])
	for _, field := range []string{"observation_complete", "flow_complete", "billing_complete", "billing_scope_complete"} {
		if denominators[field] != true {
			return empty()
		}
	}
	observed, ok := databaseDecimal(denominators["observed_processed_bytes"])
	attributed, aok := databaseDecimal(denominators["attributed_cohort_bytes"])
	unattributed, uok := databaseDecimal(denominators["unattributed_bytes"])
	if !ok || !aok || !uok || observed.Sign() < 0 || observed.Cmp(attributed) != 0 || unattributed.Sign() != 0 {
		return empty()
	}
	economics := storageObject(assessment["economics"])
	currency := model.String(economics, "currency")
	total, tok := databaseDecimal(economics["detected_native_cost"])
	if !databaseCoverageCurrency.MatchString(currency) || !tok {
		return empty()
	}
	cohorts := storageRows(assessment["cohorts"])
	candidates := storageRows(assessment["candidates"])
	if len(cohorts) == 0 || len(cohorts) > 4096 || len(candidates) != len(cohorts) {
		return empty()
	}
	byCohort := map[string]model.Document{}
	for _, candidate := range candidates {
		id := model.String(candidate, "cohort_id")
		if id == "" || byCohort[id] != nil {
			return empty()
		}
		byCohort[id] = candidate
	}
	allocated, bytes := new(big.Rat), new(big.Rat)
	seen := map[string]bool{}
	for _, cohort := range cohorts {
		id := model.String(cohort, "id")
		candidate := byCohort[id]
		if id == "" || seen[id] || candidate == nil || cohort["traffic_complete"] != true || cohort["attribution_complete"] != true {
			return empty()
		}
		seen[id] = true
		status := model.String(candidate, "status")
		econ := storageObject(candidate["economics"])
		if (status != "RECOMMENDED" && status != "NO_CHANGE") || model.String(econ, "status") != "MODELLED_NATIVE_CUSTOMER_ECONOMICS" || model.String(econ, "pricing_basis") != "NATIVE_CUSTOMER_NET_ONLY" || model.String(econ, "currency") != currency {
			return empty()
		}
		amount, valid := databaseDecimal(econ["observed_allocated_cost"])
		count, cvalid := databaseDecimal(cohort["bytes"])
		if !valid || !cvalid || count.Sign() < 0 {
			return empty()
		}
		allocated.Add(allocated, amount)
		bytes.Add(bytes, count)
	}
	if allocated.Cmp(total) != 0 || bytes.Cmp(observed) != 0 {
		return empty()
	}
	return databaseCoverageEconomicLines(model.Document{"source_refs": assessment["financial_references"]})
}

func (a *API) networkCoveragePublications(ctx context.Context, tx *store.Tx) (map[string]networkCoveragePublication, error) {
	rows, err := tx.Query(ctx, `SELECT id,resource_id,document FROM (SELECT DISTINCT ON(resource_id) id,resource_id,document,created_at FROM network_assessments WHERE tenant_id=$1 ORDER BY resource_id,created_at DESC,id DESC) latest ORDER BY resource_id LIMIT $2`, tx.Tenant, databaseCoverageLimit+1)
	if err != nil {
		return nil, err
	}
	records := []model.Document{}
	for rows.Next() {
		var id, resource string
		var raw []byte
		if err = rows.Scan(&id, &resource, &raw); err != nil {
			break
		}
		var record model.Document
		if err = json.Unmarshal(raw, &record); err != nil {
			break
		}
		record["id"], record["resource_id"] = id, resource
		records = append(records, record)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return nil, err
	}
	if len(records) > databaseCoverageLimit {
		return nil, problem(422, "NETWORK_COVERAGE_ASSESSMENT_LIMIT", "network assessment coverage bound exceeded")
	}
	out := map[string]networkCoveragePublication{}
	for _, record := range records {
		assessment := storageObject(record["assessment"])
		publication := networkCoveragePublication{blocked: model.String(record, "status") == "BLOCKED" || model.String(assessment, "status") == "BLOCKED", currency: model.String(storageObject(assessment["economics"]), "currency"), lines: map[string]bool{}}
		if model.String(record, "status") == "ASSESSED" {
			current, err := a.networkCurrent(ctx, tx, record)
			if err != nil {
				return nil, err
			}
			if current["current"] == true {
				publication.lines = networkCoverageEconomicLines(assessment)
			} else {
				publication.blocked = true
			}
		}
		out[model.String(record, "resource_id")] = publication
	}
	return out, nil
}

func networkCoverageRows(groups map[string]*databaseCoverageTotals, incomplete bool) []model.Document {
	currencies := make([]string, 0, len(groups))
	for currency := range groups {
		currencies = append(currencies, currency)
	}
	sort.Strings(currencies)
	out := []model.Document{}
	for _, currency := range currencies {
		g := groups[currency]
		row := model.Document{"currency": nullableDatabaseString(currency), "basis": "POSITIVE_BILLED_CHARGES", "complete": g.complete && g.known && !incomplete, "analysed_percent": nil}
		for key, value := range g.values {
			if g.known {
				row[key] = databaseCoverageAmount(value)
			} else {
				row[key] = nil
			}
		}
		if model.Bool(row, "complete") && g.values["detected_spend"].Sign() > 0 {
			row["analysed_percent"] = databaseCoverageAmount(new(big.Rat).Mul(new(big.Rat).Quo(g.values["analysed_spend"], g.values["detected_spend"]), big.NewRat(100, 1)))
		}
		out = append(out, row)
	}
	return out
}

func networkCoverageComponent(record model.Document) string {
	raw := storageObject(record["x_ProviderFields"])
	if kind := networkChargeKind(raw); kind != "" {
		return kind
	}
	service := databaseRawString(raw, "product_servicecode")
	if service == "" {
		service = model.String(record, "ServiceName")
	}
	if service == "AmazonVPC" || service == "AWSDataTransfer" || service == "AWSELB" {
		return "UNSUPPORTED_NETWORK_COMPONENT"
	}
	if service == "AmazonEC2" {
		switch databaseRawString(raw, "product_product_family") {
		case "Data Transfer", "IP Address", "NAT Gateway", "Networking":
			return "UNSUPPORTED_NETWORK_COMPONENT"
		}
	}
	return ""
}
