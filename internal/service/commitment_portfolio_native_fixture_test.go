package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/savingsplans"
	portfolio "github.com/christopherosiemo/bn-implementation-Finops/internal/commitmentportfolio"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
)

const portfolioNativeModel = "http://commitment-portfolio-model:8000"
const portfolioNativeSource = "assessment-native"
const portfolioNativeRI = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"

var portfolioNativePlans = []string{
	"arn:aws:savingsplans::111122223333:savingsplan/11111111-1111-4111-8111-111111111111",
	"arn:aws:savingsplans::111122223333:savingsplan/22222222-2222-4222-8222-222222222222",
	"arn:aws:savingsplans::111122223333:savingsplan/33333333-3333-4333-8333-333333333333",
}

const portfolioNativeRetired = "arn:aws:savingsplans::111122223333:savingsplan/44444444-4444-4444-8444-444444444444"

type commitmentPortfolioNativeEvidence struct {
	Selection        portfolio.Selection
	Plans            []string
	CanonicalRows    int
	CanonicalSHA256  string
	ArchiveReadbacks int
}

type commitmentPortfolioNativeReader struct {
	*nativeAssessmentBillingReader
	commitment model.Document
}

func (r *commitmentPortfolioNativeReader) BillingCommitments(context.Context, string) (model.Document, error) {
	return model.Clone(r.commitment), nil
}

// These bytes are visibly synthetic provider transport responses. RI projection
// uses the same decoder called by the production signed collector; SP uses its
// actual SDK response types. They do not establish live-account authority.
func commitmentPortfolioNativeResponses(now time.Time) (model.Document, []byte, []byte, error) {
	day := now.UTC().Truncate(24 * time.Hour)
	end := day.AddDate(0, 0, 200)
	start := end.Add(-365 * 24 * time.Hour)
	riRaw := []byte(fmt.Sprintf(`<DescribeReservedInstancesResponse><reservedInstancesSet><item><reservedInstancesId>%s</reservedInstancesId><state>active</state><start>%s</start><end>%s</end><duration>31536000</duration><offeringClass>standard</offeringClass><offeringType>No Upfront</offeringType><scope>Region</scope><currencyCode>USD</currencyCode><fixedPrice>0.0</fixedPrice><usagePrice>0.0</usagePrice><instanceCount>2</instanceCount><instanceType>m6i.large</instanceType><instanceTenancy>default</instanceTenancy><productDescription>Linux/UNIX</productDescription><recurringCharges><item><frequency>Hourly</frequency><amount>0.05</amount></item></recurringCharges></item><item><reservedInstancesId>bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb</reservedInstancesId><state>payment-pending</state><end>%s</end></item></reservedInstancesSet></DescribeReservedInstancesResponse>`, portfolioNativeRI, start.Format(time.RFC3339), end.Format(time.RFC3339), end.Format(time.RFC3339)))
	ris, next, e := provider.ParseReservedInstancesResponse(riRaw, "eu-west-1")
	if e != nil || next != "" || len(ris) != 2 {
		return nil, nil, nil, errors.New("PORTFOLIO_NATIVE_RI_RESPONSE_DIFFERS")
	}
	plans := []model.Document{}
	for index, id := range portfolioNativePlans {
		until := end
		if index == 1 {
			until = day.AddDate(0, 0, 20)
		}
		from := until.Add(-365 * 24 * time.Hour)
		kind, rate := []string{"Compute", "Compute", "EC2Instance"}[index], []string{"2", "6", "1"}[index]
		plan := model.Document{"savingsPlanArn": id, "savingsPlanType": kind, "state": "active", "start": from.Format(time.RFC3339), "end": until.Format(time.RFC3339), "currency": "USD", "commitment": rate, "upfrontPaymentAmount": "0", "recurringPaymentAmount": rate, "paymentOption": "No Upfront"}
		if index == 2 {
			plan["region"], plan["ec2InstanceFamily"] = "eu-west-1", "m6i"
		}
		plans = append(plans, plan)
	}
	spRaw, e := json.Marshal(model.Document{"savingsPlans": plans})
	if e != nil {
		return nil, nil, nil, e
	}
	var response savingsplans.DescribeSavingsPlansOutput
	if json.Unmarshal(spRaw, &response) != nil || len(response.SavingsPlans) != 3 {
		return nil, nil, nil, errors.New("PORTFOLIO_NATIVE_SP_RESPONSE_DIFFERS")
	}
	nativePlans := []model.Document{}
	for _, p := range response.SavingsPlans {
		nativePlans = append(nativePlans, source.Object(p))
	}
	return model.Document{"payer_account_id": nativeAssessmentAccount, "usage_account_ids": []string{nativeAssessmentAccount}, "scope": "PAYER_ALL_LINKED_ACCOUNTS_ALL_REGIONS", "complete": true, "reserved_instance_count": len(ris), "savings_plan_count": len(nativePlans), "native_snapshots": []model.Document{{"account_id": nativeAssessmentAccount, "regions": []model.Document{{"Name": "eu-west-1"}}, "reserved_instances": ris, "savings_plans": nativePlans}}}, riRaw, spRaw, nil
}

func commitmentPortfolioNativeRows(start time.Time) []model.Document {
	rows := []model.Document{}
	for hour := 0; hour < 24; hour++ {
		at := start.Add(time.Duration(hour) * time.Hour)
		for index, plan := range portfolioNativePlans {
			rate, used, demand := []string{"2", "6", "1"}[index], []string{"1.5", "3", "0.25"}[index], []string{"4", "9", "0.8"}[index]
			for _, kind := range []string{"SavingsPlanRecurringFee", "SavingsPlanCoveredUsage", "SavingsPlanNegation"} {
				cost := rate
				if kind == "SavingsPlanCoveredUsage" {
					cost = demand
				}
				if kind == "SavingsPlanNegation" {
					cost = "-" + demand
				}
				row := nativeAssessmentUsage("i-0123456789abcdef0", "m6i.large", "PORTFOLIO-EXPLICIT-FIXTURE-SKU", cost, rate, at, at.Add(time.Hour))
				row["identity_line_item_id"] = fmt.Sprintf("portfolio:%d:%02d:%s", index, hour, kind)
				row["line_item_line_item_type"], row["savings_plan_savings_plan_a_r_n"] = kind, plan
				row["line_item_usage_amount"] = "1"
				if kind == "SavingsPlanRecurringFee" {
					row["line_item_resource_id"] = ""
					row["pricing_term"] = "Reserved"
					row["product_servicecode"] = "ComputeSavingsPlans"
					row["savings_plan_total_commitment_to_date"], row["savings_plan_used_commitment"] = rate, used
				}
				if kind == "SavingsPlanCoveredUsage" {
					row["savings_plan_savings_plan_effective_cost"] = used
				}
				rows = append(rows, row)
			}
		}
	}
	retired := nativeAssessmentUsage("", "m6i.large", "PORTFOLIO-RETIRED-FIXTURE", "0.5", "0.5", start, start.Add(time.Hour))
	retired["identity_line_item_id"] = "portfolio:retired:fee"
	retired["line_item_line_item_type"] = "SavingsPlanRecurringFee"
	retired["savings_plan_savings_plan_a_r_n"] = portfolioNativeRetired
	retired["savings_plan_total_commitment_to_date"], retired["savings_plan_used_commitment"] = "0.5", "0"
	ri := nativeAssessmentUsage("i-0123456789abcdef0", "m6i.large", "PORTFOLIO-RI-FIXTURE", "0", "0", start, start.Add(time.Hour))
	ri["identity_line_item_id"] = "portfolio:ri:covered"
	ri["line_item_line_item_type"] = "DiscountedUsage"
	ri["reservation_reservation_a_r_n"] = "arn:aws:ec2:eu-west-1:" + nativeAssessmentAccount + ":reserved-instances/" + portfolioNativeRI
	ri["reservation_effective_cost"] = "0.1"
	return append(rows, retired, ri)
}

// The callback writes to a separately owned, versioned MinIO bucket and verifies
// exact version readback. Only the ordinary ingester Pipeline issues receipts.
// Raw and canonical sources are never uploaded in an acceptance artifact.
func commitmentPortfolioIssueNative(t *testing.T, ctx context.Context, f *mutationReplayFixture, modelToken string, put func(context.Context, string, []byte) model.Document) (commitmentPortfolioNativeEvidence, error) {
	t.Helper()
	var proof commitmentPortfolioNativeEvidence
	var registration model.Document
	if e := f.roles["ingester"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		var e error
		registration, e = tx.SourceGet(ctx, portfolioNativeSource)
		return e
	}); e != nil {
		return proof, e
	}
	r, e := source.ParseRegistration(registration)
	if e != nil {
		return proof, e
	}
	now := time.Now().UTC()
	end := now.Truncate(24 * time.Hour)
	start := end.Add(-24 * time.Hour)
	scope, riRaw, spRaw, e := commitmentPortfolioNativeResponses(now)
	if e != nil {
		return proof, e
	}
	archive := func(c context.Context, key string, raw []byte) error {
		ref := put(c, "tenant/"+f.tenant+"/portfolio/"+key+"/"+source.BytesHash(raw)+".bin", raw)
		if model.String(ref, "body_sha256") != source.BytesHash(raw) || model.String(ref, "version_id") == "" || model.String(ref, "version_id") == "null" {
			return errors.New("PORTFOLIO_NATIVE_ARCHIVE_IDENTITY_DIFFERS")
		}
		proof.ArchiveReadbacks++
		return nil
	}
	if e = archive(ctx, "provider-ri", riRaw); e != nil {
		return proof, e
	}
	if e = archive(ctx, "provider-sp", spRaw); e != nil {
		return proof, e
	}
	period := time.Date(start.Year(), start.Month(), 1, 0, 0, 0, 0, time.UTC)
	reader := &commitmentPortfolioNativeReader{nativeAssessmentBillingReader: &nativeAssessmentBillingReader{}, commitment: scope}
	reader.months = []*source.FixtureReader{nativeAssessmentExport(t, r, period, commitmentPortfolioNativeRows(start), now)}
	reader.FixtureReader = reader.months[0]
	secret := os.Getenv("FLEET_CAPACITY_CLICKHOUSE_PASSWORD")
	if secret == "" {
		return proof, errors.New("PORTFOLIO_OWNED_ANALYTICS_CREDENTIAL_UNAVAILABLE")
	}
	t.Setenv("CLICKHOUSE_URL", "http://clickhouse:8123/")
	t.Setenv("CLICKHOUSE_DATABASE", "finops")
	t.Setenv("CLICKHOUSE_USER", "finops")
	t.Setenv("CLICKHOUSE_PASSWORD", secret)
	normalizerToken := os.Getenv("TEST_COMMITMENT_PORTFOLIO_NORMALIZER_TOKEN")
	if len(normalizerToken) < 32 || normalizerToken == modelToken {
		return proof, errors.New("PORTFOLIO_DISTINCT_NORMALIZER_CREDENTIAL_UNAVAILABLE")
	}
	normalizerHTTP := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer normalizerHTTP.CloseIdleConnections()
	normalizer := &API{Config: Config{EconomicsURL: "http://economics:8000", EconomicsToken: normalizerToken}, Client: normalizerHTTP}
	facts := []model.Document{}
	pipeline := source.Pipeline{Store: f.roles["ingester"], ProviderFactory: func(context.Context, source.Registration) (source.Reader, error) { return reader, nil }, Normalize: normalizer.NormalizeTrustedSource, Persist: func(c context.Context, tenant, src string, raw, canonical model.Document) error {
		encoded, e := json.Marshal(raw)
		if e != nil {
			return e
		}
		if e = archive(c, "normalized-native", encoded); e != nil {
			return e
		}
		rows, e := billingFactRows(tenant, src, canonical)
		if e != nil {
			return e
		}
		if e = persistBillingFacts(c, tenant, src, canonical); e != nil {
			return e
		}
		facts = append(facts, rows...)
		return nil
	}, ArchiveObject: func(c context.Context, tenant, src, key string, raw []byte) error {
		return archive(c, "source-"+source.BytesHash([]byte(key)), raw)
	}}
	if e = pipeline.Sync(ctx, f.tenant, portfolioNativeSource); e != nil {
		return proof, e
	}
	if len(facts) != 218 {
		return proof, errors.New("PORTFOLIO_NATIVE_FACT_POPULATION_DIFFERS")
	}
	if e = commitmentPortfolioReadbackFacts(ctx, f.tenant, secret, facts); e != nil {
		return proof, e
	}
	if e = f.roles["ingester"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		var e error
		registration, e = tx.SourceGet(ctx, portfolioNativeSource)
		return e
	}); e != nil {
		return proof, e
	}
	if model.String(registration, "status") != "HEALTHY" || model.String(registration, "commitment_receipt_id") == "" || model.String(registration, "latest_receipt_id") == "" {
		return proof, errors.New("PORTFOLIO_NATIVE_CURRENT_RECEIPTS_UNAVAILABLE")
	}
	proof.Selection = portfolio.Selection{SourceID: portfolioNativeSource, CommitmentReceiptID: model.String(registration, "commitment_receipt_id"), BillingReceiptIDs: []string{model.String(registration, "latest_receipt_id")}, Period: portfolio.Period{Start: start, End: end}}
	proof.Plans = append([]string{}, portfolioNativePlans...)
	proof.CanonicalRows = len(facts)
	proof.CanonicalSHA256 = portfolio.Hash(facts)
	return proof, nil
}

func commitmentPortfolioReadbackFacts(ctx context.Context, tenant, secret string, facts []model.Document) error {
	if !tenantKey.MatchString(tenant) || len(facts) != 218 {
		return errors.New("PORTFOLIO_NATIVE_ANALYTICS_SCOPE_DIFFERS")
	}
	wanted := map[string]model.Document{}
	versions := map[string]bool{}
	for _, f := range facts {
		v := model.String(f, "source_version")
		if !daemonFixtureSHA.MatchString(v) || f["tenant_id"] != tenant || f["source_id"] != portfolioNativeSource {
			return errors.New("PORTFOLIO_NATIVE_ANALYTICS_PIN_DIFFERS")
		}
		key := v + ":" + model.String(f, "source_record_id")
		if wanted[key] != nil {
			return errors.New("PORTFOLIO_NATIVE_ANALYTICS_DUPLICATE")
		}
		wanted[key] = f
		versions[v] = true
	}
	quoted := []string{}
	for v := range versions {
		quoted = append(quoted, "'"+v+"'")
	}
	sort.Strings(quoted)
	if len(quoted) != 1 {
		return errors.New("PORTFOLIO_NATIVE_ANALYTICS_VERSION_DIFFERS")
	}
	q := "SELECT source_version,source_record_id,resource_id,currency,toString(billed_cost) AS billed_cost,toString(effective_cost) AS effective_cost,toString(toUnixTimestamp64Nano(source_time)) AS source_time_ns,payload FROM billing_facts FINAL WHERE tenant_id='" + tenant + "' AND source_id='" + portfolioNativeSource + "' AND source_version IN (" + strings.Join(quoted, ",") + ") ORDER BY source_version,source_record_id FORMAT JSONEachRow"
	r, e := http.NewRequestWithContext(ctx, http.MethodPost, "http://clickhouse:8123/?"+url.Values{"database": {"finops"}, "query": {q}}.Encode(), nil)
	if e != nil {
		return e
	}
	r.Header.Set("X-ClickHouse-User", "finops")
	r.Header.Set("X-ClickHouse-Key", secret)
	c := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer c.CloseIdleConnections()
	response, e := c.Do(r)
	if e != nil {
		return errors.New("PORTFOLIO_NATIVE_ANALYTICS_UNAVAILABLE")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return errors.New("PORTFOLIO_NATIVE_ANALYTICS_REFUSED")
	}
	raw, e := io.ReadAll(io.LimitReader(response.Body, (4<<20)+1))
	if e != nil || len(raw) > 4<<20 {
		return errors.New("PORTFOLIO_NATIVE_ANALYTICS_BOUND")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	count := 0
	for {
		var got model.Document
		e = d.Decode(&got)
		if e == io.EOF {
			break
		}
		if e != nil || count >= 218 {
			return errors.New("PORTFOLIO_NATIVE_ANALYTICS_SHAPE")
		}
		count++
		key := model.String(got, "source_version") + ":" + model.String(got, "source_record_id")
		want := wanted[key]
		if want == nil || got["resource_id"] != want["resource_id"] || got["currency"] != want["currency"] || got["payload"] != want["payload"] {
			return errors.New("PORTFOLIO_NATIVE_ANALYTICS_COLUMN_DIFFERS")
		}
		value, ok := new(big.Rat).SetString(model.String(got, "billed_cost"))
		expected, ok2 := new(big.Rat).SetString(model.String(want, "billed_cost"))
		at, e := time.Parse(time.RFC3339, model.String(want, "source_time"))
		if !ok || !ok2 || value.Cmp(expected) != 0 || e != nil || model.String(got, "source_time_ns") != strconv.FormatInt(at.UnixNano(), 10) {
			return errors.New("PORTFOLIO_NATIVE_ANALYTICS_EXACT_FACT_DIFFERS")
		}
		if want["effective_cost"] == nil {
			if got["effective_cost"] != nil {
				return errors.New("PORTFOLIO_NATIVE_ANALYTICS_UNKNOWN_COST_CHANGED")
			}
		} else {
			a, ok := new(big.Rat).SetString(model.String(got, "effective_cost"))
			b, ok2 := new(big.Rat).SetString(model.String(want, "effective_cost"))
			if !ok || !ok2 || a.Cmp(b) != 0 {
				return errors.New("PORTFOLIO_NATIVE_ANALYTICS_EFFECTIVE_COST_DIFFERS")
			}
		}
		delete(wanted, key)
	}
	if count != 218 || len(wanted) != 0 {
		return errors.New("PORTFOLIO_NATIVE_ANALYTICS_POPULATION_DIFFERS")
	}
	return nil
}

func commitmentPortfolioNativeRuntime(t *testing.T, ctx context.Context, admin *store.Store, tenant string) *store.Store {
	t.Helper()
	dir := t.TempDir()
	raw, e := os.ReadFile(filepath.Join("..", "..", "migrations", "039_commitment_portfolio.sql"))
	if e != nil {
		t.Fatal(e)
	}
	if os.WriteFile(filepath.Join(dir, "039_commitment_portfolio.sql"), raw, 0600) != nil {
		t.Fatal("portfolio migration copy failed")
	}
	if e = admin.Migrate(ctx, dir); e != nil {
		t.Fatal(e)
	}
	login := "portfolio_native_" + strings.ReplaceAll(model.ID(), "-", "")
	password := model.ID()
	id := model.ID()
	install, e := admin.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if e != nil {
		t.Fatal(e)
	}
	defer install.Rollback(ctx)
	if _, e = install.Exec(ctx, "CREATE ROLE "+pgx.Identifier{login}.Sanitize()+" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '"+password+"' IN ROLE finops_commitment_portfolio"); e != nil {
		t.Fatal(e)
	}
	if _, e = install.Exec(ctx, "INSERT INTO commitment_portfolio_credentials(id,database_login,role_oid,tenant_id) SELECT $1,rolname,oid,$3 FROM pg_roles WHERE rolname=$2", id, login, tenant); e != nil {
		t.Fatal(e)
	}
	var installedOID uint32
	if e = install.QueryRow(ctx, "SELECT oid FROM pg_roles WHERE rolname=$1", login).Scan(&installedOID); e != nil {
		t.Fatal(e)
	}
	if e = install.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	var analyst *store.Store
	t.Cleanup(func() {
		if analyst != nil {
			analyst.Pool.Close()
		}
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var actual uint32
		if e := admin.Pool.QueryRow(c, "SELECT oid FROM pg_roles WHERE rolname=$1", login).Scan(&actual); e != nil || actual != installedOID {
			t.Error("portfolio owned login cleanup identity differs")
			return
		}
		if _, e := admin.Pool.Exec(c, "DROP ROLE "+pgx.Identifier{login}.Sanitize()); e != nil {
			t.Error("portfolio owned login cleanup failed")
		}
	})
	cfg := admin.Pool.Config().ConnConfig
	dsn := url.URL{Scheme: "postgres", Host: net.JoinHostPort(cfg.Host, strconv.Itoa(int(cfg.Port))), Path: "/" + cfg.Database, User: url.UserPassword(login, password), RawQuery: "sslmode=disable"}
	analyst, e = store.OpenRuntime(ctx, dsn.String(), "commitment-portfolio-reader")
	if e != nil {
		t.Fatal(e)
	}
	return analyst
}

func commitmentPortfolioGet(t *testing.T, f *mutationReplayFixture, token, id string) model.Document {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/v1/commitment-portfolio-analyses/"+id, nil)
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	f.api.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal("portfolio persisted read failed", w.Code)
	}
	var result model.Document
	if json.Unmarshal(w.Body.Bytes(), &result) != nil {
		t.Fatal("portfolio persisted response shape invalid")
	}
	return result
}

func commitmentPortfolioAssertNative(t *testing.T, record model.Document, proof commitmentPortfolioNativeEvidence) {
	t.Helper()
	analysis := source.Object(record["analysis"])
	if model.String(record, "status") != "ASSESSED" || portfolio.Hash(record["selection"]) != portfolio.Hash(proof.Selection) || model.String(analysis, "recommendation_status") != "BLOCKED" {
		t.Fatal("portfolio native selection or assessment differs")
	}
	byID := map[string]model.Document{}
	for _, row := range source.Rows(analysis["positions"]) {
		byID[model.String(source.Object(row["position"]), "id")] = row
	}
	for index, want := range []struct{ committed, used, unused, utilization string }{{"48", "36", "12", "0.75"}, {"144", "72", "72", "0.5"}, {"24", "6", "18", "0.25"}} {
		p := byID[proof.Plans[index]]
		if model.String(p, "observed_committed_cost") != want.committed || model.String(p, "observed_used_commitment") != want.used || model.String(p, "observed_unused_commitment") != want.unused || model.String(p, "utilization") != want.utilization {
			t.Fatal("portfolio native hourly utilization arithmetic differs", index)
		}
	}
	found := false
	for _, p := range source.Rows(analysis["partitions"]) {
		if model.String(p, "class") == "COMPUTE_SAVINGS_PLAN" {
			if model.String(p, "observed_committed_cost") != "192" || model.String(p, "observed_used_commitment") != "108" || model.String(p, "observed_unused_commitment") != "84" || model.String(p, "utilization") != "0.5625" || model.String(p, "hourly_commitment_rate") != "8" {
				t.Fatal("portfolio native partition arithmetic differs")
			}
			shares := source.Rows(p["position_shares"])
			if len(shares) != 2 || shares[0]["share"] != "0.25" || shares[1]["share"] != "0.75" {
				t.Fatal("portfolio native concentration differs")
			}
			found = true
		}
	}
	if !found {
		t.Fatal("portfolio native compute partition absent")
	}
	expiry := source.Object(byID[proof.Plans[1]]["expiry"])
	remaining, okay := new(big.Rat).SetString(model.String(expiry, "remaining_seconds"))
	if model.String(expiry, "status") != "ACTIVE" || !model.Bool(expiry, "expires_within_window") || model.Number(expiry, "within_days") != 30 || !okay || remaining.Sign() <= 0 || remaining.Cmp(big.NewRat(30*86400, 1)) > 0 {
		t.Fatal("portfolio native expiry was not derived from the issued term")
	}
	p := byID[nativeAssessmentAccount+":ri:"+portfolioNativeRI]
	if p == nil || p["utilization"] != nil || model.String(source.Object(p["position"]), "class") != "EC2_STANDARD_RI" || model.String(p, "observed_allocated_cost") != "0.1" {
		t.Fatal("native RI terms/allocation became inferred hourly utilization")
	}
	terms := source.Object(source.Object(p["position"])["reserved_instance_terms"])
	if terms["fixed_price"] != "0.0" || terms["usage_price"] != "0.0" || terms["instance_count"] != "2" || terms["scope"] != "Region" || terms["currency_code"] != "USD" {
		t.Fatal("native RI observed zero or scope/price terms were lost")
	}
	unknown := byID[nativeAssessmentAccount+":ri:bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"]
	if unknown == nil || unknown["utilization"] != nil || unknown["observed_billed_cost"] != nil || source.Object(unknown["position"])["currency"] != nil {
		t.Fatal("unpriced RI unknown became observed zero")
	}
	unmatched := source.Rows(analysis["unmatched_billing"])
	if len(unmatched) != 1 || model.String(unmatched[0], "commitment_id") != portfolioNativeRetired || model.String(unmatched[0], "observed_billed_cost") != "0.5" {
		t.Fatal("native retired commitment billing disappeared")
	}
	for _, row := range source.Rows(analysis["positions"]) {
		if row["coverage"] != nil || row["cash_requirement"] != nil || row["remaining_value"] != nil || row["expected_utilization"] != nil || row["confidence_interval"] != nil {
			t.Fatal("portfolio unknown economics became an observed value")
		}
	}
	stages := source.Rows(analysis["optimization_order"])
	if len(stages) != 5 {
		t.Fatal("portfolio mandatory optimization order disappeared")
	}
	for _, s := range stages {
		if model.String(s, "status") != "BLOCKED" || s["decision_ref"] != nil || s["outcome_ref"] != nil || s["scope_sha256"] != nil {
			t.Fatal("portfolio unissued optimization completion was invented")
		}
	}
	if analysis["expected_savings"] != nil || analysis["estimated_saving"] != nil || analysis["verified_saving"] != nil || model.Bool(analysis, "recommendation_authorized") || model.Bool(analysis, "purchase_authorized") || model.Bool(analysis, "execution_authorized") {
		t.Fatal("portfolio analysis granted financial or execution authority")
	}
}

func TestCommitmentPortfolioProviderShapedNativeFixture(t *testing.T) {
	now := time.Now().UTC()
	scope, _, _, e := commitmentPortfolioNativeResponses(now)
	if e != nil || model.Number(scope, "reserved_instance_count") != 2 || model.Number(scope, "savings_plan_count") != 3 {
		t.Fatal("native inventory fixture invalid", e)
	}
	rows := commitmentPortfolioNativeRows(now.Truncate(24 * time.Hour).Add(-24 * time.Hour))
	if len(rows) != 218 {
		t.Fatal("native CUR fixture row count invalid")
	}
	for _, row := range rows {
		a, e1 := time.Parse(time.RFC3339, model.String(row, "line_item_usage_start_date"))
		b, e2 := time.Parse(time.RFC3339, model.String(row, "line_item_usage_end_date"))
		if e1 != nil || e2 != nil || b.Sub(a) != time.Hour {
			t.Fatal("native hourly CUR became a daily total")
		}
	}
}

func commitmentPortfolioCheckModelAuthentication(t *testing.T, ctx context.Context) {
	t.Helper()
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	for _, endpoint := range []string{"http://economics:8000/v3/normalize", portfolioNativeModel + "/v5/commitment-portfolio"} {
		for _, token := range []string{"", "fixture-wrong-bearer"} {
			r, e := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(`{}`))
			if e != nil {
				t.Fatal(e)
			}
			r.Header.Set("Content-Type", "application/json")
			if token != "" {
				r.Header.Set("Authorization", "Bearer "+token)
			}
			response, e := client.Do(r)
			if e != nil {
				t.Fatal("portfolio private authentication probe unavailable")
			}
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
			_ = response.Body.Close()
			if response.StatusCode != http.StatusUnauthorized {
				t.Fatal("portfolio private authentication was bypassed", response.StatusCode)
			}
		}
	}
}

func TestCommitmentPortfolioActualIssuedNativePipelineAndModel(t *testing.T) {
	if os.Getenv("COMMITMENT_PORTFOLIO_NATIVE_LAB") != "ISOLATED_VERSIONED_MINIO_CLICKHOUSE" {
		t.Skip("requires separately owned PG/MinIO/ClickHouse/private Python")
	}
	if os.Getenv("TEST_FLEET_HISTORY_S3_ENDPOINT") != "http://minio:9000" || os.Getenv("FLEET_CAPACITY_CLICKHOUSE_URL") != "http://clickhouse:8123" {
		t.Fatal("portfolio isolated endpoint boundary differs")
	}
	modelToken := os.Getenv("TEST_COMMITMENT_PORTFOLIO_MODEL_TOKEN")
	access, secret := os.Getenv("TEST_FLEET_HISTORY_S3_ACCESS_KEY"), os.Getenv("TEST_FLEET_HISTORY_S3_SECRET_KEY")
	if len(modelToken) < 32 || access == "" || secret == "" || modelToken == secret {
		t.Fatal("portfolio private service credentials unavailable")
	}
	f, admin, _, _ := newFleetNativeHTTPTest(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	analyst := commitmentPortfolioNativeRuntime(t, ctx, admin, f.tenant)
	commitmentPortfolioAssertSharedRoleMigration(t, ctx, admin)
	commitmentPortfolioCheckModelAuthentication(t, ctx)
	archive := s3.NewFromConfig(aws.Config{Region: "eu-west-1", Credentials: credentials.NewStaticCredentialsProvider(access, secret, "")}, func(o *s3.Options) { o.BaseEndpoint = aws.String("http://minio:9000"); o.UsePathStyle = true })
	bucket := "native-portfolio-" + strings.ReplaceAll(model.ID(), "-", "")
	owner := model.ID()
	if _, e := archive.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)}); e != nil {
		t.Fatal(e)
	}
	if _, e := archive.PutBucketTagging(ctx, &s3.PutBucketTaggingInput{Bucket: aws.String(bucket), Tagging: &s3types.Tagging{TagSet: []s3types.Tag{{Key: aws.String("finops-portfolio-owner"), Value: aws.String(owner)}}}}); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		c, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		tags, e := archive.GetBucketTagging(c, &s3.GetBucketTaggingInput{Bucket: aws.String(bucket)})
		owned := false
		if e == nil {
			for _, tag := range tags.TagSet {
				owned = owned || aws.ToString(tag.Key) == "finops-portfolio-owner" && aws.ToString(tag.Value) == owner
			}
		}
		if !owned {
			t.Error("portfolio archive cleanup ownership differs")
			return
		}
		pages := s3.NewListObjectVersionsPaginator(archive, &s3.ListObjectVersionsInput{Bucket: aws.String(bucket)})
		for pages.HasMorePages() {
			page, e := pages.NextPage(c)
			if e != nil || len(page.Versions)+len(page.DeleteMarkers) > 1000 {
				t.Error("portfolio archive cleanup enumeration failed")
				return
			}
			objects := []s3types.ObjectIdentifier{}
			for _, v := range page.Versions {
				objects = append(objects, s3types.ObjectIdentifier{Key: v.Key, VersionId: v.VersionId})
			}
			for _, v := range page.DeleteMarkers {
				objects = append(objects, s3types.ObjectIdentifier{Key: v.Key, VersionId: v.VersionId})
			}
			if len(objects) > 0 {
				out, e := archive.DeleteObjects(c, &s3.DeleteObjectsInput{Bucket: aws.String(bucket), Delete: &s3types.Delete{Objects: objects, Quiet: aws.Bool(true)}})
				if e != nil || len(out.Errors) > 0 {
					t.Error("portfolio archive version cleanup failed")
					return
				}
			}
		}
		if _, e = archive.DeleteBucket(c, &s3.DeleteBucketInput{Bucket: aws.String(bucket)}); e != nil {
			t.Error("portfolio archive bucket cleanup failed")
		}
	})
	if _, e := archive.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{Bucket: aws.String(bucket), VersioningConfiguration: &s3types.VersioningConfiguration{Status: s3types.BucketVersioningStatusEnabled}}); e != nil {
		t.Fatal(e)
	}
	put := func(c context.Context, key string, raw []byte) model.Document {
		t.Helper()
		out, e := archive.PutObject(c, &s3.PutObjectInput{Bucket: aws.String(bucket), Key: aws.String(key), Body: bytes.NewReader(raw)})
		if e != nil || out.VersionId == nil || aws.ToString(out.VersionId) == "null" {
			t.Fatal("portfolio versioned archive failed")
		}
		back, e := archive.GetObject(c, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key), VersionId: out.VersionId})
		if e != nil {
			t.Fatal("portfolio version readback failed")
		}
		body, e := io.ReadAll(io.LimitReader(back.Body, (32<<20)+1))
		_ = back.Body.Close()
		if e != nil || len(body) > 32<<20 || !bytes.Equal(body, raw) || aws.ToString(back.VersionId) != aws.ToString(out.VersionId) {
			t.Fatal("portfolio archived version bytes differ")
		}
		return model.Document{"bucket": bucket, "key": key, "version_id": aws.ToString(out.VersionId), "body_sha256": source.BytesHash(raw)}
	}
	proof, e := commitmentPortfolioIssueNative(t, ctx, f, modelToken, put)
	if e != nil {
		t.Fatal("portfolio ordinary source ingestion failed", e)
	}
	finance := f.token(f.tenant, "native-portfolio-finance", "FINANCE")
	code, queued, _ := f.request("commitment-portfolio-analyses", `"0"`, "native-portfolio-actual", finance, source.Object(proof.Selection))
	if code != 202 {
		t.Fatal("portfolio IDs-only queue failed", code)
	}
	calculator, e := portfolio.NewHTTPCalculator(ctx, portfolioNativeModel, "LOCAL_PRIVATE", modelToken)
	if e != nil {
		t.Fatal(e)
	}
	worker := portfolio.Worker{Pool: analyst.Pool, Tenant: f.tenant, Calculator: calculator}
	if replayed, e := worker.Process(ctx, model.String(queued, "id")); e != nil || replayed {
		t.Fatal("actual native portfolio worker failed", e)
	}
	first := commitmentPortfolioGet(t, f, finance, model.String(queued, "id"))
	commitmentPortfolioAssertNative(t, first, proof)
	if replayed, e := worker.Process(ctx, model.String(queued, "id")); e != nil || !replayed {
		t.Fatal("portfolio immutable worker replay failed", e)
	}
	second := commitmentPortfolioGet(t, f, finance, model.String(queued, "id"))
	if portfolio.Hash(first) != portfolio.Hash(second) {
		t.Fatal("portfolio persisted reload/replay changed")
	}
	commitmentPortfolioAssertBoundaries(t, ctx, f, analyst, proof.Selection, finance, model.String(queued, "id"))
	commitmentPortfolioPositiveBrowserPhase(t, ctx, f, admin, analyst, proof, modelToken)
	t.Log("Actual issued native portfolio:218 canonical rows,versioned archive+ClickHouse,private Python,restricted worker/API,immutable replay; no live,forecast,purchase or execution claim")
}
