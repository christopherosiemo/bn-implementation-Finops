//go:build commitment_decision_native_integration

package service

// This extends the existing portfolio native lab; it owns no runtime. CUR and
// historical provider transports are explicit deterministic doubles. Ordinary
// ingester receipts, private normalization, CH facts and versioned app mirrors
// must still be produced by their real code. No fixture row grants authority.
import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	portfolio "github.com/christopherosiemo/bn-implementation-Finops/internal/commitmentportfolio"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
)

type commitmentDecisionNativeHistory struct {
	Selection            portfolio.Selection
	Training             portfolio.Period
	CurrentMonthReceipts []portfolio.Ref
	NativeHourlyRows     int
	AnalyticsReadbacks   int
	ArchiveReadbacks     int
	Refresh              func(context.Context) error `json:"-"`
}

// Derive the training window from the SAME policy as the actual PREPARE worker.
// Keep enough history for the largest supported real billing-to-projection gap,
// including an hour/day boundary during fixture preparation. Only actual rows
// below are admitted; this does not change production now or receipt clocks.
func commitmentDecisionNativeWindow(now time.Time) (portfolio.Period, portfolio.Period, error) {
	end := now.UTC().Truncate(24 * time.Hour)
	selected := portfolio.Period{Start: end.Add(-24 * time.Hour), End: end}
	training, err := portfolio.DecisionHistoryTrainingPeriod(selected, end.Add(49*time.Hour))
	return selected, training, err
}

func commitmentDecisionNativeMonthRows(resource string, start, end time.Time) []model.Document {
	rows := make([]model.Document, 0, int(end.Sub(start)/time.Hour))
	for at := start; at.Before(end); at = at.Add(time.Hour) {
		row := nativeAssessmentUsage(resource, "m6i.large", "EXPLICIT-TRANSPORT-FIXTURE-M6I-LARGE", "0.2", "0.2", at, at.Add(time.Hour))
		row["identity_line_item_id"] = "advice-native:" + resource + ":" + at.Format("20060102T150405Z")
		row["line_item_net_unblended_cost"], row["line_item_net_unblended_rate"] = "0.2", "0.2"
		// Preserve the native CUR labels. The model/issuer, never this producer,
		// owns documented mappings to SavingsPlan SKU/platform properties.
		row["product_instance_family"] = "General purpose"
		row["bill_invoice_id"] = "decision-native-invoice-" + at.Format("200601")
		rows = append(rows, row)
	}
	return rows
}

// Caller first creates the workload/resource and registered source using the
// existing actual fixture/API. This helper never inserts trusted evidence.
func commitmentDecisionIssueNativeHistory(t *testing.T, ctx context.Context, f *mutationReplayFixture, sourceID, resource string, put func(context.Context, string, []byte) (model.Document, error)) (commitmentDecisionNativeHistory, error) {
	t.Helper()
	proof := commitmentDecisionNativeHistory{CurrentMonthReceipts: []portfolio.Ref{}}
	if f == nil || put == nil || sourceID == "" || resource == "" {
		return proof, errors.New("DECISION_NATIVE_FIXTURE_DEPENDENCIES_REQUIRED")
	}
	var registration model.Document
	if err := f.roles["ingester"].Do(ctx, f.tenant, func(tx *store.Tx) error { var err error; registration, err = tx.SourceGet(ctx, sourceID); return err }); err != nil {
		return proof, err
	}
	r, err := source.ParseRegistration(registration)
	if err != nil || r.PayerAccountID != nativeAssessmentAccount || r.Region != "eu-west-1" || len(r.UsageAccountIDs) != 1 || r.UsageAccountIDs[0] != nativeAssessmentAccount {
		return proof, errors.New("DECISION_NATIVE_SOURCE_SCOPE_DIFFERS")
	}
	now := time.Now().UTC()
	selected, training, err := commitmentDecisionNativeWindow(now)
	if err != nil {
		return proof, err
	}
	proof.Training = training
	reader := &nativeAssessmentBillingReader{}
	firstMonth := time.Date(training.Start.Year(), training.Start.Month(), 1, 0, 0, 0, 0, time.UTC)
	for month := firstMonth; month.Before(training.End); month = month.AddDate(0, 1, 0) {
		start, end := month, month.AddDate(0, 1, 0)
		if end.After(training.End) {
			end = training.End
		}
		rows := commitmentDecisionNativeMonthRows(resource, start, end)
		if len(rows) == 0 {
			return proof, errors.New("DECISION_NATIVE_EMPTY_MONTH")
		}
		proof.NativeHourlyRows += len(rows)
		frame := nativeAssessmentExport(t, r, month, rows, now)
		for _, invoice := range frame.Invoices {
			invoice["InvoiceId"] = "decision-native-invoice-" + month.Format("200601")
		}
		// Preserve the full first native calendar month even when the requested
		// training starts inside it. The resolver selects its exact chunk without
		// slicing or resealing the immutable source job. Last/current month ends at
		// the actual latest complete billing day, never an invented future hour.
		// Existing helper names by month only; make the *actual* native execution
		// ordering unique over years too. Do not modify the original helper.
		frame.Execution["ExecutionStatus"] = model.Document{"StatusCode": "DELIVERY_SUCCESS", "CreatedAt": now.Add(-time.Duration(len(reader.months)+2) * time.Second).Format(time.RFC3339Nano)}
		reader.months = append(reader.months, frame)
	}
	if len(reader.months) < 1 || len(reader.months) > 64 || proof.NativeHourlyRows != int(training.End.Sub(firstMonth)/time.Hour) || proof.NativeHourlyRows > 100000 {
		return proof, errors.New("DECISION_NATIVE_HISTORY_BOUNDS_DIFFER")
	}
	reader.FixtureReader = reader.months[0]
	archive := func(c context.Context, key string, raw []byte) error {
		ref, err := put(c, "tenant/"+f.tenant+"/decision-native/"+sourceID+"/"+source.BytesHash([]byte(key))+"/"+source.BytesHash(raw)+".bin", raw)
		if err != nil {
			return err
		}
		if model.String(ref, "body_sha256") != source.BytesHash(raw) || model.String(ref, "version_id") == "" || model.String(ref, "version_id") == "null" {
			return errors.New("DECISION_NATIVE_IMMUTABLE_READBACK_DIFFERS")
		}
		proof.ArchiveReadbacks++
		return nil
	}
	chPassword := os.Getenv("FLEET_CAPACITY_CLICKHOUSE_PASSWORD")
	normalizerToken := os.Getenv("TEST_COMMITMENT_PORTFOLIO_NORMALIZER_TOKEN")
	if chPassword == "" || len(normalizerToken) < 32 {
		return proof, errors.New("DECISION_NATIVE_PRIVATE_SERVICE_CREDENTIAL_REQUIRED")
	}
	// Same fixed owned endpoints as commitment-portfolio-lab.mjs. No arbitrary
	// endpoint, customer credential, mutable clock, or network fallback is added.
	t.Setenv("CLICKHOUSE_URL", "http://clickhouse:8123/")
	t.Setenv("CLICKHOUSE_DATABASE", "finops")
	t.Setenv("CLICKHOUSE_USER", "finops")
	t.Setenv("CLICKHOUSE_PASSWORD", chPassword)
	client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	normalizer := &API{Config: Config{EconomicsURL: "http://economics:8000", EconomicsToken: normalizerToken}, Client: client}
	pipeline := source.Pipeline{Store: f.roles["ingester"], ProviderFactory: func(context.Context, source.Registration) (source.Reader, error) { return reader, nil }, Normalize: normalizer.NormalizeTrustedSource,
		Persist: func(c context.Context, tenant, src string, raw, canonical model.Document) error {
			body, err := json.Marshal(raw)
			if err != nil {
				return err
			}
			if err = archive(c, "normalized-native", body); err != nil {
				return err
			}
			facts, err := billingFactRows(tenant, src, canonical)
			if err != nil {
				return err
			}
			if err = persistBillingFacts(c, tenant, src, canonical); err != nil {
				return err
			}
			if err = commitmentDecisionReadbackNativeFacts(c, tenant, src, chPassword, facts); err != nil {
				return err
			}
			proof.AnalyticsReadbacks += len(facts)
			return nil
		}, ArchiveObject: func(c context.Context, tenant, src, key string, raw []byte) error { return archive(c, key, raw) }}
	proof.Refresh = func(c context.Context) error { return pipeline.Sync(c, f.tenant, sourceID) }
	if err = proof.Refresh(ctx); err != nil {
		return proof, err
	}
	if proof.AnalyticsReadbacks != proof.NativeHourlyRows {
		return proof, errors.New("DECISION_NATIVE_ANALYTICS_POPULATION_DIFFERS")
	}
	err = f.roles["ingester"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		current, err := tx.SourceGet(ctx, sourceID)
		if err != nil {
			return err
		}
		if model.String(current, "status") != "HEALTHY" || source.ConfigurationHash(current) != source.ConfigurationHash(registration) || model.Number(current, "version") != r.Version || model.Number(current, "backfill_pending") != 0 {
			return errors.New("DECISION_NATIVE_SOURCE_NOT_CURRENT")
		}
		proof.Selection = portfolio.Selection{SourceID: sourceID, CommitmentReceiptID: model.String(current, "commitment_receipt_id"), BillingReceiptIDs: []string{}, Period: selected}
		rows, err := tx.Query(ctx, "SELECT r.id,r.document||jsonb_build_object('writer_role',r.writer_role,'created_at',r.created_at) FROM source_checkpoints c JOIN source_receipts r ON(r.tenant_id,r.id)=(c.tenant_id,c.document->>'receipt_id') WHERE c.tenant_id=$1 AND c.source_id=$2 AND starts_with(c.checkpoint_key,$3) ORDER BY c.checkpoint_key", f.tenant, sourceID, "month:"+source.ConfigurationHash(current)+":")
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			var raw []byte
			if err = rows.Scan(&id, &raw); err != nil {
				return err
			}
			decoder := json.NewDecoder(strings.NewReader(string(raw)))
			decoder.UseNumber()
			var receipt model.Document
			if decoder.Decode(&receipt) != nil {
				return errors.New("DECISION_NATIVE_RECEIPT_INVALID")
			}
			proof.CurrentMonthReceipts = append(proof.CurrentMonthReceipts, portfolio.Ref{Kind: "SOURCE_RECEIPT", ID: id, SHA256: portfolio.Hash(receipt)})
			span := source.Object(receipt["source_proof"])
			start, e1 := time.Parse(time.RFC3339, model.String(span, "billing_period_start"))
			end, e2 := time.Parse(time.RFC3339, model.String(span, "billing_period_end"))
			if e1 != nil || e2 != nil {
				return errors.New("DECISION_NATIVE_CALENDAR_HEAD_INVALID")
			}
			if start.Before(selected.End) && end.After(selected.Start) {
				proof.Selection.BillingReceiptIDs = append(proof.Selection.BillingReceiptIDs, id)
			}
		}
		if err = rows.Err(); err != nil {
			return err
		}
		sort.Strings(proof.Selection.BillingReceiptIDs)
		if len(proof.CurrentMonthReceipts) != len(reader.months) || len(proof.Selection.BillingReceiptIDs) == 0 || proof.Selection.CommitmentReceiptID == "" {
			return errors.New("DECISION_NATIVE_EXACT_SOURCE_HEADS_REQUIRED")
		}
		return nil
	})
	return proof, err
}

// Read back one actual immutable source version at a time. This preserves the
// old218-row helper and bounds each response without allocating all974days.
func commitmentDecisionReadbackNativeFacts(ctx context.Context, tenant, src, password string, facts []model.Document) error {
	if len(facts) < 1 || len(facts) > 31*24 {
		return errors.New("DECISION_NATIVE_ANALYTICS_MONTH_BOUND")
	}
	wanted := map[string]model.Document{}
	version := model.String(facts[0], "source_version")
	for _, fact := range facts {
		key := model.String(fact, "source_record_id")
		if key == "" || wanted[key] != nil || fact["tenant_id"] != tenant || fact["source_id"] != src || model.String(fact, "source_version") != version {
			return errors.New("DECISION_NATIVE_ANALYTICS_PIN_DIFFERS")
		}
		wanted[key] = fact
	}
	query := "SELECT source_record_id,resource_id,currency,toString(billed_cost) billed_cost,toString(effective_cost) effective_cost,toString(toUnixTimestamp64Nano(source_time)) source_time_ns,payload FROM billing_facts FINAL WHERE tenant_id={tenant:String} AND source_id={source:String} AND source_version={version:String} ORDER BY source_record_id FORMAT JSONEachRow"
	parameters := url.Values{"database": {"finops"}, "query": {query}, "param_tenant": {tenant}, "param_source": {src}, "param_version": {version}}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://clickhouse:8123/?"+parameters.Encode(), nil)
	if err != nil {
		return err
	}
	request.Header.Set("X-ClickHouse-User", "finops")
	request.Header.Set("X-ClickHouse-Key", password)
	client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	response, err := client.Do(request)
	if err != nil {
		return errors.New("DECISION_NATIVE_ANALYTICS_UNAVAILABLE")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return errors.New("DECISION_NATIVE_ANALYTICS_REFUSED")
	}
	limited := &io.LimitedReader{R: response.Body, N: (8 << 20) + 1}
	decoder := json.NewDecoder(limited)
	decoder.UseNumber()
	count := 0
	for {
		var got model.Document
		err = decoder.Decode(&got)
		if err == io.EOF {
			break
		}
		if err != nil || count >= len(facts) {
			return errors.New("DECISION_NATIVE_ANALYTICS_SHAPE")
		}
		count++
		id := model.String(got, "source_record_id")
		want := wanted[id]
		if want == nil || got["resource_id"] != want["resource_id"] || got["currency"] != want["currency"] || got["payload"] != want["payload"] {
			return errors.New("DECISION_NATIVE_ANALYTICS_COLUMN_DIFFERS")
		}
		for _, key := range []string{"billed_cost", "effective_cost"} {
			if want[key] == nil {
				if got[key] != nil {
					return errors.New("DECISION_NATIVE_ANALYTICS_UNKNOWN_BECAME_VALUE")
				}
			} else {
				a, ok := new(big.Rat).SetString(model.String(got, key))
				b, ok2 := new(big.Rat).SetString(model.String(want, key))
				if !ok || !ok2 || a.Cmp(b) != 0 {
					return errors.New("DECISION_NATIVE_ANALYTICS_MONEY_DIFFERS")
				}
			}
		}
		at, err := time.Parse(time.RFC3339, model.String(want, "source_time"))
		if err != nil || model.String(got, "source_time_ns") != strconv.FormatInt(at.UnixNano(), 10) {
			return errors.New("DECISION_NATIVE_ANALYTICS_TIME_DIFFERS")
		}
		delete(wanted, id)
	}
	if limited.N <= 1 || count != len(facts) || len(wanted) != 0 {
		return errors.New("DECISION_NATIVE_ANALYTICS_POPULATION_DIFFERS")
	}
	return nil
}

func TestCommitmentDecisionNativeHourlySourceFixture(t *testing.T) {
	now := time.Date(2026, 10, 19, 22, 0, 0, 0, time.UTC)
	selected, training, err := commitmentDecisionNativeWindow(now)
	if err != nil {
		t.Fatal(err)
	}
	if !selected.End.Equal(now.Truncate(24*time.Hour)) || training.End != selected.End || training.Start.After(selected.End.Add(-23376*time.Hour)) {
		t.Fatal("server training policy not retained")
	}
	count, months := 0, 0
	for month := time.Date(training.Start.Year(), training.Start.Month(), 1, 0, 0, 0, 0, time.UTC); month.Before(training.End); month = month.AddDate(0, 1, 0) {
		start, end := month, month.AddDate(0, 1, 0)
		if end.After(training.End) {
			end = training.End
		}
		rows := commitmentDecisionNativeMonthRows("i-0d040000000000001", start, end)
		count += len(rows)
		months++
		for _, row := range rows {
			if row["line_item_usage_amount"] != "1" || row["line_item_net_unblended_cost"] != "0.2" || row["product_operating_system"] != "Linux" || row["product_instance_family"] != "General purpose" {
				t.Fatal("fixture invents zero/aggregate/native labels")
			}
		}
	}
	if count != int(training.End.Sub(time.Date(training.Start.Year(), training.Start.Month(), 1, 0, 0, 0, 0, time.UTC))/time.Hour) || months < 32 || months > 34 {
		t.Fatal(fmt.Sprintf("exact source calendar coverage differs hours=%d months=%d", count, months))
	}
}
