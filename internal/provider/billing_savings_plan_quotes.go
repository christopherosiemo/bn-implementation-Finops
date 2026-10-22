package provider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/savingsplans"
	sp "github.com/aws/aws-sdk-go-v2/service/savingsplans/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

const SavingsPlanQuoteProjection = "AWS_SAVINGS_PLAN_RATE_QUOTES_V1"

// This optional collector has no callsite in BillingCommitments. The issuer must
// bind its selectors and existing plan IDs to the current issued inventory and
// archive/read back this SDK projection before it becomes new source evidence.
type SavingsPlanQuoteSelection struct {
	PlanType        string   `json:"plan_type"`
	PaymentOption   string   `json:"payment_option"`
	DurationSeconds int64    `json:"duration_seconds"`
	Currency        string   `json:"currency"`
	ExistingPlanIDs []string `json:"existing_plan_ids"`
}

var (
	errSavingsPlanQuote = errors.New("AWS_SAVINGS_PLAN_QUOTES_INVALID")
	errQuoteLimit       = errors.New("AWS_SAVINGS_PLAN_QUOTES_LIMIT")
	quoteAccount        = regexp.MustCompile(`^[0-9]{12}$`)
	quotePlanID         = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,127}$`)
	quoteOfferingID     = regexp.MustCompile(`^[a-f0-9]+(-[a-f0-9]+)*$`)
	quoteToken          = regexp.MustCompile(`^[A-Za-z0-9/=+]+$`)
)

func (s SavingsPlanQuoteSelection) valid(account string) bool {
	if !quoteAccount.MatchString(account) || (s.PlanType != "Compute" && s.PlanType != "EC2Instance") || s.PaymentOption != "No Upfront" || s.DurationSeconds != 31536000 || (s.Currency != "USD" && s.Currency != "CNY" && s.Currency != "EUR") || len(s.ExistingPlanIDs) > 2000 || !sort.StringsAreSorted(s.ExistingPlanIDs) {
		return false
	}
	for i, id := range s.ExistingPlanIDs {
		if !quotePlanID.MatchString(id) || i > 0 && s.ExistingPlanIDs[i-1] == id {
			return false
		}
	}
	return true
}

// SDK field names are projected to their native JSON names. Decimal price
// strings, null pointer fields, native units and property arrays stay intact.
// This is deliberately SDK_PROJECTION, not the original AWS HTTP wire bytes.
func quoteSDKDocument(v any) (model.Document, error) {
	raw, err := json.Marshal(v)
	if err != nil || len(raw) > 2<<20 {
		return nil, errQuoteLimit
	}
	var value any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err = d.Decode(&value); err != nil {
		return nil, err
	}
	var native func(any) any
	native = func(v any) any {
		switch x := v.(type) {
		case map[string]any:
			out := model.Document{}
			for key, item := range x {
				if key != "" {
					key = strings.ToLower(key[:1]) + key[1:]
				}
				out[key] = native(item)
			}
			return out
		case []any:
			for i := range x {
				x[i] = native(x[i])
			}
			return x
		default:
			return v
		}
	}
	out, ok := native(value).(model.Document)
	if !ok {
		return nil, errSavingsPlanQuote
	}
	return out, nil
}

type quotePages struct {
	rows, bytes int
	pages       []model.Document
	hashes      []string
}

func (b *quotePages) append(operation string, request, response model.Document, count int) (string, error) {
	if len(b.pages) >= 4096 || count < 0 || b.rows+count > 100000 {
		return "", errQuoteLimit
	}
	page := model.Document{"operation": operation, "ordinal": len(b.pages) + 1, "request": request, "response": response}
	raw, err := json.Marshal(page)
	if err != nil || len(raw) > 2<<20 || b.bytes+len(raw) > 32<<20 {
		return "", errQuoteLimit
	}
	digest := sha256.Sum256(raw)
	hash := hex.EncodeToString(digest[:])
	page["sha256"] = hash
	b.pages = append(b.pages, page)
	b.hashes = append(b.hashes, hash)
	b.rows += count
	b.bytes += len(raw)
	return hash, nil
}

func quoteNext(next *string, seen map[string]bool, page int) (*string, bool, error) {
	if next == nil || *next == "" {
		return nil, true, nil
	}
	if page == 99 || len(*next) > 1024 || !quoteToken.MatchString(*next) || seen[*next] {
		return nil, false, errQuoteLimit
	}
	seen[*next] = true
	return next, false, nil
}

// BillingSavingsPlanQuotes uses only the three read-only native rate APIs and
// STS identity. Catalog rows have no account-owner field: authenticated_account_id
// records acquisition context, while existing plan ownership is issuer-checked.
// Any error discards all partial rows and pages.
func (a *BillingAWS) BillingSavingsPlanQuotes(ctx context.Context, account string, selection SavingsPlanQuoteSelection) (model.Document, error) {
	if a == nil || a.AWS == nil || !selection.valid(account) {
		return nil, errSavingsPlanQuote
	}
	// Never retain an alias of the issuer's mutable ID slice in an evidence body.
	selection.ExistingPlanIDs = append([]string{}, selection.ExistingPlanIDs...)
	identity, err := sts.NewFromConfig(a.cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, err
	}
	if aws.ToString(identity.Account) != account {
		return nil, errSavingsPlanQuote
	}
	c := savingsplans.NewFromConfig(a.global())
	b := quotePages{pages: []model.Document{}, hashes: []string{}}
	offerings, rates, contracts := []model.Document{}, []model.Document{}, []model.Document{}
	ids := []string{}
	known := map[string]bool{}
	var token *string
	seen := map[string]bool{}
	for page := 0; page < 100; page++ {
		request := &savingsplans.DescribeSavingsPlansOfferingsInput{Currencies: []sp.CurrencyCode{sp.CurrencyCode(selection.Currency)}, Durations: []int64{selection.DurationSeconds}, PaymentOptions: []sp.SavingsPlanPaymentOption{sp.SavingsPlanPaymentOption(selection.PaymentOption)}, PlanTypes: []sp.SavingsPlanType{sp.SavingsPlanType(selection.PlanType)}, MaxResults: 1000, NextToken: token}
		r, e := c.DescribeSavingsPlansOfferings(ctx, request)
		if e != nil {
			return nil, e
		}
		req, e := quoteSDKDocument(request)
		if e != nil {
			return nil, e
		}
		response, e := quoteSDKDocument(model.Document{"searchResults": r.SearchResults, "nextToken": r.NextToken})
		if e != nil {
			return nil, e
		}
		hash, e := b.append("DescribeSavingsPlansOfferings", req, response, len(r.SearchResults))
		if e != nil {
			return nil, e
		}
		for _, v := range r.SearchResults {
			id := aws.ToString(v.OfferingId)
			if !quoteOfferingID.MatchString(id) || len(id) > 128 || known[id] || len(ids) >= 2000 || string(v.Currency) != selection.Currency || v.DurationSeconds != selection.DurationSeconds || string(v.PaymentOption) != selection.PaymentOption || string(v.PlanType) != selection.PlanType {
				return nil, errSavingsPlanQuote
			}
			row, e := quoteSDKDocument(v)
			if e != nil {
				return nil, e
			}
			known[id] = true
			ids = append(ids, id)
			offerings = append(offerings, model.Document{"native": row, "page_sha256": hash})
		}
		var done bool
		token, done, e = quoteNext(r.NextToken, seen, page)
		if e != nil {
			return nil, e
		}
		if done {
			break
		}
	}
	sort.Strings(ids)
	if len(ids) > 0 {
		token, seen = nil, map[string]bool{}
		for page := 0; page < 100; page++ {
			request := &savingsplans.DescribeSavingsPlansOfferingRatesInput{SavingsPlanOfferingIds: ids, SavingsPlanTypes: []sp.SavingsPlanType{sp.SavingsPlanType(selection.PlanType)}, SavingsPlanPaymentOptions: []sp.SavingsPlanPaymentOption{sp.SavingsPlanPaymentOption(selection.PaymentOption)}, MaxResults: 1000, NextToken: token}
			r, e := c.DescribeSavingsPlansOfferingRates(ctx, request)
			if e != nil {
				return nil, e
			}
			req, e := quoteSDKDocument(request)
			if e != nil {
				return nil, e
			}
			response, e := quoteSDKDocument(model.Document{"searchResults": r.SearchResults, "nextToken": r.NextToken})
			if e != nil {
				return nil, e
			}
			hash, e := b.append("DescribeSavingsPlansOfferingRates", req, response, len(r.SearchResults))
			if e != nil {
				return nil, e
			}
			for _, v := range r.SearchResults {
				parent := v.SavingsPlanOffering
				if parent == nil || !known[aws.ToString(parent.OfferingId)] || string(parent.Currency) != selection.Currency || parent.DurationSeconds != selection.DurationSeconds || string(parent.PaymentOption) != selection.PaymentOption || string(parent.PlanType) != selection.PlanType {
					return nil, errSavingsPlanQuote
				}
				row, e := quoteSDKDocument(v)
				if e != nil {
					return nil, e
				}
				rates = append(rates, model.Document{"native": row, "page_sha256": hash})
			}
			var done bool
			token, done, e = quoteNext(r.NextToken, seen, page)
			if e != nil {
				return nil, e
			}
			if done {
				break
			}
		}
	}
	for _, id := range selection.ExistingPlanIDs {
		token, seen = nil, map[string]bool{}
		for page := 0; page < 100; page++ {
			request := &savingsplans.DescribeSavingsPlanRatesInput{SavingsPlanId: aws.String(id), MaxResults: aws.Int32(1000), NextToken: token}
			r, e := c.DescribeSavingsPlanRates(ctx, request)
			if e != nil {
				return nil, e
			}
			if aws.ToString(r.SavingsPlanId) != id {
				return nil, errSavingsPlanQuote
			}
			req, e := quoteSDKDocument(request)
			if e != nil {
				return nil, e
			}
			response, e := quoteSDKDocument(model.Document{"savingsPlanId": r.SavingsPlanId, "searchResults": r.SearchResults, "nextToken": r.NextToken})
			if e != nil {
				return nil, e
			}
			hash, e := b.append("DescribeSavingsPlanRates", req, response, len(r.SearchResults))
			if e != nil {
				return nil, e
			}
			for _, v := range r.SearchResults {
				row, e := quoteSDKDocument(v)
				if e != nil {
					return nil, e
				}
				contracts = append(contracts, model.Document{"savingsPlanId": id, "native": row, "page_sha256": hash})
			}
			var done bool
			token, done, e = quoteNext(r.NextToken, seen, page)
			if e != nil {
				return nil, e
			}
			if done {
				break
			}
		}
	}
	proof := model.Document{"schema_version": "1", "native_projection": SavingsPlanQuoteProjection, "serialization": "SDK_PROJECTION", "authenticated_account_id": account, "selection": selection, "complete": true, "observed_at": model.Now(), "offerings": offerings, "offering_rates": rates, "existing_plan_rates": contracts, "pages": b.pages, "ordered_page_sha256s": b.hashes}
	// Pages and their row projections share one archived source body. Bound the
	// final encoding too, rather than treating only the page subtotal as its size.
	raw, err := json.Marshal(proof)
	if err != nil || len(raw) > 32<<20 {
		return nil, errQuoteLimit
	}
	return proof, nil
}
