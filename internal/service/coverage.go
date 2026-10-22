package service

import (
	"sort"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/evidence"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

// Billing coverage is a separate observation, never a synthesized CUR record.
// Only a finalized complete export and owned downtime can prove absent spend.
func billingObservations(records, proofs, owned []model.Document, start, end time.Time) []model.Document {
	type window struct {
		start, end time.Time
		id         string
	}
	observed := []window{}
	bounds := []time.Time{start, end}
	for _, record := range records {
		raw := evidence.Object(record["x_ProviderFields"])
		family := strings.ToLower(strings.ReplaceAll(model.String(raw, "product_product_family"), " ", ""))
		if model.String(record, "ServiceName") != "AmazonEC2" || !(family == "computeinstance" || strings.Contains(model.String(raw, "line_item_usage_type"), "BoxUsage:") || strings.HasPrefix(model.String(raw, "line_item_operation"), "RunInstances")) {
			continue
		}
		s, e1 := time.Parse(time.RFC3339Nano, model.String(record, "ChargePeriodStart"))
		e, e2 := time.Parse(time.RFC3339Nano, model.String(record, "ChargePeriodEnd"))
		if e1 != nil || e2 != nil {
			continue
		}
		observed = append(observed, window{s, e, model.String(record, "x_SourceRecordId")})
		bounds = append(bounds, s, e)
	}
	for _, o := range owned {
		for _, k := range []string{"stopped_at", "running_at"} {
			if at, e := time.Parse(time.RFC3339Nano, model.String(o, k)); e == nil && at.After(start) && at.Before(end) {
				bounds = append(bounds, at)
			}
		}
	}
	for _, p := range proofs {
		for _, k := range []string{"period_start", "period_end"} {
			if at, e := time.Parse(time.RFC3339Nano, model.String(p, k)); e == nil && at.After(start) && at.Before(end) {
				bounds = append(bounds, at)
			}
		}
	}
	sort.Slice(bounds, func(i, j int) bool { return bounds[i].Before(bounds[j]) })
	out := []model.Document{}
	for n := 1; n < len(bounds); n++ {
		left, right := bounds[n-1], bounds[n]
		if !left.Before(right) || left.Before(start) || right.After(end) {
			continue
		}
		d := model.Document{"start": left.UTC().Format(time.RFC3339Nano), "end": right.UTC().Format(time.RFC3339Nano), "state": "UNKNOWN"}
		ids := []string{}
		for _, o := range observed {
			if !left.Before(o.start) && !right.After(o.end) {
				ids = append(ids, o.id)
			}
		}
		if len(ids) > 0 {
			d["state"], d["source_record_ids"] = "OBSERVED", ids
		} else {
			ownedHere := false
			for _, o := range owned {
				s, e1 := time.Parse(time.RFC3339Nano, model.String(o, "stopped_at"))
				e, e2 := time.Parse(time.RFC3339Nano, model.String(o, "running_at"))
				if e1 == nil && e2 == nil && !left.Before(s) && !right.After(e) {
					ownedHere = true
				}
			}
			if ownedHere {
				for _, p := range proofs {
					s, e1 := time.Parse(time.RFC3339Nano, model.String(p, "period_start"))
					e, e2 := time.Parse(time.RFC3339Nano, model.String(p, "period_end"))
					if e1 == nil && e2 == nil && model.String(p, "state") == "FINAL" && !left.Before(s) && !right.After(e) {
						d["state"], d["source_receipt_id"] = "ABSENT_FINAL_EXPORT", p["receipt_id"]
						break
					}
				}
			}
		}
		out = append(out, d)
	}
	return out
}
