package workflow

import (
	"context"
	"errors"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/telemetry"
	"testing"
	"time"
)

func TestDatabaseNativePeriodUsesIssuedProfileWithoutInventedOwner(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 34, 0, 0, time.UTC)
	for _, tc := range []struct {
		profile model.Document
		days    int
		unknown bool
	}{{model.Document{"criticality": "NON_PRODUCTION"}, 14, false}, {model.Document{"criticality": "TIER_1"}, 30, false}, {model.Document{"criticality": "PRODUCTION", "high_seasonality": true}, 90, false}, {model.Document{}, 30, true}} {
		start, end, reasons := databasePeriod(tc.profile, now)
		if end != time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC) || end.Sub(start) != time.Duration(tc.days)*24*time.Hour || (len(reasons) > 0) != tc.unknown {
			t.Fatal("profile history or observation-only fallback changed")
		}
	}
}
func TestDatabaseNativeFactsKeepCountsARNAndBoundedChunks(t *testing.T) {
	at := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	arn := "arn:aws:rds:eu-west-1:111122223333:db:primary"
	resource := model.Document{"id": "native-resource", "account_id": "111122223333", "region": "eu-west-1", "provider_resource_id": arn, "resource_type": "RDS_INSTANCE", "database_configuration": model.Document{"class": "db.r6g.large"}}
	e := provider.RDSMetricEvidence{RDSReadEvidence: provider.RDSReadEvidence{Scope: provider.RDSScope{TenantID: "tenant", AccountID: "111122223333", Region: "eu-west-1"}, RawSHA256: "native-raw", CollectedAt: at.Add(24 * time.Hour)}, Selection: provider.RDSMetricSelection{ResourceARN: arn, Start: at, End: at.Add(7 * 24 * time.Hour), PeriodSeconds: 60}, Metrics: []model.Document{}}
	for i := 0; i < 5001; i++ {
		e.Metrics = append(e.Metrics, model.Document{"metric": "CPUUtilization", "value": "0", "unit": "Percent", "statistic": "Maximum", "source_time": at.Add(time.Duration(i) * time.Minute).Format(time.RFC3339), "period_seconds": 60, "sample_count": int64(1), "provider_resource_id": arn, "raw_page_sha256": "native-page"})
	}
	batches, err := databaseMetricBatches(resource, e)
	if err != nil || len(batches) != 2 || len(batches[0].Samples) != 5000 || len(batches[1].Samples) != 1 {
		t.Fatal("native chunk boundary changed", err)
	}
	count := 0
	for _, b := range batches {
		if b.Binding.ProviderResourceID != arn || b.SourceKind != "RDS_CLOUDWATCH" {
			t.Fatal("cross-resource or EC2 substitution")
		}
		for _, sample := range b.Samples {
			count++
			if sample.Value != "0" || model.Number(sample.OriginalAttributes, "sample_count") != 1 {
				t.Fatal("actual zero/count changed")
			}
		}
	}
	if count != len(e.Metrics) {
		t.Fatal("population truncated")
	}
	batches[0].Samples[0].OriginalAttributes["sample_count"] = int64(99)
	if e.Metrics[0]["sample_count"] != int64(1) {
		t.Fatal("retained native metric aliases a mutable batch")
	}
}

type databaseMemoryArchive struct {
	raw     []byte
	corrupt bool
}

func (a *databaseMemoryArchive) Archive(_ context.Context, tenant, kind, id string, raw []byte) (model.Document, error) {
	if kind != "wire" && kind != "canonical" {
		return nil, errors.New("unsupported native archive kind")
	}
	a.raw = append([]byte{}, raw...)
	return model.Document{"bucket": "private", "key": "tenant/" + tenant + "/native/" + id, "version_id": "actual-version", "body_sha256": telemetry.BytesHash(raw)}, nil
}
func (a *databaseMemoryArchive) Read(context.Context, string, model.Document) ([]byte, error) {
	if a.corrupt {
		return []byte("different"), nil
	}
	return a.raw, nil
}
func (a *databaseMemoryArchive) WriteFacts(context.Context, string, string, telemetry.Batch) (model.Document, error) {
	panic("archive-only component must not write facts")
}
func TestDatabaseNativeArchiveRequiresExactVersionReadback(t *testing.T) {
	store := &databaseMemoryArchive{}
	if _, e := databaseArchiveReadback(context.Background(), store, "tenant", "wire", "id", []byte("exact-native-response")); e != nil {
		t.Fatal(e)
	}
	asset := provider.RDSDocumentedIOBaselineAsset()
	ref, e := databaseArchiveReadback(context.Background(), store, "tenant", "wire", "rds-ebs-baseline-"+telemetry.BytesHash(asset), asset)
	if e != nil || model.String(ref, "body_sha256") != telemetry.BytesHash(asset) {
		t.Fatal("documentation asset lacked exact immutable readback")
	}
	if _, e = databaseArchiveReadback(context.Background(), store, "tenant", "documentation", "id", asset); e == nil {
		t.Fatal("test adapter admitted an unsupported production archive kind")
	}
	store.corrupt = true
	if _, e := databaseArchiveReadback(context.Background(), store, "tenant", "wire", "id", []byte("exact-native-response")); e == nil {
		t.Fatal("corrupt native readback accepted")
	}
}
