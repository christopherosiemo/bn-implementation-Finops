package objectstorage

import (
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

func appAccessReportFixture(t *testing.T, days int, mutateHeader func(*appAccessHeader), mutateMinute func(int, *appAccessMinute)) (io.ReadCloser, Registration, time.Time) {
	t.Helper()
	now := time.Date(2026, 10, 20, 1, 0, 0, 0, time.UTC)
	r := Registration{ID: "synthetic-source", TenantID: "synthetic-tenant", AccountID: "111122223333", Region: "eu-west-1", Bucket: "synthetic-app-access", ReportType: AppAccessReportType, Datasets: []DatasetSelector{{ID: "synthetic-dataset", Kind: "PREFIX", Prefix: "logs/"}}}
	end := now.UTC().Truncate(24 * time.Hour)
	header := appAccessHeader{SchemaVersion: "1", Kind: "S3_APPLICATION_ACCESS_HISTORY", AccountID: r.AccountID, Region: r.Region, Bucket: r.Bucket, DatasetID: "synthetic-dataset", DatasetVersion: 1,
		MetricDefinition: appAccessDefinition{ID: "synthetic-approved-definition", Version: "1", Unit: AppAccessReportUnit}, PopulationSHA256: strings.Repeat("a", 64), IntervalStart: end.Add(-time.Duration(days) * 24 * time.Hour), IntervalEnd: end, AuthoritativeAccessScope: true}
	if mutateHeader != nil {
		mutateHeader(&header)
	}
	reader, writer := io.Pipe()
	t.Cleanup(func() { _ = reader.Close() })
	go func() {
		defer writer.Close()
		encoder := json.NewEncoder(writer)
		if encoder.Encode(header) != nil {
			return
		}
		for minute := 0; minute < days*1440; minute++ {
			row := appAccessMinute{Sequence: int64(minute + 1), IntervalStart: header.IntervalStart.Add(time.Duration(minute) * time.Minute), IntervalEnd: header.IntervalStart.Add(time.Duration(minute+1) * time.Minute), GetRequests: "0", RetrievedBytes: "0", Heartbeat: true}
			if mutateMinute != nil {
				mutateMinute(minute, &row)
			}
			if encoder.Encode(row) != nil {
				return
			}
		}
	}()
	return reader, r, now
}

func TestHistoricalAppAccessDerivesActualCompleteZeroAndNinetyDayTierHistory(t *testing.T) {
	reader, registration, now := appAccessReportFixture(t, 90, nil, nil)
	result, err := ParseAppAccess(reader, registration, now, "synthetic-approved-definition", "1")
	if err != nil {
		t.Fatal(err)
	}
	if result["complete"] != true || result["request_accounting_complete"] != true || result["requests"] != "0" || result["retrieved_bytes"] != "0" || result["eligible_cold_bytes_fraction"] != "1" || result["observed_minutes"] != int64(90*1440) {
		t.Fatalf("explicit authenticated minute accounting lost: %+v", result)
	}
	tiers := Doc(result["it_tier_fractions"])
	if tiers["ARCHIVE_INSTANT"] != "1" || tiers["FREQUENT"] != "0" || tiers["ARCHIVE"] != "0" {
		t.Fatal("ninety genuine days did not establish a bounded native tier scenario")
	}
	days := Rows(result["observations"])
	if len(days) != 90 || model.Number(days[0], "observed_minutes") != 1440 || model.Number(days[0], "native_period_seconds") != 60 || len(model.String(days[0], "minute_population_sha256")) != 64 || result["requires_inventory_population_match"] != true {
		t.Fatal("bounded daily facts lost actual native minute provenance")
	}
}

func TestHistoricalAppAccessNonzeroCannotInventUnobservedObjectDistribution(t *testing.T) {
	reader, registration, now := appAccessReportFixture(t, 14, nil, func(minute int, row *appAccessMinute) {
		if minute == 17 {
			row.GetRequests, row.RetrievedBytes = "2", "1000"
		}
	})
	result, err := ParseAppAccess(reader, registration, now, "synthetic-approved-definition", "1")
	if err != nil {
		t.Fatal(err)
	}
	if result["requests"] != "2" || result["retrieved_bytes"] != "1000" || result["eligible_cold_bytes_fraction"] != nil || result["it_tier_fractions"] != nil {
		t.Fatal("aggregate nonzero reads became fabricated object-level cold fractions")
	}
}

func TestHistoricalAppAccessScopeAndPrivateDefinitionFailClosed(t *testing.T) {
	for name, change := range map[string]func(*appAccessHeader){
		"account":         func(h *appAccessHeader) { h.AccountID = "444455556666" },
		"region":          func(h *appAccessHeader) { h.Region = "us-east-1" },
		"bucket":          func(h *appAccessHeader) { h.Bucket = "unapproved-bucket" },
		"dataset":         func(h *appAccessHeader) { h.DatasetID = "unregistered-dataset" },
		"scope":           func(h *appAccessHeader) { h.AuthoritativeAccessScope = false },
		"definition":      func(h *appAccessHeader) { h.MetricDefinition.ID = "console-invented-definition" },
		"unversioned":     func(h *appAccessHeader) { h.MetricDefinition.Version = "" },
		"altered-version": func(h *appAccessHeader) { h.MetricDefinition.Version = "2" },
		"population":      func(h *appAccessHeader) { h.PopulationSHA256 = "aggregate-count-is-not-identity" },
	} {
		t.Run(name, func(t *testing.T) {
			reader, registration, now := appAccessReportFixture(t, 1, change, nil)
			defer reader.Close()
			if _, err := ParseAppAccess(reader, registration, now, "synthetic-approved-definition", "1"); err == nil {
				t.Fatal("unapproved historical access authority accepted")
			}
		})
	}
	reader, registration, now := appAccessReportFixture(t, 1, nil, nil)
	defer reader.Close()
	if _, err := ParseAppAccess(reader, registration, now, "", "1"); err == nil {
		t.Fatal("report body supplied its own private approved definition")
	}
}

func TestHistoricalAppAccessMissingHeartbeatSequenceAndBytesAreNotZero(t *testing.T) {
	for name, change := range map[string]func(int, *appAccessMinute){
		"missing-minute": func(i int, m *appAccessMinute) {
			if i == 3 {
				m.IntervalStart = m.IntervalStart.Add(time.Minute)
				m.IntervalEnd = m.IntervalEnd.Add(time.Minute)
			}
		},
		"conflicting-sequence": func(i int, m *appAccessMinute) {
			if i == 3 {
				m.Sequence = 2
			}
		},
		"unavailable-heartbeat": func(i int, m *appAccessMinute) {
			if i == 3 {
				m.Heartbeat = false
			}
		},
		"unknown-get": func(i int, m *appAccessMinute) {
			if i == 3 {
				m.GetRequests = ""
			}
		},
		"bytes-without-get": func(i int, m *appAccessMinute) {
			if i == 3 {
				m.RetrievedBytes = "1"
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			reader, registration, now := appAccessReportFixture(t, 1, nil, change)
			defer reader.Close()
			if _, err := ParseAppAccess(reader, registration, now, "synthetic-approved-definition", "1"); err == nil {
				t.Fatal("missing or contradictory historical minute became zero")
			}
		})
	}
}

func TestHistoricalAppAccessNoCallerCompletenessOrColdnessFields(t *testing.T) {
	for _, body := range []string{
		`{"sequence":1,"interval_start":"2026-10-19T00:00:00Z","interval_end":"2026-10-19T00:01:00Z","get_requests":"0","retrieved_bytes":"0","heartbeat":true,"complete":true}`,
		`{"sequence":1,"sequence":2,"interval_start":"2026-10-19T00:00:00Z","interval_end":"2026-10-19T00:01:00Z","get_requests":"0","retrieved_bytes":"0","heartbeat":true}`,
		`{"sequence":1,"interval_start":"2026-10-19T00:00:00Z","interval_end":"2026-10-19T00:01:00Z","get_requests":"0","retrieved_bytes":"0"}`,
	} {
		var row appAccessMinute
		if appAccessDecode([]byte(body), &row, []string{"sequence", "interval_start", "interval_end", "get_requests", "retrieved_bytes", "heartbeat"}) == nil {
			t.Fatal("caller completeness, replay conflict or missing facts accepted")
		}
	}
}
