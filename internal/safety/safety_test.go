package safety

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

func eligible() (model.Document, model.Document, model.Document) {
	return model.Document{"environment": "NON_PRODUCTION", "configuration_authority": "TERRAFORM", "runtime_stop_start_delegated": true, "root_device_type": "ebs", "commitment_known": true, "uncovered_on_demand": true, "stable_network": true, "observation_days": 14}, model.Document{"environment": "NON_PRODUCTION", "owner": "owner", "incident": "CLEAR", "deployment": "CLEAR", "job": "CLEAR", "signals_at": model.Now()}, model.Document{"paused": false}
}
func TestEligibilityFailsClosed(t *testing.T) {
	r, w, p := eligible()
	if got := Eligibility(r, w, p, time.Now()); len(got) != 0 {
		t.Fatal(got)
	}
	cases := []struct {
		field string
		value any
		which string
	}{{"environment", "PRODUCTION", "resource"}, {"configuration_authority", "UNKNOWN", "resource"}, {"spot", true, "resource"}, {"instance_store", true, "resource"}, {"fleet_managed", true, "resource"}, {"stop_protection", true, "resource"}, {"uncovered_on_demand", false, "resource"}, {"runtime_stop_start_delegated", false, "resource"}, {"observation_days", 13, "resource"}, {"incident", "UNKNOWN", "workload"}, {"job", "ACTIVE", "workload"}, {"signals_at", time.Now().Add(-6 * time.Minute).Format(time.RFC3339), "workload"}, {"paused", true, "policy"}}
	for _, c := range cases {
		t.Run(c.which+"/"+c.field, func(t *testing.T) {
			rr, ww, pp := eligible()
			switch c.which {
			case "resource":
				rr[c.field] = c.value
			case "workload":
				ww[c.field] = c.value
			default:
				pp[c.field] = c.value
			}
			if len(Eligibility(rr, ww, pp, time.Now())) == 0 {
				t.Fatal("unsafe resource eligible")
			}
		})
	}
}
func plan(now time.Time) model.Plan {
	op := model.Operation{Type: "EC2_STOP", ResourceID: "resource", ProviderResourceID: "i-123", Region: "eu-west-1", AccountID: "123456789012"}
	other := op
	other.Type = "EC2_START"
	return model.Plan{ID: "plan", TenantID: "tenant-a", Nonce: "nonce", Operations: []model.Operation{op, other}, CreatedAt: now.Add(-time.Minute), StopAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)}
}
func TestSignedPlanBindingExpiryAndRecovery(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now()
	p := plan(now)
	e, err := Sign(p, priv)
	if err != nil {
		t.Fatal(err)
	}
	if err = Verify(e, pub, "tenant-a", now, false); err != nil {
		t.Fatal(err)
	}
	if Verify(e, pub, "tenant-b", now, false) == nil {
		t.Fatal("cross-tenant signature accepted")
	}
	if Verify(e, pub, "tenant-a", now.Add(time.Hour), false) == nil {
		t.Fatal("expired stop accepted")
	}
	if err = Verify(e, pub, "tenant-a", now.Add(time.Hour), true); err != nil {
		t.Fatal("owned restoration cannot expire", err)
	}
	e.Plan.Operations[0].ProviderResourceID = "i-other"
	if Verify(e, pub, "tenant-a", now, false) == nil {
		t.Fatal("tampering accepted")
	}
	p = plan(now)
	p.Operations[1].Region = "us-east-1"
	e, _ = Sign(p, priv)
	if Verify(e, pub, "tenant-a", now, true) == nil {
		t.Fatal("cross-region restoration accepted")
	}
	p = plan(now)
	p.StopAt = now.Add(time.Hour)
	e, _ = Sign(p, priv)
	if Verify(e, pub, "tenant-a", now, false) == nil {
		t.Fatal("early stop accepted")
	}
}
func TestScheduleTimezoneAndBounds(t *testing.T) {
	now := time.Date(2026, 10, 16, 19, 0, 0, 0, time.UTC)
	s, r, e := NextWindow(now, "Europe/London", "20:00", "07:00", []int{5})
	if e != nil {
		t.Fatal(e)
	}
	if r.Sub(s) != 10*time.Hour+45*time.Minute {
		t.Fatalf("lead time not preserved: %v", r.Sub(s))
	}
	if _, _, e = NextWindow(now, "Europe/London", "20:00", "20:00", []int{5}); e == nil {
		t.Fatal("zero window accepted")
	}
	if _, _, e = NextWindow(now, "Europe/London", "20:00", "07:00", []int{8}); e == nil {
		t.Fatal("invalid weekday accepted")
	}
	if _, _, e = NextWindow(now, "invalid", "20:00", "07:00", []int{5}); e == nil {
		t.Fatal("invalid timezone accepted")
	}
}
func TestSnapshotIgnoresHeartbeatsButBindsSafetyAndEconomics(t *testing.T) {
	r, _, _ := eligible()
	h := SnapshotHash(r)
	r["last_seen_at"] = model.Now()
	r["version"] = 99
	r["cpu_p99"] = "1"
	if SnapshotHash(r) != h {
		t.Fatal("heartbeat invalidated immutable plan")
	}
	for _, field := range []string{"state", "instance_type", "billing_source_version", "hourly_effective_cost", "runtime_stop_start_delegated", "environment"} {
		copy := model.Clone(r)
		copy[field] = "changed"
		if SnapshotHash(copy) == h {
			t.Fatalf("safety/economic field %s unbound", field)
		}
	}
}
