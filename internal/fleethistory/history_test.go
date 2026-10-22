package fleethistory

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func ptr[T any](v T) *T { return &v }
func testInput() Input {
	start := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	b := Binding{TenantID: "tenant-one", WorkloadID: "checkout", Provider: "AWS", AccountID: "111122223333", Region: "eu-west-1"}
	r := Registration{SchemaVersion: SchemaVersion, ID: "registration", Version: 1, FleetID: "fleet-checkout", Binding: b, ASGARN: "arn:aws:autoscaling:eu-west-1:111122223333:autoScalingGroup:12345678-1234-1234-1234-123456789abc:autoScalingGroupName/checkout", SourceID: "inventory", SourceSystem: "AWS_SOURCE_CONNECTION", SourceRegistrationVersion: 2, SourceConfigHash: strings.Repeat("a", 64), CadenceSeconds: 60, MaxGapSeconds: 90}
	d := DemandDefinition{SchemaVersion: SchemaVersion, ID: "completed-orders", Version: 3, Binding: b, Aggregation: "SINGLE_EXTERNAL_TOTAL", Meaning: "COMPLETED_WORK", BusinessOperation: "order_committed", Unit: "completed_orders", Metric: "external_orders_committed_total", MetricDefinitionID: "order-completions", MetricDefinitionVersion: "native-metric-v2", ValueField: "COMPLETED", Origin: "INDEPENDENT_EXTERNAL_SYSTEM", SemanticContractID: "reviewed-orders-definition", SemanticContractHash: strings.Repeat("b", 64), SourceID: "external-activity", SourceSystem: "ACTIVITY_SOURCE", SourceConfigHash: strings.Repeat("c", 64), Temporality: "DELTA", CadenceSeconds: 60, MaxGapSeconds: 90}
	in := Input{Registration: r, Definition: d, Start: start, End: start.Add(2 * time.Minute), AsOf: start.Add(3 * time.Minute)}
	in.Sources = []SourceState{{SourceID: r.SourceID, SourceSystem: r.SourceSystem, SourceRegistrationVersion: ptr(r.SourceRegistrationVersion), ConfigHash: r.SourceConfigHash, Binding: b, Status: "ACTIVE", CheckedAt: in.AsOf}, {SourceID: d.SourceID, SourceSystem: d.SourceSystem, SourceRegistrationVersion: d.SourceRegistrationVersion, ConfigHash: d.SourceConfigHash, Binding: b, Status: "ACTIVE", CheckedAt: in.AsOf}}
	for i := 0; i < 3; i++ {
		at := start.Add(time.Duration(i) * time.Minute)
		source := testRef(in, "AWS_FLEET_MEMBERSHIP", r.SourceID, r.ASGARN, at)
		hw := testRef(in, "AWS_EC2_HARDWARE", r.SourceID, "i-0123456789abcdef0", at)
		in.Observations = append(in.Observations, MembershipObservation{SchemaVersion: SchemaVersion, ID: "point-" + at.Format("150405"), RegistrationID: r.ID, RegistrationVersion: r.Version, RegistrationHash: RegistrationHash(r), ASGARN: r.ASGARN, ObservedAt: at, ReceivedAt: at.Add(2 * time.Second), Source: source, Members: []Member{{InstanceID: hw.Target, LaunchTime: ptr(start.Add(-24 * time.Hour)), LaunchTemplateID: "lt-0123456789abcdef0", LaunchTemplateVersion: 7, ResourceID: "ec2-resource", Hardware: &hw}}})
	}
	for i := 0; i < 2; i++ {
		end := start.Add(time.Duration(i+1) * time.Minute)
		in.Demand = append(in.Demand, DemandSample{SchemaVersion: SchemaVersion, ID: "demand-" + end.Format("150405"), DefinitionID: d.ID, DefinitionVersion: d.Version, DefinitionHash: DefinitionHash(d), MetricDefinitionID: d.MetricDefinitionID, MetricDefinitionVersion: d.MetricDefinitionVersion, Start: end.Add(-time.Minute), Time: end, ReceivedAt: end.Add(2 * time.Second), Value: ptr("10"), Source: testRef(in, "INDEPENDENT_COMPLETED_WORK", d.SourceID, d.Binding.WorkloadID, end)})
	}
	return in
}
func testRef(in Input, kind, source, target string, at time.Time) SourceRef {
	version, config, system := ptr(in.Registration.SourceRegistrationVersion), in.Registration.SourceConfigHash, in.Registration.SourceSystem
	if kind == "INDEPENDENT_COMPLETED_WORK" {
		version, config, system = in.Definition.SourceRegistrationVersion, in.Definition.SourceConfigHash, in.Definition.SourceSystem
	}
	ref := SourceRef{Kind: kind, Binding: in.Registration.Binding, SourceID: source, SourceSystem: system, RevisionID: "native-data-" + at.Format(time.RFC3339Nano), SourceRegistrationVersion: version, ConfigHash: config, ReceiptID: source + "-" + kind + "-" + at.Format(time.RFC3339Nano), Target: target, RawSHA256: strings.Repeat("d", 64), CanonicalHash: strings.Repeat("e", 64), CapturedAt: at, StorageKind: "VERSIONED_OBJECT", Archive: &ArchiveRef{Bucket: "raw", Key: "tenant/" + in.Registration.Binding.TenantID + "/observations/raw", VersionID: "immutable-version", SHA256: strings.Repeat("d", 64)}}
	if system == "ACTIVITY_SOURCE" {
		ref.StorageKind = "POSTGRES_RECEIPT"
		ref.RevisionID = ""
		ref.Archive = nil
		ref.CapturedAt = at.Add(2 * time.Second)
	}
	return ref
}
func analyze(t *testing.T, in Input) Analysis {
	t.Helper()
	out, err := Analyze(in)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
func has(in []string, s string) bool {
	for _, v := range in {
		if v == s {
			return true
		}
	}
	return false
}

func TestPointProvenanceNeverBecomesHistoricalOwnership(t *testing.T) {
	in := testInput()
	out := analyze(t, in)
	if out.Status != "BLOCKED" || out.MembershipStatus != "INTERVAL_OWNERSHIP_UNPROVEN" || len(out.Observations) != 3 || len(out.MembershipGaps) != 1 || len(out.ObservationGaps) != 0 {
		t.Fatalf("unexpected analysis %+v", out)
	}
	if !out.MembershipGaps[0].Start.Equal(in.Start) || !out.MembershipGaps[0].End.Equal(in.End) {
		t.Fatal("equal points manufactured interval coverage")
	}
	if out.Demand.Status != "OBSERVED" || out.Demand.WindowUnits == nil || *out.Demand.WindowUnits != "20" {
		t.Fatalf("native demand count unavailable %+v", out.Demand)
	}
	raw, _ := json.Marshal(out)
	for _, key := range []string{`"execution_authorized"`, `"verified_saving"`, `"complete":`, `"attested"`, `"currency"`} {
		if strings.Contains(string(raw), key) {
			t.Fatalf("authority/money field leaked: %s", key)
		}
	}
	if err := ValidateSnapshot(out, in); err != nil {
		t.Fatal(err)
	}
}
func TestUnknownIncarnationPreservesTruthfulNativePoint(t *testing.T) {
	in := testInput()
	for i := range in.Observations {
		in.Observations[i].Members[0].LaunchTime = nil
		in.Observations[i].Members[0].Hardware = nil
		in.Observations[i].Members[0].ResourceID = ""
	}
	out := analyze(t, in)
	if len(out.Observations) != 3 || !has(out.ReasonCodes, "HISTORY_MEMBER_LAUNCH_TIME_UNOBSERVED") || !has(out.ReasonCodes, "HISTORY_MEMBER_HARDWARE_UNOBSERVED") {
		t.Fatalf("missing facts dropped or invented: %+v", out)
	}
	if out.Observations[0].Members[0].LaunchTime != nil {
		t.Fatal("invented launch time")
	}
}
func TestRegistrationAndNativeIdentityCannotBeBorrowed(t *testing.T) {
	base := testInput()
	for name, change := range map[string]func(*Registration){"tenant": func(r *Registration) { r.Binding.TenantID = "" }, "account": func(r *Registration) { r.Binding.AccountID = "999900001111" }, "region": func(r *Registration) { r.Binding.Region = "us-east-1" }, "provider": func(r *Registration) { r.Binding.Provider = "GCP" }, "name-only": func(r *Registration) { r.ASGARN = "checkout" }, "unversioned": func(r *Registration) { r.SourceRegistrationVersion = 0 }} {
		t.Run(name, func(t *testing.T) {
			r := base.Registration
			change(&r)
			if ValidateRegistration(r) == nil {
				t.Fatal("invalid registration accepted")
			}
		})
	}
	for name, change := range map[string]func(*MembershipObservation){"recreated-asg": func(o *MembershipObservation) {
		o.ASGARN = strings.Replace(o.ASGARN, "12345678-1234", "99999999-1234", 1)
	}, "other-account": func(o *MembershipObservation) { o.Source.Binding.AccountID = "999900001111" }, "other-target": func(o *MembershipObservation) { o.Source.Target = "wrong" }, "missing-object-version": func(o *MembershipObservation) { o.Source.Archive.VersionID = "null" }, "changed-raw": func(o *MembershipObservation) { o.Source.RawSHA256 = strings.Repeat("f", 64) }, "future-launch": func(o *MembershipObservation) { o.Members[0].LaunchTime = ptr(o.ObservedAt.Add(time.Second)) }, "duplicate-member": func(o *MembershipObservation) { o.Members = append(o.Members, o.Members[0]) }} {
		t.Run(name, func(t *testing.T) {
			o := clone(base.Observations[0])
			change(&o)
			if ValidateObservation(base.Registration, o) == nil {
				t.Fatal("native identity/ref mutation accepted")
			}
		})
	}
	in := clone(base)
	in.Sources[0].Binding.TenantID = "other"
	if _, err := Analyze(in); err == nil {
		t.Fatal("foreign lifecycle projection accepted")
	}
	in = clone(base)
	in.Definition.Binding.TenantID = "other"
	if _, err := Analyze(in); err == nil {
		t.Fatal("foreign demand definition accepted")
	}
}
func TestMembershipCorrectionsForksAndNativeConflicts(t *testing.T) {
	in := testInput()
	original := in.Observations[0]
	in.Observations = in.Observations[:1]
	correction := clone(original)
	correction.ID = "correction"
	correction.CorrectsID = original.ID
	correction.ReceivedAt = correction.ReceivedAt.Add(time.Second)
	correction.Members[0].ResourceID = "corrected-resource"
	correction.Source.ReceiptID = "corrected-receipt"
	in.Observations = append(in.Observations, correction)
	out := analyze(t, in)
	if len(out.Observations) != 1 || out.Observations[0].ID != "correction" || !reflect.DeepEqual(out.SupersededIDs, []string{original.ID}) {
		t.Fatalf("correction not selected %+v", out)
	}
	branch := clone(correction)
	branch.ID = "branch"
	in.Observations = append(in.Observations, branch)
	out = analyze(t, in)
	if len(out.Observations) != 0 || !has(out.ReasonCodes, "HISTORY_CORRECTION_BRANCH_CONFLICT") {
		t.Fatal("fork resolved by arbitrary order")
	}
	in.Observations = []MembershipObservation{original, correction}
	in.Observations[1].CorrectsID = ""
	out = analyze(t, in)
	if len(out.Observations) != 0 || !has(out.ReasonCodes, "HISTORY_POINT_MEMBERSHIP_CONFLICT") {
		t.Fatal("same native point conflict blended")
	}
	in.Observations[1].ID = original.ID
	out = analyze(t, in)
	if len(out.Observations) != 0 || !has(out.ReasonCodes, "HISTORY_IMMUTABLE_RECORD_CONFLICT") {
		t.Fatal("immutable ID silently overwritten")
	}
	in.Observations = []MembershipObservation{original, correction}
	in.Observations[0].CorrectsID = correction.ID
	out = analyze(t, in)
	if len(out.Observations) != 0 || !has(out.ReasonCodes, "HISTORY_CORRECTION_CYCLE") {
		t.Fatal("correction cycle accepted")
	}
}
func TestSourceLifecycleAndConfigurationNeverReviveOldAuthority(t *testing.T) {
	for _, status := range []string{"REVOKED", "SUPERSEDED", "DEGRADED"} {
		t.Run(status, func(t *testing.T) {
			in := testInput()
			in.Sources[0].Status = status
			out := analyze(t, in)
			if len(out.Observations) != 0 || !has(out.ReasonCodes, "HISTORY_SOURCE_"+status) {
				t.Fatal("inactive source appeared current")
			}
		})
	}
	in := testInput()
	*in.Sources[0].SourceRegistrationVersion++
	in.Sources[0].ConfigHash = strings.Repeat("f", 64)
	out := analyze(t, in)
	if len(out.Observations) != 0 || !has(out.ReasonCodes, "HISTORY_SOURCE_CONFIGURATION_CHANGED") {
		t.Fatal("source config correction ignored")
	}
	in = testInput()
	*in.Sources[0].SourceRegistrationVersion++
	out = analyze(t, in)
	if len(out.Observations) != 3 {
		t.Fatal("benign registry version increment discarded point history")
	}
	in = testInput()
	in.Sources[0].CheckedAt = in.AsOf.Add(-5*time.Minute - time.Nanosecond)
	out = analyze(t, in)
	if len(out.Observations) != 0 || !has(out.ReasonCodes, "HISTORY_SOURCE_STATE_STALE") {
		t.Fatal("stale projection current")
	}
	in = testInput()
	in.Sources = append(in.Sources, in.Sources[0])
	if _, err := Analyze(in); err == nil {
		t.Fatal("ambiguous current source states accepted")
	}
}
func TestGapAndIncarnationConflictsAreExplicit(t *testing.T) {
	in := testInput()
	in.Observations = []MembershipObservation{in.Observations[0]}
	out := analyze(t, in)
	if len(out.ObservationGaps) == 0 {
		t.Fatal("missing observation cadence hidden")
	}
	in = testInput()
	in.Observations[1].Members[0].LaunchTime = ptr(in.Start.Add(-12 * time.Hour))
	out = analyze(t, in)
	if !has(out.ReasonCodes, "HISTORY_INSTANCE_INCARNATION_CONFLICT") {
		t.Fatal("instance incarnation merged")
	}
}
func TestSnapshotBindsAllInputsAndIsIndependentOfCollectionOrder(t *testing.T) {
	in := testInput()
	original := clone(in)
	out := analyze(t, in)
	if !reflect.DeepEqual(in, original) {
		t.Fatal("input mutated")
	}
	in.Observations[0], in.Observations[2] = in.Observations[2], in.Observations[0]
	in.Sources[0], in.Sources[1] = in.Sources[1], in.Sources[0]
	in.Demand[0], in.Demand[1] = in.Demand[1], in.Demand[0]
	if got := analyze(t, in); out.Hash != got.Hash {
		t.Fatal("collection order affected canonical snapshot")
	}
	for i := 0; i < 20; i++ {
		if analyze(t, in).Hash != out.Hash {
			t.Fatal("map iteration affected canonical snapshot")
		}
	}
	in = clone(original)
	in.Sources[0].Status = "REVOKED"
	if ValidateSnapshot(out, in) == nil {
		t.Fatal("revocation did not invalidate bound snapshot")
	}
	changed := clone(out)
	changed.Observations[0].Members[0].ResourceID = "tampered"
	if ValidateSnapshot(changed, original) == nil {
		t.Fatal("snapshot alteration accepted")
	}
	zone := time.FixedZone("offset", 3600)
	in = clone(original)
	in.Start = in.Start.In(zone)
	in.End = in.End.In(zone)
	in.AsOf = in.AsOf.In(zone)
	for i := range in.Observations {
		in.Observations[i].ObservedAt = in.Observations[i].ObservedAt.In(zone)
	}
	if analyze(t, in).Hash != out.Hash {
		t.Fatal("equivalent instants changed canonical identity")
	}
}
func TestStrictDocumentsCannotSmuggleCoverageOrAuthority(t *testing.T) {
	in := testInput()
	raw, _ := json.Marshal(in.Registration)
	if _, err := DecodeRegistration(raw); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"complete":true`, `"attested":true`, `"trusted":true`, `"execution_authorized":true`, `"hourly_cost":"1.00"`} {
		poison := append(append([]byte{}, raw[:len(raw)-1]...), []byte(","+field+"}")...)
		if _, err := DecodeRegistration(poison); err == nil {
			t.Fatalf("unknown authority accepted %s", field)
		}
	}
	if _, err := DecodeRegistration(append(raw, raw...)); err == nil {
		t.Fatal("trailing JSON accepted")
	}
	o, _ := json.Marshal(in.Observations[0])
	if _, err := DecodeObservation(in.Registration, o); err != nil {
		t.Fatal(err)
	}
	d, _ := json.Marshal(in.Definition)
	if _, err := DecodeDemandDefinition(in.Registration, d); err != nil {
		t.Fatal(err)
	}
	s, _ := json.Marshal(in.Demand[0])
	if _, err := DecodeDemandSample(in.Registration, in.Definition, s); err != nil {
		t.Fatal(err)
	}
}

func TestIndependentRegistryNamespacesAndReceiptVariantsCannotBeConfused(t *testing.T) {
	in := testInput()
	// Equal textual IDs in different registries are legitimate and independent.
	in.Definition.SourceID = in.Registration.SourceID
	in.Sources[1].SourceID = in.Definition.SourceID
	for i := range in.Demand {
		in.Demand[i].DefinitionHash = DefinitionHash(in.Definition)
		in.Demand[i].Source.SourceID = in.Definition.SourceID
	}
	out := analyze(t, in)
	if out.Demand.WindowUnits == nil || len(out.Observations) != 3 {
		t.Fatal("independent namespaces collided")
	}
	in.Sources[1].Status = "REVOKED"
	out = analyze(t, in)
	if out.Demand.WindowUnits != nil || len(out.Observations) != 3 {
		t.Fatal("AWS source status was borrowed by independent demand")
	}
	in = testInput()
	for i := range in.Sources {
		if in.Sources[i].SourceSystem == "ACTIVITY_SOURCE" {
			in.Sources[i].SourceSystem = "AWS_SOURCE_CONNECTION"
			in.Sources[i].SourceRegistrationVersion = ptr(int64(1))
		}
	}
	out = analyze(t, in)
	if out.Demand.WindowUnits != nil || !has(out.Demand.ReasonCodes, "HISTORY_SOURCE_STATE_MISSING") {
		t.Fatal("wrong registry status authorized demand")
	}
	in = testInput()
	if in.Demand[0].Source.RevisionID != "" || in.Demand[0].Source.Archive != nil || in.Demand[0].Source.SourceRegistrationVersion != nil || in.Demand[0].Epoch != nil {
		t.Fatal("activity fixture invented source metadata")
	}
	for name, change := range map[string]func(*DemandSample){"fake-version": func(s *DemandSample) { s.Source.SourceRegistrationVersion = ptr(int64(1)) }, "fake-data-revision": func(s *DemandSample) { s.Source.RevisionID = "invented" }, "wrong-native-metric-version": func(s *DemandSample) { s.MetricDefinitionVersion = "another-version" }, "fake-epoch": func(s *DemandSample) { s.Epoch = ptr(s.Start) }, "changed-original-receive-time": func(s *DemandSample) { s.ReceivedAt = s.ReceivedAt.Add(time.Second) }} {
		t.Run(name, func(t *testing.T) {
			s := clone(in.Demand[0])
			change(&s)
			if ValidateDemandSample(in.Registration, in.Definition, s) == nil {
				t.Fatal("invented/changed immutable receipt metadata accepted")
			}
		})
	}
	for _, field := range []string{"ACCEPTED", "REQUEST_COUNT", "BACKLOG"} {
		d := in.Definition
		d.ValueField = field
		if ValidateDemandDefinition(in.Registration, d) == nil {
			t.Fatal("activity Completed field substitution accepted")
		}
	}
}
