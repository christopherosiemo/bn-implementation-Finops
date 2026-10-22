package service

// These fixtures expose native protocol-shaped responses to the real parsers.
// They are dependency doubles, not AWS or independent production observations.

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleetassessment"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleetbilling"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleetcapacity"
	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/native"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/telemetry"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/workload"
)

type fleetCapacityFixtureOptions struct {
	CPU, Memory   string
	MissingMetric string
	MissingEpoch  bool
	GapMetric     string
	WrongCPUUnit  bool
}

func fleetCapacityFixtureConnection(binding telemetry.Binding) telemetry.Connection {
	c := telemetry.Connection{SchemaVersion: "1", ID: "native-capacity-" + binding.ResourceID, Version: 1, Kind: "PROMETHEUS", ReadBindingID: "approved-" + binding.ResourceID, Enabled: true, Binding: binding, Definitions: []telemetry.Definition{}}
	for _, metric := range []string{"cpu_utilization", "memory_utilization", "cpu_capacity", "memory_capacity", "network_in", "network_out", "disk_read_operations", "disk_write_operations", "disk_read_bytes", "disk_write_bytes", "request_count"} {
		kind, unit, name := "SUM", "bytes", metric+"_total"
		switch metric {
		case "cpu_utilization", "memory_utilization":
			kind, unit, name = "GAUGE", "ratio", metric
		case "cpu_capacity":
			kind, unit, name = "GAUGE", "vCPU", metric
		case "memory_capacity":
			kind, unit, name = "GAUGE", "bytes", metric
		case "disk_read_operations", "disk_write_operations", "request_count":
			unit = "count"
		}
		name = "finops_capacity_" + metric
		if !strings.HasSuffix(name, "_"+unit) {
			name += "_" + unit
		}
		if kind == "SUM" {
			name += "_total"
		}
		d := telemetry.Definition{ID: metric, Version: "1", Metric: metric, Name: name, Type: kind, Unit: unit, Monotonic: kind == "SUM", CadenceSeconds: 300, MaxGapSeconds: 600, Attributes: map[string]string{"instance": binding.ProviderResourceID}, ResourceAttributes: map[string]string{}}
		if kind == "SUM" {
			d.EpochMetric = "process_start_time_seconds"
			d.EpochAttributes = map[string]string{"instance": binding.ProviderResourceID}
		}
		c.Definitions = append(c.Definitions, d)
	}
	return c
}

func fleetCapacityFixtureProfile(binding telemetry.Binding, now time.Time, quadruple bool) workload.Profile {
	p := workload.Profile{SchemaVersion: "1", ID: "unit-capacity-profile", WorkloadID: binding.WorkloadID, Version: 1, Criticality: "NON_PRODUCTION", Statefulness: "UNKNOWN", Timezone: "UTC", MinReplicas: 1, MinZones: 1, Headroom: workload.Headroom{CPUFreePPM: 300000, MemoryFreePPM: 250000, ReserveAboveForecastPPM: 300000}, Saturation: workload.Saturation{CPUP99PPM: 850000, MemoryP99PPM: 900000}, RTOSeconds: 300, Maintenance: []workload.WeeklyWindow{}, RecurringBlackouts: []workload.WeeklyWindow{}, Blackouts: []workload.Blackout{}, DemandEvents: []workload.DemandEvent{}, MaxSimultaneousChangePPM: 250000, VMCooldownSeconds: 86400}
	if quadruple {
		p.DemandEvents = []workload.DemandEvent{{ID: "declared-fourfold-demand", Reason: "Fixture declared launch demand", Start: now.Add(24 * time.Hour), End: now.Add(48 * time.Hour), DemandMultiplierPPM: 4000000}}
	}
	return p
}

func TestFleetCapacityNativeFixtureProfilePublicArrayWire(t *testing.T) {
	now := time.Now().UTC()
	for _, quadruple := range []bool{false, true} {
		p := fleetCapacityFixtureProfile(telemetry.Binding{WorkloadID: "fixture-workload"}, now, quadruple)
		raw, e := json.Marshal(p)
		if e != nil {
			t.Fatal(e)
		}
		var document model.Document
		if e = json.Unmarshal(raw, &document); e != nil {
			t.Fatal(e)
		}
		for _, field := range []string{"maintenance", "recurring_blackouts", "blackouts", "demand_events"} {
			values, ok := document[field].([]any)
			if !ok {
				t.Fatalf("public profile %s must serialize as an array", field)
			}
			want := 0
			if field == "demand_events" && quadruple {
				want = 1
			}
			if len(values) != want {
				t.Fatalf("public profile %s has %d entries, want %d", field, len(values), want)
			}
		}
		for _, field := range []string{"id", "version", "workload_id"} {
			delete(document, field)
		}
		if _, e = safetyProfileRequest(document); e != nil {
			t.Fatal("fixture profile does not satisfy the public request contract", e)
		}
		for _, field := range []string{"maintenance", "recurring_blackouts", "blackouts", "demand_events"} {
			invalid := model.Clone(document)
			invalid[field] = nil
			if _, e = safetyProfileRequest(invalid); e == nil {
				t.Fatalf("null %s unexpectedly satisfies the public profile contract", field)
			}
		}
	}
}

func fleetCapacityFixturePrometheus(t *testing.T, c telemetry.Connection, now time.Time, options fleetCapacityFixtureOptions) (*httptest.Server, time.Time, time.Time) {
	t.Helper()
	if telemetry.ValidateConnection(c) != nil {
		t.Fatal("invalid capacity protocol fixture connection")
	}
	if options.CPU == "" {
		options.CPU = "0.2"
	}
	if options.Memory == "" {
		options.Memory = "0.2"
	}
	end := now.UTC().Truncate(24 * time.Hour)
	start := end.AddDate(0, 0, -14)
	defs := map[string]telemetry.Definition{}
	for _, d := range c.Definitions {
		defs[d.Name] = d
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reply := func(data any) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(model.Document{"status": "success", "data": data})
		}
		if r.ParseForm() != nil {
			http.Error(w, "invalid fixture form", 400)
			return
		}
		if r.URL.Path == "/api/v1/metadata" && r.Method == http.MethodGet {
			family := r.Form.Get("metric")
			for _, d := range c.Definitions {
				if strings.TrimSuffix(d.Name, "_total") == family {
					unit := d.Unit
					if options.WrongCPUUnit && d.Metric == "cpu_utilization" {
						unit = "percent"
					}
					kind := "gauge"
					if d.Type == "SUM" {
						kind = "counter"
					}
					reply(model.Document{family: []any{model.Document{"type": kind, "unit": unit}}})
					return
				}
			}
			http.Error(w, "unknown fixture metadata", 404)
			return
		}
		if r.URL.Path != "/api/v1/query" || r.Method != http.MethodPost {
			http.Error(w, "unsupported fixture route", 404)
			return
		}
		query := r.Form.Get("query")
		at := strings.IndexByte(query, '{')
		if at <= 0 {
			http.Error(w, "unbound fixture selector", 400)
			return
		}
		name := query[:at]
		expected := name + "{instance=" + strconv.Quote(c.Binding.ProviderResourceID) + "}[1210201s]"
		if query != expected || r.Form.Get("time") != end.Format(time.RFC3339Nano) {
			http.Error(w, "fixture range or instance differs", 400)
			return
		}
		d, known := defs[name]
		epoch := name == "process_start_time_seconds"
		if !known && !epoch {
			http.Error(w, "unknown fixture metric", 400)
			return
		}
		if known && d.Metric == options.MissingMetric || epoch && options.MissingEpoch {
			reply(model.Document{"resultType": "matrix", "result": []any{}})
			return
		}
		values := []any{}
		queryStart := start.Add(-600 * time.Second)
		for point, index := queryStart, 0; !point.After(end); point, index = point.Add(300*time.Second), index+1 {
			if known && d.Metric == options.GapMetric && index >= 200 && index <= 202 {
				continue
			}
			value := "0"
			if epoch {
				value = strconv.FormatInt(start.Add(-30*24*time.Hour).Unix(), 10)
			} else {
				switch d.Metric {
				case "cpu_utilization":
					value = options.CPU
				case "memory_utilization":
					value = options.Memory
				case "cpu_capacity":
					value = "2"
				case "memory_capacity":
					value = "17179869184"
				default:
					rate := int64(1000)
					if strings.HasSuffix(d.Metric, "operations") {
						rate = 10
					}
					if d.Metric == "request_count" {
						rate = 60
					}
					value = strconv.FormatInt(10000+int64(index)*300*rate, 10)
				}
			}
			values = append(values, []any{point.Unix(), value})
		}
		reply(model.Document{"resultType": "matrix", "result": []any{model.Document{"metric": map[string]string{"__name__": name, "instance": c.Binding.ProviderResourceID}, "values": values}}})
	}))
	t.Cleanup(server.Close)
	return server, start, end
}

func fleetCapacityFixtureRead(t *testing.T, c telemetry.Connection, now time.Time, options fleetCapacityFixtureOptions) (telemetry.Batch, time.Time, time.Time) {
	t.Helper()
	server, start, end := fleetCapacityFixturePrometheus(t, c, now, options)
	batch, e := (telemetry.PromReader{URL: server.URL, AllowHTTP: true, AllowPrivate: true, Now: func() time.Time { return now }}).Read(context.Background(), c, start, end)
	if e != nil {
		t.Fatal("capacity native Prometheus fixture rejected", e)
	}
	return batch, start, end
}

func fleetCapacityFixtureHardware(t *testing.T, instance string, now time.Time) (provider.HardwareEvidence, []byte) {
	t.Helper()
	if !regexp.MustCompile(`^i-[a-f0-9]{17}$`).MatchString(instance) {
		t.Fatal("invalid fixture instance")
	}
	pages := []nativeAssessmentPage{}
	for _, page := range fleetCapacityHardwarePages {
		selector, e := url.ParseQuery(page.selector)
		if e != nil {
			t.Fatal(e)
		}
		if selector.Get("Action") == "DescribeInstances" {
			selector.Set("InstanceId.1", instance)
		}
		volume := "vol-" + strings.TrimPrefix(instance, "i-")
		if selector.Get("Action") == "DescribeVolumes" {
			selector.Set("VolumeId.1", volume)
		}
		body := strings.ReplaceAll(strings.ReplaceAll(page.body, "<instanceId>i-0123456789abcdef0</instanceId>", "<instanceId>"+instance+"</instanceId>"), "vol-0123456789abcdef0", volume)
		if selector.Get("Action") == "DescribeVolumes" {
			body = strings.ReplaceAll(body, "<volumeType>gp3</volumeType>", "<volumeType>gp3</volumeType><size>64</size>")
		}
		pages = append(pages, nativeAssessmentPage{selector, body})
	}
	raw := nativeAssessmentFrame(pages...)
	hardware, e := provider.ParseHardwareEvidence(raw, nativeAssessmentAccount, "eu-west-1", instance, []string{"m6i.large"}, now)
	if e != nil {
		t.Fatal("rich native hardware fixture rejected", e)
	}
	if e = provider.ValidateHardwareEvidence(hardware, instance, []string{"m6i.large"}); e != nil {
		t.Fatal("rich native hardware raw binding rejected", e)
	}
	return hardware, raw
}

func fleetCapacityFixtureTemplates() (model.Document, []byte) {
	body := `<DescribeLaunchTemplateVersionsResponse><launchTemplateVersionSet>`
	for index, kind := range []string{"m6i.xlarge", "m6i.large"} {
		body += fmt.Sprintf(`<item><launchTemplateId>%s</launchTemplateId><versionNumber>%d</versionNumber><launchTemplateData><instanceType>%s</instanceType><imageId>%s</imageId><placement><tenancy>default</tenancy></placement><blockDeviceMappingSet><item><deviceName>/dev/sda1</deviceName><ebs><volumeType>gp3</volumeType><volumeSize>64</volumeSize><iops>3000</iops><throughput>125</throughput><encrypted>true</encrypted><deleteOnTermination>true</deleteOnTermination></ebs></item></blockDeviceMappingSet></launchTemplateData></item>`, nativeAssessmentTemplate, index+1, kind, nativeAssessmentImage)
	}
	body += `</launchTemplateVersionSet></DescribeLaunchTemplateVersionsResponse>`
	raw := nativeAssessmentFrame(nativeAssessmentPage{url.Values{"Action": {"DescribeLaunchTemplateVersions"}, "Version": {"2016-11-15"}, "MaxResults": {"100"}, "ResolveAlias": {"false"}, "LaunchTemplateId": {nativeAssessmentTemplate}, "LaunchTemplateVersion.1": {"1"}, "LaunchTemplateVersion.2": {"2"}}, body})
	var parsed struct {
		Items []provider.FleetTemplateVersion `xml:"launchTemplateVersionSet>item"`
	}
	if xml.Unmarshal([]byte(body), &parsed) != nil {
		panic("invalid fixed native capacity template fixture")
	}
	return model.Document{"requests": []provider.FleetTemplateRequest{{ID: nativeAssessmentTemplate, Version: 1}, {ID: nativeAssessmentTemplate, Version: 2}}, "templates": parsed.Items}, raw
}

// Unit-only source metadata exercises the pure036 adapter, never a database
// publication path. Connected acceptance replaces these refs with issued rows.
func fleetCapacityFixtureUnitMember(t *testing.T, c telemetry.Connection, profile workload.Profile, population native.CapacityPopulation, now time.Time) fleetcapacity.MemberInput {
	t.Helper()
	selection := func(side string, ordinal int) g.Selection {
		return g.Selection{Target: g.GroupTarget{TenantID: c.Binding.TenantID, WorkloadID: c.Binding.WorkloadID, Provider: "AWS", AccountID: c.Binding.AccountID, Region: c.Binding.Region, FleetID: "unit-" + side, ASGARN: fmt.Sprintf("arn:aws:autoscaling:eu-west-1:111122223333:autoScalingGroup:00000000-0000-4000-8000-%012d:autoScalingGroupName/unit-%s", ordinal, side)}, Registration: g.VersionedRef{ID: "unit-registration-" + side, Version: 1, SHA256: strings.Repeat("a", 64)}, Declaration: g.VersionedRef{ID: "unit-declaration-" + side, Version: 1, SHA256: strings.Repeat("b", 64)}, Scope: g.SnapshotRef{ID: "unit-scope-" + side, SHA256: strings.Repeat("d", 64)}, SourceID: "unit-native-source", SourceRegistrationVersion: 1, SourceConfigSHA256: strings.Repeat("c", 64)}
	}
	old, candidate := selection("old", 1), selection("candidate", 2)
	pin := func(side string) fleetbilling.GroupNativePin {
		return fleetbilling.GroupNativePin{ReceiptID: "unit-only-membership-" + side, RevisionID: "unit-only-revision-" + side, ReceiptSHA256: strings.Repeat("a", 64), RawSHA256: strings.Repeat("b", 64), ReceiptVersionID: "unit-only-v1", RevisionVersionID: "unit-only-v1"}
	}
	scope := fleetcapacity.Scope{Selection: fleetassessment.Selection{Groups: fleetbilling.GroupSelection{OldProposal: g.SnapshotRef{ID: "unit-old-proposal", SHA256: strings.Repeat("e", 64)}, CandidateProposal: g.SnapshotRef{ID: "unit-candidate-proposal", SHA256: strings.Repeat("f", 64)}, Binding: g.Binding{Old: old, Candidate: candidate}}, SafetyProfile: g.VersionedRef{ID: profile.ID, Version: profile.Version, SHA256: workload.Hash(profile)}}, SnapshotSHA256: strings.Repeat("a", 64), PopulationStatus: "OBSERVED_POINT", ObservedAt: now, MembershipPins: []fleetbilling.GroupNativePin{pin("old"), pin("candidate")}, CurrentMemberIDs: []string{c.Binding.ProviderResourceID}}
	resource := model.Document{"id": c.Binding.ResourceID, "version": 1, "workload_id": c.Binding.WorkloadID, "provider": "AWS", "provider_resource_id": c.Binding.ProviderResourceID, "account_id": c.Binding.AccountID, "region": c.Binding.Region, "instance_type": "m6i.xlarge", "environment": "NON_PRODUCTION"}
	connection := telemetry.Document(c)
	connection["revision_id"] = "unit-only-telemetry-revision"
	connection["config_hash"] = telemetry.ConfigHash(c)
	evidence := func(kind, id string, document model.Document, raw []byte) fleetcapacity.NativeEvidence {
		ref := model.Document{"bucket": "unit-only-archive", "key": "tenant/" + c.Binding.TenantID + "/unit-only/" + id, "version_id": "unit-only-v1", "body_sha256": telemetry.BytesHash(raw)}
		metadata := model.Document{"id": id, "kind": kind, "writer_role": "finops_ingester", "revision_id": id + "-revision", "source_id": old.SourceID, "config_hash": old.SourceConfigSHA256, "registration_version": 1, "collected_at": now.Format(time.RFC3339Nano), "raw_object": ref}
		for key, value := range metadata {
			document[key] = value
		}
		revision := model.Document{"id": id + "-revision", "kind": kind, "writer_role": "finops_ingester", "source_id": old.SourceID, "config_hash": old.SourceConfigSHA256, "registration_version": 1, "raw_object": ref}
		return fleetcapacity.NativeEvidence{Receipt: document, Revision: revision, Raw: raw, RevisionRaw: raw}
	}
	hardware, hardwareRaw := fleetCapacityFixtureHardware(t, c.Binding.ProviderResourceID, now)
	hardwareEvidence := evidence("AWS_EC2_HARDWARE", "unit-only-hardware", model.Document{"binding": c.Binding, "native": telemetry.Document(hardware), "resource_snapshot_hash": telemetry.Hash(resource), "resource_version": 1, "candidate_types": []string{"m6i.large"}}, hardwareRaw)
	template, templateRaw := fleetCapacityFixtureTemplates()
	templateEvidence := evidence("AWS_FLEET_LAUNCH_TEMPLATES", "unit-only-template", template, templateRaw)
	decoded, e := fleetcapacity.DecodeCandidateTemplate(templateEvidence, candidate, provider.FleetLaunchTemplate{ID: nativeAssessmentTemplate, Version: "2"}, now)
	if e != nil {
		t.Fatal("candidate native decoder rejected exact fixture", e)
	}
	return fleetcapacity.MemberInput{BatchID: "unit-only-capacity-batch", Scope: scope, InstanceID: c.Binding.ProviderResourceID, Resource: resource, Connection: connection, Profile: profile, Population: &population, Hardware: hardwareEvidence.Receipt, HardwareEvidence: &hardwareEvidence, Candidate: decoded}
}

type fleetCapacityFixtureCalculator struct{ endpoint string }

func (c fleetCapacityFixtureCalculator) Calculate(ctx context.Context, input native.CapacityModelRequest) ([]byte, error) {
	raw, e := json.Marshal(input)
	if e != nil {
		return nil, e
	}
	r, e := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.endpoint, "/")+"/v4/capacity", bytes.NewReader(raw))
	if e != nil {
		return nil, e
	}
	r.Header.Set("Content-Type", "application/json")
	if token := os.Getenv("ECONOMICS_TEST_TOKEN"); token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	client := &http.Client{Timeout: 90 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, e := client.Do(r)
	if e != nil {
		return nil, e
	}
	defer response.Body.Close()
	body, e := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if e != nil {
		return nil, e
	}
	if len(body) > 1<<20 || response.StatusCode != 200 {
		return nil, errors.New("actual capacity fixture response refused")
	}
	return body, nil
}

// Unit-only projection for testing mapper/units. Connected acceptance must use
// the real native.Server selector and database-issued receipt references.
func fleetCapacityFixtureUnitPopulation(c telemetry.Connection, b telemetry.Batch, start, end, now time.Time, p workload.Profile) native.CapacityPopulation {
	e := telemetry.EvaluateHistory(telemetry.HistoryInput{Now: now, Definitions: c.Definitions, Samples: b.Samples, Days: 14, Timezone: "UTC"})
	segments := []telemetry.Segment{}
	for _, s := range telemetry.Segments(b.Samples, c.Definitions) {
		if s.End.After(start) && s.Start.Before(end) {
			segments = append(segments, s)
		}
	}
	out := native.CapacityPopulation{SchemaVersion: "1", Binding: c.Binding, ConnectionID: c.ID, ConnectionVersion: c.Version, ConfigHash: telemetry.ConfigHash(c), SafetyProfileID: p.ID, SafetyProfileVersion: p.Version, SafetyProfileHash: workload.Hash(p), AsOf: now, Start: start, End: end, HistoryDays: 14, Timezone: "UTC", Environment: "NON_PRODUCTION", Definitions: c.Definitions, Segments: segments, ReceiptIDs: []string{"unit-only-telemetry-receipt"}, SourceRefs: []native.CapacityReceiptRef{{ReceiptID: "unit-only-telemetry-receipt", BatchID: "unit-only-batch", ConfigHash: telemetry.ConfigHash(c), RawSHA256: b.RawSHA256, CanonicalHash: telemetry.CanonicalHash(b)}}, ReasonCodes: []string{}, Evaluation: e}
	out.PopulationHash = native.CapacityPopulationHash(out)
	return out
}

func TestFleetCapacityNativeFixtureProtocolUnitsAndIndependentDemand(t *testing.T) {
	now := time.Now().UTC()
	for _, instance := range fleetCapacityPromInstances {
		hardware, _ := fleetCapacityFixtureHardware(t, instance, now)
		if hardware.Instance.ID != instance || hardware.Instance.ImageID != "ami-0123456789abcdef0" {
			t.Fatal("changing a native instance rewrote its independent image identifier")
		}
	}
	binding := telemetry.Binding{TenantID: "unit-capacity-fixture", WorkloadID: "workload", ResourceID: "resource", Provider: "AWS", ProviderResourceID: "i-0123456789abcdef0", AccountID: nativeAssessmentAccount, Region: "eu-west-1"}
	c := fleetCapacityFixtureConnection(binding)
	p := fleetCapacityFixtureProfile(binding, now, false)
	b, start, end := fleetCapacityFixtureRead(t, c, now, fleetCapacityFixtureOptions{})
	population := fleetCapacityFixtureUnitPopulation(c, b, start, end, now, p)
	if population.Evaluation.Status != "READY" || len(b.Rejections) != 0 || len(b.Warnings) != 0 || end.Sub(start) != 14*24*time.Hour {
		t.Fatal("complete native history fixture is not ready", population.Evaluation.ReasonCodes)
	}
	for _, m := range population.Evaluation.Metrics {
		if m.P50 == nil || m.P95 == nil || m.P99 == nil || m.P999 == nil || m.CoveragePPM != 1000000 || m.ExpectedSamples != 4032 {
			t.Fatal("native statistics or complete population missing", m.Metric)
		}
	}
	hardware, _ := fleetCapacityFixtureHardware(t, binding.ProviderResourceID, now)
	receipt := model.Document{"id": "unit-only-hardware-receipt", "kind": "AWS_EC2_HARDWARE", "writer_role": "finops_ingester", "registration_version": 1, "native": telemetry.Document(hardware), "candidate_types": []string{"m6i.large"}}
	mapped, e := native.BuildCapacityModelInput(population, p, receipt)
	if e != nil || mapped.Request == nil {
		t.Fatal("real native hardware/population mapping failed", e, mapped.ReasonCodes)
	}
	input := mapped.Request
	if *input.Current.Capacity.CPU != "2.000000000000" || *input.Current.Capacity.Memory != "17179869184.000000000000" || len(input.Candidates) != 1 || *input.Candidates[0].Capacity.Memory != "8589934592.000000000000" || input.Candidates[0].Pricing != nil {
		t.Fatal("native units/default CPU options were reinterpreted")
	}
	for _, m := range input.Metrics {
		if m.Name == "demand" {
			if m.SemanticRole != native.CapacityRequestProxyRole || m.SourceMetric != "request_count" || m.SourceUnit != "count" || m.Unit != "count/second" || m.Denominator != nil || len(m.Points) != 4032 || *m.Points[0].Value != "60.000000000000" {
				t.Fatal("request counter proxy became invented business-work capacity")
			}
		}
	}
	for _, tc := range []struct {
		name    string
		options fleetCapacityFixtureOptions
		metric  string
	}{{"missing memory", fleetCapacityFixtureOptions{MissingMetric: "memory_utilization"}, "memory_utilization"}, {"missing counter epoch", fleetCapacityFixtureOptions{MissingEpoch: true}, "request_count"}, {"memory observation gap", fleetCapacityFixtureOptions{GapMetric: "memory_utilization"}, "memory_utilization"}} {
		t.Run(tc.name, func(t *testing.T) {
			batch, left, right := fleetCapacityFixtureRead(t, c, now, tc.options)
			pop := fleetCapacityFixtureUnitPopulation(c, batch, left, right, now, p)
			if pop.Evaluation.Status == "READY" {
				t.Fatal("missing native data silently completed history")
			}
			found := false
			for _, m := range pop.Evaluation.Metrics {
				if m.Metric == tc.metric {
					found = true
					if m.Status == "READY" || m.CoveragePPM == 1000000 {
						t.Fatal("missing evidence treated as zero or observed")
					}
					if tc.options.MissingMetric != "" && m.P50 != nil {
						t.Fatal("missing population fabricated a statistic")
					}
				}
			}
			if !found {
				t.Fatal("missing metric disappeared from explanation")
			}
			m, e := native.BuildCapacityModelInput(pop, p, receipt)
			if e != nil || m.Request != nil {
				t.Fatal("incomplete native population reached capacity calculation")
			}
		})
	}
	t.Run("percent cannot replace ratio", func(t *testing.T) {
		server, left, right := fleetCapacityFixturePrometheus(t, c, now, fleetCapacityFixtureOptions{WrongCPUUnit: true})
		_, e := (telemetry.PromReader{URL: server.URL, AllowHTTP: true, AllowPrivate: true}).Read(context.Background(), c, left, right)
		if e == nil || !strings.Contains(e.Error(), "METADATA_MISMATCH") {
			t.Fatal("native metadata unit mismatch accepted", e)
		}
	})
}

// This optional component acceptance uses the actual Python HTTP evaluator and
// native response decoder. Database issuance/publication is covered separately
// by the connected036 test; the refs in this mapper fixture are unit-only.
func TestFleetCapacityNativeFixtureActualPythonSafetyCases(t *testing.T) {
	endpoint := os.Getenv("ECONOMICS_TEST_URL")
	if endpoint == "" {
		t.Skip("requires separately owned actual Python capacity worker")
	}
	for _, tc := range []struct {
		name                    string
		options                 fleetCapacityFixtureOptions
		quadruple               bool
		failedDimension, reason string
	}{
		{"complete low utilization", fleetCapacityFixtureOptions{}, false, "", ""},
		{"low CPU cannot conceal memory95", fleetCapacityFixtureOptions{CPU: "0.2", Memory: "0.95"}, false, "memory", "MEMORY_P95_PLANNING_LIMIT"},
		{"declared fourfold demand needs actual reserve", fleetCapacityFixtureOptions{}, true, "cpu", "CPU_FORECAST_RESERVE_INSUFFICIENT"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Now().UTC()
			binding := telemetry.Binding{TenantID: "unit-capacity-python", WorkloadID: "workload", ResourceID: "resource", Provider: "AWS", ProviderResourceID: "i-0123456789abcdef0", AccountID: nativeAssessmentAccount, Region: "eu-west-1"}
			c := fleetCapacityFixtureConnection(binding)
			profile := fleetCapacityFixtureProfile(binding, now, tc.quadruple)
			batch, start, end := fleetCapacityFixtureRead(t, c, now, tc.options)
			population := fleetCapacityFixtureUnitPopulation(c, batch, start, end, now, profile)
			input := fleetCapacityFixtureUnitMember(t, c, profile, population, now)
			plan, e := fleetcapacity.Prepare(input, now)
			if e != nil || plan.Request == nil {
				t.Fatal("exact native member preparation refused", e, plan.Result.ReasonCodes)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			member, e := fleetcapacity.Evaluate(ctx, plan, fleetCapacityFixtureCalculator{endpoint}, time.Now().UTC())
			if e != nil || !member.ModelEvaluated || member.ModelEvaluation == nil {
				t.Fatal("actual Python capacity contract refused", e, member.ReasonCodes)
			}
			if member.GroupCapacityAuthorized || member.ExecutionAuthorized || member.CompletedBusinessWorkPreserved != nil || member.EstimatedSaving != nil || member.VerifiedSaving != nil || member.ChangePlanID != nil {
				t.Fatal("member calculation invented group or financial authority")
			}
			out := member.ModelEvaluation
			if len(out.Candidates) != 1 || out.ModelVersion != native.CapacityProxyModelVersion {
				t.Fatal("actual evaluator changed candidate or metric contract")
			}
			candidate := out.Candidates[0]
			if candidate.Economics.Status != "UNAVAILABLE" || candidate.Economics.EstimatedSaving != nil || candidate.Economics.VerifiedSaving != nil || candidate.FutureRisk.ProbabilityUpperPPM != nil || candidate.CapacitySuitable {
				t.Fatal("unknown commitment, price or future risk invented authority")
			}
			if !strings.Contains(strings.Join(candidate.ReasonCodes, ","), "COMMITMENT_COMPATIBILITY_UNKNOWN_OR_FALSE") {
				t.Fatal("unproved commitment compatibility disappeared")
			}
			checks := map[string]model.Document{}
			for _, check := range candidate.Checks {
				checks[model.String(check, "dimension")] = check
			}
			if len(checks) != 5 {
				t.Fatal("actual evaluator omitted a physical dimension")
			}
			if tc.failedDimension == "" {
				for name, check := range checks {
					if model.String(check, "status") != "PASS" {
						t.Fatal("low utilization native physical check failed", name)
					}
				}
			} else {
				if model.String(checks[tc.failedDimension], "status") != "FAIL" || !strings.Contains(strings.Join(candidate.ReasonCodes, ","), tc.reason) {
					t.Fatal("unsafe candidate was not explicitly rejected", tc.failedDimension, candidate.ReasonCodes)
				}
				if tc.quadruple && model.String(checks["cpu"], "required_with_reserve") != "2.080000000000" {
					t.Fatal("fourfold forecast reserve was not retained", checks["cpu"]["required_with_reserve"])
				}
			}
			found := false
			for _, metric := range out.Metrics {
				if model.String(metric, "name") == "demand" {
					found = model.String(metric, "semantic_role") == native.CapacityRequestProxyRole && model.String(metric, "unit") == "count/second" && model.String(metric, "source_metric") == "request_count"
				}
			}
			if !found {
				t.Fatal("actual evaluator promoted or erased request proxy meaning")
			}
		})
	}
}

// Explicit EC2 protocol fixtures copied from the established017 parser test.
var fleetCapacityHardwarePages = []struct{ selector, body string }{
	{"Action=DescribeInstances&InstanceId.1=i-0123456789abcdef0&Version=2016-11-15", "<DescribeInstancesResponse><reservationSet><item><ownerId>111122223333</ownerId><instancesSet><item><instanceId>i-0123456789abcdef0</instanceId><instanceType>m6i.xlarge</instanceType><imageId>ami-0123456789abcdef0</imageId><architecture>x86_64</architecture><platformDetails>Linux/UNIX</platformDetails><usageOperation>RunInstances</usageOperation><virtualizationType>hvm</virtualizationType><rootDeviceType>ebs</rootDeviceType><ebsOptimized>true</ebsOptimized><enaSupport>true</enaSupport><cpuOptions><coreCount>1</coreCount><threadsPerCore>2</threadsPerCore></cpuOptions><placement><availabilityZone>eu-west-1a</availabilityZone><tenancy>default</tenancy></placement><blockDeviceMapping><item><deviceName>/dev/sda1</deviceName><ebs><volumeId>vol-0123456789abcdef0</volumeId></ebs></item></blockDeviceMapping></item></instancesSet></item></reservationSet></DescribeInstancesResponse>"},
	{"Action=DescribeInstanceTypes&IncludeUnsupportedInRegion=false&InstanceType.1=m6i.large&InstanceType.2=m6i.xlarge&Version=2016-11-15", "<DescribeInstanceTypesResponse><instanceTypeSet><item><instanceType>m6i.large</instanceType><vCpuInfo><defaultVCpus>2</defaultVCpus><defaultCores>1</defaultCores><defaultThreadsPerCore>2</defaultThreadsPerCore></vCpuInfo><memoryInfo><sizeInMiB>8192</sizeInMiB></memoryInfo><processorInfo><manufacturer>Intel</manufacturer><supportedArchitectures><item>x86_64</item></supportedArchitectures></processorInfo><instanceStorageSupported>false</instanceStorageSupported><burstablePerformanceSupported>false</burstablePerformanceSupported><bareMetal>false</bareMetal><hypervisor>nitro</hypervisor><supportedRootDeviceTypes><item>ebs</item></supportedRootDeviceTypes><supportedUsageClasses><item>on-demand</item></supportedUsageClasses><supportedVirtualizationTypes><item>hvm</item></supportedVirtualizationTypes><networkInfo><enaSupport>required</enaSupport><networkCards><item><networkCardIndex>0</networkCardIndex><baselineBandwidthInGbps>0.781</baselineBandwidthInGbps><peakBandwidthInGbps>12.5</peakBandwidthInGbps></item></networkCards></networkInfo><ebsInfo><ebsOptimizedInfo><baselineIops>3600</baselineIops><baselineThroughputInMBps>81.25</baselineThroughputInMBps><maximumIops>40000</maximumIops><maximumThroughputInMBps>1250</maximumThroughputInMBps></ebsOptimizedInfo></ebsInfo></item><item><instanceType>m6i.xlarge</instanceType><vCpuInfo><defaultVCpus>4</defaultVCpus><defaultCores>2</defaultCores><defaultThreadsPerCore>2</defaultThreadsPerCore></vCpuInfo><memoryInfo><sizeInMiB>16384</sizeInMiB></memoryInfo><processorInfo><manufacturer>Intel</manufacturer><supportedArchitectures><item>x86_64</item></supportedArchitectures></processorInfo><instanceStorageSupported>false</instanceStorageSupported><burstablePerformanceSupported>false</burstablePerformanceSupported><bareMetal>false</bareMetal><hypervisor>nitro</hypervisor><supportedRootDeviceTypes><item>ebs</item></supportedRootDeviceTypes><supportedUsageClasses><item>on-demand</item></supportedUsageClasses><supportedVirtualizationTypes><item>hvm</item></supportedVirtualizationTypes><networkInfo><enaSupport>required</enaSupport><networkCards><item><networkCardIndex>0</networkCardIndex><baselineBandwidthInGbps>0.781</baselineBandwidthInGbps><peakBandwidthInGbps>12.5</peakBandwidthInGbps></item></networkCards></networkInfo><ebsInfo><ebsOptimizedInfo><baselineIops>3600</baselineIops><baselineThroughputInMBps>81.25</baselineThroughputInMBps><maximumIops>40000</maximumIops><maximumThroughputInMBps>1250</maximumThroughputInMBps></ebsOptimizedInfo></ebsInfo></item></instanceTypeSet></DescribeInstanceTypesResponse>"},
	{"Action=DescribeInstanceTypeOfferings&Filter.1.Name=instance-type&Filter.1.Value.1=m6i.large&Filter.1.Value.2=m6i.xlarge&Filter.2.Name=location&Filter.2.Value.1=eu-west-1a&LocationType=availability-zone&MaxResults=1000&Version=2016-11-15", "<DescribeInstanceTypeOfferingsResponse><instanceTypeOfferingSet><item><instanceType>m6i.large</instanceType><locationType>availability-zone</locationType><location>eu-west-1a</location></item><item><instanceType>m6i.xlarge</instanceType><locationType>availability-zone</locationType><location>eu-west-1a</location></item></instanceTypeOfferingSet></DescribeInstanceTypeOfferingsResponse>"},
	{"Action=DescribeVolumes&Version=2016-11-15&VolumeId.1=vol-0123456789abcdef0", "<DescribeVolumesResponse><volumeSet><item><volumeId>vol-0123456789abcdef0</volumeId><volumeType>gp3</volumeType><availabilityZone>eu-west-1a</availabilityZone><iops>3000</iops><throughput>125</throughput><attachmentSet><item><instanceId>i-0123456789abcdef0</instanceId><device>/dev/sda1</device><status>attached</status></item></attachmentSet></item></volumeSet></DescribeVolumesResponse>"},
	{"Action=DescribeImages&ImageId.1=ami-0123456789abcdef0&Version=2016-11-15", "<DescribeImagesResponse><imagesSet><item><imageId>ami-0123456789abcdef0</imageId><architecture>x86_64</architecture><virtualizationType>hvm</virtualizationType><rootDeviceType>ebs</rootDeviceType><imageState>available</imageState><enaSupport>true</enaSupport></item></imagesSet></DescribeImagesResponse>"},
}
