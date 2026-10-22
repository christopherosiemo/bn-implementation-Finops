package service

// Server-only projection of native immutable EBS, policy and billing receipts.
// A public request selects an entity; it never supplies these observations.
import (
	"context"
	"errors"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/evidence"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"time"
)

func storageBinding(tenant string, r model.Document) model.Document {
	return model.Document{"tenant_id": tenant, "workload_id": r["workload_id"], "resource_id": r["id"], "provider": "AWS", "provider_resource_id": r["provider_resource_id"], "account_id": r["account_id"], "region": r["region"]}
}
func storageRef(kind, id, version, hash string) model.Document {
	return model.Document{"kind": kind, "id": id, "version": version, "sha256": hash}
}
func storageArchiveRef(kind string, value any) model.Document {
	d := storageObject(value)
	if model.String(d, "version_id") == "" || len(model.String(d, "body_sha256")) != 64 {
		return nil
	}
	id := model.String(d, "key")
	if id == "" {
		id = model.String(d, "object_key")
	}
	if id == "" {
		return nil
	}
	return storageRef(kind, id, model.String(d, "version_id"), model.String(d, "body_sha256"))
}
func storageStrNumber(v any) any {
	if r, ok := databaseDecimal(v); ok {
		return databaseInputMoney(r)
	}
	return nil
}
func storageNumber(d model.Document, k string) *big.Rat { r, _ := databaseDecimal(d[k]); return r }
func storageMin(a, b *big.Rat) *big.Rat {
	if a == nil || b == nil {
		return nil
	}
	if a.Cmp(b) < 0 {
		return new(big.Rat).Set(a)
	}
	return new(big.Rat).Set(b)
}
func storageCeil(r *big.Rat) *big.Rat {
	if r == nil {
		return nil
	}
	q, m := new(big.Int), new(big.Int)
	q.QuoRem(r.Num(), r.Denom(), m)
	if m.Sign() > 0 {
		q.Add(q, big.NewInt(1))
	}
	return new(big.Rat).SetInt(q)
}

func storagePolicy(p model.Document) model.Document {
	policy := storageObject(p["storage"])
	if len(policy) == 0 {
		return nil
	}
	out := model.Clone(policy)
	out["criticality"] = p["criticality"]
	out["high_seasonality"] = p["high_seasonality"]
	out["allows_lower_durability"] = out["allow_durability_reduction"]
	delete(out, "allow_durability_reduction")
	out["requires_multi_attach"] = out["require_multi_attach"]
	delete(out, "require_multi_attach")
	reserve := model.Number(storageObject(p["headroom"]), "reserve_above_forecast_ppm")
	out["reserve_above_demand_fraction"] = databaseInputMoney(big.NewRat(reserve, 1000000))
	// Declared demand events are policy, not a calibrated forecast.
	growth := int64(1000000)
	for _, event := range storageRows(p["demand_events"]) {
		if v := model.Number(event, "demand_multiplier_ppm"); v > growth {
			growth = v
		}
	}
	out["demand_growth_multiplier"] = databaseInputMoney(big.NewRat(growth, 1000000))
	out["source_ref"] = storageRef("WORKLOAD_SAFETY_PROFILE", model.String(p, "id"), strconv.FormatInt(model.Number(p, "version"), 10), model.String(p, "hash"))
	return out
}

func storageCapabilities(canonical, native model.Document) (model.Document, model.Document, []string) {
	if model.String(native, "outpost_arn") != "" || len(strings.Split(model.String(native, "availability_zone"), "-")) > 3 {
		return nil, nil, []string{"STORAGE_SPECIAL_LOCATION_CAPABILITY_UNSUPPORTED"}
	}
	asset := storageObject(canonical["capabilities"])
	ref := storageArchiveRef("AWS_DOCUMENTED_EBS_CAPABILITIES_V1", asset["asset_ref"])
	assetHash := model.String(provider.EBSCapabilities(), "source_excerpt_sha256")
	if ref == nil || model.String(asset, "source_excerpt_sha256") != assetHash || model.String(ref, "sha256") != assetHash {
		return nil, nil, []string{"STORAGE_DOCUMENTED_CAPABILITY_RECEIPT_REQUIRED"}
	}
	// The exact selected-facts asset is separately versioned and archived. It is
	// never presented as a native provider response or a customer price.
	expected := provider.EBSCapabilities()
	delete(expected, "source_excerpt_sha256")
	actual := model.Clone(asset)
	delete(actual, "asset_ref")
	delete(actual, "source_excerpt_sha256")
	if evidence.Hash(expected) != evidence.Hash(actual) {
		return nil, nil, []string{"STORAGE_DOCUMENTED_CAPABILITY_CHANGED"}
	}
	types := storageObject(asset["volume_types"])
	entries := []model.Document{}
	var current model.Document
	for _, kind := range []string{"gp2", "gp3", "io1", "io2"} {
		v := storageObject(types[kind])
		if len(v) == 0 {
			continue
		}
		entry := model.Document{"id": "aws-ebs-" + kind + "-2026-10-20", "volume_type": kind, "min_size_gib": v["min_size_gib"], "max_size_gib": v["max_size_gib"], "min_iops": v["min_iops"], "max_iops": v["max_iops"], "min_throughput_mib_per_second": "0", "max_throughput_mib_per_second": v["max_throughput_mibps"], "max_iops_per_gib": v["iops_per_gib"], "max_throughput_kib_per_iop": "256", "baseline_iops": "0", "baseline_throughput_mib_per_second": v["max_throughput_mibps"], "multi_attach_supported": v["multi_attach"], "durability_class": "PROVIDER_DOCUMENTED_STANDARD", "latency_class": "PROVIDER_DOCUMENTED_MILLISECOND", "source_ref": ref}
		switch kind {
		case "gp3":
			entry["min_iops"], entry["baseline_iops"] = v["baseline_iops"], v["baseline_iops"]
			entry["min_throughput_mib_per_second"], entry["baseline_throughput_mib_per_second"] = v["baseline_throughput_mibps"], v["baseline_throughput_mibps"]
		case "gp2":
			entry["min_iops"] = v["min_baseline_iops"]
			entry["max_iops_per_gib"] = "3000"
			entry["baseline_iops"] = storageStrNumber(native["iops"])
			size := storageNumber(native, "size_gib")
			entry["baseline_throughput_mib_per_second"] = v["throughput_mibps_below_170_gib"]
			if size != nil && size.Cmp(big.NewRat(334, 1)) >= 0 {
				entry["baseline_throughput_mib_per_second"] = v["max_throughput_mibps"]
			}
		case "io1", "io2":
			entry["max_iops"] = v["max_iops_nitro"]
			if kind == "io2" {
				entry["durability_class"] = "PROVIDER_DOCUMENTED_HIGHER_DURABILITY"
				entry["latency_class"] = "PROVIDER_DOCUMENTED_SUB_MILLISECOND"
			}
		}
		entries = append(entries, entry)
		if kind == model.String(native, "volume_type") {
			current = entry
		}
	}
	return model.Document{"source_ref": ref, "entries": entries}, current, nil
}

type storageMetricDefinition struct {
	native, name, unit, statistic, sourceUnit, sourceStat string
	rate                                                  bool
}

var storageMetricDefinitions = []storageMetricDefinition{
	{"VolumeReadOps", "read_iops", "Count/Second", "MAXIMUM_OF_NATIVE_PERIOD_RATES", "Count", "Sum", true},
	{"VolumeWriteOps", "write_iops", "Count/Second", "MAXIMUM_OF_NATIVE_PERIOD_RATES", "Count", "Sum", true},
	{"VolumeReadBytes", "read_throughput", "Bytes/Second", "MAXIMUM_OF_NATIVE_PERIOD_RATES", "Bytes", "Sum", true},
	{"VolumeWriteBytes", "write_throughput", "Bytes/Second", "MAXIMUM_OF_NATIVE_PERIOD_RATES", "Bytes", "Sum", true},
	{"VolumeQueueLength", "queue_length", "Count", "Maximum", "Count", "Maximum", false},
	{"VolumeAvgReadLatency", "read_latency", "Seconds", "MAXIMUM_OF_NATIVE_PERIOD_OPERATION_MEANS", "Milliseconds", "Maximum", false},
	{"VolumeAvgWriteLatency", "write_latency", "Seconds", "MAXIMUM_OF_NATIVE_PERIOD_OPERATION_MEANS", "Milliseconds", "Maximum", false},
	{"BurstBalance", "burst_balance", "Percent", "Minimum", "Percent", "Minimum", false},
	{"VolumeIOPSExceededCheck", "iops_exceeded", "Count", "Maximum", "None", "Maximum", false},
	{"VolumeThroughputExceededCheck", "throughput_exceeded", "Count", "Maximum", "None", "Maximum", false},
	{"VolumeThroughputPercentage", "throughput_percentage", "Percent", "Maximum", "Percent", "Maximum", false},
	{"VolumeConsumedReadWriteOps", "consumed_iops", "Count/Second", "MAXIMUM_OF_NATIVE_PERIOD_RATES", "Count", "Sum", true},
	{"VolumeIdleTime", "idle_time", "Seconds", "Sum", "Seconds", "Sum", false},
}

type storageNativeBin struct {
	value, samples, maximum *big.Rat
	maximumPeriod           int
	duplicate               bool
}

func storageMetrics(canonical, native model.Document, now time.Time) (model.Document, []model.Document, map[string]*big.Rat, []string) {
	period := storageObject(canonical["period"])
	start, e1 := time.Parse(time.RFC3339Nano, model.String(period, "start"))
	end, e2 := time.Parse(time.RFC3339Nano, model.String(period, "end"))
	reasons := []string{}
	_, startOffset := start.Zone()
	_, endOffset := end.Zone()
	if e1 != nil || e2 != nil || !end.After(start) || startOffset != 0 || endOffset != 0 || start.Unix()%86400 != 0 || end.Unix()%86400 != 0 || end.Sub(start) > 90*24*time.Hour || end.After(now) || now.Sub(end) > 48*time.Hour {
		return nil, []model.Document{}, map[string]*big.Rat{}, []string{"STORAGE_COMPLETE_UTC_HISTORY_REQUIRED"}
	}
	bins := map[string]map[int64]*storageNativeBin{}
	defs := map[string]storageMetricDefinition{}
	periodSeconds := 0
	refs := []model.Document{}
	for _, d := range storageMetricDefinitions {
		defs[d.native] = d
	}
	for _, ev := range storageRows(canonical["metrics"]) {
		sel := storageObject(ev["selection"])
		scope := storageObject(ev["scope"])
		p := int(model.Number(sel, "period_seconds"))
		if model.String(sel, "volume_id") != model.String(native, "volume_id") || scope["account_id"] != native["account_id"] || scope["region"] != native["region"] || p != 60 && p != 300 && p != 3600 || periodSeconds != 0 && p != periodSeconds {
			reasons = append(reasons, "STORAGE_NATIVE_METRIC_SCOPE_INVALID")
			continue
		}
		periodSeconds = p
		if ref := storageArchiveRef("AWS_CLOUDWATCH_EBS_STATISTICS", ev["raw_ref"]); ref != nil {
			refs = append(refs, ref)
		} else {
			reasons = append(reasons, "STORAGE_NATIVE_METRIC_RECEIPT_REQUIRED")
		}
		for _, row := range storageRows(ev["metrics"]) {
			if model.String(row, "namespace") != "AWS/EBS" || model.String(row, "provider_resource_id") != model.String(native, "volume_id") {
				continue
			}
			name := model.String(row, "metric")
			def, known := defs[name]
			if !known {
				continue
			}
			at, e := time.Parse(time.RFC3339Nano, model.String(row, "source_time"))
			if e != nil || at.Before(start) || !at.Before(end) || at.Unix()%int64(p) != 0 || at.Nanosecond() != 0 || row["account_id"] != native["account_id"] || row["region"] != native["region"] || model.Number(row, "period_seconds") != int64(p) || model.String(row, "dimension_name") != "VolumeId" || row["dimension_value"] != native["volume_id"] || model.String(row, "unit") != def.sourceUnit || model.String(row, "statistic") != def.sourceStat {
				reasons = append(reasons, "STORAGE_NATIVE_METRIC_DIMENSIONS_UNSUPPORTED")
				continue
			}
			if bins[name] == nil {
				bins[name] = map[int64]*storageNativeBin{}
			}
			if old := bins[name][at.Unix()]; old != nil {
				old.duplicate = true
				continue
			}
			v, vok := databaseDecimal(row["value"])
			samples, sok := databaseDecimal(row["sample_count"])
			if !vok || v.Sign() < 0 || !sok || !samples.IsInt() || samples.Cmp(big.NewRat(int64(p/60), 1)) < 0 {
				v = nil
			}
			maximum, mok := databaseDecimal(row["native_maximum"])
			maximumPeriod := int(model.Number(row, "native_maximum_period_seconds"))
			if !mok || maximum.Sign() < 0 || maximumPeriod != 60 && maximumPeriod != 300 || maximumPeriod > p {
				maximum = nil
			}
			bins[name][at.Unix()] = &storageNativeBin{value: v, samples: samples, maximum: maximum, maximumPeriod: maximumPeriod}
		}
	}
	if periodSeconds == 0 {
		return nil, []model.Document{}, map[string]*big.Rat{}, append(reasons, "STORAGE_NATIVE_METRICS_UNAVAILABLE")
	}
	nitro := false
	for _, attachment := range storageRows(native["attachments"]) {
		for _, instance := range storageRows(storageObject(canonical["inventory"])["instances"]) {
			if instance["instance_id"] == attachment["instance_id"] {
				for _, catalog := range storageRows(storageObject(canonical["inventory"])["instance_types"]) {
					if catalog["instance_type"] == instance["instance_type"] && model.String(catalog, "hypervisor") == "nitro" {
						nitro = true
					}
				}
			}
		}
	}
	selected := []storageMetricDefinition{}
	for j, def := range storageMetricDefinitions {
		if j < 7 || def.name == "burst_balance" && model.String(native, "volume_type") == "gp2" || nitro && (def.name == "iops_exceeded" || def.name == "throughput_exceeded") || bins[def.native] != nil {
			selected = append(selected, def)
		}
	}
	definitions := []model.Document{}
	for _, def := range selected {
		definitions = append(definitions, model.Document{"name": def.name, "unit": def.unit, "statistic": def.statistic, "period_seconds": 3600, "sample_period_seconds": periodSeconds, "expected_sample_count": 3600 / periodSeconds, "expected_native_sample_count": 60})
	}
	observations := []model.Document{}
	maxima := map[string]*big.Rat{}
	for hour := start; hour.Before(end); hour = hour.Add(time.Hour) {
		values := model.Document{}
		for _, def := range selected {
			count, duplicates := 0, 0
			totalSamples := new(big.Rat)
			var extreme *big.Rat
			operations := new(big.Rat)
			complete := true
			for at := hour; at.Before(hour.Add(time.Hour)); at = at.Add(time.Duration(periodSeconds) * time.Second) {
				b := bins[def.native][at.Unix()]
				if b == nil || b.value == nil || b.samples == nil {
					complete = false
					continue
				}
				if b.duplicate {
					duplicates++
					complete = false
				}
				value := new(big.Rat).Set(b.value)
				if def.rate {
					if b.maximum != nil {
						value.Set(b.maximum)
						value.Quo(value, big.NewRat(int64(b.maximumPeriod), 1))
					} else if periodSeconds == 60 {
						value.Quo(value, big.NewRat(60, 1))
					} else {
						complete = false
						continue
					}
				}
				if def.name == "read_latency" || def.name == "write_latency" {
					op := "VolumeReadOps"
					if def.name == "write_latency" {
						op = "VolumeWriteOps"
					}
					other := bins[op][at.Unix()]
					if other == nil || other.value == nil || other.samples == nil || other.duplicate {
						complete = false
						continue
					}
					operations.Add(operations, other.value)
					if other.value.Sign() == 0 {
						if b.value.Sign() != 0 {
							complete = false
						}
						value = nil
					} else {
						value.Quo(value, big.NewRat(1000, 1))
					}
				}
				count++
				totalSamples.Add(totalSamples, b.samples)
				if value != nil {
					if def.name == "idle_time" {
						if extreme == nil {
							extreme = new(big.Rat)
						}
						extreme.Add(extreme, value)
					} else if extreme == nil || def.name == "burst_balance" && value.Cmp(extreme) < 0 || def.name != "burst_balance" && value.Cmp(extreme) > 0 {
						extreme = new(big.Rat).Set(value)
					}
				}
			}
			point := model.Document{"value": nil, "sample_count": count, "native_sample_count": databaseInputMoney(totalSamples), "duplicate_sample_count": duplicates}
			if def.name == "read_latency" || def.name == "write_latency" {
				point["operations"] = databaseInputMoney(operations)
			}
			if complete && count == 3600/periodSeconds && extreme != nil {
				point["value"] = databaseInputMoney(extreme)
				if old := maxima[def.name]; old == nil || def.name == "burst_balance" && extreme.Cmp(old) < 0 || def.name != "burst_balance" && extreme.Cmp(old) > 0 {
					maxima[def.name] = new(big.Rat).Set(extreme)
				}
			} else if !complete || count != 3600/periodSeconds {
				reasons = append(reasons, "STORAGE_NATIVE_HOURLY_COVERAGE_INCOMPLETE")
			}
			values[def.name] = point
		}
		observations = append(observations, model.Document{"start": hour.Format(time.RFC3339), "end": hour.Add(time.Hour).Format(time.RFC3339), "metrics": values})
	}
	return model.Document{"start": start.Format(time.RFC3339), "end": end.Format(time.RFC3339), "source_refs": refs, "metrics": definitions}, observations, maxima, databaseSortedReasons(reasons)
}

func (a *API) storageAssessmentInput(ctx context.Context, t *store.Tx, resource, snapshot, canonical, profile model.Document) (model.Document, []model.Document, []string, error) {
	inventory := storageObject(canonical["inventory"])
	scope := storageObject(inventory["scope"])
	native := storageObject(resource["storage_configuration"])
	now := a.now().UTC()
	reasons := []string{}
	if scope["tenant_id"] != t.Tenant || scope["account_id"] != resource["account_id"] || scope["region"] != resource["region"] || native["provider_resource_id"] != resource["provider_resource_id"] {
		return nil, nil, []string{"STORAGE_NATIVE_INVENTORY_BINDING_INVALID"}, nil
	}
	rawRef := storageArchiveRef("AWS_EBS_NATIVE_INVENTORY", inventory["raw_ref"])
	if rawRef == nil {
		return nil, nil, []string{"STORAGE_NATIVE_INVENTORY_RECEIPT_REQUIRED"}, nil
	}
	refs := []model.Document{model.Document{"kind": "AWS_EBS_NATIVE_SNAPSHOT", "id": snapshot["id"], "version": "1", "sha256": snapshot["content_hash"], "archive": snapshot["archive"], "observed_at": snapshot["observed_at"]}, rawRef}
	policy := storagePolicy(profile)
	caps, currentCap, rs := storageCapabilities(canonical, native)
	reasons = append(reasons, rs...)
	current := model.Document{"state": native["state"], "source_ref": rawRef, "volume_type": native["volume_type"], "size_gib": storageStrNumber(native["size_gib"]), "iops": storageStrNumber(native["iops"]), "throughput_mib_per_second": storageStrNumber(native["throughput_mibps"]), "native_provisioned_throughput_mib_per_second": storageStrNumber(native["throughput_mibps"]), "throughput_basis": "NATIVE_PROVISIONED_WHEN_PRESENT", "multi_attach_enabled": native["multi_attach_enabled"], "encrypted": native["encrypted"], "kms_key_id": native["kms_key_id"], "created_at": native["create_time"], "attachments": storageAttachments(native, inventory), "capability_id": currentCap["id"]}
	if current["throughput_mib_per_second"] == nil && len(currentCap) > 0 {
		current["throughput_mib_per_second"] = currentCap["baseline_throughput_mib_per_second"]
		current["throughput_basis"] = "DOCUMENTED_FAMILY_CAPACITY_NOT_NATIVE_PROVISIONING"
	}
	if model.String(resource, "resource_type") == "EBS_SNAPSHOT" {
		current = model.Document{"state": native["state"], "source_ref": rawRef, "snapshot_id": native["snapshot_id"], "source_volume_id": native["volume_id"], "started_at": native["start_time"], "created_at": native["start_time"], "storage_tier": native["storage_tier"], "encrypted": native["encrypted"], "kms_key_id": native["kms_key_id"]}
		reasons = []string{}
	}
	input := model.Document{"schema_version": "1", "model_version": "storage-observed-demand-v1", "resource_kind": resource["resource_type"], "binding": storageBinding(t.Tenant, resource), "as_of": now.Format(time.RFC3339Nano), "current_configuration": current, "capabilities": caps, "candidate_configurations": []model.Document{}, "history": nil, "observations": []model.Document{}, "policy": policy, "safety": nil, "current_pricing": nil, "continuing_costs": nil, "snapshots": []model.Document{}}
	safety, safetyRefs, rs, e := storageSafety(ctx, t, resource, canonical, profile, rawRef, now)
	if e != nil {
		return nil, refs, nil, e
	}
	input["safety"] = safety
	refs = append(refs, safetyRefs...)
	reasons = append(reasons, rs...)
	input["snapshots"] = storageSnapshotReviews(inventory, resource, rawRef, policy, model.Bool(safety, "dependency_complete"), now)
	unattached, known := native["attachments"].([]any)
	reviewOnly := model.String(resource, "resource_type") == "EBS_SNAPSHOT" || known && len(unattached) == 0
	// Native []Document values arise in internal tests before JSON roundtrip.
	if list, ok := native["attachments"].([]model.Document); ok && len(list) == 0 {
		reviewOnly = true
	}
	if !reviewOnly {
		history, observations, maxima, rs := storageMetrics(canonical, native, now)
		input["history"], input["observations"] = history, observations
		reasons = append(reasons, rs...)
		input["candidate_configurations"] = storageCandidates(current, policy, maxima)
		reasons = append(reasons, storageHistoryReasons(canonical, native, now)...)
		if created, e := time.Parse(time.RFC3339Nano, model.String(native, "create_time")); e != nil || history != nil && created.Format(time.RFC3339) > model.String(history, "start") {
			reasons = append(reasons, "STORAGE_VOLUME_CREATED_WITHIN_OBSERVATION_WINDOW")
		}
		if model.String(safety, "owner") == "" {
			reasons = append(reasons, "STORAGE_OWNERSHIP_REQUIRED")
		}
	}
	financialRefs, financialReasons, e := a.storageFinancialInput(ctx, t, resource, canonical, input, now)
	if e != nil {
		return nil, refs, nil, e
	}
	refs = append(refs, financialRefs...)
	reasons = append(reasons, financialReasons...)
	return input, refs, databaseSortedReasons(reasons), nil
}

func storageCandidates(current, policy model.Document, maxima map[string]*big.Rat) []model.Document {
	size := storageNumber(current, "size_gib")
	if size == nil {
		return []model.Document{}
	}
	required := func(a, b, fraction string, minimum int64) *big.Rat {
		left, right := maxima[a], maxima[b]
		reserve, growth, frac := storageNumber(policy, "reserve_above_demand_fraction"), storageNumber(policy, "demand_growth_multiplier"), storageNumber(policy, fraction)
		if left == nil || right == nil || reserve == nil || growth == nil || frac == nil || frac.Sign() <= 0 {
			return big.NewRat(minimum, 1)
		}
		v := new(big.Rat).Add(left, right)
		v.Mul(v, growth)
		v.Mul(v, new(big.Rat).Add(big.NewRat(1, 1), reserve))
		v.Quo(v, frac)
		if a == "read_throughput" {
			v.Quo(v, big.NewRat(1<<20, 1))
		}
		v = storageCeil(v)
		if v.Cmp(big.NewRat(minimum, 1)) < 0 {
			return big.NewRat(minimum, 1)
		}
		return v
	}
	iops, throughput := required("read_iops", "write_iops", "iops_max_fraction", 3000), required("read_throughput", "write_throughput", "throughput_max_fraction", 125)
	makeCandidate := func(id string, io, tp *big.Rat) model.Document {
		return model.Document{"id": id, "capability_id": "aws-ebs-gp3-2026-10-20", "volume_type": "gp3", "size_gib": databaseInputMoney(size), "iops": databaseInputMoney(io), "throughput_mib_per_second": databaseInputMoney(tp), "pricing": nil}
	}
	out := []model.Document{}
	if model.String(current, "volume_type") == "gp3" {
		oldIO, oldTP := storageNumber(current, "iops"), storageNumber(current, "throughput_mib_per_second")
		if oldIO == nil || oldTP == nil {
			return out
		}
		iops = storageMin(iops, oldIO)
		throughput = storageMin(throughput, oldTP)
		if iops.Cmp(oldIO) < 0 {
			out = append(out, makeCandidate("gp3-iops", iops, oldTP))
		}
		if throughput.Cmp(oldTP) < 0 {
			out = append(out, makeCandidate("gp3-throughput", oldIO, throughput))
		}
		out = append(out, makeCandidate("gp3-combined", iops, throughput))
	} else {
		out = append(out, makeCandidate("gp3-alternative", iops, throughput))
	}
	return out
}

func storageSafety(ctx context.Context, t *store.Tx, r, canonical, profile, rawRef model.Document, now time.Time) (model.Document, []model.Document, []string, error) {
	inv := storageObject(canonical["inventory"])
	native := storageObject(r["storage_configuration"])
	refs := []model.Document{rawRef}
	reasons := []string{}
	s := model.Document{"owner": r["owner"], "configuration_authority": r["configuration_authority"], "configuration_ref": nil, "attachment_compatible": nil, "instance_iops_limit": nil, "instance_throughput_mib_per_second_limit": nil, "filesystem_reviewed": nil, "backup_observed": nil, "application_slo_clear": nil, "dependency_complete": false, "io_latency_compatible": nil, "io_durability_compatible": nil, "modification_state": "UNKNOWN", "source_refs": refs}
	if model.String(r, "workload_id") != "" {
		w, e := t.Get(ctx, "workloads", model.String(r, "workload_id"))
		if e != nil {
			return nil, nil, nil, e
		}
		if owner := model.String(w, "owner_subject"); owner != "" {
			s["owner"] = owner
		} else if owner = model.String(w, "owner"); owner != "" {
			s["owner"] = owner
		}
	}
	authority, authorityErr := storageConfigurationAuthority(ctx, t, model.String(r, "id"))
	if authorityErr != nil && !errors.Is(authorityErr, pgx.ErrNoRows) {
		return nil, nil, nil, authorityErr
	}
	if storageBoundAuthority(authority, r, t.Tenant) {
		s["configuration_authority"] = authority["authority"]
		ref := storageRef("DECLARED_CONFIGURATION_AUTHORITY", model.String(authority, "id"), strconv.FormatInt(model.Number(authority, "version"), 10), evidence.Hash(storageAuthorityDocument(authority)))
		s["configuration_ref"] = ref
		refs = append(refs, ref)
	}
	g, e := dependencyGraph(ctx, t)
	if e != nil {
		return nil, nil, nil, e
	}
	review, e := t.DependencyReviewLatest(ctx, model.String(r, "id"))
	if e != nil && !errors.Is(e, pgx.ErrNoRows) {
		return nil, nil, nil, e
	}
	if storageReviewCurrent(review, g, model.String(r, "id"), now) {
		s["dependency_complete"] = true
		ref := storageRef("REVIEWED_DEPENDENCY_GRAPH", model.String(review, "id"), strconv.FormatInt(model.Number(review, "graph_version"), 10), evidence.Hash(review))
		refs = append(refs, ref)
	}
	volumes := storageRows(inv["volumes"])
	for _, snap := range storageRows(inv["snapshots"]) {
		if model.String(snap, "volume_id") == model.String(native, "volume_id") && model.String(snap, "state") == "completed" {
			s["backup_observed"] = true
		}
	}
	attachments := storageRows(native["attachments"])
	if len(attachments) > 0 {
		compatible := true
		var ioLimit, tpLimit *big.Rat
		for _, attachment := range attachments {
			var instance, catalog model.Document
			for _, row := range storageRows(inv["instances"]) {
				if row["instance_id"] == attachment["instance_id"] {
					instance = row
				}
			}
			for _, row := range storageRows(inv["instance_types"]) {
				if row["instance_type"] == instance["instance_type"] {
					catalog = row
				}
			}
			support := model.String(storageObject(catalog["ebs"]), "optimized_support")
			if model.String(attachment, "state") != "attached" || model.String(attachment, "device") == "" || model.String(instance, "root_device_name") == "" || model.String(catalog, "hypervisor") != "nitro" || support != "supported" && support != "default" || instance["ebs_optimized"] != true {
				compatible = false
			}
			caps := storageObject(storageObject(catalog["ebs"])["optimized_info"])
			io, tp := storageNumber(caps, "baseline_iops"), storageNumber(caps, "baseline_throughput_mb_per_second")
			if io == nil || tp == nil {
				compatible = false
			} else {
				tp.Mul(tp, big.NewRat(1000000, 1))
				tp.Quo(tp, big.NewRat(1<<20, 1))
				if ioLimit == nil {
					ioLimit, tpLimit = io, tp
				} else {
					ioLimit, tpLimit = storageMin(ioLimit, io), storageMin(tpLimit, tp)
				}
			}
		}
		s["attachment_compatible"] = compatible
		if ioLimit != nil {
			s["instance_iops_limit"] = databaseInputMoney(ioLimit)
			s["instance_throughput_mib_per_second_limit"] = databaseInputMoney(tpLimit)
		}
		// Same GiB and type/performance changes require no filesystem resize. An
		// explicit policy can nevertheless require an independent operator review.
		if storageObject(profile["storage"])["filesystem_review_required"] == false {
			s["filesystem_reviewed"] = true
		}
		sloRefs, rs, e := databaseApplicationSLO(ctx, t, r, now)
		if e != nil {
			return nil, nil, nil, e
		}
		refs = append(refs, sloRefs...)
		s["application_slo_clear"] = len(rs) == 0
		for _, reason := range rs {
			reasons = append(reasons, strings.ReplaceAll(reason, "DATABASE_", "STORAGE_"))
		}
		reasons = append(reasons, storageSharedInstanceReasons(canonical, native, storagePolicy(profile), s)...)
	}
	for _, row := range storageRows(inv["coverage"]) {
		if model.String(row, "component") == "volume_modifications" && strings.HasPrefix(model.String(row, "status"), "OBSERVED_COMPLETE") {
			s["modification_state"] = "NONE"
		}
	}
	for _, row := range storageRows(inv["volume_modifications"]) {
		if row["volume_id"] == native["volume_id"] {
			state := strings.ToUpper(model.String(row, "modification_state"))
			if state == "COMPLETED" {
				s["modification_state"] = "COMPLETED"
			} else {
				s["modification_state"] = state
			}
		}
	}
	_ = volumes
	s["source_refs"] = refs
	return s, refs, reasons, nil
}

func storageAttachments(native, inventory model.Document) any {
	if native["attachments"] == nil {
		return nil
	}
	out := []model.Document{}
	for _, a := range storageRows(native["attachments"]) {
		var root, deleted any
		deleted = a["delete_on_termination"]
		for _, instance := range storageRows(inventory["instances"]) {
			if instance["instance_id"] != a["instance_id"] {
				continue
			}
			if name := model.String(instance, "root_device_name"); name != "" {
				root = name == model.String(a, "device")
			}
			for _, mapping := range storageRows(instance["block_device_mappings"]) {
				if mapping["volume_id"] == native["volume_id"] && mapping["device_name"] == a["device"] {
					if deleted != nil && mapping["delete_on_termination"] != nil && deleted != mapping["delete_on_termination"] {
						deleted = nil
					} else if deleted == nil {
						deleted = mapping["delete_on_termination"]
					}
				}
			}
		}
		out = append(out, model.Document{"instance_id": a["instance_id"], "device": a["device"], "state": a["state"], "delete_on_termination": deleted, "root_device": root})
	}
	return out
}

func storageSnapshotReviews(inv, resource, ref, policy model.Document, reviewed bool, now time.Time) []model.Document {
	out := []model.Document{}
	native := storageObject(resource["storage_configuration"])
	for _, snap := range storageRows(inv["snapshots"]) {
		if model.String(resource, "resource_type") == "EBS_SNAPSHOT" && snap["snapshot_id"] != native["snapshot_id"] || model.String(resource, "resource_type") == "EBS_VOLUME" && snap["volume_id"] != native["volume_id"] {
			continue
		}
		amiIDs := []string{}
		for _, image := range storageRows(inv["owned_images"]) {
			for _, mapping := range storageRows(image["block_device_mappings"]) {
				if mapping["snapshot_id"] == snap["snapshot_id"] {
					amiIDs = append(amiIDs, model.String(image, "image_id"))
				}
			}
		}
		sort.Strings(amiIDs)
		state := "UNKNOWN"
		var required any
		var restores any
		restoreIDs := []string{}
		for _, row := range storageRows(inv["fast_snapshot_restores"]) {
			if row["snapshot_id"] == snap["snapshot_id"] && model.String(row, "state") != "disabled" {
				restoreIDs = append(restoreIDs, "FAST_SNAPSHOT_RESTORE:"+model.String(row, "availability_zone"))
			}
		}
		for _, row := range storageRows(inv["snapshot_tier_statuses"]) {
			if row["snapshot_id"] == snap["snapshot_id"] {
				if until, e := time.Parse(time.RFC3339Nano, model.String(row, "restore_expiry_time")); e == nil && until.After(now) {
					restoreIDs = append(restoreIDs, "ACTIVE_ARCHIVE_RESTORE")
				}
			}
		}
		for _, row := range storageRows(inv["locked_snapshots"]) {
			if row["snapshot_id"] == snap["snapshot_id"] && model.String(row, "lock_state") != "unlocked" {
				required = true
			}
		}
		if len(amiIDs) > 0 || len(restoreIDs) > 0 {
			state = "AMI_OR_RESTORE_DEPENDENT"
			restores = restoreIDs
		} else if reviewed && storageCoverageKnown(inv, "owned_images") && storageCoverageKnown(inv, "snapshots") && storageCoverageKnown(inv, "snapshot_locks") && storageCoverageKnown(inv, "fast_snapshot_restores") && storageCoverageKnown(inv, "snapshot_tiers") && storageSnapshotSharingKnown(inv, model.String(snap, "snapshot_id")) {
			state = "KNOWN_UNREFERENCED"
			restores = []string{}
			if required == nil {
				required = false
			}
		}
		if days := int(model.Number(policy, "snapshot_retention_days")); days > 0 {
			if at, e := time.Parse(time.RFC3339Nano, model.String(snap, "start_time")); e == nil && now.Sub(at) < time.Duration(days)*24*time.Hour {
				required = true
			}
		}
		out = append(out, model.Document{"id": snap["snapshot_id"], "volume_id": snap["volume_id"], "started_at": snap["start_time"], "state": snap["state"], "storage_tier": snap["storage_tier"], "dependency_state": state, "ami_ids": amiIDs, "restore_references": restores, "policy_required": required, "source_ref": ref, "monthly_cost": nil, "currency": nil, "pricing_source_ref": nil})
	}
	return out
}
func storageCoverageKnown(inv model.Document, component string) bool {
	for _, row := range storageRows(inv["coverage"]) {
		if model.String(row, "component") == component {
			return strings.HasPrefix(model.String(row, "status"), "OBSERVED_COMPLETE")
		}
	}
	return false
}
func storageSnapshotSharingKnown(inv model.Document, id string) bool {
	known := false
	for _, c := range storageRows(inv["coverage"]) {
		if model.String(c, "component") == "snapshot_permissions" && c["snapshot_id"] == id && model.String(c, "status") == "OBSERVED" {
			known = true
		}
	}
	if !known {
		return false
	}
	for _, row := range storageRows(inv["snapshot_permissions"]) {
		if row["snapshot_id"] == id {
			node := storageObject(row["permissions"])
			children, childrenKnown := node["children"].([]any)
			if list, ok := node["children"].([]model.Document); ok {
				return model.String(node, "name") == "createVolumePermission" && model.String(node, "value") == "" && len(list) == 0
			}
			return model.String(node, "name") == "createVolumePermission" && model.String(node, "value") == "" && childrenKnown && len(children) == 0
		}
	}
	return false
}
