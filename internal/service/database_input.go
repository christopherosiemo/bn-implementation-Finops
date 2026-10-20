package service

// This mapper accepts only the collector's immutable native snapshot. Customer
// policy supplies limits, not observations; billing is selected below from the
// current authenticated export. A missing value never becomes a zero.
import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/evidence"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/slo"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/workload"
	"github.com/jackc/pgx/v5"
)

const databaseModelVersion = "database-observed-capacity-v1"

func databaseInputRows(v any) []model.Document {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var out []model.Document
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.UseNumber()
	if d.Decode(&out) != nil {
		return nil
	}
	return out
}
func databaseInputObject(v any) model.Document {
	b, err := json.Marshal(v)
	if err != nil {
		return model.Document{}
	}
	var out model.Document
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.UseNumber()
	if d.Decode(&out) != nil || out == nil {
		return model.Document{}
	}
	return out
}
func databaseInputArrayKnown(v any) bool {
	b, err := json.Marshal(v)
	return err == nil && len(b) > 0 && b[0] == '[' && databaseInputRows(v) != nil
}
func databaseInputRef(kind, id, version, hash string) model.Document {
	return model.Document{"kind": kind, "id": id, "version": version, "sha256": hash}
}
func databaseArchiveRef(kind string, raw any) model.Document {
	d := databaseInputObject(raw)
	if model.String(d, "bucket") == "" || model.String(d, "key") == "" || model.String(d, "version_id") == "" || len(model.String(d, "body_sha256")) != 64 {
		return nil
	}
	return databaseInputRef(kind, model.String(d, "bucket")+"/"+model.String(d, "key"), model.String(d, "version_id"), model.String(d, "body_sha256"))
}
func databaseSortedReasons(rs []string) []string {
	set := map[string]bool{}
	for _, r := range rs {
		if r != "" {
			set[r] = true
		}
	}
	out := []string{}
	for r := range set {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}
func databaseDecimal(v any) (*big.Rat, bool) {
	var s string
	switch n := v.(type) {
	case string:
		s = n
	case json.Number:
		s = n.String()
	case int:
		s = strconv.Itoa(n)
	case int64:
		s = strconv.FormatInt(n, 10)
	case float64:
		if n != float64(int64(n)) || n > 9007199254740991 || n < 0 {
			return nil, false
		}
		s = strconv.FormatInt(int64(n), 10)
	default:
		return nil, false
	}
	if !databaseCoverageDecimal.MatchString(s) {
		return nil, false
	}
	r, ok := new(big.Rat).SetString(s)
	return r, ok
}

// Decimal12, ROUND_HALF_EVEN, including negative credits. No binary float math.
func databaseInputMoney(r *big.Rat) string {
	negative := r.Sign() < 0
	n := new(big.Int).Abs(new(big.Int).Set(r.Num()))
	n.Mul(n, big.NewInt(1000000000000))
	q, rem := new(big.Int), new(big.Int)
	q.QuoRem(n, r.Denom(), rem)
	c := new(big.Int).Lsh(rem, 1).Cmp(r.Denom())
	if c > 0 || c == 0 && q.Bit(0) == 1 {
		q.Add(q, big.NewInt(1))
	}
	s := q.String()
	for len(s) < 13 {
		s = "0" + s
	}
	s = s[:len(s)-12] + "." + s[len(s)-12:]
	if negative && q.Sign() != 0 {
		s = "-" + s
	}
	return s
}
func databaseNativeNumber(v any) any {
	r, ok := databaseDecimal(v)
	if !ok || r.Sign() <= 0 {
		return nil
	}
	return databaseInputMoney(r)
}
func databaseScaled(v any, scale int64) any {
	r, ok := databaseDecimal(v)
	if !ok || r.Sign() <= 0 {
		return nil
	}
	return databaseInputMoney(r.Mul(r, big.NewRat(scale, 1)))
}
func databaseUTC(d model.Document, key string) (time.Time, bool) {
	v, e := time.Parse(time.RFC3339Nano, model.String(d, key))
	_, z := v.Zone()
	return v.UTC(), e == nil && z == 0
}
func databaseSameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x := append([]string{}, a...)
	y := append([]string{}, b...)
	sort.Strings(x)
	sort.Strings(y)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

// databaseNativeInput is pure. It neither renews a capture nor accepts caller
// completion flags. Its output is the private Python versioned wire format.
func databaseNativeInput(resource, snapshot, canonical, profile model.Document, now time.Time) (model.Document, []string) {
	rs := []string{}
	block := func(s string) { rs = append(rs, s) }
	for _, s := range model.Strings(canonical, "collection_reason_codes") {
		block(s)
	}
	if len(databaseInputObject(databaseInputObject(resource["database_configuration"])["pending_modified_values"])) > 0 {
		block("DATABASE_PENDING_CONFIGURATION_CHANGE")
	}
	if model.String(canonical, "schema_version") != "1" || model.String(snapshot, "schema_version") != "1" {
		block("DATABASE_NATIVE_SCHEMA_UNSUPPORTED")
	}
	if model.String(resource, "provider") != "AWS" || !databaseResource(resource) || model.String(resource, "workload_id") == "" || model.String(resource, "configuration_authority") == "" || model.String(resource, "configuration_authority") == "UNKNOWN" {
		block("DATABASE_OWNERSHIP_AND_CONFIGURATION_REQUIRED")
	}
	if DatabaseConfigurationHash(resource) != DatabaseConfigurationHash(databaseInputObject(canonical["resource"])) || model.String(snapshot, "resource_id") != model.String(resource, "id") || model.String(snapshot, "config_hash") != DatabaseConfigurationHash(resource) {
		block("DATABASE_NATIVE_CONFIGURATION_CHANGED")
	}
	discovery := databaseInputObject(canonical["discovery"])
	instances := databaseInputRows(discovery["instances"])
	clusters := databaseInputRows(discovery["clusters"])
	account, region := model.String(resource, "account_id"), model.String(resource, "region")
	if model.String(databaseInputObject(discovery["scope"]), "account_id") != account || model.String(databaseInputObject(discovery["scope"]), "region") != region {
		block("DATABASE_NATIVE_DISCOVERY_SCOPE_INVALID")
	}
	nativeByARN := map[string]model.Document{}
	nativeByName := map[string]model.Document{}
	for _, d := range instances {
		arn := model.String(d, "arn")
		if arn == "" || nativeByARN[arn] != nil || model.String(d, "account_id") != account || model.String(d, "region") != region {
			block("DATABASE_NATIVE_INSTANCE_SCOPE_INVALID")
			continue
		}
		nativeByARN[arn] = d
		name := model.String(d, "identifier")
		if nativeByName[name] != nil {
			block("DATABASE_NATIVE_INSTANCE_AMBIGUOUS")
		}
		nativeByName[name] = d
	}
	selected := []model.Document{}
	whole := []model.Document{}
	replicas := []string{}
	native := model.Document{}
	arn := model.String(resource, "provider_resource_id")
	if model.String(resource, "resource_type") == "RDS_INSTANCE" {
		native = nativeByARN[arn]
		if native == nil {
			block("DATABASE_NATIVE_INSTANCE_REQUIRED")
		} else {
			selected = append(selected, native)
			whole = append(whole, native)
			if model.String(native, "read_replica_source_identifier") != "" {
				replicas = append(replicas, arn)
			}
			if model.String(native, "cluster_identifier") != "" {
				block("DATABASE_CLUSTER_MEMBER_REQUIRES_WHOLE_CLUSTER_ASSESSMENT")
			}
			for _, id := range model.Strings(native, "read_replica_identifiers") {
				r := nativeByName[id]
				if r == nil {
					r = nativeByARN[id]
				}
				if r == nil {
					block("DATABASE_WHOLE_HA_CONTEXT_UNAVAILABLE")
				} else {
					whole = append(whole, r)
				}
			}
			if parent := model.String(native, "read_replica_source_identifier"); parent != "" {
				r := nativeByName[parent]
				if r == nil {
					r = nativeByARN[parent]
				}
				if r == nil {
					block("DATABASE_WHOLE_HA_CONTEXT_UNAVAILABLE")
				} else {
					whole = append(whole, r)
				}
			}
		}
	} else {
		for _, c := range clusters {
			if model.String(c, "arn") == arn {
				if len(native) > 0 {
					block("DATABASE_CLUSTER_AMBIGUOUS")
				}
				native = c
			}
		}
		if len(native) == 0 {
			block("DATABASE_NATIVE_CLUSTER_REQUIRED")
		}
		for _, m := range databaseInputRows(native["members"]) {
			r := nativeByName[model.String(m, "identifier")]
			if r == nil {
				block("DATABASE_WHOLE_HA_CONTEXT_UNAVAILABLE")
				continue
			}
			selected = append(selected, r)
			whole = append(whole, r)
			if !model.Bool(m, "is_writer") {
				replicas = append(replicas, model.String(r, "arn"))
			}
		}
		if native["serverless_v2"] != nil || model.String(native, "engine_mode") == "serverless" {
			block("DATABASE_SERVERLESS_CLASS_ASSESSMENT_UNSUPPORTED")
		}
		// Aurora shared volume limits cannot be multiplied into per-node storage.
		if strings.HasPrefix(model.String(native, "engine"), "aurora") {
			block("DATABASE_SHARED_STORAGE_CAPACITY_UNAVAILABLE")
		}
	}
	if len(selected) < 1 || len(selected) > 16 {
		block("DATABASE_MEMBER_BOUND_UNSUPPORTED")
	}
	members := []string{}
	classes := model.Document{}
	zonesSet := map[string]bool{}
	wholeIDs := []string{}
	wholeZones := map[string]bool{}
	class, engine, engineVersion, license, storage := "", "", "", "", ""
	for _, d := range selected {
		a := model.String(d, "arn")
		members = append(members, a)
		classes[a] = d["class"]
		if class == "" {
			class = model.String(d, "class")
			engine = model.String(d, "engine")
			engineVersion = model.String(d, "engine_version")
			license = model.String(d, "license_model")
			storage = model.String(d, "storage_type")
		} else if class != model.String(d, "class") || engine != model.String(d, "engine") || engineVersion != model.String(d, "engine_version") || license != model.String(d, "license_model") || storage != model.String(d, "storage_type") {
			block("DATABASE_MIXED_MEMBER_CONFIGURATION_UNSUPPORTED")
		}
		if model.String(d, "status") != "available" {
			block("DATABASE_NATIVE_NOT_AVAILABLE")
		}
		if len(databaseInputObject(d["pending_modified_values"])) > 0 {
			block("DATABASE_PENDING_CONFIGURATION_CHANGE")
		}
		for _, k := range []string{"availability_zone", "secondary_availability_zone"} {
			if z := model.String(d, k); z != "" {
				zonesSet[z] = true
			}
		}
	}
	for _, d := range whole {
		wholeIDs = append(wholeIDs, model.String(d, "arn"))
		for _, k := range []string{"availability_zone", "secondary_availability_zone"} {
			if z := model.String(d, k); z != "" {
				wholeZones[z] = true
			}
		}
	}
	keys := func(m map[string]bool) []string {
		x := []string{}
		for s := range m {
			x = append(x, s)
		}
		sort.Strings(x)
		return x
	}
	sort.Strings(members)
	sort.Strings(wholeIDs)
	sort.Strings(replicas)
	zones := keys(zonesSet)
	if len(zones) == 0 || class == "" || engine == "" || engineVersion == "" || license == "" || storage == "" {
		block("DATABASE_NATIVE_DIMENSIONS_UNAVAILABLE")
	}
	if strings.HasPrefix(class, "db.t") {
		block("DATABASE_BURST_CREDIT_BASELINE_AND_EXPOSURE_UNRESOLVED")
	}
	configRef := databaseArchiveRef("AWS_RDS_DISCOVERY", discovery["raw_ref"])
	if configRef == nil {
		block("DATABASE_NATIVE_DISCOVERY_REFERENCE_REQUIRED")
	}
	multi := model.Bool(native, "multi_az")
	if len(selected) > 1 {
		multi = true
	}
	configuration := model.Document{"class_id": class, "member_ids": members, "member_class_ids": classes, "replica_member_ids": replicas, "zones": zones, "multi_az": multi, "network_metrics_supported": true, "source_ref": configRef, "ha_context": model.Document{"member_ids": wholeIDs, "zones": keys(wholeZones), "source_ref": configRef}}
	input := model.Document{"schema_version": "1", "model_version": databaseModelVersion, "resource_kind": resource["resource_type"], "binding": model.Document{"tenant_id": resource["tenant_id"], "workload_id": resource["workload_id"], "resource_id": resource["id"], "provider": "AWS", "provider_resource_id": arn, "account_id": account, "region": region}, "as_of": now.UTC().Format(time.RFC3339Nano), "engine": engine, "engine_version": engineVersion, "license_model": license, "storage_type": storage, "current_configuration": configuration}
	policy, err := parseSafetyProfile(profile)
	if err != nil || policy.Database == nil || policy.WorkloadID != model.String(resource, "workload_id") {
		block("DATABASE_SAFETY_POLICY_REQUIRED")
	} else {
		fraction := func(v int64) string { return databaseInputMoney(big.NewRat(v, 1000000)) }
		db := policy.Database
		input["policy"] = model.Document{"criticality": policy.Criticality, "high_seasonality": policy.HighSeasonality, "min_instances": policy.MinReplicas, "min_zones": policy.MinZones, "cpu_max_fraction": fraction(policy.Saturation.CPUP99PPM), "memory_max_fraction": fraction(policy.Saturation.MemoryP99PPM), "connections_max_fraction": db.ConnectionsMaxFraction, "iops_max_fraction": db.IOPSMaxFraction, "throughput_max_fraction": db.ThroughputMaxFraction, "network_max_fraction": db.ThroughputMaxFraction, "storage_max_fraction": db.StorageMaxFraction, "cpu_headroom_fraction": fraction(policy.Headroom.CPUFreePPM), "memory_headroom_fraction": fraction(policy.Headroom.MemoryFreePPM), "reserve_above_forecast_fraction": fraction(policy.Headroom.ReserveAboveForecastPPM), "max_read_latency_seconds": db.MaxReadLatencySeconds, "max_write_latency_seconds": db.MaxWriteLatencySeconds, "max_disk_queue_depth": db.MaxDiskQueueDepth, "max_replica_lag_seconds": db.MaxReplicaLagSeconds, "source_ref": databaseInputRef("WORKLOAD_SAFETY_PROFILE", policy.ID, strconv.FormatInt(policy.Version, 10), workload.Hash(policy))}
	}
	entries, candidates, catalogReasons := databaseCatalogInput(canonical, selected, configuration, region)
	rs = append(rs, catalogReasons...)
	input["catalog"] = model.Document{"source_ref": nil, "entries": entries}
	if len(entries) > 0 {
		input["catalog"].(model.Document)["source_ref"] = entries[0]["source_ref"]
	}
	input["current_catalog_id"] = "class:" + class
	input["candidate_configurations"] = candidates
	history, observations, metricReasons := databaseMetricsInput(canonical, selected, replicas, now)
	input["history"] = history
	input["observations"] = observations
	rs = append(rs, metricReasons...)
	return input, databaseSortedReasons(rs)
}

func databaseCatalogInput(canonical model.Document, members []model.Document, configuration model.Document, region string) ([]model.Document, []model.Document, []string) {
	entries, candidates := []model.Document{}, []model.Document{}
	rs := []string{}
	if len(members) == 0 {
		return entries, candidates, []string{"DATABASE_NATIVE_CATALOG_REQUIRED"}
	}
	catalogs := databaseInputObject(canonical["catalogs"])
	parameters := databaseInputObject(canonical["parameters"])
	first := members[0]
	catalog := databaseInputObject(catalogs[model.String(first, "arn")])
	parameter := databaseInputObject(parameters[model.String(first, "arn")])
	ref := databaseArchiveRef("AWS_RDS_ORDERABLE_CAPACITY", catalog["raw_ref"])
	paramRef := databaseArchiveRef("AWS_RDS_EFFECTIVE_PARAMETERS", parameter["raw_ref"])
	if ref == nil || paramRef == nil {
		rs = append(rs, "DATABASE_CATALOG_AND_PARAMETER_REFERENCES_REQUIRED")
	}
	if model.String(parameter, "connection_capacity_status") != "EXPLICIT_NATIVE_PARAMETER_LITERAL_ALL_GROUPS_IN_SYNC" {
		rs = append(rs, "DATABASE_EFFECTIVE_CONNECTION_CAPACITY_UNAVAILABLE")
	}
	for _, m := range members {
		if reason := databaseModificationReason(databaseInputObject(catalogs[model.String(m, "arn")]), m); reason != "" {
			rs = append(rs, reason)
		}
		p := databaseInputObject(parameters[model.String(m, "arn")])
		if model.String(p, "connection_capacity_status") != "EXPLICIT_NATIVE_PARAMETER_LITERAL_ALL_GROUPS_IN_SYNC" || fmt.Sprint(p["connection_capacity"]) != fmt.Sprint(parameter["connection_capacity"]) {
			rs = append(rs, "DATABASE_MEMBER_PARAMETER_CAPACITY_DIFFERS")
		}
		for _, k := range []string{"allocated_storage_gib", "iops", "storage_throughput_mibps"} {
			if fmt.Sprint(m[k]) != fmt.Sprint(first[k]) {
				rs = append(rs, "DATABASE_MIXED_MEMBER_STORAGE_UNSUPPORTED")
			}
		}
	}
	caps := map[string]model.Document{}
	for _, c := range databaseInputRows(catalog["capacities"]) {
		key := model.String(c, "class")
		if caps[key] != nil {
			rs = append(rs, "DATABASE_NATIVE_CATALOG_AMBIGUOUS")
		}
		caps[key] = c
	}
	seen := map[string]bool{}
	for _, o := range databaseInputRows(catalog["options"]) {
		class := model.String(o, "class")
		if o["engine"] != first["engine"] || o["engine_version"] != first["engine_version"] || o["license_model"] != first["license_model"] || o["storage_type"] != first["storage_type"] {
			continue
		}
		if seen[class] {
			continue
		}
		seen[class] = true
		c := caps[class]
		capacity := model.Document{"vcpu": databaseNativeNumber(c["vcpu"]), "memory_bytes": databaseNativeNumber(c["memory_bytes"]), "max_connections": databaseNativeNumber(parameter["connection_capacity"]), "iops": databaseNativeNumber(first["iops"]), "throughput_bytes_per_second": databaseScaled(first["storage_throughput_mibps"], 1<<20), "network_bytes_per_second": databaseNativeNumber(c["network_bytes_per_second"]), "storage_bytes": databaseScaled(first["allocated_storage_gib"], 1<<30)}
		// A provisioned storage setting must remain supported by this native option;
		// an orderable maximum is never substituted for provisioned capacity.
		for _, pair := range [][3]string{{"iops", "min_iops", "max_iops"}, {"storage_throughput_mibps", "min_throughput_mibps", "max_throughput_mibps"}, {"allocated_storage_gib", "min_storage_gib", "max_storage_gib"}} {
			v, ok := databaseDecimal(first[pair[0]])
			lo, lok := databaseDecimal(o[pair[1]])
			hi, hok := databaseDecimal(o[pair[2]])
			if !ok || !lok || !hok || v.Sign() <= 0 || v.Cmp(lo) < 0 || v.Cmp(hi) > 0 {
				switch pair[0] {
				case "iops":
					capacity["iops"] = nil
				case "storage_throughput_mibps":
					capacity["throughput_bytes_per_second"] = nil
				default:
					capacity["storage_bytes"] = nil
				}
			}
		}
		// Storage settings and orderability maxima do not establish the lower
		// class's sustained EBS capacity. Unknown/burst limits stay unavailable.
		capacity["iops"], capacity["throughput_bytes_per_second"] = databaseClassIOCapacity(class, c, catalog, capacity["iops"], capacity["throughput_bytes_per_second"])
		if strings.HasPrefix(class, "db.t") {
			continue
		}
		entry := model.Document{"id": "class:" + class, "class_id": class, "engine": first["engine"], "engine_version": first["engine_version"], "license_model": first["license_model"], "storage_type": first["storage_type"], "region": region, "architecture": c["architecture"], "cpu_model": c["cpu_model"], "multi_az_capable": o["multi_az_capable"], "zones": o["availability_zones"], "capacity": capacity, "source_ref": ref, "parameter_source_ref": paramRef}
		entries = append(entries, entry)
		candidates = append(candidates, model.Document{"id": "class:" + class, "catalog_id": "class:" + class, "member_count": len(members), "zones": configuration["zones"], "multi_az": configuration["multi_az"], "pricing": nil})
		if len(entries) > 100 {
			rs = append(rs, "DATABASE_NATIVE_CATALOG_LIMIT")
			break
		}
	}
	if !seen[model.String(first, "class")] {
		rs = append(rs, "DATABASE_CURRENT_ORDERABLE_CAPACITY_REQUIRED")
	}
	if len(candidates) == 0 {
		rs = append(rs, "DATABASE_NATIVE_CANDIDATES_UNAVAILABLE")
	}
	sort.Slice(entries, func(i, j int) bool { return model.String(entries[i], "id") < model.String(entries[j], "id") })
	sort.Slice(candidates, func(i, j int) bool { return model.String(candidates[i], "id") < model.String(candidates[j], "id") })
	return entries, candidates, databaseSortedReasons(rs)
}

func databaseClassIOCapacity(class string, native, catalog model.Document, provisionedIOPS, provisionedThroughput any) (any, any) {
	expected, err := provider.RDSDocumentedIOBaseline(class)
	ref := databaseInputObject(catalog["ebs_baseline_asset_ref"])
	if err != nil || expected == nil || evidence.Hash(expected) != evidence.Hash(native["ebs_baseline"]) || databaseArchiveRef("AWS_RDS_DOCUMENTED_IO_BASELINE", ref) == nil || model.String(ref, "body_sha256") != source.BytesHash(provider.RDSDocumentedIOBaselineAsset()) {
		return nil, nil
	}
	capAtBaseline := func(provisioned any, field string) any {
		setting, ok := databaseDecimal(provisioned)
		baseline, known := databaseDecimal(expected[field])
		if !ok || !known || setting.Sign() <= 0 || baseline.Sign() <= 0 {
			return nil
		}
		if setting.Cmp(baseline) > 0 {
			setting = baseline
		}
		return databaseInputMoney(setting)
	}
	return capAtBaseline(provisionedIOPS, "iops"), capAtBaseline(provisionedThroughput, "throughput_bytes_per_second")
}

// Native orderability and current-instance modification constraints are
// independent reads. Their maxima do not stand in for provisioned capacity.
func databaseModificationReason(catalog, native model.Document) string {
	if model.String(catalog, "modification_constraints_status") != "OBSERVED_NATIVE_CURRENT_INSTANCE_CONSTRAINTS" {
		return "DATABASE_NATIVE_MODIFICATION_CONSTRAINTS_UNAVAILABLE"
	}
	constraints := databaseInputObject(catalog["modification_constraints"])
	if model.String(constraints, "resource_arn") != model.String(native, "arn") || model.String(constraints, "basis") != "NATIVE_DESCRIBE_VALID_DB_INSTANCE_MODIFICATIONS_CURRENT_INSTANCE_ONLY" || len(model.String(constraints, "raw_page_sha256")) != 64 || len(databaseInputObject(constraints["native_message"])) == 0 {
		return "DATABASE_NATIVE_MODIFICATION_CONSTRAINTS_BINDING_INVALID"
	}
	if len(databaseInputRows(native["processor_features"])) > 0 {
		return "DATABASE_PROCESSOR_FEATURE_CONFIGURATION_UNSUPPORTED"
	}
	var selected model.Document
	for _, row := range databaseInputRows(constraints["storage"]) {
		if row["storage_type"] == native["storage_type"] {
			if selected != nil {
				return "DATABASE_NATIVE_STORAGE_CONSTRAINTS_AMBIGUOUS"
			}
			selected = row
		}
	}
	if selected == nil {
		return "DATABASE_NATIVE_STORAGE_CONSTRAINTS_UNAVAILABLE"
	}
	inside := func(v any, ranges any, stepRequired bool) bool {
		value, ok := v.(*big.Rat)
		if !ok {
			value, ok = databaseDecimal(v)
		}
		if !ok || value.Sign() <= 0 || !databaseInputArrayKnown(ranges) {
			return false
		}
		for _, r := range databaseInputRows(ranges) {
			low, lok := databaseDecimal(r["from"])
			high, hok := databaseDecimal(r["to"])
			if !lok || !hok || low.Cmp(high) > 0 || value.Cmp(low) < 0 || value.Cmp(high) > 0 {
				continue
			}
			if !stepRequired {
				return true
			}
			step, sok := databaseDecimal(r["step"])
			if !sok || step.Sign() <= 0 {
				continue
			}
			distance := new(big.Rat).Quo(new(big.Rat).Sub(value, low), step)
			if distance.IsInt() {
				return true
			}
		}
		return false
	}
	for _, pair := range [][2]string{{"allocated_storage_gib", "storage_size"}, {"iops", "provisioned_iops"}, {"storage_throughput_mibps", "provisioned_storage_throughput"}} {
		if !inside(native[pair[0]], selected[pair[1]], true) {
			return "DATABASE_NATIVE_STORAGE_MODIFICATION_BOUND_UNPROVEN"
		}
	}
	size, sok := databaseDecimal(native["allocated_storage_gib"])
	iops, iok := databaseDecimal(native["iops"])
	throughput, tok := databaseDecimal(native["storage_throughput_mibps"])
	if !sok || !iok || !tok || size.Sign() <= 0 || iops.Sign() <= 0 {
		return "DATABASE_NATIVE_STORAGE_MODIFICATION_BOUND_UNPROVEN"
	}
	if !inside(new(big.Rat).Quo(iops, size), selected["iops_to_storage_ratio"], false) || !inside(new(big.Rat).Quo(throughput, iops), selected["storage_throughput_to_iops_ratio"], false) {
		return "DATABASE_NATIVE_STORAGE_MODIFICATION_RATIO_UNPROVEN"
	}
	return ""
}

type databaseMetricDef struct{ native, name, unit, stat string }

var databaseMetricDefs = []databaseMetricDef{{"CPUUtilization", "cpu_utilization", "Percent", "Maximum"}, {"FreeableMemory", "freeable_memory", "Bytes", "Minimum"}, {"DatabaseConnections", "connections", "Count", "Maximum"}, {"ReadIOPS", "read_iops", "Count/Second", "Maximum"}, {"WriteIOPS", "write_iops", "Count/Second", "Maximum"}, {"ReadThroughput", "read_throughput", "Bytes/Second", "Maximum"}, {"WriteThroughput", "write_throughput", "Bytes/Second", "Maximum"}, {"NetworkReceiveThroughput", "network_receive", "Bytes/Second", "Maximum"}, {"NetworkTransmitThroughput", "network_transmit", "Bytes/Second", "Maximum"}, {"FreeStorageSpace", "used_storage", "Bytes", "Minimum"}, {"ReadLatency", "read_latency", "Seconds", "Maximum"}, {"WriteLatency", "write_latency", "Seconds", "Maximum"}, {"DiskQueueDepth", "disk_queue_depth", "Count", "Maximum"}, {"ReplicaLag", "replica_lag", "Seconds", "Maximum"}}

type databaseMetricHour struct {
	value, nativeSamples *big.Rat
	count, duplicates    int
	seen                 map[int64]bool
	unknown              bool
}

func databaseMetricsInput(canonical model.Document, members []model.Document, replicas []string, now time.Time) (model.Document, []model.Document, []string) {
	rs := []string{}
	period := databaseInputObject(canonical["period"])
	start, ok := databaseUTC(period, "start")
	end, eok := databaseUTC(period, "end")
	if !ok || !eok || !end.After(start) || start.Hour() != 0 || end.Hour() != 0 || start.Minute() != 0 || end.Minute() != 0 || start.Second() != 0 || end.Second() != 0 || start.Nanosecond() != 0 || end.Nanosecond() != 0 || end.Sub(start) > 90*24*time.Hour || end.After(now) || now.Sub(end) > 48*time.Hour {
		return nil, nil, []string{"DATABASE_COMPLETE_UTC_HISTORY_REQUIRED"}
	}
	defByNative := map[string]databaseMetricDef{}
	for _, d := range databaseMetricDefs {
		defByNative[d.native] = d
	}
	defByNative["AuroraReplicaLag"] = databaseMetricDef{"AuroraReplicaLag", "replica_lag", "Milliseconds", "Maximum"}
	byMember := map[string]model.Document{}
	replicaSet := map[string]bool{}
	for _, m := range members {
		byMember[model.String(m, "arn")] = m
	}
	for _, m := range replicas {
		replicaSet[m] = true
	}
	hours := map[string]*databaseMetricHour{}
	cadence := map[string]int{}
	refs := []model.Document{}
	seenEvidence := map[string]bool{}
	for _, ev := range databaseInputRows(canonical["metrics"]) {
		sel := databaseInputObject(ev["selection"])
		arn := model.String(sel, "resource_arn")
		if byMember[arn] == nil {
			continue
		}
		if seenEvidence[arn] {
			rs = append(rs, "DATABASE_METRIC_RESOURCE_AMBIGUOUS")
		}
		seenEvidence[arn] = true
		ref := databaseArchiveRef("AWS_CLOUDWATCH_RDS_STATISTICS", ev["raw_ref"])
		if ref == nil {
			rs = append(rs, "DATABASE_METRIC_REFERENCE_REQUIRED")
		} else {
			refs = append(refs, ref)
		}
		for _, row := range databaseInputRows(ev["metrics"]) {
			def, known := defByNative[model.String(row, "metric")]
			if !known {
				continue
			}
			if def.name == "replica_lag" && !replicaSet[arn] {
				continue
			}
			p := int(model.Number(row, "period_seconds"))
			at, valid := databaseUTC(row, "source_time")
			if !valid || p != 60 && p != 300 && p != 3600 || at.Before(start) || !at.Before(end) || at.Nanosecond() != 0 || at.Unix()%int64(p) != 0 || model.String(row, "provider_resource_id") != arn || row["account_id"] != byMember[arn]["account_id"] || row["region"] != byMember[arn]["region"] || model.String(row, "unit") != def.unit || model.String(row, "statistic") != def.stat {
				rs = append(rs, "DATABASE_METRIC_NATIVE_DIMENSIONS_INVALID")
				continue
			}
			if old := cadence[def.name]; old != 0 && old != p {
				rs = append(rs, "DATABASE_METRIC_CADENCE_DIFFERS")
				continue
			}
			cadence[def.name] = p
			k := arn + "\x00" + at.Truncate(time.Hour).Format(time.RFC3339) + "\x00" + def.name
			h := hours[k]
			if h == nil {
				h = &databaseMetricHour{seen: map[int64]bool{}, nativeSamples: new(big.Rat)}
				hours[k] = h
			}
			if h.seen[at.Unix()] {
				h.duplicates++
				continue
			}
			h.seen[at.Unix()] = true
			value, vok := databaseDecimal(row["value"])
			count, cok := databaseDecimal(row["sample_count"])
			if !vok || value.Sign() < 0 || !cok || count.Sign() <= 0 || !count.IsInt() {
				h.unknown = true
				continue
			}
			if count.Cmp(big.NewRat(int64(p/60), 1)) < 0 {
				h.unknown = true
				rs = append(rs, "DATABASE_NATIVE_SAMPLE_COVERAGE_INCOMPLETE")
				continue
			}
			if model.String(row, "metric") == "AuroraReplicaLag" {
				value.Quo(value, big.NewRat(1000, 1))
			}
			if def.name == "used_storage" {
				allocated, aok := databaseDecimal(byMember[arn]["allocated_storage_gib"])
				if !aok || allocated.Sign() <= 0 {
					h.unknown = true
					continue
				}
				allocated.Mul(allocated, big.NewRat(1<<30, 1))
				if value.Cmp(allocated) > 0 {
					h.unknown = true
					continue
				}
				value.Sub(allocated, value)
			}
			if h.value == nil || def.name != "freeable_memory" && value.Cmp(h.value) > 0 || def.name == "freeable_memory" && value.Cmp(h.value) < 0 {
				h.value = new(big.Rat).Set(value)
			}
			h.count++
			h.nativeSamples.Add(h.nativeSamples, count)
		}
	}
	definitions := []model.Document{}
	for _, def := range databaseMetricDefs {
		if def.name == "replica_lag" && len(replicas) == 0 {
			continue
		}
		p := cadence[def.name]
		if p == 0 {
			rs = append(rs, "DATABASE_METRIC_UNAVAILABLE_"+strings.ToUpper(def.name))
			continue
		}
		stat := def.stat
		if def.name == "used_storage" {
			stat = "Maximum"
		}
		definitions = append(definitions, model.Document{"name": def.name, "unit": def.unit, "statistic": stat, "period_seconds": 3600, "sample_period_seconds": p, "expected_sample_count": 3600 / p, "expected_native_sample_count": 60})
	}
	observations := []model.Document{}
	for at := start; at.Before(end); at = at.Add(time.Hour) {
		for _, m := range members {
			arn := model.String(m, "arn")
			values := model.Document{}
			for _, def := range databaseMetricDefs {
				if def.name == "replica_lag" && !replicaSet[arn] {
					continue
				}
				h := hours[arn+"\x00"+at.Format(time.RFC3339)+"\x00"+def.name]
				v := model.Document{"value": nil, "sample_count": 0, "native_sample_count": nil, "duplicate_sample_count": 0}
				p := cadence[def.name]
				if h != nil {
					v["sample_count"] = h.count
					v["native_sample_count"] = databaseInputMoney(h.nativeSamples)
					v["duplicate_sample_count"] = h.duplicates
					if !h.unknown && h.value != nil {
						v["value"] = databaseInputMoney(h.value)
					}
					if h.unknown || h.duplicates > 0 || p == 0 || h.count != 3600/p {
						rs = append(rs, "DATABASE_METRIC_HOURLY_COVERAGE_INCOMPLETE")
					}
				} else {
					rs = append(rs, "DATABASE_METRIC_HOURLY_COVERAGE_INCOMPLETE")
				}
				values[def.name] = v
			}
			observations = append(observations, model.Document{"member_id": arn, "start": at.Format(time.RFC3339), "end": at.Add(time.Hour).Format(time.RFC3339), "metrics": values})
		}
	}
	return model.Document{"start": start.Format(time.RFC3339), "end": end.Format(time.RFC3339), "source_refs": refs, "metrics": definitions}, observations, databaseSortedReasons(rs)
}

func (a *API) databaseAssessmentInput(ctx context.Context, t *store.Tx, resource, snapshot, canonical, profile model.Document) (model.Document, []model.Document, []string, error) {
	now := a.now().UTC()
	input, rs := databaseNativeInput(resource, snapshot, canonical, profile, now)
	binding := databaseInputObject(input["binding"])
	binding["tenant_id"] = t.Tenant
	input["binding"] = binding
	refs := []model.Document{model.Document{"kind": "AWS_RDS_NATIVE_SNAPSHOT", "id": snapshot["id"], "version": "1", "sha256": snapshot["content_hash"], "archive": snapshot["archive"], "observed_at": snapshot["observed_at"]}}
	for _, value := range databaseInputObject(canonical["catalogs"]) {
		catalog := databaseInputObject(value)
		if ref := databaseArchiveRef("AWS_RDS_DOCUMENTED_IO_BASELINE", catalog["ebs_baseline_asset_ref"]); ref != nil {
			ref["basis"] = "AWS_DOCUMENTED_NON_BURST_BASELINE_V1"
			refs = append(refs, ref)
		}
	}
	sloRefs, sloReasons, err := databaseApplicationSLO(ctx, t, resource, now)
	if err != nil {
		return nil, refs, nil, err
	}
	refs = append(refs, sloRefs...)
	rs = append(rs, sloReasons...)
	financialRefs, financialReasons, err := a.databaseFinancialInput(ctx, t, resource, canonical, input, now)
	if err != nil {
		return nil, refs, nil, err
	}
	refs = append(refs, financialRefs...)
	rs = append(rs, financialReasons...)
	return input, refs, databaseSortedReasons(rs), nil
}

// Read-only re-evaluation of actual app evidence. Database latency limits do not
// replace an application objective, and no objective is an unknown policy.
func databaseApplicationSLO(ctx context.Context, t *store.Tx, resource model.Document, now time.Time) ([]model.Document, []string, error) {
	d, err := t.SLOObjectiveLatest(ctx, model.String(resource, "workload_id"))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, []string{"DATABASE_APPLICATION_SLO_POLICY_UNKNOWN"}, nil
	}
	if err != nil {
		return nil, nil, err
	}
	obj, err := slo.ParseObjective(d)
	if err != nil {
		return nil, []string{"DATABASE_APPLICATION_SLO_OBJECTIVE_INVALID"}, nil
	}
	latest, err := t.SLOLatest(ctx, model.String(resource, "id"), obj.ID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, []string{"DATABASE_APPLICATION_SLO_EVIDENCE_REQUIRED"}, nil
	}
	if err != nil {
		return nil, nil, err
	}
	src, err := t.SLOSource(ctx, latest.SourceID)
	if err != nil {
		return nil, nil, err
	}
	if src.Binding() != (slo.Binding{TenantID: t.Tenant, WorkloadID: model.String(resource, "workload_id"), ResourceID: model.String(resource, "id"), ProviderResourceID: model.String(resource, "provider_resource_id"), AccountID: model.String(resource, "account_id"), Region: model.String(resource, "region")}) {
		return nil, []string{"DATABASE_APPLICATION_SLO_BINDING_CHANGED"}, nil
	}
	end := now.Truncate(time.Minute)
	rows, err := t.SLOReceipts(ctx, model.String(resource, "id"), obj.ID, end.Add(-time.Duration(obj.EvaluationMinutes)*time.Minute), end)
	if err != nil {
		return nil, nil, err
	}
	eval := slo.Evaluate(slo.Input{Now: now, Objective: obj, Source: src, Receipts: rows})
	refs := []model.Document{databaseInputRef("APPLICATION_SLO_OBJECTIVE", obj.ID, strconv.FormatInt(obj.Version, 10), slo.ObjectiveHash(obj)), databaseInputRef("APPLICATION_SLO_SOURCE", src.ID, "1", slo.SourceHash(src))}
	for _, r := range rows {
		refs = append(refs, databaseInputRef("APPLICATION_SLO_INTERVAL", r.ID, strconv.FormatInt(r.Sequence, 10), r.BodySHA256))
	}
	if eval.Status != "CLEAR" {
		return refs, append([]string{"DATABASE_APPLICATION_SLO_NOT_CLEAR"}, eval.ReasonCodes...), nil
	}
	return refs, nil, nil
}

type databaseNativePrice struct {
	wire       model.Document
	ids        []string
	dimensions string
}

func databaseRawString(d model.Document, key string) string {
	if s := model.String(d, key); s != "" {
		return s
	}
	if s := model.String(d, strings.ReplaceAll(key, "_", "/")); s != "" {
		return s
	}
	// Native CUR exports in this repository use underscore columns; the slash
	// spelling has one section separator, rather than one per word.
	for _, section := range []string{"line_item", "product", "pricing", "bill"} {
		prefix := section + "_"
		if strings.HasPrefix(key, prefix) {
			return model.String(d, strings.ReplaceAll(section, "_", "")+"/"+strings.TrimPrefix(key, prefix))
		}
	}
	return ""
}
func databaseNativeAliases(d model.Document) []string {
	out := []string{}
	for _, key := range []string{"arn", "resource_id"} {
		if s := model.String(d, key); s != "" {
			out = append(out, s)
		}
	}
	return out
}
func databaseAliasSet(ds []model.Document) map[string]bool {
	out := map[string]bool{}
	for _, d := range ds {
		for _, id := range databaseNativeAliases(d) {
			out[id] = true
		}
	}
	return out
}

// An observed customer rate is usable only for a complete, non-overlapping
// day of this exact native instance. It is never borrowed from a public SKU.
func databaseCURPrice(records []model.Document, native model.Document, start, end time.Time, ref model.Document) (databaseNativePrice, string) {
	result := databaseNativePrice{}
	aliases := databaseAliasSet([]model.Document{native})
	type part struct {
		start, end               time.Time
		quantity, amount, rate   *big.Rat
		id, dimensions, currency string
	}
	parts := []part{}
	for _, row := range records {
		if !aliases[model.String(row, "ResourceId")] || model.String(row, "SubAccountId") != model.String(native, "account_id") || model.String(row, "RegionId") != model.String(native, "region") {
			continue
		}
		raw := databaseInputObject(row["x_ProviderFields"])
		if databaseRawString(raw, "product_servicecode") != "AmazonRDS" || databaseRawString(raw, "product_product_family") != "Database Instance" {
			continue
		}
		a, ea := time.Parse(time.RFC3339Nano, model.String(row, "ChargePeriodStart"))
		b, eb := time.Parse(time.RFC3339Nano, model.String(row, "ChargePeriodEnd"))
		if ea != nil || eb != nil || !b.After(a) {
			return result, "DATABASE_CUR_PRICE_INTERVAL_INVALID"
		}
		if !a.Before(end) || !b.After(start) {
			continue
		}
		if a.Before(start) || b.After(end) {
			return result, "DATABASE_CUR_PRICE_PARTIAL_RECORD_UNSUPPORTED"
		}
		if databaseRawString(raw, "line_item_line_item_type") != "Usage" || databaseRawString(raw, "pricing_unit") != "Hrs" || databaseRawString(raw, "product_instance_type") != model.String(native, "class") {
			return result, "DATABASE_CUR_PRICE_DIMENSIONS_UNSUPPORTED"
		}
		if databaseRawString(raw, "product_region_code") != model.String(native, "region") || databaseRawString(raw, "line_item_usage_account_id") != model.String(native, "account_id") || !aliases[databaseRawString(raw, "line_item_resource_id")] {
			return result, "DATABASE_CUR_NATIVE_BINDING_INVALID"
		}
		rate, rok := databaseDecimal(databaseRawString(raw, "line_item_net_unblended_rate"))
		quantity, qok := databaseDecimal(databaseRawString(raw, "line_item_usage_amount"))
		amount, aok := databaseDecimal(databaseRawString(raw, "line_item_net_unblended_cost"))
		billed, bok := databaseDecimal(row["BilledCost"])
		if !rok || !qok || !aok || !bok || rate.Sign() < 0 || quantity.Sign() <= 0 || amount.Sign() < 0 || amount.Cmp(billed) != 0 || databaseInputMoney(new(big.Rat).Mul(rate, quantity)) != databaseInputMoney(amount) || quantity.Cmp(big.NewRat(int64(b.Sub(a)/time.Second), 3600)) != 0 {
			return result, "DATABASE_CUR_NET_RATE_ARITHMETIC_UNAVAILABLE"
		}
		currency := model.String(row, "BillingCurrency")
		if !databaseCoverageCurrency.MatchString(currency) || databaseRawString(raw, "line_item_currency_code") != currency {
			return result, "DATABASE_CUR_CURRENCY_UNAVAILABLE"
		}
		dims := []string{}
		for _, key := range []string{"product_database_engine", "product_license_model", "product_deployment_option", "line_item_operation", "pricing_term"} {
			v := databaseRawString(raw, key)
			if v == "" {
				return result, "DATABASE_CUR_PRICE_DIMENSIONS_UNAVAILABLE"
			}
			dims = append(dims, v)
		}
		parts = append(parts, part{a.UTC(), b.UTC(), quantity, amount, rate, model.String(row, "x_SourceRecordId"), strings.Join(dims, "\x00"), currency})
	}
	if len(parts) == 0 {
		return result, "DATABASE_CUR_CONTRACTED_CLASS_PRICE_UNAVAILABLE"
	}
	sort.Slice(parts, func(i, j int) bool { return parts[i].start.Before(parts[j].start) })
	expected := start
	quantity, amount := new(big.Rat), new(big.Rat)
	for _, p := range parts {
		if !p.start.Equal(expected) || p.rate.Cmp(parts[0].rate) != 0 || p.dimensions != parts[0].dimensions || p.currency != parts[0].currency || p.id == "" {
			return result, "DATABASE_CUR_PRICE_GAP_OR_MIXED_CONFIGURATION"
		}
		expected = p.end
		quantity.Add(quantity, p.quantity)
		amount.Add(amount, p.amount)
		result.ids = append(result.ids, p.id)
	}
	if !expected.Equal(end) {
		return result, "DATABASE_CUR_PRICE_COVERAGE_INCOMPLETE"
	}
	result.dimensions = parts[0].dimensions
	result.wire = model.Document{"basis": "NATIVE_CUR_NET_USAGE_EXCLUDING_COMMITMENT_FEES", "class_id": native["class"], "engine": native["engine"], "license_model": native["license_model"], "region": native["region"], "multi_az": model.Bool(native, "multi_az"), "currency": parts[0].currency, "unit": "Hrs", "rate": databaseInputMoney(parts[0].rate), "quantity": databaseInputMoney(quantity), "amount": databaseInputMoney(amount), "period": model.Document{"start": start.Format(time.RFC3339), "end": end.Format(time.RFC3339)}, "source_ref": ref}
	return result, ""
}

func databaseCommitmentClosure(canonical, registration, receipt model.Document, now time.Time) string {
	if model.String(receipt, "kind") != "AWS_COMMITMENT" || model.String(receipt, "id") != model.String(registration, "commitment_receipt_id") || model.String(receipt, "source_id") != model.String(registration, "id") || model.String(receipt, "config_hash") != source.ConfigurationHash(registration) {
		return "DATABASE_COMMITMENT_CURRENT_RECEIPT_REQUIRED"
	}
	scope := databaseInputObject(receipt["commitment_scope"])
	observed, ok := databaseUTC(scope, "observed_at")
	if !ok || observed.After(now) || now.Sub(observed) > 5*time.Minute {
		return "DATABASE_COMMITMENT_INVENTORY_STALE"
	}
	account := model.String(databaseInputObject(canonical["resource"]), "account_id")
	if !model.Bool(scope, "complete") || model.String(scope, "scope") != "PAYER_ALL_LINKED_ACCOUNTS_ALL_REGIONS" || model.String(scope, "payer_account_id") != model.String(registration, "payer_account_id") || !databaseSameStrings(model.Strings(scope, "usage_account_ids"), []string{account}) {
		return "DATABASE_ORGANISATION_COMMITMENT_ALLOCATION_UNAVAILABLE"
	}
	if scope["savings_plan_count"] == nil || model.Number(scope, "savings_plan_count") != 0 {
		return "DATABASE_SAVINGS_PLAN_EXPOSURE_UNRESOLVED"
	}
	dbsp := databaseInputObject(canonical["database_savings_plans"])
	if model.String(dbsp, "status") != "OBSERVED_ACCOUNT_ONLY_NOT_COMPLETE_PAYER_PORTFOLIO" || !databaseInputArrayKnown(dbsp["plans"]) || len(databaseInputRows(dbsp["plans"])) != 0 || databaseArchiveRef("AWS_DATABASE_SAVINGS_PLANS", dbsp["raw_ref"]) == nil {
		return "DATABASE_NATIVE_DATABASE_SAVINGS_PLAN_EXPOSURE_UNRESOLVED"
	}
	commitments := databaseInputObject(canonical["commitments"])
	if model.String(commitments, "scope_basis") != "ACCOUNT_REGION_NATIVE_RDS_RESERVATION_INVENTORY" || !databaseInputArrayKnown(commitments["reserved_instances"]) {
		return "DATABASE_RESERVED_INVENTORY_UNAVAILABLE"
	}
	for _, reservation := range databaseInputRows(commitments["reserved_instances"]) {
		if model.String(reservation, "state") != "retired" && model.String(reservation, "state") != "payment-failed" {
			return "DATABASE_RESERVED_COMMITMENT_ALLOCATION_UNAVAILABLE"
		}
	}
	return ""
}

// Pure economics selection over one complete unfiltered authenticated export.
// Zero continuing charges are justified only by that exhaustive native export
// and a separately current, complete, empty applicable commitment inventory.
func databaseCURInput(resource, canonical, input, ref, registration, commitment model.Document, records []model.Document, now time.Time) (model.Document, []string) {
	rs := []string{}
	proof := databaseInputObject(ref["source_proof"])
	end, ok := databaseUTC(proof, "period_end")
	begin, bok := databaseUTC(proof, "period_start")
	if !ok || !bok || end.After(now) || now.Sub(end) > 48*time.Hour || end.Hour() != 0 || end.Minute() != 0 || end.Second() != 0 || end.Nanosecond() != 0 || !end.Add(-24*time.Hour).After(begin.Add(-time.Second)) || model.String(proof, "state") != "COMPLETE" && model.String(proof, "state") != "FINAL" {
		return nil, []string{"DATABASE_CUR_COMPLETE_RECENT_DAY_REQUIRED"}
	}
	start := end.Add(-24 * time.Hour)
	compact := databaseInputRef("AWS_CUR_NET_USAGE", model.String(ref, "source_receipt_id"), model.String(ref, "source_version"), model.String(ref, "canonical_hash"))
	instances := databaseInputRows(databaseInputObject(canonical["discovery"])["instances"])
	byARN := map[string]model.Document{}
	for _, d := range instances {
		byARN[model.String(d, "arn")] = d
	}
	current := databaseInputObject(input["current_configuration"])
	members := model.Strings(current, "member_ids")
	selected := []model.Document{}
	var price databaseNativePrice
	ids := map[string]bool{}
	for _, arn := range members {
		n := byARN[arn]
		if n == nil {
			return nil, []string{"DATABASE_CUR_NATIVE_MEMBER_BINDING_REQUIRED"}
		}
		selected = append(selected, n)
		p, reason := databaseCURPrice(records, n, start, end, compact)
		if reason != "" {
			rs = append(rs, reason)
			continue
		}
		if price.wire == nil {
			price = p
		} else if price.dimensions != p.dimensions || price.wire["rate"] != p.wire["rate"] || price.wire["currency"] != p.wire["currency"] {
			rs = append(rs, "DATABASE_MEMBER_CONTRACTED_PRICES_DIFFER")
		}
		for _, id := range p.ids {
			ids[id] = true
		}
	}
	if price.wire != nil {
		price.wire["multi_az"] = current["multi_az"]
		input["current_pricing"] = price.wire
	}
	candidates := databaseInputRows(input["candidate_configurations"])
	matched := 0
	for _, candidate := range candidates {
		class := strings.TrimPrefix(model.String(candidate, "catalog_id"), "class:")
		var target databaseNativePrice
		for _, n := range instances {
			if model.String(n, "class") != class || model.String(n, "engine") != model.String(input, "engine") || model.String(n, "engine_version") != model.String(input, "engine_version") || model.String(n, "license_model") != model.String(input, "license_model") || model.String(n, "storage_type") != model.String(input, "storage_type") || model.String(n, "region") != model.String(resource, "region") || model.String(n, "account_id") != model.String(resource, "account_id") || model.Bool(n, "multi_az") != model.Bool(current, "multi_az") {
				continue
			}
			p, reason := databaseCURPrice(records, n, start, end, compact)
			if reason != "" || price.wire == nil || p.dimensions != price.dimensions || p.wire["currency"] != price.wire["currency"] {
				continue
			}
			if target.wire != nil && target.wire["rate"] != p.wire["rate"] {
				target = databaseNativePrice{}
				rs = append(rs, "DATABASE_TARGET_CONTRACTED_RATE_AMBIGUOUS")
				break
			}
			target = p
		}
		if target.wire != nil {
			candidate["pricing"] = target.wire
			for _, id := range target.ids {
				ids[id] = true
			}
			matched++
		}
	}
	input["candidate_configurations"] = candidates
	if matched == 0 {
		rs = append(rs, "DATABASE_TARGET_CUSTOMER_CUR_PRICE_REQUIRED")
	}
	if reason := databaseCommitmentClosure(canonical, registration, commitment, now); reason != "" {
		rs = append(rs, reason)
	}
	aliases := databaseAliasSet(selected)
	if model.String(resource, "resource_type") == "RDS_CLUSTER" {
		aliases[model.String(resource, "provider_resource_id")] = true
	}
	amounts := map[string]*big.Rat{"storage": new(big.Rat), "backup": new(big.Rat), "io": new(big.Rat)}
	currency := ""
	if price.wire != nil {
		currency = model.String(price.wire, "currency")
	}
	for _, row := range records {
		raw := databaseInputObject(row["x_ProviderFields"])
		if databaseRawString(raw, "product_servicecode") != "AmazonRDS" {
			continue
		}
		a, ea := time.Parse(time.RFC3339Nano, model.String(row, "ChargePeriodStart"))
		b, eb := time.Parse(time.RFC3339Nano, model.String(row, "ChargePeriodEnd"))
		if ea != nil || eb != nil {
			return nil, []string{"DATABASE_CUR_CHARGE_INTERVAL_UNAVAILABLE"}
		}
		if !a.Before(end) || !b.After(start) {
			continue
		}
		// Unallocated payer fees/credits cannot silently become a resource zero.
		if model.String(row, "ResourceId") == "" {
			rs = append(rs, "DATABASE_UNALLOCATED_RDS_CHARGE_EXPOSURE")
			continue
		}
		if !aliases[model.String(row, "ResourceId")] {
			continue
		}
		if model.String(row, "SubAccountId") != model.String(resource, "account_id") || model.String(row, "RegionId") != model.String(resource, "region") || model.String(row, "BillingCurrency") != currency {
			rs = append(rs, "DATABASE_CONTINUING_CHARGE_SCOPE_OR_CURRENCY_DIFFERS")
			continue
		}
		family := databaseRawString(raw, "product_product_family")
		if family == "Database Instance" {
			if databaseRawString(raw, "line_item_line_item_type") != "Usage" {
				rs = append(rs, "DATABASE_COVERED_COMPUTE_EXPOSURE_UNRESOLVED")
			}
			continue
		}
		if a.Before(start) || b.After(end) {
			rs = append(rs, "DATABASE_CONTINUING_CHARGE_PERIOD_UNSUPPORTED")
			continue
		}
		kind := ""
		switch family {
		case "Database Storage", "Storage", "Aurora Storage":
			kind = "storage"
		case "Storage Snapshot", "Backup Storage":
			kind = "backup"
		case "Provisioned IOPS", "System Operation":
			kind = "io"
		default:
			rs = append(rs, "DATABASE_CONTINUING_CHARGE_FAMILY_UNSUPPORTED")
			continue
		}
		amount, aok := databaseDecimal(databaseRawString(raw, "line_item_net_unblended_cost"))
		billed, bok := databaseDecimal(row["BilledCost"])
		if !aok || !bok || amount.Sign() < 0 || amount.Cmp(billed) != 0 {
			rs = append(rs, "DATABASE_CONTINUING_NET_COST_UNAVAILABLE")
			continue
		}
		amounts[kind].Add(amounts[kind], amount)
		ids[model.String(row, "x_SourceRecordId")] = true
	}
	continuing := model.Document{"currency": currency, "period": model.Document{"start": start.Format(time.RFC3339), "end": end.Format(time.RFC3339)}}
	for name, amount := range amounts {
		continuing[name] = model.Document{"amount": databaseInputMoney(amount), "source_ref": compact}
	}
	zeroTargets := model.Document{}
	for _, candidate := range candidates {
		zeroTargets[model.String(candidate, "id")] = "0.000000000000"
	}
	commitRef := databaseInputRef("AWS_RDS_AND_PAYER_COMMITMENT_INVENTORY", model.String(commitment, "id"), strconv.FormatInt(model.Number(registration, "version"), 10), evidence.Hash(model.Document{"payer": commitment, "rds": canonical["commitments"], "discovery_ref": databaseInputObject(canonical["discovery"])["raw_ref"]}))
	continuing["commitment_exposure"] = model.Document{"current_amount": "0.000000000000", "candidate_amounts": zeroTargets, "source_ref": commitRef}
	input["continuing_costs"] = continuing
	used := []string{}
	for id := range ids {
		if id != "" {
			used = append(used, id)
		}
	}
	sort.Strings(used)
	full := databaseInputObject(ref)
	full["economic_record_ids"] = used
	if len(used) == 0 {
		rs = append(rs, "DATABASE_ECONOMIC_RECORD_REFERENCES_REQUIRED")
	}
	return full, databaseSortedReasons(rs)
}

// Each accepted historical hour has one whole native billed instance-hour at
// the current class. This is a conditional billed-capacity basis, not a claim
// that a point Config capture describes effective configuration transitions.
// Split, minimum-billed, covered, daily-aggregated and recreated instances fail
// closed. Original monthly jobs and their current heads remain unchanged.
func databaseCURClassHistory(records []model.Document, members []model.Document, start, end time.Time) ([]string, string) {
	if !end.After(start) || end.Sub(start) > 90*24*time.Hour || start.Minute() != 0 || start.Second() != 0 || start.Nanosecond() != 0 || end.Minute() != 0 || end.Second() != 0 || end.Nanosecond() != 0 {
		return nil, "DATABASE_HISTORICAL_CONFIGURATION_REQUIRED"
	}
	byAlias := map[string]model.Document{}
	for _, native := range members {
		created, ok := databaseUTC(native, "instance_create_time")
		if !ok || created.After(start) || model.String(native, "resource_id") == "" {
			return nil, "DATABASE_HISTORICAL_INCARNATION_UNAVAILABLE"
		}
		for _, alias := range databaseNativeAliases(native) {
			if old := byAlias[alias]; old != nil && model.String(old, "arn") != model.String(native, "arn") {
				return nil, "DATABASE_HISTORICAL_NATIVE_BINDING_AMBIGUOUS"
			}
			byAlias[alias] = native
		}
	}
	seen := map[string]bool{}
	dimensions := map[string]string{}
	ids := []string{}
	sourceIDs := map[string]bool{}
	for _, row := range records {
		native := byAlias[model.String(row, "ResourceId")]
		if native == nil {
			continue
		}
		raw := databaseInputObject(row["x_ProviderFields"])
		if databaseRawString(raw, "product_servicecode") != "AmazonRDS" || databaseRawString(raw, "product_product_family") != "Database Instance" {
			continue
		}
		a, ea := time.Parse(time.RFC3339Nano, model.String(row, "ChargePeriodStart"))
		b, eb := time.Parse(time.RFC3339Nano, model.String(row, "ChargePeriodEnd"))
		_, az := a.Zone()
		_, bz := b.Zone()
		if ea != nil || eb != nil || !b.After(a) {
			return nil, "DATABASE_HISTORICAL_USAGE_INTERVAL_INVALID"
		}
		if !a.Before(end) || !b.After(start) {
			continue
		}
		if az != 0 || bz != 0 || a.Before(start) || b.After(end) || b.Sub(a) != time.Hour || a.Minute() != 0 || a.Second() != 0 || a.Nanosecond() != 0 || databaseRawString(raw, "line_item_line_item_type") != "Usage" || databaseRawString(raw, "pricing_unit") != "Hrs" {
			return nil, "DATABASE_HISTORICAL_WHOLE_HOURLY_USAGE_REQUIRED"
		}
		quantity, qok := databaseDecimal(databaseRawString(raw, "line_item_usage_amount"))
		if !qok || quantity.Cmp(big.NewRat(1, 1)) != 0 {
			return nil, "DATABASE_HISTORICAL_WHOLE_HOURLY_USAGE_REQUIRED"
		}
		if model.String(row, "SubAccountId") != model.String(native, "account_id") || model.String(row, "RegionId") != model.String(native, "region") || databaseRawString(raw, "line_item_usage_account_id") != model.String(native, "account_id") || databaseRawString(raw, "product_region_code") != model.String(native, "region") || !databaseAliasSet([]model.Document{native})[databaseRawString(raw, "line_item_resource_id")] {
			return nil, "DATABASE_HISTORICAL_NATIVE_BINDING_CHANGED"
		}
		if databaseRawString(raw, "product_instance_type") != model.String(native, "class") {
			return nil, "DATABASE_HISTORICAL_CLASS_CHANGED"
		}
		dims := []string{}
		for _, key := range []string{"product_database_engine", "product_license_model", "product_deployment_option", "line_item_operation", "pricing_term", "line_item_currency_code"} {
			value := databaseRawString(raw, key)
			if value == "" {
				return nil, "DATABASE_HISTORICAL_DIMENSIONS_UNAVAILABLE"
			}
			dims = append(dims, value)
		}
		identity := strings.Join(dims, "\x00")
		arn := model.String(native, "arn")
		if old := dimensions[arn]; old != "" && old != identity {
			return nil, "DATABASE_HISTORICAL_DIMENSIONS_CHANGED"
		}
		dimensions[arn] = identity
		key := arn + "\x00" + a.UTC().Format(time.RFC3339)
		id := model.String(row, "x_SourceRecordId")
		if seen[key] || id == "" || sourceIDs[id] {
			return nil, "DATABASE_HISTORICAL_USAGE_AMBIGUOUS"
		}
		seen[key] = true
		sourceIDs[id] = true
		ids = append(ids, id)
	}
	for at := start; at.Before(end); at = at.Add(time.Hour) {
		for _, native := range members {
			if !seen[model.String(native, "arn")+"\x00"+at.Format(time.RFC3339)] {
				return nil, "DATABASE_HISTORICAL_CONFIGURATION_REQUIRED"
			}
		}
	}
	sort.Strings(ids)
	return ids, ""
}

func (a *API) databaseBillingHistory(ctx context.Context, t *store.Tx, canonical, input, selectedRef model.Document, selectedRecords []model.Document) ([]model.Document, []string, error) {
	period := databaseInputObject(input["history"])
	start, ok := databaseUTC(period, "start")
	end, eok := databaseUTC(period, "end")
	if !ok || !eok || !end.After(start) || end.Sub(start) > 90*24*time.Hour {
		return nil, []string{"DATABASE_HISTORICAL_CONFIGURATION_REQUIRED"}, nil
	}
	selected := map[string]bool{}
	for _, arn := range model.Strings(databaseInputObject(input["current_configuration"]), "member_ids") {
		selected[arn] = true
	}
	members := []model.Document{}
	for _, native := range databaseInputRows(databaseInputObject(canonical["discovery"])["instances"]) {
		if selected[model.String(native, "arn")] {
			members = append(members, native)
		}
	}
	if len(members) != len(selected) || len(members) == 0 {
		return nil, []string{"DATABASE_HISTORICAL_CONFIGURATION_REQUIRED"}, nil
	}
	refs := []model.Document{}
	compactRefs := databaseInputRows(period["source_refs"])
	totalRows, totalBytes := 0, 0
	months := 0
	for month := time.Date(start.Year(), start.Month(), 1, 0, 0, 0, 0, time.UTC); month.Before(end); month = month.AddDate(0, 1, 0) {
		months++
		if months > 4 {
			return nil, []string{"DATABASE_HISTORICAL_MONTH_LIMIT"}, nil
		}
		ref, records := selectedRef, selectedRecords
		if model.String(selectedRef, "billing_period_start") != month.Format(time.RFC3339) {
			var err error
			ref, records, err = a.databaseBillingMonth(ctx, t, model.String(selectedRef, "source_connection_id"), month)
			if err != nil {
				if databaseDomainError(err) || errors.Is(err, pgx.ErrNoRows) {
					return nil, []string{"DATABASE_HISTORICAL_CURRENT_MONTH_HEAD_REQUIRED"}, nil
				}
				return nil, nil, err
			}
		}
		totalRows += len(records)
		raw, err := json.Marshal(records)
		if err != nil {
			return nil, nil, err
		}
		totalBytes += len(raw)
		if totalRows > 100000 || totalBytes > 64<<20 {
			return nil, []string{"DATABASE_HISTORICAL_BILLING_BOUND_EXCEEDED"}, nil
		}
		chunkStart, chunkEnd := month, month.AddDate(0, 1, 0)
		if start.After(chunkStart) {
			chunkStart = start
		}
		if end.Before(chunkEnd) {
			chunkEnd = end
		}
		proof := databaseInputObject(ref["source_proof"])
		coveredStart, sok := databaseUTC(proof, "period_start")
		coveredEnd, cok := databaseUTC(proof, "period_end")
		if !sok || !cok || coveredStart.After(chunkStart) || coveredEnd.Before(chunkEnd) || model.String(proof, "state") != "COMPLETE" && model.String(proof, "state") != "FINAL" {
			return nil, []string{"DATABASE_HISTORICAL_CURRENT_MONTH_HEAD_REQUIRED"}, nil
		}
		ids, reason := databaseCURClassHistory(records, members, chunkStart, chunkEnd)
		if reason != "" {
			return nil, []string{reason}, nil
		}
		full := databaseInputObject(ref)
		full["historical_configuration_record_ids"] = ids
		full["historical_configuration_basis"] = "NATIVE_CUR_WHOLE_HOURLY_BILLED_CLASS_CONTINUITY"
		full["historical_configuration_period"] = model.Document{"start": chunkStart.Format(time.RFC3339), "end": chunkEnd.Format(time.RFC3339)}
		refs = append(refs, full)
		compactRefs = append(compactRefs, databaseInputRef("AWS_CUR_HOURLY_CLASS_CONTINUITY", model.String(ref, "source_receipt_id"), model.String(ref, "source_version"), model.String(ref, "canonical_hash")))
	}
	period["source_refs"] = compactRefs
	input["history"] = period
	return refs, nil, nil
}

func (a *API) databaseFinancialInput(ctx context.Context, t *store.Tx, resource, canonical, input model.Document, now time.Time) ([]model.Document, []string, error) {
	rows, err := t.Query(ctx, `SELECT id FROM source_registrations WHERE tenant_id=$1 AND kind='AWS_CUR2' AND (document->'usage_account_ids' ? $2) ORDER BY id LIMIT 257`, t.Tenant, model.String(resource, "account_id"))
	if err != nil {
		return nil, nil, err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			break
		}
		ids = append(ids, id)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return nil, nil, err
	}
	if len(ids) > 256 {
		return nil, []string{"DATABASE_BILLING_SOURCE_LIMIT"}, nil
	}
	var registration, ref model.Document
	var records []model.Document
	reasons := []string{}
	for _, id := range ids {
		r, e := t.SourceGet(ctx, id)
		if e != nil {
			return nil, nil, e
		}
		if model.String(r, "status") != "HEALTHY" || !model.Bool(r, "enabled") {
			continue
		}
		if _, e = source.ParseRegistration(r); e != nil {
			continue
		}
		month := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
		var found model.Document
		var data []model.Document
		for n := 0; n < 2; n++ {
			f, d, e := a.databaseBillingMonth(ctx, t, id, month.AddDate(0, -n, 0))
			if e != nil {
				if errors.Is(e, pgx.ErrNoRows) || databaseDomainError(e) {
					continue
				}
				return nil, nil, e
			}
			proof := databaseInputObject(f["source_proof"])
			end, ok := databaseUTC(proof, "period_end")
			start, sok := databaseUTC(proof, "period_start")
			if ok && sok && !end.After(now) && now.Sub(end) <= 48*time.Hour && end.Sub(start) >= 24*time.Hour {
				found, data = f, d
				break
			}
		}
		if found == nil {
			continue
		}
		if ref != nil {
			return nil, []string{"DATABASE_BILLING_SOURCE_AMBIGUOUS"}, nil
		}
		ref, records, registration = found, data, r
	}
	if ref == nil {
		return nil, []string{"DATABASE_AUTHENTICATED_CUSTOMER_CUR_REQUIRED"}, nil
	}
	commitment, err := t.SourceReceiptGet(ctx, model.String(registration, "commitment_receipt_id"))
	if errors.Is(err, pgx.ErrNoRows) {
		return []model.Document{ref}, []string{"DATABASE_COMMITMENT_CURRENT_RECEIPT_REQUIRED"}, nil
	}
	if err != nil {
		return nil, nil, err
	}
	full, rs := databaseCURInput(resource, canonical, input, ref, registration, commitment, records, now)
	reasons = append(reasons, rs...)
	if full == nil {
		full = ref
	}
	historyRefs, historyReasons, err := a.databaseBillingHistory(ctx, t, canonical, input, ref, records)
	if err != nil {
		return nil, nil, err
	}
	reasons = append(reasons, historyReasons...)
	refs := []model.Document{full}
	for _, historical := range historyRefs {
		if model.String(historical, "source_receipt_id") == model.String(full, "source_receipt_id") {
			for _, key := range []string{"historical_configuration_record_ids", "historical_configuration_basis", "historical_configuration_period"} {
				full[key] = historical[key]
			}
		} else {
			refs = append(refs, historical)
		}
	}
	return refs, databaseSortedReasons(reasons), nil
}
func databaseDomainError(err error) bool {
	for _, prefix := range []string{"DATABASE_", "SOURCE_", "TRUSTED_", "ALLOCATION_"} {
		if strings.HasPrefix(err.Error(), prefix) {
			return true
		}
	}
	return false
}
