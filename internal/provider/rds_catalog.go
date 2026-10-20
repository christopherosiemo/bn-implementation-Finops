package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"io"
	"math/big"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

func rdsJSON(raw []byte, out any) error {
	// Reject duplicate JSON keys before interpreting signed native responses.
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var walk func() error
	walk = func() error {
		token, e := d.Token()
		if e != nil {
			return e
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		if delim == '{' {
			seen := map[string]bool{}
			for d.More() {
				key, e := d.Token()
				if e != nil {
					return e
				}
				s, ok := key.(string)
				if !ok || seen[s] {
					return ErrRDSRead
				}
				seen[s] = true
				if e = walk(); e != nil {
					return e
				}
			}
		} else if delim == '[' {
			for d.More() {
				if e := walk(); e != nil {
					return e
				}
			}
		} else {
			return ErrRDSRead
		}
		_, e = d.Token()
		return e
	}
	if e := walk(); e != nil {
		return ErrRDSRead
	}
	if d.Decode(new(any)) != io.EOF {
		return ErrRDSRead
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return ErrRDSRead
	}
	return nil
}
func rdsOption(n *rdsNode, page string) (model.Document, error) {
	out, e := rdsFields(n, map[string]string{"engine": "Engine", "engine_version": "EngineVersion", "class": "DBInstanceClass", "license_model": "LicenseModel", "storage_type": "StorageType", "availability_zone_group": "AvailabilityZoneGroup", "min_iops_per_gib": "MinIopsPerGib", "max_iops_per_gib": "MaxIopsPerGib"}, map[string]string{"vpc": "Vpc", "multi_az_capable": "MultiAZCapable", "read_replica_capable": "ReadReplicaCapable", "supports_storage_encryption": "SupportsStorageEncryption", "supports_storage_autoscaling": "SupportsStorageAutoscaling", "supports_storage_throughput": "SupportsStorageThroughput", "supports_iops": "SupportsIops", "supports_clusters": "SupportsClusters"}, map[string]string{"min_storage_gib": "MinStorageSize", "max_storage_gib": "MaxStorageSize", "min_iops": "MinIopsPerDbInstance", "max_iops": "MaxIopsPerDbInstance", "min_throughput_mibps": "MinStorageThroughputPerDbInstance", "max_throughput_mibps": "MaxStorageThroughputPerDbInstance"})
	if e != nil {
		return nil, e
	}
	zones := []string{}
	for _, z := range n.list("AvailabilityZones") {
		zones = append(zones, z.value("Name"))
	}
	out["availability_zones"] = zones
	out["engine_modes"] = rdsStringList(n, "SupportedEngineModes")
	out["raw_page_sha256"] = page
	return out, nil
}

var rdsMemory = regexp.MustCompile("^([0-9]+(?:\\.[0-9]+)?) (GiB|TiB)$")
var rdsNetwork = regexp.MustCompile("^([0-9]+(?:\\.[0-9]+)?) Gigabit$")

func rdsScaled(s string, multiplier int64) (int64, bool) {
	n, ok := new(big.Rat).SetString(s)
	if !ok || n.Sign() <= 0 {
		return 0, false
	}
	n.Mul(n, big.NewRat(multiplier, 1))
	if !n.IsInt() || !n.Num().IsInt64() {
		return 0, false
	}
	return n.Num().Int64(), true
}
func (r *rdsRead) capacity(ctx context.Context, class string) (model.Document, error) {
	out := model.Document{"class": class, "vcpu": nil, "memory_bytes": nil, "cpu_model": nil, "architecture": nil, "network_bytes_per_second": nil, "status": "UNAVAILABLE", "basis": "NATIVE_RDS_ORDERABLE_OPTIONS_AND_PRICING_CATALOG_CAPACITY_ONLY", "pricing_skus": []string{}, "reason_codes": []string{"NATIVE_CATALOG_CAPACITY_UNAVAILABLE"}}
	baseline, e := RDSDocumentedIOBaseline(class)
	if e != nil {
		return nil, e
	}
	out["ebs_baseline"] = baseline
	if class == "db.serverless" {
		out["reason_codes"] = []string{"SERVERLESS_ACU_IS_NOT_FIXED_INSTANCE_CAPACITY"}
		return out, nil
	}
	token := ""
	seen := map[string]bool{}
	skus := map[string]bool{}
	var signature string
	var fields model.Document
	for page := 0; page < 10; page++ {
		p := model.Document{"ServiceCode": "AmazonRDS", "FormatVersion": "aws_v1", "MaxResults": 100, "Filters": []model.Document{{"Type": "TERM_MATCH", "Field": "regionCode", "Value": r.scope.Region}, {"Type": "TERM_MATCH", "Field": "instanceType", "Value": class}}}
		if token != "" {
			p["NextToken"] = token
		}
		raw, e := r.jsonRead(ctx, "pricing", "GetProducts", p)
		if e != nil {
			return nil, e
		}
		var response struct {
			Products []string `json:"PriceList"`
			Next     string   `json:"NextToken"`
		}
		if rdsJSON(raw, &response) != nil || response.Products == nil {
			return nil, ErrRDSRead
		}
		for _, encoded := range response.Products {
			var product struct {
				Product struct {
					SKU        string            `json:"sku"`
					Family     string            `json:"productFamily"`
					Attributes map[string]string `json:"attributes"`
				} `json:"product"`
			}
			if rdsJSON([]byte(encoded), &product) != nil {
				return nil, ErrRDSRead
			}
			x := product.Product
			a := x.Attributes
			if x.SKU == "" || skus[x.SKU] || a["regionCode"] != r.scope.Region || a["instanceType"] != class || a["servicecode"] != "AmazonRDS" {
				return nil, ErrRDSRead
			}
			skus[x.SKU] = true
			if len(skus) > 512 {
				return nil, ErrRDSRead
			}
			// Storage/IO product lines do not describe instance compute capacities.
			if x.Family != "Database Instance" {
				continue
			}
			vcpu, e := strconv.ParseInt(a["vcpu"], 10, 64)
			m := rdsMemory.FindStringSubmatch(a["memory"])
			if e != nil || vcpu <= 0 || len(m) != 3 {
				continue
			}
			factor := int64(1 << 30)
			if m[2] == "TiB" {
				factor = 1 << 40
			}
			memory, ok := rdsScaled(m[1], factor)
			if !ok {
				continue
			}
			var cpu, architecture, network any
			var architectureBasis any
			if a["physicalProcessor"] != "" {
				cpu = a["physicalProcessor"]
			}
			if a["processorArchitecture"] == "x86_64" || a["processorArchitecture"] == "arm64" {
				architecture = a["processorArchitecture"]
				architectureBasis = "PRICING_NATIVE_ARCHITECTURE"
			} else if processor := a["physicalProcessor"]; strings.HasPrefix(processor, "Intel Xeon") || strings.HasPrefix(processor, "AMD EPYC") {
				architecture = "x86_64"
				architectureBasis = "EXPLICIT_NATIVE_PROCESSOR_ARCHITECTURE_MAP_V1"
			} else if strings.HasPrefix(processor, "AWS Graviton") {
				architecture = "arm64"
				architectureBasis = "EXPLICIT_NATIVE_PROCESSOR_ARCHITECTURE_MAP_V1"
			}
			if x := rdsNetwork.FindStringSubmatch(a["networkPerformance"]); len(x) == 2 {
				if n, ok := rdsScaled(x[1], 1000000000/8); ok {
					network = n
				}
			}
			current := model.Document{"vcpu": vcpu, "memory_bytes": memory, "cpu_model": cpu, "architecture": architecture, "architecture_basis": architectureBasis, "network_bytes_per_second": network}
			b, _ := json.Marshal(current)
			if signature != "" && signature != string(b) {
				out["reason_codes"] = []string{"NATIVE_CATALOG_CAPACITY_CONFLICT"}
				out["pricing_skus"] = sortedRDSKeys(skus)
				return out, nil
			}
			signature = string(b)
			fields = current
		}
		if response.Next == "" {
			out["pricing_skus"] = sortedRDSKeys(skus)
			if fields != nil {
				for key, value := range fields {
					out[key] = value
				}
				out["status"] = "OBSERVED_CATALOG_CAPACITY"
				out["reason_codes"] = []string{}
			}
			return out, nil
		}
		token = response.Next
		if len(token) > 4096 || seen[token] {
			return nil, ErrRDSRead
		}
		seen[token] = true
	}
	return nil, ErrRDSRead
}
func sortedRDSKeys(m map[string]bool) []string {
	out := []string{}
	for key := range m {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}
func (a *AWS) RDSCatalog(ctx context.Context, s RDSScope, instanceARN string) (RDSCatalogEvidence, error) {
	var out RDSCatalogEvidence
	r, e := newRDSRead(a, s)
	if e != nil {
		return out, e
	}
	if _, e = rdsARN(s, instanceARN, "db"); e != nil {
		return out, e
	}
	rows, e := r.pages(ctx, "DescribeDBInstances", "DBInstances", instanceARN, rdsInstance)
	if e != nil || len(rows) != 1 {
		return out, ErrRDSRead
	}
	out.Instance = rows[0]
	engine, version, license := model.String(out.Instance, "engine"), model.String(out.Instance, "engine_version"), model.String(out.Instance, "license_model")
	if engine == "" || version == "" || license == "" {
		return out, ErrRDSRead
	}
	out.ModificationConstraintsStatus = "UNSUPPORTED_NATIVE_MODIFICATION_CONSTRAINTS"
	if strings.HasPrefix(engine, "aurora") {
		out.ModificationConstraintsStatus = "AURORA_INSTANCE_MODIFICATION_CONSTRAINTS_UNSUPPORTED"
	} else if engine == "postgres" || engine == "mysql" || engine == "mariadb" || strings.HasPrefix(engine, "oracle-") || strings.HasPrefix(engine, "sqlserver-") || strings.HasPrefix(engine, "db2-") {
		raw, err := r.query(ctx, "rds", "DescribeValidDBInstanceModifications", url.Values{"DBInstanceIdentifier": {instanceARN}})
		if err != nil {
			return RDSCatalogEvidence{}, err
		}
		out.ModificationConstraints, err = rdsModificationConstraints(raw, instanceARN)
		if err != nil {
			return RDSCatalogEvidence{}, err
		}
		out.ModificationConstraintsStatus = "OBSERVED_NATIVE_CURRENT_INSTANCE_CONSTRAINTS"
	}
	out.Options = []model.Document{}
	out.Capacities = []model.Document{}
	classes := map[string]bool{}
	keys := map[string]bool{}
	tokens := map[string]bool{}
	token := ""
	for page := 0; page < 100; page++ {
		v := url.Values{"Engine": {engine}, "EngineVersion": {version}, "LicenseModel": {license}, "MaxRecords": {"1000"}}
		if token != "" {
			v.Set("Marker", token)
		}
		raw, e := r.query(ctx, "rds", "DescribeOrderableDBInstanceOptions", v)
		if e != nil {
			return RDSCatalogEvidence{}, e
		}
		result, e := rdsTree(raw, "DescribeOrderableDBInstanceOptions", "OrderableDBInstanceOptions")
		if e != nil {
			return RDSCatalogEvidence{}, e
		}
		for _, n := range result.list("OrderableDBInstanceOptions") {
			option, e := rdsOption(n, rdsSHA(raw))
			class := model.String(option, "class")
			if e != nil || model.String(option, "engine") != engine || model.String(option, "engine_version") != version || model.String(option, "license_model") != license || !rdsClass.MatchString(class) && class != "db.serverless" {
				return RDSCatalogEvidence{}, ErrRDSRead
			}
			key := class + "\x00" + model.String(option, "storage_type") + "\x00" + model.String(option, "availability_zone_group") + "\x00"
			b, _ := json.Marshal(option["vpc"])
			key += string(b)
			if keys[key] {
				return RDSCatalogEvidence{}, ErrRDSRead
			}
			keys[key] = true
			classes[class] = true
			out.Options = append(out.Options, option)
			if len(out.Options) > 4096 || len(classes) > 64 {
				return RDSCatalogEvidence{}, ErrRDSRead
			}
		}
		token = result.value("Marker")
		if token == "" {
			break
		}
		if len(token) > 4096 || tokens[token] || page == 99 {
			return RDSCatalogEvidence{}, ErrRDSRead
		}
		tokens[token] = true
	}
	// The documentation asset is distinct from AWS API observations and is
	// retained verbatim in the same immutable catalogue archive.
	if e := r.retain("aws_documentation", "global", "ReviewedRDSNonBurstEBSBaselineV1", rdsDocumentedIOAssetSHA256, RDSDocumentedIOBaselineAsset()); e != nil {
		return RDSCatalogEvidence{}, e
	}
	for _, class := range sortedRDSKeys(classes) {
		capacity, e := r.capacity(ctx, class)
		if e != nil {
			return RDSCatalogEvidence{}, e
		}
		out.Capacities = append(out.Capacities, capacity)
	}
	out.RDSReadEvidence = r.evidence()
	return out, nil
}
