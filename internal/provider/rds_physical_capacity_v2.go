package provider

import (
	"encoding/json"
	"math/big"
	"strings"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

// This reviewed asset is an explicit allowlist, not a family-size formula.
// Values describe default class hardware; native regional orderability,
// configuration, storage limits and customer economics remain separate.
const rdsDocumentedPhysicalAssetSHA256 = "9b2efcc641706823f35c592b95046332f5f6f9f5423482cb0fd88f25cea7f8de"

const rdsDocumentedPhysicalAssetV2 = `{
  "schema_version": "2",
  "source_revision": "2026-10-21",
  "basis": "AWS_DOCUMENTED_PHYSICAL_CAPACITY_V2",
  "provenance": "REVIEWED_NORMALIZED_METADATA_NOT_FULL_HTTP_BODY",
  "sources": [
    {"url":"https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Concepts.DBInstanceClass.Summary.html","review_notes":"Literal class hardware rows supply CPU, RAM, processor generation and fixed network bandwidth. Optimized CPU configurations require separate runtime evidence."},
    {"url":"https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-optimized.html","review_notes":"Only sustained non-burst rows are included. I/O values use default bandwidth weighting; storage provisioning can impose smaller limits."}
  ],
  "entries": [
    {"class_id":"db.m8g.8xlarge","vcpu":"32","memory_bytes":"137438953472","cpu_model":"AWS Graviton4","architecture":"arm64","network_bytes_per_second":"1875000000","iops":"40000","throughput_bytes_per_second":"1250000000"},
    {"class_id":"db.m8g.12xlarge","vcpu":"48","memory_bytes":"206158430208","cpu_model":"AWS Graviton4","architecture":"arm64","network_bytes_per_second":"2812500000","iops":"60000","throughput_bytes_per_second":"1875000000"},
    {"class_id":"db.m8g.16xlarge","vcpu":"64","memory_bytes":"274877906944","cpu_model":"AWS Graviton4","architecture":"arm64","network_bytes_per_second":"3750000000","iops":"80000","throughput_bytes_per_second":"2500000000"},
    {"class_id":"db.r8g.8xlarge","vcpu":"32","memory_bytes":"274877906944","cpu_model":"AWS Graviton4","architecture":"arm64","network_bytes_per_second":"1875000000","iops":"40000","throughput_bytes_per_second":"1250000000"},
    {"class_id":"db.r8g.12xlarge","vcpu":"48","memory_bytes":"412316860416","cpu_model":"AWS Graviton4","architecture":"arm64","network_bytes_per_second":"2812500000","iops":"60000","throughput_bytes_per_second":"1875000000"},
    {"class_id":"db.r8g.16xlarge","vcpu":"64","memory_bytes":"549755813888","cpu_model":"AWS Graviton4","architecture":"arm64","network_bytes_per_second":"3750000000","iops":"80000","throughput_bytes_per_second":"2500000000"},
    {"class_id":"db.m8i.8xlarge","vcpu":"32","memory_bytes":"137438953472","cpu_model":"Intel Xeon 6","architecture":"x86_64","network_bytes_per_second":"1875000000","iops":"40000","throughput_bytes_per_second":"1250000000"},
    {"class_id":"db.m8i.12xlarge","vcpu":"48","memory_bytes":"206158430208","cpu_model":"Intel Xeon 6","architecture":"x86_64","network_bytes_per_second":"2812500000","iops":"60000","throughput_bytes_per_second":"1875000000"},
    {"class_id":"db.m8i.16xlarge","vcpu":"64","memory_bytes":"274877906944","cpu_model":"Intel Xeon 6","architecture":"x86_64","network_bytes_per_second":"3750000000","iops":"80000","throughput_bytes_per_second":"2500000000"},
    {"class_id":"db.r8i.8xlarge","vcpu":"32","memory_bytes":"274877906944","cpu_model":"Intel Xeon 6","architecture":"x86_64","network_bytes_per_second":"1875000000","iops":"40000","throughput_bytes_per_second":"1250000000"},
    {"class_id":"db.r8i.12xlarge","vcpu":"48","memory_bytes":"412316860416","cpu_model":"Intel Xeon 6","architecture":"x86_64","network_bytes_per_second":"2812500000","iops":"60000","throughput_bytes_per_second":"1875000000"},
    {"class_id":"db.r8i.16xlarge","vcpu":"64","memory_bytes":"549755813888","cpu_model":"Intel Xeon 6","architecture":"x86_64","network_bytes_per_second":"3750000000","iops":"80000","throughput_bytes_per_second":"2500000000"},
    {"class_id":"db.m7i.8xlarge","vcpu":"32","memory_bytes":"137438953472","cpu_model":"Intel Xeon Scalable generation 4","architecture":"x86_64","network_bytes_per_second":"1562500000","iops":"40000","throughput_bytes_per_second":"1250000000"},
    {"class_id":"db.m7i.12xlarge","vcpu":"48","memory_bytes":"206158430208","cpu_model":"Intel Xeon Scalable generation 4","architecture":"x86_64","network_bytes_per_second":"2343750000","iops":"60000","throughput_bytes_per_second":"1875000000"},
    {"class_id":"db.m7i.16xlarge","vcpu":"64","memory_bytes":"274877906944","cpu_model":"Intel Xeon Scalable generation 4","architecture":"x86_64","network_bytes_per_second":"3125000000","iops":"80000","throughput_bytes_per_second":"2500000000"},
    {"class_id":"db.r7i.8xlarge","vcpu":"32","memory_bytes":"274877906944","cpu_model":"Intel Xeon Scalable generation 4","architecture":"x86_64","network_bytes_per_second":"1562500000","iops":"40000","throughput_bytes_per_second":"1250000000"},
    {"class_id":"db.r7i.12xlarge","vcpu":"48","memory_bytes":"412316860416","cpu_model":"Intel Xeon Scalable generation 4","architecture":"x86_64","network_bytes_per_second":"2343750000","iops":"60000","throughput_bytes_per_second":"1875000000"},
    {"class_id":"db.r7i.16xlarge","vcpu":"64","memory_bytes":"549755813888","cpu_model":"Intel Xeon Scalable generation 4","architecture":"x86_64","network_bytes_per_second":"3125000000","iops":"80000","throughput_bytes_per_second":"2500000000"}
  ]
}
`

func RDSDocumentedPhysicalCapacityAssetV2() []byte { return []byte(rdsDocumentedPhysicalAssetV2) }

// RDSDocumentedCapacityAsset resolves immutable supported revisions. Historical
// callers keep their exact V1 asset instead of being silently upgraded.
func RDSDocumentedCapacityAsset(assetSHA string) ([]byte, error) {
	switch assetSHA {
	case rdsDocumentedIOAssetSHA256:
		return RDSDocumentedIOBaselineAsset(), nil
	case rdsDocumentedPhysicalAssetSHA256:
		return RDSDocumentedPhysicalCapacityAssetV2(), nil
	default:
		return nil, ErrRDSRead
	}
}

func RDSDocumentedCapacity(class, assetSHA string) (model.Document, error) {
	if assetSHA == rdsDocumentedIOAssetSHA256 {
		return RDSDocumentedIOBaseline(class)
	}
	if assetSHA != rdsDocumentedPhysicalAssetSHA256 {
		return nil, ErrRDSRead
	}
	return rdsDocumentedPhysicalCapacity(RDSDocumentedPhysicalCapacityAssetV2(), class)
}

func rdsDocumentedPhysicalCapacity(raw []byte, class string) (model.Document, error) {
	if rdsSHA(raw) != rdsDocumentedPhysicalAssetSHA256 {
		return nil, ErrRDSRead
	}
	var asset struct {
		Schema   string `json:"schema_version"`
		Revision string `json:"source_revision"`
		Basis    string `json:"basis"`
		Sources  []struct {
			URL string `json:"url"`
		} `json:"sources"`
		Entries []model.Document `json:"entries"`
	}
	if rdsJSON(raw, &asset) != nil || asset.Schema != "2" || asset.Revision != "2026-10-21" || asset.Basis != "AWS_DOCUMENTED_PHYSICAL_CAPACITY_V2" || len(asset.Sources) != 2 || len(asset.Entries) != 18 {
		return nil, ErrRDSRead
	}
	for _, row := range asset.Entries {
		if model.String(row, "class_id") == class {
			row["basis"] = asset.Basis
			row["source_revision"] = asset.Revision
			row["source_excerpt_sha256"] = rdsDocumentedPhysicalAssetSHA256
			row["source_urls"] = []string{asset.Sources[0].URL, asset.Sources[1].URL}
			row["bandwidth_basis"] = "DEFAULT_NON_BURST"
			return row, nil
		}
	}
	return nil, nil
}

// Native values must agree with reviewed default hardware before absent fields
// can be filled. An unrecognised explicit native value is not missing evidence.
func rdsMergeDocumentedPhysical(native, documented model.Document) (model.Document, bool) {
	out := model.Document{}
	for k, v := range native {
		out[k] = v
	}
	for _, key := range []string{"vcpu", "memory_bytes", "network_bytes_per_second"} {
		if value := native[key]; value != nil {
			encoded, _ := json.Marshal(value)
			got, ok := new(big.Rat).SetString(strings.Trim(string(encoded), "\""))
			want, valid := new(big.Rat).SetString(model.String(documented, key))
			if !ok || !valid || got.Cmp(want) != 0 {
				return nil, false
			}
		} else {
			v, ok := rdsScaled(model.String(documented, key), 1)
			if !ok {
				return nil, false
			}
			out[key] = v
		}
	}
	if a := model.String(native, "architecture"); a != "" && a != model.String(documented, "architecture") {
		return nil, false
	}
	if native["architecture"] == nil {
		out["architecture"] = documented["architecture"]
		out["architecture_basis"] = documented["basis"]
	}
	if native["cpu_model"] == nil {
		out["cpu_model"] = documented["cpu_model"]
	}
	return out, true
}

func rdsDocumentedNativeFields(a map[string]string, documented model.Document) (model.Document, bool) {
	fields := model.Document{}
	if value := a["vcpu"]; value != "" {
		n, ok := rdsScaled(value, 1)
		if !ok {
			return nil, false
		}
		fields["vcpu"] = n
	}
	if value := a["memory"]; value != "" {
		m := rdsMemory.FindStringSubmatch(value)
		if len(m) != 3 {
			return nil, false
		}
		factor := int64(1 << 30)
		if m[2] == "TiB" {
			factor = 1 << 40
		}
		n, ok := rdsScaled(m[1], factor)
		if !ok {
			return nil, false
		}
		fields["memory_bytes"] = n
	}
	if value := a["networkPerformance"]; value != "" {
		m := rdsNetwork.FindStringSubmatch(value)
		if len(m) != 2 {
			return nil, false
		}
		n, ok := rdsScaled(m[1], 1000000000/8)
		if !ok {
			return nil, false
		}
		fields["network_bytes_per_second"] = n
	}
	processor, arch := a["physicalProcessor"], a["processorArchitecture"]
	if processor != "" {
		fields["cpu_model"] = processor
		switch {
		case strings.HasPrefix(processor, "Intel Xeon"):
			fields["architecture"] = "x86_64"
		case strings.HasPrefix(processor, "AWS Graviton4"):
			fields["architecture"] = "arm64"
		default:
			return nil, false
		}
	}
	if arch == "x86_64" || arch == "arm64" {
		if known := model.String(fields, "architecture"); known != "" && known != arch {
			return nil, false
		}
		fields["architecture"] = arch
	} else if arch != "" && arch != "64-bit" {
		return nil, false
	}
	if fields["architecture"] != nil {
		fields["architecture_basis"] = "EXPLICIT_NATIVE_PROCESSOR_ARCHITECTURE_MAP_V1"
	}
	return rdsMergeDocumentedPhysical(fields, documented)
}
