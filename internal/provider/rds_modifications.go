package provider

import (
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"math/big"
	"regexp"
	"strconv"
	"strings"
)

var rdsModificationDecimal = regexp.MustCompile(`^(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]{1,3})?$`)

// This is a native read constraint projection, never an authorization to apply
// a class or storage change. Ranges retain their native Step; maxima alone do
// not establish an admissible modification or provisioned hardware capacity.
func rdsModificationConstraints(raw []byte, arn string) (model.Document, error) {
	root, e := rdsTree(raw, "DescribeValidDBInstanceModifications", "ValidDBInstanceModificationsMessage")
	if e != nil {
		return nil, e
	}
	message := root.get("ValidDBInstanceModificationsMessage")
	if message == nil {
		return nil, ErrRDSRead
	}
	// Message fields are singleton even though their children may be lists.
	seen := map[string]bool{}
	for _, n := range message.children {
		if seen[n.name] {
			return nil, ErrRDSRead
		}
		seen[n.name] = true
	}
	out, e := rdsFields(message, nil, map[string]string{"supports_dedicated_log_volume": "SupportsDedicatedLogVolume"}, nil)
	if e != nil {
		return nil, e
	}
	out["resource_arn"] = arn
	out["raw_page_sha256"] = rdsSHA(raw)
	out["basis"] = "NATIVE_DESCRIBE_VALID_DB_INSTANCE_MODIFICATIONS_CURRENT_INSTANCE_ONLY"
	out["native_message"] = rdsNormalizedNode(message)
	var storage []model.Document
	if message.get("Storage") != nil {
		storage = []model.Document{}
	}
	types := map[string]bool{}
	for _, n := range message.list("Storage") {
		row, e := rdsFields(n, map[string]string{"storage_type": "StorageType"}, map[string]string{"supports_storage_autoscaling": "SupportsStorageAutoscaling"}, nil)
		if e != nil {
			return nil, e
		}
		kind := model.String(row, "storage_type")
		if kind == "" || types[kind] {
			return nil, ErrRDSRead
		}
		types[kind] = true
		for _, p := range [][2]string{{"storage_size", "StorageSize"}, {"provisioned_iops", "ProvisionedIops"}, {"provisioned_storage_throughput", "ProvisionedStorageThroughput"}} {
			ranges, e := rdsModificationRanges(n, p[1], false)
			if e != nil {
				return nil, e
			}
			row[p[0]] = ranges
		}
		for _, p := range [][2]string{{"iops_to_storage_ratio", "IopsToStorageRatio"}, {"storage_throughput_to_iops_ratio", "StorageThroughputToIopsRatio"}} {
			ranges, e := rdsModificationRanges(n, p[1], true)
			if e != nil {
				return nil, e
			}
			row[p[0]] = ranges
		}
		row["native_fields"] = rdsNormalizedNode(n)
		storage = append(storage, row)
	}
	out["storage"] = storage
	var features []model.Document
	if message.get("ValidProcessorFeatures") != nil {
		features = []model.Document{}
	}
	names := map[string]bool{}
	for _, n := range message.list("ValidProcessorFeatures") {
		row, e := rdsFields(n, map[string]string{"name": "Name", "default_value": "DefaultValue", "allowed_values": "AllowedValues"}, nil, nil)
		if e != nil {
			return nil, e
		}
		name := model.String(row, "name")
		if name == "" || names[name] {
			return nil, ErrRDSRead
		}
		names[name] = true
		features = append(features, row)
	}
	out["valid_processor_features"] = features
	if additional := message.get("AdditionalStorage"); additional != nil {
		out["additional_storage"] = rdsNormalizedNode(additional)
	} else {
		out["additional_storage"] = nil
	}
	return out, nil
}
func rdsModificationRanges(parent *rdsNode, name string, decimal bool) ([]model.Document, error) {
	var out []model.Document
	if parent.get(name) == nil {
		return out, nil
	}
	out = []model.Document{}
	if len(parent.list(name)) > 128 {
		return nil, ErrRDSRead
	}
	for _, n := range parent.list(name) {
		row := model.Document{"from": nil, "to": nil}
		limits := map[string]*big.Rat{}
		for _, p := range [][2]string{{"from", "From"}, {"to", "To"}} {
			if n.get(p[1]) == nil {
				continue
			}
			raw := n.value(p[1])
			if len(raw) > 64 || !rdsModificationDecimal.MatchString(raw) {
				return nil, ErrRDSRead
			}
			number, ok := new(big.Rat).SetString(raw)
			if !ok || number.Sign() < 0 {
				return nil, ErrRDSRead
			}
			limits[p[0]] = number
			if decimal {
				row[p[0]] = raw
			} else {
				v, e := strconv.ParseInt(raw, 10, 64)
				if e != nil || v < 0 {
					return nil, ErrRDSRead
				}
				row[p[0]] = v
			}
		}
		if limits["from"] != nil && limits["to"] != nil && limits["from"].Cmp(limits["to"]) > 0 {
			return nil, ErrRDSRead
		}
		if !decimal {
			row["step"] = nil
			if n.get("Step") != nil {
				v, e := strconv.ParseInt(n.value("Step"), 10, 64)
				if e != nil || v <= 0 {
					return nil, ErrRDSRead
				}
				row["step"] = v
			}
		}
		out = append(out, row)
	}
	return out, nil
}

// Preserve the complete ordered native message, including unprojected fields,
// without inventing a scalar type or dropping repeated native list members.
func rdsNormalizedNode(n *rdsNode) model.Document {
	children := []model.Document{}
	for _, child := range n.children {
		children = append(children, rdsNormalizedNode(child))
	}
	return model.Document{"name": n.name, "value": strings.TrimSpace(n.text), "children": children}
}
