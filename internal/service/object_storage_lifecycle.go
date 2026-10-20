package service

import (
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"strings"
)

// Native filters must cover the complete assessed cohort. Partial membership,
// object tags absent from Inventory, and unsupported rules stay unknown.
func objectStorageRuleApplies(filter, selector, cohort model.Document) (bool, bool) {
	if len(filter) == 0 {
		return true, true
	}
	for k, v := range filter {
		if v == nil || v == "" {
			continue
		}
		switch k {
		case "Prefix", "ObjectSizeGreaterThan", "ObjectSizeLessThan":
		case "And":
			return objectStorageRuleApplies(storageObject(v), selector, cohort)
		default:
			return false, false
		}
	}
	if prefix := model.String(filter, "Prefix"); prefix != "" {
		scope := model.String(selector, "prefix")
		if strings.HasPrefix(scope, prefix) {
		} else if strings.HasPrefix(prefix, scope) {
			return false, false
		} else {
			return false, true
		}
	}
	bands := storageRows(cohort["size_bands"])
	for _, bound := range []struct {
		key     string
		greater bool
	}{{"ObjectSizeGreaterThan", true}, {"ObjectSizeLessThan", false}} {
		if filter[bound.key] == nil {
			continue
		}
		n, ok := databaseDecimal(filter[bound.key])
		if !ok {
			return false, false
		}
		allIn, allOut := true, true
		for _, b := range bands {
			lo, lok := databaseDecimal(b["min_bytes"])
			hi, hok := databaseDecimal(b["max_bytes"])
			if !lok || !hok {
				return false, false
			}
			inside, outside := lo.Cmp(n) > 0, hi.Cmp(n) <= 0
			if !bound.greater {
				inside, outside = hi.Cmp(n) < 0, lo.Cmp(n) >= 0
			}
			allIn = allIn && inside
			allOut = allOut && outside
		}
		if len(bands) == 0 {
			return false, false
		}
		if allOut {
			return false, true
		}
		if !allIn {
			return false, false
		}
	}
	return true, true
}
func objectStorageLifecycle(canonical, dataset, cohort model.Document) model.Document {
	out := model.Document{"state": "UNKNOWN", "already_targets": []string{}, "conflicts": nil, "archive_access_enabled": nil, "deep_archive_access_enabled": nil, "small_object_transition_allowed": false}
	configurations := storageObject(storageObject(canonical["configuration"])["configurations"])
	life := storageObject(configurations["lifecycle"])
	selector := storageObject(dataset["selector"])
	unknown := false
	targets := []string{}
	conflict := false
	switch model.String(life, "status") {
	case "ABSENT":
		out["state"], out["conflicts"] = "NONE", false
	case "OBSERVED":
		out["state"] = "KNOWN"
		value := storageObject(life["value"])
		for _, rule := range storageRows(value["Rules"]) {
			if model.String(rule, "Status") == "Disabled" {
				continue
			}
			if model.String(rule, "Status") != "Enabled" {
				unknown = true
				continue
			}
			filter := storageObject(rule["Filter"])
			if p := model.String(rule, "Prefix"); p != "" {
				if len(filter) > 0 {
					unknown = true
					continue
				}
				filter = model.Document{"Prefix": p}
			}
			applies, known := objectStorageRuleApplies(filter, selector, cohort)
			if !known {
				unknown = true
				continue
			}
			if !applies {
				continue
			}
			if rule["Expiration"] != nil {
				conflict = true
			}
			if model.String(cohort, "state") == "CURRENT" {
				for _, tr := range storageRows(rule["Transitions"]) {
					if target := objectStorageLifecycleClass(model.String(tr, "StorageClass")); target != "" {
						targets = append(targets, target)
					} else {
						unknown = true
					}
				}
			} else if model.String(cohort, "state") == "NONCURRENT" {
				if rule["NoncurrentVersionExpiration"] != nil {
					targets = append(targets, "NONCURRENT_POLICY_REVIEW")
				}
				for _, tr := range storageRows(rule["NoncurrentVersionTransitions"]) {
					if target := objectStorageLifecycleClass(model.String(tr, "StorageClass")); target != "" {
						targets = append(targets, target)
					} else {
						unknown = true
					}
				}
			} else if model.String(cohort, "state") == "MULTIPART" && rule["AbortIncompleteMultipartUpload"] != nil {
				targets = append(targets, "MULTIPART_POLICY_REVIEW")
			}
		}
		out["conflicts"] = conflict
	}
	it := storageObject(configurations["intelligent_tiering"])
	switch model.String(it, "status") {
	case "ABSENT":
		out["archive_access_enabled"], out["deep_archive_access_enabled"] = false, false
	case "OBSERVED":
		v := storageObject(it["value"])
		if v["complete"] == true {
			out["archive_access_enabled"], out["deep_archive_access_enabled"] = false, false
			for _, rule := range storageRows(v["Configurations"]) {
				if model.String(rule, "Status") == "Disabled" {
					continue
				}
				if model.String(rule, "Status") != "Enabled" {
					unknown = true
					continue
				}
				applies, known := objectStorageRuleApplies(storageObject(rule["Filter"]), selector, cohort)
				if !known {
					unknown = true
					continue
				}
				if !applies {
					continue
				}
				for _, tier := range storageRows(rule["Tierings"]) {
					switch model.String(tier, "AccessTier") {
					case "ARCHIVE_ACCESS":
						out["archive_access_enabled"] = true
					case "DEEP_ARCHIVE_ACCESS":
						out["deep_archive_access_enabled"] = true
					default:
						unknown = true
					}
				}
				if model.String(cohort, "source_class") == "INTELLIGENT_TIERING" {
					targets = append(targets, "INTELLIGENT_TIERING_POLICY_REVIEW")
				} else {
					conflict = true
				}
			}
		} else {
			unknown = true
		}
	default:
		unknown = true
	}
	if unknown {
		out["state"], out["conflicts"] = "UNKNOWN", nil
	} else if conflict {
		out["conflicts"] = true
	}
	out["already_targets"] = databaseSortedReasons(targets)
	return out
}
func objectStorageLifecycleClass(s string) string {
	switch s {
	case "STANDARD_IA", "ONEZONE_IA", "INTELLIGENT_TIERING":
		return s
	case "GLACIER_IR":
		return "GLACIER_INSTANT_RETRIEVAL"
	case "GLACIER":
		return "GLACIER_FLEXIBLE_RETRIEVAL"
	case "DEEP_ARCHIVE":
		return s
	}
	return ""
}
