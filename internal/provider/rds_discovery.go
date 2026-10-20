package provider

import (
	"bytes"
	"context"
	"encoding/xml"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"io"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

type rdsNode struct {
	name, text string
	children   []*rdsNode
}

func (n *rdsNode) get(name string) *rdsNode {
	for _, c := range n.children {
		if c.name == name {
			return c
		}
	}
	return nil
}
func (n *rdsNode) value(name string) string {
	if n == nil {
		return ""
	}
	v := n.get(name)
	if v == nil {
		return ""
	}
	return strings.TrimSpace(v.text)
}
func (n *rdsNode) list(name string) []*rdsNode {
	if n == nil {
		return nil
	}
	v := n.get(name)
	if v == nil {
		return nil
	}
	return v.children
}

var rdsCollections = map[string]bool{"DBInstances": true, "DBClusters": true, "ReservedDBInstances": true, "OrderableDBInstanceOptions": true, "DBClusterMembers": true, "AvailabilityZones": true, "SupportedEngineModes": true, "ReadReplicaDBInstanceIdentifiers": true, "ReadReplicaIdentifiers": true, "TagList": true, "RecurringCharges": true, "VpcSecurityGroups": true, "DBSecurityGroups": true, "DBParameterGroups": true, "DBClusterParameterGroups": true, "Subnets": true, "OptionGroupMemberships": true, "DomainMemberships": true, "ProcessorFeatures": true, "AvailableProcessorFeatures": true, "SupportedNetworkTypes": true, "AssociatedRoles": true, "StatusInfos": true, "EnabledCloudwatchLogsExports": true, "DBSystemId": true, "Parameters": true, "ValidDBInstanceModificationsMessage": true, "Datapoints": true, "SupportedCharacterSets": true, "Storage": true, "StorageSize": true, "ProvisionedIops": true, "ProvisionedStorageThroughput": true, "IopsToStorageRatio": true, "StorageThroughputToIopsRatio": true, "ValidProcessorFeatures": true}

func rdsTree(raw []byte, action, collection string) (*rdsNode, error) {
	if len(raw) > rdsPageLimit {
		return nil, ErrRDSRead
	}
	decoder := xml.NewDecoder(bytes.NewReader(raw))
	stack := []*rdsNode{}
	var root *rdsNode
	for {
		token, e := decoder.Token()
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, ErrRDSRead
		}
		switch t := token.(type) {
		case xml.StartElement:
			n := &rdsNode{name: t.Name.Local}
			if len(stack) == 0 {
				if root != nil || n.name != action+"Response" {
					return nil, ErrRDSRead
				}
				root = n
			} else {
				parent := stack[len(stack)-1]
				if !rdsCollections[parent.name] && parent.get(n.name) != nil {
					return nil, ErrRDSRead
				}
				parent.children = append(parent.children, n)
			}
			stack = append(stack, n)
			if len(stack) > 64 {
				return nil, ErrRDSRead
			}
		case xml.CharData:
			if len(stack) == 0 {
				if strings.TrimSpace(string(t)) != "" {
					return nil, ErrRDSRead
				}
			} else {
				stack[len(stack)-1].text += string(t)
			}
		case xml.EndElement:
			if len(stack) == 0 {
				return nil, ErrRDSRead
			}
			stack = stack[:len(stack)-1]
		case xml.Directive:
			return nil, ErrRDSRead
		}
	}
	if root == nil {
		return nil, ErrRDSRead
	}
	result := root.get(action + "Result")
	if result == nil || collection != "" && result.get(collection) == nil {
		return nil, ErrRDSRead
	}
	return result, nil
}
func rdsFields(n *rdsNode, stringsMap, boolMap, intMap map[string]string) (model.Document, error) {
	out := model.Document{}
	for key, tag := range stringsMap {
		var v any
		if child := n.get(tag); child != nil {
			v = strings.TrimSpace(child.text)
		}
		out[key] = v
	}
	for key, tag := range boolMap {
		var v any
		if child := n.get(tag); child != nil {
			switch strings.TrimSpace(child.text) {
			case "true":
				v = true
			case "false":
				v = false
			default:
				return nil, ErrRDSRead
			}
		}
		out[key] = v
	}
	for key, tag := range intMap {
		var v any
		if child := n.get(tag); child != nil {
			raw := strings.TrimSpace(child.text)
			x, e := strconv.ParseInt(raw, 10, 64)
			if e != nil || x < 0 {
				return nil, ErrRDSRead
			}
			v = x
		}
		out[key] = v
	}
	return out, nil
}
func rdsStringList(n *rdsNode, name string) []string {
	var out []string
	if n.get(name) != nil {
		out = []string{}
	}
	for _, x := range n.list(name) {
		out = append(out, strings.TrimSpace(x.text))
	}
	return out
}
func rdsTags(n *rdsNode) (map[string]string, error) {
	out := map[string]string{}
	for _, v := range n.list("TagList") {
		key := v.value("Key")
		if key == "" {
			return nil, ErrRDSRead
		}
		if _, ok := out[key]; ok {
			return nil, ErrRDSRead
		}
		out[key] = v.value("Value")
	}
	return out, nil
}

// Absence is unknown; an explicit empty native structure is an observed empty
// set. Retain complete native child structures rather than treating an
// available instance/cluster status as proof that no modification is pending.
func rdsPendingValues(n *rdsNode) (model.Document, error) {
	v := n.get("PendingModifiedValues")
	if v == nil {
		return nil, nil
	}
	if strings.TrimSpace(v.text) != "" {
		return nil, ErrRDSRead
	}
	out := model.Document{}
	for _, child := range v.children {
		out[child.name] = rdsNormalizedNode(child)
	}
	return out, nil
}
func rdsInstance(n *rdsNode, s RDSScope, page string) (model.Document, error) {
	out, e := rdsFields(n, map[string]string{"arn": "DBInstanceArn", "identifier": "DBInstanceIdentifier", "resource_id": "DbiResourceId", "class": "DBInstanceClass", "engine": "Engine", "engine_version": "EngineVersion", "status": "DBInstanceStatus", "license_model": "LicenseModel", "cluster_identifier": "DBClusterIdentifier", "availability_zone": "AvailabilityZone", "secondary_availability_zone": "SecondaryAvailabilityZone", "storage_type": "StorageType", "preferred_backup_window": "PreferredBackupWindow", "preferred_maintenance_window": "PreferredMaintenanceWindow", "read_replica_source_identifier": "ReadReplicaSourceDBInstanceIdentifier", "instance_create_time": "InstanceCreateTime"}, map[string]string{"multi_az": "MultiAZ", "storage_encrypted": "StorageEncrypted", "publicly_accessible": "PubliclyAccessible", "deletion_protection": "DeletionProtection", "performance_insights_enabled": "PerformanceInsightsEnabled"}, map[string]string{"allocated_storage_gib": "AllocatedStorage", "max_allocated_storage_gib": "MaxAllocatedStorage", "iops": "Iops", "storage_throughput_mibps": "StorageThroughput", "backup_retention_days": "BackupRetentionPeriod"})
	if e != nil {
		return nil, e
	}
	id, e := rdsARN(s, model.String(out, "arn"), "db")
	if e != nil || id != model.String(out, "identifier") || model.String(out, "engine") == "" || model.String(out, "resource_id") == "" || model.String(out, "class") == "" {
		return nil, ErrRDSRead
	}
	out["provider"] = "AWS"
	out["resource_type"] = "RDS_INSTANCE"
	out["provider_resource_id"] = out["arn"]
	out["account_id"] = s.AccountID
	out["region"] = s.Region
	out["raw_page_sha256"] = page
	out["read_replica_identifiers"] = rdsStringList(n, "ReadReplicaDBInstanceIdentifiers")
	groups := []model.Document{}
	for _, v := range n.list("DBParameterGroups") {
		if v.value("DBParameterGroupName") == "" || v.value("ParameterApplyStatus") == "" {
			return nil, ErrRDSRead
		}
		groups = append(groups, model.Document{"name": v.value("DBParameterGroupName"), "apply_status": v.value("ParameterApplyStatus")})
	}
	out["parameter_groups"] = groups
	features := []model.Document{}
	for _, v := range n.list("ProcessorFeatures") {
		features = append(features, model.Document{"name": v.value("Name"), "value": v.value("Value")})
	}
	out["processor_features"] = features
	pending, e := rdsPendingValues(n)
	if e != nil {
		return nil, e
	}
	out["pending_modified_values"] = pending
	tags, e := rdsTags(n)
	if e != nil {
		return nil, e
	}
	out["tags"] = tags
	return out, nil
}
func rdsCluster(n *rdsNode, s RDSScope, page string) (model.Document, error) {
	out, e := rdsFields(n, map[string]string{"arn": "DBClusterArn", "identifier": "DBClusterIdentifier", "resource_id": "DbClusterResourceId", "engine": "Engine", "engine_version": "EngineVersion", "engine_mode": "EngineMode", "status": "Status", "class": "DBClusterInstanceClass", "storage_type": "StorageType", "global_cluster_identifier": "GlobalClusterIdentifier", "cluster_parameter_group": "DBClusterParameterGroup", "preferred_backup_window": "PreferredBackupWindow", "preferred_maintenance_window": "PreferredMaintenanceWindow"}, map[string]string{"storage_encrypted": "StorageEncrypted", "multi_az": "MultiAZ", "deletion_protection": "DeletionProtection"}, map[string]string{"allocated_storage_gib": "AllocatedStorage", "iops": "Iops", "storage_throughput_mibps": "StorageThroughput", "backup_retention_days": "BackupRetentionPeriod"})
	if e != nil {
		return nil, e
	}
	id, e := rdsARN(s, model.String(out, "arn"), "cluster")
	if e != nil || id != model.String(out, "identifier") || model.String(out, "engine") == "" || model.String(out, "resource_id") == "" {
		return nil, ErrRDSRead
	}
	members := []model.Document{}
	seen := map[string]bool{}
	for _, v := range n.list("DBClusterMembers") {
		m, e := rdsFields(v, map[string]string{"identifier": "DBInstanceIdentifier", "parameter_group_status": "DBClusterParameterGroupStatus"}, map[string]string{"is_writer": "IsClusterWriter"}, map[string]string{"promotion_tier": "PromotionTier"})
		id := model.String(m, "identifier")
		if e != nil || !rdsIdentifier.MatchString(id) || seen[id] {
			return nil, ErrRDSRead
		}
		seen[id] = true
		members = append(members, m)
	}
	out["members"] = members
	out["serverless_v2"] = nil
	if v := n.get("ServerlessV2ScalingConfiguration"); v != nil {
		x, e := rdsFields(v, map[string]string{"min_acu": "MinCapacity", "max_acu": "MaxCapacity"}, nil, map[string]string{"auto_pause_seconds": "SecondsUntilAutoPause"})
		if e != nil {
			return nil, e
		}
		out["serverless_v2"] = x
	}
	out["provider"] = "AWS"
	out["resource_type"] = "RDS_CLUSTER"
	out["provider_resource_id"] = out["arn"]
	out["account_id"] = s.AccountID
	out["region"] = s.Region
	out["availability_zones"] = rdsStringList(n, "AvailabilityZones")
	out["raw_page_sha256"] = page
	pending, e := rdsPendingValues(n)
	if e != nil {
		return nil, e
	}
	out["pending_modified_values"] = pending
	tags, e := rdsTags(n)
	if e != nil {
		return nil, e
	}
	out["tags"] = tags
	return out, nil
}
func rdsReserved(n *rdsNode, s RDSScope, page string) (model.Document, error) {
	out, e := rdsFields(n, map[string]string{"arn": "ReservedDBInstanceArn", "identifier": "ReservedDBInstanceId", "offering_id": "ReservedDBInstancesOfferingId", "class": "DBInstanceClass", "product_description": "ProductDescription", "state": "State", "start_time": "StartTime", "offering_type": "OfferingType", "fixed_price": "FixedPrice", "usage_price": "UsagePrice", "currency": "CurrencyCode"}, map[string]string{"multi_az": "MultiAZ"}, map[string]string{"duration_seconds": "Duration", "count": "DBInstanceCount"})
	if e != nil {
		return nil, e
	}
	id, e := rdsARN(s, model.String(out, "arn"), "ri")
	if e != nil || id != model.String(out, "identifier") {
		return nil, ErrRDSRead
	}
	charges := []model.Document{}
	for _, v := range n.list("RecurringCharges") {
		charges = append(charges, model.Document{"amount": v.value("RecurringChargeAmount"), "frequency": v.value("RecurringChargeFrequency")})
	}
	out["recurring_charges"] = charges
	out["raw_page_sha256"] = page
	out["scope_basis"] = "ACCOUNT_REGION_NATIVE_RDS_RESERVATION_INVENTORY"
	return out, nil
}
func (r *rdsRead) pages(ctx context.Context, action, collection, selector string, parse func(*rdsNode, RDSScope, string) (model.Document, error)) ([]model.Document, error) {
	rows := []model.Document{}
	tokens := map[string]bool{}
	seen := map[string]bool{}
	token := ""
	for page := 0; page < 100; page++ {
		v := url.Values{"MaxRecords": {"100"}}
		if selector != "" {
			key := "DBInstanceIdentifier"
			if action == "DescribeDBClusters" {
				key = "DBClusterIdentifier"
			}
			v.Set(key, selector)
		}
		if token != "" {
			v.Set("Marker", token)
		}
		raw, e := r.query(ctx, "rds", action, v)
		if e != nil {
			return nil, e
		}
		result, e := rdsTree(raw, action, collection)
		if e != nil {
			return nil, e
		}
		for _, n := range result.list(collection) {
			row, e := parse(n, r.scope, rdsSHA(raw))
			if e != nil {
				return nil, e
			}
			id := model.String(row, "arn")
			if seen[id] || selector != "" && selector != id {
				return nil, ErrRDSRead
			}
			seen[id] = true
			rows = append(rows, row)
			if len(rows) > 2048 {
				return nil, ErrRDSRead
			}
		}
		token = result.value("Marker")
		if token == "" {
			sort.Slice(rows, func(i, j int) bool { return model.String(rows[i], "arn") < model.String(rows[j], "arn") })
			return rows, nil
		}
		if len(token) > 4096 || tokens[token] {
			return nil, ErrRDSRead
		}
		tokens[token] = true
	}
	return nil, ErrRDSRead
}
func (a *AWS) RDSDiscover(ctx context.Context, s RDSScope) (RDSDiscoveryEvidence, error) {
	var out RDSDiscoveryEvidence
	r, e := newRDSRead(a, s)
	if e != nil {
		return out, e
	}
	out.Instances, e = r.pages(ctx, "DescribeDBInstances", "DBInstances", "", rdsInstance)
	if e != nil {
		return RDSDiscoveryEvidence{}, e
	}
	out.Clusters, e = r.pages(ctx, "DescribeDBClusters", "DBClusters", "", rdsCluster)
	if e != nil {
		return RDSDiscoveryEvidence{}, e
	}
	out.ReservedInstances, e = r.pages(ctx, "DescribeReservedDBInstances", "ReservedDBInstances", "", rdsReserved)
	if e != nil {
		return RDSDiscoveryEvidence{}, e
	}
	// Reciprocal observed membership must agree. This is a non-atomic point read,
	// not evidence of historic writer ownership or replica health.
	instances := map[string]model.Document{}
	for _, v := range out.Instances {
		instances[model.String(v, "identifier")] = v
	}
	for _, c := range out.Clusters {
		for _, m := range c["members"].([]model.Document) {
			v, ok := instances[model.String(m, "identifier")]
			if !ok || model.String(v, "cluster_identifier") != model.String(c, "identifier") || model.String(v, "engine") != model.String(c, "engine") {
				return RDSDiscoveryEvidence{}, ErrRDSRead
			}
		}
	}
	out.RDSReadEvidence = r.evidence()
	return out, nil
}

type RDSCommitmentExposure struct {
	RDSReadEvidence
	Plans []model.Document `json:"plans"`
}

// Optional separate commissioned read. A refusal never becomes an empty
// complete portfolio, and this is not complete payer/linked-account coverage.
func (a *AWS) RDSDatabaseSavingsPlans(ctx context.Context, s RDSScope) (RDSCommitmentExposure, error) {
	var out RDSCommitmentExposure
	r, e := newRDSRead(a, s)
	if e != nil {
		return out, e
	}
	out.Plans = []model.Document{}
	tokens := map[string]bool{}
	seen := map[string]bool{}
	token := ""
	for page := 0; page < 100; page++ {
		p := model.Document{"maxResults": 1000, "filters": []model.Document{{"name": "savings-plan-type", "values": []string{"Database"}}}}
		if token != "" {
			p["nextToken"] = token
		}
		raw, e := r.jsonRead(ctx, "savingsplans", "DescribeSavingsPlans", p)
		if e != nil {
			return RDSCommitmentExposure{}, e
		}
		var response struct {
			Plans []model.Document `json:"savingsPlans"`
			Next  *string          `json:"nextToken"`
		}
		if rdsJSON(raw, &response) != nil || response.Plans == nil {
			return RDSCommitmentExposure{}, ErrRDSRead
		}
		for _, plan := range response.Plans {
			arn := model.String(plan, "savingsPlanArn")
			if !strings.HasPrefix(arn, "arn:aws:savingsplans::"+s.AccountID+":savingsplan/") || model.String(plan, "savingsPlanType") != "Database" || seen[arn] {
				return RDSCommitmentExposure{}, ErrRDSRead
			}
			seen[arn] = true
			plan["raw_page_sha256"] = rdsSHA(raw)
			out.Plans = append(out.Plans, plan)
			if len(out.Plans) > 4096 {
				return RDSCommitmentExposure{}, ErrRDSRead
			}
		}
		if response.Next == nil || *response.Next == "" {
			out.RDSReadEvidence = r.evidence()
			return out, nil
		}
		token = *response.Next
		if len(token) > 1024 || tokens[token] {
			return RDSCommitmentExposure{}, ErrRDSRead
		}
		tokens[token] = true
	}
	return RDSCommitmentExposure{}, ErrRDSRead
}
