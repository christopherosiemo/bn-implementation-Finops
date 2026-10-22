package provider

import (
	"context"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"net/url"
	"strconv"
)

// Values returned by DescribeDBParameters can be formulas. This reader retains
// them verbatim; it never silently resolves DBInstanceClassMemory or assumes
// that a pending/reboot value is already the effective server limit.
func (a *AWS) RDSParameters(ctx context.Context, s RDSScope, arn string) (RDSParameterEvidence, error) {
	var out RDSParameterEvidence
	r, e := newRDSRead(a, s)
	if e != nil {
		return out, e
	}
	if _, e = rdsARN(s, arn, "db"); e != nil {
		return out, e
	}
	instances, e := r.pages(ctx, "DescribeDBInstances", "DBInstances", arn, rdsInstance)
	if e != nil || len(instances) != 1 {
		return out, ErrRDSRead
	}
	out.Instance = instances[0]
	out.Parameters = []model.Document{}
	out.ConnectionCapacityStatus = "NATIVE_EFFECTIVE_CONNECTION_CAPACITY_UNAVAILABLE"
	type group struct{ name, action, status string }
	groups := []group{}
	for _, g := range out.Instance["parameter_groups"].([]model.Document) {
		groups = append(groups, group{model.String(g, "name"), "DescribeDBParameters", model.String(g, "apply_status")})
	}
	if id := model.String(out.Instance, "cluster_identifier"); id != "" {
		clusterARN := "arn:aws:rds:" + s.Region + ":" + s.AccountID + ":cluster:" + id
		rows, e := r.pages(ctx, "DescribeDBClusters", "DBClusters", clusterARN, rdsCluster)
		if e != nil || len(rows) != 1 {
			return out, ErrRDSRead
		}
		name := model.String(rows[0], "cluster_parameter_group")
		status := ""
		for _, m := range rows[0]["members"].([]model.Document) {
			if model.String(m, "identifier") == model.String(out.Instance, "identifier") {
				status = model.String(m, "parameter_group_status")
			}
		}
		if name != "" {
			groups = append(groups, group{name, "DescribeDBClusterParameters", status})
		}
	}
	allApplied := len(groups) > 0
	literal := ""
	conflict := false
	for _, g := range groups {
		if !rdsIdentifier.MatchString(g.name) {
			return out, ErrRDSRead
		}
		if g.status != "in-sync" {
			allApplied = false
		}
		token := ""
		seen := map[string]bool{}
		names := map[string]bool{}
		for page := 0; page < 100; page++ {
			key := "DBParameterGroupName"
			if g.action == "DescribeDBClusterParameters" {
				key = "DBClusterParameterGroupName"
			}
			v := url.Values{key: {g.name}, "MaxRecords": {"100"}}
			if token != "" {
				v.Set("Marker", token)
			}
			raw, e := r.query(ctx, "rds", g.action, v)
			if e != nil {
				return RDSParameterEvidence{}, e
			}
			result, e := rdsTree(raw, g.action, "Parameters")
			if e != nil {
				return RDSParameterEvidence{}, e
			}
			for _, n := range result.list("Parameters") {
				name := n.value("ParameterName")
				if name == "" || names[name] {
					return RDSParameterEvidence{}, ErrRDSRead
				}
				names[name] = true
				if name != "max_connections" {
					continue
				}
				row, e := rdsFields(n, map[string]string{"parameter_name": "ParameterName", "value": "ParameterValue", "source": "Source", "apply_type": "ApplyType", "apply_method": "ApplyMethod", "data_type": "DataType", "allowed_values": "AllowedValues"}, map[string]string{"is_modifiable": "IsModifiable"}, nil)
				if e != nil {
					return RDSParameterEvidence{}, e
				}
				row["group"] = g.name
				row["group_apply_status"] = g.status
				row["action"] = g.action
				row["raw_page_sha256"] = rdsSHA(raw)
				out.Parameters = append(out.Parameters, row)
				value := model.String(row, "value")
				number, e := strconv.ParseInt(value, 10, 64)
				if e != nil || number <= 0 || strconv.FormatInt(number, 10) != value {
					conflict = true
				} else if literal != "" && literal != value {
					conflict = true
				} else {
					literal = value
				}
			}
			token = result.value("Marker")
			if token == "" {
				break
			}
			if len(token) > 4096 || seen[token] || page == 99 {
				return RDSParameterEvidence{}, ErrRDSRead
			}
			seen[token] = true
		}
	}
	if allApplied && !conflict && literal != "" {
		out.ConnectionCapacity = &literal
		out.ConnectionCapacityStatus = "EXPLICIT_NATIVE_PARAMETER_LITERAL_ALL_GROUPS_IN_SYNC"
	}
	out.RDSReadEvidence = r.evidence()
	return out, nil
}
