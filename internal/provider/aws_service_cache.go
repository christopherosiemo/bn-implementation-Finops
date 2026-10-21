package provider

import (
	"context"
	"net/url"
	"strings"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/awsservice"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

func (i *serviceInventory) cache(ctx context.Context, c serviceCursor) (string, bool, error) {
	specs := []struct{ action, key, kind, id, arn, resource string }{{"DescribeReplicationGroups", "ReplicationGroups", "ELASTICACHE_REPLICATION_GROUP", "ReplicationGroupId", "ARN", "replicationgroup:"}, {"DescribeCacheClusters", "CacheClusters", "ELASTICACHE_CLUSTER", "CacheClusterId", "ARN", "cluster:"}, {"DescribeServerlessCaches", "ServerlessCaches", "ELASTICACHE_SERVERLESS_CACHE", "ServerlessCacheName", "ARN", "serverlesscache:"}}
	if c.Phase >= len(specs) {
		return "", false, awsservice.ErrEvidence
	}
	spec := specs[c.Phase]
	p := url.Values{"MaxRecords": {"20"}}
	tokenKey := "Marker"
	if c.Phase == 2 {
		p = url.Values{"MaxResults": {"5"}}
		tokenKey = "NextToken"
	}
	if c.Phase == 1 {
		p.Set("ShowCacheNodeInfo", "true")
	}
	if c.Token != "" {
		p.Set(tokenKey, c.Token)
	}
	page, e := i.r.query(ctx, "elasticache", spec.action, "2015-02-02", p)
	if e != nil {
		return "", false, e
	}
	if _, ok := page[spec.key]; !ok {
		return "", false, awsservice.ErrEvidence
	}
	for _, cfg := range serviceList(page[spec.key]) {
		id := model.String(cfg, spec.id)
		arn := model.String(cfg, spec.arn)
		if arn == "" {
			arn = "arn:aws:elasticache:" + i.out.Scope.Region + ":" + i.out.Scope.AccountID + ":" + spec.resource + id
		}
		if !i.accepts(arn) {
			// Replication-group scoped collections include their evidenced member clusters.
			if c.Phase != 1 {
				continue
			}
			rg := model.String(cfg, "ReplicationGroupId")
			if !i.selected["arn:aws:elasticache:"+i.out.Scope.Region+":"+i.out.Scope.AccountID+":replicationgroup:"+rg] {
				continue
			}
		}
		d, e := i.put(spec.kind, arn, id, cfg)
		if e != nil {
			return "", false, e
		}
		d["state"] = cfg["Status"]
		if state := cfg["CacheClusterStatus"]; state != nil {
			d["state"] = state
		}
		i.set(d, "node_capacity_status", "UNKNOWN_UNTIL_INDEPENDENT_NATIVE_CAPABILITY_EVIDENCE")
		if c.Phase == 2 {
			i.set(d, "capacity_model", "SERVERLESS_NATIVE_STORAGE_AND_ECPU_LIMITS")
		} else {
			i.set(d, "capacity_model", "PROVISIONED_NODE_TOPOLOGY")
		}
		i.queryOptional(ctx, d, "tags", "elasticache", "ListTagsForResource", "2015-02-02", url.Values{"ResourceName": {arn}})
		if c.Phase == 1 {
			if rg := model.String(cfg, "ReplicationGroupId"); rg != "" {
				serviceRel(d, "MEMBER_OF", "arn:aws:elasticache:"+i.out.Scope.Region+":"+i.out.Scope.AccountID+":replicationgroup:"+rg)
				i.set(d, "economic_role", "MEMBER_COST_NOT_ADDITIONAL_REPLICATION_GROUP_COST")
			}
			if subnet := model.String(cfg, "CacheSubnetGroupName"); subnet != "" {
				i.queryOptional(ctx, d, "subnet_group", "elasticache", "DescribeCacheSubnetGroups", "2015-02-02", url.Values{"CacheSubnetGroupName": {subnet}})
			}
			parameter := awsservice.Document(cfg["CacheParameterGroup"])
			if group := model.String(parameter, "CacheParameterGroupName"); group != "" {
				i.queryOptional(ctx, d, "parameter_group", "elasticache", "DescribeCacheParameterGroups", "2015-02-02", url.Values{"CacheParameterGroupName": {group}})
				parameters, err := i.cachePages(ctx, "DescribeCacheParameters", "Parameters", url.Values{"CacheParameterGroupName": {group}, "MaxRecords": {"100"}})
				i.set(d, "parameter_metadata", parameters)
				if err != nil {
					i.problem(d, "parameter_metadata", err)
				}
			}
			snapshots, err := i.cachePages(ctx, "DescribeSnapshots", "Snapshots", url.Values{"CacheClusterId": {id}, "MaxRecords": {"20"}})
			i.set(d, "snapshots", snapshots)
			if err != nil {
				i.problem(d, "snapshots", err)
			}
		}
		if c.Phase == 0 {
			for _, nodegroup := range serviceList(cfg["NodeGroups"]) {
				for _, member := range serviceList(nodegroup["NodeGroupMembers"]) {
					if cid := model.String(member, "CacheClusterId"); cid != "" {
						serviceRel(d, "CONTAINS", "arn:aws:elasticache:"+i.out.Scope.Region+":"+i.out.Scope.AccountID+":cluster:"+cid)
					}
				}
			}
			i.scaling(ctx, d, "elasticache", "replication-group/"+id)
		}
		if c.Phase == 2 {
			snapshots, err := i.cachePages(ctx, "DescribeServerlessCacheSnapshots", "ServerlessCacheSnapshots", url.Values{"ServerlessCacheName": {id}, "MaxResults": {"20"}})
			i.set(d, "snapshots", snapshots)
			if err != nil {
				i.problem(d, "snapshots", err)
			}
		}
	}
	return i.next(c, model.String(page, tokenKey), 3)
}
func (i *serviceInventory) cachePages(ctx context.Context, action, key string, p url.Values) ([]model.Document, error) {
	rows := []model.Document{}
	tokens := map[string]bool{}
	tokenKey := "Marker"
	if strings.Contains(action, "Serverless") {
		tokenKey = "NextToken"
	}
	for n := 0; n < 32; n++ {
		v, e := i.r.query(ctx, "elasticache", action, "2015-02-02", p)
		if e != nil {
			return rows, e
		}
		if _, ok := v[key]; !ok {
			return rows, awsservice.ErrEvidence
		}
		rows = append(rows, serviceList(v[key])...)
		if len(rows) > awsservice.MaxRows {
			return rows, awsservice.ErrEvidence
		}
		next := model.String(v, tokenKey)
		if next == "" {
			return rows, nil
		}
		if len(next) > 4096 || tokens[next] {
			return rows, awsservice.ErrEvidence
		}
		tokens[next] = true
		p.Set(tokenKey, next)
	}
	return rows, awsservice.ErrEvidence
}
