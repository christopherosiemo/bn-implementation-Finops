package provider

import (
	"context"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/awsservice"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

func (i *serviceInventory) dynamodb(ctx context.Context, c serviceCursor) (string, bool, error) {
	if c.Phase != 0 {
		return "", false, awsservice.ErrEvidence
	}
	p := model.Document{"Limit": 5}
	if c.Token != "" {
		p["ExclusiveStartTableName"] = c.Token
	}
	page, e := i.r.json(ctx, "dynamodb", "ListTables", "/", p)
	if e != nil {
		return "", false, e
	}
	if _, ok := page["TableNames"]; !ok {
		return "", false, awsservice.ErrEvidence
	}
	for _, name := range serviceStrings(page["TableNames"]) {
		arn := "arn:aws:dynamodb:" + i.out.Scope.Region + ":" + i.out.Scope.AccountID + ":table/" + name
		if !i.accepts(arn) {
			continue
		}
		native, e := i.r.json(ctx, "dynamodb", "DescribeTable", "/", model.Document{"TableName": name})
		if e != nil {
			if _, err := i.unavailable("DYNAMODB_TABLE", arn, name, "table_description", e); err != nil {
				return "", false, err
			}
			continue
		}
		cfg := awsservice.Document(native["Table"])
		if model.String(cfg, "TableArn") != arn {
			return "", false, awsservice.ErrEvidence
		}
		table, e := i.put("DYNAMODB_TABLE", arn, name, cfg)
		if e != nil {
			return "", false, e
		}
		table["state"] = cfg["TableStatus"]
		i.set(table, "size_and_item_count_semantics", "AWS_APPROXIMATE_SIX_HOUR_METADATA_NOT_REALTIME_TELEMETRY")
		i.set(table, "capacity_unit", "READ_CAPACITY_UNITS_AND_WRITE_CAPACITY_UNITS_DISTINCT")
		i.set(table, "storage_unit", "bytes")
		for _, spec := range []struct{ action, key string }{{"DescribeContinuousBackups", "continuous_backups"}, {"DescribeTimeToLive", "time_to_live"}, {"DescribeTableReplicaAutoScaling", "replica_autoscaling"}} {
			i.jsonOptional(ctx, table, spec.key, "dynamodb", spec.action, "/", model.Document{"TableName": name})
		}
		tags, err := i.jsonPages(ctx, "dynamodb", "ListTagsOfResource", "/", "Tags", "NextToken", "NextToken", model.Document{"ResourceArn": arn})
		i.set(table, "tags", tags)
		if err != nil {
			i.problem(table, "tags", err)
		}
		backups, err := i.jsonPages(ctx, "dynamodb", "ListBackups", "/", "BackupSummaries", "LastEvaluatedBackupArn", "ExclusiveStartBackupArn", model.Document{"TableName": name, "Limit": 100})
		i.set(table, "backups", backups)
		if err != nil {
			i.problem(table, "backups", err)
		}
		i.scaling(ctx, table, "dynamodb", "table/"+name)
		for _, index := range awsservice.Rows(cfg["GlobalSecondaryIndexes"]) {
			indexARN := model.String(index, "IndexArn")
			if indexARN == "" {
				i.problem(table, "index_identity", awsservice.ErrEvidence)
				continue
			}
			child, e := i.put("DYNAMODB_GSI", indexARN, model.String(index, "IndexName"), index)
			if e != nil {
				return "", false, e
			}
			serviceRel(child, "MEMBER_OF", arn)
			i.set(child, "economic_role", "SEPARATE_ONLY_WHEN_NATIVE_BILLING_IDENTIFIES_INDEX")
			i.set(child, "size_and_item_count_semantics", "AWS_APPROXIMATE_SIX_HOUR_METADATA_NOT_REALTIME_TELEMETRY")
			i.scaling(ctx, child, "dynamodb", "table/"+name+"/index/"+model.String(index, "IndexName"))
		}
		for _, replica := range awsservice.Rows(cfg["Replicas"]) {
			region := model.String(replica, "RegionName")
			if region != "" && region != i.out.Scope.Region {
				serviceRel(table, "REPLICATED_WITH", "arn:aws:dynamodb:"+region+":"+i.out.Scope.AccountID+":table/"+name)
			}
		}
	}
	return i.next(c, model.String(page, "LastEvaluatedTableName"), 1)
}
