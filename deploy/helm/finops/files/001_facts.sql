CREATE TABLE IF NOT EXISTS finops.billing_facts (
  tenant_id String,
  source_id String,
  source_version String,
  source_record_id String,
  resource_id String,
  currency LowCardinality(String),
  billed_cost Decimal(38,12),
  effective_cost Nullable(Decimal(38,12)),
  source_time DateTime64(3,'UTC'),
  ingested_at DateTime64(3,'UTC') DEFAULT now64(3),
  payload String
) ENGINE=ReplacingMergeTree(ingested_at)
PARTITION BY toYYYYMM(source_time)
ORDER BY (tenant_id,source_id,source_version,source_record_id);

CREATE TABLE IF NOT EXISTS finops.metric_facts (
  tenant_id String,
  resource_id String,
  metric_name LowCardinality(String),
  source_time DateTime64(3,'UTC'),
  value Decimal(38,12),
  ingested_at DateTime64(3,'UTC') DEFAULT now64(3)
) ENGINE=ReplacingMergeTree(ingested_at)
PARTITION BY toYYYYMM(source_time)
ORDER BY (tenant_id,resource_id,metric_name,source_time)
TTL toDateTime(source_time) + INTERVAL 120 DAY;

ALTER TABLE finops.billing_facts MODIFY SETTING non_replicated_deduplication_window=1000;
ALTER TABLE finops.metric_facts MODIFY SETTING non_replicated_deduplication_window=1000;

-- Native facts preserve unlike units/statistics and source revisions separately.
-- They never replace another source's observation at the same wall-clock time.
CREATE TABLE IF NOT EXISTS finops.native_metric_samples (
 tenant_id String,batch_id String,connection_id String,config_hash String,
 canonical_hash String,sample_id String,definition_id String,stream_id String,
 resource_id String,workload_id String,provider LowCardinality(String),account_id String,region LowCardinality(String),
 metric LowCardinality(String),unit LowCardinality(String),statistic LowCardinality(String),
 source_time DateTime64(9,'UTC'),raw_sha256 String,payload String,
 ingested_at DateTime64(3,'UTC') DEFAULT now64(3)
) ENGINE=MergeTree
PARTITION BY toYYYYMM(source_time)
ORDER BY(tenant_id,connection_id,config_hash,batch_id,definition_id,stream_id,sample_id);
CREATE TABLE IF NOT EXISTS finops.native_metric_batches (
 tenant_id String,batch_id String,connection_id String,config_hash String,
 canonical_hash String,sample_count UInt64,raw_sha256 String,
 ingested_at DateTime64(3,'UTC') DEFAULT now64(3)
) ENGINE=MergeTree ORDER BY(tenant_id,connection_id,config_hash,batch_id);
ALTER TABLE finops.native_metric_samples MODIFY SETTING non_replicated_deduplication_window=1000;
ALTER TABLE finops.native_metric_batches MODIFY SETTING non_replicated_deduplication_window=1000;
