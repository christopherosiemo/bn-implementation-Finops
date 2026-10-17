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
