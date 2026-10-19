-- Derived scheduling metadata, never authority or a replacement for evidence.
-- Stored generated columns avoid repeatedly decompressing historical billing
-- payloads even when PostgreSQL correctly chooses a small-heap sequential scan.
-- Original document contents, entity versions and evidence hashes are unchanged.
ALTER TABLE entities ADD COLUMN ingestion_status text GENERATED ALWAYS AS (
 CASE WHEN kind='ingestion_jobs' THEN document->>'status' END
) STORED,
ADD COLUMN ingestion_seal_kind text GENERATED ALWAYS AS (
 CASE WHEN kind='ingestion_jobs' AND document ? 'fixture_baseline' THEN 'baseline'
      WHEN kind='ingestion_jobs' AND document ? 'fixture_measurement' THEN 'measurement_snapshot' END
) STORED,
ADD COLUMN ingestion_seal_id text GENERATED ALWAYS AS (
 CASE WHEN kind='ingestion_jobs' AND document ? 'fixture_baseline' THEN id
      WHEN kind='ingestion_jobs' AND document ? 'fixture_measurement' THEN
       'fixture-snapshot-'||CASE WHEN jsonb_typeof(document->'fixture_measurement'->'measurement_id')='string'
       THEN document->'fixture_measurement'->>'measurement_id' ELSE '' END END
) STORED;

CREATE INDEX ingestion_jobs_runnable ON entities(tenant_id,created_at,id)
 WHERE kind='ingestion_jobs' AND ingestion_status IS DISTINCT FROM 'PERSISTED';
CREATE INDEX ingestion_jobs_fixture_seals ON entities(tenant_id,created_at,id)
 WHERE kind='ingestion_jobs' AND ingestion_status='PERSISTED' AND ingestion_seal_kind IS NOT NULL;
