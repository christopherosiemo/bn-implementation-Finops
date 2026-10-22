-- Additive bounded evaluation metadata. Full samples/segments remain in pinned
-- canonical receipt objects; PostgreSQL retains at most16 IDs, count and full hash.
CREATE OR REPLACE FUNCTION guard_telemetry_evaluation() RETURNS trigger LANGUAGE plpgsql AS $$ DECLARE cfg jsonb;r jsonb;rid text;metric jsonb;BEGIN
 cfg:=telemetry_active_config(NEW.tenant_id,NEW.connection_id,NEW.revision_id);NEW.writer_role:='finops_api';NEW.created_at:=clock_timestamp();
 IF NEW.metadata-ARRAY['connection_id','config_hash','receipt_ids','evaluation']<>'{}'::jsonb OR NEW.metadata->>'connection_id' IS DISTINCT FROM NEW.connection_id OR NEW.metadata->>'config_hash' IS DISTINCT FROM (SELECT config_hash FROM telemetry_source_revisions WHERE tenant_id=NEW.tenant_id AND id=NEW.revision_id) OR jsonb_typeof(NEW.metadata->'receipt_ids') IS DISTINCT FROM 'array' OR jsonb_array_length(NEW.metadata->'receipt_ids') NOT BETWEEN 1 AND 2048 OR jsonb_typeof(NEW.metadata->'evaluation') IS DISTINCT FROM 'object' OR NEW.metadata->'evaluation'->>'schema_version' IS DISTINCT FROM '1' OR (NEW.metadata->'evaluation')-ARRAY['schema_version','status','reason_codes','start','end','evaluated_at','metrics','hash','history_days','timezone']<>'{}'::jsonb THEN RAISE EXCEPTION 'telemetry evaluation metadata invalid';END IF;
 FOR rid IN SELECT jsonb_array_elements_text(NEW.metadata->'receipt_ids') LOOP
  SELECT document INTO r FROM telemetry_receipts WHERE tenant_id=NEW.tenant_id AND id=rid AND connection_id=NEW.connection_id AND revision_id=NEW.revision_id;
  IF r IS NULL OR r->'binding' IS DISTINCT FROM cfg->'binding' THEN RAISE EXCEPTION 'telemetry evaluation receipt binding invalid';END IF;
 END LOOP;
 IF jsonb_typeof(NEW.metadata->'evaluation'->'metrics') IS DISTINCT FROM 'array' OR jsonb_array_length(NEW.metadata->'evaluation'->'metrics')>32 THEN RAISE EXCEPTION 'telemetry evaluation metrics invalid';END IF;
 FOR metric IN SELECT value FROM jsonb_array_elements(NEW.metadata->'evaluation'->'metrics') LOOP
  IF jsonb_typeof(metric->'segment_ids') IS DISTINCT FROM 'array' OR jsonb_array_length(metric->'segment_ids')>16 OR jsonb_typeof(metric->'segment_count') IS DISTINCT FROM 'number' OR coalesce(metric->>'segment_count','')!~'^[0-9]+$' OR (metric->>'segment_count')::bigint>1000000000 OR coalesce(metric->>'segment_hash','')!~'^[a-f0-9]{64}$' OR jsonb_typeof(metric->'segment_ids_truncated') IS DISTINCT FROM 'boolean' OR ((metric->>'segment_ids_truncated')::boolean AND ((metric->>'segment_count')::bigint<=16 OR jsonb_array_length(metric->'segment_ids')<>16)) OR (NOT (metric->>'segment_ids_truncated')::boolean AND (metric->>'segment_count')::bigint<>jsonb_array_length(metric->'segment_ids')) THEN RAISE EXCEPTION 'telemetry bounded segment references invalid';END IF;
  IF metric-ARRAY['start','end','definition_id','metric','unit','status','reason_codes','observed_samples','expected_samples','coverage_ppm','observed_duration_ns','unknown_duration_ns','p50','p90','p95','p99','p999','maximum','total','histogram','segment_ids','segment_count','segment_hash','segment_ids_truncated','statistic']<>'{}'::jsonb OR NOT EXISTS(
   SELECT 1 FROM jsonb_array_elements(cfg->'definitions') d WHERE d->>'id'=metric->>'definition_id' AND d->>'metric'=metric->>'metric' AND (
    (d->>'type'<>'SUM' AND d->>'unit'=metric->>'unit') OR
    (d->>'type'='SUM' AND metric->>'unit'=(d->>'unit')||'/second' AND metric->>'statistic'='OBSERVED_INTERVAL_RATE_DISTRIBUTION') OR
    (d->>'type'='SUM' AND d->>'unit'=metric->>'unit' AND metric->>'status'='BLOCKED' AND coalesce((metric->>'observed_samples')::bigint,0)=0 AND coalesce(metric->'p50','null')='null' AND coalesce(metric->'p90','null')='null' AND coalesce(metric->'p95','null')='null' AND coalesce(metric->'p99','null')='null' AND coalesce(metric->'p999','null')='null' AND coalesce(metric->'maximum','null')='null')
   )) THEN RAISE EXCEPTION 'telemetry evaluation definition or derived unit invalid';END IF;
 END LOOP;
 NEW.document:=NEW.metadata||jsonb_build_object('id',NEW.id,'tenant_id',NEW.tenant_id,'revision_id',NEW.revision_id,'binding',cfg->'binding','hash',NEW.content_hash,'writer_role',NEW.writer_role,'created_at',NEW.created_at);RETURN NEW;
END $$;
