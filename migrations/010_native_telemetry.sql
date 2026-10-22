-- Native telemetry has separate transport identities from current-minute activity
-- and SLO receipts. PostgreSQL contains metadata/small evaluations, never raw
-- sample batches. Persistence checkpoints attest work performed by the trusted
-- transport process; they are not proof that PostgreSQL inspected S3/ClickHouse.
DO $$ BEGIN
 IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='finops_telemetry_reader') THEN CREATE ROLE finops_telemetry_reader NOLOGIN;END IF;
 IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='finops_telemetry_ingress') THEN CREATE ROLE finops_telemetry_ingress NOLOGIN;END IF;
END $$;
GRANT USAGE ON SCHEMA public TO finops_telemetry_reader,finops_telemetry_ingress;
GRANT SELECT ON entities TO finops_telemetry_reader,finops_telemetry_ingress;
GRANT SELECT ON tenant_registry TO finops_telemetry_reader;
CREATE POLICY telemetry_reader_tenant_routing ON tenant_registry FOR SELECT TO finops_telemetry_reader USING(true);

CREATE TABLE telemetry_connections(
 tenant_id text NOT NULL,id text NOT NULL,version bigint NOT NULL CHECK(version>0),kind text NOT NULL CHECK(kind IN('PROMETHEUS','OTLP')),
 config_hash text NOT NULL CHECK(config_hash ~ '^[a-f0-9]{64}$'),config jsonb NOT NULL,document jsonb NOT NULL DEFAULT '{}',
 writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,id,version),UNIQUE(tenant_id,id,config_hash),CHECK(pg_column_size(config)<=65536)
);
CREATE TABLE telemetry_metric_definitions(
 tenant_id text NOT NULL,connection_id text NOT NULL,connection_version bigint NOT NULL,id text NOT NULL,version text NOT NULL,
 content_hash text NOT NULL CHECK(content_hash ~ '^[a-f0-9]{64}$'),document jsonb NOT NULL,writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,connection_id,connection_version,id),FOREIGN KEY(tenant_id,connection_id,connection_version) REFERENCES telemetry_connections(tenant_id,id,version)
);
CREATE TABLE telemetry_source_revisions(
 tenant_id text NOT NULL,id text NOT NULL,connection_id text NOT NULL,connection_version bigint NOT NULL,config_hash text NOT NULL,
 document jsonb NOT NULL DEFAULT '{}',writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,id),UNIQUE(tenant_id,connection_id,config_hash),FOREIGN KEY(tenant_id,connection_id,connection_version) REFERENCES telemetry_connections(tenant_id,id,version),
 FOREIGN KEY(tenant_id,connection_id,config_hash) REFERENCES telemetry_connections(tenant_id,id,config_hash)
);
CREATE TABLE telemetry_source_revocations(
 tenant_id text NOT NULL,id text NOT NULL,revision_id text NOT NULL,reason text NOT NULL CHECK(length(reason) BETWEEN 1 AND 2000),
 document jsonb NOT NULL DEFAULT '{}',writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,id),UNIQUE(tenant_id,revision_id),FOREIGN KEY(tenant_id,revision_id) REFERENCES telemetry_source_revisions(tenant_id,id)
);
CREATE TABLE telemetry_batches(
 tenant_id text NOT NULL,id text NOT NULL,connection_id text NOT NULL,revision_id text NOT NULL,idempotency_key text NOT NULL CHECK(length(idempotency_key) BETWEEN 1 AND 200),
 request_hash text NOT NULL CHECK(request_hash ~ '^[a-f0-9]{64}$'),metadata jsonb NOT NULL,document jsonb NOT NULL DEFAULT '{}',
 writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,id),UNIQUE(tenant_id,connection_id,idempotency_key),FOREIGN KEY(tenant_id,revision_id) REFERENCES telemetry_source_revisions(tenant_id,id),CHECK(pg_column_size(metadata)<=16384)
);
CREATE TABLE telemetry_checkpoints(
 tenant_id text NOT NULL,id text NOT NULL,batch_id text NOT NULL,stage text NOT NULL CHECK(stage IN('RAW_PERSISTED','ANALYTICS_PERSISTED')),
 content_hash text NOT NULL CHECK(content_hash ~ '^[a-f0-9]{64}$'),metadata jsonb NOT NULL,document jsonb NOT NULL DEFAULT '{}',
 writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,id),UNIQUE(tenant_id,batch_id,stage),FOREIGN KEY(tenant_id,batch_id) REFERENCES telemetry_batches(tenant_id,id),CHECK(pg_column_size(metadata)<=8192)
);
CREATE TABLE telemetry_receipts(
 tenant_id text NOT NULL,id text NOT NULL,batch_id text NOT NULL,revision_id text NOT NULL,connection_id text NOT NULL,
 document jsonb NOT NULL DEFAULT '{}',writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,id),UNIQUE(tenant_id,batch_id),FOREIGN KEY(tenant_id,batch_id) REFERENCES telemetry_batches(tenant_id,id),FOREIGN KEY(tenant_id,revision_id) REFERENCES telemetry_source_revisions(tenant_id,id)
);
CREATE INDEX telemetry_receipts_connection ON telemetry_receipts(tenant_id,connection_id,created_at,id);
CREATE TABLE telemetry_evaluations(
 tenant_id text NOT NULL,id text NOT NULL,connection_id text NOT NULL,revision_id text NOT NULL,content_hash text NOT NULL CHECK(content_hash ~ '^[a-f0-9]{64}$'),
 metadata jsonb NOT NULL,document jsonb NOT NULL DEFAULT '{}',writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,id),FOREIGN KEY(tenant_id,revision_id) REFERENCES telemetry_source_revisions(tenant_id,id),CHECK(pg_column_size(metadata)<=131072)
);
CREATE TABLE telemetry_sync_requests(
 tenant_id text NOT NULL,id text NOT NULL,connection_id text NOT NULL,revision_id text NOT NULL,idempotency_key text NOT NULL CHECK(length(idempotency_key) BETWEEN 1 AND 200),
 request_hash text NOT NULL CHECK(request_hash ~ '^[a-f0-9]{64}$'),metadata jsonb NOT NULL,document jsonb NOT NULL DEFAULT '{}',
 status text NOT NULL DEFAULT 'PENDING' CHECK(status IN('PENDING','RUNNING','COMPLETED','RETRY','BLOCKED')),attempts integer NOT NULL DEFAULT 0 CHECK(attempts>=0),
 lease_token text,lease_until timestamptz,next_attempt timestamptz NOT NULL DEFAULT clock_timestamp(),receipt_id text,receipt_ids jsonb NOT NULL DEFAULT '[]' CHECK(jsonb_typeof(receipt_ids)='array' AND jsonb_array_length(receipt_ids)<=400),reason_code text,
 writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,id),UNIQUE(tenant_id,connection_id,idempotency_key),FOREIGN KEY(tenant_id,revision_id) REFERENCES telemetry_source_revisions(tenant_id,id),
 FOREIGN KEY(tenant_id,receipt_id) REFERENCES telemetry_receipts(tenant_id,id),CHECK(pg_column_size(metadata)<=8192)
);
CREATE INDEX telemetry_sync_due ON telemetry_sync_requests(tenant_id,next_attempt,created_at) WHERE status NOT IN('COMPLETED','BLOCKED');

DO $$ DECLARE tab text;BEGIN FOREACH tab IN ARRAY ARRAY['telemetry_connections','telemetry_metric_definitions','telemetry_source_revisions','telemetry_source_revocations','telemetry_batches','telemetry_checkpoints','telemetry_receipts','telemetry_evaluations','telemetry_sync_requests'] LOOP
 EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',tab);EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',tab);
 EXECUTE format('CREATE POLICY tenant_isolation ON %I USING(tenant_id=current_setting(''app.tenant_id'',true)) WITH CHECK(tenant_id=current_setting(''app.tenant_id'',true))',tab);
 IF tab<>'telemetry_sync_requests' THEN EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION deny_evidence_mutation()',tab||'_immutable',tab);END IF;
 EXECUTE format('GRANT SELECT ON %I TO finops_api,finops_worker,finops_signer,finops_executor,finops_telemetry_reader,finops_telemetry_ingress',tab);
END LOOP;END $$;
GRANT INSERT ON telemetry_connections,telemetry_metric_definitions,telemetry_source_revisions,telemetry_source_revocations,telemetry_evaluations,telemetry_sync_requests TO finops_api;
GRANT INSERT ON telemetry_batches,telemetry_checkpoints,telemetry_receipts TO finops_telemetry_reader,finops_telemetry_ingress;
GRANT UPDATE ON telemetry_sync_requests TO finops_telemetry_reader;
CREATE TRIGGER telemetry_sync_no_delete BEFORE DELETE ON telemetry_sync_requests FOR EACH ROW EXECUTE FUNCTION deny_evidence_mutation();

CREATE FUNCTION telemetry_active_config(p_tenant text,p_connection text,p_revision text) RETURNS jsonb LANGUAGE plpgsql AS $$ DECLARE rev telemetry_source_revisions;cfg telemetry_connections;resource jsonb;BEGIN
 IF p_tenant IS DISTINCT FROM current_setting('app.tenant_id',true) THEN RAISE EXCEPTION 'telemetry tenant mismatch';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(p_tenant||':dependency-graph',0));PERFORM pg_advisory_xact_lock(hashtextextended(p_tenant||':telemetry:'||p_connection,0));
 SELECT * INTO rev FROM telemetry_source_revisions WHERE tenant_id=p_tenant AND id=p_revision AND connection_id=p_connection;
 SELECT * INTO cfg FROM telemetry_connections WHERE tenant_id=p_tenant AND id=p_connection ORDER BY version DESC LIMIT 1;
 IF rev.id IS NULL OR cfg.id IS NULL OR cfg.version<>rev.connection_version OR cfg.config_hash<>rev.config_hash OR cfg.config->>'enabled' IS DISTINCT FROM 'true' OR EXISTS(SELECT 1 FROM telemetry_source_revocations WHERE tenant_id=p_tenant AND revision_id=p_revision) THEN RAISE EXCEPTION 'telemetry source revision inactive';END IF;
 SELECT document INTO resource FROM entities WHERE tenant_id=p_tenant AND kind='resources' AND id=cfg.config->'binding'->>'resource_id';
 IF resource IS NULL OR cfg.config->'binding' IS DISTINCT FROM jsonb_build_object('tenant_id',p_tenant,'resource_id',cfg.config->'binding'->>'resource_id','workload_id',resource->>'workload_id','provider',resource->>'provider','provider_resource_id',resource->>'provider_resource_id','account_id',resource->>'account_id','region',resource->>'region') THEN RAISE EXCEPTION 'telemetry current inventory binding changed';END IF;
 RETURN cfg.config;
END $$;
CREATE FUNCTION telemetry_transport_role(p_kind text) RETURNS text LANGUAGE plpgsql AS $$ BEGIN
 IF p_kind='PROMETHEUS' AND pg_has_role(current_user,'finops_telemetry_reader','MEMBER') THEN RETURN 'finops_telemetry_reader';END IF;
 IF p_kind='OTLP' AND pg_has_role(current_user,'finops_telemetry_ingress','MEMBER') THEN RETURN 'finops_telemetry_ingress';END IF;
 RAISE EXCEPTION 'telemetry protocol writer forbidden';
END $$;

CREATE FUNCTION guard_telemetry_config() RETURNS trigger LANGUAGE plpgsql AS $$ DECLARE cfg telemetry_connections;resource jsonb;definition jsonb;v bigint;refs jsonb;BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id||':dependency-graph',0));
 NEW.created_at:=clock_timestamp();NEW.writer_role:='finops_api';
 IF TG_TABLE_NAME='telemetry_connections' THEN
  PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id||':telemetry:'||NEW.id,0));
  SELECT coalesce(max(version),0)+1 INTO v FROM telemetry_connections WHERE tenant_id=NEW.tenant_id AND id=NEW.id;
  SELECT document INTO resource FROM entities WHERE tenant_id=NEW.tenant_id AND kind='resources' AND id=NEW.config->'binding'->>'resource_id';
  IF NEW.version<>v OR NEW.config->>'schema_version' IS DISTINCT FROM '1' OR NEW.config->>'id' IS DISTINCT FROM NEW.id OR (NEW.config->>'version')::bigint IS DISTINCT FROM NEW.version OR NEW.config->>'kind' IS DISTINCT FROM NEW.kind OR jsonb_typeof(NEW.config->'enabled') IS DISTINCT FROM 'boolean' OR resource IS NULL THEN RAISE EXCEPTION 'telemetry connection invalid';END IF;
  IF NEW.config->'binding' IS DISTINCT FROM jsonb_build_object('tenant_id',NEW.tenant_id,'resource_id',NEW.config->'binding'->>'resource_id','workload_id',resource->>'workload_id','provider',resource->>'provider','provider_resource_id',resource->>'provider_resource_id','account_id',resource->>'account_id','region',resource->>'region') THEN RAISE EXCEPTION 'telemetry resource binding mismatch';END IF;
  IF jsonb_typeof(NEW.config->'definitions') IS DISTINCT FROM 'array' OR jsonb_array_length(NEW.config->'definitions') NOT BETWEEN 1 AND 32 OR (SELECT count(DISTINCT x->>'id') FROM jsonb_array_elements(NEW.config->'definitions') x)<>jsonb_array_length(NEW.config->'definitions') THEN RAISE EXCEPTION 'telemetry definitions invalid';END IF;
  IF NEW.kind='PROMETHEUS' AND coalesce(NEW.config->>'read_binding_id','')='' OR NEW.kind='OTLP' AND (coalesce(NEW.config->>'issuer','')='' OR coalesce(NEW.config->>'subject','')='') THEN RAISE EXCEPTION 'telemetry credential binding missing';END IF;
  NEW.document:=NEW.config||jsonb_build_object('config_hash',NEW.config_hash);
 ELSIF TG_TABLE_NAME='telemetry_metric_definitions' THEN
  SELECT * INTO cfg FROM telemetry_connections WHERE tenant_id=NEW.tenant_id AND id=NEW.connection_id AND version=NEW.connection_version;
  SELECT x INTO definition FROM jsonb_array_elements(cfg.config->'definitions') x WHERE x->>'id'=NEW.id;
  IF definition IS NULL OR definition IS DISTINCT FROM NEW.document OR definition->>'version' IS DISTINCT FROM NEW.version THEN RAISE EXCEPTION 'telemetry definition differs from immutable config';END IF;
  NEW.document:=definition||jsonb_build_object('connection_id',NEW.connection_id,'connection_version',NEW.connection_version,'hash',NEW.content_hash);
 ELSIF TG_TABLE_NAME='telemetry_source_revisions' THEN
  SELECT * INTO cfg FROM telemetry_connections WHERE tenant_id=NEW.tenant_id AND id=NEW.connection_id AND version=NEW.connection_version;
  IF cfg.config_hash IS DISTINCT FROM NEW.config_hash OR (SELECT count(*) FROM telemetry_metric_definitions WHERE tenant_id=NEW.tenant_id AND connection_id=NEW.connection_id AND connection_version=NEW.connection_version)<>jsonb_array_length(cfg.config->'definitions') THEN RAISE EXCEPTION 'telemetry revision definitions incomplete';END IF;
  SELECT jsonb_agg(jsonb_build_object('id',id,'version',version,'hash',content_hash) ORDER BY id) INTO refs FROM telemetry_metric_definitions WHERE tenant_id=NEW.tenant_id AND connection_id=NEW.connection_id AND connection_version=NEW.connection_version;
  NEW.document:=jsonb_build_object('connection_id',NEW.connection_id,'connection_version',NEW.connection_version,'config_hash',NEW.config_hash,'binding',cfg.config->'binding','source_kind',cfg.kind,'definition_refs',refs);
 ELSE
  SELECT c.* INTO cfg FROM telemetry_connections c JOIN telemetry_source_revisions r ON r.tenant_id=c.tenant_id AND r.connection_id=c.id AND r.connection_version=c.version WHERE r.tenant_id=NEW.tenant_id AND r.id=NEW.revision_id;
  PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id||':telemetry:'||cfg.id,0));
  NEW.document:=jsonb_build_object('revision_id',NEW.revision_id,'connection_id',cfg.id,'reason',NEW.reason);
 END IF;
 NEW.document:=NEW.document||jsonb_build_object('id',NEW.id,'tenant_id',NEW.tenant_id,'created_at',NEW.created_at,'writer_role',NEW.writer_role);RETURN NEW;
END $$;
CREATE TRIGGER telemetry_connection_writer BEFORE INSERT ON telemetry_connections FOR EACH ROW EXECUTE FUNCTION guard_telemetry_config();
CREATE TRIGGER telemetry_definition_writer BEFORE INSERT ON telemetry_metric_definitions FOR EACH ROW EXECUTE FUNCTION guard_telemetry_config();
CREATE TRIGGER telemetry_revision_writer BEFORE INSERT ON telemetry_source_revisions FOR EACH ROW EXECUTE FUNCTION guard_telemetry_config();
CREATE TRIGGER telemetry_revocation_writer BEFORE INSERT ON telemetry_source_revocations FOR EACH ROW EXECUTE FUNCTION guard_telemetry_config();

CREATE FUNCTION guard_telemetry_batch() RETURNS trigger LANGUAGE plpgsql AS $$ DECLARE cfg jsonb;rev jsonb;k text;observed_start timestamptz;observed_end timestamptz;collected timestamptz;lookback_seconds integer;BEGIN
 cfg:=telemetry_active_config(NEW.tenant_id,NEW.connection_id,NEW.revision_id);
 NEW.writer_role:=telemetry_transport_role(cfg->>'kind');NEW.created_at:=clock_timestamp();
 IF jsonb_typeof(NEW.metadata) IS DISTINCT FROM 'object' OR NEW.metadata-ARRAY['raw_sha256','canonical_hash','binding','source_kind','collected_at','start','end','sample_count','rejection_count','warning_count','query_start','query_end']<>'{}'::jsonb OR NEW.metadata->'binding' IS DISTINCT FROM cfg->'binding' OR NEW.metadata->>'source_kind' IS DISTINCT FROM cfg->>'kind' THEN RAISE EXCEPTION 'telemetry batch binding or metadata invalid';END IF;
 FOREACH k IN ARRAY ARRAY['raw_sha256','canonical_hash'] LOOP IF coalesce(NEW.metadata->>k,'')!~'^[a-f0-9]{64}$' THEN RAISE EXCEPTION 'telemetry batch hash missing';END IF;END LOOP;
 FOREACH k IN ARRAY ARRAY['sample_count','rejection_count','warning_count'] LOOP IF jsonb_typeof(NEW.metadata->k) IS DISTINCT FROM 'number' OR (NEW.metadata->>k)!~'^[0-9]+$' OR (NEW.metadata->>k)::bigint>250000 THEN RAISE EXCEPTION 'telemetry batch count invalid';END IF;END LOOP;
 observed_start:=(NEW.metadata->>'start')::timestamptz;observed_end:=(NEW.metadata->>'end')::timestamptz;collected:=(NEW.metadata->>'collected_at')::timestamptz;
 IF collected IS NULL OR NOT isfinite(collected) OR collected>NEW.created_at+interval '5 seconds' OR ((NEW.metadata->>'sample_count')::bigint>0 AND (observed_start IS NULL OR observed_end IS NULL OR NOT isfinite(observed_start) OR NOT isfinite(observed_end) OR observed_end<observed_start OR observed_end>NEW.created_at+interval '5 seconds')) OR ((NEW.metadata->>'sample_count')::bigint=0 AND (observed_start IS NOT NULL OR observed_end IS NOT NULL)) THEN RAISE EXCEPTION 'telemetry observation time invalid';END IF;
 IF cfg->>'kind'='OTLP' AND (collected<NEW.created_at-interval '2 minutes' OR observed_start<NEW.created_at-interval '5 minutes' OR NEW.metadata ? 'query_start' OR NEW.metadata ? 'query_end') THEN RAISE EXCEPTION 'OTLP historical backfill forbidden';END IF;
 SELECT greatest(0,least(600,coalesce(max((d->>'max_gap_seconds')::integer),0))) INTO lookback_seconds FROM jsonb_array_elements(cfg->'definitions') d;
 IF cfg->>'kind'='PROMETHEUS' AND ((NEW.metadata->>'query_start')::timestamptz IS NULL OR (NEW.metadata->>'query_end')::timestamptz IS NULL OR NOT isfinite((NEW.metadata->>'query_start')::timestamptz) OR NOT isfinite((NEW.metadata->>'query_end')::timestamptz) OR (NEW.metadata->>'query_end')::timestamptz<=(NEW.metadata->>'query_start')::timestamptz OR (NEW.metadata->>'query_end')::timestamptz-(NEW.metadata->>'query_start')::timestamptz>interval '92 days' OR (NEW.metadata->>'query_end')::timestamptz>NEW.created_at+interval '5 seconds' OR observed_start<(NEW.metadata->>'query_start')::timestamptz-lookback_seconds*interval '1 second' OR observed_end>(NEW.metadata->>'query_end')::timestamptz) THEN RAISE EXCEPTION 'telemetry native query bounds invalid';END IF;
 SELECT document INTO rev FROM telemetry_source_revisions WHERE tenant_id=NEW.tenant_id AND id=NEW.revision_id;
 NEW.document:=NEW.metadata||jsonb_build_object('id',NEW.id,'tenant_id',NEW.tenant_id,'connection_id',NEW.connection_id,'revision_id',NEW.revision_id,'config_hash',rev->>'config_hash','definition_refs',rev->'definition_refs','idempotency_key',NEW.idempotency_key,'request_hash',NEW.request_hash,'created_at',NEW.created_at,'writer_role',NEW.writer_role);RETURN NEW;
END $$;
CREATE TRIGGER telemetry_batch_writer BEFORE INSERT ON telemetry_batches FOR EACH ROW EXECUTE FUNCTION guard_telemetry_batch();

CREATE FUNCTION telemetry_object_key(p_tenant text,p_key text) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
 SELECT p_key IS NOT NULL AND length(p_key) BETWEEN 1 AND 1024 AND starts_with(p_key,'tenant/'||p_tenant||'/native/') AND p_key!~'(^|/)\.\.?(/|$)' AND position('//' IN p_key)=0 AND position(chr(92) IN p_key)=0
$$;
CREATE FUNCTION guard_telemetry_checkpoint() RETURNS trigger LANGUAGE plpgsql AS $$ DECLARE batch telemetry_batches;cfg jsonb;BEGIN
 SELECT * INTO batch FROM telemetry_batches WHERE tenant_id=NEW.tenant_id AND id=NEW.batch_id;
 cfg:=telemetry_active_config(NEW.tenant_id,batch.connection_id,batch.revision_id);NEW.writer_role:=telemetry_transport_role(cfg->>'kind');NEW.created_at:=clock_timestamp();
 IF NEW.stage='RAW_PERSISTED' THEN
  IF NEW.metadata-ARRAY['bucket','key','version_id','body_sha256']<>'{}'::jsonb OR coalesce(NEW.metadata->>'bucket','')!~'^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$' OR NOT telemetry_object_key(NEW.tenant_id,NEW.metadata->>'key') OR length(coalesce(NEW.metadata->>'version_id','')) NOT BETWEEN 1 AND 1024 OR NEW.metadata->>'version_id'='null' OR NEW.metadata->>'body_sha256' IS DISTINCT FROM batch.metadata->>'raw_sha256' THEN RAISE EXCEPTION 'telemetry raw persistence checkpoint invalid';END IF;
 ELSE
  IF NEW.metadata-ARRAY['database','table','write_id','canonical_hash','sample_count','canonical_bucket','canonical_key','canonical_version_id','canonical_body_sha256']<>'{}'::jsonb OR length(coalesce(NEW.metadata->>'database','')) NOT BETWEEN 1 AND 128 OR length(coalesce(NEW.metadata->>'table','')) NOT BETWEEN 1 AND 128 OR length(coalesce(NEW.metadata->>'write_id','')) NOT BETWEEN 1 AND 200 OR NEW.metadata->>'canonical_hash' IS DISTINCT FROM batch.metadata->>'canonical_hash' OR NEW.metadata->'sample_count' IS DISTINCT FROM batch.metadata->'sample_count' OR coalesce(NEW.metadata->>'canonical_bucket','')!~'^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$' OR NOT telemetry_object_key(NEW.tenant_id,NEW.metadata->>'canonical_key') OR length(coalesce(NEW.metadata->>'canonical_version_id','')) NOT BETWEEN 1 AND 1024 OR NEW.metadata->>'canonical_version_id'='null' OR coalesce(NEW.metadata->>'canonical_body_sha256','')!~'^[a-f0-9]{64}$' THEN RAISE EXCEPTION 'telemetry analytics persistence checkpoint invalid';END IF;
 END IF;
 NEW.document:=NEW.metadata||jsonb_build_object('id',NEW.id,'tenant_id',NEW.tenant_id,'batch_id',NEW.batch_id,'stage',NEW.stage,'hash',NEW.content_hash,'writer_role',NEW.writer_role,'created_at',NEW.created_at);RETURN NEW;
END $$;
CREATE TRIGGER telemetry_checkpoint_writer BEFORE INSERT ON telemetry_checkpoints FOR EACH ROW EXECUTE FUNCTION guard_telemetry_checkpoint();
CREATE FUNCTION guard_telemetry_receipt() RETURNS trigger LANGUAGE plpgsql AS $$ DECLARE batch telemetry_batches;cfg jsonb;raw jsonb;analytics jsonb;BEGIN
 SELECT * INTO batch FROM telemetry_batches WHERE tenant_id=NEW.tenant_id AND id=NEW.batch_id;
 IF batch.connection_id IS DISTINCT FROM NEW.connection_id OR batch.revision_id IS DISTINCT FROM NEW.revision_id THEN RAISE EXCEPTION 'telemetry publication binding invalid';END IF;
 cfg:=telemetry_active_config(NEW.tenant_id,NEW.connection_id,NEW.revision_id);NEW.writer_role:=telemetry_transport_role(cfg->>'kind');NEW.created_at:=clock_timestamp();
 SELECT document INTO raw FROM telemetry_checkpoints WHERE tenant_id=NEW.tenant_id AND batch_id=NEW.batch_id AND stage='RAW_PERSISTED';
 SELECT document INTO analytics FROM telemetry_checkpoints WHERE tenant_id=NEW.tenant_id AND batch_id=NEW.batch_id AND stage='ANALYTICS_PERSISTED';
 IF raw IS NULL OR analytics IS NULL THEN RAISE EXCEPTION 'telemetry persistence incomplete';END IF;
 NEW.document:=batch.document||jsonb_build_object('id',NEW.id,'batch_id',NEW.batch_id,'raw_checkpoint',raw,'analytics_checkpoint',analytics,'published_at',NEW.created_at,'created_at',NEW.created_at,'writer_role',NEW.writer_role,'source_provenance','NATIVE_TELEMETRY');RETURN NEW;
END $$;
CREATE TRIGGER telemetry_receipt_writer BEFORE INSERT ON telemetry_receipts FOR EACH ROW EXECUTE FUNCTION guard_telemetry_receipt();

CREATE FUNCTION guard_telemetry_evaluation() RETURNS trigger LANGUAGE plpgsql AS $$ DECLARE cfg jsonb;r jsonb;rid text;metric jsonb;BEGIN
 cfg:=telemetry_active_config(NEW.tenant_id,NEW.connection_id,NEW.revision_id);NEW.writer_role:='finops_api';NEW.created_at:=clock_timestamp();
 IF NEW.metadata-ARRAY['connection_id','config_hash','receipt_ids','evaluation']<>'{}'::jsonb OR NEW.metadata->>'connection_id' IS DISTINCT FROM NEW.connection_id OR NEW.metadata->>'config_hash' IS DISTINCT FROM (SELECT config_hash FROM telemetry_source_revisions WHERE tenant_id=NEW.tenant_id AND id=NEW.revision_id) OR jsonb_typeof(NEW.metadata->'receipt_ids') IS DISTINCT FROM 'array' OR jsonb_array_length(NEW.metadata->'receipt_ids') NOT BETWEEN 1 AND 2048 OR jsonb_typeof(NEW.metadata->'evaluation') IS DISTINCT FROM 'object' OR NEW.metadata->'evaluation'->>'schema_version' IS DISTINCT FROM '1' OR (NEW.metadata->'evaluation')-ARRAY['schema_version','status','reason_codes','start','end','evaluated_at','metrics','hash','history_days','timezone']<>'{}'::jsonb THEN RAISE EXCEPTION 'telemetry evaluation metadata invalid';END IF;
 FOR rid IN SELECT jsonb_array_elements_text(NEW.metadata->'receipt_ids') LOOP
  SELECT document INTO r FROM telemetry_receipts WHERE tenant_id=NEW.tenant_id AND id=rid AND connection_id=NEW.connection_id AND revision_id=NEW.revision_id;
  IF r IS NULL OR r->'binding' IS DISTINCT FROM cfg->'binding' THEN RAISE EXCEPTION 'telemetry evaluation receipt binding invalid';END IF;
 END LOOP;
 IF jsonb_typeof(NEW.metadata->'evaluation'->'metrics') IS DISTINCT FROM 'array' OR jsonb_array_length(NEW.metadata->'evaluation'->'metrics')>32 THEN RAISE EXCEPTION 'telemetry evaluation metrics invalid';END IF;
 FOR metric IN SELECT value FROM jsonb_array_elements(NEW.metadata->'evaluation'->'metrics') LOOP
  IF metric-ARRAY['definition_id','metric','unit','status','reason_codes','observed_samples','expected_samples','coverage_ppm','observed_duration_ns','unknown_duration_ns','p50','p90','p95','p99','p999','maximum','total','histogram','segment_ids','statistic']<>'{}'::jsonb OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(cfg->'definitions') d WHERE d->>'id'=metric->>'definition_id' AND d->>'metric'=metric->>'metric' AND d->>'unit'=metric->>'unit') THEN RAISE EXCEPTION 'telemetry evaluation definition invalid';END IF;
 END LOOP;
 NEW.document:=NEW.metadata||jsonb_build_object('id',NEW.id,'tenant_id',NEW.tenant_id,'revision_id',NEW.revision_id,'binding',cfg->'binding','hash',NEW.content_hash,'writer_role',NEW.writer_role,'created_at',NEW.created_at);RETURN NEW;
END $$;
CREATE TRIGGER telemetry_evaluation_writer BEFORE INSERT ON telemetry_evaluations FOR EACH ROW EXECUTE FUNCTION guard_telemetry_evaluation();

CREATE FUNCTION guard_telemetry_sync() RETURNS trigger LANGUAGE plpgsql AS $$ DECLARE cfg jsonb;r jsonb;rid text;cursor_time timestamptz;BEGIN
 IF TG_OP='INSERT' THEN
  cfg:=telemetry_active_config(NEW.tenant_id,NEW.connection_id,NEW.revision_id);
  IF cfg->>'kind'<>'PROMETHEUS' OR NEW.metadata-ARRAY['start','end','history_days']<>'{}'::jsonb OR (NEW.metadata->>'history_days')::integer NOT IN(14,30,90) OR NEW.metadata->>'history_days' IS NULL OR (NEW.metadata->>'start')::timestamptz IS NULL OR (NEW.metadata->>'end')::timestamptz IS NULL OR NOT isfinite((NEW.metadata->>'start')::timestamptz) OR NOT isfinite((NEW.metadata->>'end')::timestamptz) OR (NEW.metadata->>'end')::timestamptz<=(NEW.metadata->>'start')::timestamptz OR (NEW.metadata->>'end')::timestamptz-(NEW.metadata->>'start')::timestamptz>interval '91 days' OR (NEW.metadata->>'end')::timestamptz>clock_timestamp()+interval '5 seconds' THEN RAISE EXCEPTION 'telemetry historical sync window invalid';END IF;
  NEW.status:='PENDING';NEW.attempts:=0;NEW.lease_token:=NULL;NEW.lease_until:=NULL;NEW.receipt_id:=NULL;NEW.receipt_ids:='[]';NEW.reason_code:=NULL;NEW.next_attempt:=clock_timestamp();NEW.created_at:=clock_timestamp();NEW.writer_role:='finops_api';
  NEW.document:=NEW.metadata||jsonb_build_object('id',NEW.id,'tenant_id',NEW.tenant_id,'connection_id',NEW.connection_id,'revision_id',NEW.revision_id,'config_hash',(SELECT config_hash FROM telemetry_source_revisions WHERE tenant_id=NEW.tenant_id AND id=NEW.revision_id),'binding',cfg->'binding','idempotency_key',NEW.idempotency_key,'request_hash',NEW.request_hash,'created_at',NEW.created_at,'writer_role',NEW.writer_role);
 ELSE
  IF (NEW.tenant_id,NEW.id,NEW.connection_id,NEW.revision_id,NEW.idempotency_key,NEW.request_hash,NEW.metadata,NEW.document,NEW.writer_role,NEW.created_at) IS DISTINCT FROM (OLD.tenant_id,OLD.id,OLD.connection_id,OLD.revision_id,OLD.idempotency_key,OLD.request_hash,OLD.metadata,OLD.document,OLD.writer_role,OLD.created_at) OR OLD.status IN('COMPLETED','BLOCKED') THEN RAISE EXCEPTION 'telemetry sync immutable request or terminal state';END IF;
  IF NEW.status='RUNNING' THEN
   IF (OLD.status='RUNNING' AND OLD.lease_until>clock_timestamp()) OR OLD.next_attempt>clock_timestamp() OR coalesce(NEW.lease_token,'')='' OR NEW.lease_token IS NOT DISTINCT FROM OLD.lease_token OR NEW.lease_until<=clock_timestamp() OR NEW.lease_until>clock_timestamp()+interval '15 minutes' OR NEW.attempts<>OLD.attempts+1 THEN RAISE EXCEPTION 'telemetry sync lease invalid';END IF;
  ELSE
   IF OLD.status<>'RUNNING' OR OLD.lease_until<=clock_timestamp() OR NEW.lease_token IS DISTINCT FROM OLD.lease_token OR NEW.attempts<>OLD.attempts OR NEW.status NOT IN('COMPLETED','RETRY','BLOCKED') THEN RAISE EXCEPTION 'telemetry sync finish without current lease';END IF;
   IF NEW.status='COMPLETED' THEN
    PERFORM telemetry_active_config(NEW.tenant_id,NEW.connection_id,NEW.revision_id);
    IF jsonb_array_length(NEW.receipt_ids) NOT BETWEEN 1 AND 400 OR (SELECT count(DISTINCT value) FROM jsonb_array_elements_text(NEW.receipt_ids))<>jsonb_array_length(NEW.receipt_ids) OR (NEW.receipt_id IS NOT NULL AND (jsonb_array_length(NEW.receipt_ids)<>1 OR NEW.receipt_ids->>0 IS DISTINCT FROM NEW.receipt_id)) THEN RAISE EXCEPTION 'telemetry completion receipt IDs invalid';END IF;
    FOR rid IN SELECT jsonb_array_elements_text(NEW.receipt_ids) LOOP
     SELECT document INTO r FROM telemetry_receipts WHERE tenant_id=NEW.tenant_id AND id=rid AND connection_id=NEW.connection_id AND revision_id=NEW.revision_id;
     IF r IS NULL OR (r->>'query_start')::timestamptz IS NULL OR (r->>'query_end')::timestamptz IS NULL OR (r->>'query_start')::timestamptz<(NEW.metadata->>'start')::timestamptz OR (r->>'query_end')::timestamptz>(NEW.metadata->>'end')::timestamptz THEN RAISE EXCEPTION 'telemetry sync completion receipt invalid';END IF;
    END LOOP;
    cursor_time:=(NEW.metadata->>'start')::timestamptz;
    FOR r IN SELECT document FROM telemetry_receipts WHERE tenant_id=NEW.tenant_id AND id IN(SELECT jsonb_array_elements_text(NEW.receipt_ids)) ORDER BY (document->>'query_start')::timestamptz LOOP
     IF (r->>'query_start')::timestamptz>cursor_time THEN RAISE EXCEPTION 'telemetry requested query range incomplete';END IF;
     cursor_time:=greatest(cursor_time,(r->>'query_end')::timestamptz);
    END LOOP;
    IF cursor_time<(NEW.metadata->>'end')::timestamptz THEN RAISE EXCEPTION 'telemetry requested query range incomplete';END IF;
   ELSIF NEW.status='BLOCKED' THEN
    IF coalesce(NEW.reason_code,'')='' OR NEW.receipt_id IS NOT NULL OR NEW.receipt_ids<>'[]'::jsonb THEN RAISE EXCEPTION 'telemetry blocked metadata invalid';END IF;
   ELSIF NEW.next_attempt<clock_timestamp() OR NEW.next_attempt>clock_timestamp()+interval '1 hour' OR coalesce(NEW.reason_code,'')='' THEN RAISE EXCEPTION 'telemetry retry metadata invalid';END IF;
  END IF;
 END IF;
 NEW.updated_at:=clock_timestamp();RETURN NEW;
END $$;
CREATE TRIGGER telemetry_sync_writer BEFORE INSERT OR UPDATE ON telemetry_sync_requests FOR EACH ROW EXECUTE FUNCTION guard_telemetry_sync();
