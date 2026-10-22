CREATE FUNCTION slo_receive_time() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp() $$;
CREATE TABLE slo_objectives(
 tenant_id text NOT NULL,id text NOT NULL,workload_id text NOT NULL,version bigint NOT NULL CHECK(version>0),
 content_hash text NOT NULL CHECK(content_hash ~ '^[a-f0-9]{64}$'),document jsonb NOT NULL,writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,id),UNIQUE(tenant_id,workload_id,version)
);
CREATE TABLE slo_sources(
 tenant_id text NOT NULL,id text NOT NULL,objective_id text NOT NULL,resource_id text NOT NULL,workload_id text NOT NULL,document jsonb NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,id),UNIQUE(tenant_id,resource_id,objective_id),FOREIGN KEY(tenant_id,objective_id) REFERENCES slo_objectives(tenant_id,id)
);
CREATE TABLE slo_receipts(
 tenant_id text NOT NULL,id text NOT NULL,source_id text NOT NULL,objective_id text NOT NULL,resource_id text NOT NULL,
 sequence bigint NOT NULL CHECK(sequence>0),interval_start timestamptz NOT NULL,interval_end timestamptz NOT NULL,received_at timestamptz NOT NULL DEFAULT slo_receive_time(),
 body_sha256 text NOT NULL CHECK(body_sha256 ~ '^[a-f0-9]{64}$'),idempotency_key text NOT NULL,raw_body bytea NOT NULL,document jsonb NOT NULL,writer_role text NOT NULL DEFAULT current_user,
 PRIMARY KEY(tenant_id,id),FOREIGN KEY(tenant_id,source_id) REFERENCES slo_sources(tenant_id,id),FOREIGN KEY(tenant_id,objective_id) REFERENCES slo_objectives(tenant_id,id),
 UNIQUE(tenant_id,source_id,sequence),UNIQUE(tenant_id,source_id,interval_start),UNIQUE(tenant_id,source_id,idempotency_key),CHECK(interval_end-interval_start=interval '1 minute')
);
CREATE INDEX slo_receipts_resource ON slo_receipts(tenant_id,resource_id,objective_id,interval_end DESC);
CREATE TABLE slo_evaluations(
 tenant_id text NOT NULL,id text NOT NULL,objective_id text NOT NULL,resource_id text NOT NULL,content_hash text NOT NULL CHECK(content_hash ~ '^[a-f0-9]{64}$'),
 document jsonb NOT NULL,writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,id),FOREIGN KEY(tenant_id,objective_id) REFERENCES slo_objectives(tenant_id,id)
);
CREATE TABLE slo_violations(
 tenant_id text NOT NULL,id text NOT NULL,execution_id text NOT NULL,plan_id text NOT NULL,measurement_id text NOT NULL CHECK(length(measurement_id)>0),
 document jsonb NOT NULL,writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,id),UNIQUE(tenant_id,execution_id),FOREIGN KEY(tenant_id,plan_id) REFERENCES signed_plans(tenant_id,plan_id)
);
CREATE INDEX slo_violations_measurement ON slo_violations(tenant_id,measurement_id,created_at,id);
DO $$ DECLARE tab text; BEGIN FOREACH tab IN ARRAY ARRAY['slo_objectives','slo_sources','slo_receipts','slo_evaluations','slo_violations'] LOOP
 EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',tab);EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',tab);
 EXECUTE format('CREATE POLICY tenant_isolation ON %I USING(tenant_id=current_setting(''app.tenant_id'',true)) WITH CHECK(tenant_id=current_setting(''app.tenant_id'',true))',tab);
 EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION deny_evidence_mutation()',tab||'_immutable',tab);
END LOOP;END $$;
GRANT SELECT ON slo_objectives,slo_sources,slo_receipts,slo_evaluations,slo_violations TO finops_api,finops_worker,finops_signer,finops_executor,finops_ingester;
GRANT SELECT ON slo_objectives,slo_sources,slo_receipts TO finops_activity;
GRANT INSERT ON slo_objectives,slo_sources TO finops_api;
GRANT INSERT ON slo_evaluations TO finops_api,finops_worker;
GRANT INSERT ON slo_receipts TO finops_activity;
GRANT INSERT ON slo_violations TO finops_worker;
CREATE FUNCTION slo_metadata_writer() RETURNS trigger LANGUAGE plpgsql AS $$ DECLARE source jsonb;objective jsonb;BEGIN
 NEW.created_at:=clock_timestamp();
 IF TG_TABLE_NAME='slo_objectives' THEN
  NEW.writer_role:='finops_api';
  IF NEW.document->>'workload_id' IS DISTINCT FROM NEW.workload_id THEN RAISE EXCEPTION 'SLO objective workload mismatch';END IF;
  NEW.document:=NEW.document||jsonb_build_object('version',NEW.version,'hash',NEW.content_hash);
 ELSIF TG_TABLE_NAME='slo_sources' THEN
  SELECT document INTO objective FROM slo_objectives WHERE tenant_id=NEW.tenant_id AND id=NEW.objective_id;
  SELECT document INTO source FROM entities WHERE tenant_id=NEW.tenant_id AND kind='resources' AND id=NEW.resource_id;
  IF objective IS NULL OR source IS NULL OR objective->>'workload_id' IS DISTINCT FROM NEW.workload_id OR source->>'workload_id' IS DISTINCT FROM NEW.workload_id OR NEW.document->>'provider_resource_id' IS DISTINCT FROM source->>'provider_resource_id' OR NEW.document->>'account_id' IS DISTINCT FROM source->>'account_id' OR NEW.document->>'region' IS DISTINCT FROM source->>'region' THEN RAISE EXCEPTION 'SLO source resource or objective mismatch';END IF;
  NEW.document:=NEW.document||jsonb_build_object('tenant_id',NEW.tenant_id,'id',NEW.id,'objective_id',NEW.objective_id,'resource_id',NEW.resource_id,'workload_id',NEW.workload_id);
  RETURN NEW;
 ELSE
  NEW.writer_role:=CASE WHEN pg_has_role(current_user,'finops_api','MEMBER') THEN 'finops_api' ELSE 'finops_worker' END;
  IF NEW.document->>'objective_id' IS DISTINCT FROM NEW.objective_id OR NEW.document->>'resource_id' IS DISTINCT FROM NEW.resource_id THEN RAISE EXCEPTION 'SLO evaluation binding mismatch';END IF;
  NEW.document:=NEW.document||jsonb_build_object('hash',NEW.content_hash,'evaluation_hash',NEW.content_hash);
 END IF;
 NEW.document:=NEW.document||jsonb_build_object('tenant_id',NEW.tenant_id,'id',NEW.id,'created_at',NEW.created_at,'writer_role',NEW.writer_role);
 RETURN NEW;END $$;
CREATE TRIGGER slo_objective_writer BEFORE INSERT ON slo_objectives FOR EACH ROW EXECUTE FUNCTION slo_metadata_writer();
CREATE TRIGGER slo_source_writer BEFORE INSERT ON slo_sources FOR EACH ROW EXECUTE FUNCTION slo_metadata_writer();
CREATE TRIGGER slo_evaluation_writer BEFORE INSERT ON slo_evaluations FOR EACH ROW EXECUTE FUNCTION slo_metadata_writer();
CREATE FUNCTION guard_slo_receipt() RETURNS trigger LANGUAGE plpgsql AS $$ DECLARE source jsonb;raw jsonb;latency jsonb;total numeric;last_bound numeric;prev_end timestamptz;prev_sequence bigint;BEGIN
 SELECT document INTO source FROM slo_sources WHERE tenant_id=NEW.tenant_id AND id=NEW.source_id;
 IF source IS NULL OR source->>'enabled' IS DISTINCT FROM 'true' OR source->>'objective_id' IS DISTINCT FROM NEW.objective_id OR source->>'resource_id' IS DISTINCT FROM NEW.resource_id OR source->>'subject' IS DISTINCT FROM NEW.document->>'subject' THEN RAISE EXCEPTION 'SLO source binding mismatch';END IF;
 NEW.received_at:=slo_receive_time();NEW.writer_role:='finops_activity';
 IF NEW.interval_end>NEW.received_at+interval '5 seconds' OR NEW.interval_end<NEW.received_at-interval '2 minutes' OR date_trunc('minute',NEW.interval_start)<>NEW.interval_start THEN RAISE EXCEPTION 'SLO observation outside receive window';END IF;
 raw:=convert_from(NEW.raw_body,'UTF8')::jsonb;
 IF jsonb_typeof(raw->'request_count') IS DISTINCT FROM 'number' OR jsonb_typeof(raw->'error_count') IS DISTINCT FROM 'number' OR jsonb_typeof(raw->'availability_good_seconds') IS DISTINCT FROM 'number' OR jsonb_typeof(raw->'availability_total_seconds') IS DISTINCT FROM 'number' THEN RAISE EXCEPTION 'SLO numeric observations required';END IF;
 IF encode(sha256(NEW.raw_body),'hex') IS DISTINCT FROM NEW.body_sha256 OR (raw-ARRAY['interval_start','interval_end']) IS DISTINCT FROM (NEW.document-ARRAY['id','tenant_id','subject','received_at','body_sha256','idempotency_key','binding','writer_role','interval_start','interval_end']) THEN RAISE EXCEPTION 'SLO original body differs';END IF;
 IF raw->>'schema_version' IS DISTINCT FROM '1' OR raw->>'source_id' IS DISTINCT FROM NEW.source_id OR raw->>'objective_id' IS DISTINCT FROM NEW.objective_id OR raw->>'resource_id' IS DISTINCT FROM NEW.resource_id OR raw->>'workload_id' IS DISTINCT FROM source->>'workload_id' OR (raw->>'sequence')::bigint IS DISTINCT FROM NEW.sequence OR (raw->>'interval_start')::timestamptz IS DISTINCT FROM NEW.interval_start OR (raw->>'interval_end')::timestamptz IS DISTINCT FROM NEW.interval_end THEN RAISE EXCEPTION 'SLO body binding mismatch';END IF;
 IF NEW.document->'binding' IS DISTINCT FROM jsonb_build_object('tenant_id',NEW.tenant_id,'workload_id',source->>'workload_id','resource_id',NEW.resource_id,'provider_resource_id',source->>'provider_resource_id','account_id',source->>'account_id','region',source->>'region') THEN RAISE EXCEPTION 'SLO provider binding mismatch';END IF;
 IF (raw->>'request_count')::bigint NOT BETWEEN 0 AND 1000000000000 OR (raw->>'error_count')::bigint NOT BETWEEN 0 AND (raw->>'request_count')::bigint OR (raw->>'availability_total_seconds')::bigint<>60 OR (raw->>'availability_good_seconds')::bigint NOT BETWEEN 0 AND 60 THEN RAISE EXCEPTION 'SLO counts invalid';END IF;
 latency:=raw->'latency';IF latency->>'unit' IS DISTINCT FROM 'milliseconds' OR (latency->>'sample_count')::bigint IS DISTINCT FROM (raw->>'request_count')::bigint OR jsonb_array_length(latency->'buckets') NOT BETWEEN 1 AND 256 THEN RAISE EXCEPTION 'SLO histogram invalid';END IF;
 total:=0;last_bound:=-1;
 FOR raw IN SELECT value FROM jsonb_array_elements(latency->'buckets') LOOP
  IF jsonb_typeof(raw->'count') IS DISTINCT FROM 'number' OR (raw->>'count')::bigint NOT BETWEEN 0 AND 1000000000000 OR raw->'upper_bound_ms' IS NULL THEN RAISE EXCEPTION 'SLO histogram fields invalid';END IF;
  total:=total+(raw->>'count')::bigint;
  IF last_bound IS NULL THEN RAISE EXCEPTION 'SLO infinity bucket must be last';END IF;
  IF raw->'upper_bound_ms'='null'::jsonb THEN last_bound:=NULL;ELSE IF (raw->>'upper_bound_ms')::bigint<=last_bound OR (raw->>'upper_bound_ms')::bigint>86400000 THEN RAISE EXCEPTION 'SLO bucket ordering invalid';END IF;last_bound:=(raw->>'upper_bound_ms')::bigint;END IF;
 END LOOP;
 IF total<>(latency->>'sample_count')::bigint OR last_bound IS NOT NULL THEN RAISE EXCEPTION 'SLO histogram samples invalid';END IF;
 SELECT interval_end,sequence INTO prev_end,prev_sequence FROM slo_receipts WHERE tenant_id=NEW.tenant_id AND source_id=NEW.source_id ORDER BY sequence DESC LIMIT 1;
 IF NEW.sequence<=prev_sequence OR NEW.interval_start<prev_end THEN RAISE EXCEPTION 'SLO sequence moved backwards';END IF;
 NEW.document:=NEW.document||jsonb_build_object('id',NEW.id,'tenant_id',NEW.tenant_id,'received_at',NEW.received_at,'body_sha256',NEW.body_sha256,'idempotency_key',NEW.idempotency_key,'writer_role',NEW.writer_role);
 RETURN NEW;END $$;
CREATE TRIGGER slo_receipt_writer BEFORE INSERT ON slo_receipts FOR EACH ROW EXECUTE FUNCTION guard_slo_receipt();
-- The trigger alone may lock the executor-owned receipt; the observer receives
-- no UPDATE privilege on provider_operations. Explicit tenant predicates remain
-- mandatory inside this narrow trigger-only definer function.
CREATE FUNCTION guard_slo_violation() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=public,pg_temp AS $$ DECLARE plan jsonb;execution jsonb;BEGIN
 IF NEW.tenant_id IS DISTINCT FROM current_setting('app.tenant_id',true) THEN RAISE EXCEPTION 'SLO violation tenant mismatch';END IF;
 SELECT envelope->'plan' INTO plan FROM signed_plans WHERE tenant_id=NEW.tenant_id AND plan_id=NEW.plan_id;
 SELECT document INTO execution FROM entities WHERE tenant_id=NEW.tenant_id AND kind='executions' AND id=NEW.execution_id;
 IF plan IS NULL OR execution IS NULL OR execution->>'change_plan_id' IS DISTINCT FROM NEW.plan_id OR plan->>'id' IS DISTINCT FROM NEW.plan_id OR plan->>'measurement_id' IS DISTINCT FROM NEW.measurement_id OR coalesce(plan->>'slo_objective_id','')='' OR plan->>'slo_objective_id' IS DISTINCT FROM NEW.document->>'objective_id' OR plan->>'workload_id' IS DISTINCT FROM NEW.document->>'workload_id' THEN RAISE EXCEPTION 'SLO violation signed occurrence mismatch';END IF;
 PERFORM 1 FROM provider_operations WHERE tenant_id=NEW.tenant_id AND execution_id=NEW.execution_id AND (stop_intent OR stop_owned) AND NOT restored FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'SLO violation requires active owned occurrence';END IF;
 NEW.writer_role:='finops_worker';NEW.created_at:=clock_timestamp();NEW.document:=NEW.document||jsonb_build_object('id',NEW.id,'tenant_id',NEW.tenant_id,'execution_id',NEW.execution_id,'plan_id',NEW.plan_id,'measurement_id',NEW.measurement_id,'writer_role',NEW.writer_role,'created_at',NEW.created_at);RETURN NEW;END $$;
CREATE TRIGGER slo_violation_writer BEFORE INSERT ON slo_violations FOR EACH ROW EXECUTE FUNCTION guard_slo_violation();
