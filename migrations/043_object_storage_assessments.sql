-- Read-only S3 advice. No object, lifecycle, signing or execution authority.
DO $$ BEGIN
 IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='finops_object_storage_analyst') THEN CREATE ROLE finops_object_storage_analyst NOLOGIN; END IF;
END $$;
GRANT USAGE ON SCHEMA public TO finops_object_storage_analyst;
GRANT SELECT ON tenant_registry,entities,source_registrations,source_revisions,source_receipts,source_checkpoints,workload_safety_profiles,configuration_authority_revisions TO finops_object_storage_analyst;
-- Read-only source-head locking protects both the native SKU metadata join and
-- its analytical projection. This grants no financial write or action right.
GRANT EXECUTE ON FUNCTION financial_source_current_lock(text,text) TO finops_object_storage_analyst,finops_ingester;
CREATE POLICY object_storage_analyst_routing ON tenant_registry FOR SELECT TO finops_object_storage_analyst USING(true);
CREATE TABLE object_storage_evidence_snapshots(
 tenant_id text NOT NULL,id text NOT NULL,resource_id text NOT NULL,source_id text,
 account_id text NOT NULL CHECK(account_id~'^[0-9]{12}$'),region text NOT NULL,
 config_hash text NOT NULL CHECK(config_hash~'^[a-f0-9]{64}$'),content_hash text NOT NULL CHECK(content_hash~'^[a-f0-9]{64}$'),
 document jsonb NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),writer_role name NOT NULL DEFAULT current_user,
 PRIMARY KEY(tenant_id,id),CHECK(octet_length(document::text)<=262144)
);
CREATE INDEX object_storage_evidence_resource ON object_storage_evidence_snapshots(tenant_id,resource_id,created_at DESC,id DESC);
CREATE TABLE object_storage_datasets(
 tenant_id text NOT NULL,id text NOT NULL,version bigint NOT NULL CHECK(version>0),resource_id text NOT NULL,
 document jsonb NOT NULL,created_by text NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,id,version),CHECK(octet_length(document::text)<=32768)
);
CREATE TABLE object_storage_assessments(
 tenant_id text NOT NULL,id text NOT NULL,resource_id text NOT NULL,workload_id text,snapshot_id text,
 dataset_id text,dataset_version bigint,resource_version bigint NOT NULL CHECK(resource_version>0),
 status text NOT NULL DEFAULT 'QUEUED' CHECK(status IN('QUEUED','RUNNING','ASSESSED','BLOCKED','FAILED')),
 document jsonb NOT NULL,created_by text NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,id),FOREIGN KEY(tenant_id,snapshot_id) REFERENCES object_storage_evidence_snapshots(tenant_id,id),
 FOREIGN KEY(tenant_id,dataset_id,dataset_version) REFERENCES object_storage_datasets(tenant_id,id,version)
);
CREATE INDEX object_storage_assessment_queue ON object_storage_assessments(tenant_id,status,created_at,id);
CREATE TABLE object_storage_recommendation_publications(
 tenant_id text NOT NULL,assessment_id text NOT NULL,resource_id text NOT NULL,document jsonb NOT NULL,
 currency text,current_monthly_cost numeric(38,12),candidate_monthly_cost numeric(38,12),created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,assessment_id),FOREIGN KEY(tenant_id,assessment_id) REFERENCES object_storage_assessments(tenant_id,id)
);
DO $$ DECLARE tab text; BEGIN
 FOREACH tab IN ARRAY ARRAY['object_storage_evidence_snapshots','object_storage_datasets','object_storage_assessments','object_storage_recommendation_publications'] LOOP
 EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',tab);
 EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',tab);
 EXECUTE format('CREATE POLICY tenant_isolation ON %I USING(tenant_id=current_setting(''app.tenant_id'',true)) WITH CHECK(tenant_id=current_setting(''app.tenant_id'',true))',tab);
 END LOOP;
END $$;
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE ON object_storage_evidence_snapshots FOR EACH ROW EXECUTE FUNCTION deny_evidence_mutation();
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE ON object_storage_datasets FOR EACH ROW EXECUTE FUNCTION deny_evidence_mutation();
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE ON object_storage_recommendation_publications FOR EACH ROW EXECUTE FUNCTION deny_evidence_mutation();
GRANT SELECT ON object_storage_evidence_snapshots,object_storage_datasets,object_storage_assessments,object_storage_recommendation_publications TO finops_api,finops_ingester,finops_object_storage_analyst;
GRANT INSERT ON object_storage_evidence_snapshots TO finops_ingester;
GRANT INSERT ON object_storage_datasets,object_storage_assessments TO finops_api;
GRANT UPDATE ON object_storage_assessments TO finops_object_storage_analyst;
GRANT INSERT ON object_storage_recommendation_publications,audit_events,outbox TO finops_object_storage_analyst;
CREATE FUNCTION guard_object_storage_evidence() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname=current_user) AND current_user<>'finops_ingester' THEN RAISE EXCEPTION 'object evidence requires ingestion identity'; END IF;
 IF NEW.tenant_id IS DISTINCT FROM current_setting('app.tenant_id',true) OR NEW.document->>'schema_version' IS DISTINCT FROM '1'
 OR NEW.document->>'resource_id' IS DISTINCT FROM NEW.resource_id OR NEW.document->>'account_id' IS DISTINCT FROM NEW.account_id OR NEW.document->>'region' IS DISTINCT FROM NEW.region
 OR NEW.document->>'config_hash' IS DISTINCT FROM NEW.config_hash OR NEW.document->>'content_hash' IS DISTINCT FROM NEW.content_hash
 OR coalesce(NEW.document->'archive'->>'version_id','')='' OR NEW.document->'archive'->>'body_sha256' IS DISTINCT FROM NEW.content_hash
 OR NOT EXISTS(SELECT FROM entities r WHERE r.tenant_id=NEW.tenant_id AND r.kind='resources' AND r.id=NEW.resource_id AND r.document->>'provider'='AWS'
 AND r.document->>'resource_type'='S3_BUCKET' AND r.document->>'account_id'=NEW.account_id AND r.document->>'region'=NEW.region)
 OR (NEW.source_id IS NOT NULL AND NOT EXISTS(SELECT FROM source_registrations s WHERE s.tenant_id=NEW.tenant_id AND s.id=NEW.source_id AND s.document->>'enabled'='true' AND s.document->>'kind' LIKE 'AWS_S3_%')) THEN RAISE EXCEPTION 'object evidence scope invalid'; END IF;
 NEW.writer_role:=current_user; NEW.created_at:=clock_timestamp(); RETURN NEW;
END $$;
CREATE TRIGGER object_storage_evidence_writer BEFORE INSERT ON object_storage_evidence_snapshots FOR EACH ROW EXECUTE FUNCTION guard_object_storage_evidence();
CREATE FUNCTION guard_object_storage_dataset() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname=current_user) AND current_user<>'finops_api' THEN RAISE EXCEPTION 'dataset requires API identity'; END IF;
 IF NEW.tenant_id IS DISTINCT FROM current_setting('app.tenant_id',true) OR NOT EXISTS(SELECT FROM entities r WHERE r.tenant_id=NEW.tenant_id AND r.kind='resources' AND r.id=NEW.resource_id AND r.document->>'resource_type'='S3_BUCKET') THEN RAISE EXCEPTION 'dataset bucket scope invalid'; END IF;
 IF NEW.version<>coalesce((SELECT max(version)+1 FROM object_storage_datasets WHERE tenant_id=NEW.tenant_id AND id=NEW.id),1) OR EXISTS(SELECT FROM object_storage_datasets WHERE tenant_id=NEW.tenant_id AND id=NEW.id AND resource_id<>NEW.resource_id) THEN RAISE EXCEPTION 'dataset revision conflict'; END IF;
 NEW.document:=NEW.document||jsonb_build_object('id',NEW.id,'version',NEW.version,'resource_id',NEW.resource_id,'created_at',NEW.created_at); RETURN NEW;
END $$;
CREATE TRIGGER object_storage_dataset_writer BEFORE INSERT ON object_storage_datasets FOR EACH ROW EXECUTE FUNCTION guard_object_storage_dataset();
CREATE FUNCTION guard_object_storage_assessment() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF TG_OP='INSERT' THEN
  IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname=current_user) AND current_user<>'finops_api' THEN RAISE EXCEPTION 'object assessment requires API identity'; END IF;
  IF NEW.status<>'QUEUED' OR NEW.document->'assessment' IS DISTINCT FROM 'null'::jsonb THEN RAISE EXCEPTION 'caller cannot supply object assessment'; END IF;
 ELSE
  IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname=current_user) AND current_user<>'finops_object_storage_analyst' THEN RAISE EXCEPTION 'object assessment requires analytical identity'; END IF;
  IF OLD.status IN('ASSESSED','BLOCKED','FAILED') OR (NEW.tenant_id,NEW.id,NEW.resource_id,NEW.workload_id,NEW.snapshot_id,NEW.dataset_id,NEW.dataset_version,NEW.resource_version,NEW.created_by,NEW.created_at) IS DISTINCT FROM (OLD.tenant_id,OLD.id,OLD.resource_id,OLD.workload_id,OLD.snapshot_id,OLD.dataset_id,OLD.dataset_version,OLD.resource_version,OLD.created_by,OLD.created_at) THEN RAISE EXCEPTION 'object assessment immutable identity'; END IF;
 END IF;
 IF NEW.status IN('ASSESSED','BLOCKED') AND (NEW.document->'assessment'->>'schema_version' IS DISTINCT FROM '1' OR NEW.document->'assessment'->'proposal'->'executable' IS DISTINCT FROM 'false'::jsonb OR NEW.document->'assessment'->'proposal'->'execution_authorized' IS DISTINCT FROM 'false'::jsonb OR NEW.document->'assessment'->'verified_saving' IS DISTINCT FROM 'null'::jsonb) THEN RAISE EXCEPTION 'object advice cannot authorize mutation'; END IF;
 NEW.document:=NEW.document||jsonb_build_object('id',NEW.id,'version',1,'resource_id',NEW.resource_id,'workload_id',NEW.workload_id,'dataset_id',NEW.dataset_id,'dataset_version',NEW.dataset_version,'status',NEW.status,'created_at',NEW.created_at);
 NEW.updated_at:=clock_timestamp(); RETURN NEW;
END $$;
CREATE TRIGGER object_storage_assessment_writer BEFORE INSERT OR UPDATE ON object_storage_assessments FOR EACH ROW EXECUTE FUNCTION guard_object_storage_assessment();
CREATE FUNCTION guard_object_storage_publication() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname=current_user) AND current_user<>'finops_object_storage_analyst' THEN RAISE EXCEPTION 'object publication requires analytical identity'; END IF;
 IF NEW.document->>'model_kind' IS DISTINCT FROM 'OBJECT_STORAGE_ASSESSMENT_V1' OR NEW.document->'pre_execution_ready' IS DISTINCT FROM 'false'::jsonb OR NEW.document->'execution_authorized' IS DISTINCT FROM 'false'::jsonb OR NEW.document->>'risk_class' IS DISTINCT FROM 'R3' OR NEW.document->'verified_saving' IS DISTINCT FROM 'null'::jsonb
 OR NOT EXISTS(SELECT FROM object_storage_assessments a WHERE a.tenant_id=NEW.tenant_id AND a.id=NEW.assessment_id AND a.resource_id=NEW.resource_id AND a.status IN('ASSESSED','BLOCKED') AND NEW.document->'assessment'=a.document->'assessment' AND NEW.document->>'object_storage_assessment_id'=a.id AND NEW.document->>'resource_id'=a.resource_id AND (NEW.document->>'workload_id') IS NOT DISTINCT FROM a.workload_id
 AND NEW.currency IS NOT DISTINCT FROM a.document->'assessment'->'economics'->>'currency'
 AND NEW.current_monthly_cost IS NOT DISTINCT FROM (a.document->'assessment'->'economics'->>'current_monthly_cost')::numeric
 AND NEW.candidate_monthly_cost IS NOT DISTINCT FROM (a.document->'assessment'->'economics'->>'candidate_monthly_cost')::numeric) THEN RAISE EXCEPTION 'object publication must match immutable assessment'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER object_storage_publication_writer BEFORE INSERT ON object_storage_recommendation_publications FOR EACH ROW EXECUTE FUNCTION guard_object_storage_publication();

-- Independently authenticated current application observations. Source scope
-- remains a declaration; it cannot manufacture object-level historical access.
CREATE TABLE object_storage_access_sources(
 tenant_id text NOT NULL,id text NOT NULL,resource_id text NOT NULL,dataset_id text NOT NULL,dataset_version bigint NOT NULL,
 issuer text NOT NULL,subject text NOT NULL,document jsonb NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,id),FOREIGN KEY(tenant_id,dataset_id,dataset_version) REFERENCES object_storage_datasets(tenant_id,id,version),
 CHECK(octet_length(document::text)<=16384)
);
CREATE INDEX object_storage_access_source_resource ON object_storage_access_sources(tenant_id,resource_id,id);
CREATE TABLE object_storage_access_revocations(
 tenant_id text NOT NULL,source_id text NOT NULL,actor text NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,source_id),FOREIGN KEY(tenant_id,source_id) REFERENCES object_storage_access_sources(tenant_id,id)
);
CREATE TABLE object_storage_access_receipts(
 tenant_id text NOT NULL,id text NOT NULL,source_id text NOT NULL,resource_id text NOT NULL,dataset_id text NOT NULL,dataset_version bigint NOT NULL,
 sequence bigint NOT NULL CHECK(sequence>0),interval_start timestamptz NOT NULL,interval_end timestamptz NOT NULL,
 received_at timestamptz NOT NULL DEFAULT activity_receive_time(),body_sha256 text NOT NULL CHECK(body_sha256~'^[a-f0-9]{64}$'),
 idempotency_key text NOT NULL,document jsonb NOT NULL,raw_body bytea NOT NULL,
 PRIMARY KEY(tenant_id,id),FOREIGN KEY(tenant_id,source_id) REFERENCES object_storage_access_sources(tenant_id,id),
 UNIQUE(tenant_id,source_id,sequence),UNIQUE(tenant_id,source_id,interval_start),UNIQUE(tenant_id,source_id,idempotency_key),
 CHECK(interval_end-interval_start=interval '1 minute'),CHECK(octet_length(raw_body)<=16384),CHECK(octet_length(document::text)<=32768)
);
CREATE INDEX object_storage_access_source_window ON object_storage_access_receipts(tenant_id,source_id,interval_start);
DO $$ DECLARE tab text; BEGIN
 FOREACH tab IN ARRAY ARRAY['object_storage_access_sources','object_storage_access_revocations','object_storage_access_receipts'] LOOP
 EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',tab);
 EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',tab);
 EXECUTE format('CREATE POLICY tenant_isolation ON %I USING(tenant_id=current_setting(''app.tenant_id'',true)) WITH CHECK(tenant_id=current_setting(''app.tenant_id'',true))',tab);
 EXECUTE format('CREATE TRIGGER immutable BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION deny_evidence_mutation()',tab);
 END LOOP;
END $$;
GRANT SELECT ON object_storage_access_sources,object_storage_access_revocations,object_storage_access_receipts TO finops_api,finops_activity,finops_object_storage_analyst;
GRANT SELECT(tenant_id,id,resource_id,version) ON object_storage_datasets TO finops_activity;
GRANT INSERT ON object_storage_access_sources,object_storage_access_revocations TO finops_api;
GRANT INSERT ON object_storage_access_receipts TO finops_activity;
CREATE FUNCTION guard_object_storage_access_source() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE resource jsonb;BEGIN
 IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname=current_user) AND current_user<>'finops_api' THEN RAISE EXCEPTION 'object access source requires API identity';END IF;
 IF NEW.tenant_id IS DISTINCT FROM current_setting('app.tenant_id',true) THEN RAISE EXCEPTION 'object access tenant mismatch';END IF;
 SELECT document INTO resource FROM entities WHERE tenant_id=NEW.tenant_id AND kind='resources' AND id=NEW.resource_id;
 IF resource IS NULL OR resource->>'provider' IS DISTINCT FROM 'AWS' OR resource->>'resource_type' IS DISTINCT FROM 'S3_BUCKET'
 OR NEW.document->>'provider_resource_id' IS DISTINCT FROM resource->>'provider_resource_id' OR NEW.document->>'account_id' IS DISTINCT FROM resource->>'account_id' OR NEW.document->>'region' IS DISTINCT FROM resource->>'region'
 OR NEW.document->>'resource_id' IS DISTINCT FROM NEW.resource_id OR NEW.document->>'dataset_id' IS DISTINCT FROM NEW.dataset_id OR (NEW.document->>'dataset_version')::bigint IS DISTINCT FROM NEW.dataset_version
 OR NEW.document->>'issuer' IS DISTINCT FROM NEW.issuer OR NEW.document->>'subject' IS DISTINCT FROM NEW.subject OR length(NEW.issuer)<1 OR length(NEW.subject) NOT BETWEEN 1 AND 2048
 OR NEW.document->'metric_definition'->>'unit' IS DISTINCT FROM 's3-get-requests-and-bytes' OR coalesce(NEW.document->'metric_definition'->>'id','')='' OR coalesce(NEW.document->'metric_definition'->>'version','')=''
 OR jsonb_typeof(NEW.document->'authoritative_access_scope') IS DISTINCT FROM 'boolean'
 OR NOT EXISTS(SELECT FROM object_storage_datasets d WHERE d.tenant_id=NEW.tenant_id AND d.id=NEW.dataset_id AND d.resource_id=NEW.resource_id AND d.version=NEW.dataset_version)
 OR NEW.dataset_version IS DISTINCT FROM (SELECT max(version) FROM object_storage_datasets WHERE tenant_id=NEW.tenant_id AND id=NEW.dataset_id) THEN RAISE EXCEPTION 'object access source binding mismatch';END IF;
 NEW.created_at:=clock_timestamp();
 NEW.document:=NEW.document||jsonb_build_object('id',NEW.id,'version',1,'enabled',true,'created_at',NEW.created_at);
 RETURN NEW;END $$;
CREATE TRIGGER object_storage_access_source_writer BEFORE INSERT ON object_storage_access_sources FOR EACH ROW EXECUTE FUNCTION guard_object_storage_access_source();
CREATE FUNCTION guard_object_storage_access_revocation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname=current_user) AND current_user<>'finops_api' THEN RAISE EXCEPTION 'object access revocation requires API identity';END IF;
 IF NEW.tenant_id IS DISTINCT FROM current_setting('app.tenant_id',true) OR length(NEW.actor)<1 THEN RAISE EXCEPTION 'object access revocation binding mismatch';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id||':object-access:'||NEW.source_id,0));
 NEW.created_at:=clock_timestamp();RETURN NEW;END $$;
CREATE TRIGGER object_storage_access_revocation_writer BEFORE INSERT ON object_storage_access_revocations FOR EACH ROW EXECUTE FUNCTION guard_object_storage_access_revocation();
CREATE FUNCTION guard_object_storage_access_receipt() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE source jsonb;raw jsonb;prior_end timestamptz;prior_sequence bigint;BEGIN
 IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname=current_user) AND current_user<>'finops_activity' THEN RAISE EXCEPTION 'object access receipt requires independent machine identity';END IF;
 IF NEW.tenant_id IS DISTINCT FROM current_setting('app.tenant_id',true) THEN RAISE EXCEPTION 'object access receipt tenant mismatch';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id||':object-access:'||NEW.source_id,0));
 SELECT document INTO source FROM object_storage_access_sources WHERE tenant_id=NEW.tenant_id AND id=NEW.source_id;
 IF source IS NULL OR EXISTS(SELECT FROM object_storage_access_revocations WHERE tenant_id=NEW.tenant_id AND source_id=NEW.source_id)
 OR source->>'resource_id' IS DISTINCT FROM NEW.resource_id OR source->>'dataset_id' IS DISTINCT FROM NEW.dataset_id OR (source->>'dataset_version')::bigint IS DISTINCT FROM NEW.dataset_version
 OR NEW.dataset_version IS DISTINCT FROM (SELECT max(version) FROM object_storage_datasets WHERE tenant_id=NEW.tenant_id AND id=NEW.dataset_id)
 OR source->>'subject' IS DISTINCT FROM NEW.document->>'subject' OR source->>'issuer' IS DISTINCT FROM NEW.document->>'issuer' OR source->'metric_definition' IS DISTINCT FROM NEW.document->'metric_definition' THEN RAISE EXCEPTION 'object access receipt source mismatch';END IF;
 NEW.received_at:=activity_receive_time();
 IF date_trunc('minute',NEW.interval_start)<>NEW.interval_start OR NEW.interval_end>NEW.received_at+interval '5 seconds' OR NEW.interval_end<NEW.received_at-interval '5 minutes' THEN RAISE EXCEPTION 'object access receipt outside current receive window';END IF;
 raw:=convert_from(NEW.raw_body,'UTF8')::jsonb;
 IF jsonb_typeof(raw) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(raw))<>12
 OR raw->>'schema_version' IS DISTINCT FROM '1' OR raw->>'source_id' IS DISTINCT FROM NEW.source_id OR raw->>'resource_id' IS DISTINCT FROM NEW.resource_id OR raw->>'dataset_id' IS DISTINCT FROM NEW.dataset_id
 OR (raw->>'dataset_version')::bigint IS DISTINCT FROM NEW.dataset_version OR (raw->>'sequence')::bigint IS DISTINCT FROM NEW.sequence OR (raw->>'interval_start')::timestamptz IS DISTINCT FROM NEW.interval_start OR (raw->>'interval_end')::timestamptz IS DISTINCT FROM NEW.interval_end
 OR jsonb_typeof(raw->'heartbeat') IS DISTINCT FROM 'boolean' OR jsonb_typeof(raw->'get_requests') IS DISTINCT FROM 'string' OR jsonb_typeof(raw->'retrieved_bytes') IS DISTINCT FROM 'string'
 OR NOT coalesce(raw->>'get_requests','')~'^(0|[1-9][0-9]{0,25})$' OR NOT coalesce(raw->>'retrieved_bytes','')~'^(0|[1-9][0-9]{0,25})$'
 OR (raw->>'get_requests'='0' AND raw->>'retrieved_bytes'<>'0')
 OR encode(sha256(NEW.raw_body),'hex') IS DISTINCT FROM NEW.body_sha256
 OR (raw-ARRAY['interval_start','interval_end']) IS DISTINCT FROM (NEW.document-ARRAY['id','tenant_id','issuer','subject','received_at','body_sha256','idempotency_key','binding','interval_start','interval_end']) THEN RAISE EXCEPTION 'object access raw body mismatch';END IF;
 IF NEW.document->>'tenant_id' IS DISTINCT FROM NEW.tenant_id OR NEW.document->>'id' IS DISTINCT FROM NEW.id OR NEW.document->>'idempotency_key' IS DISTINCT FROM NEW.idempotency_key OR NEW.document->>'body_sha256' IS DISTINCT FROM NEW.body_sha256
 OR NEW.document->'binding' IS DISTINCT FROM jsonb_build_object('tenant_id',NEW.tenant_id,'resource_id',NEW.resource_id,'dataset_id',NEW.dataset_id,'dataset_version',NEW.dataset_version,'provider_resource_id',source->>'provider_resource_id','account_id',source->>'account_id','region',source->>'region') THEN RAISE EXCEPTION 'object access provider binding mismatch';END IF;
 SELECT interval_end,sequence INTO prior_end,prior_sequence FROM object_storage_access_receipts WHERE tenant_id=NEW.tenant_id AND source_id=NEW.source_id ORDER BY sequence DESC LIMIT 1;
 IF NEW.sequence<=prior_sequence OR NEW.interval_start<prior_end THEN RAISE EXCEPTION 'object access sequence or interval moved backwards';END IF;
 NEW.document:=NEW.document||jsonb_build_object('received_at',NEW.received_at);RETURN NEW;END $$;
CREATE TRIGGER object_storage_access_receipt_writer BEFORE INSERT ON object_storage_access_receipts FOR EACH ROW EXECUTE FUNCTION guard_object_storage_access_receipt();
