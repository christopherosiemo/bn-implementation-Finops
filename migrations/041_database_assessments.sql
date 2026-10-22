-- Read-only AWS database advice. No provider execution or signing authority.
DO $$ BEGIN
 IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='finops_database_analyst') THEN CREATE ROLE finops_database_analyst NOLOGIN; END IF;
END $$;
GRANT USAGE ON SCHEMA public TO finops_database_analyst;
GRANT SELECT ON tenant_registry,entities,source_registrations,source_revisions,source_receipts,source_checkpoints,workload_safety_profiles TO finops_database_analyst;
GRANT SELECT ON slo_objectives,slo_sources,slo_receipts TO finops_database_analyst;
GRANT EXECUTE ON FUNCTION financial_source_current_lock(text,text) TO finops_database_analyst;
CREATE POLICY database_analyst_routing ON tenant_registry FOR SELECT TO finops_database_analyst USING(true);

CREATE TABLE database_evidence_snapshots(
 tenant_id text NOT NULL,id text NOT NULL,resource_id text NOT NULL,
 account_id text NOT NULL CHECK(account_id~'^[0-9]{12}$'),region text NOT NULL,
 config_hash text NOT NULL CHECK(config_hash~'^[a-f0-9]{64}$'),
 content_hash text NOT NULL CHECK(content_hash~'^[a-f0-9]{64}$'),document jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),writer_role name NOT NULL DEFAULT current_user,
 PRIMARY KEY(tenant_id,id),CHECK(octet_length(document::text)<=262144)
);
CREATE INDEX database_evidence_resource ON database_evidence_snapshots(tenant_id,resource_id,created_at DESC,id DESC);
CREATE TABLE database_assessments(
 tenant_id text NOT NULL,id text NOT NULL,resource_id text NOT NULL,workload_id text,
 snapshot_id text,resource_version bigint NOT NULL CHECK(resource_version>0),
 safety_profile_id text,status text NOT NULL DEFAULT 'QUEUED' CHECK(status IN('QUEUED','RUNNING','ASSESSED','BLOCKED','FAILED')),
 document jsonb NOT NULL,created_by text NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,id),FOREIGN KEY(tenant_id,snapshot_id) REFERENCES database_evidence_snapshots(tenant_id,id)
);
CREATE INDEX database_assessment_queue ON database_assessments(tenant_id,status,created_at,id);
CREATE TABLE database_recommendation_publications(
 tenant_id text NOT NULL,assessment_id text NOT NULL,resource_id text NOT NULL,document jsonb NOT NULL,
 current_hourly_cost numeric(38,12),candidate_hourly_cost numeric(38,12),currency text,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,assessment_id),FOREIGN KEY(tenant_id,assessment_id) REFERENCES database_assessments(tenant_id,id)
);
DO $$ DECLARE tab text;BEGIN
 FOREACH tab IN ARRAY ARRAY['database_evidence_snapshots','database_assessments','database_recommendation_publications'] LOOP
 EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',tab);
 EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',tab);
 EXECUTE format('CREATE POLICY tenant_isolation ON %I USING(tenant_id=current_setting(''app.tenant_id'',true)) WITH CHECK(tenant_id=current_setting(''app.tenant_id'',true))',tab);
 END LOOP;
END $$;
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE ON database_evidence_snapshots FOR EACH ROW EXECUTE FUNCTION deny_evidence_mutation();
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE ON database_recommendation_publications FOR EACH ROW EXECUTE FUNCTION deny_evidence_mutation();
GRANT SELECT ON database_evidence_snapshots,database_assessments,database_recommendation_publications TO finops_api,finops_ingester,finops_database_analyst;
GRANT INSERT ON database_evidence_snapshots TO finops_ingester;
GRANT INSERT ON database_assessments TO finops_api;
GRANT UPDATE ON database_assessments TO finops_database_analyst;
GRANT INSERT ON database_recommendation_publications,audit_events,outbox TO finops_database_analyst;

CREATE FUNCTION guard_database_evidence() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname=current_user) AND current_user<>'finops_ingester' THEN RAISE EXCEPTION 'database evidence requires ingestion identity';END IF;
 IF NEW.tenant_id IS DISTINCT FROM current_setting('app.tenant_id',true) OR
 NEW.document->>'resource_id' IS DISTINCT FROM NEW.resource_id OR
 NEW.document->>'account_id' IS DISTINCT FROM NEW.account_id OR
 NEW.document->>'region' IS DISTINCT FROM NEW.region OR
 NEW.document->>'config_hash' IS DISTINCT FROM NEW.config_hash OR
 NEW.document->>'content_hash' IS DISTINCT FROM NEW.content_hash OR
 NEW.document->>'schema_version' IS DISTINCT FROM '1' OR
 coalesce(NEW.document->'archive'->>'version_id','')='' OR NEW.document->'archive'->>'body_sha256' IS DISTINCT FROM NEW.content_hash OR
 NOT EXISTS(SELECT FROM entities r WHERE r.tenant_id=NEW.tenant_id AND r.kind='resources' AND r.id=NEW.resource_id
 AND r.document->>'account_id'=NEW.account_id AND r.document->>'region'=NEW.region
 AND r.document->>'resource_type' IN('RDS_INSTANCE','RDS_CLUSTER')) THEN RAISE EXCEPTION 'database evidence binding invalid';END IF;
 NEW.writer_role:=current_user;NEW.created_at:=clock_timestamp();RETURN NEW;
END $$;
CREATE TRIGGER database_evidence_writer BEFORE INSERT ON database_evidence_snapshots FOR EACH ROW EXECUTE FUNCTION guard_database_evidence();
CREATE FUNCTION guard_database_assessment() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF TG_OP='INSERT' THEN
  IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname=current_user) AND current_user<>'finops_api' THEN RAISE EXCEPTION 'database assessment request requires API identity';END IF;
  IF NEW.status<>'QUEUED' OR NEW.document->'assessment' IS DISTINCT FROM 'null'::jsonb THEN RAISE EXCEPTION 'database request cannot supply assessment results';END IF;
 ELSE
  IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname=current_user) AND current_user<>'finops_database_analyst' THEN RAISE EXCEPTION 'database assessment requires analytical identity';END IF;
  IF OLD.status IN('ASSESSED','BLOCKED','FAILED') OR (NEW.tenant_id,NEW.id,NEW.resource_id,NEW.workload_id,NEW.snapshot_id,NEW.resource_version,NEW.safety_profile_id,NEW.created_by,NEW.created_at)
   IS DISTINCT FROM (OLD.tenant_id,OLD.id,OLD.resource_id,OLD.workload_id,OLD.snapshot_id,OLD.resource_version,OLD.safety_profile_id,OLD.created_by,OLD.created_at) THEN RAISE EXCEPTION 'database assessment identity or completed result is immutable';END IF;
 END IF;
 IF NEW.status IN('ASSESSED','BLOCKED') AND (
 NEW.document->'assessment'->>'schema_version' IS DISTINCT FROM '1' OR
 NEW.document->'assessment'->'proposal'->'executable' IS DISTINCT FROM 'false'::jsonb OR
 NEW.document->'assessment'->'proposal'->'execution_authorized' IS DISTINCT FROM 'false'::jsonb OR
 NEW.document->'assessment'->'proposal'->>'risk_class' IS DISTINCT FROM 'R3' OR
 NEW.document->'assessment'->'verified_saving' IS DISTINCT FROM 'null'::jsonb
 ) THEN RAISE EXCEPTION 'completed database assessment cannot authorize execution or verified savings';END IF;
 NEW.document:=NEW.document||jsonb_build_object('id',NEW.id,'version',1,'resource_id',NEW.resource_id,'workload_id',NEW.workload_id,'status',NEW.status,'created_at',NEW.created_at);
 NEW.updated_at:=clock_timestamp();RETURN NEW;
END $$;
CREATE TRIGGER database_assessment_writer BEFORE INSERT OR UPDATE ON database_assessments FOR EACH ROW EXECUTE FUNCTION guard_database_assessment();
CREATE FUNCTION guard_database_publication() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname=current_user) AND current_user<>'finops_database_analyst' THEN RAISE EXCEPTION 'database recommendation requires analytical identity';END IF;
 IF NEW.document->>'model_kind' IS DISTINCT FROM 'DATABASE_ASSESSMENT_V1' OR NEW.document->'pre_execution_ready' IS DISTINCT FROM 'false'::jsonb
 OR NEW.document->'execution_authorized' IS DISTINCT FROM 'false'::jsonb OR NEW.document->>'risk_class' IS DISTINCT FROM 'R3'
 OR NEW.document->'verified_saving' IS DISTINCT FROM 'null'::jsonb OR NOT EXISTS(SELECT FROM database_assessments a WHERE a.tenant_id=NEW.tenant_id AND a.id=NEW.assessment_id AND a.resource_id=NEW.resource_id AND a.status IN('ASSESSED','BLOCKED')
 AND NEW.document->>'database_assessment_id'=a.id AND NEW.document->>'resource_id'=a.resource_id
 AND (NEW.document->>'workload_id') IS NOT DISTINCT FROM a.workload_id
 AND NEW.document->'assessment'=a.document->'assessment'
 AND NEW.document->>'status'=a.document->'assessment'->>'status'
 AND NEW.current_hourly_cost IS NOT DISTINCT FROM (a.document->'assessment'->'economics'->>'current_hourly_cost')::numeric
 AND NEW.candidate_hourly_cost IS NOT DISTINCT FROM (a.document->'assessment'->'economics'->>'candidate_hourly_cost')::numeric
 AND NEW.currency IS NOT DISTINCT FROM a.document->'assessment'->'economics'->>'currency'
 ) THEN RAISE EXCEPTION 'database advice is read-only and bound to an assessment';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER database_publication_writer BEFORE INSERT ON database_recommendation_publications FOR EACH ROW EXECUTE FUNCTION guard_database_publication();
