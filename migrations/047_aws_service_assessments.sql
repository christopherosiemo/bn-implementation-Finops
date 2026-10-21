-- Shared read-only assessments for ECS/Fargate, DynamoDB, ElastiCache and ELB.
DO $$ BEGIN IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='finops_service_analyst') THEN CREATE ROLE finops_service_analyst NOLOGIN; END IF; END $$;
GRANT USAGE ON SCHEMA public TO finops_service_analyst;
GRANT SELECT ON tenant_registry,entities,source_registrations,source_revisions,source_receipts,source_checkpoints,workload_safety_profiles,configuration_authority_revisions,aws_service_evidence_snapshots TO finops_service_analyst;
GRANT SELECT ON slo_objectives,slo_sources,slo_receipts TO finops_service_analyst;
GRANT EXECUTE ON FUNCTION financial_source_current_lock(text,text) TO finops_service_analyst;
CREATE POLICY aws_service_analyst_routing ON tenant_registry FOR SELECT TO finops_service_analyst USING(true);
CREATE TABLE aws_service_assessments(
 tenant_id text NOT NULL,id text NOT NULL,resource_id text NOT NULL,workload_id text,
 family text NOT NULL CHECK(family IN('ECS','DYNAMODB','ELASTICACHE','ELB')),
 snapshot_id text,safety_profile_id text,resource_version bigint NOT NULL CHECK(resource_version>0),
 status text NOT NULL DEFAULT 'QUEUED' CHECK(status IN('QUEUED','RUNNING','ASSESSED','BLOCKED','FAILED')),
 document jsonb NOT NULL,created_by text NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,id),FOREIGN KEY(tenant_id,snapshot_id) REFERENCES aws_service_evidence_snapshots(tenant_id,id),
 FOREIGN KEY(tenant_id,safety_profile_id) REFERENCES workload_safety_profiles(tenant_id,id),CHECK(octet_length(document::text)<=2097152)
);
CREATE INDEX aws_service_assessment_queue ON aws_service_assessments(tenant_id,status,created_at,id);
CREATE TABLE aws_service_recommendation_publications(
 tenant_id text NOT NULL,assessment_id text NOT NULL,resource_id text NOT NULL,document jsonb NOT NULL,
 currency text,current_monthly_cost numeric(38,12),candidate_monthly_cost numeric(38,12),created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,assessment_id),FOREIGN KEY(tenant_id,assessment_id) REFERENCES aws_service_assessments(tenant_id,id)
);
DO $$ DECLARE tab text; BEGIN FOREACH tab IN ARRAY ARRAY['aws_service_assessments','aws_service_recommendation_publications'] LOOP
 EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',tab);EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',tab);
 EXECUTE format('CREATE POLICY tenant_isolation ON %I USING(tenant_id=current_setting(''app.tenant_id'',true)) WITH CHECK(tenant_id=current_setting(''app.tenant_id'',true))',tab);
END LOOP; END $$;
GRANT SELECT ON aws_service_assessments,aws_service_recommendation_publications TO finops_api,finops_service_analyst;
GRANT INSERT ON aws_service_assessments TO finops_api;
GRANT UPDATE ON aws_service_assessments TO finops_service_analyst;
GRANT INSERT ON aws_service_recommendation_publications,audit_events,outbox TO finops_service_analyst;
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE ON aws_service_recommendation_publications FOR EACH ROW EXECUTE FUNCTION deny_evidence_mutation();
CREATE FUNCTION guard_aws_service_assessment() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF NEW.tenant_id IS DISTINCT FROM current_setting('app.tenant_id',true)
 OR NOT EXISTS(SELECT FROM entities r WHERE r.tenant_id=NEW.tenant_id AND r.kind='resources' AND r.id=NEW.resource_id AND r.document->>'provider'='AWS' AND r.document->>'service_family'=NEW.family AND (r.document->>'workload_id') IS NOT DISTINCT FROM NEW.workload_id AND jsonb_typeof(r.document->'aws_service_configuration')='object')
 OR (NEW.snapshot_id IS NOT NULL AND NOT EXISTS(SELECT FROM aws_service_evidence_snapshots s WHERE s.tenant_id=NEW.tenant_id AND s.id=NEW.snapshot_id AND s.resource_id=NEW.resource_id AND s.family=NEW.family))
 OR (NEW.safety_profile_id IS NOT NULL AND NOT EXISTS(SELECT FROM workload_safety_profiles p WHERE p.tenant_id=NEW.tenant_id AND p.id=NEW.safety_profile_id AND p.workload_id=NEW.workload_id)) THEN RAISE EXCEPTION 'AWS service assessment resource/evidence binding invalid'; END IF;
 IF TG_OP='INSERT' THEN
  IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname=current_user) AND current_user<>'finops_api' THEN RAISE EXCEPTION 'AWS service assessment requires API identity'; END IF;
  IF NEW.status<>'QUEUED' OR NEW.document->'assessment' IS DISTINCT FROM 'null'::jsonb THEN RAISE EXCEPTION 'caller cannot supply AWS service assessment'; END IF;
 ELSE
  IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname=current_user) AND current_user<>'finops_service_analyst' THEN RAISE EXCEPTION 'AWS service assessment requires analytical identity'; END IF;
  IF OLD.status IN('ASSESSED','BLOCKED','FAILED') OR (NEW.tenant_id,NEW.id,NEW.resource_id,NEW.workload_id,NEW.family,NEW.snapshot_id,NEW.safety_profile_id,NEW.resource_version,NEW.created_by,NEW.created_at) IS DISTINCT FROM (OLD.tenant_id,OLD.id,OLD.resource_id,OLD.workload_id,OLD.family,OLD.snapshot_id,OLD.safety_profile_id,OLD.resource_version,OLD.created_by,OLD.created_at) THEN RAISE EXCEPTION 'AWS service assessment immutable identity'; END IF;
 END IF;
 IF NEW.status IN('ASSESSED','BLOCKED') AND (NEW.document->'assessment'->>'schema_version' IS DISTINCT FROM '1' OR NEW.document->'assessment'->>'model_kind' IS DISTINCT FROM 'AWS_SERVICE_ASSESSMENT_V1' OR NEW.document->'assessment'->'binding'->>'tenant_id' IS DISTINCT FROM NEW.tenant_id OR NEW.document->'assessment'->'binding'->>'resource_id' IS DISTINCT FROM NEW.resource_id OR NEW.document->'assessment'->>'family' IS DISTINCT FROM NEW.family OR NEW.document->'assessment'->'read_only' IS DISTINCT FROM 'true'::jsonb OR NEW.document->'assessment'->'pre_execution_ready' IS DISTINCT FROM 'false'::jsonb OR NEW.document->'assessment'->'execution_authorized' IS DISTINCT FROM 'false'::jsonb OR NEW.document->'assessment'->'verified_saving' IS DISTINCT FROM 'null'::jsonb) THEN RAISE EXCEPTION 'AWS service advice cannot authorize mutation'; END IF;
 NEW.document:=NEW.document||jsonb_build_object('id',NEW.id,'version',1,'resource_id',NEW.resource_id,'workload_id',NEW.workload_id,'family',NEW.family,'snapshot_id',NEW.snapshot_id,'safety_profile_id',NEW.safety_profile_id,'status',NEW.status,'created_at',NEW.created_at,'created_by',NEW.created_by);
 NEW.updated_at:=clock_timestamp();RETURN NEW;
END $$;
CREATE TRIGGER aws_service_assessment_writer BEFORE INSERT OR UPDATE ON aws_service_assessments FOR EACH ROW EXECUTE FUNCTION guard_aws_service_assessment();
CREATE FUNCTION guard_aws_service_publication() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname=current_user) AND current_user<>'finops_service_analyst' THEN RAISE EXCEPTION 'AWS service publication requires analytical identity'; END IF;
 IF NEW.document->>'model_kind' IS DISTINCT FROM 'AWS_SERVICE_ASSESSMENT_V1' OR NEW.document->'pre_execution_ready' IS DISTINCT FROM 'false'::jsonb OR NEW.document->'execution_authorized' IS DISTINCT FROM 'false'::jsonb OR NEW.document->>'risk_class' IS DISTINCT FROM 'R3' OR NEW.document->'verified_saving' IS DISTINCT FROM 'null'::jsonb
 OR NOT EXISTS(SELECT FROM aws_service_assessments a WHERE a.tenant_id=NEW.tenant_id AND a.id=NEW.assessment_id AND a.resource_id=NEW.resource_id AND a.status IN('ASSESSED','BLOCKED') AND NEW.document->'assessment'=a.document->'assessment' AND NEW.document->>'aws_service_assessment_id'=a.id AND NEW.document->>'resource_id'=a.resource_id AND (NEW.document->>'workload_id') IS NOT DISTINCT FROM a.workload_id AND NEW.currency IS NOT DISTINCT FROM a.document->'assessment'->'economics'->>'currency' AND NEW.current_monthly_cost IS NOT DISTINCT FROM (a.document->'assessment'->'economics'->>'current_monthly_cost')::numeric AND NEW.candidate_monthly_cost IS NOT DISTINCT FROM (a.document->'assessment'->'economics'->>'candidate_monthly_cost')::numeric) THEN RAISE EXCEPTION 'AWS service publication must match immutable assessment'; END IF;RETURN NEW;
END $$;
CREATE TRIGGER aws_service_publication_writer BEFORE INSERT ON aws_service_recommendation_publications FOR EACH ROW EXECUTE FUNCTION guard_aws_service_publication();
