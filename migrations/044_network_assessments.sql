-- Read-only network advice. No route, NAT, IP, endpoint, signing or execution authority.
DO $$ BEGIN
 IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='finops_network_analyst') THEN CREATE ROLE finops_network_analyst NOLOGIN; END IF;
END $$;
GRANT USAGE ON SCHEMA public TO finops_network_analyst;
GRANT SELECT ON tenant_registry,entities,source_registrations,source_revisions,source_receipts,source_checkpoints,workload_safety_profiles,configuration_authority_revisions TO finops_network_analyst;
-- Read-only source-head locking protects both the native SKU metadata join and
-- its analytical projection. This grants no financial write or action right.
GRANT EXECUTE ON FUNCTION financial_source_current_lock(text,text) TO finops_network_analyst,finops_ingester;
CREATE POLICY network_analyst_routing ON tenant_registry FOR SELECT TO finops_network_analyst USING(true);
CREATE TABLE network_evidence_snapshots(
 tenant_id text NOT NULL,id text NOT NULL,resource_id text NOT NULL,source_id text,
 account_id text NOT NULL CHECK(account_id~'^[0-9]{12}$'),region text NOT NULL,
 config_hash text NOT NULL CHECK(config_hash~'^[a-f0-9]{64}$'),content_hash text NOT NULL CHECK(content_hash~'^[a-f0-9]{64}$'),
 document jsonb NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),writer_role name NOT NULL DEFAULT current_user,
 PRIMARY KEY(tenant_id,id),CHECK(octet_length(document::text)<=262144)
);
CREATE INDEX network_evidence_resource ON network_evidence_snapshots(tenant_id,resource_id,created_at DESC,id DESC);
CREATE TABLE network_policies(
 tenant_id text NOT NULL,id text NOT NULL,version bigint NOT NULL CHECK(version>0),resource_id text NOT NULL,
 document jsonb NOT NULL,created_by text NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,id,version),CHECK(octet_length(document::text)<=32768)
);
CREATE TABLE network_assessments(
 tenant_id text NOT NULL,id text NOT NULL,resource_id text NOT NULL,workload_id text,snapshot_id text,
 policy_id text,policy_version bigint,resource_version bigint NOT NULL CHECK(resource_version>0),
 status text NOT NULL DEFAULT 'QUEUED' CHECK(status IN('QUEUED','RUNNING','ASSESSED','BLOCKED','FAILED')),
 document jsonb NOT NULL,created_by text NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,id),FOREIGN KEY(tenant_id,snapshot_id) REFERENCES network_evidence_snapshots(tenant_id,id),
 FOREIGN KEY(tenant_id,policy_id,policy_version) REFERENCES network_policies(tenant_id,id,version)
);
CREATE INDEX network_assessment_queue ON network_assessments(tenant_id,status,created_at,id);
CREATE TABLE network_recommendation_publications(
 tenant_id text NOT NULL,assessment_id text NOT NULL,resource_id text NOT NULL,document jsonb NOT NULL,
 currency text,current_monthly_cost numeric(38,12),candidate_monthly_cost numeric(38,12),created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,assessment_id),FOREIGN KEY(tenant_id,assessment_id) REFERENCES network_assessments(tenant_id,id)
);
DO $$ DECLARE tab text; BEGIN
 FOREACH tab IN ARRAY ARRAY['network_evidence_snapshots','network_policies','network_assessments','network_recommendation_publications'] LOOP
 EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',tab);
 EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',tab);
 EXECUTE format('CREATE POLICY tenant_isolation ON %I USING(tenant_id=current_setting(''app.tenant_id'',true)) WITH CHECK(tenant_id=current_setting(''app.tenant_id'',true))',tab);
 END LOOP;
END $$;
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE ON network_evidence_snapshots FOR EACH ROW EXECUTE FUNCTION deny_evidence_mutation();
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE ON network_policies FOR EACH ROW EXECUTE FUNCTION deny_evidence_mutation();
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE ON network_recommendation_publications FOR EACH ROW EXECUTE FUNCTION deny_evidence_mutation();
GRANT SELECT ON network_evidence_snapshots,network_policies,network_assessments,network_recommendation_publications TO finops_api,finops_ingester,finops_network_analyst;
GRANT INSERT ON network_evidence_snapshots TO finops_ingester;
GRANT INSERT ON network_policies,network_assessments TO finops_api;
GRANT UPDATE ON network_assessments TO finops_network_analyst;
GRANT INSERT ON network_recommendation_publications,audit_events,outbox TO finops_network_analyst;
CREATE FUNCTION guard_network_evidence() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname=current_user) AND current_user<>'finops_ingester' THEN RAISE EXCEPTION 'network evidence requires ingestion identity'; END IF;
 IF NEW.tenant_id IS DISTINCT FROM current_setting('app.tenant_id',true) OR NEW.document->>'schema_version' IS DISTINCT FROM '1'
 OR NEW.document->>'resource_id' IS DISTINCT FROM NEW.resource_id OR NEW.document->>'account_id' IS DISTINCT FROM NEW.account_id OR NEW.document->>'region' IS DISTINCT FROM NEW.region
 OR NEW.document->>'config_hash' IS DISTINCT FROM NEW.config_hash OR NEW.document->>'content_hash' IS DISTINCT FROM NEW.content_hash
 OR coalesce(NEW.document->'archive'->>'version_id','')='' OR NEW.document->'archive'->>'body_sha256' IS DISTINCT FROM NEW.content_hash
 OR NOT EXISTS(SELECT FROM entities r WHERE r.tenant_id=NEW.tenant_id AND r.kind='resources' AND r.id=NEW.resource_id AND r.document->>'provider'='AWS'
 AND r.document->>'resource_type' IN('AVAILABILITY_ZONE','SECURITY_GROUP','VPC_ENDPOINT_SERVICE','FLOW_LOG','AWS_SERVICE_PREFIX_LIST','NAT_GATEWAY','ELASTIC_IP','PUBLIC_IPV4','VPC','SUBNET','ROUTE_TABLE','VPC_ENDPOINT','NETWORK_INTERFACE','INTERNET_GATEWAY','EGRESS_ONLY_INTERNET_GATEWAY','VPC_PEERING','TRANSIT_GATEWAY_ATTACHMENT','LOAD_BALANCER') AND r.document->>'account_id'=NEW.account_id AND r.document->>'region'=NEW.region)
 OR (NEW.source_id IS NOT NULL AND NOT EXISTS(SELECT FROM source_registrations s WHERE s.tenant_id=NEW.tenant_id AND s.id=NEW.source_id AND s.document->>'enabled'='true' AND s.document->>'kind'='AWS_VPC_FLOW_LOGS' AND s.document->>'account_id'=NEW.account_id AND s.document->>'region'=NEW.region)) THEN RAISE EXCEPTION 'network evidence scope invalid'; END IF;
 NEW.writer_role:=current_user; NEW.created_at:=clock_timestamp(); RETURN NEW;
END $$;
CREATE TRIGGER network_evidence_writer BEFORE INSERT ON network_evidence_snapshots FOR EACH ROW EXECUTE FUNCTION guard_network_evidence();
CREATE FUNCTION guard_network_policy() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname=current_user) AND current_user<>'finops_api' THEN RAISE EXCEPTION 'policy requires API identity'; END IF;
 IF NEW.tenant_id IS DISTINCT FROM current_setting('app.tenant_id',true) OR NOT EXISTS(SELECT FROM entities r WHERE r.tenant_id=NEW.tenant_id AND r.kind='resources' AND r.id=NEW.resource_id AND r.document->>'provider'='AWS' AND jsonb_typeof(r.document->'network_configuration')='object' AND r.document->>'resource_type' IN('AVAILABILITY_ZONE','SECURITY_GROUP','VPC_ENDPOINT_SERVICE','FLOW_LOG','AWS_SERVICE_PREFIX_LIST','NAT_GATEWAY','ELASTIC_IP','PUBLIC_IPV4','VPC','SUBNET','ROUTE_TABLE','VPC_ENDPOINT','NETWORK_INTERFACE','INTERNET_GATEWAY','EGRESS_ONLY_INTERNET_GATEWAY','VPC_PEERING','TRANSIT_GATEWAY_ATTACHMENT','LOAD_BALANCER')) THEN RAISE EXCEPTION 'network policy resource scope invalid'; END IF;
 IF NEW.version<>coalesce((SELECT max(version)+1 FROM network_policies WHERE tenant_id=NEW.tenant_id AND id=NEW.id),1) OR EXISTS(SELECT FROM network_policies WHERE tenant_id=NEW.tenant_id AND id=NEW.id AND resource_id<>NEW.resource_id) THEN RAISE EXCEPTION 'policy revision conflict'; END IF;
 NEW.document:=NEW.document||jsonb_build_object('id',NEW.id,'version',NEW.version,'resource_id',NEW.resource_id,'created_at',NEW.created_at); RETURN NEW;
END $$;
CREATE TRIGGER network_policy_writer BEFORE INSERT ON network_policies FOR EACH ROW EXECUTE FUNCTION guard_network_policy();
CREATE FUNCTION guard_network_assessment() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF NEW.tenant_id IS DISTINCT FROM current_setting('app.tenant_id',true)
 OR NOT EXISTS(SELECT FROM entities r WHERE r.tenant_id=NEW.tenant_id AND r.kind='resources' AND r.id=NEW.resource_id AND r.document->>'provider'='AWS'
 AND (r.document->>'workload_id') IS NOT DISTINCT FROM NEW.workload_id AND jsonb_typeof(r.document->'network_configuration')='object'
 AND r.document->>'resource_type' IN('AVAILABILITY_ZONE','SECURITY_GROUP','VPC_ENDPOINT_SERVICE','FLOW_LOG','AWS_SERVICE_PREFIX_LIST','NAT_GATEWAY','ELASTIC_IP','PUBLIC_IPV4','VPC','SUBNET','ROUTE_TABLE','VPC_ENDPOINT','NETWORK_INTERFACE','INTERNET_GATEWAY','EGRESS_ONLY_INTERNET_GATEWAY','VPC_PEERING','TRANSIT_GATEWAY_ATTACHMENT','LOAD_BALANCER'))
 OR (NEW.snapshot_id IS NOT NULL AND NOT EXISTS(SELECT FROM network_evidence_snapshots s WHERE s.tenant_id=NEW.tenant_id AND s.id=NEW.snapshot_id AND s.resource_id=NEW.resource_id))
 OR (NEW.policy_id IS NOT NULL AND NOT EXISTS(SELECT FROM network_policies p WHERE p.tenant_id=NEW.tenant_id AND p.id=NEW.policy_id AND p.version=NEW.policy_version AND p.resource_id=NEW.resource_id)) THEN RAISE EXCEPTION 'network assessment resource/evidence binding invalid'; END IF;
 IF TG_OP='INSERT' THEN
  IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname=current_user) AND current_user<>'finops_api' THEN RAISE EXCEPTION 'network assessment requires API identity'; END IF;
  IF NEW.status<>'QUEUED' OR NEW.document->'assessment' IS DISTINCT FROM 'null'::jsonb THEN RAISE EXCEPTION 'caller cannot supply network assessment'; END IF;
 ELSE
  IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname=current_user) AND current_user<>'finops_network_analyst' THEN RAISE EXCEPTION 'network assessment requires analytical identity'; END IF;
  IF OLD.status IN('ASSESSED','BLOCKED','FAILED') OR (NEW.tenant_id,NEW.id,NEW.resource_id,NEW.workload_id,NEW.snapshot_id,NEW.policy_id,NEW.policy_version,NEW.resource_version,NEW.created_by,NEW.created_at) IS DISTINCT FROM (OLD.tenant_id,OLD.id,OLD.resource_id,OLD.workload_id,OLD.snapshot_id,OLD.policy_id,OLD.policy_version,OLD.resource_version,OLD.created_by,OLD.created_at) THEN RAISE EXCEPTION 'network assessment immutable identity'; END IF;
 END IF;
 IF NEW.status IN('ASSESSED','BLOCKED') AND (NEW.document->'assessment'->>'schema_version' IS DISTINCT FROM '1' OR NEW.document->'assessment'->>'model_kind' IS DISTINCT FROM 'NETWORK_ASSESSMENT_V1' OR NEW.document->'assessment'->'binding'->>'tenant_id' IS DISTINCT FROM NEW.tenant_id OR NEW.document->'assessment'->'binding'->>'resource_id' IS DISTINCT FROM NEW.resource_id OR NEW.document->'assessment'->'pre_execution_ready' IS DISTINCT FROM 'false'::jsonb OR NEW.document->'assessment'->'execution_authorized' IS DISTINCT FROM 'false'::jsonb OR NEW.document->'assessment'->'proposal'->'executable' IS DISTINCT FROM 'false'::jsonb OR NEW.document->'assessment'->'proposal'->'execution_authorized' IS DISTINCT FROM 'false'::jsonb OR NEW.document->'assessment'->'verified_saving' IS DISTINCT FROM 'null'::jsonb) THEN RAISE EXCEPTION 'network advice cannot authorize mutation'; END IF;
 NEW.document:=NEW.document||jsonb_build_object('id',NEW.id,'version',1,'resource_id',NEW.resource_id,'workload_id',NEW.workload_id,'policy_id',NEW.policy_id,'policy_version',NEW.policy_version,'status',NEW.status,'created_at',NEW.created_at);
 NEW.updated_at:=clock_timestamp(); RETURN NEW;
END $$;
CREATE TRIGGER network_assessment_writer BEFORE INSERT OR UPDATE ON network_assessments FOR EACH ROW EXECUTE FUNCTION guard_network_assessment();
CREATE FUNCTION guard_network_publication() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname=current_user) AND current_user<>'finops_network_analyst' THEN RAISE EXCEPTION 'network publication requires analytical identity'; END IF;
 IF NEW.document->>'model_kind' IS DISTINCT FROM 'NETWORK_ASSESSMENT_V1' OR NEW.document->'pre_execution_ready' IS DISTINCT FROM 'false'::jsonb OR NEW.document->'execution_authorized' IS DISTINCT FROM 'false'::jsonb OR NEW.document->>'risk_class' IS DISTINCT FROM 'R3' OR NEW.document->'verified_saving' IS DISTINCT FROM 'null'::jsonb
 OR NOT EXISTS(SELECT FROM network_assessments a WHERE a.tenant_id=NEW.tenant_id AND a.id=NEW.assessment_id AND a.resource_id=NEW.resource_id AND a.status IN('ASSESSED','BLOCKED') AND NEW.document->'assessment'=a.document->'assessment' AND NEW.document->>'network_assessment_id'=a.id AND NEW.document->>'resource_id'=a.resource_id AND (NEW.document->>'workload_id') IS NOT DISTINCT FROM a.workload_id
 AND NEW.currency IS NOT DISTINCT FROM a.document->'assessment'->'economics'->>'currency'
 AND NEW.current_monthly_cost IS NOT DISTINCT FROM (a.document->'assessment'->'economics'->>'current_monthly_cost')::numeric
 AND NEW.candidate_monthly_cost IS NOT DISTINCT FROM (a.document->'assessment'->'economics'->>'candidate_monthly_cost')::numeric) THEN RAISE EXCEPTION 'network publication must match immutable assessment'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER network_publication_writer BEFORE INSERT ON network_recommendation_publications FOR EACH ROW EXECUTE FUNCTION guard_network_publication();

