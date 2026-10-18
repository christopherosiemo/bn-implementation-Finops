-- Private machine observations. No declaration, receipt or archived artifact
-- grants approval/signing/execution or financial-ledger authority.
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='finops_configuration_attestor') THEN CREATE ROLE finops_configuration_attestor NOLOGIN;END IF;
 IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='finops_configuration_attestor' AND (rolsuper OR rolcreaterole OR rolcreatedb OR rolbypassrls OR rolreplication OR rolcanlogin)) OR EXISTS(SELECT 1 FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.member WHERE r.rolname='finops_configuration_attestor') THEN RAISE EXCEPTION 'configuration attestor group must be independent';END IF;
END $$;
GRANT USAGE ON SCHEMA public TO finops_configuration_attestor;
GRANT SELECT ON entities,configuration_authority_revisions TO finops_configuration_attestor;
CREATE POLICY configuration_attestor_inventory_only ON entities AS RESTRICTIVE FOR SELECT TO finops_configuration_attestor USING(kind IN('resources','workloads'));

CREATE TABLE configuration_artifact_registrations(
 tenant_id text NOT NULL,id text NOT NULL,version bigint NOT NULL CHECK(version>0),resource_id text NOT NULL,authority_id text NOT NULL,
 document jsonb NOT NULL CHECK(pg_column_size(document)<=65536),content_hash text NOT NULL CHECK(content_hash~'^[a-f0-9]{64}$'),
 writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,id,version),FOREIGN KEY(tenant_id,authority_id) REFERENCES configuration_authority_revisions(tenant_id,id)
);
CREATE TABLE configuration_artifact_revocations(
 tenant_id text NOT NULL,registration_id text NOT NULL,registration_version bigint NOT NULL,reason_code text NOT NULL CHECK(reason_code~'^[A-Z][A-Z0-9_]{0,119}$'),
 writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,registration_id,registration_version),FOREIGN KEY(tenant_id,registration_id,registration_version) REFERENCES configuration_artifact_registrations(tenant_id,id,version)
);
CREATE TABLE configuration_artifact_jobs(
 tenant_id text NOT NULL,id text NOT NULL,registration_id text NOT NULL,registration_version bigint NOT NULL,idempotency_key text NOT NULL CHECK(length(idempotency_key) BETWEEN 8 AND 200),
 request_hash text NOT NULL CHECK(request_hash~'^[a-f0-9]{64}$'),metadata jsonb NOT NULL CHECK(pg_column_size(metadata)<=65536),
 writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,id),UNIQUE(tenant_id,registration_id,idempotency_key),FOREIGN KEY(tenant_id,registration_id,registration_version) REFERENCES configuration_artifact_registrations(tenant_id,id,version)
);
CREATE TABLE configuration_artifact_archives(
 tenant_id text NOT NULL,job_id text NOT NULL,document jsonb NOT NULL CHECK(pg_column_size(document)<=8192),
 writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,job_id),FOREIGN KEY(tenant_id,job_id) REFERENCES configuration_artifact_jobs(tenant_id,id)
);
CREATE TABLE configuration_artifact_receipts(
 tenant_id text NOT NULL,id text NOT NULL,job_id text NOT NULL,document jsonb NOT NULL CHECK(pg_column_size(document)<=131072),
 writer_role text NOT NULL DEFAULT current_user,observed_at timestamptz NOT NULL DEFAULT clock_timestamp(),received_at timestamptz NOT NULL DEFAULT clock_timestamp(),expires_at timestamptz NOT NULL DEFAULT clock_timestamp()+interval '15 minutes',
 PRIMARY KEY(tenant_id,id),UNIQUE(tenant_id,job_id),FOREIGN KEY(tenant_id,job_id) REFERENCES configuration_artifact_jobs(tenant_id,id)
);
CREATE FUNCTION configuration_artifact_current(p_tenant text,p_registration text,p_version bigint) RETURNS jsonb LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE r configuration_artifact_registrations;a configuration_authority_revisions;resource jsonb;rv bigint;
BEGIN
 IF p_tenant IS DISTINCT FROM current_setting('app.tenant_id',true) THEN RAISE EXCEPTION 'configuration artifact tenant mismatch';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(p_tenant||':dependency-graph',0));
 PERFORM pg_advisory_xact_lock(hashtextextended(p_tenant||':configuration-artifact:'||p_registration,0));
 SELECT * INTO r FROM configuration_artifact_registrations WHERE tenant_id=p_tenant AND id=p_registration ORDER BY version DESC LIMIT 1;
 IF r.id IS NULL OR r.version IS DISTINCT FROM p_version OR EXISTS(SELECT 1 FROM configuration_artifact_revocations WHERE tenant_id=p_tenant AND registration_id=p_registration AND registration_version=p_version) THEN RAISE EXCEPTION 'configuration artifact registration inactive';END IF;
 SELECT * INTO a FROM configuration_authority_revisions WHERE tenant_id=p_tenant AND resource_id=r.resource_id ORDER BY version DESC LIMIT 1;
 SELECT document,version INTO resource,rv FROM entities WHERE tenant_id=p_tenant AND kind='resources' AND id=r.resource_id;
 IF a.id IS DISTINCT FROM r.authority_id OR resource IS NULL OR rv IS DISTINCT FROM a.resource_version OR a.resource_snapshot IS DISTINCT FROM(resource||jsonb_build_object('id',r.resource_id,'version',rv)) OR r.document->'binding' IS DISTINCT FROM a.document->'binding' OR r.document->>'authority_hash' IS DISTINCT FROM a.content_hash THEN RAISE EXCEPTION 'configuration artifact declaration superseded';END IF;
 RETURN r.document;
END $$;
REVOKE ALL ON FUNCTION configuration_artifact_current(text,text,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION configuration_artifact_current(text,text,bigint) TO finops_configuration_attestor;
CREATE FUNCTION guard_configuration_artifact() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE cfg jsonb;a configuration_authority_revisions;j configuration_artifact_jobs;ref jsonb;prior bigint;
BEGIN
 IF current_user<>'finops_configuration_attestor' OR NEW.tenant_id IS DISTINCT FROM current_setting('app.tenant_id',true) THEN RAISE EXCEPTION 'configuration artifact dedicated writer required';END IF;
 NEW.writer_role:='finops_configuration_attestor';
 IF TG_TABLE_NAME='configuration_artifact_registrations' THEN
  PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id||':dependency-graph',0));
  PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id||':configuration-artifact:'||NEW.id,0));
  SELECT coalesce(max(version),0) INTO prior FROM configuration_artifact_registrations WHERE tenant_id=NEW.tenant_id AND id=NEW.id;
  SELECT * INTO a FROM configuration_authority_revisions WHERE tenant_id=NEW.tenant_id AND id=NEW.authority_id AND resource_id=NEW.resource_id;
  IF NEW.version<>prior+1 OR a.id IS NULL OR NEW.document-ARRAY['schema_version','id','version','binding','authority_id','authority_version','authority_hash','declaration','issuer','audience','subject','pipeline_id','toolchain']<>'{}'::jsonb OR NEW.document->>'schema_version' IS DISTINCT FROM '1' OR NEW.document->>'id' IS DISTINCT FROM NEW.id OR NEW.document->'version' IS DISTINCT FROM to_jsonb(NEW.version) OR NEW.document->'binding' IS DISTINCT FROM a.document->'binding' OR NEW.document->>'authority_id' IS DISTINCT FROM a.id OR NEW.document->'authority_version' IS DISTINCT FROM to_jsonb(a.version) OR NEW.document->>'authority_hash' IS DISTINCT FROM a.content_hash THEN RAISE EXCEPTION 'configuration artifact registration binding invalid';END IF;
  IF NEW.document->'declaration' IS DISTINCT FROM jsonb_build_object('schema_version',a.document->'schema_version','authority',a.document->'authority','repository',a.document->'repository','pipeline',a.document->'pipeline','terraform',a.document->'terraform') OR NEW.document->>'issuer' IS DISTINCT FROM a.document->'pipeline'->'identity'->>'issuer' OR NEW.document->>'subject' IS DISTINCT FROM a.document->'pipeline'->'identity'->>'subject' OR NEW.document->>'pipeline_id' IS DISTINCT FROM a.document->'pipeline'->'identity'->>'pipeline_id' OR NEW.document->>'audience' IS DISTINCT FROM 'finops-configuration-attestor' THEN RAISE EXCEPTION 'configuration artifact machine not registered';END IF;
  IF jsonb_typeof(NEW.document->'toolchain') IS DISTINCT FROM 'object' OR NOT(NEW.document->'toolchain' ?& ARRAY['terraform_version','image','os','architecture','working_directory']) OR (NEW.document->'toolchain')-ARRAY['terraform_version','image','os','architecture','working_directory']<>'{}'::jsonb OR NEW.document->'toolchain'->>'os' IS DISTINCT FROM 'linux' OR coalesce(NEW.document->'toolchain'->>'architecture','') NOT IN('amd64','arm64') OR coalesce(NEW.document->'toolchain'->>'terraform_version','')!~'^[0-9]+\.[0-9]+\.[0-9]+$' OR coalesce(NEW.document->'toolchain'->>'image','')!~'^[a-z0-9./:_-]+@sha256:[a-f0-9]{64}$' OR coalesce(NEW.document->'toolchain'->>'working_directory','')!~'^/workspace(/[^[:space:]]*)?$' THEN RAISE EXCEPTION 'configuration artifact toolchain metadata invalid';END IF;
  NEW.created_at:=clock_timestamp();RETURN NEW;
 END IF;
 IF TG_TABLE_NAME='configuration_artifact_revocations' THEN PERFORM configuration_artifact_current(NEW.tenant_id,NEW.registration_id,NEW.registration_version);NEW.created_at:=clock_timestamp();RETURN NEW;END IF;
 IF TG_TABLE_NAME='configuration_artifact_jobs' THEN
  cfg:=configuration_artifact_current(NEW.tenant_id,NEW.registration_id,NEW.registration_version);
  IF NOT(NEW.metadata ?& ARRAY['schema_version','registration_id','registration_version','registration_hash','binding','authority_id','authority_version','authority_hash','git','toolchain','state','bundle_sha256','saved_plan_sha256','plan_json_sha256','state_sha256','status','reason_codes','execution_authorized','verified_saving']) OR NEW.metadata-ARRAY['schema_version','registration_id','registration_version','registration_hash','binding','authority_id','authority_version','authority_hash','git','toolchain','state','bundle_sha256','saved_plan_sha256','plan_json_sha256','state_sha256','status','reason_codes','execution_authorized','verified_saving']<>'{}'::jsonb OR NEW.metadata->>'schema_version' IS DISTINCT FROM '1' OR NEW.metadata->>'registration_id' IS DISTINCT FROM NEW.registration_id OR NEW.metadata->'registration_version' IS DISTINCT FROM to_jsonb(NEW.registration_version) OR NEW.metadata->'binding' IS DISTINCT FROM cfg->'binding' OR NEW.metadata->>'authority_id' IS DISTINCT FROM cfg->>'authority_id' OR NEW.metadata->'authority_version' IS DISTINCT FROM cfg->'authority_version' OR NEW.metadata->>'authority_hash' IS DISTINCT FROM cfg->>'authority_hash' OR NEW.metadata->'toolchain' IS DISTINCT FROM cfg->'toolchain' OR coalesce(NEW.metadata->>'status','') NOT IN('OBSERVED','BLOCKED') OR NEW.metadata->'execution_authorized' IS DISTINCT FROM 'false'::jsonb OR NEW.metadata->'verified_saving' IS DISTINCT FROM 'null'::jsonb OR jsonb_typeof(NEW.metadata->'reason_codes') IS DISTINCT FROM 'array' OR NOT(NEW.metadata->'reason_codes' @> '["NO_EXECUTION_AUTHORITY","REMOTE_GIT_HEAD_UNVERIFIED","NATIVE_STATE_FRESHNESS_UNPROVEN"]'::jsonb) THEN RAISE EXCEPTION 'configuration artifact cannot grant authority';END IF;
  IF (NEW.metadata->'git')-ARRAY['commit','tree','ref','configuration_sha256','dependency_sha256']<>'{}'::jsonb OR (NEW.metadata->'state')-ARRAY['lineage','serial','workspace']<>'{}'::jsonb OR NEW.metadata->'state'->>'lineage' IS DISTINCT FROM cfg->'declaration'->'terraform'->>'state_lineage' OR NEW.metadata->'state'->>'workspace' IS DISTINCT FROM cfg->'declaration'->'terraform'->>'workspace' OR NEW.metadata->'git'->>'ref' IS DISTINCT FROM cfg->'declaration'->'repository'->>'ref' THEN RAISE EXCEPTION 'configuration artifact metadata invalid';END IF;
  IF jsonb_typeof(NEW.metadata->'git') IS DISTINCT FROM 'object' OR NOT(NEW.metadata->'git' ?& ARRAY['commit','tree','ref','configuration_sha256','dependency_sha256']) OR coalesce(NEW.metadata->'git'->>'commit','')!~'^([a-f0-9]{40}|[a-f0-9]{64})$' OR coalesce(NEW.metadata->'git'->>'tree','')!~'^([a-f0-9]{40}|[a-f0-9]{64})$' OR jsonb_typeof(NEW.metadata->'state'->'serial') IS DISTINCT FROM 'number' OR coalesce(NEW.metadata->'state'->>'serial','')!~'^(0|[1-9][0-9]*)$' OR (NEW.metadata->'state'->>'serial')::numeric>9223372036854775807 THEN RAISE EXCEPTION 'configuration artifact exact Git and state provenance required';END IF;
  FOREACH ref IN ARRAY ARRAY[NEW.metadata->'registration_hash',NEW.metadata->'bundle_sha256',NEW.metadata->'saved_plan_sha256',NEW.metadata->'plan_json_sha256',NEW.metadata->'state_sha256',NEW.metadata->'git'->'configuration_sha256',NEW.metadata->'git'->'dependency_sha256'] LOOP IF coalesce(ref#>>'{}','')!~'^[a-f0-9]{64}$' THEN RAISE EXCEPTION 'configuration artifact digest required';END IF;END LOOP;
  NEW.created_at:=clock_timestamp();RETURN NEW;
 END IF;
 SELECT * INTO j FROM configuration_artifact_jobs WHERE tenant_id=NEW.tenant_id AND id=NEW.job_id;
 IF j.id IS NULL THEN RAISE EXCEPTION 'configuration artifact job missing';END IF;
 cfg:=configuration_artifact_current(NEW.tenant_id,j.registration_id,j.registration_version);
 IF TG_TABLE_NAME='configuration_artifact_archives' THEN
  ref:=NEW.document;
  IF NOT(ref ?& ARRAY['bucket','key','version_id','sha256','bytes']) OR ref-ARRAY['bucket','key','version_id','sha256','bytes']<>'{}'::jsonb OR coalesce(ref->>'bucket','')!~'^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$' OR coalesce(ref->>'version_id','') IN('','null') OR length(ref->>'version_id')>1024 OR coalesce(ref->>'sha256','')!~'^[a-f0-9]{64}$' OR ref->'bytes' IS NULL OR ref->'bytes'='null'::jsonb OR (ref->>'bytes')::bigint NOT BETWEEN 1 AND 134217728 OR NOT starts_with(coalesce(ref->>'key',''),'tenant/'||NEW.tenant_id||'/configuration-artifacts/'||NEW.job_id||'/') OR position('..' IN ref->>'key')>0 OR position(chr(92) IN ref->>'key')>0 THEN RAISE EXCEPTION 'configuration artifact encrypted version required';END IF;
  NEW.created_at:=clock_timestamp();RETURN NEW;
 END IF;
 SELECT document INTO ref FROM configuration_artifact_archives WHERE tenant_id=NEW.tenant_id AND job_id=NEW.job_id;
 IF ref IS NULL OR NEW.document-ARRAY['id','job_id','metadata','archive','observed_at','received_at','expires_at']<>'{}'::jsonb OR NEW.document->>'id' IS DISTINCT FROM NEW.id OR NEW.document->>'job_id' IS DISTINCT FROM NEW.job_id OR NEW.document->'metadata' IS DISTINCT FROM j.metadata OR NEW.document->'archive' IS DISTINCT FROM ref THEN RAISE EXCEPTION 'configuration artifact publication incomplete';END IF;
 NEW.observed_at:=j.created_at;NEW.received_at:=clock_timestamp();NEW.expires_at:=NEW.observed_at+interval '15 minutes';NEW.document:=NEW.document||jsonb_build_object('observed_at',NEW.observed_at,'received_at',NEW.received_at,'expires_at',NEW.expires_at);RETURN NEW;
END $$;
CREATE FUNCTION configuration_artifact_immutable() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$ BEGIN RAISE EXCEPTION 'configuration artifact evidence is append only';END $$;
DO $$ DECLARE tab text;BEGIN
 FOREACH tab IN ARRAY ARRAY['configuration_artifact_registrations','configuration_artifact_revocations','configuration_artifact_jobs','configuration_artifact_archives','configuration_artifact_receipts'] LOOP
  EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',tab);EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',tab);
  EXECUTE format('CREATE POLICY tenant_isolation ON %I USING(tenant_id=current_setting(''app.tenant_id'',true)) WITH CHECK(tenant_id=current_setting(''app.tenant_id'',true))',tab);
  EXECUTE format('CREATE TRIGGER immutable BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION configuration_artifact_immutable()',tab);
  EXECUTE format('CREATE TRIGGER writer BEFORE INSERT ON %I FOR EACH ROW EXECUTE FUNCTION guard_configuration_artifact()',tab);
  EXECUTE format('GRANT SELECT,INSERT ON %I TO finops_configuration_attestor',tab);EXECUTE format('GRANT SELECT ON %I TO finops_api',tab);
 END LOOP;
END $$;
REVOKE ALL ON FUNCTION guard_configuration_artifact(),configuration_artifact_immutable() FROM PUBLIC;
