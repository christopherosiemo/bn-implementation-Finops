-- Account commissioning observes read access and persisted evidence; it grants
-- no customer mutation, signing, purchasing or financial-write authority.
CREATE TABLE aws_account_preflights(
 tenant_id text NOT NULL,id text NOT NULL,cloud_account_id text NOT NULL,
 cloud_account_version bigint NOT NULL CHECK(cloud_account_version>0),
 account_id text NOT NULL CHECK(account_id~'^[0-9]{12}$'),region text NOT NULL CHECK(region='eu-west-1'),
 read_role_binding_id text NOT NULL CHECK(length(read_role_binding_id) BETWEEN 1 AND 128),
 status text NOT NULL DEFAULT 'QUEUED' CHECK(status IN('QUEUED','RUNNING','COMPLETED','FAILED')),
 created_by text NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 lease_token text,lease_until timestamptz,report_id text,reason_code text,
 PRIMARY KEY(tenant_id,id)
);
CREATE INDEX aws_account_preflight_queue ON aws_account_preflights(tenant_id,status,created_at,id);
CREATE TABLE aws_account_commissioning_reports(
 tenant_id text NOT NULL,id text NOT NULL,preflight_id text NOT NULL,
 document jsonb NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,id),UNIQUE(tenant_id,preflight_id),
 FOREIGN KEY(tenant_id,preflight_id) REFERENCES aws_account_preflights(tenant_id,id),
 CHECK(octet_length(document::text)<=2097152)
);
DO $$ DECLARE tab text; BEGIN FOREACH tab IN ARRAY ARRAY['aws_account_preflights','aws_account_commissioning_reports'] LOOP
 EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',tab);
 EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',tab);
 EXECUTE format('CREATE POLICY tenant_isolation ON %I USING(tenant_id=current_setting(''app.tenant_id'',true)) WITH CHECK(tenant_id=current_setting(''app.tenant_id'',true))',tab);
END LOOP; END $$;
GRANT SELECT ON aws_account_preflights,aws_account_commissioning_reports TO finops_api,finops_ingester;
GRANT INSERT ON aws_account_preflights TO finops_api;
GRANT UPDATE ON aws_account_preflights TO finops_ingester;
GRANT INSERT ON aws_account_commissioning_reports TO finops_ingester;
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE ON aws_account_commissioning_reports FOR EACH ROW EXECUTE FUNCTION deny_evidence_mutation();
CREATE FUNCTION guard_aws_account_preflight() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF NEW.tenant_id IS DISTINCT FROM current_setting('app.tenant_id',true) THEN RAISE EXCEPTION 'commissioning tenant mismatch'; END IF;
 IF TG_OP='INSERT' THEN
  IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname=current_user) AND current_user<>'finops_api' THEN RAISE EXCEPTION 'commissioning request requires API identity'; END IF;
  IF NEW.status<>'QUEUED' OR NEW.lease_token IS NOT NULL OR NEW.lease_until IS NOT NULL OR NEW.report_id IS NOT NULL OR NEW.reason_code IS NOT NULL
   OR NOT EXISTS(SELECT FROM entities WHERE tenant_id=NEW.tenant_id AND kind='cloud_accounts' AND id=NEW.cloud_account_id AND version=NEW.cloud_account_version AND document->>'provider'='AWS' AND document->>'account_id'=NEW.account_id AND document->>'region'=NEW.region AND document->>'read_role_binding_id'=NEW.read_role_binding_id AND document->>'connection_mode'='READ_ONLY') THEN RAISE EXCEPTION 'invalid commissioning request binding'; END IF;
 ELSE
  IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname=current_user) AND current_user<>'finops_ingester' THEN RAISE EXCEPTION 'commissioning processing requires ingester identity'; END IF;
  IF OLD.status IN('COMPLETED','FAILED') OR (NEW.tenant_id,NEW.id,NEW.cloud_account_id,NEW.cloud_account_version,NEW.account_id,NEW.region,NEW.read_role_binding_id,NEW.created_by,NEW.created_at) IS DISTINCT FROM (OLD.tenant_id,OLD.id,OLD.cloud_account_id,OLD.cloud_account_version,OLD.account_id,OLD.region,OLD.read_role_binding_id,OLD.created_by,OLD.created_at) THEN RAISE EXCEPTION 'commissioning immutable request'; END IF;
  IF NEW.status='COMPLETED' AND NOT EXISTS(SELECT FROM aws_account_commissioning_reports WHERE tenant_id=NEW.tenant_id AND id=NEW.report_id AND preflight_id=NEW.id) THEN RAISE EXCEPTION 'commissioning completion requires immutable report'; END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER aws_account_preflight_writer BEFORE INSERT OR UPDATE ON aws_account_preflights FOR EACH ROW EXECUTE FUNCTION guard_aws_account_preflight();
CREATE FUNCTION guard_aws_account_commissioning_report() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname=current_user) AND current_user<>'finops_ingester' THEN RAISE EXCEPTION 'commissioning report requires ingester identity'; END IF;
 IF NEW.tenant_id IS DISTINCT FROM current_setting('app.tenant_id',true)
  OR NEW.document->>'schema_version' IS DISTINCT FROM '1' OR NEW.document->>'id' IS DISTINCT FROM NEW.id OR NEW.document->>'preflight_id' IS DISTINCT FROM NEW.preflight_id
  OR NEW.document->>'tenant_id' IS DISTINCT FROM NEW.tenant_id OR NEW.document->'execution_authorized' IS DISTINCT FROM 'false'::jsonb OR NEW.document->'verified_saving' IS DISTINCT FROM 'null'::jsonb
  OR NOT EXISTS(SELECT FROM aws_account_preflights p WHERE p.tenant_id=NEW.tenant_id AND p.id=NEW.preflight_id AND p.status='RUNNING' AND p.lease_until>clock_timestamp() AND NEW.document->>'cloud_account_id'=p.cloud_account_id AND (NEW.document->>'cloud_account_version')::bigint=p.cloud_account_version AND NEW.document->>'account_id'=p.account_id AND NEW.document->>'region'=p.region AND NEW.document->>'read_role_binding_id'=p.read_role_binding_id)
 THEN RAISE EXCEPTION 'invalid immutable commissioning report'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER aws_account_commissioning_report_writer BEFORE INSERT ON aws_account_commissioning_reports FOR EACH ROW EXECUTE FUNCTION guard_aws_account_commissioning_report();
-- Tenant RLS remains active on every reporting input. These are read grants,
-- deliberately excluding plaintext IaC artifacts and any new financial writes.
GRANT SELECT ON aws_service_assessments,aws_service_recommendation_publications,lambda_performance_receipts,
 telemetry_connections,telemetry_source_revisions,telemetry_source_revocations,telemetry_receipts,telemetry_metric_definitions,telemetry_evaluations,
 configuration_artifact_registrations,configuration_artifact_revocations,configuration_artifact_receipts TO finops_ingester;

-- Preserve denial of raw configuration declarations to the ingester. The
-- commissioning reader needs only exact current identity-bound declaration
-- counts, never repository, pipeline, state, snapshot or artifact contents.
CREATE FUNCTION public.commissioning_configuration_authority_metadata(p_account text,p_resources text[])
RETURNS SETOF jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $$
DECLARE tenant_scope text:=current_setting('app.tenant_id',true);
BEGIN
 IF coalesce(tenant_scope,'')='' THEN RETURN; END IF;
 IF p_account IS NULL OR p_account!~'^[0-9]{12}$' OR p_resources IS NULL
 OR cardinality(p_resources)>10000 OR coalesce(array_ndims(p_resources),1)<>1
 OR EXISTS(SELECT FROM unnest(p_resources) resource_id WHERE resource_id IS NULL OR length(resource_id) NOT BETWEEN 1 AND 256)
 THEN RAISE EXCEPTION 'commissioning authority scope invalid'; END IF;
 RETURN QUERY
 SELECT jsonb_build_object('id',a.id,'binding',jsonb_build_object(
  'resource_id',r.id,'provider_resource_id',a.document->'binding'->>'provider_resource_id',
  'account_id',a.document->'binding'->>'account_id','region',a.document->'binding'->>'region'))
 FROM public.entities r
 CROSS JOIN LATERAL(
  SELECT v.id,v.document FROM public.configuration_authority_revisions v
  WHERE v.tenant_id=tenant_scope AND v.tenant_id=r.tenant_id AND v.resource_id=r.id
  ORDER BY v.version DESC LIMIT 1
 ) a
 WHERE r.tenant_id=tenant_scope AND r.kind='resources' AND r.id=ANY(p_resources)
  AND r.document->>'provider'='AWS' AND r.document->>'account_id'=p_account
  AND a.document->'binding'->>'tenant_id'=tenant_scope
  AND a.document->'binding'->>'resource_id'=r.id
  AND a.document->'binding'->>'provider'='AWS'
  AND a.document->'binding'->>'provider_resource_id'=r.document->>'provider_resource_id'
  AND a.document->'binding'->>'account_id'=p_account
  AND a.document->'binding'->>'region'=r.document->>'region'
 ORDER BY r.id LIMIT 10000;
END $$;
REVOKE ALL ON FUNCTION public.commissioning_configuration_authority_metadata(text,text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.commissioning_configuration_authority_metadata(text,text[]) TO finops_ingester;
