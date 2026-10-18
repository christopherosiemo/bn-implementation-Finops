-- Private, observational Azure/GCP publication. This identity has no inherited
-- execution, signing, AWS ingestion, application mutation or financial grants.
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='finops_multicloud_ingester') THEN CREATE ROLE finops_multicloud_ingester NOLOGIN; END IF;
 IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='finops_multicloud_ingester' AND (rolsuper OR rolcreaterole OR rolcreatedb OR rolbypassrls OR rolcanlogin)) OR EXISTS(SELECT 1 FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.member WHERE r.rolname='finops_multicloud_ingester') THEN RAISE EXCEPTION 'multicloud group must be independent and unprivileged';END IF;
END $$;
GRANT USAGE ON SCHEMA public TO finops_multicloud_ingester;

CREATE TABLE multicloud_registrations(
 tenant_id text NOT NULL,id text NOT NULL,version bigint NOT NULL CHECK(version>0),
 config_hash text NOT NULL CHECK(config_hash~'^[a-f0-9]{64}$'),scope_hash text NOT NULL CHECK(scope_hash~'^[a-f0-9]{64}$'),binding_hash text NOT NULL CHECK(binding_hash~'^[a-f0-9]{64}$'),
 document jsonb NOT NULL CHECK(pg_column_size(document)<=65536),writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,id,version)
);
CREATE TABLE multicloud_revocations(
 tenant_id text NOT NULL,registration_id text NOT NULL,registration_version bigint NOT NULL,
 reason_code text NOT NULL CHECK(reason_code~'^[A-Z][A-Z0-9_]{0,99}$'),writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,registration_id,registration_version),FOREIGN KEY(tenant_id,registration_id,registration_version) REFERENCES multicloud_registrations(tenant_id,id,version)
);
CREATE TABLE multicloud_jobs(
 tenant_id text NOT NULL,id text NOT NULL,registration_id text NOT NULL,registration_version bigint NOT NULL,
 idempotency_key text NOT NULL CHECK(length(idempotency_key) BETWEEN 1 AND 200),request_hash text NOT NULL CHECK(request_hash~'^[a-f0-9]{64}$'),
 manifest jsonb NOT NULL CHECK(pg_column_size(manifest)<=1048576),writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,id),UNIQUE(tenant_id,registration_id,idempotency_key),FOREIGN KEY(tenant_id,registration_id,registration_version) REFERENCES multicloud_registrations(tenant_id,id,version)
);
CREATE TABLE multicloud_checkpoints(
 tenant_id text NOT NULL,job_id text NOT NULL,stage text NOT NULL CHECK(stage IN('RAW_ARCHIVED','CANONICAL_ARCHIVED','ANALYTICS_PERSISTED')),
 content_hash text NOT NULL CHECK(content_hash~'^[a-f0-9]{64}$'),document jsonb NOT NULL CHECK(pg_column_size(document)<=1048576),
 writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,job_id,stage),FOREIGN KEY(tenant_id,job_id) REFERENCES multicloud_jobs(tenant_id,id)
);
CREATE TABLE multicloud_receipts(
 tenant_id text NOT NULL,id text NOT NULL,job_id text NOT NULL,registration_id text NOT NULL,registration_version bigint NOT NULL,
 sequence bigint NOT NULL CHECK(sequence>0),document jsonb NOT NULL CHECK(pg_column_size(document)<=1048576),
 writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,id),UNIQUE(tenant_id,job_id),UNIQUE(tenant_id,registration_id,sequence),
 FOREIGN KEY(tenant_id,job_id) REFERENCES multicloud_jobs(tenant_id,id),FOREIGN KEY(tenant_id,registration_id,registration_version) REFERENCES multicloud_registrations(tenant_id,id,version)
);
CREATE INDEX multicloud_receipt_current ON multicloud_receipts(tenant_id,registration_id,sequence DESC);

CREATE FUNCTION multicloud_deny_mutation() RETURNS trigger LANGUAGE plpgsql SET search_path=public,pg_temp AS $$ BEGIN RAISE EXCEPTION 'multicloud evidence is append only'; END $$;
CREATE FUNCTION multicloud_current(p_tenant text,p_id text,p_version bigint) RETURNS jsonb LANGUAGE plpgsql SET search_path=public,pg_temp AS $$
DECLARE r multicloud_registrations;
BEGIN
 IF p_tenant IS DISTINCT FROM current_setting('app.tenant_id',true) THEN RAISE EXCEPTION 'multicloud tenant mismatch';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(p_tenant||':multicloud:'||p_id,0));
 SELECT * INTO r FROM multicloud_registrations WHERE tenant_id=p_tenant AND id=p_id ORDER BY version DESC LIMIT 1;
 IF r.id IS NULL OR r.version IS DISTINCT FROM p_version OR EXISTS(SELECT 1 FROM multicloud_revocations WHERE tenant_id=p_tenant AND registration_id=p_id AND registration_version=p_version) THEN RAISE EXCEPTION 'multicloud registration inactive';END IF;
 RETURN r.document;
END $$;
REVOKE ALL ON FUNCTION multicloud_current(text,text,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION multicloud_current(text,text,bigint) TO finops_multicloud_ingester;

CREATE FUNCTION multicloud_guard() RETURNS trigger LANGUAGE plpgsql SET search_path=public,pg_temp AS $$
DECLARE cfg jsonb;j multicloud_jobs;obj jsonb;ref jsonb;ordinal bigint;expected_sequence bigint;prior bigint;
BEGIN
 IF NOT pg_has_role(current_user,'finops_multicloud_ingester','MEMBER') OR NEW.tenant_id IS DISTINCT FROM current_setting('app.tenant_id',true) THEN RAISE EXCEPTION 'multicloud publication identity required';END IF;
 NEW.writer_role:='finops_multicloud_ingester';NEW.created_at:=clock_timestamp();
 IF TG_TABLE_NAME='multicloud_registrations' THEN
  PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id||':multicloud:'||NEW.id,0));
  SELECT coalesce(max(version),0) INTO prior FROM multicloud_registrations WHERE tenant_id=NEW.tenant_id AND id=NEW.id;
  IF (NEW.document->'registration')-ARRAY['schema_version','id','version','tenant_id','read_binding_id','kind','azure','gcp']<>'{}'::jsonb OR (coalesce(NEW.document->'registration'->'azure','{}'::jsonb))-ARRAY['directory_tenant_id','export_resource_id','billing_account_id','subscription_ids','storage_account_resource_id','storage_account_name','container','prefix','data_version']<>'{}'::jsonb OR (coalesce(NEW.document->'registration'->'gcp','{}'::jsonb))-ARRAY['billing_account_id','query_project_id','dataset_project_id','dataset_id','table_id','location','usage_project_ids','maximum_bytes_billed']<>'{}'::jsonb THEN RAISE EXCEPTION 'multicloud registration contains unrelated credential or authority fields';END IF;
  IF NOT(NEW.document ?& ARRAY['registration','read_binding','config_hash','scope_hash','binding_hash']) OR NOT(NEW.document->'read_binding' ?& ARRAY['id','tenant_id','provider','scope_hash']) OR (NEW.document->'read_binding')-ARRAY['id','tenant_id','provider','directory_tenant_id','billing_account_id','dataset_project_id','scope_hash']<>'{}'::jsonb OR NEW.version<>prior+1 OR NEW.document-ARRAY['registration','read_binding','config_hash','scope_hash','binding_hash']<>'{}'::jsonb OR NEW.document->'registration'->>'schema_version' IS DISTINCT FROM '1' OR NEW.document->'registration'->>'tenant_id' IS DISTINCT FROM NEW.tenant_id OR NEW.document->'registration'->>'id' IS DISTINCT FROM NEW.id OR NEW.document->'registration'->'version' IS DISTINCT FROM to_jsonb(NEW.version) OR NEW.document->>'config_hash' IS DISTINCT FROM NEW.config_hash OR NEW.document->>'scope_hash' IS DISTINCT FROM NEW.scope_hash OR NEW.document->>'binding_hash' IS DISTINCT FROM NEW.binding_hash OR NEW.document->'read_binding'->>'tenant_id' IS DISTINCT FROM NEW.tenant_id OR NEW.document->'read_binding'->>'id' IS DISTINCT FROM NEW.document->'registration'->>'read_binding_id' OR NEW.document->'read_binding'->>'scope_hash' IS DISTINCT FROM NEW.scope_hash OR coalesce(NEW.document->'read_binding'->>'provider','') NOT IN('AZURE','GCP') OR coalesce(NEW.document->'registration'->>'kind','') NOT IN('AZURE_ACTUAL_COST','AZURE_AMORTIZED_COST','AZURE_FOCUS_COST','GCP_DETAILED_BILLING','GCP_ACCOUNT_PRICING','GCP_SPEND_CUD_METADATA') THEN RAISE EXCEPTION 'multicloud private registration invalid';END IF;
  RETURN NEW;
 END IF;
 IF TG_TABLE_NAME='multicloud_revocations' THEN PERFORM multicloud_current(NEW.tenant_id,NEW.registration_id,NEW.registration_version);RETURN NEW;END IF;
 IF TG_TABLE_NAME='multicloud_jobs' THEN
  cfg:=multicloud_current(NEW.tenant_id,NEW.registration_id,NEW.registration_version);
  IF NEW.manifest->>'native_observed_at' IS NULL OR NOT isfinite((NEW.manifest->>'native_observed_at')::timestamptz) OR (NEW.manifest->>'native_observed_at')::timestamptz<'2000-01-01T00:00:00Z'::timestamptz OR (NEW.manifest->>'native_observed_at')::timestamptz>clock_timestamp()+interval '30 seconds' THEN RAISE EXCEPTION 'multicloud native observation ordering required';END IF;
  IF (SELECT coalesce(sum((value->>'bytes')::bigint),0) FROM jsonb_array_elements(NEW.manifest->'raw_objects'))>134217728 OR (NEW.manifest->>'native_row_count')::bigint>100000 OR (NEW.manifest->>'record_count')::bigint>200000 THEN RAISE EXCEPTION 'multicloud collection metadata exceeds budget';END IF;
  IF coalesce(NEW.manifest->>'native_reference','')='' OR length(NEW.manifest->>'native_reference')>4096 OR jsonb_typeof(NEW.manifest->'source_reason_codes') IS DISTINCT FROM 'array' OR jsonb_array_length(NEW.manifest->'source_reason_codes')>100 THEN RAISE EXCEPTION 'multicloud native recovery metadata invalid';END IF;
  IF NOT(NEW.manifest ?& ARRAY['schema_version','tenant_id','registration_id','registration_version','config_hash','scope_hash','binding_hash','kind','period','native_revision','native_reference','native_observed_at','source_reason_codes','raw_objects','raw_manifest_hash','canonical_sha256','fact_hash','population_id','economic_hash','native_row_count','record_count','distinct_rows','status','reason_codes']) OR EXISTS(SELECT 1 FROM jsonb_each(NEW.manifest) p WHERE p.value='null'::jsonb) THEN RAISE EXCEPTION 'multicloud manifest fields required';END IF;
  IF NEW.manifest-ARRAY['schema_version','tenant_id','registration_id','registration_version','config_hash','scope_hash','binding_hash','kind','period','native_revision','native_reference','native_observed_at','source_reason_codes','raw_objects','raw_manifest_hash','canonical_sha256','fact_hash','population_id','economic_hash','native_row_count','record_count','distinct_rows','status','reason_codes']<>'{}'::jsonb OR NEW.manifest->>'schema_version' IS DISTINCT FROM '1' OR NEW.manifest->>'tenant_id' IS DISTINCT FROM NEW.tenant_id OR NEW.manifest->>'registration_id' IS DISTINCT FROM NEW.registration_id OR NEW.manifest->'registration_version' IS DISTINCT FROM to_jsonb(NEW.registration_version) OR NEW.manifest->>'config_hash' IS DISTINCT FROM cfg->>'config_hash' OR NEW.manifest->>'scope_hash' IS DISTINCT FROM cfg->>'scope_hash' OR NEW.manifest->>'binding_hash' IS DISTINCT FROM cfg->>'binding_hash' OR NEW.manifest->>'kind' IS DISTINCT FROM cfg->'registration'->>'kind' OR NEW.manifest->>'status' IS DISTINCT FROM 'PROVISIONAL' OR NEW.manifest->>'native_revision'!~'^[a-f0-9]{64}$' OR NEW.manifest->>'canonical_sha256'!~'^[a-f0-9]{64}$' OR NEW.manifest->>'fact_hash'!~'^[a-f0-9]{64}$' OR NEW.manifest->>'raw_manifest_hash'!~'^[a-f0-9]{64}$' OR NEW.manifest->>'economic_hash'!~'^[a-f0-9]{64}$' OR NEW.manifest->>'population_id' IS DISTINCT FROM 'mc-pop-'||(NEW.manifest->>'fact_hash') OR jsonb_typeof(NEW.manifest->'raw_objects') IS DISTINCT FROM 'array' OR jsonb_array_length(NEW.manifest->'raw_objects') NOT BETWEEN 1 AND 1100 OR jsonb_typeof(NEW.manifest->'reason_codes') IS DISTINCT FROM 'array' OR NOT(NEW.manifest->'reason_codes' @> '["NO_EXECUTION_AUTHORITY","INVOICE_FINALITY_UNPROVEN","REPORTING_PERIOD_COMPLETENESS_UNPROVEN","VM_INCARNATION_ALLOCATION_UNPROVEN"]'::jsonb) THEN RAISE EXCEPTION 'multicloud provisional manifest invalid';END IF;
  IF (NEW.manifest->>'record_count')::bigint<0 OR (NEW.manifest->>'native_row_count')::bigint<0 OR (NEW.manifest->>'distinct_rows')::bigint<0 OR (NEW.manifest->>'distinct_rows')::bigint>(NEW.manifest->>'record_count')::bigint OR (NEW.manifest->'period'->>'end')::timestamptz<=(NEW.manifest->'period'->>'start')::timestamptz THEN RAISE EXCEPTION 'multicloud population bounds invalid';END IF;
  FOR obj IN SELECT value FROM jsonb_array_elements(NEW.manifest->'raw_objects') LOOP
   IF NOT(obj ?& ARRAY['kind','resource','sha256','bytes']) OR obj->'bytes'='null'::jsonb OR obj-ARRAY['kind','resource','version','etag','sha256','bytes','last_modified']<>'{}'::jsonb OR coalesce(obj->>'sha256','')!~'^[a-f0-9]{64}$' OR (obj->>'bytes')::bigint NOT BETWEEN 1 AND 33554432 OR coalesce(obj->>'kind','')='' OR coalesce(obj->>'resource','')='' THEN RAISE EXCEPTION 'multicloud raw object metadata invalid';END IF;
  END LOOP;RETURN NEW;
 END IF;
 SELECT * INTO j FROM multicloud_jobs WHERE tenant_id=NEW.tenant_id AND id=NEW.job_id;
 IF j.id IS NULL THEN RAISE EXCEPTION 'multicloud job missing';END IF;
 cfg:=multicloud_current(NEW.tenant_id,j.registration_id,j.registration_version);
 IF TG_TABLE_NAME='multicloud_checkpoints' THEN
  IF NEW.document->>'stage' IS DISTINCT FROM NEW.stage THEN RAISE EXCEPTION 'multicloud checkpoint stage mismatch';END IF;
  IF NEW.stage='RAW_ARCHIVED' THEN
   IF NEW.document-ARRAY['stage','raw']<>'{}'::jsonb OR jsonb_typeof(NEW.document->'raw') IS DISTINCT FROM 'array' OR jsonb_array_length(NEW.document->'raw')<>jsonb_array_length(j.manifest->'raw_objects') THEN RAISE EXCEPTION 'multicloud raw checkpoint incomplete';END IF;
   FOR ref,ordinal IN SELECT value,ordinality FROM jsonb_array_elements(NEW.document->'raw') WITH ORDINALITY LOOP
    obj:=j.manifest->'raw_objects'->(ordinal-1)::int;
    IF ref->>'sha256' IS DISTINCT FROM obj->>'sha256' OR ref->'bytes' IS DISTINCT FROM obj->'bytes' OR NOT starts_with(coalesce(ref->>'key',''),'tenant/'||NEW.tenant_id||'/multicloud/'||NEW.job_id||'/raw-'||lpad((ordinal-1)::text,4,'0')||'/') THEN RAISE EXCEPTION 'multicloud raw checkpoint binding invalid';END IF;
   END LOOP;
  ELSIF NEW.stage='CANONICAL_ARCHIVED' THEN
   IF NEW.document-ARRAY['stage','canonical']<>'{}'::jsonb OR NOT EXISTS(SELECT 1 FROM multicloud_checkpoints WHERE tenant_id=NEW.tenant_id AND job_id=NEW.job_id AND stage='RAW_ARCHIVED') OR NEW.document->'canonical'->>'sha256' IS DISTINCT FROM j.manifest->>'canonical_sha256' OR NOT starts_with(coalesce(NEW.document->'canonical'->>'key',''),'tenant/'||NEW.tenant_id||'/multicloud/'||NEW.job_id||'/canonical/') THEN RAISE EXCEPTION 'multicloud canonical checkpoint binding invalid';END IF;
  ELSE
   ref:=NEW.document->'facts';
   IF ref->>'tenant_id' IS DISTINCT FROM NEW.tenant_id THEN RAISE EXCEPTION 'multicloud analytics tenant binding invalid';END IF;
   IF NEW.document-ARRAY['stage','facts']<>'{}'::jsonb OR NOT EXISTS(SELECT 1 FROM multicloud_checkpoints WHERE tenant_id=NEW.tenant_id AND job_id=NEW.job_id AND stage='CANONICAL_ARCHIVED') OR ref->>'population_id' IS DISTINCT FROM j.manifest->>'population_id' OR ref->>'fact_hash' IS DISTINCT FROM j.manifest->>'fact_hash' OR ref->>'economic_hash' IS DISTINCT FROM j.manifest->>'economic_hash' OR ref->'record_count' IS DISTINCT FROM j.manifest->'record_count' OR ref->'distinct_rows' IS DISTINCT FROM j.manifest->'distinct_rows' OR coalesce(ref->>'database','')!~'^[A-Za-z_][A-Za-z0-9_]{0,62}$' OR coalesce(ref->>'table','')!~'^[A-Za-z_][A-Za-z0-9_]{0,62}$' OR ref-ARRAY['tenant_id','population_id','fact_hash','economic_hash','record_count','distinct_rows','database','table']<>'{}'::jsonb THEN RAISE EXCEPTION 'multicloud analytics checkpoint invalid';END IF;
  END IF;
  IF NEW.stage<>'ANALYTICS_PERSISTED' THEN
   FOR ref IN SELECT value FROM jsonb_array_elements(CASE WHEN NEW.stage='RAW_ARCHIVED' THEN NEW.document->'raw' ELSE jsonb_build_array(NEW.document->'canonical') END) LOOP
    IF NOT(ref ?& ARRAY['bucket','key','version_id','sha256','bytes']) OR ref->'bytes'='null'::jsonb OR ref-ARRAY['bucket','key','version_id','sha256','bytes']<>'{}'::jsonb OR coalesce(ref->>'bucket','')!~'^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$' OR coalesce(ref->>'version_id','') IN('','null') OR length(ref->>'version_id')>1024 OR coalesce(ref->>'sha256','')!~'^[a-f0-9]{64}$' OR (ref->>'bytes')::bigint NOT BETWEEN 1 AND 134217728 OR position('..' IN ref->>'key')>0 OR position(chr(92) IN ref->>'key')>0 THEN RAISE EXCEPTION 'multicloud pinned archive required';END IF;
   END LOOP;
  END IF;RETURN NEW;
 END IF;
 IF NEW.registration_id IS DISTINCT FROM j.registration_id OR NEW.registration_version IS DISTINCT FROM j.registration_version OR (SELECT count(*) FROM multicloud_checkpoints WHERE tenant_id=NEW.tenant_id AND job_id=NEW.job_id)<>3 THEN RAISE EXCEPTION 'multicloud publication incomplete';END IF;
 SELECT coalesce(max(sequence),0)+1 INTO expected_sequence FROM multicloud_receipts WHERE tenant_id=NEW.tenant_id AND registration_id=NEW.registration_id;
 IF NEW.sequence<>expected_sequence OR NEW.document-ARRAY['id','job_id','manifest','sequence','created_at','active_source','is_current','execution_authorized','verified_saving']<>'{}'::jsonb OR NEW.document->>'id' IS DISTINCT FROM NEW.id OR NEW.document->>'job_id' IS DISTINCT FROM NEW.job_id OR NEW.document->'manifest' IS DISTINCT FROM j.manifest OR NEW.document->'sequence' IS DISTINCT FROM to_jsonb(NEW.sequence) OR NEW.document->'execution_authorized' IS DISTINCT FROM 'false'::jsonb OR NEW.document->'verified_saving' IS DISTINCT FROM 'null'::jsonb OR NEW.document->'active_source' IS DISTINCT FROM 'false'::jsonb OR NEW.document->'is_current' IS DISTINCT FROM 'false'::jsonb THEN RAISE EXCEPTION 'multicloud receipt cannot grant authority';END IF;
 NEW.document:=NEW.document||jsonb_build_object('created_at',NEW.created_at);RETURN NEW;
END $$;

DO $$ DECLARE tab text;BEGIN
 FOREACH tab IN ARRAY ARRAY['multicloud_registrations','multicloud_revocations','multicloud_jobs','multicloud_checkpoints','multicloud_receipts'] LOOP
  EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',tab);EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',tab);
  EXECUTE format('CREATE POLICY tenant_isolation ON %I USING(tenant_id=current_setting(''app.tenant_id'',true)) WITH CHECK(tenant_id=current_setting(''app.tenant_id'',true))',tab);
  EXECUTE format('CREATE TRIGGER immutable BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION multicloud_deny_mutation()',tab);
  EXECUTE format('CREATE TRIGGER writer BEFORE INSERT ON %I FOR EACH ROW EXECUTE FUNCTION multicloud_guard()',tab);
  EXECUTE format('GRANT SELECT,INSERT ON %I TO finops_multicloud_ingester',tab);EXECUTE format('GRANT SELECT ON %I TO finops_api',tab);
 END LOOP;
END $$;
REVOKE ALL ON FUNCTION multicloud_guard(),multicloud_deny_mutation() FROM PUBLIC;
