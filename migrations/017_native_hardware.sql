-- Provider hardware is read-only source evidence. Ingestion credentials remain
-- independent of signing/execution. No operator catalogue or public price input.
DO $$ BEGIN IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='finops_hardware_reader') THEN CREATE ROLE finops_hardware_reader NOLOGIN;END IF;END $$;
GRANT finops_ingester TO finops_hardware_reader;
CREATE FUNCTION hardware_source_current_lock(p_tenant text,p_source text) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=public,pg_temp AS $$ BEGIN
 IF p_tenant IS DISTINCT FROM current_setting('app.tenant_id',true) THEN RAISE EXCEPTION 'hardware tenant mismatch';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(p_tenant||':dependency-graph',0));
 PERFORM 1 FROM source_registrations WHERE tenant_id=p_tenant AND id=p_source FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'hardware source not found';END IF;
END $$;
REVOKE ALL ON FUNCTION hardware_source_current_lock(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION hardware_source_current_lock(text,text) TO finops_ingester;

CREATE FUNCTION guard_native_hardware_source() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE registration source_registrations;revision source_revisions;resource jsonb;rv bigint;binding jsonb;
BEGIN
 IF NOT pg_has_role(current_user,'finops_ingester','MEMBER') THEN RAISE EXCEPTION 'hardware evidence requires ingestion identity';END IF;
 PERFORM hardware_source_current_lock(NEW.tenant_id,NEW.source_id);
 SELECT * INTO registration FROM source_registrations WHERE tenant_id=NEW.tenant_id AND id=NEW.source_id;
 IF registration.id IS NULL OR registration.kind IS DISTINCT FROM 'AWS_CUR2' OR registration.document->'enabled' IS DISTINCT FROM 'true'::jsonb OR registration.document->>'revoked'='true' OR coalesce(registration.document->>'read_role_binding_id','')='' OR NEW.document->'registration_version' IS DISTINCT FROM to_jsonb(registration.version) OR coalesce(NEW.document->>'config_hash','')!~'^[a-f0-9]{64}$' THEN RAISE EXCEPTION 'hardware source registration inactive or changed';END IF;
 IF coalesce(NEW.document->'raw_object'->>'bucket','')='' OR coalesce(NEW.document->'raw_object'->>'version_id','') IN('','null') OR coalesce(NEW.document->'raw_object'->>'body_sha256','')!~'^[a-f0-9]{64}$' OR NOT starts_with(coalesce(NEW.document->'raw_object'->>'key',''),'tenant/'||NEW.tenant_id||'/hardware/') OR position('..' IN NEW.document->'raw_object'->>'key')>0 THEN RAISE EXCEPTION 'hardware versioned raw archive required';END IF;
 IF TG_TABLE_NAME='source_revisions' THEN
  IF NEW.document-ARRAY['id','tenant_id','source_id','kind','registration_version','revision_hash','config_hash','resource_snapshot_hash','raw_object','observed_at']<>'{}'::jsonb THEN RAISE EXCEPTION 'hardware revision metadata contains unrelated authority';END IF;
  RETURN NEW;
 END IF;
 SELECT document,version INTO resource,rv FROM entities WHERE tenant_id=NEW.tenant_id AND kind='resources' AND id=NEW.document->'binding'->>'resource_id';
 SELECT * INTO revision FROM source_revisions WHERE tenant_id=NEW.tenant_id AND id=NEW.revision_id AND source_id=NEW.source_id;
 binding:=jsonb_build_object('tenant_id',NEW.tenant_id,'resource_id',NEW.document->'binding'->>'resource_id','workload_id',resource->>'workload_id','provider',resource->>'provider','provider_resource_id',resource->>'provider_resource_id','account_id',resource->>'account_id','region',resource->>'region');
 IF resource IS NULL OR resource->>'provider' IS DISTINCT FROM 'AWS' OR resource->>'region' IS DISTINCT FROM 'eu-west-1' OR coalesce(resource->>'instance_type','')='' OR NEW.document->'binding' IS DISTINCT FROM binding OR NEW.document->'resource_version' IS DISTINCT FROM to_jsonb(rv) OR NEW.document->'inventory_snapshot' IS DISTINCT FROM(resource||jsonb_build_object('id',NEW.document->'binding'->>'resource_id','version',rv)) OR coalesce(NEW.document->>'resource_snapshot_hash','')!~'^[a-f0-9]{64}$' THEN RAISE EXCEPTION 'hardware current inventory binding invalid';END IF;
 IF NOT coalesce(registration.document->>'payer_account_id'=resource->>'account_id',false) AND NOT coalesce(registration.document->'usage_account_ids' ? (resource->>'account_id'),false) THEN RAISE EXCEPTION 'hardware account outside registered source';END IF;
 IF revision.id IS NULL OR revision.document->>'kind' IS DISTINCT FROM 'AWS_EC2_HARDWARE' OR revision.document->>'config_hash' IS DISTINCT FROM NEW.document->>'config_hash' OR revision.document->'registration_version' IS DISTINCT FROM NEW.document->'registration_version' OR revision.document->'raw_object'->>'body_sha256' IS DISTINCT FROM NEW.document->'raw_object'->>'body_sha256' OR revision.document->>'resource_snapshot_hash' IS DISTINCT FROM NEW.document->>'resource_snapshot_hash' OR NEW.document->>'read_role_binding_id' IS DISTINCT FROM registration.document->>'read_role_binding_id' THEN RAISE EXCEPTION 'hardware immutable source revision mismatch';END IF;
 IF NEW.document->'execution_authorized' IS DISTINCT FROM 'false'::jsonb OR jsonb_typeof(NEW.document->'candidate_types') IS DISTINCT FROM 'array' OR jsonb_array_length(NEW.document->'candidate_types') NOT BETWEEN 1 AND 99 OR jsonb_typeof(NEW.document->'native') IS DISTINCT FROM 'object' OR (NEW.document->'native')-ARRAY['schema_version','provider','account_id','region','collected_at','raw_sha256','instance','types','offerings','volumes','image']<>'{}'::jsonb OR NEW.document->'native'->>'schema_version' IS DISTINCT FROM '1' OR NEW.document->'native'->>'provider' IS DISTINCT FROM 'AWS' OR NEW.document->'native'->>'account_id' IS DISTINCT FROM resource->>'account_id' OR NEW.document->'native'->>'region' IS DISTINCT FROM resource->>'region' OR NEW.document->'native'->'instance'->>'id' IS DISTINCT FROM resource->>'provider_resource_id' OR NEW.document->'native'->'instance'->>'instance_type' IS DISTINCT FROM resource->>'instance_type' OR NEW.document->'native'->>'raw_sha256' IS DISTINCT FROM NEW.document->'raw_object'->>'body_sha256' OR NEW.document->>'collected_at' IS DISTINCT FROM NEW.document->'native'->>'collected_at' THEN RAISE EXCEPTION 'hardware native facts cannot carry authority or supplied prices';END IF;
 IF NEW.document-ARRAY['id','tenant_id','kind','source_id','revision_id','registration_version','read_role_binding_id','config_hash','binding','resource_version','resource_snapshot_hash','inventory_snapshot','candidate_types','native','collected_at','raw_object','execution_authorized']<>'{}'::jsonb OR jsonb_typeof(NEW.document->'collected_at') IS DISTINCT FROM 'string' OR (NEW.document->>'collected_at')::timestamptz<clock_timestamp()-interval '2 minutes' OR (NEW.document->>'collected_at')::timestamptz>clock_timestamp()+interval '5 seconds' OR pg_column_size(NEW.document)>262144 THEN RAISE EXCEPTION 'hardware evidence stale oversized or contains unrelated authority';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER hardware_revision_guard BEFORE INSERT ON source_revisions FOR EACH ROW WHEN(NEW.document->>'kind'='AWS_EC2_HARDWARE') EXECUTE FUNCTION guard_native_hardware_source();
CREATE TRIGGER hardware_receipt_guard BEFORE INSERT ON source_receipts FOR EACH ROW WHEN(NEW.kind='AWS_EC2_HARDWARE') EXECUTE FUNCTION guard_native_hardware_source();

CREATE TABLE native_capacity_results (
 tenant_id text NOT NULL,id text NOT NULL,workload_id text NOT NULL,resource_id text NOT NULL,
 connection_id text NOT NULL,revision_id text NOT NULL,safety_profile_id text NOT NULL,hardware_receipt_id text NOT NULL,
 input_hash text NOT NULL CHECK(input_hash ~ '^[a-f0-9]{64}$'),content_hash text NOT NULL CHECK(content_hash ~ '^[a-f0-9]{64}$'),
 document jsonb NOT NULL CHECK(pg_column_size(document)<=1048576),writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,id),FOREIGN KEY(tenant_id,revision_id) REFERENCES telemetry_source_revisions(tenant_id,id),
 FOREIGN KEY(tenant_id,safety_profile_id) REFERENCES workload_safety_profiles(tenant_id,id),FOREIGN KEY(tenant_id,hardware_receipt_id) REFERENCES source_receipts(tenant_id,id)
);
CREATE INDEX native_capacity_result_workload ON native_capacity_results(tenant_id,workload_id,created_at DESC,id DESC);
ALTER TABLE native_capacity_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE native_capacity_results FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON native_capacity_results USING(tenant_id=current_setting('app.tenant_id',true)) WITH CHECK(tenant_id=current_setting('app.tenant_id',true));
CREATE TRIGGER native_capacity_result_immutable BEFORE UPDATE OR DELETE ON native_capacity_results FOR EACH ROW EXECUTE FUNCTION deny_evidence_mutation();
GRANT SELECT,INSERT ON native_capacity_results TO finops_api;
CREATE FUNCTION guard_native_capacity_result() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE cfg jsonb;profile jsonb;hardware source_receipts;registration source_registrations;resource jsonb;rv bigint;candidate jsonb;rid text;receipt jsonb;ref jsonb;
BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id||':dependency-graph',0));
 cfg:=telemetry_active_config(NEW.tenant_id,NEW.connection_id,NEW.revision_id);
 SELECT document INTO profile FROM workload_safety_profiles WHERE tenant_id=NEW.tenant_id AND workload_id=NEW.workload_id ORDER BY version DESC LIMIT 1;
 SELECT * INTO hardware FROM source_receipts WHERE tenant_id=NEW.tenant_id AND id=NEW.hardware_receipt_id AND kind='AWS_EC2_HARDWARE' AND writer_role='finops_ingester';
 SELECT * INTO registration FROM source_registrations WHERE tenant_id=NEW.tenant_id AND id=hardware.source_id FOR SHARE;
 SELECT document,version INTO resource,rv FROM entities WHERE tenant_id=NEW.tenant_id AND kind='resources' AND id=NEW.resource_id;
 IF profile IS NULL OR profile->>'id' IS DISTINCT FROM NEW.safety_profile_id OR hardware.id IS NULL OR resource IS NULL OR cfg->'binding' IS DISTINCT FROM hardware.document->'binding' OR cfg->'binding'->>'workload_id' IS DISTINCT FROM NEW.workload_id OR cfg->'binding'->>'resource_id' IS DISTINCT FROM NEW.resource_id OR hardware.document->'resource_version' IS DISTINCT FROM to_jsonb(rv) OR hardware.document->'inventory_snapshot' IS DISTINCT FROM(resource||jsonb_build_object('id',NEW.resource_id,'version',rv)) THEN RAISE EXCEPTION 'native capacity current hardware binding invalid';END IF;
 IF registration.document->'enabled' IS DISTINCT FROM 'true'::jsonb OR registration.document->>'revoked'='true' OR hardware.document->'registration_version' IS DISTINCT FROM to_jsonb(registration.version) OR (hardware.document->>'collected_at')::timestamptz<clock_timestamp()-interval '2 minutes' THEN RAISE EXCEPTION 'native capacity hardware source changed or stale';END IF;
 IF NEW.document->>'schema_version' IS DISTINCT FROM '1' OR NEW.document->>'status' IS DISTINCT FROM 'BLOCKED' OR NEW.document->'execution_authorized' IS DISTINCT FROM 'false'::jsonb OR NEW.document->'estimated_saving' IS DISTINCT FROM 'null'::jsonb OR NEW.document->'verified_saving' IS DISTINCT FROM 'null'::jsonb OR NEW.document->'change_plan_id' IS DISTINCT FROM 'null'::jsonb OR NEW.document->>'native_price_status' IS DISTINCT FROM 'UNAVAILABLE' THEN RAISE EXCEPTION 'native hardware assessment cannot authorize execution or fabricate money';END IF;
 IF NEW.document->'binding' IS DISTINCT FROM cfg->'binding' OR NEW.document->>'hardware_receipt_id' IS DISTINCT FROM NEW.hardware_receipt_id OR NEW.document->>'hardware_raw_sha256' IS DISTINCT FROM hardware.document->'native'->>'raw_sha256' OR NEW.document->>'resource_snapshot_hash' IS DISTINCT FROM hardware.document->>'resource_snapshot_hash' OR NEW.document->>'safety_profile_id' IS DISTINCT FROM NEW.safety_profile_id OR NEW.document->'safety_profile_version' IS DISTINCT FROM profile->'version' OR NEW.document->>'safety_profile_hash' IS DISTINCT FROM profile->>'hash' OR NEW.document->>'connection_id' IS DISTINCT FROM NEW.connection_id OR NEW.document->'connection_version' IS DISTINCT FROM cfg->'version' OR NEW.document->>'revision_id' IS DISTINCT FROM NEW.revision_id OR NEW.document->>'config_hash' IS DISTINCT FROM(SELECT config_hash FROM telemetry_source_revisions WHERE tenant_id=NEW.tenant_id AND id=NEW.revision_id) OR NEW.document->>'input_hash' IS DISTINCT FROM NEW.input_hash OR coalesce(NEW.document->>'population_hash','')!~'^[a-f0-9]{64}$' THEN RAISE EXCEPTION 'native capacity selected references invalid';END IF;
 IF jsonb_typeof(NEW.document->'receipt_ids') IS DISTINCT FROM 'array' OR jsonb_array_length(NEW.document->'receipt_ids')>2048 OR jsonb_typeof(NEW.document->'source_refs') IS DISTINCT FROM 'array' OR jsonb_array_length(NEW.document->'source_refs')<>jsonb_array_length(NEW.document->'receipt_ids') OR (SELECT count(DISTINCT x) FROM jsonb_array_elements_text(NEW.document->'receipt_ids') x)<>jsonb_array_length(NEW.document->'receipt_ids') THEN RAISE EXCEPTION 'native capacity receipt selection invalid';END IF;
 FOR rid IN SELECT jsonb_array_elements_text(NEW.document->'receipt_ids') LOOP
  SELECT document INTO receipt FROM telemetry_receipts WHERE tenant_id=NEW.tenant_id AND id=rid AND connection_id=NEW.connection_id AND revision_id=NEW.revision_id;
  SELECT r INTO ref FROM jsonb_array_elements(NEW.document->'source_refs') r WHERE r->>'receipt_id'=rid;
  IF receipt IS NULL OR ref IS NULL OR receipt->'binding' IS DISTINCT FROM cfg->'binding' OR ref->>'config_hash' IS DISTINCT FROM NEW.document->>'config_hash' OR ref->>'batch_id' IS DISTINCT FROM receipt->>'batch_id' OR ref->>'raw_sha256' IS DISTINCT FROM receipt->>'raw_sha256' OR ref->>'canonical_hash' IS DISTINCT FROM receipt->>'canonical_hash' THEN RAISE EXCEPTION 'native capacity telemetry provenance mismatch';END IF;
 END LOOP;
 IF jsonb_typeof(NEW.document->'reason_codes') IS DISTINCT FROM 'array' OR NOT(NEW.document->'reason_codes' @> '["NATIVE_PRICE_UNAVAILABLE","EXECUTION_AUTHORITY_NOT_GRANTED"]'::jsonb) OR jsonb_typeof(NEW.document->'model_evaluated') IS DISTINCT FROM 'boolean' OR jsonb_path_exists(NEW.document,'$.**.points') OR jsonb_path_exists(NEW.document,'$.**.segments') OR jsonb_path_exists(NEW.document,'$.**.samples') THEN RAISE EXCEPTION 'native capacity requires bounded evidence summaries';END IF;
 IF NEW.document->'model_evaluated'='true'::jsonb THEN
  IF NEW.document->'model_evaluation'->>'schema_version' IS DISTINCT FROM '4' OR NEW.document->'model_evaluation'->'binding' IS DISTINCT FROM cfg->'binding' OR coalesce(NEW.document->'model_evaluation'->'verified_saving','null'::jsonb) IS DISTINCT FROM 'null'::jsonb THEN RAISE EXCEPTION 'native capacity model response binding invalid';END IF;
  FOR candidate IN SELECT jsonb_array_elements(NEW.document->'model_evaluation'->'candidates') LOOP
   IF candidate->'economics'->>'status' IS DISTINCT FROM 'UNAVAILABLE' OR candidate->'economics'->'estimated_saving' IS DISTINCT FROM 'null'::jsonb OR coalesce(candidate->'economics'->'verified_saving','null'::jsonb) IS DISTINCT FROM 'null'::jsonb OR candidate->'future_risk'->'future_breach_probability_upper_ppm' IS DISTINCT FROM 'null'::jsonb THEN RAISE EXCEPTION 'native capacity cannot manufacture prices or calibrated future risk';END IF;
  END LOOP;
 ELSIF NEW.document->'model_evaluation' IS DISTINCT FROM 'null'::jsonb THEN RAISE EXCEPTION 'unevaluated capacity result cannot include a model claim';END IF;
 NEW.writer_role:='finops_api';NEW.created_at:=clock_timestamp();NEW.document:=NEW.document||jsonb_build_object('id',NEW.id,'tenant_id',NEW.tenant_id,'hash',NEW.content_hash,'created_at',NEW.created_at,'writer_role',NEW.writer_role);RETURN NEW;
END $$;
CREATE TRIGGER native_capacity_result_writer BEFORE INSERT ON native_capacity_results FOR EACH ROW EXECUTE FUNCTION guard_native_capacity_result();
