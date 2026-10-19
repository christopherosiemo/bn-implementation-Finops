-- Analytical join of issued group observations; no financial or execution grant.
DO $$ BEGIN IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='finops_group_decision') THEN
 CREATE ROLE finops_group_decision NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
END IF;END $$;
GRANT USAGE ON SCHEMA public TO finops_group_decision;

CREATE TABLE fleet_joint_decision_requests(
 tenant_id text NOT NULL,id text NOT NULL,workload_id text NOT NULL,creator_id text NOT NULL,
 assessment_request_id text NOT NULL,capacity_request_id text NOT NULL,
 content_hash text NOT NULL CHECK(content_hash~'^[a-f0-9]{64}$'),document jsonb NOT NULL,raw_document bytea NOT NULL,
 writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,id),
 FOREIGN KEY(tenant_id,assessment_request_id) REFERENCES fleet_native_assessment_requests(tenant_id,id),
 FOREIGN KEY(tenant_id,capacity_request_id) REFERENCES fleet_native_capacity_requests(tenant_id,id),
 CHECK(octet_length(raw_document)<=131072 AND octet_length(document::text)<=131072)
);
CREATE TABLE fleet_joint_decisions(
 tenant_id text NOT NULL,id text NOT NULL,request_id text NOT NULL,
 content_hash text NOT NULL CHECK(content_hash~'^[a-f0-9]{64}$'),input_snapshot_hash text NOT NULL CHECK(input_snapshot_hash~'^[a-f0-9]{64}$'),
 document jsonb NOT NULL,raw_document bytea NOT NULL,
 writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,id),UNIQUE(tenant_id,request_id),
 FOREIGN KEY(tenant_id,request_id) REFERENCES fleet_joint_decision_requests(tenant_id,id),
 CHECK(octet_length(raw_document)<=2097152)
);
CREATE INDEX fleet_joint_decision_page ON fleet_joint_decision_requests(tenant_id,workload_id,id);
CREATE TABLE fleet_joint_decision_refusals(
 tenant_id text NOT NULL,id text NOT NULL,request_id text NOT NULL,
 content_hash text NOT NULL CHECK(content_hash~'^[a-f0-9]{64}$'),document jsonb NOT NULL,raw_document bytea NOT NULL,
 writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,id),UNIQUE(tenant_id,request_id),
 FOREIGN KEY(tenant_id,request_id) REFERENCES fleet_joint_decision_requests(tenant_id,id),
 CHECK(octet_length(raw_document)<=4096 AND octet_length(document::text)<=4096)
);
DO $$ DECLARE tab text;BEGIN FOREACH tab IN ARRAY ARRAY['fleet_joint_decision_requests','fleet_joint_decisions'] LOOP
 EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',tab);
 EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',tab);
 EXECUTE format('CREATE POLICY tenant_isolation ON %I USING(tenant_id=current_setting(''app.tenant_id'',true)) WITH CHECK(tenant_id=current_setting(''app.tenant_id'',true))',tab);
 EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION public.deny_evidence_mutation()',tab||'_immutable',tab);
END LOOP;
 ALTER TABLE fleet_joint_decision_refusals ENABLE ROW LEVEL SECURITY;
 ALTER TABLE fleet_joint_decision_refusals FORCE ROW LEVEL SECURITY;
 CREATE POLICY tenant_isolation ON fleet_joint_decision_refusals USING(tenant_id=current_setting('app.tenant_id',true)) WITH CHECK(tenant_id=current_setting('app.tenant_id',true));
 CREATE TRIGGER fleet_joint_refusal_immutable BEFORE UPDATE OR DELETE ON fleet_joint_decision_refusals FOR EACH ROW EXECUTE FUNCTION public.deny_evidence_mutation();
END $$;
GRANT SELECT ON fleet_joint_decision_requests,fleet_joint_decisions,fleet_joint_decision_refusals TO finops_api,finops_group_decision;
GRANT INSERT ON fleet_joint_decision_requests TO finops_api;
GRANT INSERT ON fleet_joint_decisions,fleet_joint_decision_refusals TO finops_group_decision;

CREATE FUNCTION fleet_joint_reason_codes(d jsonb) RETURNS boolean LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$
 SELECT CASE WHEN jsonb_typeof(d)='array' THEN jsonb_array_length(d)<=64 AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(d) x WHERE jsonb_typeof(x) IS DISTINCT FROM 'string' OR length(x#>>'{}')>128 OR length(x#>>'{}')=0) ELSE false END
$$;
REVOKE ALL ON FUNCTION fleet_joint_reason_codes(jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION fleet_joint_reason_codes(jsonb) TO finops_group_decision;

-- This resolver selects the exact immutable035/036 inputs. New role has no
-- direct source/archive/financial/control writes or broad source SELECT grant.
CREATE FUNCTION fleet_joint_decision_inputs(p_tenant text,p_assessment text,p_capacity text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE who text:=coalesce(nullif(current_setting('role',true),'none'),session_user);
 ar public.fleet_native_assessment_requests%ROWTYPE;cr public.fleet_native_capacity_requests%ROWTYPE;
 a public.fleet_native_assessments%ROWTYPE;s public.fleet_native_capacity_scopes%ROWTYPE;b public.fleet_native_capacity_batches%ROWTYPE;
 profile public.workload_safety_profiles%ROWTYPE;binding jsonb;members jsonb;member jsonb;pin jsonb;
 actual text[];claimed text[];n bigint;size bigint;refs jsonb;baseline_ref jsonb;
BEGIN
 IF who NOT IN('finops_api','finops_group_decision') OR p_tenant IS NULL OR p_tenant='' OR p_tenant IS DISTINCT FROM current_setting('app.tenant_id',true) THEN RAISE EXCEPTION 'joint decision reader scope differs';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(p_tenant||':dependency-graph',0));
 SELECT * INTO ar FROM public.fleet_native_assessment_requests WHERE tenant_id=p_tenant AND id=p_assessment;
 SELECT * INTO cr FROM public.fleet_native_capacity_requests WHERE tenant_id=p_tenant AND id=p_capacity;
 SELECT * INTO a FROM public.fleet_native_assessments WHERE tenant_id=p_tenant AND request_id=p_assessment;
 SELECT * INTO s FROM public.fleet_native_capacity_scopes WHERE tenant_id=p_tenant AND request_id=p_capacity;
 SELECT * INTO b FROM public.fleet_native_capacity_batches WHERE tenant_id=p_tenant AND request_id=p_capacity;
 IF ar.id IS NULL OR cr.id IS NULL OR a.id IS NULL OR s.request_id IS NULL OR b.id IS NULL OR ar.workload_id IS DISTINCT FROM cr.workload_id OR ar.document->'selection' IS DISTINCT FROM cr.document->'selection' OR a.document->'selection' IS DISTINCT FROM ar.document->'selection' OR s.document->'scope'->'selection' IS DISTINCT FROM ar.document->'selection' OR b.document->'scope' IS DISTINCT FROM s.document->'scope' THEN RAISE EXCEPTION 'joint decision exact assessed pair required';END IF;
 IF jsonb_typeof(a.document->'observed_at') IS DISTINCT FROM 'string' OR (a.document->>'observed_at')::timestamptz<clock_timestamp()-interval '2 minutes' OR (a.document->>'observed_at')::timestamptz>clock_timestamp()+interval '5 seconds'
 OR jsonb_typeof(s.document->'scope'->'observed_at') IS DISTINCT FROM 'string' OR (s.document->'scope'->>'observed_at')::timestamptz<clock_timestamp()-interval '5 minutes' OR (s.document->'scope'->>'observed_at')::timestamptz>clock_timestamp()+interval '5 seconds'
 OR a.document->'native_rates'->>'status'='OBSERVED_CONDITIONAL' AND (a.document->'native_rates'->>'valid_until')::timestamptz<=clock_timestamp() THEN RAISE EXCEPTION 'joint decision observation expired';END IF;
 binding:=public.fleet_native_selection_current(p_tenant,ar.old_proposal_id,ar.candidate_proposal_id);
 SELECT * INTO profile FROM public.workload_safety_profiles WHERE tenant_id=p_tenant AND workload_id=ar.workload_id ORDER BY version DESC LIMIT 1;
 IF binding IS NULL OR binding IS DISTINCT FROM ar.document->'selection'->'groups'->'binding' OR ar.document->'selection'->'safety_profile' IS DISTINCT FROM jsonb_build_object('id',profile.id,'version',profile.version,'sha256',profile.content_hash) THEN RAISE EXCEPTION 'joint decision current pair/profile differs';END IF;
 -- No old hardware or membership fallback after a newer native point exists.
 SELECT coalesce(array_agg(id ORDER BY id),ARRAY[]::text[]) INTO actual FROM unnest(public.fleet_native_current_pin_ids(p_tenant,binding)) id;
 SELECT coalesce(array_agg(value->>'receipt_id' ORDER BY value->>'receipt_id'),ARRAY[]::text[]) INTO claimed FROM jsonb_array_elements(a.document->'native_rates'->'source_pins');
 -- Missing member hardware remains an explicit UNKNOWN. Only conditional
 -- rate observations carry035's stronger full native population floor.
 IF actual IS DISTINCT FROM claimed OR cardinality(actual)<3 OR a.document->'native_rates'->>'status'='OBSERVED_CONDITIONAL' AND cardinality(actual)<5 THEN RAISE EXCEPTION 'joint decision native point changed';END IF;
 FOR baseline_ref IN SELECT value FROM jsonb_array_elements(a.document->'native_rates'->'billing_source_refs') LOOP
  IF NOT EXISTS(SELECT 1 FROM public.source_checkpoints c JOIN public.source_receipts r ON r.tenant_id=c.tenant_id AND r.id=c.document->>'receipt_id'
   WHERE c.tenant_id=p_tenant AND c.source_id=binding->'old'->>'source_id' AND c.checkpoint_key LIKE 'month:'||(binding->'old'->>'source_config_sha256')||':%'
   AND r.id=baseline_ref->>'receipt_id' AND r.revision_id=baseline_ref->>'revision_id' AND r.document->>'ingestion_job_id'=baseline_ref->>'ingestion_job_id') THEN RAISE EXCEPTION 'joint decision billing head changed';END IF;
 END LOOP;
 -- Preflight byte and row budgets before JSON aggregation or network decoding.
 SELECT count(*),coalesce(sum(octet_length(raw_document)),0) INTO n,size FROM public.fleet_native_capacity_members WHERE tenant_id=p_tenant AND request_id=p_capacity;
 IF n<1 OR n>256 OR n<>jsonb_array_length(s.document->'scope'->'current_member_ids') OR size>33554432 THEN RAISE EXCEPTION 'joint decision full bounded roster required';END IF;
 SELECT jsonb_agg(jsonb_build_object('ref',jsonb_build_object('id',m.id,'sha256',m.content_hash),'document',m.document) ORDER BY m.instance_id) INTO members
 FROM public.fleet_native_capacity_members m WHERE m.tenant_id=p_tenant AND m.request_id=p_capacity;
 FOR member IN SELECT value->'document' FROM jsonb_array_elements(members) LOOP
  IF member->'scope' IS DISTINCT FROM s.document->'scope' THEN RAISE EXCEPTION 'joint decision member scope differs';END IF;
  IF jsonb_typeof(member->'observed_at') IS DISTINCT FROM 'string' OR (member->>'observed_at')::timestamptz<clock_timestamp()-interval '5 minutes' OR (member->>'observed_at')::timestamptz>clock_timestamp()+interval '5 seconds' THEN RAISE EXCEPTION 'joint decision member observation expired';END IF;
  IF member->'model_evaluated'='true'::jsonb THEN
   IF NOT EXISTS(SELECT 1 FROM public.entities e WHERE e.tenant_id=p_tenant AND e.kind='resources' AND e.id=member->>'resource_id'
     AND e.version=(member->'hardware'->>'resource_version')::bigint AND e.document->>'provider_resource_id'=member->>'instance_id' AND e.document->>'workload_id'=ar.workload_id)
    OR NOT EXISTS(SELECT 1 FROM public.telemetry_connections c JOIN public.telemetry_source_revisions r ON r.tenant_id=c.tenant_id AND r.connection_id=c.id AND r.connection_version=c.version
     WHERE c.tenant_id=p_tenant AND c.id=member->'telemetry'->>'connection_id' AND c.version=(member->'telemetry'->>'connection_version')::bigint AND c.config_hash=member->'telemetry'->>'config_hash' AND c.config->'enabled'='true'::jsonb
     AND NOT EXISTS(SELECT 1 FROM public.telemetry_connections newer WHERE newer.tenant_id=c.tenant_id AND newer.id=c.id AND newer.version>c.version)
     AND r.id=member->'telemetry'->>'revision_id' AND NOT EXISTS(SELECT 1 FROM public.telemetry_source_revocations x WHERE x.tenant_id=r.tenant_id AND x.revision_id=r.id)) THEN RAISE EXCEPTION 'joint decision member mapping/revision changed';END IF;
  END IF;
 END LOOP;
 RETURN jsonb_build_object('assessment_ref',jsonb_build_object('id',a.id,'sha256',a.content_hash),'assessment',a.document,
  'scope_ref',jsonb_build_object('id',s.request_id,'sha256',s.content_hash),'scope',s.document,
  'batch_ref',jsonb_build_object('id',b.id,'sha256',b.content_hash),'batch',b.document,'members',members,
  'profile',profile.document-ARRAY['tenant_id','hash','created_at','writer_role']);
 EXCEPTION WHEN raise_exception THEN RAISE EXCEPTION 'joint decision current inputs unavailable';
END $$;
REVOKE ALL ON FUNCTION fleet_joint_decision_inputs(text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION fleet_joint_decision_inputs(text,text,text) TO finops_api,finops_group_decision;

CREATE FUNCTION guard_fleet_joint_decision_request() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE inputs jsonb;selection jsonb;refs jsonb;BEGIN
 IF current_user<>'finops_api' THEN RAISE EXCEPTION 'joint decision request requires API';END IF;
 inputs:=public.fleet_joint_decision_inputs(NEW.tenant_id,NEW.assessment_request_id,NEW.capacity_request_id);selection:=inputs->'assessment'->'selection';
 refs:=jsonb_build_array(inputs->'assessment_ref',inputs->'scope_ref',inputs->'batch_ref');
 IF NEW.document IS DISTINCT FROM jsonb_build_object('schema_version','1','id',NEW.id,'workload_id',NEW.workload_id,'creator_id',NEW.creator_id,
  'assessment_request_id',NEW.assessment_request_id,'capacity_batch_request_id',NEW.capacity_request_id,'selection',selection,'input_refs',refs,'execution_authorized',false,'verified_saving',NULL)
  OR NEW.workload_id IS DISTINCT FROM selection->'groups'->'binding'->'old'->'target'->>'workload_id' OR coalesce(NEW.creator_id,'')=''
  OR encode(sha256(NEW.raw_document),'hex') IS DISTINCT FROM NEW.content_hash OR public.fleet_history_json_hash(NEW.document) IS DISTINCT FROM NEW.content_hash OR convert_from(NEW.raw_document,'UTF8')::jsonb IS DISTINCT FROM NEW.document THEN RAISE EXCEPTION 'joint decision immutable request differs';END IF;
 NEW.writer_role:='finops_api';NEW.created_at:=clock_timestamp();RETURN NEW;
END $$;
CREATE TRIGGER fleet_joint_decision_request_guard BEFORE INSERT ON fleet_joint_decision_requests FOR EACH ROW EXECUTE FUNCTION guard_fleet_joint_decision_request();

CREATE FUNCTION guard_fleet_joint_decision() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE req public.fleet_joint_decision_requests%ROWTYPE;inputs jsonb;expected_refs jsonb;refs jsonb;entry jsonb;source jsonb;dim jsonb;checkrow jsonb;metric jsonb;physical text:='PASS';member_status text;dimension_status text;names text[];ids jsonb;expected_ids jsonb;BEGIN
 IF current_user<>'finops_group_decision' THEN RAISE EXCEPTION 'joint decision requires private evaluator';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id||':dependency-graph',0));
 IF EXISTS(SELECT 1 FROM public.fleet_joint_decision_refusals WHERE tenant_id=NEW.tenant_id AND request_id=NEW.request_id) THEN RAISE EXCEPTION 'joint decision already refused';END IF;
 -- Requests are append-only, and the input resolver holds the graph guard.
 -- A row lock would unnecessarily require UPDATE privilege on API requests.
 SELECT * INTO req FROM public.fleet_joint_decision_requests WHERE tenant_id=NEW.tenant_id AND id=NEW.request_id;
 inputs:=public.fleet_joint_decision_inputs(NEW.tenant_id,req.assessment_request_id,req.capacity_request_id);
 IF req.id IS NULL OR NEW.input_snapshot_hash IS DISTINCT FROM public.fleet_history_json_hash(inputs) OR req.document->'selection' IS DISTINCT FROM inputs->'assessment'->'selection'
 OR req.document->'input_refs' IS DISTINCT FROM jsonb_build_array(inputs->'assessment_ref',inputs->'scope_ref',inputs->'batch_ref') THEN RAISE EXCEPTION 'joint decision issued input changed';END IF;
 expected_refs:=req.document->'input_refs'||jsonb_build_array(jsonb_build_object('id',inputs->'profile'->>'id','sha256',req.document->'selection'->'safety_profile'->>'sha256'));
 FOR source IN SELECT value FROM jsonb_array_elements(inputs->'members') LOOP expected_refs:=expected_refs||jsonb_build_array(source->'ref');END LOOP;
 IF NEW.document->>'schema_version' IS DISTINCT FROM '1' OR NEW.document->>'id' IS DISTINCT FROM NEW.id OR NEW.document->>'request_id' IS DISTINCT FROM NEW.request_id OR NEW.id IS DISTINCT FROM 'group-joint-decision-'||public.fleet_history_json_hash(jsonb_set(NEW.document,'{id}','""'))
 OR NEW.document->'selection' IS DISTINCT FROM req.document->'selection' OR NEW.document->'inputs' IS DISTINCT FROM expected_refs OR NEW.document->'scenario' IS DISTINCT FROM inputs->'assessment'->'scenario'
 OR NEW.document->>'status' IS DISTINCT FROM 'BLOCKED' OR NEW.document->'contracted_avoidable_cost' IS DISTINCT FROM 'null'::jsonb OR NEW.document->'estimated_saving' IS DISTINCT FROM 'null'::jsonb OR NEW.document->'verified_saving' IS DISTINCT FROM 'null'::jsonb
 OR NEW.document->'group_capacity_authorized' IS DISTINCT FROM 'false'::jsonb OR NEW.document->'completed_business_work_preserved' IS DISTINCT FROM 'null'::jsonb OR NEW.document->'plan_eligible' IS DISTINCT FROM 'false'::jsonb OR NEW.document->'execution_authorized' IS DISTINCT FROM 'false'::jsonb OR NEW.document->'change_plan_id' IS DISTINCT FROM 'null'::jsonb
 OR jsonb_typeof(NEW.document->'observed_at') IS DISTINCT FROM 'string' OR (NEW.document->>'observed_at')::timestamptz<clock_timestamp()-interval '30 seconds' OR (NEW.document->>'observed_at')::timestamptz>clock_timestamp()+interval '5 seconds'
 OR jsonb_typeof(NEW.document->'members') IS DISTINCT FROM 'array' OR jsonb_array_length(NEW.document->'members')<>jsonb_array_length(inputs->'members') OR NOT public.fleet_joint_reason_codes(NEW.document->'reason_codes') OR encode(sha256(NEW.raw_document),'hex') IS DISTINCT FROM NEW.content_hash OR public.fleet_history_json_hash(NEW.document) IS DISTINCT FROM NEW.content_hash OR convert_from(NEW.raw_document,'UTF8')::jsonb IS DISTINCT FROM NEW.document THEN RAISE EXCEPTION 'joint decision observations cannot grant authority or new amounts';END IF;
 SELECT jsonb_agg(value->>'instance_id' ORDER BY value->>'instance_id') INTO ids FROM jsonb_array_elements(NEW.document->'members');
 SELECT jsonb_agg(value->'document'->>'instance_id' ORDER BY value->'document'->>'instance_id') INTO expected_ids FROM jsonb_array_elements(inputs->'members');
 IF ids IS DISTINCT FROM expected_ids OR EXISTS(SELECT 1 FROM jsonb_object_keys(NEW.document) k WHERE k<>ALL(ARRAY['schema_version','id','request_id','selection','observed_at','inputs','members','physical_status','scenario','contracted_avoidable_cost','estimated_saving','verified_saving','status','group_capacity_authorized','completed_business_work_preserved','plan_eligible','execution_authorized','change_plan_id','reason_codes'])) THEN RAISE EXCEPTION 'joint decision complete member population differs';END IF;
 -- SQL enforces issuer/input/financial closure. The private Go evaluator owns
 -- detailed model-summary consistency, not a public arbitrary proof endpoint.
 FOR entry IN SELECT value FROM jsonb_array_elements(NEW.document->'members') LOOP
  SELECT value INTO source FROM jsonb_array_elements(inputs->'members') WHERE value->'document'->>'instance_id'=entry->>'instance_id';
  IF source IS NULL OR entry->'result' IS DISTINCT FROM source->'ref' OR jsonb_typeof(entry->'dimensions') IS DISTINCT FROM 'array' OR jsonb_array_length(entry->'dimensions')<>5 OR NOT entry ?& ARRAY['instance_id','result','status','dimensions'] OR EXISTS(SELECT 1 FROM jsonb_object_keys(entry) k WHERE k<>ALL(ARRAY['instance_id','result','status','dimensions'])) THEN RAISE EXCEPTION 'joint decision exact member/dimensions differ';END IF;
  SELECT array_agg(value->>'name' ORDER BY value->>'name') INTO names FROM jsonb_array_elements(entry->'dimensions');
  IF names IS DISTINCT FROM ARRAY['cpu','memory','network','storage_iops','storage_throughput'] THEN RAISE EXCEPTION 'joint decision required dimensions differ';END IF;
  member_status:='PASS';
  FOR dim IN SELECT value FROM jsonb_array_elements(entry->'dimensions') LOOP
   IF jsonb_typeof(dim->'status') IS DISTINCT FROM 'string' OR dim->>'status' NOT IN('PASS','FAIL','UNKNOWN') OR dim->>'unit' IS DISTINCT FROM (CASE dim->>'name' WHEN 'cpu' THEN 'vCPU' WHEN 'memory' THEN 'bytes' WHEN 'network' THEN 'bytes/second' WHEN 'storage_iops' THEN 'operations/second' ELSE 'bytes/second' END) THEN RAISE EXCEPTION 'joint decision physical dimension invalid';END IF;
   IF NOT dim ?& ARRAY['name','unit','status','candidate_capacity','required_with_reserve','reason_codes'] OR NOT public.fleet_joint_reason_codes(dim->'reason_codes') OR EXISTS(SELECT 1 FROM jsonb_object_keys(dim) k WHERE k<>ALL(ARRAY['name','unit','status','candidate_capacity','required_with_reserve','reason_codes'])) THEN RAISE EXCEPTION 'joint decision physical observation shape differs';END IF;
   checkrow:=NULL;metric:=NULL;
   IF source->'document'->'model_evaluated'='true'::jsonb THEN
    SELECT value INTO checkrow FROM jsonb_array_elements(source->'document'->'model_evaluation'->'candidates'->0->'checks') WHERE value->>'dimension'=dim->>'name';
    SELECT value INTO metric FROM jsonb_array_elements(source->'document'->'model_evaluation'->'metrics') WHERE value->>'name'=dim->>'name';
   END IF;
   IF checkrow IS NULL THEN
    IF dim->>'status' IS DISTINCT FROM 'UNKNOWN' OR dim->'candidate_capacity' IS DISTINCT FROM 'null'::jsonb OR dim->'required_with_reserve' IS DISTINCT FROM 'null'::jsonb THEN RAISE EXCEPTION 'joint decision missing native check cannot be physical pass';END IF;
   ELSE
    IF dim->'candidate_capacity' IS DISTINCT FROM checkrow->'candidate_capacity' OR dim->'required_with_reserve' IS DISTINCT FROM checkrow->'required_with_reserve' OR checkrow->>'status'='FAIL' AND dim->>'status' IS DISTINCT FROM 'FAIL' OR dim->>'status'='FAIL' AND checkrow->>'status' IS DISTINCT FROM 'FAIL' THEN RAISE EXCEPTION 'joint decision native check observation differs';END IF;
    IF dim->>'status'='PASS' AND (checkrow->>'status' IS DISTINCT FROM 'PASS' OR source->'document'->'model_evaluation'->>'status' IS DISTINCT FROM 'BLOCKED' OR metric IS NULL OR metric->>'unit' IS DISTINCT FROM dim->>'unit' OR metric->>'coverage_ppm' IS DISTINCT FROM '1000000' OR metric->>'time_coverage_ppm' IS DISTINCT FROM '1000000' OR metric->>'sampling_coverage_ppm' IS DISTINCT FROM '1000000' OR metric->>'missing_intervals' IS DISTINCT FROM '0') THEN RAISE EXCEPTION 'joint decision incomplete physical check cannot be pass';END IF;
   END IF;
   IF dim->>'status'='FAIL' THEN member_status:='FAIL';ELSIF dim->>'status'='UNKNOWN' AND member_status<>'FAIL' THEN member_status:='UNKNOWN';END IF;
  END LOOP;
  IF entry->>'status' IS DISTINCT FROM member_status THEN RAISE EXCEPTION 'joint decision member aggregate differs';END IF;
  IF member_status='FAIL' THEN physical:='FAIL';ELSIF member_status='UNKNOWN' AND physical<>'FAIL' THEN physical:='UNKNOWN';END IF;
 END LOOP;
 IF NEW.document->>'physical_status' IS DISTINCT FROM physical THEN RAISE EXCEPTION 'joint decision aggregate differs';END IF;
 NEW.writer_role:='finops_group_decision';NEW.created_at:=clock_timestamp();RETURN NEW;
END $$;
CREATE TRIGGER fleet_joint_decision_guard BEFORE INSERT ON fleet_joint_decisions FOR EACH ROW EXECUTE FUNCTION guard_fleet_joint_decision();
CREATE FUNCTION guard_fleet_joint_decision_refusal() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE req public.fleet_joint_decision_requests%ROWTYPE;reason text;unavailable boolean:=false;BEGIN
 IF current_user<>'finops_group_decision' THEN RAISE EXCEPTION 'joint decision refusal requires private evaluator';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id||':dependency-graph',0));
 SELECT * INTO req FROM public.fleet_joint_decision_requests WHERE tenant_id=NEW.tenant_id AND id=NEW.request_id;
 IF req.id IS NULL OR EXISTS(SELECT 1 FROM public.fleet_joint_decisions WHERE tenant_id=NEW.tenant_id AND request_id=NEW.request_id) THEN RAISE EXCEPTION 'joint decision terminal outcome exists or request missing';END IF;
 reason:=NEW.document->'reason_codes'->>0;
 IF NEW.document IS DISTINCT FROM jsonb_build_object('schema_version','1','id',NEW.id,'request_id',NEW.request_id,'reason_codes',jsonb_build_array(reason),'observed_at',NEW.document->'observed_at','execution_authorized',false,'verified_saving',NULL)
 OR reason IS NULL OR reason NOT IN('JOINT_DECISION_INPUTS_CHANGED','JOINED_MODEL_SUMMARY_UNSUPPORTED','RESERVE_ARITHMETIC_OR_UNSUPPORTED_PRECISION','RATE_ARITHMETIC_OR_UNSUPPORTED_PRECISION','JOINED_INPUT_FORMAT_UNSUPPORTED')
 OR NEW.id IS DISTINCT FROM 'group-joint-refusal-'||public.fleet_history_json_hash(jsonb_set(NEW.document,'{id}','""'))
 OR jsonb_typeof(NEW.document->'observed_at') IS DISTINCT FROM 'string' OR (NEW.document->>'observed_at')::timestamptz<clock_timestamp()-interval '30 seconds' OR (NEW.document->>'observed_at')::timestamptz>clock_timestamp()+interval '5 seconds'
 OR encode(sha256(NEW.raw_document),'hex') IS DISTINCT FROM NEW.content_hash OR public.fleet_history_json_hash(NEW.document) IS DISTINCT FROM NEW.content_hash OR convert_from(NEW.raw_document,'UTF8')::jsonb IS DISTINCT FROM NEW.document THEN RAISE EXCEPTION 'joint decision refusal shape differs';END IF;
 IF reason='JOINT_DECISION_INPUTS_CHANGED' THEN
  BEGIN PERFORM public.fleet_joint_decision_inputs(NEW.tenant_id,req.assessment_request_id,req.capacity_request_id);EXCEPTION WHEN raise_exception THEN unavailable:=true;END;
  IF NOT unavailable THEN RAISE EXCEPTION 'joint decision current inputs cannot be labelled stale';END IF;
 END IF;
 NEW.writer_role:='finops_group_decision';NEW.created_at:=clock_timestamp();RETURN NEW;
END $$;
CREATE TRIGGER fleet_joint_refusal_guard BEFORE INSERT ON fleet_joint_decision_refusals FOR EACH ROW EXECUTE FUNCTION guard_fleet_joint_decision_refusal();
GRANT EXECUTE ON FUNCTION fleet_history_json_hash(jsonb),fleet_history_json_text(jsonb) TO finops_group_decision;
