-- Immutable analysis context. This is read-only recommendation metadata, never
-- approval, signed-plan or owned-restoration authority.
CREATE TABLE recommendation_currentness_contexts(
 tenant_id text NOT NULL,family text NOT NULL,recommendation_id text NOT NULL,resource_id text NOT NULL,
 document jsonb NOT NULL,captured_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,family,recommendation_id),CHECK(octet_length(document::text)<=65536)
);
ALTER TABLE recommendation_currentness_contexts ENABLE ROW LEVEL SECURITY;
ALTER TABLE recommendation_currentness_contexts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON recommendation_currentness_contexts USING(tenant_id=current_setting('app.tenant_id',true)) WITH CHECK(tenant_id=current_setting('app.tenant_id',true));
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE ON recommendation_currentness_contexts FOR EACH ROW EXECUTE FUNCTION deny_evidence_mutation();
CREATE INDEX recommendation_context_resource ON recommendation_currentness_contexts(tenant_id,resource_id,family,captured_at DESC);

CREATE FUNCTION public.recommendation_context_fingerprint(p_value jsonb) RETURNS text LANGUAGE sql IMMUTABLE
SET search_path=pg_catalog,pg_temp AS $$ SELECT encode(sha256(convert_to(coalesce(p_value,'null'::jsonb)::text,'UTF8')),'hex') $$;
REVOKE ALL ON FUNCTION public.recommendation_context_fingerprint(jsonb) FROM PUBLIC;

-- Only hashes and safe identity/revision metadata leave this broker. It does
-- not return configuration declarations, state, telemetry or provider payloads.
CREATE FUNCTION public.recommendation_context_inputs(p_resource text,p_sources text[]) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $$
DECLARE tenant_scope text:=current_setting('app.tenant_id',true); r jsonb;w jsonb;a jsonb;art jsonb;profile jsonb;slo jsonb;policies jsonb;telemetry jsonb;financial jsonb;generation text;
BEGIN
 IF coalesce(tenant_scope,'')='' OR p_resource IS NULL OR length(p_resource) NOT BETWEEN 1 AND 256 THEN RETURN NULL; END IF;
 IF p_sources IS NULL OR cardinality(p_sources)>64 OR coalesce(array_ndims(p_sources),1)<>1 THEN RAISE EXCEPTION 'recommendation source scope invalid'; END IF;
 SELECT document INTO r FROM public.entities WHERE tenant_id=tenant_scope AND kind='resources' AND id=p_resource;
 IF r IS NULL THEN RETURN NULL; END IF;
 SELECT public.recommendation_context_fingerprint(CASE WHEN document->'fixture'='true'::jsonb THEN document->'fixture_generation' ELSE NULL END) INTO generation FROM public.entities WHERE tenant_id=tenant_scope AND kind='org' AND id=tenant_scope;
 SELECT document INTO w FROM public.entities WHERE tenant_id=tenant_scope AND kind='workloads' AND id=r->>'workload_id';
 SELECT jsonb_build_object('id',id,'version',version,'hash',content_hash) INTO profile FROM public.workload_safety_profiles WHERE tenant_id=tenant_scope AND workload_id=r->>'workload_id' ORDER BY version DESC LIMIT 1;
 SELECT jsonb_build_object('id',id,'version',version,'hash',content_hash) INTO slo FROM public.slo_objectives WHERE tenant_id=tenant_scope AND workload_id=r->>'workload_id' ORDER BY version DESC LIMIT 1;
 SELECT coalesce(jsonb_agg(jsonb_build_object('id',id,'version',version,'hash',public.recommendation_context_fingerprint(document)) ORDER BY id),'[]'::jsonb) INTO policies FROM (SELECT id,version,document FROM public.entities WHERE tenant_id=tenant_scope AND kind='policies' AND (id='policy-default' OR document->>'workload_id'=r->>'workload_id') ORDER BY id LIMIT 129) bounded;
 SELECT jsonb_build_object('id',id,'version',version,'hash',content_hash) INTO a FROM public.configuration_authority_revisions WHERE tenant_id=tenant_scope AND resource_id=p_resource ORDER BY version DESC LIMIT 1;
 IF a IS NOT NULL THEN
  SELECT jsonb_build_object('commit',j.metadata->'git'->>'commit','receipt_id',p.id,'expires_at',p.expires_at,'registration_id',g.id,'registration_version',g.version,
   'active',NOT EXISTS(SELECT FROM public.configuration_artifact_revocations v WHERE v.tenant_id=g.tenant_id AND v.registration_id=g.id AND v.registration_version=g.version)
    AND NOT EXISTS(SELECT FROM public.configuration_artifact_registrations n WHERE n.tenant_id=g.tenant_id AND n.id=g.id AND n.version>g.version)) INTO art
  FROM public.configuration_artifact_receipts p JOIN public.configuration_artifact_jobs j ON j.tenant_id=p.tenant_id AND j.id=p.job_id
   JOIN public.configuration_artifact_registrations g ON g.tenant_id=j.tenant_id AND g.id=j.registration_id AND g.version=j.registration_version
  WHERE p.tenant_id=tenant_scope AND g.resource_id=p_resource AND g.authority_id=a->>'id' AND j.metadata->>'status'='OBSERVED'
  ORDER BY p.observed_at DESC,p.id DESC LIMIT 1;
 END IF;
 SELECT coalesce(jsonb_agg(jsonb_build_object('id',c.id,'version',c.version,'config_hash',c.config_hash,'enabled',c.config->'enabled',
  'revision_id',v.id,'revoked',EXISTS(SELECT FROM public.telemetry_source_revocations x WHERE x.tenant_id=v.tenant_id AND x.revision_id=v.id)) ORDER BY c.id),'[]'::jsonb) INTO telemetry
 FROM (SELECT c.* FROM public.telemetry_connections c WHERE c.tenant_id=tenant_scope AND c.config->'binding'->>'resource_id'=p_resource
  AND NOT EXISTS(SELECT FROM public.telemetry_connections n WHERE n.tenant_id=c.tenant_id AND n.id=c.id AND n.version>c.version) ORDER BY c.id LIMIT 129) c
 LEFT JOIN public.telemetry_source_revisions v ON v.tenant_id=c.tenant_id AND v.connection_id=c.id AND v.connection_version=c.version;
 SELECT coalesce(jsonb_agg(jsonb_build_object('id',s.id,'version',s.version,'kind',s.kind,'enabled',s.document->'enabled','revoked',s.document->'revoked','status',c.document->'status','latest_receipt_id',c.document->'latest_receipt_id','latest_revision_id',c.document->'latest_revision_id','ingestion_job_id',c.document->'ingestion_job_id','commitment_receipt_id',c.document->'commitment_receipt_id') ORDER BY s.id),'[]'::jsonb) INTO financial
 FROM public.source_registrations s LEFT JOIN public.source_checkpoints c ON c.tenant_id=s.tenant_id AND c.source_id=s.id AND c.checkpoint_key='status'
 WHERE s.tenant_id=tenant_scope AND s.id=ANY(p_sources) AND s.kind IN('AWS_CUR2','AWS_COMMITMENTS');
 RETURN jsonb_build_object('context_complete',jsonb_array_length(policies)<=128 AND jsonb_array_length(telemetry)<=128,'fixture_generation',generation,'resource_configuration',public.recommendation_context_fingerprint(r-ARRAY['id','tenant_id','version','last_seen_at','last_seen','observed_at','created_at','updated_at','monthly_effective_cost','hourly_effective_cost','eligibility','blockers','owner','owner_subject','workload_id','environment','aws_service_assessment_evidence','activity_evidence','aws_service_generation_id']),
  'workload_mapping',public.recommendation_context_fingerprint(jsonb_build_object('workload_id',r->'workload_id','provider',r->'provider','provider_resource_id',r->'provider_resource_id','account_id',r->'account_id','region',r->'region')),
  'ownership',public.recommendation_context_fingerprint(jsonb_build_object('resource_owner',r->'owner','resource_owner_subject',r->'owner_subject','environment',r->'environment','workload_owner',w->'owner','owner_subject',w->'owner_subject','criticality',w->'criticality','workload_environment',w->'environment')),
  'safety_profile',public.recommendation_context_fingerprint(profile),'slo',public.recommendation_context_fingerprint(slo),'policy',public.recommendation_context_fingerprint(policies),
  'configuration_authority',public.recommendation_context_fingerprint(a),'telemetry',public.recommendation_context_fingerprint(telemetry),'financial_sources',public.recommendation_context_fingerprint(financial),'financial_source_ids',to_jsonb(p_sources),
  'iac',CASE WHEN a IS NULL THEN NULL ELSE jsonb_build_object('authority_id',a->>'id','commit',art->>'commit','active',art->'active','expires_at',art->'expires_at') END);
END $$;
REVOKE ALL ON FUNCTION public.recommendation_context_inputs(text,text[]) FROM PUBLIC;

CREATE FUNCTION public.capture_recommendation_currentness() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $$
DECLARE family text;rid text;identifier text;inputs jsonb;refs jsonb:='[]'::jsonb;baseline jsonb;sources text[];
BEGIN
 IF NEW.tenant_id IS DISTINCT FROM current_setting('app.tenant_id',true) THEN RAISE EXCEPTION 'recommendation context tenant mismatch'; END IF;
 IF TG_TABLE_SCHEMA<>'public' OR TG_OP<>'INSERT' THEN RAISE EXCEPTION 'recommendation context capture invalid'; END IF;
 IF TG_TABLE_NAME='entities' THEN
  IF NEW.kind<>'recommendations' THEN RETURN NEW; END IF;
  family:='EC2';identifier:=NEW.id;rid:=NEW.document->>'resource_id';
 ELSE
  family:=CASE TG_TABLE_NAME WHEN 'database_recommendation_publications' THEN 'DATABASE' WHEN 'storage_recommendation_publications' THEN 'STORAGE' WHEN 'object_storage_recommendation_publications' THEN 'OBJECT_STORAGE' WHEN 'network_recommendation_publications' THEN 'NETWORK' WHEN 'lambda_recommendation_publications' THEN 'LAMBDA' WHEN 'aws_service_recommendation_publications' THEN 'AWS_SERVICE' END;
  identifier:=NEW.assessment_id;rid:=NEW.resource_id;
 END IF;
 IF family IS NULL THEN RAISE EXCEPTION 'recommendation context family invalid'; END IF;
 IF family='EC2' THEN
  SELECT document INTO baseline FROM public.readiness_evidence WHERE tenant_id=NEW.tenant_id AND kind='baseline' AND id=NEW.document->>'baseline_id' AND resource_id=rid;
  refs:=CASE WHEN jsonb_typeof(baseline->'source_refs')='array' THEN baseline->'source_refs' ELSE '[]'::jsonb END;
  IF baseline->>'source_connection_id' IS NOT NULL THEN refs:=refs||jsonb_build_array(jsonb_build_object('source_connection_id',baseline->>'source_connection_id')); END IF;
 END IF;
 refs:=refs||CASE WHEN jsonb_typeof(NEW.document->'assessment'->'financial_references')='array' THEN NEW.document->'assessment'->'financial_references' ELSE '[]'::jsonb END
  ||CASE WHEN jsonb_typeof(NEW.document->'assessment'->'source_refs')='array' THEN NEW.document->'assessment'->'source_refs' ELSE '[]'::jsonb END
  ||CASE WHEN jsonb_typeof(NEW.document->'source_refs')='array' THEN NEW.document->'source_refs' ELSE '[]'::jsonb END;
 SELECT coalesce(array_agg(DISTINCT s.id ORDER BY s.id),'{}'::text[]) INTO sources FROM jsonb_array_elements(refs) ref JOIN public.source_registrations s ON s.tenant_id=NEW.tenant_id AND s.id=coalesce(ref->>'source_connection_id',ref->>'source_id') AND s.kind IN('AWS_CUR2','AWS_COMMITMENTS');
 inputs:=public.recommendation_context_inputs(rid,sources);
 IF inputs IS NOT NULL THEN
  IF family='EC2' AND NEW.document->'fixture'='true'::jsonb AND EXISTS(SELECT FROM public.entities WHERE tenant_id=NEW.tenant_id AND kind='org' AND id=NEW.tenant_id AND document->'fixture'='true'::jsonb) THEN
   -- Reset reseeds the fixed fixture ID. Retain its first immutable context;
   -- its prior generation must read STALE, never acquire new analysis credit.
   INSERT INTO public.recommendation_currentness_contexts(tenant_id,family,recommendation_id,resource_id,document) VALUES(NEW.tenant_id,family,identifier,rid,inputs) ON CONFLICT(tenant_id,family,recommendation_id) DO NOTHING;
  ELSE
   INSERT INTO public.recommendation_currentness_contexts(tenant_id,family,recommendation_id,resource_id,document) VALUES(NEW.tenant_id,family,identifier,rid,inputs);
  END IF;
 END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION public.capture_recommendation_currentness() FROM PUBLIC;
CREATE TRIGGER recommendation_context_capture AFTER INSERT ON entities FOR EACH ROW WHEN(NEW.kind='recommendations') EXECUTE FUNCTION public.capture_recommendation_currentness();
DO $$ DECLARE tab text; BEGIN FOREACH tab IN ARRAY ARRAY['database_recommendation_publications','storage_recommendation_publications','object_storage_recommendation_publications','network_recommendation_publications','lambda_recommendation_publications','aws_service_recommendation_publications'] LOOP
 EXECUTE format('CREATE TRIGGER recommendation_context_capture AFTER INSERT ON public.%I FOR EACH ROW EXECUTE FUNCTION public.capture_recommendation_currentness()',tab);
END LOOP; END $$;

CREATE FUNCTION public.recommendation_currentness_context(p_family text,p_recommendation text) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $$
DECLARE tenant_scope text:=current_setting('app.tenant_id',true); c public.recommendation_currentness_contexts;
BEGIN
 IF coalesce(tenant_scope,'')='' OR p_family NOT IN('EC2','DATABASE','STORAGE','OBJECT_STORAGE','NETWORK','LAMBDA','AWS_SERVICE') OR length(p_recommendation) NOT BETWEEN 1 AND 256 THEN RETURN NULL; END IF;
 SELECT * INTO c FROM public.recommendation_currentness_contexts WHERE tenant_id=tenant_scope AND family=p_family AND recommendation_id=p_recommendation;
 IF c.recommendation_id IS NULL THEN RETURN NULL; END IF;
 RETURN jsonb_build_object('baseline',c.document,'current',public.recommendation_context_inputs(c.resource_id,ARRAY(SELECT jsonb_array_elements_text(c.document->'financial_source_ids'))),'captured_at',c.captured_at,'resource_id',c.resource_id);
END $$;
REVOKE ALL ON FUNCTION public.recommendation_currentness_context(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.recommendation_currentness_context(text,text) TO finops_api,finops_ingester,finops_database_analyst,finops_storage_analyst,finops_object_storage_analyst,finops_network_analyst,finops_lambda_analyst,finops_service_analyst;

CREATE FUNCTION public.recommendation_currentness_summary(p_account text,p_region text) RETURNS SETOF jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $$
DECLARE tenant_scope text:=current_setting('app.tenant_id',true);
BEGIN
 IF coalesce(tenant_scope,'')='' THEN RETURN; END IF;
 IF p_account IS NULL OR p_account!~'^[0-9]{12}$' OR p_region IS DISTINCT FROM 'eu-west-1' THEN RAISE EXCEPTION 'recommendation summary scope invalid'; END IF;
 RETURN QUERY SELECT public.recommendation_currentness_context(q.family,q.recommendation_id)||jsonb_build_object('family',q.family,'recommendation_id',q.recommendation_id)
 FROM (SELECT DISTINCT ON(c.family,c.resource_id) c.family,c.recommendation_id,c.resource_id,c.captured_at
  FROM public.recommendation_currentness_contexts c JOIN public.entities r ON r.tenant_id=c.tenant_id AND r.id=c.resource_id AND r.kind='resources'
  WHERE c.tenant_id=tenant_scope AND r.document->>'provider'='AWS' AND r.document->>'account_id'=p_account AND r.document->>'region'=p_region
  ORDER BY c.family,c.resource_id,c.captured_at DESC,c.recommendation_id DESC)q ORDER BY q.family,q.resource_id LIMIT 257;
END $$;
REVOKE ALL ON FUNCTION public.recommendation_currentness_summary(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.recommendation_currentness_summary(text,text) TO finops_api,finops_ingester;
