-- Isolated group fixture selection and exact prepared-program approval only.
-- No runtime, signing, customer execution or financial authority is enabled.
DO $$ BEGIN IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='finops_group_fixture') THEN CREATE ROLE finops_group_fixture NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;END IF;END $$;

CREATE TABLE fleet_fixture_profile_templates (id text PRIMARY KEY,model jsonb NOT NULL,model_hash text NOT NULL);
INSERT INTO fleet_fixture_profile_templates SELECT 'builtin-group-fixture-v1',m,public.fleet_history_json_hash(m) FROM(SELECT jsonb_build_object(
 'old_template',jsonb_build_object('id','lt-12345678','version',1,'instance_type','m6i.large','sha256',encode(sha256(convert_to('fixture-model-old-template','UTF8')),'hex')),
 'candidate_template',jsonb_build_object('id','lt-87654321','version',1,'instance_type','m6i.medium','sha256',encode(sha256(convert_to('fixture-model-candidate-template','UTF8')),'hex')),
 'budget',jsonb_build_object('cost_basis','FIXTURE_MODEL_COST','currency','USD','baseline_count',20,'max_in_flight',2,'max_unavailable',0,'max_blast_radius_ppm',100000,'max_surge_count',20,'old_hourly_cost','0.5','candidate_hourly_cost','0.3','maximum_model_cost','100','maximum_duration_seconds',21600),
 'policy',jsonb_build_object('id','isolated-group-fixture-policy','version',1,'sha256',encode(sha256(convert_to('fixture-model-policy-v1','UTF8')),'hex'),'approver_role','fleet_approver')) m)x;
CREATE TRIGGER fleet_fixture_templates_immutable BEFORE UPDATE OR DELETE ON fleet_fixture_profile_templates FOR EACH ROW EXECUTE FUNCTION public.deny_evidence_mutation();
CREATE TABLE fleet_fixture_profiles (
 id text PRIMARY KEY,generation text NOT NULL,content_hash text NOT NULL CHECK(content_hash~'^[a-f0-9]{64}$'),document jsonb NOT NULL,raw_document bytea NOT NULL,producer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),UNIQUE(id,generation),CHECK(octet_length(raw_document)<=16384)
);
-- Deliberately no installed generation is seeded by a migration. Only the
-- private producer may commission a real pinned local toolchain installation.
CREATE TRIGGER fleet_fixture_profiles_immutable BEFORE UPDATE OR DELETE ON fleet_fixture_profiles FOR EACH ROW EXECUTE FUNCTION public.deny_evidence_mutation();
GRANT SELECT ON fleet_fixture_profiles,fleet_fixture_profile_templates TO finops_api,finops_group_fixture;
GRANT INSERT ON fleet_fixture_profiles TO finops_group_fixture;
CREATE FUNCTION guard_fleet_fixture_installation() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE m public.fleet_fixture_profile_templates%ROWTYPE;BEGIN
 IF current_user<>'finops_group_fixture' THEN RAISE EXCEPTION 'fixture installation requires private producer';END IF;
 NEW.producer_role:='finops_group_fixture';NEW.created_at:=clock_timestamp();SELECT * INTO m FROM public.fleet_fixture_profile_templates WHERE id=NEW.document->'installation'->>'template_id';
 IF m.id IS NULL OR NEW.document->>'schema_version' IS DISTINCT FROM '1' OR NEW.document->>'id' IS DISTINCT FROM NEW.id OR NEW.document->>'generation' IS DISTINCT FROM NEW.generation OR NEW.generation !~ '^[a-f0-9-]{36}$' OR NEW.document->>'name' IS DISTINCT FROM 'Isolated built-in Terraform group fixture' OR NEW.document->>'realm_kind' IS DISTINCT FROM 'ISOLATED_FIXTURE' OR NEW.document->>'model_kind' IS DISTINCT FROM 'TERRAFORM_BUILTIN_FIXTURE' OR NEW.document->>'model_version' IS DISTINCT FROM '5.1' OR NEW.document->'runtime_available' IS DISTINCT FROM 'false'::jsonb OR NEW.document->'model' IS DISTINCT FROM m.model OR NEW.document->>'model_sha256' IS DISTINCT FROM m.model_hash OR coalesce(NEW.document->'installation'->>'toolchain_image_sha256','') !~ '^[a-f0-9]{64}$' OR NEW.document->'installation'->>'terraform_version' IS DISTINCT FROM '1.16.0' OR coalesce(NEW.document->'installation'->>'receipt_id','')='' OR coalesce(NEW.document->'installation'->>'source_sha256','') !~ '^[a-f0-9]{64}$' OR NOT NEW.document ?& ARRAY['schema_version','id','generation','name','realm_kind','model_kind','model_version','model_sha256','runtime_available','model','installation'] OR EXISTS(SELECT 1 FROM jsonb_object_keys(NEW.document) k WHERE k<>ALL(ARRAY['schema_version','id','generation','name','realm_kind','model_kind','model_version','model_sha256','runtime_available','model','installation'])) OR EXISTS(SELECT 1 FROM jsonb_object_keys(NEW.document->'installation') k WHERE k<>ALL(ARRAY['template_id','toolchain_image_sha256','terraform_version','receipt_id','source_sha256'])) OR encode(sha256(NEW.raw_document),'hex') IS DISTINCT FROM NEW.content_hash OR convert_from(NEW.raw_document,'UTF8')::jsonb IS DISTINCT FROM NEW.document THEN RAISE EXCEPTION 'fixture installation/model provenance differs';END IF;RETURN NEW;
END $$;
CREATE TRIGGER fleet_fixture_installation_guard BEFORE INSERT ON fleet_fixture_profiles FOR EACH ROW EXECUTE FUNCTION guard_fleet_fixture_installation();

CREATE TABLE fleet_fixture_proposals (
 tenant_id text NOT NULL,id text NOT NULL,workload_id text NOT NULL,profile_id text NOT NULL,profile_generation text NOT NULL,
 old_configuration_proposal_id text NOT NULL,candidate_configuration_proposal_id text NOT NULL,
 content_hash text NOT NULL CHECK(content_hash~'^[a-f0-9]{64}$'),document jsonb NOT NULL,raw_document bytea NOT NULL,
 writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,id),FOREIGN KEY(profile_id,profile_generation) REFERENCES fleet_fixture_profiles(id,generation),
 FOREIGN KEY(tenant_id,old_configuration_proposal_id) REFERENCES fleet_configuration_proposals(tenant_id,id),
 FOREIGN KEY(tenant_id,candidate_configuration_proposal_id) REFERENCES fleet_configuration_proposals(tenant_id,id),CHECK(old_configuration_proposal_id<>candidate_configuration_proposal_id),CHECK(octet_length(raw_document)<=65536)
);
CREATE TABLE fleet_fixture_prepared_programs (
 tenant_id text NOT NULL,id text NOT NULL,proposal_id text NOT NULL,
 program_hash text NOT NULL CHECK(program_hash~'^[a-f0-9]{64}$'),manifest_hash text NOT NULL CHECK(manifest_hash~'^[a-f0-9]{64}$'),journal_review_hash text NOT NULL CHECK(journal_review_hash~'^[a-f0-9]{64}$'),
 program jsonb NOT NULL,program_raw bytea NOT NULL,journal_review jsonb NOT NULL,journal_review_raw bytea NOT NULL,
 proof_hash text NOT NULL CHECK(proof_hash~'^[a-f0-9]{64}$'),artifact_refs jsonb NOT NULL,
 producer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,id),UNIQUE(tenant_id,proposal_id),UNIQUE(tenant_id,id,program_hash),FOREIGN KEY(tenant_id,proposal_id) REFERENCES fleet_fixture_proposals(tenant_id,id),CHECK(octet_length(program_raw)<=262144),CHECK(octet_length(journal_review_raw)<=32768)
);
CREATE TABLE fleet_fixture_approvals (
 tenant_id text NOT NULL,id text NOT NULL,proposal_id text NOT NULL,prepared_program_id text NOT NULL,actor_id text NOT NULL,
 program_hash text NOT NULL,manifest_hash text NOT NULL,journal_review_hash text NOT NULL,
 content_hash text NOT NULL CHECK(content_hash~'^[a-f0-9]{64}$'),document jsonb NOT NULL,raw_document bytea NOT NULL,
 writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,id),UNIQUE(tenant_id,proposal_id),FOREIGN KEY(tenant_id,proposal_id) REFERENCES fleet_fixture_proposals(tenant_id,id),
 FOREIGN KEY(tenant_id,prepared_program_id,program_hash) REFERENCES fleet_fixture_prepared_programs(tenant_id,id,program_hash),CHECK(octet_length(raw_document)<=8192)
);
CREATE INDEX fleet_fixture_proposals_page ON fleet_fixture_proposals(tenant_id,workload_id,created_at DESC,id DESC);
DO $$ DECLARE tab text;BEGIN FOREACH tab IN ARRAY ARRAY['fleet_fixture_proposals','fleet_fixture_prepared_programs','fleet_fixture_approvals'] LOOP
 EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',tab);EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',tab);
 EXECUTE format('CREATE POLICY tenant_isolation ON %I USING(tenant_id=current_setting(''app.tenant_id'',true)) WITH CHECK(tenant_id=current_setting(''app.tenant_id'',true))',tab);
 EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION public.deny_evidence_mutation()',tab||'_immutable',tab);
 END LOOP;END $$;
GRANT SELECT ON fleet_fixture_proposals,fleet_fixture_prepared_programs,fleet_fixture_approvals TO finops_api,finops_group_fixture;
GRANT INSERT ON fleet_fixture_proposals,fleet_fixture_approvals TO finops_api;
GRANT INSERT ON fleet_fixture_prepared_programs TO finops_group_fixture;
GRANT SELECT ON entities,source_registrations,source_checkpoints,activity_sources,fleet_history_registrations,fleet_demand_definitions,fleet_history_scopes,fleet_history_scope_references,fleet_history_observations,fleet_configuration_declarations,fleet_configuration_proposals TO finops_group_fixture;
GRANT EXECUTE ON FUNCTION fleet_history_source_lock(text,text) TO finops_group_fixture;
GRANT EXECUTE ON FUNCTION fleet_history_json_text(jsonb),fleet_history_json_hash(jsonb),fleet_history_source_config(jsonb),fleet_history_lock(text,text) TO finops_group_fixture;
GRANT EXECUTE ON FUNCTION fleet_configuration_registration(text,text),fleet_configuration_scope_sources(text,text,text,timestamptz) TO finops_group_fixture;

-- Called BEFORE current source/head reads. All selectors have the same order:
-- graph -> sorted registrations -> sorted shared Sync guards -> source rows.
CREATE FUNCTION fleet_fixture_selection_current(p_tenant text,p_old text,p_candidate text) RETURNS jsonb LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE o public.fleet_configuration_proposals%ROWTYPE;c public.fleet_configuration_proposals%ROWTYPE;x record;r jsonb;rh text;decl public.fleet_configuration_declarations%ROWTYPE;sc public.fleet_history_scopes%ROWTYPE;states jsonb;srcv bigint;side jsonb;result jsonb:='{}';om jsonb;cm jsonb;BEGIN
 IF p_tenant IS NULL OR p_tenant='' OR p_tenant IS DISTINCT FROM current_setting('app.tenant_id',true) OR coalesce(p_old,'')='' OR coalesce(p_candidate,'')='' OR p_old=p_candidate THEN RETURN NULL;END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(p_tenant||':dependency-graph',0));
 SELECT * INTO o FROM public.fleet_configuration_proposals WHERE tenant_id=p_tenant AND id=p_old;SELECT * INTO c FROM public.fleet_configuration_proposals WHERE tenant_id=p_tenant AND id=p_candidate;
 IF o.id IS NULL OR c.id IS NULL OR o.registration_id=c.registration_id OR o.workload_id IS DISTINCT FROM c.workload_id THEN RETURN NULL;END IF;
 FOR x IN SELECT DISTINCT id FROM unnest(ARRAY[o.registration_id,c.registration_id]) id ORDER BY id LOOP PERFORM public.fleet_history_lock(p_tenant,x.id);END LOOP;
 FOR x IN SELECT DISTINCT source_id FROM (
  SELECT document->>'source_id' source_id FROM public.fleet_history_registrations WHERE tenant_id=p_tenant AND id IN(o.registration_id,c.registration_id)
  UNION SELECT document->>'source_id' FROM public.fleet_history_scope_references WHERE tenant_id=p_tenant AND scope_id IN(o.scope_id,c.scope_id) AND kind='SOURCE_STATE' AND document->>'source_system'='AWS_SOURCE_CONNECTION'
 ) s ORDER BY source_id LOOP
  IF NOT pg_try_advisory_xact_lock_shared(hashtextextended(p_tenant||':trusted-source:'||x.source_id,0)) THEN RAISE EXCEPTION USING ERRCODE='55P03',MESSAGE='FLEET_FIXTURE_SOURCE_BUSY';END IF;
  IF NOT public.fleet_history_source_lock(p_tenant,x.source_id) THEN RETURN NULL;END IF;
 END LOOP;
 FOR x IN SELECT 'old' label,o.id proposal_id UNION ALL SELECT 'candidate',c.id LOOP
  SELECT * INTO decl FROM public.fleet_configuration_declarations WHERE tenant_id=p_tenant AND id=(SELECT declaration_id FROM public.fleet_configuration_proposals WHERE tenant_id=p_tenant AND id=x.proposal_id);
  r:=public.fleet_configuration_registration(p_tenant,decl.registration_id);
  IF r IS NULL OR decl.id IS NULL OR decl.id IS DISTINCT FROM (SELECT id FROM public.fleet_configuration_declarations WHERE tenant_id=p_tenant AND registration_id=decl.registration_id ORDER BY version DESC LIMIT 1) OR decl.registration_version IS DISTINCT FROM (r->>'version')::bigint THEN RETURN NULL;END IF;
  SELECT * INTO sc FROM public.fleet_history_scopes WHERE tenant_id=p_tenant AND id=(SELECT scope_id FROM public.fleet_configuration_proposals WHERE tenant_id=p_tenant AND id=x.proposal_id);
  SELECT content_hash INTO rh FROM public.fleet_history_registrations WHERE tenant_id=p_tenant AND id=decl.registration_id AND version=decl.registration_version;
  IF sc.id IS NULL OR sc.registration_version IS DISTINCT FROM decl.registration_version OR sc.document->>'registration_hash' IS DISTINCT FROM rh OR decl.document->>'registration_hash' IS DISTINCT FROM rh THEN RETURN NULL;END IF;
  states:=public.fleet_configuration_scope_sources(p_tenant,decl.registration_id,sc.id,clock_timestamp());
  IF states IS NULL OR EXISTS(SELECT 1 FROM jsonb_array_elements(states) st WHERE st->>'status' IS DISTINCT FROM 'ACTIVE') THEN RETURN NULL;END IF;
  SELECT version INTO srcv FROM public.source_registrations WHERE tenant_id=p_tenant AND id=r->>'source_id';
  side:=jsonb_build_object('target',jsonb_build_object('tenant_id',p_tenant,'workload_id',r->'binding'->>'workload_id','provider',r->'binding'->>'provider','account_id',r->'binding'->>'account_id','region',r->'binding'->>'region','fleet_id',r->>'fleet_id','asg_arn',r->>'asg_arn'),'registration',jsonb_build_object('id',decl.registration_id,'version',decl.registration_version,'sha256',rh),'declaration',jsonb_build_object('id',decl.id,'version',decl.version,'sha256',decl.content_hash),'scope',jsonb_build_object('id',sc.id,'sha256',sc.content_hash),'source_id',r->>'source_id','source_registration_version',srcv,'source_config_sha256',r->>'source_config_hash');
  result:=result||jsonb_build_object(x.label,side);
  IF x.label='old' THEN om:=decl.document->'metadata';ELSE cm:=decl.document->'metadata';END IF;
 END LOOP;
 IF result->'old'->'target'->>'provider' IS DISTINCT FROM 'AWS' OR result->'old'->'target'->>'region' IS DISTINCT FROM 'eu-west-1' OR result->'old'->'target'->>'account_id' IS DISTINCT FROM result->'candidate'->'target'->>'account_id' OR result->'old'->'target'->>'region' IS DISTINCT FROM result->'candidate'->'target'->>'region' OR result->'candidate'->'target'->>'provider' IS DISTINCT FROM 'AWS' OR result->'old'->'target'->>'fleet_id'=result->'candidate'->'target'->>'fleet_id' OR result->'old'->'target'->>'asg_arn'=result->'candidate'->'target'->>'asg_arn' THEN RETURN NULL;END IF;
 IF om->'repository' IS DISTINCT FROM cm->'repository' OR om->'pipeline' IS DISTINCT FROM cm->'pipeline' OR om->'terraform'->>'workspace' IS DISTINCT FROM cm->'terraform'->>'workspace' OR om->'terraform'->>'state_lineage' IS DISTINCT FROM cm->'terraform'->>'state_lineage' OR om->'terraform'->'traffic' IS NULL OR om->'terraform'->'traffic' IS DISTINCT FROM cm->'terraform'->'traffic' OR om->'terraform'->>'asg_address'=cm->'terraform'->>'asg_address' OR om->'terraform'->>'launch_template_address'=cm->'terraform'->>'launch_template_address' THEN RETURN NULL;END IF;
 RETURN result;
END $$;

CREATE FUNCTION guard_fleet_fixture_proposal() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE profile jsonb;binding jsonb;o public.fleet_configuration_proposals%ROWTYPE;c public.fleet_configuration_proposals%ROWTYPE;BEGIN
 IF NEW.tenant_id IS DISTINCT FROM current_setting('app.tenant_id',true) OR current_user<>'finops_api' THEN RAISE EXCEPTION 'fleet fixture requires API role';END IF;
 NEW.writer_role:='finops_api';NEW.created_at:=clock_timestamp();
 SELECT document INTO profile FROM public.fleet_fixture_profiles WHERE id=NEW.profile_id AND generation=NEW.profile_generation;
 binding:=public.fleet_fixture_selection_current(NEW.tenant_id,NEW.old_configuration_proposal_id,NEW.candidate_configuration_proposal_id);
 SELECT * INTO o FROM public.fleet_configuration_proposals WHERE tenant_id=NEW.tenant_id AND id=NEW.old_configuration_proposal_id;SELECT * INTO c FROM public.fleet_configuration_proposals WHERE tenant_id=NEW.tenant_id AND id=NEW.candidate_configuration_proposal_id;
 IF profile IS NULL OR binding IS NULL OR NEW.document->'binding' IS DISTINCT FROM binding OR NEW.document->'profile' IS DISTINCT FROM profile OR NEW.document->>'schema_version' IS DISTINCT FROM '1' OR NEW.document->>'id' IS DISTINCT FROM NEW.id OR NEW.document->>'purpose' IS DISTINCT FROM 'ISOLATED_GROUP_FIXTURE_PROPOSAL' OR NEW.document->>'workload_id' IS DISTINCT FROM NEW.workload_id OR NEW.workload_id IS DISTINCT FROM o.workload_id OR (coalesce(NEW.document->>'creator_id','') !~ '^[!-~]+$' OR length(NEW.document->>'creator_id')>256) OR NEW.document->'realm' IS DISTINCT FROM jsonb_build_object('kind','ISOLATED_FIXTURE','fixture_id',NEW.profile_id,'generation',NEW.profile_generation,'model_sha256',profile->>'model_sha256') OR NEW.document->'customer_execution_authorized' IS DISTINCT FROM 'false'::jsonb OR NEW.document->'estimated_saving' IS DISTINCT FROM 'null'::jsonb OR NEW.document->'verified_saving' IS DISTINCT FROM 'null'::jsonb OR NEW.document->'old_configuration_proposal' IS DISTINCT FROM jsonb_build_object('id',o.id,'sha256',o.content_hash,'scope_reference_root',o.document->>'scope_reference_root','customer_status','BLOCKED','customer_reasons',o.document->'reason_codes') OR NEW.document->'candidate_configuration_proposal' IS DISTINCT FROM jsonb_build_object('id',c.id,'sha256',c.content_hash,'scope_reference_root',c.document->>'scope_reference_root','customer_status','BLOCKED','customer_reasons',c.document->'reason_codes') OR EXISTS(SELECT 1 FROM jsonb_object_keys(NEW.document) k WHERE k<>ALL(ARRAY['schema_version','id','purpose','creator_id','workload_id','profile','realm','binding','old_configuration_proposal','candidate_configuration_proposal','customer_execution_authorized','estimated_saving','verified_saving'])) OR encode(sha256(NEW.raw_document),'hex') IS DISTINCT FROM NEW.content_hash OR convert_from(NEW.raw_document,'UTF8')::jsonb IS DISTINCT FROM NEW.document THEN RAISE EXCEPTION 'fleet fixture selection or exact no-authority seal differs';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER fleet_fixture_proposal_guard BEFORE INSERT ON fleet_fixture_proposals FOR EACH ROW EXECUTE FUNCTION guard_fleet_fixture_proposal();

CREATE FUNCTION fleet_fixture_proposal_current(p_tenant text,p_id text) RETURNS jsonb LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE p public.fleet_fixture_proposals%ROWTYPE;b jsonb;BEGIN
 IF p_tenant IS DISTINCT FROM current_setting('app.tenant_id',true) OR coalesce(p_id,'')='' THEN RETURN NULL;END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(p_tenant||':dependency-graph',0));PERFORM pg_advisory_xact_lock(hashtextextended(p_tenant||':fleet-fixture:'||p_id,0));
 SELECT * INTO p FROM public.fleet_fixture_proposals WHERE tenant_id=p_tenant AND id=p_id;IF p.id IS NULL THEN RETURN NULL;END IF;
 b:=public.fleet_fixture_selection_current(p_tenant,p.old_configuration_proposal_id,p.candidate_configuration_proposal_id);
 IF b IS DISTINCT FROM p.document->'binding' THEN RETURN NULL;END IF;RETURN p.document;
END $$;

CREATE FUNCTION guard_fleet_fixture_preparation() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE p jsonb;ref jsonb;mapping jsonb;seen text[]:='{}';proof_seen boolean:=false;state_seen boolean:=false;BEGIN
 IF NEW.tenant_id IS DISTINCT FROM current_setting('app.tenant_id',true) OR current_user<>'finops_group_fixture' THEN RAISE EXCEPTION 'fleet fixture preparation requires private producer';END IF;
 NEW.producer_role:='finops_group_fixture';NEW.created_at:=clock_timestamp();p:=public.fleet_fixture_proposal_current(NEW.tenant_id,NEW.proposal_id);
 IF NOT NEW.program ?& ARRAY['schema_version','kind','id','binding','realm','creator_id','environment','policy','artifact_context','manifest','manifest_sha256','old_template','candidate_template','budget','stages','evidence','created_at','expires_at','nonce'] OR NOT NEW.journal_review ?& ARRAY['schema_version','policy','ref','pipeline_id','pipeline_key_sha256','ledger_key_sha256','base','max_effects','max_records','expires_at'] OR EXISTS(SELECT 1 FROM jsonb_object_keys(NEW.journal_review) k WHERE k<>ALL(ARRAY['schema_version','policy','ref','pipeline_id','pipeline_key_sha256','ledger_key_sha256','base','max_effects','max_records','expires_at'])) THEN RAISE EXCEPTION 'fleet fixture prepared metadata missing';END IF;
 IF NEW.program->>'artifact_context' IS NULL THEN RAISE EXCEPTION 'fleet fixture artifact context missing';END IF;
 IF NEW.program->'artifact_context'->>'repository_id' IS DISTINCT FROM NEW.proposal_id OR NEW.program->'artifact_context'->>'pipeline_id' IS DISTINCT FROM ('fixture-pipeline-'||(p->'profile'->>'generation')) OR NEW.program->'artifact_context'->>'workspace' IS DISTINCT FROM 'default' OR NEW.program->'artifact_context'->>'toolchain_image_sha256' IS DISTINCT FROM p->'profile'->'installation'->>'toolchain_image_sha256' OR NEW.program->'artifact_context'->>'terraform_version' IS DISTINCT FROM p->'profile'->'installation'->>'terraform_version' OR NEW.program->'old_template' IS DISTINCT FROM p->'profile'->'model'->'old_template' OR NEW.program->'candidate_template' IS DISTINCT FROM p->'profile'->'model'->'candidate_template' OR NEW.program->'budget' IS DISTINCT FROM p->'profile'->'model'->'budget' OR NEW.program->'policy' IS DISTINCT FROM p->'profile'->'model'->'policy' THEN RAISE EXCEPTION 'fleet fixture installed model or pipeline differs';END IF;
 SELECT jsonb_build_object('old_declared_asg',o.document->'metadata'->'terraform'->>'asg_address','candidate_declared_asg',c.document->'metadata'->'terraform'->>'asg_address','declared_listener_rule',o.document->'metadata'->'terraform'->'traffic'->>'listener_rule_address','old_model','terraform_data.old','candidate_model','terraform_data.candidate','traffic_model','terraform_data.traffic') INTO mapping FROM public.fleet_configuration_declarations o,public.fleet_configuration_declarations c WHERE o.tenant_id=NEW.tenant_id AND c.tenant_id=NEW.tenant_id AND o.id=p->'binding'->'old'->'declaration'->>'id' AND c.id=p->'binding'->'candidate'->'declaration'->>'id';
 IF mapping IS NULL OR NEW.program->'artifact_context'->'mapping' IS DISTINCT FROM mapping THEN RAISE EXCEPTION 'fleet fixture declared mapping differs';END IF;
 IF p IS NULL OR encode(sha256(NEW.program_raw),'hex') IS DISTINCT FROM NEW.program_hash OR convert_from(NEW.program_raw,'UTF8')::jsonb IS DISTINCT FROM NEW.program OR encode(sha256(NEW.journal_review_raw),'hex') IS DISTINCT FROM NEW.journal_review_hash OR convert_from(NEW.journal_review_raw,'UTF8')::jsonb IS DISTINCT FROM NEW.journal_review OR NEW.program->>'schema_version' IS DISTINCT FROM '5.1' OR NEW.program->>'kind' IS DISTINCT FROM 'STATELESS_GROUP_RIGHTSIZING' OR NEW.program->'binding' IS DISTINCT FROM p->'binding' OR NEW.program->'realm' IS DISTINCT FROM p->'realm' OR NEW.program->>'creator_id' IS DISTINCT FROM p->>'creator_id' OR NEW.program->>'manifest_sha256' IS DISTINCT FROM NEW.manifest_hash OR NEW.program->>'environment' IS DISTINCT FROM 'NON_PRODUCTION' OR (NEW.program->>'created_at')::timestamptz>clock_timestamp()+interval '5 seconds' OR (NEW.program->>'expires_at')::timestamptz<=clock_timestamp() OR NEW.journal_review->>'schema_version' IS DISTINCT FROM '1' OR NEW.journal_review->'policy' IS DISTINCT FROM NEW.program->'policy' OR NEW.journal_review->>'ref' IS DISTINCT FROM NEW.program->'manifest'->>'ref' OR NEW.journal_review->>'pipeline_id' IS DISTINCT FROM NEW.program->'artifact_context'->>'pipeline_id' OR coalesce(NEW.journal_review->>'pipeline_key_sha256','') !~ '^[a-f0-9]{64}$' OR coalesce(NEW.journal_review->>'ledger_key_sha256','') !~ '^[a-f0-9]{64}$' OR NEW.journal_review->>'pipeline_key_sha256'=NEW.journal_review->>'ledger_key_sha256' OR NEW.journal_review->'base'->'revision' IS DISTINCT FROM NEW.program->'manifest'->'base' OR NEW.journal_review->'base'->>'state_lineage' IS DISTINCT FROM NEW.program->'artifact_context'->>'state_lineage' OR NEW.journal_review->'base'->'state_serial' IS DISTINCT FROM NEW.program->'artifact_context'->'initial_state_serial' OR coalesce(NEW.journal_review->'base'->>'state_sha256','') !~ '^[a-f0-9]{64}$' OR NEW.journal_review->'base'->'model' IS DISTINCT FROM NEW.program->'manifest'->'entries'->0->'before' OR coalesce((NEW.journal_review->>'max_effects')::bigint,0) NOT BETWEEN 1 AND 32 OR coalesce((NEW.journal_review->>'max_records')::bigint,0) NOT BETWEEN 1 AND 512 OR NEW.journal_review->'expires_at' IS DISTINCT FROM NEW.program->'expires_at' OR jsonb_typeof(NEW.artifact_refs) IS DISTINCT FROM 'array' OR jsonb_array_length(NEW.artifact_refs) NOT BETWEEN 1 AND 128 THEN RAISE EXCEPTION 'fleet fixture prepared program binding differs';END IF;
 FOR ref IN SELECT value FROM jsonb_array_elements(NEW.artifact_refs) LOOP
  IF NOT ref ?& ARRAY['id','bucket','key','version_id','sha256','size_bytes'] OR EXISTS(SELECT 1 FROM jsonb_object_keys(ref) k WHERE k<>ALL(ARRAY['id','bucket','key','version_id','sha256','size_bytes'])) OR coalesce(ref->>'id','')='' OR ref->>'id'=ANY(seen) OR coalesce(ref->>'bucket','')='' OR coalesce(ref->>'key','')='' OR coalesce(ref->>'version_id','')='' OR coalesce(ref->>'sha256','') !~ '^[a-f0-9]{64}$' OR coalesce((ref->>'size_bytes')::bigint,0) NOT BETWEEN 1 AND 16777216 THEN RAISE EXCEPTION 'fleet fixture private artifact pin differs';END IF;seen:=array_append(seen,ref->>'id');IF ref->>'sha256'=NEW.proof_hash THEN proof_seen:=true;END IF;IF ref->>'sha256'=NEW.journal_review->'base'->>'state_sha256' THEN state_seen:=true;END IF;
 END LOOP;
 IF NOT proof_seen OR NOT state_seen THEN RAISE EXCEPTION 'fleet fixture Git or base native state archive missing';END IF;
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(NEW.program->'evidence') e WHERE NOT EXISTS(SELECT 1 FROM jsonb_array_elements(NEW.artifact_refs) a WHERE a->>'id'=e->>'id' AND a->>'sha256'=e->>'sha256')) THEN RAISE EXCEPTION 'fleet fixture evidence archive missing';END IF;RETURN NEW;
END $$;
CREATE TRIGGER fleet_fixture_preparation_guard BEFORE INSERT ON fleet_fixture_prepared_programs FOR EACH ROW EXECUTE FUNCTION guard_fleet_fixture_preparation();

CREATE FUNCTION guard_fleet_fixture_approval() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE p jsonb;prepared public.fleet_fixture_prepared_programs%ROWTYPE;proposal_hash text;BEGIN
 IF NEW.tenant_id IS DISTINCT FROM current_setting('app.tenant_id',true) OR current_user<>'finops_api' THEN RAISE EXCEPTION 'fleet fixture approval requires API';END IF;
 NEW.writer_role:='finops_api';NEW.created_at:=clock_timestamp();p:=public.fleet_fixture_proposal_current(NEW.tenant_id,NEW.proposal_id);
 SELECT * INTO prepared FROM public.fleet_fixture_prepared_programs WHERE tenant_id=NEW.tenant_id AND proposal_id=NEW.proposal_id AND id=NEW.prepared_program_id;
 SELECT content_hash INTO proposal_hash FROM public.fleet_fixture_proposals WHERE tenant_id=NEW.tenant_id AND id=NEW.proposal_id;
 IF p IS NULL OR prepared.id IS NULL OR NEW.actor_id=p->>'creator_id' OR (coalesce(NEW.actor_id,'') !~ '^[!-~]+$' OR length(NEW.actor_id)>256) OR NEW.program_hash IS DISTINCT FROM prepared.program_hash OR NEW.manifest_hash IS DISTINCT FROM prepared.manifest_hash OR NEW.journal_review_hash IS DISTINCT FROM prepared.journal_review_hash OR (prepared.program->>'expires_at')::timestamptz<=clock_timestamp() OR NEW.document IS DISTINCT FROM jsonb_build_object('schema_version','1','id',NEW.id,'proposal_id',NEW.proposal_id,'proposal_hash',proposal_hash,'prepared_program_id',prepared.id,'program_hash',prepared.program_hash,'manifest_hash',prepared.manifest_hash,'journal_review_hash',prepared.journal_review_hash,'actor_id',NEW.actor_id,'role','fleet_approver','approval_scope','EXACT_FIXTURE_PROGRAM_AND_JOURNAL_REVIEW','customer_execution_authorized',false,'estimated_saving',NULL,'verified_saving',NULL) OR encode(sha256(NEW.raw_document),'hex') IS DISTINCT FROM NEW.content_hash OR convert_from(NEW.raw_document,'UTF8')::jsonb IS DISTINCT FROM NEW.document THEN RAISE EXCEPTION 'fleet fixture independent exact-program approval differs';END IF;RETURN NEW;
END $$;
CREATE TRIGGER fleet_fixture_approval_guard BEFORE INSERT ON fleet_fixture_approvals FOR EACH ROW EXECUTE FUNCTION guard_fleet_fixture_approval();

REVOKE ALL ON FUNCTION fleet_fixture_selection_current(text,text,text),fleet_fixture_proposal_current(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION fleet_fixture_selection_current(text,text,text),fleet_fixture_proposal_current(text,text) TO finops_api,finops_group_fixture;
