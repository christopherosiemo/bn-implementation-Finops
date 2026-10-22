-- Commitment advice extends the existing analytical identity and recommendation
-- queue. Neither this result nor Finance review authorizes a provider purchase.
CREATE TABLE configuration_artifact_readback_proofs(
 tenant_id text NOT NULL,receipt_id text NOT NULL,registration_id text NOT NULL,registration_version bigint NOT NULL,
 receipt_sha256 text NOT NULL,metadata_sha256 text NOT NULL,archive jsonb NOT NULL,ciphertext bytea NOT NULL,receipt jsonb NOT NULL,
 writer_role name NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,receipt_id),FOREIGN KEY(tenant_id,receipt_id) REFERENCES configuration_artifact_receipts(tenant_id,id),
 CHECK(octet_length(ciphertext) BETWEEN 1 AND 8388608)
);
ALTER TABLE configuration_artifact_readback_proofs ENABLE ROW LEVEL SECURITY;
ALTER TABLE configuration_artifact_readback_proofs FORCE ROW LEVEL SECURITY;
CREATE POLICY attestor_scope ON configuration_artifact_readback_proofs TO finops_configuration_attestor USING(tenant_id=current_setting('app.tenant_id',true)) WITH CHECK(tenant_id=current_setting('app.tenant_id',true));
DO $$ BEGIN EXECUTE format('CREATE POLICY operator_scope ON configuration_artifact_readback_proofs TO %I USING(true) WITH CHECK(true)',current_user);END $$;
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE ON configuration_artifact_readback_proofs FOR EACH ROW EXECUTE FUNCTION public.deny_evidence_mutation();
GRANT SELECT,INSERT ON configuration_artifact_readback_proofs TO finops_configuration_attestor;
CREATE FUNCTION guard_commitment_artifact_readback() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE receipt public.configuration_artifact_receipts%ROWTYPE;BEGIN
 IF current_setting('role',true)<>'finops_configuration_attestor' OR NEW.tenant_id IS DISTINCT FROM current_setting('app.tenant_id',true) THEN RAISE EXCEPTION 'authenticated artifact attestor required';END IF;
 SELECT * INTO receipt FROM public.configuration_artifact_receipts WHERE tenant_id=NEW.tenant_id AND id=NEW.receipt_id AND writer_role='finops_configuration_attestor';
 IF receipt.id IS NULL OR NEW.registration_id IS DISTINCT FROM receipt.document->'metadata'->>'registration_id' OR NEW.registration_version IS DISTINCT FROM (receipt.document->'metadata'->>'registration_version')::bigint OR NEW.receipt-ARRAY['observed_at','received_at','expires_at'] IS DISTINCT FROM receipt.document-ARRAY['observed_at','received_at','expires_at'] OR (NEW.receipt->>'observed_at')::timestamptz IS DISTINCT FROM receipt.observed_at OR (NEW.receipt->>'received_at')::timestamptz IS DISTINCT FROM receipt.received_at OR (NEW.receipt->>'expires_at')::timestamptz IS DISTINCT FROM receipt.expires_at OR NEW.receipt_sha256 IS DISTINCT FROM public.fleet_history_json_hash(NEW.receipt) OR NEW.archive IS DISTINCT FROM receipt.document->'archive' OR encode(sha256(NEW.ciphertext),'hex') IS DISTINCT FROM NEW.archive->>'sha256' OR octet_length(NEW.ciphertext) IS DISTINCT FROM (NEW.archive->>'bytes')::bigint THEN RAISE EXCEPTION 'artifact authenticated version readback differs';END IF;
 PERFORM public.configuration_artifact_current(NEW.tenant_id,NEW.registration_id,NEW.registration_version);
 NEW.metadata_sha256:=public.fleet_history_json_hash(receipt.document->'metadata');NEW.writer_role:='finops_configuration_attestor';NEW.created_at:=clock_timestamp();RETURN NEW;
END $$;
CREATE TRIGGER authenticated_readback BEFORE INSERT ON configuration_artifact_readback_proofs FOR EACH ROW EXECUTE FUNCTION guard_commitment_artifact_readback();
REVOKE ALL ON FUNCTION guard_commitment_artifact_readback() FROM PUBLIC;

CREATE TABLE commitment_ownership_registrations(
 tenant_id text NOT NULL,id text NOT NULL,revision bigint NOT NULL CHECK(revision>0),document jsonb NOT NULL,
 operator_created_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(tenant_id,id,revision),CHECK(octet_length(document::text)<=8192)
);
CREATE TABLE commitment_ownership_revocations(
 tenant_id text NOT NULL,registration_id text NOT NULL,revision bigint NOT NULL,reason_code text NOT NULL CHECK(reason_code~'^[A-Z][A-Z0-9_]{0,127}$'),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(tenant_id,registration_id,revision),FOREIGN KEY(tenant_id,registration_id,revision) REFERENCES commitment_ownership_registrations(tenant_id,id,revision)
);
CREATE TABLE commitment_ownership_journals(
 tenant_id text NOT NULL,id text NOT NULL,registration_id text NOT NULL,registration_revision bigint NOT NULL,workload_id text NOT NULL,resource_id text NOT NULL,sequence bigint NOT NULL CHECK(sequence>0),
 scope_sha256 text NOT NULL,period_start timestamptz NOT NULL,period_end timestamptz NOT NULL,
 issuer text NOT NULL,subject text NOT NULL,audience text NOT NULL,raw_envelope bytea NOT NULL,envelope_sha256 text NOT NULL,
 server_recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(tenant_id,id),UNIQUE(tenant_id,registration_id,registration_revision,resource_id,sequence),
 FOREIGN KEY(tenant_id,registration_id,registration_revision) REFERENCES commitment_ownership_registrations(tenant_id,id,revision),CHECK(octet_length(raw_envelope) BETWEEN 1 AND 16384)
);
CREATE TABLE commitment_ownership_reviews(
 tenant_id text NOT NULL,id text NOT NULL,registration_id text NOT NULL,registration_revision bigint NOT NULL,workload_id text NOT NULL,
 scope_sha256 text NOT NULL,period_start timestamptz NOT NULL,period_end timestamptz NOT NULL,
 issuer text NOT NULL,subject text NOT NULL,audience text NOT NULL,raw_envelope bytea NOT NULL,envelope_sha256 text NOT NULL,
 server_recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(tenant_id,id),
 FOREIGN KEY(tenant_id,registration_id,registration_revision) REFERENCES commitment_ownership_registrations(tenant_id,id,revision),CHECK(octet_length(raw_envelope) BETWEEN 1 AND 65536)
);
CREATE INDEX ownership_review_scope ON commitment_ownership_reviews(tenant_id,workload_id,scope_sha256,period_start,period_end,server_recorded_at DESC,id);
CREATE INDEX ownership_journal_scope ON commitment_ownership_journals(tenant_id,workload_id,scope_sha256,registration_id,resource_id,sequence);
DO $$ DECLARE tab text;BEGIN
 FOREACH tab IN ARRAY ARRAY['commitment_ownership_registrations','commitment_ownership_revocations','commitment_ownership_journals','commitment_ownership_reviews'] LOOP
 EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',tab);EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',tab);
 EXECUTE format('CREATE POLICY operator_scope ON public.%I TO %I USING(true) WITH CHECK(true)',tab,current_user);
 EXECUTE format('CREATE TRIGGER immutable BEFORE UPDATE OR DELETE ON public.%I FOR EACH ROW EXECUTE FUNCTION public.deny_evidence_mutation()',tab);
 END LOOP;
 FOREACH tab IN ARRAY ARRAY['commitment_ownership_registrations','commitment_ownership_revocations','commitment_ownership_journals','commitment_ownership_reviews'] LOOP
 EXECUTE format('CREATE POLICY observer_scope ON public.%I TO finops_deployment_observer USING(tenant_id=current_setting(''app.tenant_id'',true)) WITH CHECK(tenant_id=current_setting(''app.tenant_id'',true))',tab);
 END LOOP;
END $$;
GRANT SELECT ON commitment_ownership_registrations,commitment_ownership_revocations,commitment_ownership_journals,commitment_ownership_reviews TO finops_deployment_observer;
GRANT INSERT ON commitment_ownership_journals,commitment_ownership_reviews TO finops_deployment_observer;

CREATE FUNCTION guard_commitment_ownership_registration() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE registration public.commitment_ownership_registrations%ROWTYPE;prior bigint;key_id text;BEGIN
 IF TG_TABLE_NAME='commitment_ownership_registrations' THEN key_id:=NEW.id;ELSE key_id:=NEW.registration_id;END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id||':commitment-ownership-key:'||key_id,0));
 IF TG_TABLE_NAME='commitment_ownership_registrations' THEN
 SELECT coalesce(max(revision),0) INTO prior FROM public.commitment_ownership_registrations WHERE tenant_id=NEW.tenant_id AND id=NEW.id;
 IF jsonb_typeof(NEW.document->'public_key') IS DISTINCT FROM 'string' OR jsonb_typeof(NEW.document->'valid_from') IS DISTINCT FROM 'string' OR jsonb_typeof(NEW.document->'valid_until') IS DISTINCT FROM 'string' OR (NEW.document->>'valid_from')::timestamptz>=(NEW.document->>'valid_until')::timestamptz THEN RAISE EXCEPTION 'ownership registered key/time required';END IF;
 IF NEW.revision<>prior+1 OR NOT public.commitment_portfolio_keys(NEW.document,ARRAY['id','revision','scope_sha256','purpose','issuer','subject','audience','public_key','valid_from','valid_until','revoked_at']) OR NEW.document->>'id' IS DISTINCT FROM NEW.id OR (NEW.document->>'revision')::bigint IS DISTINCT FROM NEW.revision OR coalesce(NEW.document->>'scope_sha256','')!~'^[a-f0-9]{64}$' OR coalesce(NEW.document->>'purpose','') NOT IN('DEPLOYMENT_JOURNAL','OWNERSHIP_REVIEW') OR NEW.document->>'audience' IS DISTINCT FROM 'finops-deployment-observer' OR coalesce(NEW.document->>'issuer','')='' OR coalesce(NEW.document->>'subject','')='' OR octet_length(decode(NEW.document->>'public_key','base64'))<>32 OR (NEW.document->>'valid_from')::timestamptz>clock_timestamp() OR (NEW.document->>'valid_until')::timestamptz<=clock_timestamp() OR NEW.document->'revoked_at' IS DISTINCT FROM 'null'::jsonb THEN RAISE EXCEPTION 'ownership registered signing identity differs';END IF;
 NEW.operator_created_at:=clock_timestamp();
 ELSE
 SELECT * INTO registration FROM public.commitment_ownership_registrations WHERE tenant_id=NEW.tenant_id AND id=NEW.registration_id AND revision=NEW.revision;
 IF registration.id IS NULL THEN RAISE EXCEPTION 'ownership registration missing';END IF;NEW.created_at:=clock_timestamp();
 END IF;RETURN NEW;
END $$;
CREATE TRIGGER ownership_key_install BEFORE INSERT ON commitment_ownership_registrations FOR EACH ROW EXECUTE FUNCTION guard_commitment_ownership_registration();
CREATE TRIGGER ownership_key_revoke BEFORE INSERT ON commitment_ownership_revocations FOR EACH ROW EXECUTE FUNCTION guard_commitment_ownership_registration();
REVOKE ALL ON FUNCTION guard_commitment_ownership_registration() FROM PUBLIC;

CREATE FUNCTION guard_commitment_ownership_append() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE registration public.commitment_ownership_registrations%ROWTYPE;body jsonb;raw jsonb;prior public.commitment_ownership_journals%ROWTYPE;recorded timestamptz:=clock_timestamp();BEGIN
 IF current_setting('role',true)<>'finops_deployment_observer' OR NEW.tenant_id IS DISTINCT FROM current_setting('app.tenant_id',true) OR current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION 'authenticated ownership observer required';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended(NEW.tenant_id||':commitment-ownership-key:'||NEW.registration_id,0));
 SELECT * INTO registration FROM public.commitment_ownership_registrations WHERE tenant_id=NEW.tenant_id AND id=NEW.registration_id ORDER BY revision DESC LIMIT 1;
 recorded:=clock_timestamp();
 IF registration.id IS NULL OR registration.revision<>NEW.registration_revision OR EXISTS(SELECT 1 FROM public.commitment_ownership_revocations WHERE tenant_id=NEW.tenant_id AND registration_id=NEW.registration_id AND revision=NEW.registration_revision) OR registration.document->>'issuer' IS DISTINCT FROM NEW.issuer OR registration.document->>'subject' IS DISTINCT FROM NEW.subject OR NEW.audience IS DISTINCT FROM 'finops-deployment-observer' OR registration.document->>'audience' IS DISTINCT FROM NEW.audience OR (registration.document->>'valid_until')::timestamptz<=recorded OR (registration.document->>'valid_from')::timestamptz>recorded THEN RAISE EXCEPTION 'ownership signing registration inactive';END IF;
 raw:=convert_from(NEW.raw_envelope,'UTF8')::jsonb;body:=raw->CASE WHEN TG_TABLE_NAME='commitment_ownership_journals' THEN 'journal' ELSE 'review' END;
 IF jsonb_typeof(body->'signed_at') IS DISTINCT FROM 'string' THEN RAISE EXCEPTION 'ownership signing time required';END IF;
 IF body->>'tenant_id' IS DISTINCT FROM NEW.tenant_id OR body->>'workload_id' IS DISTINCT FROM NEW.workload_id OR body->>'id' IS DISTINCT FROM NEW.id OR body->>'registration_id' IS DISTINCT FROM NEW.registration_id OR (body->>'registration_revision')::bigint IS DISTINCT FROM NEW.registration_revision OR body->>'scope_sha256' IS DISTINCT FROM registration.document->>'scope_sha256' OR (body->>'signed_at')::timestamptz>recorded OR (body->>'signed_at')::timestamptz<(body->'period'->>'end')::timestamptz THEN RAISE EXCEPTION 'ownership signed append scope differs';END IF;
 IF TG_TABLE_NAME='commitment_ownership_journals' THEN
 IF registration.document->>'purpose' IS DISTINCT FROM 'DEPLOYMENT_JOURNAL' OR body->'resource'->>'resource_id' IS DISTINCT FROM NEW.resource_id OR (body->>'sequence')::bigint IS DISTINCT FROM NEW.sequence OR (body->'period'->>'end')::timestamptz-(body->'period'->>'start')::timestamptz NOT BETWEEN interval '1 microsecond' AND interval '1 hour' OR (body->'period'->>'end')::timestamptz>recorded OR recorded-(body->'period'->>'end')::timestamptz>interval '5 minutes' OR (body->'period'->>'start')::timestamptz<registration.operator_created_at THEN RAISE EXCEPTION 'ownership historical body cannot be backfilled';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id||':commitment-ownership-chain:'||NEW.registration_id||':'||NEW.resource_id,0));
 SELECT * INTO prior FROM public.commitment_ownership_journals WHERE tenant_id=NEW.tenant_id AND registration_id=NEW.registration_id AND registration_revision=NEW.registration_revision AND resource_id=NEW.resource_id ORDER BY sequence DESC LIMIT 1;
 IF prior.id IS NULL THEN IF NEW.sequence<>1 OR body->>'previous_sha256' IS DISTINCT FROM '' THEN RAISE EXCEPTION 'ownership journal genesis differs';END IF;
 ELSE IF NEW.sequence<>prior.sequence+1 OR body->>'previous_sha256' IS DISTINCT FROM prior.envelope_sha256 OR body->'period'->>'start' IS DISTINCT FROM (convert_from(prior.raw_envelope,'UTF8')::jsonb)->'journal'->'period'->>'end' THEN RAISE EXCEPTION 'ownership journal chain differs';END IF;END IF;
 ELSE IF registration.document->>'purpose' IS DISTINCT FROM 'OWNERSHIP_REVIEW' THEN RAISE EXCEPTION 'independent ownership reviewer required';END IF;END IF;
 recorded:=clock_timestamp();
 IF (registration.document->>'valid_until')::timestamptz<=recorded OR TG_TABLE_NAME='commitment_ownership_journals' AND recorded-(body->'period'->>'end')::timestamptz>interval '5 minutes' THEN RAISE EXCEPTION 'ownership append deadline elapsed';END IF;
 NEW.scope_sha256:=body->>'scope_sha256';NEW.period_start:=(body->'period'->>'start')::timestamptz;NEW.period_end:=(body->'period'->>'end')::timestamptz;
 IF NEW.scope_sha256 IS NULL OR NEW.period_start IS NULL OR NEW.period_end IS NULL OR NEW.period_start>=NEW.period_end THEN RAISE EXCEPTION 'ownership append period required';END IF;
 NEW.envelope_sha256:=encode(sha256(NEW.raw_envelope),'hex');NEW.server_recorded_at:=recorded;RETURN NEW;
END $$;
CREATE TRIGGER ownership_journal_append BEFORE INSERT ON commitment_ownership_journals FOR EACH ROW EXECUTE FUNCTION guard_commitment_ownership_append();
CREATE TRIGGER ownership_review_append BEFORE INSERT ON commitment_ownership_reviews FOR EACH ROW EXECUTE FUNCTION guard_commitment_ownership_append();
REVOKE ALL ON FUNCTION guard_commitment_ownership_append() FROM PUBLIC;

CREATE TABLE commitment_ownership_evidence(
 tenant_id text NOT NULL,id text NOT NULL,request_id text NOT NULL,workload_id text NOT NULL,scope_sha256 text NOT NULL,
 document jsonb NOT NULL,content_hash text NOT NULL,writer_role name NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,id),CHECK(octet_length(document::text)<=1048576)
);
ALTER TABLE commitment_ownership_evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE commitment_ownership_evidence FORCE ROW LEVEL SECURITY;
CREATE POLICY analytical_scope ON commitment_ownership_evidence USING(public.commitment_portfolio_access(tenant_id)) WITH CHECK(public.commitment_portfolio_access(tenant_id));
DO $$ BEGIN EXECUTE format('CREATE POLICY operator_scope ON commitment_ownership_evidence TO %I USING(true) WITH CHECK(true)',current_user);END $$;
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE ON commitment_ownership_evidence FOR EACH ROW EXECUTE FUNCTION public.deny_evidence_mutation();
GRANT SELECT ON commitment_ownership_evidence TO finops_commitment_portfolio,finops_api;

CREATE TABLE commitment_decision_results(
 tenant_id text NOT NULL,request_id text NOT NULL,purpose text NOT NULL CHECK(purpose IN('PREPARE','DECISION')),
 status text NOT NULL CHECK(status IN('ASSESSED','REFUSED')),document jsonb NOT NULL,
 content_hash text NOT NULL CHECK(content_hash~'^[a-f0-9]{64}$'),
 writer_role name NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,request_id),CHECK(octet_length(document::text)<=2097152)
);
ALTER TABLE commitment_decision_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE commitment_decision_results FORCE ROW LEVEL SECURITY;
CREATE POLICY credential_scope ON commitment_decision_results USING(public.commitment_portfolio_access(tenant_id)) WITH CHECK(public.commitment_portfolio_access(tenant_id));
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE ON commitment_decision_results FOR EACH ROW EXECUTE FUNCTION public.deny_evidence_mutation();
GRANT SELECT ON commitment_decision_results TO finops_api,finops_commitment_portfolio;
GRANT INSERT ON commitment_decision_results TO finops_commitment_portfolio;

-- No new generic entities privilege is granted to the analytical login.
-- These private functions select bounded typed rows under the existing fences.
CREATE FUNCTION commitment_decision_base(p_tenant text,p_workload text,p_selection jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE request public.commitment_portfolio_requests%ROWTYPE;analysis public.commitment_portfolio_results%ROWTYPE;
 offer public.source_receipts%ROWTYPE;revision public.source_revisions%ROWTYPE;workload jsonb;resources jsonb;inputs jsonb;checkpoint jsonb;
 assessment jsonb;forecast jsonb;refs jsonb;byte_count bigint;ownership jsonb;BEGIN
 IF NOT public.commitment_portfolio_access(p_tenant) THEN RAISE EXCEPTION 'decision credential scope differs';END IF;
 IF NOT public.commitment_portfolio_keys(p_selection,ARRAY['portfolio_analysis_request_id','offer_receipt_id']) AND NOT public.commitment_portfolio_keys(p_selection,ARRAY['portfolio_analysis_request_id','offer_receipt_id','post_optimization_assessment_id','forecast_id']) THEN RAISE EXCEPTION 'decision IDs-only selection differs';END IF;
 IF EXISTS(SELECT 1 FROM jsonb_each(p_selection) e WHERE jsonb_typeof(e.value)<>'string' OR e.value#>>'{}'!~'^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$') OR p_workload!~'^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$' THEN RAISE EXCEPTION 'decision IDs-only selection differs';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(p_tenant||':dependency-graph',0));
 SELECT * INTO request FROM public.commitment_portfolio_requests WHERE tenant_id=p_tenant AND id=p_selection->>'portfolio_analysis_request_id';
 SELECT * INTO analysis FROM public.commitment_portfolio_results WHERE tenant_id=p_tenant AND request_id=request.id AND status='ASSESSED';
 IF request.id IS NULL OR analysis.request_id IS NULL THEN RAISE EXCEPTION 'decision issued portfolio required';END IF;
 inputs:=public.commitment_portfolio_resolve(p_tenant,request.selection);
 IF public.fleet_history_json_hash(inputs) IS DISTINCT FROM request.input_hash OR analysis.document->>'request_id' IS DISTINCT FROM request.id OR analysis.content_hash IS DISTINCT FROM public.fleet_history_json_hash(analysis.document) THEN RAISE EXCEPTION 'decision portfolio changed';END IF;
 SELECT document||jsonb_build_object('id',id,'version',version) INTO workload FROM public.entities WHERE tenant_id=p_tenant AND kind='workloads' AND id=p_workload;
 IF workload IS NULL THEN RAISE EXCEPTION 'decision workload missing';END IF;
 SELECT coalesce(sum(octet_length(document::text)),0) INTO byte_count FROM public.entities WHERE tenant_id=p_tenant AND kind='resources' AND document->>'workload_id'=p_workload;
 IF byte_count>2097152 OR (SELECT count(*) FROM public.entities WHERE tenant_id=p_tenant AND kind='resources' AND document->>'workload_id'=p_workload)>2000 THEN RAISE EXCEPTION 'decision input byte limit';END IF;
 SELECT coalesce(jsonb_agg(document||jsonb_build_object('id',id,'version',version) ORDER BY id),'[]') INTO resources FROM public.entities WHERE tenant_id=p_tenant AND kind='resources' AND document->>'workload_id'=p_workload;
 SELECT * INTO offer FROM public.source_receipts WHERE tenant_id=p_tenant AND id=p_selection->>'offer_receipt_id' AND source_id=request.selection->>'source_id' AND kind='AWS_SAVINGS_PLAN_OFFER' AND writer_role='finops_ingester';
 SELECT * INTO revision FROM public.source_revisions WHERE tenant_id=p_tenant AND id=offer.revision_id AND source_id=offer.source_id AND writer_role='finops_ingester';
 SELECT document INTO checkpoint FROM public.source_checkpoints WHERE tenant_id=p_tenant AND source_id=offer.source_id AND checkpoint_key='savings-plan-quotes';
 IF offer.id IS NULL OR revision.id IS NULL OR offer.document->>'config_hash' IS DISTINCT FROM inputs->'checkpoint'->>'config_hash' OR checkpoint->>'revision_id' IS DISTINCT FROM revision.id OR offer.document->>'native_offering_id' IS NULL OR offer.document->>'projection' IS DISTINCT FROM 'AWS_SAVINGS_PLAN_RATE_QUOTES_V1' OR (offer.document->>'collected_at')::timestamptz<clock_timestamp()-interval '5 minutes' OR (offer.document->>'collected_at')::timestamptz>clock_timestamp()+interval '5 seconds' THEN RAISE EXCEPTION 'decision native offer not current';END IF;
 IF octet_length(revision.document::text)>16777216 OR octet_length(offer.document::text)>65536 THEN RAISE EXCEPTION 'decision input byte limit';END IF;
 refs:=request.input_refs||jsonb_build_array(jsonb_build_object('kind','COMMITMENT_PORTFOLIO_ANALYSIS','id',request.id,'sha256',analysis.content_hash),jsonb_build_object('kind','AWS_SAVINGS_PLAN_OFFER','id',offer.id,'sha256',public.fleet_history_json_hash(offer.document||jsonb_build_object('writer_role',offer.writer_role))),jsonb_build_object('kind','AWS_SAVINGS_PLAN_RATES','id',revision.id,'sha256',public.fleet_history_json_hash(revision.document||jsonb_build_object('writer_role',revision.writer_role))));
 IF p_selection ? 'post_optimization_assessment_id' THEN
 SELECT document INTO assessment FROM public.entities WHERE tenant_id=p_tenant AND kind='commitment_decision_evidence' AND id=p_selection->>'post_optimization_assessment_id' AND document->>'kind'='OPTIMIZATION_ASSESSMENT';
 SELECT document INTO forecast FROM public.entities WHERE tenant_id=p_tenant AND kind='commitment_decision_evidence' AND id=p_selection->>'forecast_id' AND document->>'kind'='POST_OPTIMIZATION_FORECAST';
 IF assessment IS NULL OR forecast IS NULL OR assessment->>'workload_id' IS DISTINCT FROM p_workload OR forecast->>'workload_id' IS DISTINCT FROM p_workload OR assessment->'selection' IS DISTINCT FROM p_selection-ARRAY['post_optimization_assessment_id','forecast_id'] OR forecast->'selection' IS DISTINCT FROM assessment->'selection' OR forecast->>'request_id' IS DISTINCT FROM assessment->>'request_id' OR forecast->>'base_sha256' IS DISTINCT FROM assessment->>'base_sha256' THEN RAISE EXCEPTION 'decision preparation scope differs';END IF;
 IF assessment->'payload'->>'status' IS DISTINCT FROM 'ASSESSED' OR forecast->'payload'->>'status' IS DISTINCT FROM 'CALIBRATED' OR assessment->'payload'->'scope'->'ownership_ref'->>'kind' IS DISTINCT FROM 'HISTORICAL_OWNERSHIP' THEN RAISE EXCEPTION 'decision issued inputs unavailable';END IF;
 SELECT e.document INTO ownership FROM public.commitment_ownership_evidence e WHERE e.tenant_id=p_tenant AND e.id=assessment->'payload'->'scope'->'ownership_ref'->>'id' AND e.content_hash=assessment->'payload'->'scope'->'ownership_ref'->>'sha256';
 IF ownership IS NULL THEN RAISE EXCEPTION 'decision ownership evidence missing';END IF;
 PERFORM public.commitment_ownership_validate(p_tenant,p_workload,ownership);
 IF assessment->>'base_sha256' IS DISTINCT FROM public.fleet_history_json_hash(public.commitment_decision_base(p_tenant,p_workload,p_selection-ARRAY['post_optimization_assessment_id','forecast_id'])) THEN RAISE EXCEPTION 'decision preparation scope differs';END IF;
 refs:=refs||jsonb_build_array(jsonb_build_object('kind','OPTIMIZATION_ASSESSMENT','id',assessment->>'id','sha256',assessment->>'payload_sha256'),jsonb_build_object('kind','POST_OPTIMIZATION_FORECAST','id',forecast->>'id','sha256',forecast->>'payload_sha256'));
 IF forecast->'calibration_ref'<>'null'::jsonb THEN refs:=refs||jsonb_build_array(forecast->'calibration_ref');END IF;
 refs:=refs||(assessment->'payload'->'input_refs')||(forecast->'payload'->'input_refs');
 END IF;
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(refs) v GROUP BY v->>'kind',v->>'id' HAVING count(DISTINCT v->>'sha256')>1) THEN RAISE EXCEPTION 'decision conflicting immutable proof';END IF;
 SELECT coalesce(jsonb_agg(v ORDER BY v->>'kind',v->>'id'),'[]') INTO refs FROM(SELECT DISTINCT v FROM jsonb_array_elements(refs) v) proofs;
 RETURN jsonb_build_object('tenant_id',p_tenant,'workload_id',p_workload,'selection',p_selection,'workload',workload,'resources',resources,'portfolio',analysis.document,'portfolio_inputs',inputs,'offer_receipt',offer.document||jsonb_build_object('writer_role',offer.writer_role),'offer_revision',revision.document||jsonb_build_object('writer_role',revision.writer_role),'assessment',assessment,'forecast',forecast,'input_refs',refs,'ownership_scope',public.commitment_ownership_scope(p_tenant,p_workload));
END $$;
REVOKE ALL ON FUNCTION commitment_decision_base(text,text,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION commitment_decision_base(text,text,jsonb) TO finops_api,finops_commitment_portfolio;

CREATE FUNCTION guard_commitment_decision_entity() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE base jsonb;BEGIN
 IF (TG_OP<>'INSERT' AND (OLD.kind='commitment_decision_evidence' OR OLD.kind='recommendations' AND OLD.document->>'category'='COMMITMENT_PORTFOLIO_DECISION' OR OLD.kind='approvals' AND OLD.document ? 'commitment_decision_id' OR NEW.kind='commitment_decision_evidence' OR NEW.kind='recommendations' AND NEW.document->>'category'='COMMITMENT_PORTFOLIO_DECISION' OR NEW.kind='approvals' AND NEW.document ? 'commitment_decision_id')) THEN RAISE EXCEPTION 'decision evidence is append only';END IF;
 IF TG_OP='DELETE' THEN RETURN OLD;END IF;
 IF TG_OP<>'INSERT' THEN RETURN NEW;END IF;
 IF NEW.kind='commitment_decision_evidence' THEN
 -- The login has no entities INSERT privilege. The narrowly granted publisher
 -- checks its SESSION_USER-bound credential before inserting as table owner.
 IF current_setting('role',true)<>'finops_commitment_portfolio' OR NOT public.commitment_portfolio_scope(NEW.tenant_id) THEN RAISE EXCEPTION 'decision private evidence publisher required';END IF;
 RETURN NEW;
 END IF;
 IF NEW.kind='recommendations' AND NEW.document->>'category'='COMMITMENT_PORTFOLIO_DECISION' THEN
 IF current_setting('role',true)<>'finops_api' OR NOT public.commitment_portfolio_access(NEW.tenant_id) OR NEW.version<>1 OR NOT public.commitment_portfolio_keys(NEW.document,ARRAY['id','version','tenant_id','category','purpose','creator_id','workload_id','selection','status','input_refs','input_sha256','created_at','execution_authorized','verified_saving']) OR NEW.document->>'id' IS DISTINCT FROM NEW.id OR NEW.document->>'tenant_id' IS DISTINCT FROM NEW.tenant_id OR NEW.document->>'status' IS DISTINCT FROM 'QUEUED' OR coalesce(NEW.document->>'purpose','') NOT IN('PREPARE','DECISION') OR coalesce(NEW.document->>'creator_id','')='' OR NEW.document->'execution_authorized' IS DISTINCT FROM 'false'::jsonb OR NEW.document->'verified_saving' IS DISTINCT FROM 'null'::jsonb THEN RAISE EXCEPTION 'decision API request differs';END IF;
 IF (NEW.document->>'purpose'='PREPARE') IS DISTINCT FROM (NOT(NEW.document->'selection' ? 'forecast_id')) THEN RAISE EXCEPTION 'decision request purpose differs';END IF;
 base:=public.commitment_decision_base(NEW.tenant_id,NEW.document->>'workload_id',NEW.document->'selection');
 NEW.document:=NEW.document||jsonb_build_object('input_sha256',public.fleet_history_json_hash(base),'input_refs',base->'input_refs','created_at',clock_timestamp());
 ELSIF NEW.kind='approvals' AND NEW.document ? 'commitment_decision_id' THEN
 IF current_setting('role',true)<>'finops_api' OR NOT public.commitment_portfolio_access(NEW.tenant_id) OR NOT public.commitment_portfolio_keys(NEW.document,ARRAY['id','version','tenant_id','commitment_decision_id','review']) OR NEW.document->'review'->>'approval_scope' IS DISTINCT FROM 'COMMITMENT_RECOMMENDATION_REVIEW_NO_PURCHASE' OR NEW.document->'review'->'purchase_authorized' IS DISTINCT FROM 'false'::jsonb OR NEW.document->'review'->'execution_authorized' IS DISTINCT FROM 'false'::jsonb OR NOT public.commitment_decision_current(NEW.tenant_id,NEW.document->>'commitment_decision_id') THEN RAISE EXCEPTION 'decision exact Finance review required';END IF;
 IF NOT EXISTS(SELECT 1 FROM public.commitment_decision_results x JOIN public.entities r ON r.tenant_id=x.tenant_id AND r.kind='recommendations' AND r.id=x.request_id WHERE x.tenant_id=NEW.tenant_id AND x.request_id=NEW.document->>'commitment_decision_id' AND x.purpose='DECISION' AND x.status='ASSESSED' AND x.document->>'status'='RECOMMEND_PURCHASE_PENDING_FINANCE' AND x.content_hash=NEW.document->'review'->>'decision_sha256' AND r.document->>'input_sha256'=NEW.document->'review'->>'input_sha256' AND r.document->>'creator_id'<>NEW.document->'review'->>'actor_id' AND NEW.document->'review'->>'decision_id'=x.document->>'id' AND NEW.document->'review'->>'id'=NEW.id) THEN RAISE EXCEPTION 'decision review payload differs';END IF;
 END IF;RETURN NEW;
END $$;
CREATE TRIGGER commitment_decision_entity BEFORE INSERT OR UPDATE OR DELETE ON entities FOR EACH ROW EXECUTE FUNCTION guard_commitment_decision_entity();
REVOKE ALL ON FUNCTION guard_commitment_decision_entity() FROM PUBLIC;

CREATE FUNCTION commitment_decision_request(p_tenant text,p_id text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE value jsonb;BEGIN
 IF NOT public.commitment_portfolio_access(p_tenant) THEN RAISE EXCEPTION 'decision credential scope differs';END IF;
 SELECT document INTO value FROM public.entities WHERE tenant_id=p_tenant AND kind='recommendations' AND id=p_id AND document->>'category'='COMMITMENT_PORTFOLIO_DECISION';
 IF value IS NULL THEN RAISE EXCEPTION 'decision request missing';END IF;RETURN value;
END $$;
CREATE FUNCTION commitment_decision_pending(p_tenant text,p_limit integer) RETURNS TABLE(id text,purpose text) LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
BEGIN
 IF NOT public.commitment_portfolio_scope(p_tenant) OR p_limit NOT BETWEEN 1 AND 16 THEN RAISE EXCEPTION 'decision credential scope differs';END IF;
 RETURN QUERY SELECT e.id,e.document->>'purpose' FROM public.entities e WHERE e.tenant_id=p_tenant AND e.kind='recommendations' AND e.document->>'category'='COMMITMENT_PORTFOLIO_DECISION' AND NOT EXISTS(SELECT 1 FROM public.commitment_decision_results x WHERE x.tenant_id=e.tenant_id AND x.request_id=e.id) ORDER BY e.id LIMIT p_limit;
END $$;
REVOKE ALL ON FUNCTION commitment_decision_request(text,text),commitment_decision_pending(text,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION commitment_decision_request(text,text) TO finops_api,finops_commitment_portfolio;
GRANT EXECUTE ON FUNCTION commitment_decision_pending(text,integer) TO finops_commitment_portfolio;

CREATE FUNCTION commitment_decision_current(p_tenant text,p_id text) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE request jsonb;base jsonb;BEGIN
 IF NOT public.commitment_portfolio_access(p_tenant) THEN RAISE EXCEPTION 'decision credential scope differs';END IF;
 request:=public.commitment_decision_request(p_tenant,p_id);
 BEGIN
 base:=public.commitment_decision_base(p_tenant,request->>'workload_id',request->'selection');
 RETURN public.fleet_history_json_hash(base)=request->>'input_sha256';
 EXCEPTION WHEN raise_exception THEN RETURN false;END;
END $$;
REVOKE ALL ON FUNCTION commitment_decision_current(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION commitment_decision_current(text,text) TO finops_api,finops_commitment_portfolio;
CREATE UNIQUE INDEX commitment_decision_one_finance_review ON entities(tenant_id,(document->>'commitment_decision_id')) WHERE kind='approvals' AND document ? 'commitment_decision_id';

CREATE FUNCTION guard_commitment_decision_result() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE request jsonb;base jsonb;value jsonb;BEGIN
 IF current_user<>'finops_commitment_portfolio' OR NOT public.commitment_portfolio_scope(NEW.tenant_id) THEN RAISE EXCEPTION 'decision analytical writer required';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id||':dependency-graph',0));
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('commitment-portfolio-credential:'||session_user::text,0));
 IF NOT public.commitment_portfolio_scope(NEW.tenant_id) THEN RAISE EXCEPTION 'decision credential scope differs';END IF;
 request:=public.commitment_decision_request(NEW.tenant_id,NEW.request_id);
 IF request->>'purpose' IS DISTINCT FROM NEW.purpose OR NEW.document->>'observed_at' IS NULL OR (NEW.document->>'observed_at')::timestamptz<(request->>'created_at')::timestamptz OR (NEW.document->>'observed_at')::timestamptz>clock_timestamp()+interval '5 seconds' THEN RAISE EXCEPTION 'decision terminal binding differs';END IF;
 IF NEW.status='REFUSED' THEN
 IF NOT public.commitment_portfolio_keys(NEW.document,ARRAY['reason_code','observed_at']) OR coalesce(NEW.document->>'reason_code','') NOT IN('ISSUED_INPUTS_CHANGED','ISSUED_INPUT_FORMAT_UNSUPPORTED','DECISION_MODEL_EVIDENCE_UNSUPPORTED') THEN RAISE EXCEPTION 'decision refusal differs';END IF;
 ELSE
 base:=public.commitment_decision_base(NEW.tenant_id,request->>'workload_id',request->'selection');
 IF public.fleet_history_json_hash(base) IS DISTINCT FROM request->>'input_sha256' OR NEW.document->>'request_id' IS DISTINCT FROM NEW.request_id OR NEW.document->'execution_authorized' IS DISTINCT FROM 'false'::jsonb OR NEW.document->'verified_saving' IS DISTINCT FROM 'null'::jsonb THEN RAISE EXCEPTION 'decision issued inputs changed';END IF;
 IF NEW.purpose='DECISION' THEN
 IF NOT public.commitment_portfolio_keys(NEW.document,ARRAY['schema_version','id','request_id','selection','scope','input_refs','status','observed_coverage','observed_effective_discount','observed_unused_exposure','computation_policy','proposed_hourly_commitment','proposed_term_obligation','expected_utilization','break_even_utilization','expected_savings','downside_exposure','cash_requirement','remaining_contractual_obligation','paid_unamortized_value','forward_price_assumption','price_change_stress','confidence','optimization_order','reason_codes','observed_at','finance_approval_required','purchase_authorized','execution_authorized','verified_saving']) OR NEW.document->>'schema_version' IS DISTINCT FROM '2' OR NEW.document->>'id' IS DISTINCT FROM public.fleet_history_json_hash(NEW.document||'{"id":""}') OR NEW.document->'input_refs' IS DISTINCT FROM base->'input_refs' OR NOT public.commitment_portfolio_strings(NEW.document->'reason_codes',128) THEN RAISE EXCEPTION 'decision result shape differs';END IF;
 IF NOT public.commitment_portfolio_keys(NEW.document->'scope',ARRAY['tenant_id','workload_id','payer_account_id','usage_account_ids','resource_ids','class','currency','configuration_sha256','ownership_ref','history_period','projection_period','sha256']) OR NEW.document->'scope'->>'tenant_id' IS DISTINCT FROM NEW.tenant_id OR NEW.document->'scope'->>'workload_id' IS DISTINCT FROM request->>'workload_id' OR NEW.document->'scope'->>'sha256' IS DISTINCT FROM public.fleet_history_json_hash((NEW.document->'scope')||'{"sha256":""}') OR NOT public.commitment_portfolio_keys(NEW.document->'confidence',ARRAY['status','lower_expected_savings','upper_expected_savings','coverage','method','calibration_ref','reason_codes']) OR NOT public.commitment_portfolio_strings(NEW.document->'confidence'->'reason_codes',128) OR NOT public.commitment_portfolio_keys(NEW.document->'price_change_stress',ARRAY['status','assumption','break_even_payg_rate_drop_fraction','zero_usage_loss','reason_codes']) OR NOT public.commitment_portfolio_strings(NEW.document->'price_change_stress'->'reason_codes',128) OR NEW.document->'price_change_stress'->'zero_usage_loss' IS DISTINCT FROM NEW.document->'downside_exposure' THEN RAISE EXCEPTION 'decision nested authority shape differs';END IF;
 FOR value IN SELECT jsonb_array_elements(NEW.document->'input_refs') LOOP IF NOT public.commitment_portfolio_keys(value,ARRAY['kind','id','sha256']) OR coalesce(value->>'sha256','')!~'^[a-f0-9]{64}$' THEN RAISE EXCEPTION 'decision reference shape differs';END IF;END LOOP;
 FOREACH value IN ARRAY ARRAY[NEW.document->'observed_coverage',NEW.document->'observed_effective_discount',NEW.document->'observed_unused_exposure',NEW.document->'proposed_hourly_commitment',NEW.document->'proposed_term_obligation',NEW.document->'expected_utilization',NEW.document->'break_even_utilization',NEW.document->'expected_savings',NEW.document->'downside_exposure',NEW.document->'cash_requirement',NEW.document->'remaining_contractual_obligation',NEW.document->'paid_unamortized_value'] LOOP
 IF NOT public.commitment_portfolio_keys(value,ARRAY['status','value','unit','currency','basis','period','reason_codes','input_refs']) OR NOT public.commitment_portfolio_strings(value->'reason_codes',128) OR value->'input_refs' IS DISTINCT FROM base->'input_refs' OR coalesce(value->>'status','') NOT IN('AVAILABLE','UNAVAILABLE') OR (value->>'status'='AVAILABLE') IS DISTINCT FROM (value->'value'<>'null'::jsonb) OR value->'value'<>'null'::jsonb AND (jsonb_typeof(value->'value')<>'string' OR value->>'value'!~'^-?(0|[1-9][0-9]{0,25})([.][0-9]{1,12})?$') THEN RAISE EXCEPTION 'decision metric shape differs';END IF;
 END LOOP;
 IF jsonb_typeof(NEW.document->'optimization_order') IS DISTINCT FROM 'array' OR jsonb_array_length(NEW.document->'optimization_order')<>5 THEN RAISE EXCEPTION 'decision stage population differs';END IF;
 FOR value IN SELECT jsonb_array_elements(NEW.document->'optimization_order') LOOP IF NOT public.commitment_portfolio_keys(value,ARRAY['stage','disposition','decision_ref','outcome_ref','scope_sha256','completed_at','reason_codes']) OR NOT public.commitment_portfolio_strings(value->'reason_codes',128) THEN RAISE EXCEPTION 'decision stage shape differs';END IF;END LOOP;
 IF coalesce(NEW.document->>'status','') NOT IN('BLOCKED','DO_NOT_PURCHASE','RECOMMEND_PURCHASE_PENDING_FINANCE') OR NEW.document->'selection' IS DISTINCT FROM request->'selection' OR NEW.document->'purchase_authorized' IS DISTINCT FROM 'false'::jsonb OR NEW.document->'finance_approval_required' IS DISTINCT FROM 'true'::jsonb OR NEW.document->>'computation_policy' IS DISTINCT FROM 'DECIMAL80_INTERMEDIATE_HALF_EVEN_12_FINAL' OR NEW.document->>'forward_price_assumption' IS DISTINCT FROM 'HELD_CURRENT_NATIVE_NET_RATE' THEN RAISE EXCEPTION 'decision cannot grant purchase authority';END IF;
 ELSE
 IF NOT public.commitment_portfolio_keys(NEW.document,ARRAY['request_id','post_optimization_assessment_id','forecast_id','input_refs','reason_codes','observed_at','execution_authorized','verified_saving']) OR NOT public.commitment_portfolio_strings(NEW.document->'reason_codes',128) THEN RAISE EXCEPTION 'decision preparation shape differs';END IF;
 END IF;END IF;
 NEW.content_hash:=public.fleet_history_json_hash(NEW.document);NEW.writer_role:=current_user;NEW.created_at:=clock_timestamp();RETURN NEW;
END $$;
CREATE TRIGGER commitment_decision_result BEFORE INSERT ON commitment_decision_results FOR EACH ROW EXECUTE FUNCTION guard_commitment_decision_result();
REVOKE ALL ON FUNCTION guard_commitment_decision_result() FROM PUBLIC;

CREATE FUNCTION commitment_decision_publish_preparation(p_tenant text,p_request text,p_assessment jsonb,p_forecast jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE request jsonb;base jsonb;evidence_kind text;payload jsonb;identity text;envelope jsonb;calibration jsonb;calibration_ref jsonb:=NULL;answer jsonb;ownership public.commitment_ownership_evidence%ROWTYPE;expected_refs jsonb;BEGIN
 IF current_setting('role',true)<>'finops_commitment_portfolio' OR NOT public.commitment_portfolio_scope(p_tenant) THEN RAISE EXCEPTION 'decision analytical publisher required';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(p_tenant||':dependency-graph',0));
 request:=public.commitment_decision_request(p_tenant,p_request);
 IF request->>'purpose' IS DISTINCT FROM 'PREPARE' THEN RAISE EXCEPTION 'decision preparation request required';END IF;
 base:=public.commitment_decision_base(p_tenant,request->>'workload_id',request->'selection');
 IF public.fleet_history_json_hash(base) IS DISTINCT FROM request->>'input_sha256' OR octet_length(p_assessment::text)>1048576 OR octet_length(p_forecast::text)>8388608 THEN RAISE EXCEPTION 'decision issued inputs changed';END IF;
 IF NOT public.commitment_portfolio_keys(p_assessment,ARRAY['schema_version','id','request_id','scope','status','optimization_order','input_refs','reason_codes','observed_at','execution_authorized','verified_saving']) OR p_assessment->>'schema_version' IS DISTINCT FROM '2' OR p_assessment->>'request_id' IS DISTINCT FROM p_request OR p_assessment->>'id' IS DISTINCT FROM public.fleet_history_json_hash(p_assessment||'{"id":""}') OR p_assessment->'scope'->>'workload_id' IS DISTINCT FROM request->>'workload_id' OR p_assessment->'scope'->>'tenant_id' IS DISTINCT FROM p_tenant OR p_assessment->'scope'->>'payer_account_id' IS DISTINCT FROM base->'portfolio_inputs'->'registration'->>'payer_account_id' OR p_assessment->'scope'->'history_period' IS DISTINCT FROM base->'portfolio'->'selection'->'period' OR p_assessment->'execution_authorized' IS DISTINCT FROM 'false'::jsonb OR p_assessment->'verified_saving' IS DISTINCT FROM 'null'::jsonb OR NOT public.commitment_portfolio_strings(p_assessment->'reason_codes',128) OR coalesce(p_assessment->>'status','') NOT IN('BLOCKED','ASSESSED') THEN RAISE EXCEPTION 'decision assessment differs';END IF;
 expected_refs:=base->'input_refs';
 IF p_assessment->'scope'->'ownership_ref'->>'kind'='HISTORICAL_OWNERSHIP' THEN
 SELECT * INTO ownership FROM public.commitment_ownership_evidence e WHERE e.tenant_id=p_tenant AND e.id=p_assessment->'scope'->'ownership_ref'->>'id' AND e.content_hash=p_assessment->'scope'->'ownership_ref'->>'sha256';
 IF ownership.id IS NULL OR ownership.workload_id IS DISTINCT FROM request->>'workload_id' OR (ownership.document->'period'->>'start')::timestamptz>(p_assessment->'scope'->'history_period'->>'start')::timestamptz OR (ownership.document->'period'->>'end')::timestamptz<(p_assessment->'scope'->'history_period'->>'end')::timestamptz OR ownership.document->'scope'->>'configuration_sha256' IS DISTINCT FROM p_assessment->'scope'->>'configuration_sha256' THEN RAISE EXCEPTION 'decision ownership evidence missing';END IF;
 PERFORM public.commitment_ownership_validate(p_tenant,request->>'workload_id',ownership.document);
 expected_refs:=expected_refs||(ownership.document->'input_refs')||jsonb_build_array(p_assessment->'scope'->'ownership_ref');
 END IF;
 SELECT jsonb_agg(v ORDER BY v->>'kind',v->>'id') INTO expected_refs FROM(SELECT DISTINCT v FROM jsonb_array_elements(expected_refs) v) proofs;
 IF p_assessment->'input_refs' IS DISTINCT FROM expected_refs OR p_forecast->'input_refs' IS DISTINCT FROM expected_refs THEN RAISE EXCEPTION 'decision assessment proof closure differs';END IF;
 IF NOT public.commitment_portfolio_keys(p_forecast,ARRAY['schema_version','id','request_id','scope_sha256','recalculated_at','status','hours','calibration','reason_codes','input_refs']) OR p_forecast->>'schema_version' IS DISTINCT FROM '2' OR p_forecast->>'request_id' IS DISTINCT FROM p_request OR p_forecast->>'id' IS DISTINCT FROM public.fleet_history_json_hash(p_forecast||'{"id":""}') OR p_forecast->>'scope_sha256' IS DISTINCT FROM p_assessment->'scope'->>'sha256' OR NOT public.commitment_portfolio_strings(p_forecast->'reason_codes',128) OR coalesce(p_forecast->>'status','') NOT IN('CALIBRATED','UNAVAILABLE') OR jsonb_typeof(p_forecast->'hours') IS DISTINCT FROM 'array' OR jsonb_array_length(p_forecast->'hours')>100000 THEN RAISE EXCEPTION 'decision forecast differs';END IF;
 IF p_forecast->>'status'='UNAVAILABLE' THEN
 IF p_forecast->'calibration' IS DISTINCT FROM 'null'::jsonb OR p_forecast->'hours' IS DISTINCT FROM '[]'::jsonb OR jsonb_array_length(p_forecast->'reason_codes')=0 THEN RAISE EXCEPTION 'decision forecast gap differs';END IF;
 ELSE
 IF p_assessment->>'status' IS DISTINCT FROM 'ASSESSED' OR p_forecast->'calibration'='null'::jsonb OR jsonb_array_length(p_forecast->'hours')=0 THEN RAISE EXCEPTION 'decision forecast calibration differs';END IF;
 calibration:=p_forecast->'calibration';
 calibration_ref:=jsonb_build_object('kind','FORECAST_CALIBRATION','id',public.fleet_history_json_hash(calibration),'sha256',public.fleet_history_json_hash(calibration));
 END IF;
 FOREACH evidence_kind IN ARRAY ARRAY['OPTIMIZATION_ASSESSMENT','POST_OPTIMIZATION_FORECAST','FORECAST_CALIBRATION'] LOOP
 payload:=CASE evidence_kind WHEN 'OPTIMIZATION_ASSESSMENT' THEN p_assessment WHEN 'POST_OPTIMIZATION_FORECAST' THEN p_forecast ELSE calibration END;
 IF payload IS NULL THEN CONTINUE;END IF;
 identity:=CASE WHEN evidence_kind='FORECAST_CALIBRATION' THEN public.fleet_history_json_hash(payload) ELSE payload->>'id' END;
 envelope:=jsonb_build_object('id',identity,'kind',evidence_kind,'request_id',p_request,'workload_id',request->>'workload_id','selection',request->'selection','base_sha256',request->>'input_sha256','scope_sha256',p_assessment->'scope'->>'sha256','payload',payload,'payload_sha256',public.fleet_history_json_hash(payload),'calibration_ref',CASE WHEN evidence_kind='POST_OPTIMIZATION_FORECAST' THEN calibration_ref ELSE NULL END,'writer_role','finops_commitment_portfolio');
 INSERT INTO public.entities(tenant_id,kind,id,document) VALUES(p_tenant,'commitment_decision_evidence',identity,envelope) ON CONFLICT(tenant_id,kind,id) DO NOTHING;
 IF NOT EXISTS(SELECT 1 FROM public.entities e WHERE e.tenant_id=p_tenant AND e.kind='commitment_decision_evidence' AND e.id=identity AND e.document=envelope) THEN RAISE EXCEPTION 'decision immutable evidence conflict';END IF;
 END LOOP;
 answer:=jsonb_build_object('request_id',p_request,'post_optimization_assessment_id',p_assessment->>'id','forecast_id',p_forecast->>'id','input_refs',p_assessment->'input_refs','reason_codes',p_assessment->'reason_codes','observed_at',p_assessment->'observed_at','execution_authorized',false,'verified_saving',NULL);
 RETURN answer;
END $$;
REVOKE ALL ON FUNCTION commitment_decision_publish_preparation(text,text,jsonb,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION commitment_decision_publish_preparation(text,text,jsonb,jsonb) TO finops_commitment_portfolio;

CREATE FUNCTION commitment_decision_choices(p_tenant text,p_workload text,p_kind text,p_after text,p_limit integer) RETURNS TABLE(value jsonb)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
BEGIN
 IF current_setting('role',true)<>'finops_api' OR NOT public.commitment_portfolio_access(p_tenant) OR p_limit NOT BETWEEN 1 AND 21 OR NOT EXISTS(SELECT 1 FROM public.entities WHERE tenant_id=p_tenant AND kind='workloads' AND id=p_workload) THEN RAISE EXCEPTION 'decision selector scope differs';END IF;
 IF p_kind='PORTFOLIO_ANALYSIS' THEN
 RETURN QUERY SELECT jsonb_build_object('id',r.id,'kind',p_kind,'label',r.selection->>'source_id'||' / '||r.id,'status',CASE WHEN s.document->'enabled'='true'::jsonb AND s.document->'revoked' IS DISTINCT FROM 'true'::jsonb AND c.document->>'status'='HEALTHY' AND c.document->>'commitment_receipt_id'=r.selection->>'commitment_receipt_id' AND (c.document->>'last_sync_at')::timestamptz>=clock_timestamp()-interval '5 minutes' THEN 'CURRENT' ELSE 'STALE' END,'scope_sha256',NULL,'period',r.selection->'period','input_refs',r.input_refs,'reason_codes','[]'::jsonb) FROM public.commitment_portfolio_requests r JOIN public.commitment_portfolio_results x ON x.tenant_id=r.tenant_id AND x.request_id=r.id AND x.status='ASSESSED' JOIN public.source_registrations s ON s.tenant_id=r.tenant_id AND s.id=r.selection->>'source_id' LEFT JOIN public.source_checkpoints c ON c.tenant_id=s.tenant_id AND c.source_id=s.id AND c.checkpoint_key='status' WHERE r.tenant_id=p_tenant AND r.id>p_after ORDER BY r.id LIMIT p_limit;
 ELSIF p_kind='OFFER' THEN
 RETURN QUERY SELECT jsonb_build_object('id',r.id,'kind',p_kind,'label',r.document->>'native_offering_id'||' / '||r.id,'status',CASE WHEN s.document->'enabled'='true'::jsonb AND s.document->'revoked' IS DISTINCT FROM 'true'::jsonb AND c.document->>'revision_id'=r.revision_id AND (r.document->>'collected_at')::timestamptz>=clock_timestamp()-interval '5 minutes' THEN 'CURRENT' ELSE 'STALE' END,'scope_sha256',NULL,'period',NULL,'input_refs',jsonb_build_array(jsonb_build_object('kind','AWS_SAVINGS_PLAN_OFFER','id',r.id,'sha256',public.fleet_history_json_hash(r.document||jsonb_build_object('writer_role',r.writer_role)))),'reason_codes','[]'::jsonb) FROM public.source_receipts r JOIN public.source_registrations s ON s.tenant_id=r.tenant_id AND s.id=r.source_id LEFT JOIN public.source_checkpoints c ON c.tenant_id=r.tenant_id AND c.source_id=r.source_id AND c.checkpoint_key='savings-plan-quotes' WHERE r.tenant_id=p_tenant AND r.kind='AWS_SAVINGS_PLAN_OFFER' AND r.writer_role='finops_ingester' AND r.id>p_after ORDER BY r.id LIMIT p_limit;
 ELSIF p_kind IN('POST_OPTIMIZATION_ASSESSMENT','FORECAST') THEN
 RETURN QUERY SELECT jsonb_build_object('id',e.id,'kind',p_kind,'label',e.document->>'kind'||' / '||e.id,'status',CASE WHEN coalesce(e.document->'payload'->>'status','') NOT IN('ASSESSED','CALIBRATED') THEN 'UNAVAILABLE' WHEN public.commitment_decision_current(p_tenant,e.document->>'request_id') THEN 'CURRENT' ELSE 'STALE' END,'scope_sha256',e.document->>'scope_sha256','period',NULL,'input_refs',coalesce(e.document->'payload'->'input_refs','[]'),'reason_codes',coalesce(e.document->'payload'->'reason_codes','[]')) FROM public.entities e WHERE e.tenant_id=p_tenant AND e.kind='commitment_decision_evidence' AND e.document->>'workload_id'=p_workload AND e.document->>'kind'=CASE p_kind WHEN 'FORECAST' THEN 'POST_OPTIMIZATION_FORECAST' ELSE 'OPTIMIZATION_ASSESSMENT' END AND e.id>p_after ORDER BY e.id LIMIT p_limit;
 ELSE RAISE EXCEPTION 'decision selector kind differs';END IF;
END $$;
REVOKE ALL ON FUNCTION commitment_decision_choices(text,text,text,text,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION commitment_decision_choices(text,text,text,text,integer) TO finops_api;

-- Private retained snapshots. None of these functions grants object-store
-- credentials or promotes a current point to a historical ownership interval.
CREATE FUNCTION commitment_ownership_machine(p_tenant text) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
BEGIN
 IF current_setting('role',true) IS DISTINCT FROM 'finops_commitment_portfolio' OR NOT public.commitment_portfolio_scope(p_tenant) THEN RAISE EXCEPTION 'ownership analytical credential scope differs';END IF;
END $$;
REVOKE ALL ON FUNCTION commitment_ownership_machine(text) FROM PUBLIC;

CREATE FUNCTION commitment_ownership_registration(p_tenant text,p_id text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE answer jsonb;BEGIN
 PERFORM public.commitment_ownership_machine(p_tenant);
 SELECT r.document||jsonb_build_object('revoked_at',(SELECT v.created_at FROM public.commitment_ownership_revocations v WHERE v.tenant_id=r.tenant_id AND v.registration_id=r.id AND v.revision=r.revision)) INTO answer FROM public.commitment_ownership_registrations r WHERE r.tenant_id=p_tenant AND r.id=p_id ORDER BY r.revision DESC LIMIT 1;
 RETURN answer;
END $$;
CREATE FUNCTION commitment_ownership_review(p_tenant text,p_workload text,p_scope text,p_start timestamptz,p_end timestamptz)
RETURNS TABLE(id text,envelope_sha256 text,server_recorded_at timestamptz,raw_envelope bytea) LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
BEGIN
 PERFORM public.commitment_ownership_machine(p_tenant);
 RETURN QUERY SELECT r.id,r.envelope_sha256,r.server_recorded_at,r.raw_envelope FROM public.commitment_ownership_reviews r WHERE r.tenant_id=p_tenant AND r.workload_id=p_workload AND r.scope_sha256=p_scope AND r.period_start=p_start AND r.period_end=p_end ORDER BY r.server_recorded_at DESC,r.id DESC LIMIT 1;
END $$;
CREATE FUNCTION commitment_ownership_journal_page(p_tenant text,p_workload text,p_scope text,p_registration text,p_start timestamptz,p_end timestamptz,p_resources text[],p_after_resource text,p_after_sequence bigint)
RETURNS TABLE(id text,envelope_sha256 text,server_recorded_at timestamptz,raw_envelope bytea,resource_id text,sequence bigint) LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
BEGIN
 PERFORM public.commitment_ownership_machine(p_tenant);
 IF coalesce(cardinality(p_resources),0) NOT BETWEEN 1 AND 128 OR p_start IS NULL OR p_end IS NULL OR p_start>=p_end OR p_end-p_start>interval '1830 days' OR p_after_sequence<0 THEN RAISE EXCEPTION 'ownership bounded page differs';END IF;
 RETURN QUERY SELECT j.id,j.envelope_sha256,j.server_recorded_at,j.raw_envelope,j.resource_id,j.sequence FROM public.commitment_ownership_journals j WHERE j.tenant_id=p_tenant AND j.workload_id=p_workload AND j.scope_sha256=p_scope AND j.registration_id=p_registration AND j.resource_id=ANY(p_resources) AND j.period_start>=p_start AND j.period_end<=p_end AND (j.resource_id,j.sequence)>(p_after_resource,p_after_sequence) ORDER BY j.resource_id,j.sequence LIMIT 256;
END $$;

CREATE FUNCTION commitment_ownership_artifact_assert(p_tenant text,p_id text,p_sha text,p_archive jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE proof public.configuration_artifact_readback_proofs%ROWTYPE;receipt public.configuration_artifact_receipts%ROWTYPE;cfg jsonb;BEGIN
 SELECT * INTO proof FROM public.configuration_artifact_readback_proofs WHERE tenant_id=p_tenant AND receipt_id=p_id;
 SELECT * INTO receipt FROM public.configuration_artifact_receipts WHERE tenant_id=p_tenant AND id=p_id AND writer_role='finops_configuration_attestor';
 IF receipt.id IS NULL OR proof.receipt_id IS NULL OR proof.writer_role<>'finops_configuration_attestor' OR public.fleet_history_json_hash(proof.receipt) IS DISTINCT FROM p_sha OR proof.receipt_sha256 IS DISTINCT FROM p_sha OR proof.metadata_sha256 IS DISTINCT FROM public.fleet_history_json_hash(receipt.document->'metadata') OR proof.archive IS DISTINCT FROM p_archive OR receipt.document->'archive' IS DISTINCT FROM p_archive OR octet_length(proof.ciphertext) IS DISTINCT FROM (p_archive->>'bytes')::bigint OR encode(sha256(proof.ciphertext),'hex') IS DISTINCT FROM p_archive->>'sha256' THEN RAISE EXCEPTION 'ownership attested readback differs';END IF;
 cfg:=public.configuration_artifact_current(p_tenant,proof.registration_id,proof.registration_version);
 IF receipt.document->'metadata'->>'registration_hash' IS DISTINCT FROM (SELECT r.content_hash FROM public.configuration_artifact_registrations r WHERE r.tenant_id=p_tenant AND r.id=proof.registration_id AND r.version=proof.registration_version) OR receipt.document->'metadata'->'binding' IS DISTINCT FROM cfg->'binding' OR receipt.document->'metadata'->>'authority_id' IS DISTINCT FROM cfg->>'authority_id' OR receipt.document->'metadata'->>'authority_hash' IS DISTINCT FROM cfg->>'authority_hash' THEN RAISE EXCEPTION 'ownership artifact registration changed';END IF;
 RETURN proof.receipt;
END $$;
CREATE FUNCTION commitment_ownership_artifact(p_tenant text,p_id text,p_sha text,p_archive jsonb)
RETURNS TABLE(receipt jsonb,ciphertext bytea) LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE value jsonb;BEGIN
 PERFORM public.commitment_ownership_machine(p_tenant);
 value:=public.commitment_ownership_artifact_assert(p_tenant,p_id,p_sha,p_archive);
 RETURN QUERY SELECT value,p.ciphertext FROM public.configuration_artifact_readback_proofs p WHERE p.tenant_id=p_tenant AND p.receipt_id=p_id;
END $$;
REVOKE ALL ON FUNCTION commitment_ownership_artifact_assert(text,text,text,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION commitment_ownership_registration(text,text),commitment_ownership_review(text,text,text,timestamptz,timestamptz),commitment_ownership_journal_page(text,text,text,text,timestamptz,timestamptz,text[],text,bigint),commitment_ownership_artifact(text,text,text,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION commitment_ownership_registration(text,text),commitment_ownership_review(text,text,text,timestamptz,timestamptz),commitment_ownership_journal_page(text,text,text,text,timestamptz,timestamptz,text[],text,bigint),commitment_ownership_artifact(text,text,text,jsonb) TO finops_commitment_portfolio;

CREATE TABLE commitment_ownership_deployments(
 tenant_id text NOT NULL,id text NOT NULL,registration_id text NOT NULL,registration_revision bigint NOT NULL,
 workload_id text NOT NULL,resource_id text NOT NULL,artifact_id text NOT NULL,artifact_sha256 text NOT NULL,
 issuer text NOT NULL,subject text NOT NULL,audience text NOT NULL,raw_body bytea NOT NULL,body_sha256 text NOT NULL,
 server_recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(tenant_id,id),
 FOREIGN KEY(tenant_id,registration_id,registration_revision) REFERENCES commitment_ownership_registrations(tenant_id,id,revision),CHECK(octet_length(raw_body) BETWEEN 1 AND 16384)
);
ALTER TABLE commitment_ownership_deployments ENABLE ROW LEVEL SECURITY;
ALTER TABLE commitment_ownership_deployments FORCE ROW LEVEL SECURITY;
DO $$ BEGIN EXECUTE format('CREATE POLICY operator_scope ON commitment_ownership_deployments TO %I USING(true) WITH CHECK(true)',current_user);END $$;
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE ON commitment_ownership_deployments FOR EACH ROW EXECUTE FUNCTION public.deny_evidence_mutation();
-- No direct INSERT is granted: the authenticated observer uses only this fixed,
-- tenant-scoped function. Its database row time cannot come from an HTTP body.
CREATE FUNCTION commitment_ownership_append_deployment(p_tenant text,p_issuer text,p_subject text,p_audience text,p_raw bytea)
RETURNS TABLE(envelope_sha256 text,server_recorded_at timestamptz,replay boolean) LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE body jsonb;r public.commitment_ownership_registrations%ROWTYPE;prior public.commitment_ownership_deployments%ROWTYPE;artifact jsonb;target jsonb;recorded timestamptz;BEGIN
 IF current_setting('role',true) IS DISTINCT FROM 'finops_deployment_observer' OR p_tenant IS DISTINCT FROM current_setting('app.tenant_id',true) OR current_setting('transaction_isolation')<>'read committed' OR octet_length(p_raw) NOT BETWEEN 1 AND 16384 OR p_audience IS DISTINCT FROM 'finops-deployment-observer' THEN RAISE EXCEPTION 'authenticated ownership observer required';END IF;
 body:=convert_from(p_raw,'UTF8')::jsonb;
 IF jsonb_typeof(body->'observed_at') IS DISTINCT FROM 'string' OR jsonb_typeof(body->'registration_revision') IS DISTINCT FROM 'number' OR coalesce(body->>'scope_sha256','')!~'^[a-f0-9]{64}$' THEN RAISE EXCEPTION 'ownership deployment observation time/scope required';END IF;
 IF NOT public.commitment_portfolio_keys(body,ARRAY['schema_version','id','registration_id','registration_revision','scope_sha256','tenant_id','workload_id','resource','artifact_ref','archive_ref','observed_at']) OR body->>'schema_version' IS DISTINCT FROM '1' OR body->>'tenant_id' IS DISTINCT FROM p_tenant OR coalesce(body->>'id','')!~'^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$' OR coalesce(body->>'workload_id','')!~'^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$' OR body->'artifact_ref'->>'kind' IS DISTINCT FROM 'CONFIGURATION_ARTIFACT' THEN RAISE EXCEPTION 'ownership deployment body differs';END IF;
 -- Match the same graph->artifact->key order used by final publication.
 PERFORM pg_advisory_xact_lock(hashtextextended(p_tenant||':dependency-graph',0));
 artifact:=public.commitment_ownership_artifact_assert(p_tenant,body->'artifact_ref'->>'id',body->'artifact_ref'->>'sha256',body->'archive_ref');
 PERFORM pg_advisory_xact_lock_shared(hashtextextended(p_tenant||':commitment-ownership-key:'||(body->>'registration_id'),0));
 SELECT * INTO r FROM public.commitment_ownership_registrations WHERE tenant_id=p_tenant AND id=body->>'registration_id' ORDER BY revision DESC LIMIT 1;
 recorded:=clock_timestamp();
 IF r.id IS NULL OR r.revision IS DISTINCT FROM (body->>'registration_revision')::bigint OR r.document->>'purpose' IS DISTINCT FROM 'DEPLOYMENT_JOURNAL' OR r.document->>'scope_sha256' IS DISTINCT FROM body->>'scope_sha256' OR r.document->>'issuer' IS DISTINCT FROM p_issuer OR r.document->>'subject' IS DISTINCT FROM p_subject OR r.document->>'audience' IS DISTINCT FROM p_audience OR EXISTS(SELECT 1 FROM public.commitment_ownership_revocations v WHERE v.tenant_id=p_tenant AND v.registration_id=r.id AND v.revision=r.revision) OR (r.document->>'valid_from')::timestamptz>recorded OR (r.document->>'valid_until')::timestamptz<=recorded THEN RAISE EXCEPTION 'ownership deployment registration inactive';END IF;
 target:=jsonb_build_object('resource_id',artifact->'metadata'->'binding'->>'resource_id','provider_resource_id',artifact->'metadata'->'binding'->>'provider_resource_id','account_id',artifact->'metadata'->'binding'->>'account_id','region',artifact->'metadata'->'binding'->>'region','repository_id',artifact->'metadata'->>'authority_id','git_commit',artifact->'metadata'->'git'->>'commit','configuration_sha256',artifact->'metadata'->'git'->>'configuration_sha256','state_lineage',artifact->'metadata'->'state'->>'lineage');
 IF body->'resource' IS DISTINCT FROM target OR artifact->'metadata'->'binding'->>'tenant_id' IS DISTINCT FROM p_tenant OR artifact->'metadata'->'binding'->>'workload_id' IS DISTINCT FROM body->>'workload_id' OR artifact->'metadata'->'binding'->>'provider' IS DISTINCT FROM 'AWS' OR (body->>'observed_at')::timestamptz<(artifact->>'received_at')::timestamptz OR (body->>'observed_at')::timestamptz>recorded OR (body->>'observed_at')::timestamptz<r.operator_created_at THEN RAISE EXCEPTION 'ownership deployment artifact binding differs';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(p_tenant||':commitment-ownership-deployment:'||(body->>'id'),0));
 SELECT * INTO prior FROM public.commitment_ownership_deployments WHERE tenant_id=p_tenant AND id=body->>'id';
 IF prior.id IS NOT NULL THEN
 IF prior.raw_body IS DISTINCT FROM p_raw OR prior.issuer IS DISTINCT FROM p_issuer OR prior.subject IS DISTINCT FROM p_subject OR prior.audience IS DISTINCT FROM p_audience THEN RAISE EXCEPTION 'ownership deployment replay differs';END IF;
 RETURN QUERY SELECT prior.body_sha256,prior.server_recorded_at,true;RETURN;END IF;
 recorded:=clock_timestamp();IF (r.document->>'valid_until')::timestamptz<=recorded OR recorded-(body->>'observed_at')::timestamptz>interval '5 minutes' THEN RAISE EXCEPTION 'ownership deployment append deadline elapsed';END IF;
 INSERT INTO public.commitment_ownership_deployments(tenant_id,id,registration_id,registration_revision,workload_id,resource_id,artifact_id,artifact_sha256,issuer,subject,audience,raw_body,body_sha256,server_recorded_at) VALUES(p_tenant,body->>'id',r.id,r.revision,body->>'workload_id',target->>'resource_id',body->'artifact_ref'->>'id',body->'artifact_ref'->>'sha256',p_issuer,p_subject,p_audience,p_raw,encode(sha256(p_raw),'hex'),recorded);
 RETURN QUERY SELECT encode(sha256(p_raw),'hex'),recorded,false;
END $$;
CREATE FUNCTION commitment_ownership_deployment(p_tenant text,p_id text,p_sha text)
RETURNS TABLE(raw_body bytea,body_sha256 text,issuer text,subject text,audience text,server_recorded_at timestamptz) LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
BEGIN
 PERFORM public.commitment_ownership_machine(p_tenant);
 RETURN QUERY SELECT d.raw_body,d.body_sha256,d.issuer,d.subject,d.audience,d.server_recorded_at FROM public.commitment_ownership_deployments d WHERE d.tenant_id=p_tenant AND d.id=p_id AND d.body_sha256=p_sha;
END $$;
REVOKE ALL ON FUNCTION commitment_ownership_append_deployment(text,text,text,text,bytea),commitment_ownership_deployment(text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION commitment_ownership_append_deployment(text,text,text,text,bytea) TO finops_deployment_observer;
GRANT EXECUTE ON FUNCTION commitment_ownership_deployment(text,text,text) TO finops_commitment_portfolio;

CREATE FUNCTION commitment_ownership_scope(p_tenant text,p_workload text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE resource record;receipt jsonb;resources jsonb:='[]';item jsonb;total integer:=0;BEGIN
 IF NOT public.commitment_portfolio_access(p_tenant) THEN RAISE EXCEPTION 'ownership credential scope differs';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(p_tenant||':dependency-graph',0));
 FOR resource IN SELECT e.id,e.document FROM public.entities e WHERE e.tenant_id=p_tenant AND e.kind='resources' AND e.document->>'workload_id'=p_workload ORDER BY e.id LOOP
 total:=total+1;IF total>128 OR resource.document->>'provider' IS DISTINCT FROM 'AWS' THEN RETURN NULL;END IF;
 SELECT p.receipt INTO receipt FROM public.configuration_artifact_receipts a JOIN public.configuration_artifact_readback_proofs p ON p.tenant_id=a.tenant_id AND p.receipt_id=a.id JOIN public.configuration_authority_revisions authority ON authority.tenant_id=a.tenant_id AND authority.id=a.document->'metadata'->>'authority_id' WHERE a.tenant_id=p_tenant AND a.writer_role='finops_configuration_attestor' AND a.document->'metadata'->'binding'->>'resource_id'=resource.id AND a.document->'metadata'->'binding'->>'workload_id'=p_workload AND authority.id=(SELECT x.id FROM public.configuration_authority_revisions x WHERE x.tenant_id=p_tenant AND x.resource_id=resource.id ORDER BY x.version DESC LIMIT 1) ORDER BY a.received_at DESC,a.id DESC LIMIT 1;
 IF receipt IS NULL THEN RETURN NULL;END IF;
 PERFORM public.commitment_ownership_artifact_assert(p_tenant,receipt->>'id',public.fleet_history_json_hash(receipt),receipt->'archive');
 item:=jsonb_build_object('resource_id',resource.id,'provider_resource_id',receipt->'metadata'->'binding'->>'provider_resource_id','account_id',receipt->'metadata'->'binding'->>'account_id','region',receipt->'metadata'->'binding'->>'region','repository_id',receipt->'metadata'->>'authority_id','git_commit',receipt->'metadata'->'git'->>'commit','configuration_sha256',receipt->'metadata'->'git'->>'configuration_sha256','state_lineage',receipt->'metadata'->'state'->>'lineage');
 resources:=resources||jsonb_build_array(item);
 END LOOP;
 IF total=0 THEN RETURN NULL;END IF;
 RETURN jsonb_build_object('tenant_id',p_tenant,'workload_id',p_workload,'configuration_sha256',public.fleet_history_json_hash(resources),'resources',resources);
END $$;
REVOKE ALL ON FUNCTION commitment_ownership_scope(text,text) FROM PUBLIC;

-- Hashes prove byte consistency. The private Go factory validates signatures,
-- chain continuity and all typed field semantics before this publication gate.
-- Here current rows, exact heads and authority/credential revocation are checked
-- again while operator changes cannot race the append transaction.
CREATE FUNCTION commitment_ownership_validate(p_tenant text,p_workload text,p_evidence jsonb) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE pin jsonb;r public.commitment_ownership_registrations%ROWTYPE;segment jsonb;head jsonb;review public.commitment_ownership_reviews%ROWTYPE;review_body jsonb;journal public.commitment_ownership_journals%ROWTYPE;body jsonb;artifact jsonb;deployment public.commitment_ownership_deployments%ROWTYPE;row_count bigint;min_sequence bigint;max_sequence bigint;first_sha text;last_sha text;key_count integer:=0;BEGIN
 IF NOT public.commitment_portfolio_access(p_tenant) OR current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION 'ownership credential scope differs';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(p_tenant||':dependency-graph',0));
 IF jsonb_typeof(p_evidence->'observed_at') IS DISTINCT FROM 'string' THEN RAISE EXCEPTION 'ownership observed timestamp required';END IF;
 IF NOT public.commitment_portfolio_keys(p_evidence,ARRAY['schema_version','id','scope','scope_sha256','period','status','basis','segments','registration_pins','input_refs','reason_codes','observed_at','execution_authorized','verified_saving']) OR p_evidence->>'schema_version' IS DISTINCT FROM '1' OR p_evidence->>'status' IS DISTINCT FROM 'CUSTOMER_JOURNAL_REVIEWED_INTERVALS' OR p_evidence->>'basis' IS DISTINCT FROM 'CUSTOMER_REGISTERED_DEPLOYMENT_JOURNAL_WITH_INDEPENDENT_REVIEW' OR p_evidence->>'id' IS DISTINCT FROM public.fleet_history_json_hash(p_evidence||'{"id":""}') OR p_evidence->'scope' IS DISTINCT FROM public.commitment_ownership_scope(p_tenant,p_workload) OR p_evidence->>'scope_sha256' IS DISTINCT FROM public.fleet_history_json_hash(p_evidence->'scope') OR p_evidence->'execution_authorized' IS DISTINCT FROM 'false'::jsonb OR p_evidence->'verified_saving' IS DISTINCT FROM 'null'::jsonb OR jsonb_typeof(p_evidence->'registration_pins') IS DISTINCT FROM 'array' OR jsonb_array_length(p_evidence->'registration_pins')<>2 OR jsonb_typeof(p_evidence->'segments') IS DISTINCT FROM 'array' OR jsonb_array_length(p_evidence->'segments') IS DISTINCT FROM jsonb_array_length(p_evidence->'scope'->'resources') OR NOT public.commitment_portfolio_strings(p_evidence->'reason_codes',128) OR (p_evidence->>'observed_at')::timestamptz>clock_timestamp() OR clock_timestamp()-(p_evidence->>'observed_at')::timestamptz>interval '5 minutes' THEN RAISE EXCEPTION 'ownership verified payload differs';END IF;
 FOR pin IN SELECT v FROM jsonb_array_elements(p_evidence->'registration_pins') v ORDER BY v->>'id' LOOP
 PERFORM pg_advisory_xact_lock_shared(hashtextextended(p_tenant||':commitment-ownership-key:'||(pin->>'id'),0));
 SELECT * INTO r FROM public.commitment_ownership_registrations WHERE tenant_id=p_tenant AND id=pin->>'id' ORDER BY revision DESC LIMIT 1;
 IF r.id IS NULL OR r.revision IS DISTINCT FROM (pin->>'revision')::bigint OR r.document->>'scope_sha256' IS DISTINCT FROM p_evidence->>'scope_sha256' OR public.fleet_history_json_hash(r.document) IS DISTINCT FROM pin->>'sha256' OR EXISTS(SELECT 1 FROM public.commitment_ownership_revocations v WHERE v.tenant_id=p_tenant AND v.registration_id=r.id AND v.revision=r.revision) OR (r.document->>'valid_from')::timestamptz>clock_timestamp() OR (r.document->>'valid_until')::timestamptz<=clock_timestamp() THEN RAISE EXCEPTION 'ownership registered key changed';END IF;
 key_count:=key_count+1;
 END LOOP;
 IF key_count<>2 OR (SELECT count(DISTINCT v->>'id') FROM jsonb_array_elements(p_evidence->'registration_pins') v)<>2 THEN RAISE EXCEPTION 'ownership independent keys required';END IF;
 IF (SELECT jsonb_agg(v->'resource' ORDER BY v->'resource'->>'resource_id') FROM jsonb_array_elements(p_evidence->'segments') v) IS DISTINCT FROM p_evidence->'scope'->'resources' THEN RAISE EXCEPTION 'ownership complete resource population differs';END IF;
 SELECT x.* INTO review FROM public.commitment_ownership_reviews x WHERE x.tenant_id=p_tenant AND x.workload_id=p_workload AND x.scope_sha256=p_evidence->>'scope_sha256' AND x.period_start=(p_evidence->'period'->>'start')::timestamptz AND x.period_end=(p_evidence->'period'->>'end')::timestamptz AND EXISTS(SELECT 1 FROM jsonb_array_elements(p_evidence->'input_refs') ref WHERE ref->>'kind'='OWNERSHIP_REVIEW' AND ref->>'id'=x.id AND ref->>'sha256'=x.envelope_sha256) ORDER BY x.server_recorded_at DESC,x.id DESC LIMIT 1;
 IF review.id IS NULL OR clock_timestamp()-review.server_recorded_at>interval '24 hours' THEN RAISE EXCEPTION 'ownership independent review missing';END IF;
 review_body:=convert_from(review.raw_envelope,'UTF8')::jsonb->'review';
 IF (SELECT jsonb_agg(v->'head' ORDER BY v->'resource'->>'resource_id') FROM jsonb_array_elements(p_evidence->'segments') v) IS DISTINCT FROM review_body->'heads' THEN RAISE EXCEPTION 'ownership complete reviewed head population differs';END IF;
 IF NOT EXISTS(SELECT 1 FROM jsonb_array_elements(p_evidence->'registration_pins') p WHERE p->>'id'=review.registration_id AND (p->>'revision')::bigint=review.registration_revision) OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(p_evidence->'registration_pins') p WHERE p->>'id'=review_body->>'journal_registration_id' AND p->'revision'=review_body->'journal_registration_revision') THEN RAISE EXCEPTION 'ownership review key pins differ';END IF;
 FOR segment IN SELECT v FROM jsonb_array_elements(p_evidence->'segments') v LOOP
 head:=segment->'head';
 IF NOT EXISTS(SELECT 1 FROM jsonb_array_elements(review_body->'heads') h WHERE h=head) OR segment->'period' IS DISTINCT FROM p_evidence->'period' OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(p_evidence->'scope'->'resources') target WHERE target=segment->'resource') THEN RAISE EXCEPTION 'ownership interval head differs';END IF;
 SELECT count(*),min(sequence),max(sequence) INTO row_count,min_sequence,max_sequence FROM public.commitment_ownership_journals j WHERE j.tenant_id=p_tenant AND j.registration_id=review_body->>'journal_registration_id' AND j.registration_revision=(review_body->>'journal_registration_revision')::bigint AND j.workload_id=p_workload AND j.resource_id=segment->'resource'->>'resource_id' AND j.scope_sha256=p_evidence->>'scope_sha256' AND j.period_start>=review.period_start AND j.period_end<=review.period_end;
 SELECT j.envelope_sha256 INTO first_sha FROM public.commitment_ownership_journals j WHERE j.tenant_id=p_tenant AND j.registration_id=review_body->>'journal_registration_id' AND j.registration_revision=(review_body->>'journal_registration_revision')::bigint AND j.resource_id=segment->'resource'->>'resource_id' AND j.sequence=min_sequence;
 SELECT j.envelope_sha256 INTO last_sha FROM public.commitment_ownership_journals j WHERE j.tenant_id=p_tenant AND j.registration_id=review_body->>'journal_registration_id' AND j.registration_revision=(review_body->>'journal_registration_revision')::bigint AND j.resource_id=segment->'resource'->>'resource_id' AND j.sequence=max_sequence;
 IF row_count IS DISTINCT FROM (head->>'count')::bigint OR row_count NOT BETWEEN 1 AND 100000 OR min_sequence IS DISTINCT FROM (head->>'first_sequence')::bigint OR max_sequence IS DISTINCT FROM (head->>'last_sequence')::bigint OR first_sha IS DISTINCT FROM head->>'first_sha256' OR last_sha IS DISTINCT FROM head->>'last_sha256' THEN RAISE EXCEPTION 'ownership retained chain changed';END IF;
 FOR journal IN SELECT j.* FROM public.commitment_ownership_journals j WHERE j.tenant_id=p_tenant AND j.registration_id=review_body->>'journal_registration_id' AND j.registration_revision=(review_body->>'journal_registration_revision')::bigint AND j.resource_id=segment->'resource'->>'resource_id' AND j.sequence BETWEEN min_sequence AND max_sequence ORDER BY j.sequence LOOP
 body:=convert_from(journal.raw_envelope,'UTF8')::jsonb->'journal';
 artifact:=public.commitment_ownership_artifact_assert(p_tenant,body->'artifact_ref'->>'id',body->'artifact_ref'->>'sha256',body->'archive_ref');
 SELECT * INTO deployment FROM public.commitment_ownership_deployments d WHERE d.tenant_id=p_tenant AND d.id=body->'deployment_ref'->>'id' AND d.body_sha256=body->'deployment_ref'->>'sha256';
 IF body->'resource' IS DISTINCT FROM segment->'resource' OR deployment.id IS NULL OR deployment.registration_id IS DISTINCT FROM journal.registration_id OR deployment.registration_revision IS DISTINCT FROM journal.registration_revision OR deployment.artifact_id IS DISTINCT FROM body->'artifact_ref'->>'id' OR deployment.artifact_sha256 IS DISTINCT FROM body->'artifact_ref'->>'sha256' OR deployment.workload_id IS DISTINCT FROM p_workload OR deployment.resource_id IS DISTINCT FROM journal.resource_id OR deployment.server_recorded_at>journal.server_recorded_at OR encode(sha256(deployment.raw_body),'hex') IS DISTINCT FROM deployment.body_sha256 THEN RAISE EXCEPTION 'ownership authenticated deployment changed';END IF;
 END LOOP;
 END LOOP;
END $$;
REVOKE ALL ON FUNCTION commitment_ownership_validate(text,text,jsonb) FROM PUBLIC;

CREATE FUNCTION commitment_ownership_publish(p_tenant text,p_request text,p_evidence jsonb) RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE request jsonb;base jsonb;identity text;digest text;BEGIN
 PERFORM public.commitment_ownership_machine(p_tenant);
 PERFORM pg_advisory_xact_lock(hashtextextended(p_tenant||':dependency-graph',0));
 request:=public.commitment_decision_request(p_tenant,p_request);
 IF request->>'purpose' IS DISTINCT FROM 'PREPARE' THEN RAISE EXCEPTION 'ownership preparation required';END IF;
 base:=public.commitment_decision_base(p_tenant,request->>'workload_id',request->'selection');
 IF public.fleet_history_json_hash(base) IS DISTINCT FROM request->>'input_sha256' THEN RAISE EXCEPTION 'decision issued inputs changed';END IF;
 IF jsonb_typeof(p_evidence->'period'->'start') IS DISTINCT FROM 'string' OR jsonb_typeof(p_evidence->'period'->'end') IS DISTINCT FROM 'string' OR (p_evidence->'period'->>'start')::timestamptz>(base->'portfolio'->'selection'->'period'->>'start')::timestamptz OR (p_evidence->'period'->>'end')::timestamptz<(base->'portfolio'->'selection'->'period'->>'end')::timestamptz THEN RAISE EXCEPTION 'ownership preparation interval not covered';END IF;
 PERFORM public.commitment_ownership_validate(p_tenant,request->>'workload_id',p_evidence);
 identity:=p_evidence->>'id';digest:=public.fleet_history_json_hash(p_evidence);
 INSERT INTO public.commitment_ownership_evidence(tenant_id,id,request_id,workload_id,scope_sha256,document,content_hash,writer_role) VALUES(p_tenant,identity,p_request,request->>'workload_id',p_evidence->>'scope_sha256',p_evidence,digest,'finops_commitment_portfolio') ON CONFLICT(tenant_id,id) DO NOTHING;
 IF NOT EXISTS(SELECT 1 FROM public.commitment_ownership_evidence e WHERE e.tenant_id=p_tenant AND e.id=identity AND e.document=p_evidence AND e.content_hash=digest) THEN RAISE EXCEPTION 'ownership immutable publication differs';END IF;
 RETURN digest;
END $$;
REVOKE ALL ON FUNCTION commitment_ownership_publish(text,text,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION commitment_ownership_publish(text,text,jsonb) TO finops_commitment_portfolio;


-- CONNECTED ADDITIVE040: migrations/040_ownership_archive_patch.sql
-- Additive candidate extension AFTER040; does not change live journal admission.
-- Native timestamps are trusted only from the approved ingestion acquisition.
-- Customer signatures describe customer claims, not native cloud ownership.
CREATE TABLE commitment_ownership_archive_sources(
 tenant_id text NOT NULL,id text NOT NULL,revision bigint NOT NULL CHECK(revision>0),
 document jsonb NOT NULL,content_hash text NOT NULL,operator_created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,id,revision),CHECK(octet_length(document::text)<=16384)
);
CREATE TABLE commitment_ownership_archive_revocations(
 tenant_id text NOT NULL,id text NOT NULL,revision bigint NOT NULL,reason_code text NOT NULL CHECK(reason_code~'^[A-Z][A-Z0-9_]{0,127}$'),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(tenant_id,id,revision),
 FOREIGN KEY(tenant_id,id,revision) REFERENCES commitment_ownership_archive_sources(tenant_id,id,revision)
);
CREATE TABLE commitment_ownership_archive_witnesses(
 tenant_id text NOT NULL,id text NOT NULL,source_id text NOT NULL,source_revision bigint NOT NULL,source_hash text NOT NULL,
 resource_id text NOT NULL,sequence bigint NOT NULL,period_start timestamptz NOT NULL,period_end timestamptz NOT NULL,
 document jsonb NOT NULL,content_hash text NOT NULL,raw_envelope bytea NOT NULL,archive jsonb NOT NULL,
 writer_role name NOT NULL DEFAULT current_user,server_recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,id),FOREIGN KEY(tenant_id,source_id,source_revision) REFERENCES commitment_ownership_archive_sources(tenant_id,id,revision),
 CHECK(octet_length(raw_envelope) BETWEEN 1 AND 65536),CHECK(octet_length(document::text)<=16384),CHECK(octet_length(archive::text)<=8192)
);
CREATE TABLE commitment_ownership_archive_source_checks(
 tenant_id text NOT NULL,id text NOT NULL,source_id text NOT NULL,source_revision bigint NOT NULL,source_hash text NOT NULL,
 document jsonb NOT NULL,writer_role name NOT NULL DEFAULT current_user,server_recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,id),FOREIGN KEY(tenant_id,source_id,source_revision) REFERENCES commitment_ownership_archive_sources(tenant_id,id,revision),
 CHECK(octet_length(document::text)<=262144)
);
CREATE TABLE commitment_ownership_archive_evidence(
 tenant_id text NOT NULL,id text NOT NULL,source_id text NOT NULL,source_revision bigint NOT NULL,workload_id text NOT NULL,
 document jsonb NOT NULL,content_hash text NOT NULL,raw_review bytea NOT NULL,raw_review_archive jsonb NOT NULL,
 writer_role name NOT NULL DEFAULT current_user,server_recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,id),FOREIGN KEY(tenant_id,source_id,source_revision) REFERENCES commitment_ownership_archive_sources(tenant_id,id,revision),
 CHECK(octet_length(document::text)<=1048576),CHECK(octet_length(raw_review) BETWEEN 1 AND 25165824),CHECK(octet_length(raw_review_archive::text)<=8192)
);
CREATE UNIQUE INDEX archive_witness_original_version ON commitment_ownership_archive_witnesses(tenant_id,source_id,source_revision,(document->'pin'->>'key'),(document->'pin'->>'version_id'));
DO $$ DECLARE tab text;BEGIN
 FOREACH tab IN ARRAY ARRAY['commitment_ownership_archive_sources','commitment_ownership_archive_revocations','commitment_ownership_archive_witnesses','commitment_ownership_archive_source_checks','commitment_ownership_archive_evidence'] LOOP
 EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',tab);
 EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',tab);
 EXECUTE format('CREATE POLICY operator_scope ON %I TO %I USING(true) WITH CHECK(true)',tab,current_user);
 EXECUTE format('CREATE TRIGGER immutable BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION public.deny_evidence_mutation()',tab);
 END LOOP;
END $$;
REVOKE ALL ON commitment_ownership_archive_sources,commitment_ownership_archive_revocations,commitment_ownership_archive_witnesses,commitment_ownership_archive_evidence FROM PUBLIC,finops_api,finops_commitment_portfolio,finops_ingester;
REVOKE ALL ON commitment_ownership_archive_source_checks FROM PUBLIC,finops_api,finops_commitment_portfolio,finops_ingester;
CREATE POLICY ingestion_scope ON commitment_ownership_archive_witnesses TO finops_ingester USING(tenant_id=current_setting('app.tenant_id',true)) WITH CHECK(tenant_id=current_setting('app.tenant_id',true));
CREATE POLICY ingestion_scope ON commitment_ownership_archive_evidence TO finops_ingester USING(tenant_id=current_setting('app.tenant_id',true)) WITH CHECK(tenant_id=current_setting('app.tenant_id',true));
CREATE POLICY ingestion_scope ON commitment_ownership_archive_source_checks TO finops_ingester USING(tenant_id=current_setting('app.tenant_id',true)) WITH CHECK(tenant_id=current_setting('app.tenant_id',true));
CREATE POLICY analytical_scope ON commitment_ownership_archive_evidence TO finops_commitment_portfolio USING(public.commitment_portfolio_scope(tenant_id));
GRANT SELECT,INSERT ON commitment_ownership_archive_witnesses,commitment_ownership_archive_evidence TO finops_ingester;
GRANT SELECT,INSERT ON commitment_ownership_archive_source_checks TO finops_ingester;
GRANT SELECT ON commitment_ownership_archive_evidence TO finops_commitment_portfolio;
GRANT EXECUTE ON FUNCTION commitment_portfolio_keys(jsonb,text[]),fleet_history_json_hash(jsonb),fleet_history_json_text(jsonb) TO finops_ingester;

CREATE FUNCTION guard_commitment_archive_source() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE field text;mapping jsonb;external jsonb;previous_resource text:='';
BEGIN
 IF TG_TABLE_NAME='commitment_ownership_archive_revocations' THEN
 PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id||':commitment-archive-source:'||NEW.id,0));NEW.created_at:=clock_timestamp();RETURN NEW;
 END IF;
 FOREACH field IN ARRAY ARRAY['id','scope_sha256','customer_namespace','tenant_id','account_id','bucket_owner','bucket','prefix','region','current_bucket_policy_sha256','signer_key_id','signer_public_key','signer_custodian_issuer','signer_custodian_subject','valid_until'] LOOP
 IF jsonb_typeof(NEW.document->field) IS DISTINCT FROM 'string' THEN RAISE EXCEPTION 'archive source string field required';END IF;
 END LOOP;
 IF NOT public.commitment_portfolio_keys(NEW.document,ARRAY['id','revision','scope_sha256','customer_namespace','external_resources','tenant_id','account_id','bucket_owner','bucket','prefix','region','read_role_binding','current_bucket_policy_sha256','signer_key_id','signer_public_key','signer_custodian_issuer','signer_custodian_subject','valid_until','revoked_at']) OR NEW.document->>'id' IS DISTINCT FROM NEW.id OR NEW.document->>'tenant_id' IS DISTINCT FROM NEW.tenant_id OR NEW.document->'revision' IS DISTINCT FROM to_jsonb(NEW.revision) OR coalesce(NEW.document->>'scope_sha256','')!~'^[a-f0-9]{64}$' OR coalesce(NEW.document->>'account_id','')!~'^[0-9]{12}$' OR NEW.document->>'bucket_owner' IS DISTINCT FROM NEW.document->>'account_id' OR NEW.document->>'region' IS DISTINCT FROM 'eu-west-1' OR coalesce(NEW.document->>'bucket','')!~'^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$' OR starts_with(NEW.document->>'prefix','/') OR position('//' IN NEW.document->>'prefix')>0 OR position(chr(92) IN NEW.document->>'prefix')>0 OR NEW.document->>'prefix'~'[[:cntrl:]]' OR right(NEW.document->>'prefix',1)<>'/' OR position('..' IN NEW.document->>'prefix')>0 OR octet_length(NEW.document->>'prefix')>1024 OR NEW.document->'revoked_at' IS DISTINCT FROM 'null'::jsonb OR NEW.document->'read_role_binding'->>'kind' IS DISTINCT FROM 'APPROVED_READ_ROLE_BINDING' OR coalesce(NEW.document->'read_role_binding'->>'sha256','')!~'^[a-f0-9]{64}$' OR coalesce(NEW.document->>'current_bucket_policy_sha256','')!~'^[a-f0-9]{64}$' OR octet_length(decode(NEW.document->>'signer_public_key','base64'))<>32 OR jsonb_typeof(NEW.document->'valid_until') IS DISTINCT FROM 'string' OR (NEW.document->>'valid_until')::timestamptz<=clock_timestamp() OR coalesce(NEW.document->>'signer_custodian_issuer','')='' OR coalesce(NEW.document->>'signer_custodian_subject','')='' THEN RAISE EXCEPTION 'archive source registration differs';END IF;
 IF coalesce(NEW.document->>'customer_namespace','')!~'^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$' OR jsonb_typeof(NEW.document->'external_resources') IS DISTINCT FROM 'array' OR jsonb_array_length(NEW.document->'external_resources') NOT BETWEEN 1 AND 128 THEN RAISE EXCEPTION 'archive external mapping required';END IF;
 FOR mapping IN SELECT v FROM jsonb_array_elements(NEW.document->'external_resources') v LOOP
 external:=mapping->'external_resource';
 IF NOT public.commitment_portfolio_keys(mapping,ARRAY['resource_id','external_resource']) OR coalesce(mapping->>'resource_id','')!~'^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$' OR mapping->>'resource_id'<=previous_resource OR NOT public.commitment_portfolio_keys(external,ARRAY['customer_workload_id','account_id','region','provider_id','repository_uri','git_commit','configuration_sha256','terraform_address','state_lineage']) OR EXISTS(SELECT 1 FROM jsonb_each(external) v WHERE jsonb_typeof(v.value) IS DISTINCT FROM 'string' OR v.value#>>'{}'='') OR external->>'account_id' IS DISTINCT FROM NEW.document->>'account_id' OR external->>'region' IS DISTINCT FROM NEW.document->>'region' OR coalesce(external->>'repository_uri','')!~'^https://[^/@?#[:space:]]+(/[^?#[:space:]]*)?$' OR position(chr(92) IN external->>'repository_uri')>0 OR octet_length(external->>'repository_uri')>2048 OR octet_length(external->>'terraform_address')>1024 OR external->>'terraform_address'~'[[:cntrl:]]' OR coalesce(external->>'configuration_sha256','')!~'^[a-f0-9]{64}$' OR coalesce(external->>'git_commit','')!~'^[a-f0-9]{40,64}$' THEN RAISE EXCEPTION 'archive external mapping differs';END IF;
 previous_resource:=mapping->>'resource_id';
 END LOOP;
 IF (SELECT count(DISTINCT v->'external_resource') FROM jsonb_array_elements(NEW.document->'external_resources') v)<>jsonb_array_length(NEW.document->'external_resources') THEN RAISE EXCEPTION 'archive duplicate external mapping';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id||':commitment-archive-source:'||NEW.id,0));
 NEW.content_hash:=public.fleet_history_json_hash(NEW.document);NEW.operator_created_at:=clock_timestamp();RETURN NEW;
END $$;
CREATE TRIGGER archive_source BEFORE INSERT ON commitment_ownership_archive_sources FOR EACH ROW EXECUTE FUNCTION guard_commitment_archive_source();
CREATE TRIGGER archive_source_revoke BEFORE INSERT ON commitment_ownership_archive_revocations FOR EACH ROW EXECUTE FUNCTION guard_commitment_archive_source();
REVOKE ALL ON FUNCTION guard_commitment_archive_source() FROM PUBLIC;

CREATE FUNCTION commitment_archive_source(p_tenant text,p_id text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE r public.commitment_ownership_archive_sources%ROWTYPE;BEGIN
 IF current_setting('app.tenant_id',true) IS DISTINCT FROM p_tenant OR (current_setting('role',true)<>'finops_ingester' AND NOT public.commitment_portfolio_access(p_tenant)) OR current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION 'archive source credential scope differs';END IF;
 SELECT * INTO r FROM public.commitment_ownership_archive_sources WHERE tenant_id=p_tenant AND id=p_id ORDER BY revision DESC LIMIT 1;
 IF r.id IS NULL OR EXISTS(SELECT 1 FROM public.commitment_ownership_archive_revocations v WHERE(v.tenant_id,v.id,v.revision)=(r.tenant_id,r.id,r.revision)) OR (r.document->>'valid_until')::timestamptz<=clock_timestamp() THEN RAISE EXCEPTION 'archive source unavailable';END IF;
 RETURN r.document;
END $$;
REVOKE ALL ON FUNCTION commitment_archive_source(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION commitment_archive_source(text,text) TO finops_ingester,finops_commitment_portfolio;

CREATE FUNCTION guard_commitment_archive_source_check() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE registration jsonb;BEGIN
 IF current_user<>'finops_ingester' OR current_setting('app.tenant_id',true) IS DISTINCT FROM NEW.tenant_id OR current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION 'archive ingestion required';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended(NEW.tenant_id||':commitment-archive-source:'||NEW.source_id,0));registration:=public.commitment_archive_source(NEW.tenant_id,NEW.source_id);
 IF (registration->>'revision')::bigint IS DISTINCT FROM NEW.source_revision OR public.fleet_history_json_hash(registration) IS DISTINCT FROM NEW.source_hash OR NEW.id IS DISTINCT FROM public.fleet_history_json_hash(jsonb_build_object('source_registration_sha256',NEW.source_hash,'document',NEW.document)) OR NOT public.commitment_portfolio_keys(NEW.document,ARRAY['versioning','policy','region','bucket_owner','observed_at']) OR NEW.document->>'versioning' IS DISTINCT FROM 'Enabled' OR NEW.document->>'region' IS DISTINCT FROM registration->>'region' OR NEW.document->>'bucket_owner' IS DISTINCT FROM registration->>'bucket_owner' OR public.fleet_history_json_hash(NEW.document->'policy') IS DISTINCT FROM registration->>'current_bucket_policy_sha256' OR jsonb_typeof(NEW.document->'observed_at') IS DISTINCT FROM 'string' OR (NEW.document->>'observed_at')::timestamptz>clock_timestamp() OR (NEW.document->>'observed_at')::timestamptz<clock_timestamp()-interval '5 minutes' THEN RAISE EXCEPTION 'archive current native source check differs';END IF;
 NEW.writer_role:=current_user;NEW.server_recorded_at:=clock_timestamp();RETURN NEW;
END $$;
CREATE TRIGGER archive_source_check BEFORE INSERT ON commitment_ownership_archive_source_checks FOR EACH ROW EXECUTE FUNCTION guard_commitment_archive_source_check();
REVOKE ALL ON FUNCTION guard_commitment_archive_source_check() FROM PUBLIC;

CREATE FUNCTION commitment_archive_review_registration(p_tenant text,p_id text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE r public.commitment_ownership_registrations%ROWTYPE;BEGIN
 IF current_setting('role',true)<>'finops_ingester' OR current_setting('app.tenant_id',true) IS DISTINCT FROM p_tenant OR current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION 'archive ingestion required';END IF;
 SELECT * INTO r FROM public.commitment_ownership_registrations WHERE tenant_id=p_tenant AND id=p_id ORDER BY revision DESC LIMIT 1;
 IF r.id IS NULL OR r.document->>'purpose' IS DISTINCT FROM 'OWNERSHIP_REVIEW' OR EXISTS(SELECT 1 FROM public.commitment_ownership_revocations v WHERE(v.tenant_id,v.registration_id,v.revision)=(r.tenant_id,r.id,r.revision)) OR (r.document->>'valid_until')::timestamptz<=clock_timestamp() THEN RAISE EXCEPTION 'archive reviewer unavailable';END IF;
 RETURN r.document;
END $$;
REVOKE ALL ON FUNCTION commitment_archive_review_registration(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION commitment_archive_review_registration(text,text) TO finops_ingester;

CREATE FUNCTION guard_commitment_archive_witness() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE registration jsonb;claim jsonb;native_at timestamptz;field text;mapped_resource text;BEGIN
 IF current_user<>'finops_ingester' OR current_setting('app.tenant_id',true) IS DISTINCT FROM NEW.tenant_id OR current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION 'archive ingestion required';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended(NEW.tenant_id||':commitment-archive-source:'||NEW.source_id,0));
 registration:=public.commitment_archive_source(NEW.tenant_id,NEW.source_id);
 FOREACH field IN ARRAY ARRAY['key','version_id','sha256'] LOOP
 IF jsonb_typeof(NEW.document->'pin'->field) IS DISTINCT FROM 'string' THEN RAISE EXCEPTION 'archive native pin field required';END IF;
 END LOOP;
 IF jsonb_typeof(NEW.document->'pin'->'bytes') IS DISTINCT FROM 'number' THEN RAISE EXCEPTION 'archive native pin byte count required';END IF;
 IF (registration->>'revision')::bigint IS DISTINCT FROM NEW.source_revision OR public.fleet_history_json_hash(registration) IS DISTINCT FROM NEW.source_hash THEN RAISE EXCEPTION 'archive source changed';END IF;
 IF NOT public.commitment_portfolio_keys(NEW.document,ARRAY['tenant_id','source_registration_sha256','account_id','bucket_owner','bucket','region','pin','native_last_modified','native_time_resolution_seconds']) OR NEW.document->>'tenant_id' IS DISTINCT FROM NEW.tenant_id OR NEW.document->>'source_registration_sha256' IS DISTINCT FROM NEW.source_hash OR NEW.document->>'account_id' IS DISTINCT FROM registration->>'account_id' OR NEW.document->>'bucket_owner' IS DISTINCT FROM registration->>'bucket_owner' OR NEW.document->>'bucket' IS DISTINCT FROM registration->>'bucket' OR NEW.document->>'region' IS DISTINCT FROM registration->>'region' OR NEW.document->'native_time_resolution_seconds' IS DISTINCT FROM '1'::jsonb OR jsonb_typeof(NEW.document->'native_last_modified') IS DISTINCT FROM 'string' OR NOT public.commitment_portfolio_keys(NEW.document->'pin',ARRAY['key','version_id','sha256','bytes']) OR NOT starts_with(NEW.document->'pin'->>'key',registration->>'prefix') OR position('..' IN NEW.document->'pin'->>'key')>0 OR coalesce(NEW.document->'pin'->>'version_id','') IN('','null') OR NEW.document->'pin'->>'sha256' IS DISTINCT FROM encode(sha256(NEW.raw_envelope),'hex') OR (NEW.document->'pin'->>'bytes')::bigint IS DISTINCT FROM octet_length(NEW.raw_envelope)::bigint OR NEW.id IS DISTINCT FROM public.fleet_history_json_hash(NEW.document) THEN RAISE EXCEPTION 'archive native witness differs';END IF;
 native_at:=(NEW.document->>'native_last_modified')::timestamptz;
 claim:=convert_from(NEW.raw_envelope,'UTF8')::jsonb->'claim';
 IF claim->>'schema_version' IS DISTINCT FROM '1' OR claim->>'customer_namespace' IS DISTINCT FROM registration->>'customer_namespace' OR claim->>'signer_key_id' IS DISTINCT FROM registration->>'signer_key_id' OR claim->'external_resource'->>'account_id' IS DISTINCT FROM registration->>'account_id' OR jsonb_typeof(claim->'signed_at') IS DISTINCT FROM 'string' OR jsonb_typeof(claim->'period'->'start') IS DISTINCT FROM 'string' OR jsonb_typeof(claim->'period'->'end') IS DISTINCT FROM 'string' OR (claim->'period'->>'start')::timestamptz>=(claim->'period'->>'end')::timestamptz OR (claim->'period'->>'end')::timestamptz-(claim->'period'->>'start')::timestamptz>interval '1 hour' OR (claim->>'signed_at')::timestamptz<(claim->'period'->>'end')::timestamptz OR native_at<(claim->>'signed_at')::timestamptz OR native_at+interval '1 second'>(claim->'period'->>'end')::timestamptz+interval '5 minutes' OR native_at<>date_trunc('second',native_at) OR native_at>clock_timestamp() THEN RAISE EXCEPTION 'archive native chronology differs';END IF;
 IF coalesce(NEW.archive->>'bucket','')='' OR NOT starts_with(NEW.archive->>'key','tenant/'||NEW.tenant_id||'/commitment-ownership-archive/') OR position('..' IN NEW.archive->>'key')>0 OR coalesce(NEW.archive->>'version_id','') IN('','null') OR NEW.archive->>'body_sha256' IS DISTINCT FROM encode(sha256(NEW.raw_envelope),'hex') THEN RAISE EXCEPTION 'archive immutable readback required';END IF;
 SELECT m->>'resource_id' INTO mapped_resource FROM jsonb_array_elements(registration->'external_resources') m WHERE m->'external_resource'=claim->'external_resource';
 IF mapped_resource IS NULL THEN RAISE EXCEPTION 'archive signed external resource unmapped';END IF;
 NEW.resource_id:=mapped_resource;NEW.sequence:=(claim->>'sequence')::bigint;NEW.period_start:=(claim->'period'->>'start')::timestamptz;NEW.period_end:=(claim->'period'->>'end')::timestamptz;
 IF NEW.resource_id IS NULL OR NEW.sequence IS NULL OR NEW.sequence<1 THEN RAISE EXCEPTION 'archive claim identity required';END IF;
 NEW.content_hash:=public.fleet_history_json_hash(NEW.document);NEW.writer_role:=current_user;NEW.server_recorded_at:=clock_timestamp();RETURN NEW;
END $$;
CREATE TRIGGER archive_witness BEFORE INSERT ON commitment_ownership_archive_witnesses FOR EACH ROW EXECUTE FUNCTION guard_commitment_archive_witness();
REVOKE ALL ON FUNCTION guard_commitment_archive_witness() FROM PUBLIC;

-- The private Go verifier checks Ed25519 customer/reviewer signatures. This
-- SQL guard independently closes the exact ingester-issued row/root population.
CREATE FUNCTION guard_commitment_archive_evidence() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE registration jsonb;review jsonb;reviewer jsonb;counted integer;root_hash text;item record;claim jsonb;heads jsonb:='[]';head jsonb;resource_index integer:=0;last_end timestamptz;last_serial bigint;BEGIN
 IF current_user<>'finops_ingester' OR current_setting('app.tenant_id',true) IS DISTINCT FROM NEW.tenant_id OR current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION 'archive ingestion required';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id||':dependency-graph',0));
 PERFORM pg_advisory_xact_lock_shared(hashtextextended(NEW.tenant_id||':commitment-archive-source:'||NEW.source_id,0));registration:=public.commitment_archive_source(NEW.tenant_id,NEW.source_id);
 review:=convert_from(NEW.raw_review,'UTF8')::jsonb->'review';
 IF coalesce(NEW.raw_review_archive->>'bucket','')='' OR NOT starts_with(NEW.raw_review_archive->>'key','tenant/'||NEW.tenant_id||'/commitment-ownership-archive/') OR position('..' IN NEW.raw_review_archive->>'key')>0 OR coalesce(NEW.raw_review_archive->>'version_id','') IN('','null') OR NEW.raw_review_archive->>'body_sha256' IS DISTINCT FROM encode(sha256(NEW.raw_review),'hex') THEN RAISE EXCEPTION 'archive review immutable readback required';END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended(NEW.tenant_id||':commitment-ownership-key:'||(review->>'reviewer_registration_id'),0));
 reviewer:=public.commitment_archive_review_registration(NEW.tenant_id,review->>'reviewer_registration_id');
 IF jsonb_typeof(review->'signed_at') IS DISTINCT FROM 'string' OR (review->>'signed_at')::timestamptz>clock_timestamp() OR (review->>'signed_at')::timestamptz<clock_timestamp()-interval '24 hours' OR (review->>'signed_at')::timestamptz<(reviewer->>'valid_from')::timestamptz THEN RAISE EXCEPTION 'archive current review deadline differs';END IF;
 IF (registration->>'revision')::bigint IS DISTINCT FROM NEW.source_revision OR NEW.document->>'registration_sha256' IS DISTINCT FROM public.fleet_history_json_hash(registration) OR review->>'source_registration_sha256' IS DISTINCT FROM public.fleet_history_json_hash(registration) OR NEW.document->>'reviewer_registration_sha256' IS DISTINCT FROM public.fleet_history_json_hash(reviewer) OR (review->>'reviewer_registration_revision')::bigint IS DISTINCT FROM (reviewer->>'revision')::bigint OR reviewer->>'scope_sha256' IS DISTINCT FROM registration->>'scope_sha256' OR (reviewer->>'issuer'=registration->>'signer_custodian_issuer' AND reviewer->>'subject'=registration->>'signer_custodian_subject') OR reviewer->>'public_key' IS NOT DISTINCT FROM registration->>'signer_public_key' THEN RAISE EXCEPTION 'archive independent commission differs';END IF;
 IF NOT public.commitment_portfolio_keys(NEW.document,ARRAY['schema_version','id','basis','query','registration_sha256','reviewer_registration_sha256','review_sha256','heads','witness_count','witness_root_sha256','observed_at','execution_authorized','verified_saving']) OR NEW.document->>'schema_version' IS DISTINCT FROM '1' OR NEW.document->>'basis' IS DISTINCT FROM 'CUSTOMER_SIGNED_ARCHIVE_NATIVE_VERSION_WITNESS' OR NEW.document->>'id' IS DISTINCT FROM public.fleet_history_json_hash(NEW.document||'{"id":""}') OR NEW.id IS DISTINCT FROM NEW.document->>'id' OR NEW.document->'execution_authorized' IS DISTINCT FROM 'false'::jsonb OR NEW.document->'verified_saving' IS DISTINCT FROM 'null'::jsonb OR NEW.document->'query' IS DISTINCT FROM review->'query' OR NEW.document->>'review_sha256' IS DISTINCT FROM encode(sha256(NEW.raw_review),'hex') OR NEW.document->'heads' IS DISTINCT FROM review->'heads' OR NEW.document->'query'->'scope'->>'tenant_id' IS DISTINCT FROM NEW.tenant_id OR NEW.document->'query'->'scope'->>'workload_id' IS DISTINCT FROM NEW.workload_id OR public.fleet_history_json_hash(NEW.document->'query'->'scope') IS DISTINCT FROM registration->>'scope_sha256' OR jsonb_typeof(NEW.document->'observed_at') IS DISTINCT FROM 'string' OR (NEW.document->>'observed_at')::timestamptz>clock_timestamp() OR (NEW.document->>'observed_at')::timestamptz<clock_timestamp()-interval '5 minutes' OR jsonb_typeof(review->'objects') IS DISTINCT FROM 'array' OR jsonb_array_length(review->'objects') NOT BETWEEN 1 AND 100000 THEN RAISE EXCEPTION 'archive compact evidence differs';END IF;
 SELECT count(*)::integer,encode(sha256(convert_to(string_agg(public.fleet_history_json_text(jsonb_build_object('kind','AWS_OWNERSHIP_ARCHIVE_OBJECT','id',w.id,'sha256',w.content_hash))||E'\n','' ORDER BY p.ordinal),'UTF8')),'hex') INTO counted,root_hash
 FROM jsonb_array_elements(review->'objects') WITH ORDINALITY p(pin,ordinal)
 JOIN public.commitment_ownership_archive_witnesses w ON w.tenant_id=NEW.tenant_id AND w.source_id=NEW.source_id AND w.source_revision=NEW.source_revision AND w.document->'pin'->>'key'=p.pin->>'key' AND w.document->'pin'->>'version_id'=p.pin->>'version_id'
 WHERE w.source_hash=NEW.document->>'registration_sha256' AND w.document->'pin'=p.pin AND w.writer_role='finops_ingester' AND w.content_hash=public.fleet_history_json_hash(w.document);
 IF counted<>jsonb_array_length(review->'objects') OR (SELECT count(DISTINCT ROW(v->>'key',v->>'version_id')) FROM jsonb_array_elements(review->'objects') v)<>counted OR NEW.document->'witness_count' IS DISTINCT FROM to_jsonb(counted) OR NEW.document->>'witness_root_sha256' IS DISTINCT FROM root_hash OR (SELECT sum((p->>'bytes')::bigint) FROM jsonb_array_elements(review->'objects') p)>134217728 THEN RAISE EXCEPTION 'archive exact native root differs';END IF;
 PERFORM public.commitment_archive_mapping_assert(NEW.tenant_id,NEW.source_id,review->'query'->'scope');
 -- Verify the complete ordered resource/interval/sequence population against
 -- the independent signed review, not merely the number of original objects.
 FOR item IN SELECT w.* FROM jsonb_array_elements(review->'objects') WITH ORDINALITY p(pin,ordinal) JOIN public.commitment_ownership_archive_witnesses w ON w.tenant_id=NEW.tenant_id AND w.source_id=NEW.source_id AND w.source_revision=NEW.source_revision AND w.document->'pin'->>'key'=p.pin->>'key' AND w.document->'pin'->>'version_id'=p.pin->>'version_id' ORDER BY p.ordinal LOOP
 claim:=convert_from(item.raw_envelope,'UTF8')::jsonb->'claim';
 IF head IS NOT NULL AND head->>'resource_id' IS DISTINCT FROM item.resource_id THEN
 IF last_end IS DISTINCT FROM (review->'query'->'period'->>'end')::timestamptz THEN RAISE EXCEPTION 'archive resource interval incomplete';END IF;
 heads:=heads||jsonb_build_array(head);resource_index:=resource_index+1;head:=NULL;
 END IF;
 IF claim->'external_resource' IS DISTINCT FROM registration->'external_resources'->resource_index->'external_resource' OR item.resource_id IS DISTINCT FROM registration->'external_resources'->resource_index->>'resource_id' OR item.resource_id IS DISTINCT FROM review->'query'->'scope'->'resources'->resource_index->>'resource_id' THEN RAISE EXCEPTION 'archive complete resource population differs';END IF;
 IF head IS NULL THEN
 IF item.period_start IS DISTINCT FROM (review->'query'->'period'->>'start')::timestamptz OR item.sequence=1 AND claim->>'previous_sha256' IS DISTINCT FROM '' OR item.sequence>1 AND coalesce(claim->>'previous_sha256','')!~'^[a-f0-9]{64}$' THEN RAISE EXCEPTION 'archive reviewed slice origin differs';END IF;
 head:=jsonb_build_object('resource_id',item.resource_id,'count',0,'first_sequence',item.sequence,'last_sequence',item.sequence,'first_sha256',item.document->'pin'->>'sha256','last_sha256',item.document->'pin'->>'sha256');
 ELSE
 IF item.period_start IS DISTINCT FROM last_end OR item.sequence IS DISTINCT FROM (head->>'last_sequence')::bigint+1 OR claim->>'previous_sha256' IS DISTINCT FROM head->>'last_sha256' OR (claim->>'state_serial')::bigint<last_serial THEN RAISE EXCEPTION 'archive exact signed chain differs';END IF;
 END IF;
 head:=head||jsonb_build_object('count',(head->>'count')::integer+1,'last_sequence',item.sequence,'last_sha256',item.document->'pin'->>'sha256');last_end:=item.period_end;last_serial:=(claim->>'state_serial')::bigint;
 END LOOP;
 IF head IS NULL OR last_end IS DISTINCT FROM (review->'query'->'period'->>'end')::timestamptz THEN RAISE EXCEPTION 'archive resource interval incomplete';END IF;
 heads:=heads||jsonb_build_array(head);
 IF heads IS DISTINCT FROM review->'heads' OR jsonb_array_length(heads) IS DISTINCT FROM jsonb_array_length(review->'query'->'scope'->'resources') THEN RAISE EXCEPTION 'archive complete reviewed heads differ';END IF;
 IF NOT EXISTS(SELECT 1 FROM public.commitment_ownership_archive_source_checks c WHERE c.tenant_id=NEW.tenant_id AND c.source_id=NEW.source_id AND c.source_revision=NEW.source_revision AND c.source_hash=NEW.document->>'registration_sha256' AND c.writer_role='finops_ingester' AND c.server_recorded_at>=clock_timestamp()-interval '5 minutes' AND (c.document->>'observed_at')::timestamptz>=clock_timestamp()-interval '5 minutes') THEN RAISE EXCEPTION 'archive current native source check unavailable';END IF;
 NEW.content_hash:=public.fleet_history_json_hash(NEW.document);NEW.writer_role:=current_user;NEW.server_recorded_at:=clock_timestamp();RETURN NEW;
END $$;
CREATE TRIGGER archive_evidence BEFORE INSERT ON commitment_ownership_archive_evidence FOR EACH ROW EXECUTE FUNCTION guard_commitment_archive_evidence();
REVOKE ALL ON FUNCTION guard_commitment_archive_evidence() FROM PUBLIC;

CREATE FUNCTION commitment_archive_resolve(p_tenant text,p_workload text,p_start timestamptz,p_end timestamptz,p_id text DEFAULT NULL,p_sha text DEFAULT NULL) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE e public.commitment_ownership_archive_evidence%ROWTYPE;registration jsonb;review jsonb;reviewer public.commitment_ownership_registrations%ROWTYPE;BEGIN
 IF NOT public.commitment_portfolio_access(p_tenant) THEN RAISE EXCEPTION 'archive analytical/API scope differs';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(p_tenant||':dependency-graph',0));
 SELECT * INTO e FROM public.commitment_ownership_archive_evidence x WHERE x.tenant_id=p_tenant AND x.workload_id=p_workload AND (p_id IS NULL OR x.id=p_id) AND (p_sha IS NULL OR x.content_hash=p_sha) AND (x.document->'query'->'period'->>'start')::timestamptz<=p_start AND (x.document->'query'->'period'->>'end')::timestamptz>=p_end ORDER BY x.server_recorded_at DESC,x.id DESC LIMIT 1;
 IF e.id IS NULL THEN RETURN NULL;END IF;
 PERFORM pg_advisory_xact_lock_shared(hashtextextended(p_tenant||':commitment-archive-source:'||e.source_id,0));registration:=public.commitment_archive_source(p_tenant,e.source_id);review:=convert_from(e.raw_review,'UTF8')::jsonb->'review';
 PERFORM pg_advisory_xact_lock_shared(hashtextextended(p_tenant||':commitment-ownership-key:'||(review->>'reviewer_registration_id'),0));
 SELECT * INTO reviewer FROM public.commitment_ownership_registrations WHERE tenant_id=p_tenant AND id=review->>'reviewer_registration_id' ORDER BY revision DESC LIMIT 1;
 IF jsonb_typeof(review->'signed_at') IS DISTINCT FROM 'string' OR (review->>'signed_at')::timestamptz>clock_timestamp() OR (review->>'signed_at')::timestamptz<clock_timestamp()-interval '24 hours' THEN RAISE EXCEPTION 'archive current review deadline differs';END IF;
 IF reviewer.id IS NULL OR EXISTS(SELECT 1 FROM public.commitment_ownership_revocations r WHERE(r.tenant_id,r.registration_id,r.revision)=(reviewer.tenant_id,reviewer.id,reviewer.revision)) OR (reviewer.document->>'valid_until')::timestamptz<=clock_timestamp() OR public.fleet_history_json_hash(reviewer.document) IS DISTINCT FROM e.document->>'reviewer_registration_sha256' OR public.fleet_history_json_hash(registration) IS DISTINCT FROM e.document->>'registration_sha256' OR e.document->'query'->'scope' IS DISTINCT FROM public.commitment_ownership_scope(p_tenant,p_workload) OR e.content_hash IS DISTINCT FROM public.fleet_history_json_hash(e.document) OR NOT EXISTS(SELECT 1 FROM public.commitment_ownership_archive_source_checks c WHERE c.tenant_id=p_tenant AND c.source_id=e.source_id AND c.source_revision=e.source_revision AND c.source_hash=e.document->>'registration_sha256' AND c.writer_role='finops_ingester' AND c.server_recorded_at>=clock_timestamp()-interval '5 minutes' AND (c.document->>'observed_at')::timestamptz>=clock_timestamp()-interval '5 minutes') THEN RAISE EXCEPTION 'archive current authority changed';END IF;
 PERFORM public.commitment_archive_mapping_assert(p_tenant,e.source_id,e.document->'query'->'scope');
 RETURN e.document;
END $$;
REVOKE ALL ON FUNCTION commitment_archive_resolve(text,text,timestamptz,timestamptz,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION commitment_archive_resolve(text,text,timestamptz,timestamptz,text,text) TO finops_commitment_portfolio;

-- Normalized private union. It authenticates the requested immutable reference;
-- the optional discovery path above never substitutes a different selected row.
CREATE FUNCTION commitment_decision_ownership_assert(p_tenant text,p_workload text,p_ref jsonb,p_start timestamptz,p_end timestamptz) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE value jsonb;basis text;scope jsonb;period jsonb;refs jsonb;pins jsonb;archive_row public.commitment_ownership_archive_evidence%ROWTYPE;review jsonb;BEGIN
 IF NOT public.commitment_portfolio_access(p_tenant) THEN RAISE EXCEPTION 'ownership analytical/API scope differs';END IF;
 IF p_start IS NULL OR p_end IS NULL OR p_start>=p_end OR NOT public.commitment_portfolio_keys(p_ref,ARRAY['kind','id','sha256']) OR p_ref->>'kind' IS DISTINCT FROM 'HISTORICAL_OWNERSHIP' OR coalesce(p_ref->>'id','')!~'^[a-f0-9]{64}$' OR coalesce(p_ref->>'sha256','')!~'^[a-f0-9]{64}$' THEN RAISE EXCEPTION 'ownership exact issued reference required';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(p_tenant||':dependency-graph',0));
 IF pg_has_role(session_user,'finops_commitment_portfolio','MEMBER') THEN
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('commitment-portfolio-credential:'||session_user::text,0));
 IF NOT public.commitment_portfolio_scope(p_tenant) THEN RAISE EXCEPTION 'ownership analytical credential scope differs';END IF;END IF;
 SELECT e.document INTO value FROM public.commitment_ownership_evidence e WHERE e.tenant_id=p_tenant AND e.id=p_ref->>'id' AND e.content_hash=p_ref->>'sha256' AND e.workload_id=p_workload;
 IF value IS NOT NULL THEN
 PERFORM public.commitment_ownership_validate(p_tenant,p_workload,value);
 scope:=value->'scope';period:=value->'period';basis:=value->>'basis';refs:=value->'input_refs';pins:=value->'registration_pins';
 ELSE
 value:=public.commitment_archive_resolve(p_tenant,p_workload,p_start,p_end,p_ref->>'id',p_ref->>'sha256');
 IF value IS NULL THEN RAISE EXCEPTION 'ownership exact issued reference unavailable';END IF;
 SELECT * INTO archive_row FROM public.commitment_ownership_archive_evidence e WHERE e.tenant_id=p_tenant AND e.id=p_ref->>'id' AND e.content_hash=p_ref->>'sha256';
 review:=convert_from(archive_row.raw_review,'UTF8')::jsonb->'review';scope:=value->'query'->'scope';period:=value->'query'->'period';basis:=value->>'basis';
 refs:=jsonb_build_array(jsonb_build_object('kind','OWNERSHIP_REVIEW','id',review->>'id','sha256',value->>'review_sha256'));
 pins:=jsonb_build_array(jsonb_build_object('id',archive_row.source_id,'revision',archive_row.source_revision,'sha256',value->>'registration_sha256'),jsonb_build_object('id',review->>'reviewer_registration_id','revision',review->'reviewer_registration_revision','sha256',value->>'reviewer_registration_sha256'));
 END IF;
 IF (period->>'start')::timestamptz>p_start OR (period->>'end')::timestamptz<p_end OR scope IS DISTINCT FROM public.commitment_ownership_scope(p_tenant,p_workload) THEN RAISE EXCEPTION 'ownership full current interval differs';END IF;
 SELECT coalesce(jsonb_agg(v ORDER BY v->>'kind',v->>'id'),'[]') INTO refs FROM(SELECT DISTINCT v FROM jsonb_array_elements(refs||jsonb_build_array(p_ref)) v) q;
 SELECT jsonb_agg(v ORDER BY v->>'id') INTO pins FROM jsonb_array_elements(pins) v;
 RETURN jsonb_build_object('scope',scope,'scope_sha256',public.fleet_history_json_hash(scope),'period',period,'basis',basis,'reference',p_ref,'input_refs',refs,'observed_at',clock_timestamp(),'registration_pins',pins);
END $$;
REVOKE ALL ON FUNCTION commitment_decision_ownership_assert(text,text,jsonb,timestamptz,timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION commitment_decision_ownership_assert(text,text,jsonb,timestamptz,timestamptz) TO finops_commitment_portfolio;

-- Only a queued IDs-only preparation selects among actually issued aggregates.
-- Subsequent use pins the exact immutable reference; it never chooses latest.
CREATE FUNCTION commitment_decision_ownership_discover(p_tenant text,p_request text,p_start timestamptz,p_end timestamptz) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE request jsonb;base jsonb;reference jsonb;answer jsonb;BEGIN
 PERFORM public.commitment_ownership_machine(p_tenant);
 IF p_start IS NULL OR p_end IS NULL OR p_start>=p_end OR p_end-p_start>interval '5 years' THEN RAISE EXCEPTION 'ownership discovery interval differs';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(p_tenant||':dependency-graph',0));
 request:=public.commitment_decision_request(p_tenant,p_request);
 IF request->>'purpose' IS DISTINCT FROM 'PREPARE' THEN RAISE EXCEPTION 'ownership preparation required';END IF;
 base:=public.commitment_decision_base(p_tenant,request->>'workload_id',request->'selection');
 IF public.fleet_history_json_hash(base) IS DISTINCT FROM request->>'input_sha256' THEN RAISE EXCEPTION 'decision issued inputs changed';END IF;
 IF base->'ownership_scope' IS NULL OR base->'ownership_scope'='null'::jsonb THEN RETURN NULL;END IF;
 SELECT jsonb_build_object('kind','HISTORICAL_OWNERSHIP','id',v.id,'sha256',v.content_hash) INTO reference FROM (
 SELECT e.id,e.content_hash,e.created_at AS server_recorded_at FROM public.commitment_ownership_evidence e WHERE e.tenant_id=p_tenant AND e.workload_id=request->>'workload_id' AND e.document->'scope'=base->'ownership_scope' AND (e.document->'period'->>'start')::timestamptz<=p_start AND (e.document->'period'->>'end')::timestamptz>=p_end
 UNION ALL
 SELECT e.id,e.content_hash,e.server_recorded_at FROM public.commitment_ownership_archive_evidence e WHERE e.tenant_id=p_tenant AND e.workload_id=request->>'workload_id' AND e.document->'query'->'scope'=base->'ownership_scope' AND (e.document->'query'->'period'->>'start')::timestamptz<=p_start AND (e.document->'query'->'period'->>'end')::timestamptz>=p_end
 ) v ORDER BY v.server_recorded_at DESC,v.id DESC LIMIT 1;
 IF reference IS NULL THEN RETURN NULL;END IF;
 answer:=public.commitment_decision_ownership_assert(p_tenant,request->>'workload_id',reference,p_start,p_end);
 IF answer->'scope' IS DISTINCT FROM base->'ownership_scope' THEN RAISE EXCEPTION 'ownership discovery scope differs';END IF;
 RETURN answer;
END $$;
REVOKE ALL ON FUNCTION commitment_decision_ownership_discover(text,text,timestamptz,timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION commitment_decision_ownership_discover(text,text,timestamptz,timestamptz) TO finops_commitment_portfolio;

-- Map historical native/customer identifiers only through current independent
-- operator approval and actual issued Terraform authority/artifact bindings.
-- It returns no artifacts or proof flags, and cannot publish an aggregate.
CREATE FUNCTION commitment_archive_mapping_assert(p_tenant text,p_source text,p_scope jsonb) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE registration jsonb;mapping jsonb;external jsonb;target jsonb;authority public.configuration_authority_revisions%ROWTYPE;receipt jsonb;index integer:=0;BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended(p_tenant||':dependency-graph',0));
 PERFORM pg_advisory_xact_lock_shared(hashtextextended(p_tenant||':commitment-archive-source:'||p_source,0));
 registration:=public.commitment_archive_source(p_tenant,p_source);
 IF p_scope->>'tenant_id' IS DISTINCT FROM p_tenant OR public.fleet_history_json_hash(p_scope) IS DISTINCT FROM registration->>'scope_sha256' OR jsonb_typeof(p_scope->'resources') IS DISTINCT FROM 'array' OR jsonb_array_length(p_scope->'resources') IS DISTINCT FROM jsonb_array_length(registration->'external_resources') THEN RAISE EXCEPTION 'archive approved mapping scope differs';END IF;
 FOR mapping IN SELECT v FROM jsonb_array_elements(registration->'external_resources') v LOOP
 external:=mapping->'external_resource';target:=p_scope->'resources'->index;index:=index+1;
 IF mapping->>'resource_id' IS DISTINCT FROM target->>'resource_id' OR external->>'provider_id' IS DISTINCT FROM target->>'provider_resource_id' OR external->>'account_id' IS DISTINCT FROM target->>'account_id' OR external->>'region' IS DISTINCT FROM target->>'region' OR external->>'git_commit' IS DISTINCT FROM target->>'git_commit' OR external->>'configuration_sha256' IS DISTINCT FROM target->>'configuration_sha256' OR external->>'state_lineage' IS DISTINCT FROM target->>'state_lineage' THEN RAISE EXCEPTION 'archive exact external mapping differs';END IF;
 SELECT * INTO authority FROM public.configuration_authority_revisions a WHERE a.tenant_id=p_tenant AND a.resource_id=target->>'resource_id' ORDER BY a.version DESC LIMIT 1;
 IF authority.id IS NULL OR authority.id IS DISTINCT FROM target->>'repository_id' OR authority.workload_id IS DISTINCT FROM p_scope->>'workload_id' OR authority.writer_role<>'finops_api' OR authority.document->'repository'->>'url' IS DISTINCT FROM external->>'repository_uri' OR NOT (authority.document->'terraform'->'addresses' ? (external->>'terraform_address')) OR authority.document->'terraform'->>'state_lineage' IS DISTINCT FROM external->>'state_lineage' THEN RAISE EXCEPTION 'archive current repository address authority differs';END IF;
 SELECT p.receipt INTO receipt FROM public.configuration_artifact_receipts a JOIN public.configuration_artifact_readback_proofs p ON p.tenant_id=a.tenant_id AND p.receipt_id=a.id WHERE a.tenant_id=p_tenant AND a.writer_role='finops_configuration_attestor' AND a.document->'metadata'->>'authority_id'=authority.id AND a.document->'metadata'->'binding'->>'resource_id'=target->>'resource_id' ORDER BY a.received_at DESC,a.id DESC LIMIT 1;
 IF receipt IS NULL THEN RAISE EXCEPTION 'archive current attested mapping unavailable';END IF;
 PERFORM public.commitment_ownership_artifact_assert(p_tenant,receipt->>'id',public.fleet_history_json_hash(receipt),receipt->'archive');
 IF receipt->'metadata'->'git'->>'commit' IS DISTINCT FROM external->>'git_commit' OR receipt->'metadata'->'git'->>'configuration_sha256' IS DISTINCT FROM external->>'configuration_sha256' OR receipt->'metadata'->'state'->>'lineage' IS DISTINCT FROM external->>'state_lineage' OR receipt->'metadata'->'binding'->>'provider_resource_id' IS DISTINCT FROM external->>'provider_id' OR receipt->'metadata'->'binding'->>'account_id' IS DISTINCT FROM external->>'account_id' OR receipt->'metadata'->'binding'->>'region' IS DISTINCT FROM external->>'region' THEN RAISE EXCEPTION 'archive actual attested external mapping differs';END IF;
 END LOOP;
END $$;
REVOKE ALL ON FUNCTION commitment_archive_mapping_assert(text,text,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION commitment_archive_mapping_assert(text,text,jsonb) TO finops_ingester;


-- CONNECTED ADDITIVE040: migrations/040_stage_outcomes_extension.sql.fragment
-- Candidate extension after040's live/archive ownership union.
-- The039 analytical login gets only two fixed functions, never entities grants.
-- Profile/SLO declarations are constraints; no execution or usage is invented.

CREATE FUNCTION commitment_optimization_stage_context(p_tenant text,p_request text,p_scope jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE request jsonb;base jsonb;ownership jsonb;resources jsonb;native_ids jsonb;accounts jsonb;offers jsonb;native_offer jsonb;
 profile public.workload_safety_profiles%ROWTYPE;objective public.slo_objectives%ROWTYPE;
 profile_value jsonb:=NULL;profile_ref jsonb:=NULL;objectives jsonb:='[]';refs jsonb;policy jsonb;answer jsonb;projection_start timestamptz;assessed_at text;
 retained_count bigint;retained_hash text;retained_stamp text;retained boolean:=false;proof record;stage_name text;
BEGIN
 IF NOT public.commitment_portfolio_access(p_tenant) OR current_setting('transaction_isolation') IS DISTINCT FROM 'read committed' OR current_setting('app.tenant_id',true) IS DISTINCT FROM p_tenant THEN RAISE EXCEPTION 'optimization credential scope differs';END IF;
 IF octet_length(p_scope::text)>65536 OR NOT public.commitment_portfolio_keys(p_scope,ARRAY['tenant_id','workload_id','payer_account_id','usage_account_ids','resource_ids','class','currency','configuration_sha256','ownership_ref','history_period','projection_period','sha256']) OR p_scope->>'tenant_id' IS DISTINCT FROM p_tenant OR p_scope->>'sha256' IS DISTINCT FROM public.fleet_history_json_hash(p_scope||'{"sha256":""}') THEN RAISE EXCEPTION 'optimization scope differs';END IF;
 -- Match the existing dependency graph/source/key order. Source-owned facts
 -- are reselected by040 base ->039 resolve under its exact source fence.
 PERFORM pg_advisory_xact_lock(hashtextextended(p_tenant||':dependency-graph',0));
 IF pg_has_role(session_user,'finops_commitment_portfolio','MEMBER') THEN
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('commitment-portfolio-credential:'||session_user::text,0));
 IF NOT public.commitment_portfolio_scope(p_tenant) THEN RAISE EXCEPTION 'optimization credential scope differs';END IF;END IF;
 request:=public.commitment_decision_request(p_tenant,p_request);
 IF request->>'purpose' IS DISTINCT FROM 'PREPARE' OR request->>'id' IS DISTINCT FROM p_request OR request->>'workload_id' IS DISTINCT FROM p_scope->>'workload_id' THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='optimization issued preparation unavailable';END IF;
 base:=public.commitment_decision_base(p_tenant,request->>'workload_id',request->'selection');
 IF public.fleet_history_json_hash(base) IS DISTINCT FROM request->>'input_sha256' THEN RAISE EXCEPTION 'optimization current inputs changed';END IF;
 IF base->'ownership_scope' IS NULL OR base->'ownership_scope'='null'::jsonb OR p_scope->'ownership_ref'->>'kind' IS DISTINCT FROM 'HISTORICAL_OWNERSHIP' THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='optimization issued ownership unavailable';END IF;
 SELECT jsonb_agg(to_jsonb(v) ORDER BY v) INTO accounts FROM jsonb_array_elements_text(base->'portfolio_inputs'->'commitment'->'commitment_scope'->'usage_account_ids') v;
 SELECT jsonb_agg(to_jsonb(v->>'provider_resource_id') ORDER BY v->>'provider_resource_id') INTO native_ids FROM jsonb_array_elements(base->'resources') v;
 SELECT jsonb_object_agg(v->>'provider_resource_id',v->>'id') INTO resources FROM jsonb_array_elements(base->'resources') v;
 IF resources IS NULL OR jsonb_array_length(native_ids) NOT BETWEEN 1 AND 128 OR (SELECT count(*) FROM jsonb_object_keys(resources)) IS DISTINCT FROM jsonb_array_length(native_ids) OR p_scope->'resource_ids' IS DISTINCT FROM native_ids OR p_scope->'usage_account_ids' IS DISTINCT FROM accounts OR p_scope->>'payer_account_id' IS DISTINCT FROM base->'portfolio_inputs'->'registration'->>'payer_account_id' OR p_scope->>'configuration_sha256' IS DISTINCT FROM base->'ownership_scope'->>'configuration_sha256' OR p_scope->'history_period' IS DISTINCT FROM base->'portfolio'->'selection'->'period' THEN RAISE EXCEPTION 'optimization exact resource scope differs';END IF;
 SELECT jsonb_agg(v->'native') INTO offers FROM jsonb_array_elements(base->'offer_revision'->'native'->'offerings') v WHERE v->'native'->>'offeringId'=base->'offer_receipt'->>'native_offering_id';
 IF jsonb_array_length(offers) IS DISTINCT FROM 1 THEN RAISE EXCEPTION 'optimization offer scope differs';END IF;native_offer:=offers->0;
 IF coalesce(native_offer->>'planType','') NOT IN('Compute','EC2Instance') OR native_offer->>'paymentOption' IS DISTINCT FROM 'No Upfront' OR native_offer->'durationSeconds' IS DISTINCT FROM '31536000'::jsonb OR p_scope->>'class' IS DISTINCT FROM (CASE native_offer->>'planType' WHEN 'Compute' THEN 'COMPUTE_SAVINGS_PLAN' WHEN 'EC2Instance' THEN 'EC2_INSTANCE_SAVINGS_PLAN' ELSE '' END) OR p_scope->>'currency' IS DISTINCT FROM native_offer->>'currency' THEN RAISE EXCEPTION 'optimization offer scope differs';END IF;
 IF NOT public.commitment_portfolio_keys(p_scope->'projection_period',ARRAY['start','end']) OR jsonb_typeof(p_scope->'projection_period'->'start') IS DISTINCT FROM 'string' OR jsonb_typeof(p_scope->'projection_period'->'end') IS DISTINCT FROM 'string' OR p_scope->'projection_period'->>'start'!~'(Z|[+]00:00)$' OR p_scope->'projection_period'->>'end'!~'(Z|[+]00:00)$' THEN RAISE EXCEPTION 'optimization projection differs';END IF;
 projection_start:=(p_scope->'projection_period'->>'start')::timestamptz;
 IF projection_start<clock_timestamp() OR projection_start>=clock_timestamp()+interval '1 hour' OR date_trunc('hour',projection_start AT TIME ZONE 'UTC') IS DISTINCT FROM projection_start AT TIME ZONE 'UTC' OR (p_scope->'projection_period'->>'end')::timestamptz-projection_start<>interval '8760 hours' THEN RAISE EXCEPTION 'optimization projection differs';END IF;
 ownership:=public.commitment_decision_ownership_assert(p_tenant,request->>'workload_id',p_scope->'ownership_ref',(p_scope->'history_period'->>'start')::timestamptz,(p_scope->'history_period'->>'end')::timestamptz);
 IF ownership->'scope' IS DISTINCT FROM base->'ownership_scope' THEN RAISE EXCEPTION 'optimization ownership scope differs';END IF;
 refs:=base->'input_refs'||ownership->'input_refs'||jsonb_build_array(jsonb_build_object('kind','COMMITMENT_PREPARATION','id',p_request,'sha256',public.fleet_history_json_hash(request)));
 SELECT * INTO profile FROM public.workload_safety_profiles p WHERE p.tenant_id=p_tenant AND p.workload_id=request->>'workload_id' ORDER BY version DESC LIMIT 1;
 IF profile.id IS NOT NULL THEN
 IF octet_length(profile.document::text)>131072 OR profile.writer_role<>'finops_api' OR profile.document->>'id' IS DISTINCT FROM profile.id OR profile.document->>'workload_id' IS DISTINCT FROM request->>'workload_id' OR profile.document->'version' IS DISTINCT FROM to_jsonb(profile.version) THEN RAISE EXCEPTION 'optimization current safety policy differs';END IF;
 profile_value:=profile.document-ARRAY['tenant_id','hash','created_at','writer_role'];
 profile_ref:=jsonb_build_object('kind','WORKLOAD_SAFETY_PROFILE','id',profile.id,'sha256',public.fleet_history_json_hash(profile.document));refs:=refs||jsonb_build_array(profile_ref);
 END IF;
 SELECT * INTO objective FROM public.slo_objectives o WHERE o.tenant_id=p_tenant AND o.workload_id=request->>'workload_id' ORDER BY version DESC LIMIT 1;
 IF objective.id IS NOT NULL THEN
 IF octet_length(objective.document::text)>131072 OR objective.writer_role<>'finops_api' OR objective.document->>'id' IS DISTINCT FROM objective.id OR objective.document->>'workload_id' IS DISTINCT FROM request->>'workload_id' OR objective.document->'version' IS DISTINCT FROM to_jsonb(objective.version) THEN RAISE EXCEPTION 'optimization current SLO policy differs';END IF;
 objectives:=jsonb_build_array(jsonb_build_object('Objective',objective.document-ARRAY['tenant_id','hash','created_at','writer_role'],'Reference',jsonb_build_object('kind','SLO_OBJECTIVE','id',objective.id,'sha256',public.fleet_history_json_hash(objective.document))));refs:=refs||jsonb_build_array(objectives->0->'Reference');
 END IF;
 policy:=public.commitment_optimization_policy_inputs(p_tenant,p_request,p_scope);refs:=refs||coalesce(policy->'current_refs','[]'::jsonb);
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(refs) v GROUP BY v->>'kind',v->>'id' HAVING count(DISTINCT v->>'sha256')>1) THEN RAISE EXCEPTION 'optimization conflicting immutable proof';END IF;
 SELECT coalesce(jsonb_agg(v ORDER BY v->>'kind',v->>'id'),'[]') INTO refs FROM(SELECT DISTINCT v FROM jsonb_array_elements(refs) v) proofs;
 -- No existing producer proves an exhaustive sizing catalog or absence of
 -- EKS/ECS/other controllers. In particular an ASG point is never unmanaged.
 -- These typed gaps remain present until a separately authenticated issuer
 -- and exact SQL join are implemented. No current hardware row invents policy.
 -- The first analytical input read uses actual DB time. Once all four stages
 -- have been issued atomically, reuse that exact observed instant and require
 -- the complete retained set/current input hash rather than append on retry.
 SELECT count(*),min(e.document->'payload'->>'assessed_at'),min(e.document->'payload'->>'input_sha256') INTO retained_count,retained_stamp,retained_hash FROM public.entities e WHERE e.tenant_id=p_tenant AND e.kind='commitment_decision_evidence' AND e.document->>'kind'='OPTIMIZATION_DECISION' AND e.document->>'request_id'=p_request AND e.document->'payload'->>'stage' IN('REMOVE_IDLE','SCHEDULE','RIGHTSIZE','AUTOSCALE');
 IF retained_count>0 THEN
 IF retained_count<>4 THEN RAISE EXCEPTION 'optimization retained prefix incomplete';END IF;
 SELECT count(*) INTO retained_count FROM public.entities e WHERE e.tenant_id=p_tenant AND e.kind='commitment_decision_evidence' AND e.document->>'kind'='OPTIMIZATION_OUTCOME' AND e.document->>'request_id'=p_request AND e.document->'payload'->>'stage' IN('REMOVE_IDLE','SCHEDULE','RIGHTSIZE','AUTOSCALE');
 IF retained_count<>4 THEN RAISE EXCEPTION 'optimization retained prefix incomplete';END IF;
 FOREACH stage_name IN ARRAY ARRAY['REMOVE_IDLE','SCHEDULE','RIGHTSIZE','AUTOSCALE'] LOOP
 SELECT count(*) INTO retained_count FROM public.entities e WHERE e.tenant_id=p_tenant AND e.kind='commitment_decision_evidence' AND e.document->>'kind'='OPTIMIZATION_DECISION' AND e.document->>'request_id'=p_request AND e.document->'payload'->>'stage'=stage_name;
 IF retained_count<>1 THEN RAISE EXCEPTION 'optimization retained prefix incomplete';END IF;
 END LOOP;
 FOR proof IN SELECT e.document FROM public.entities e WHERE e.tenant_id=p_tenant AND e.kind='commitment_decision_evidence' AND e.document->>'kind'='OPTIMIZATION_DECISION' AND e.document->>'request_id'=p_request AND e.document->'payload'->>'stage' IN('REMOVE_IDLE','SCHEDULE','RIGHTSIZE','AUTOSCALE') LOOP
 IF proof.document->>'writer_role' IS DISTINCT FROM 'finops_commitment_portfolio' OR proof.document->>'scope_sha256' IS DISTINCT FROM p_scope->>'sha256' OR proof.document->>'payload_sha256' IS DISTINCT FROM public.fleet_history_json_hash(proof.document->'payload') OR proof.document->'payload'->>'assessed_at' IS DISTINCT FROM retained_stamp OR proof.document->'payload'->>'input_sha256' IS DISTINCT FROM retained_hash THEN RAISE EXCEPTION 'optimization retained prefix differs';END IF;
 SELECT count(*) INTO retained_count FROM public.entities e WHERE e.tenant_id=p_tenant AND e.kind='commitment_decision_evidence' AND e.document->>'kind'='OPTIMIZATION_OUTCOME' AND e.document->>'request_id'=p_request AND e.document->>'writer_role'='finops_commitment_portfolio' AND e.document->>'scope_sha256'=p_scope->>'sha256' AND e.document->'payload'->>'stage'=proof.document->'payload'->>'stage' AND e.document->'payload'->'assessment'->>'assessed_at'=retained_stamp AND e.document->'payload'->'decision_ref'=jsonb_build_object('kind','OPTIMIZATION_DECISION','id',proof.document->>'id','sha256',proof.document->>'payload_sha256') AND e.document->>'payload_sha256'=public.fleet_history_json_hash(e.document->'payload');
 IF retained_count<>1 THEN RAISE EXCEPTION 'optimization retained prefix incomplete';END IF;
 END LOOP;
 assessed_at:=retained_stamp;retained:=true;
 ELSE assessed_at:=rtrim(rtrim(to_char(clock_timestamp() AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US'),'0'),'.')||'Z';END IF;
 answer:=jsonb_build_object('Scope',p_scope,'Resources',resources,'Work','[]'::jsonb,'Objectives',objectives,'ScheduleActions','[]'::jsonb,'Sizing',policy->'sizing','Profile',profile_value,'ProfileReference',profile_ref,'Controllers',policy->'controllers','UnmanagedResourceIDs','[]'::jsonb,'ControllerDiscoveryRef',policy->'controller_discovery_ref','ControllerScopeReference',policy->'controller_scope_reference','CurrentRefs',refs,'AssessedAt',assessed_at);
 IF octet_length(answer::text)>33554432 THEN RAISE EXCEPTION 'optimization input byte limit';END IF;
 IF retained AND public.fleet_history_json_hash(answer) IS DISTINCT FROM retained_hash THEN RAISE EXCEPTION 'optimization retained inputs changed';END IF;
 RETURN jsonb_build_object('request',request,'inputs',answer,'retained',retained);
END $$;
REVOKE ALL ON FUNCTION commitment_optimization_stage_context(text,text,jsonb) FROM PUBLIC;

CREATE FUNCTION commitment_optimization_stage_inputs(p_tenant text,p_request text,p_scope jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
BEGIN
 PERFORM public.commitment_ownership_machine(p_tenant);
 IF EXISTS(SELECT 1 FROM public.commitment_decision_results r WHERE r.tenant_id=p_tenant AND r.request_id=p_request) THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='optimization preparation is terminal';END IF;
 RETURN public.commitment_optimization_stage_context(p_tenant,p_request,p_scope)->'inputs';END $$;
REVOKE ALL ON FUNCTION commitment_optimization_stage_inputs(text,text,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION commitment_optimization_stage_inputs(text,text,jsonb) TO finops_commitment_portfolio;

CREATE FUNCTION commitment_optimization_prefix_publish(p_tenant text,p_request text,p_input_hash text,p_values jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE context jsonb;inputs jsonb;request jsonb;item jsonb;stage text;expected_disposition text;expected_reasons jsonb;expected_refs jsonb;verdict jsonb;
 stages text[]:=ARRAY['REMOVE_IDLE','SCHEDULE','RIGHTSIZE','AUTOSCALE'];i integer;record_kind text;payload jsonb;envelope jsonb;
 decision jsonb;outcome jsonb;decision_ref jsonb;outcome_ref jsonb;result jsonb:='[]';stamp timestamptz;
BEGIN
 PERFORM public.commitment_ownership_machine(p_tenant);
 IF EXISTS(SELECT 1 FROM public.commitment_decision_results r WHERE r.tenant_id=p_tenant AND r.request_id=p_request) THEN RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='optimization preparation is terminal';END IF;
 IF coalesce(p_input_hash,'')!~'^[a-f0-9]{64}$' OR octet_length(p_values::text)>262144 OR NOT public.commitment_portfolio_keys(p_values,ARRAY['scope','outcomes']) OR jsonb_typeof(p_values->'outcomes') IS DISTINCT FROM 'array' OR jsonb_array_length(p_values->'outcomes')<>4 THEN RAISE EXCEPTION 'optimization publisher body differs';END IF;
 -- A new READ COMMITTED statement under the retained graph/source/key and
 -- credential fences, not a caller's earlier input document or observations.
 context:=public.commitment_optimization_stage_context(p_tenant,p_request,p_values->'scope');inputs:=context->'inputs';request:=context->'request';
 IF context->'retained'='false'::jsonb THEN
 IF jsonb_typeof(p_values->'outcomes'->0->'assessed_at') IS DISTINCT FROM 'string' THEN RAISE EXCEPTION 'optimization initial assessment timestamp required';END IF;
 stamp:=(p_values->'outcomes'->0->>'assessed_at')::timestamptz;
 IF stamp<(request->>'created_at')::timestamptz OR stamp>clock_timestamp() OR stamp<clock_timestamp()-interval '5 minutes' THEN RAISE EXCEPTION 'optimization initial assessment timestamp differs';END IF;
 -- Only this already-observed instant may differ between the initial read
 -- and publication. Every selected fact/policy/ref above was freshly read.
 inputs:=inputs||jsonb_build_object('AssessedAt',p_values->'outcomes'->0->'assessed_at');
 END IF;
 IF public.fleet_history_json_hash(inputs) IS DISTINCT FROM p_input_hash THEN RAISE EXCEPTION 'optimization selected inputs changed';END IF;
 FOR i IN 1..4 LOOP
 stage:=stages[i];item:=p_values->'outcomes'->(i-1);
 IF NOT public.commitment_portfolio_keys(item,ARRAY['schema_version','id','request_id','stage','scope_sha256','disposition','input_refs','reason_codes','original_action_completed_at','assessed_at','execution_authorized','verified_saving']) OR item->>'schema_version' IS DISTINCT FROM '1' OR item->>'request_id' IS DISTINCT FROM p_request OR item->>'stage' IS DISTINCT FROM stage OR item->>'scope_sha256' IS DISTINCT FROM inputs->'Scope'->>'sha256' OR item->>'id' IS DISTINCT FROM public.fleet_history_json_hash(item||'{"id":""}') OR item->'execution_authorized' IS DISTINCT FROM 'false'::jsonb OR item->'verified_saving' IS DISTINCT FROM 'null'::jsonb OR item->'original_action_completed_at' IS DISTINCT FROM 'null'::jsonb OR jsonb_typeof(item->'assessed_at') IS DISTINCT FROM 'string' OR NOT public.commitment_portfolio_strings(item->'reason_codes',128) OR jsonb_typeof(item->'input_refs') IS DISTINCT FROM 'array' THEN RAISE EXCEPTION 'optimization factory outcome differs';END IF;
 stamp:=(item->>'assessed_at')::timestamptz;
 IF item->'assessed_at' IS DISTINCT FROM inputs->'AssessedAt' THEN RAISE EXCEPTION 'optimization stable assessment timestamp differs';END IF;
 expected_disposition:='UNAVAILABLE';expected_refs:='[]';
 IF stage='REMOVE_IDLE' THEN
 expected_reasons:='["REMOVE_IDLE_COMPLETE_BUSINESS_WORK_HISTORY_UNAVAILABLE"]';
 IF inputs->'Profile'<>'null'::jsonb AND jsonb_typeof(inputs->'Profile'->'min_replicas')='number' AND inputs->'Profile'->'min_replicas'=to_jsonb(jsonb_array_length(inputs->'Scope'->'resource_ids')) THEN expected_disposition:='EVIDENCED_NO_CHANGE';expected_reasons:='["OWNER_REQUIRED_REPLICA_FLOOR_FORBIDS_RESOURCE_REMOVAL"]';expected_refs:=jsonb_build_array(inputs->'ProfileReference');END IF;
 ELSIF stage='SCHEDULE' THEN
 expected_reasons:='["SCHEDULE_SCOPED_COMPLETED_OUTCOME_UNAVAILABLE"]';
 IF jsonb_array_length(inputs->'Objectives')=1 THEN expected_refs:=jsonb_build_array(inputs->'Objectives'->0->'Reference');IF inputs->'Objectives'->0->'Objective'->'availability'->>'mode'='ALWAYS' THEN expected_disposition:='EVIDENCED_NO_CHANGE';expected_reasons:='["CURRENT_SLO_REQUIRES_CONTINUOUS_AVAILABILITY"]';END IF;END IF;
 ELSE verdict:=public.commitment_optimization_policy_stage(p_tenant,p_request,p_values->'scope',stage);expected_disposition:=verdict->>'disposition';expected_reasons:=verdict->'reason_codes';expected_refs:=verdict->'input_refs';END IF;
 IF item->>'disposition' IS DISTINCT FROM expected_disposition OR item->'reason_codes' IS DISTINCT FROM expected_reasons OR item->'input_refs' IS DISTINCT FROM expected_refs THEN RAISE EXCEPTION 'optimization disposition lacks its selected producer';END IF;
 decision:=jsonb_build_object('schema_version','1','id','','request_id',p_request,'stage',stage,'scope_sha256',item->>'scope_sha256','input_sha256',p_input_hash,'input_refs',expected_refs,'assessed_at',item->'assessed_at','execution_authorized',false,'verified_saving',NULL);
 decision:=decision||jsonb_build_object('id',public.fleet_history_json_hash(decision));decision_ref:=jsonb_build_object('kind','OPTIMIZATION_DECISION','id',decision->>'id','sha256',public.fleet_history_json_hash(decision));
 outcome:=jsonb_build_object('schema_version','1','id','','request_id',p_request,'stage',stage,'scope_sha256',item->>'scope_sha256','decision_ref',decision_ref,'assessment',item,'execution_authorized',false,'verified_saving',NULL);
 outcome:=outcome||jsonb_build_object('id',public.fleet_history_json_hash(outcome));outcome_ref:=jsonb_build_object('kind','OPTIMIZATION_OUTCOME','id',outcome->>'id','sha256',public.fleet_history_json_hash(outcome));
 FOREACH record_kind IN ARRAY ARRAY['OPTIMIZATION_DECISION','OPTIMIZATION_OUTCOME'] LOOP
 payload:=CASE record_kind WHEN 'OPTIMIZATION_DECISION' THEN decision ELSE outcome END;
 envelope:=jsonb_build_object('id',payload->>'id','kind',record_kind,'request_id',p_request,'workload_id',request->>'workload_id','selection',request->'selection','base_sha256',request->>'input_sha256','scope_sha256',item->>'scope_sha256','payload',payload,'payload_sha256',public.fleet_history_json_hash(payload),'calibration_ref',NULL,'writer_role','finops_commitment_portfolio');
 INSERT INTO public.entities(tenant_id,kind,id,document) VALUES(p_tenant,'commitment_decision_evidence',payload->>'id',envelope) ON CONFLICT(tenant_id,kind,id) DO NOTHING;
 IF NOT EXISTS(SELECT 1 FROM public.entities e WHERE e.tenant_id=p_tenant AND e.kind='commitment_decision_evidence' AND e.id=payload->>'id' AND e.document=envelope) THEN RAISE EXCEPTION 'optimization immutable publication differs';END IF;
 END LOOP;
 result:=result||jsonb_build_array(jsonb_build_object('stage',stage,'disposition',expected_disposition,'decision_ref',decision_ref,'outcome_ref',outcome_ref,'scope_sha256',item->>'scope_sha256','completed_at',item->'assessed_at','reason_codes',expected_reasons));
 END LOOP;
 RETURN result;
END $$;
REVOKE ALL ON FUNCTION commitment_optimization_prefix_publish(text,text,text,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION commitment_optimization_prefix_publish(text,text,text,jsonb) TO finops_commitment_portfolio;

-- Internal to the owner-defined preparation/final-result publishers. The
-- analytical login has no EXECUTE grant and cannot replace this with a list of
-- arbitrary extra references. Historical rows stay immutable when inputs move.
CREATE FUNCTION commitment_optimization_prefix_current(p_tenant text,p_request text,p_scope jsonb,p_order jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE context jsonb;inputs jsonb;request jsonb;input_hash text;stage jsonb;decision jsonb;outcome jsonb;assessment jsonb;
 decision_payload jsonb;outcome_payload jsonb;refs jsonb;stages text[]:=ARRAY['REMOVE_IDLE','SCHEDULE','RIGHTSIZE','AUTOSCALE'];i integer;
BEGIN
 IF jsonb_typeof(p_order) IS DISTINCT FROM 'array' OR jsonb_array_length(p_order)<>4 OR octet_length(p_order::text)>131072 THEN RAISE EXCEPTION 'optimization exact issued prefix required';END IF;
 context:=public.commitment_optimization_stage_context(p_tenant,p_request,p_scope);inputs:=context->'inputs';request:=context->'request';input_hash:=public.fleet_history_json_hash(inputs);refs:=inputs->'CurrentRefs';
 FOR i IN 1..4 LOOP
 stage:=p_order->(i-1);
 IF NOT public.commitment_portfolio_keys(stage,ARRAY['stage','disposition','decision_ref','outcome_ref','scope_sha256','completed_at','reason_codes']) OR stage->>'stage' IS DISTINCT FROM stages[i] OR stage->>'scope_sha256' IS DISTINCT FROM p_scope->>'sha256' OR NOT public.commitment_portfolio_keys(stage->'decision_ref',ARRAY['kind','id','sha256']) OR NOT public.commitment_portfolio_keys(stage->'outcome_ref',ARRAY['kind','id','sha256']) OR stage->'decision_ref'->>'kind' IS DISTINCT FROM 'OPTIMIZATION_DECISION' OR stage->'outcome_ref'->>'kind' IS DISTINCT FROM 'OPTIMIZATION_OUTCOME' OR coalesce(stage->'decision_ref'->>'id','')!~'^[a-f0-9]{64}$' OR coalesce(stage->'outcome_ref'->>'id','')!~'^[a-f0-9]{64}$' THEN RAISE EXCEPTION 'optimization exact issued prefix differs';END IF;
 SELECT e.document INTO decision FROM public.entities e WHERE e.tenant_id=p_tenant AND e.kind='commitment_decision_evidence' AND e.id=stage->'decision_ref'->>'id';
 SELECT e.document INTO outcome FROM public.entities e WHERE e.tenant_id=p_tenant AND e.kind='commitment_decision_evidence' AND e.id=stage->'outcome_ref'->>'id';
 IF decision IS NULL OR outcome IS NULL OR decision->>'kind' IS DISTINCT FROM 'OPTIMIZATION_DECISION' OR outcome->>'kind' IS DISTINCT FROM 'OPTIMIZATION_OUTCOME' OR decision->>'writer_role' IS DISTINCT FROM 'finops_commitment_portfolio' OR outcome->>'writer_role' IS DISTINCT FROM 'finops_commitment_portfolio' OR decision->>'id' IS DISTINCT FROM stage->'decision_ref'->>'id' OR outcome->>'id' IS DISTINCT FROM stage->'outcome_ref'->>'id' OR decision->>'request_id' IS DISTINCT FROM p_request OR outcome->>'request_id' IS DISTINCT FROM p_request OR decision->>'workload_id' IS DISTINCT FROM request->>'workload_id' OR outcome->>'workload_id' IS DISTINCT FROM request->>'workload_id' OR decision->'selection' IS DISTINCT FROM request->'selection' OR outcome->'selection' IS DISTINCT FROM request->'selection' OR decision->>'base_sha256' IS DISTINCT FROM request->>'input_sha256' OR outcome->>'base_sha256' IS DISTINCT FROM request->>'input_sha256' OR decision->>'scope_sha256' IS DISTINCT FROM p_scope->>'sha256' OR outcome->>'scope_sha256' IS DISTINCT FROM p_scope->>'sha256' THEN RAISE EXCEPTION 'optimization issued row closure differs';END IF;
 decision_payload:=decision->'payload';outcome_payload:=outcome->'payload';assessment:=outcome_payload->'assessment';
 IF decision->>'payload_sha256' IS DISTINCT FROM public.fleet_history_json_hash(decision_payload) OR outcome->>'payload_sha256' IS DISTINCT FROM public.fleet_history_json_hash(outcome_payload) OR decision->>'payload_sha256' IS DISTINCT FROM stage->'decision_ref'->>'sha256' OR outcome->>'payload_sha256' IS DISTINCT FROM stage->'outcome_ref'->>'sha256' OR decision_payload->>'id' IS DISTINCT FROM decision->>'id' OR outcome_payload->>'id' IS DISTINCT FROM outcome->>'id' OR decision_payload->>'id' IS DISTINCT FROM public.fleet_history_json_hash(decision_payload||'{"id":""}') OR outcome_payload->>'id' IS DISTINCT FROM public.fleet_history_json_hash(outcome_payload||'{"id":""}') OR decision_payload->>'input_sha256' IS DISTINCT FROM input_hash OR decision_payload->>'request_id' IS DISTINCT FROM p_request OR outcome_payload->>'request_id' IS DISTINCT FROM p_request OR decision_payload->>'stage' IS DISTINCT FROM stages[i] OR outcome_payload->>'stage' IS DISTINCT FROM stages[i] OR decision_payload->>'scope_sha256' IS DISTINCT FROM p_scope->>'sha256' OR outcome_payload->>'scope_sha256' IS DISTINCT FROM p_scope->>'sha256' OR outcome_payload->'decision_ref' IS DISTINCT FROM stage->'decision_ref' THEN RAISE EXCEPTION 'optimization issued payload hash differs';END IF;
 IF assessment->>'id' IS DISTINCT FROM public.fleet_history_json_hash(assessment||'{"id":""}') OR assessment->>'request_id' IS DISTINCT FROM p_request OR assessment->>'stage' IS DISTINCT FROM stages[i] OR assessment->>'scope_sha256' IS DISTINCT FROM p_scope->>'sha256' OR assessment->>'disposition' IS DISTINCT FROM stage->>'disposition' OR assessment->'assessed_at' IS DISTINCT FROM inputs->'AssessedAt' OR assessment->'assessed_at' IS DISTINCT FROM stage->'completed_at' OR assessment->'reason_codes' IS DISTINCT FROM stage->'reason_codes' OR assessment->'input_refs' IS DISTINCT FROM decision_payload->'input_refs' OR decision_payload->'assessed_at' IS DISTINCT FROM inputs->'AssessedAt' OR assessment->'execution_authorized' IS DISTINCT FROM 'false'::jsonb OR assessment->'verified_saving' IS DISTINCT FROM 'null'::jsonb OR decision_payload->'execution_authorized' IS DISTINCT FROM 'false'::jsonb OR decision_payload->'verified_saving' IS DISTINCT FROM 'null'::jsonb OR outcome_payload->'execution_authorized' IS DISTINCT FROM 'false'::jsonb OR outcome_payload->'verified_saving' IS DISTINCT FROM 'null'::jsonb THEN RAISE EXCEPTION 'optimization issued disposition differs';END IF;
 refs:=refs||jsonb_build_array(stage->'decision_ref',stage->'outcome_ref')||decision_payload->'input_refs';
 END LOOP;
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(refs) v GROUP BY v->>'kind',v->>'id' HAVING count(DISTINCT v->>'sha256')>1) THEN RAISE EXCEPTION 'optimization conflicting issued references';END IF;
 SELECT coalesce(jsonb_agg(v ORDER BY v->>'kind',v->>'id'),'[]') INTO refs FROM(SELECT DISTINCT v FROM jsonb_array_elements(refs) v) proofs;
 RETURN refs;
END $$;
REVOKE ALL ON FUNCTION commitment_optimization_prefix_current(text,text,jsonb,jsonb) FROM PUBLIC;


-- CONNECTED ADDITIVE040: migrations/040_stage_policy_extension.sql.fragment
-- Private copied037 resolver. Only name/admission differ; original037 is untouched.
-- No role impersonation, public/API EXECUTE grant or source privilege expansion.
CREATE FUNCTION commitment_optimization_joint_inputs(p_tenant text,p_assessment text,p_capacity text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE who text:=coalesce(nullif(current_setting('role',true),'none'),session_user);
 ar public.fleet_native_assessment_requests%ROWTYPE;cr public.fleet_native_capacity_requests%ROWTYPE;
 a public.fleet_native_assessments%ROWTYPE;s public.fleet_native_capacity_scopes%ROWTYPE;b public.fleet_native_capacity_batches%ROWTYPE;
 profile public.workload_safety_profiles%ROWTYPE;binding jsonb;members jsonb;member jsonb;pin jsonb;
 actual text[];claimed text[];n bigint;size bigint;refs jsonb;baseline_ref jsonb;
BEGIN
 IF NOT public.commitment_portfolio_access(p_tenant) OR current_setting('transaction_isolation') IS DISTINCT FROM 'read committed' OR p_tenant IS NULL OR p_tenant='' OR p_tenant IS DISTINCT FROM current_setting('app.tenant_id',true) THEN RAISE EXCEPTION 'joint decision reader scope differs';END IF;
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
REVOKE ALL ON FUNCTION commitment_optimization_joint_inputs(text,text,text) FROM PUBLIC;

-- An actual customer business/configuration constraint must be approved before
-- the private operator installs it. It is not a native observation, purchase
-- approval, public request, or a list inferred from completed candidates.
CREATE TABLE commitment_optimization_policies(
 tenant_id text NOT NULL,id text NOT NULL,revision bigint NOT NULL CHECK(revision>0),workload_id text NOT NULL,
 document jsonb NOT NULL,registry_actor name NOT NULL DEFAULT session_user,operator_recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,id,revision),UNIQUE(tenant_id,workload_id,revision),CHECK(octet_length(document::text)<=65536)
);
CREATE TABLE commitment_optimization_policy_revocations(
 tenant_id text NOT NULL,id text NOT NULL,revision bigint NOT NULL,reason_code text NOT NULL,
 registry_actor name NOT NULL DEFAULT session_user,operator_recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,id,revision),FOREIGN KEY(tenant_id,id,revision) REFERENCES commitment_optimization_policies(tenant_id,id,revision)
);
DO $$ DECLARE tab text;BEGIN
 FOREACH tab IN ARRAY ARRAY['commitment_optimization_policies','commitment_optimization_policy_revocations'] LOOP
 EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',tab);EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',tab);
 EXECUTE format('CREATE POLICY operator_scope ON %I TO %I USING(true) WITH CHECK(true)',tab,current_user);
 EXECUTE format('CREATE TRIGGER immutable BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION public.deny_evidence_mutation()',tab);
 END LOOP;
END $$;
REVOKE ALL ON commitment_optimization_policies,commitment_optimization_policy_revocations FROM PUBLIC,finops_api,finops_commitment_portfolio,finops_ingester,finops_group_decision;

CREATE FUNCTION guard_commitment_optimization_policy() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE workload text;candidate jsonb;last_type text:='';native_ids jsonb;BEGIN
 IF TG_TABLE_NAME='commitment_optimization_policy_revocations' THEN
 SELECT p.workload_id INTO workload FROM public.commitment_optimization_policies p WHERE(p.tenant_id,p.id,p.revision)=(NEW.tenant_id,NEW.id,NEW.revision);
 IF workload IS NULL OR coalesce(NEW.reason_code,'')!~'^[A-Z][A-Z0-9_]{0,127}$' THEN RAISE EXCEPTION 'optimization policy revocation differs';END IF;
 ELSE
 workload:=NEW.workload_id;
 IF NOT public.commitment_portfolio_keys(NEW.document,ARRAY['schema_version','id','revision','purpose','basis','tenant_id','workload_id','ownership_scope_sha256','configuration_sha256','resource_ids','source_id','old_proposal_id','asg_arn','account_id','region','allowed_candidates','size_constraint_basis','controller_scope','customer_approval_id','customer_approval_issuer','customer_approval_subject','valid_until','execution_authorized']) OR NEW.document->>'schema_version' IS DISTINCT FROM '1' OR NEW.document->>'id' IS DISTINCT FROM NEW.id OR NEW.document->'revision' IS DISTINCT FROM to_jsonb(NEW.revision) OR NEW.document->>'tenant_id' IS DISTINCT FROM NEW.tenant_id OR NEW.document->>'workload_id' IS DISTINCT FROM workload OR NEW.document->>'purpose' IS DISTINCT FROM 'CUSTOMER_WORKLOAD_OPTIMIZATION_CONSTRAINT' OR NEW.document->>'basis' IS DISTINCT FROM 'CUSTOMER_APPROVED_SIZE_ALLOWLIST_AND_CONFIGURATION_CONTROLLER_SCOPE' OR NEW.document->'execution_authorized' IS DISTINCT FROM 'false'::jsonb OR coalesce(NEW.document->>'ownership_scope_sha256','')!~'^[a-f0-9]{64}$' OR coalesce(NEW.document->>'configuration_sha256','')!~'^[a-f0-9]{64}$' OR NOT public.commitment_portfolio_strings(NEW.document->'resource_ids',128) OR jsonb_array_length(NEW.document->'resource_ids')<1 OR coalesce(NEW.document->>'account_id','')!~'^[0-9]{12}$' OR NEW.document->>'region' IS DISTINCT FROM 'eu-west-1' OR coalesce(NEW.document->>'asg_arn','')!~('^arn:aws:autoscaling:eu-west-1:'||(NEW.document->>'account_id')||':autoScalingGroup:[a-f0-9-]{36}:autoScalingGroupName/[^*?]+$') OR coalesce(NEW.document->>'controller_scope','') NOT IN('UNAVAILABLE','CUSTOMER_REVIEWED_CONFIGURATION_ASG_ONLY') OR coalesce(NEW.document->>'customer_approval_id','')='' OR length(NEW.document->>'customer_approval_id')>200 OR coalesce(NEW.document->>'customer_approval_issuer','')='' OR length(NEW.document->>'customer_approval_issuer')>2048 OR coalesce(NEW.document->>'customer_approval_subject','')='' OR length(NEW.document->>'customer_approval_subject')>256 OR jsonb_typeof(NEW.document->'valid_until') IS DISTINCT FROM 'string' OR (NEW.document->>'valid_until')::timestamptz<=clock_timestamp() OR jsonb_typeof(NEW.document->'allowed_candidates') IS DISTINCT FROM 'array' OR jsonb_array_length(NEW.document->'allowed_candidates') NOT BETWEEN 1 AND 8 THEN RAISE EXCEPTION 'optimization customer policy differs';END IF;
 SELECT jsonb_agg(to_jsonb(v) ORDER BY v) INTO native_ids FROM(SELECT DISTINCT v FROM jsonb_array_elements_text(NEW.document->'resource_ids') v) ids;
 IF native_ids IS DISTINCT FROM NEW.document->'resource_ids' THEN RAISE EXCEPTION 'optimization exact resource roster required';END IF;
 IF coalesce(NEW.document->>'size_constraint_basis','') NOT IN('CUSTOMER_APPROVED_EXHAUSTIVE_CATALOG','BUSINESS_OR_LICENSE_RESTRICTION') OR jsonb_array_length(NEW.document->'allowed_candidates')=1 AND NEW.document->>'size_constraint_basis' IS DISTINCT FROM 'BUSINESS_OR_LICENSE_RESTRICTION' THEN RAISE EXCEPTION 'optimization explicit business or exhaustive catalog constraint required';END IF;
 FOR candidate IN SELECT value FROM jsonb_array_elements(NEW.document->'allowed_candidates') LOOP
 IF NOT public.commitment_portfolio_keys(candidate,ARRAY['instance_type','proposal_id','template_id','template_version','image_id']) OR coalesce(candidate->>'instance_type','')!~'^[a-z0-9][a-z0-9-]*[.][a-z0-9]+$' OR candidate->>'instance_type'<=last_type OR coalesce(candidate->>'proposal_id','')!~'^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$' OR coalesce(candidate->>'template_id','')!~'^lt-([a-f0-9]{8}|[a-f0-9]{17})$' OR coalesce(candidate->>'template_version','')!~'^[1-9][0-9]{0,19}$' OR coalesce(candidate->>'image_id','')!~'^ami-([a-f0-9]{8}|[a-f0-9]{17})$' THEN RAISE EXCEPTION 'optimization exhaustive allowed candidate pins required';END IF;
 last_type:=candidate->>'instance_type';
 END LOOP;
 END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id||':dependency-graph',0));
 PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id||':commitment-optimization-policy:'||workload,0));
 NEW.registry_actor:=session_user;NEW.operator_recorded_at:=clock_timestamp();RETURN NEW;
END $$;
CREATE TRIGGER policy_install BEFORE INSERT ON commitment_optimization_policies FOR EACH ROW EXECUTE FUNCTION guard_commitment_optimization_policy();
CREATE TRIGGER policy_revoke BEFORE INSERT ON commitment_optimization_policy_revocations FOR EACH ROW EXECUTE FUNCTION guard_commitment_optimization_policy();
REVOKE ALL ON FUNCTION guard_commitment_optimization_policy() FROM PUBLIC;

CREATE FUNCTION commitment_optimization_policy_inputs(p_tenant text,p_request text,p_scope jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE request jsonb;base jsonb;ownership jsonb;policy public.commitment_optimization_policies%ROWTYPE;p jsonb;policy_ref jsonb;
 candidate jsonb;joint record;input jsonb;template jsonb;joins jsonb:='[]';types jsonb:='[]';current_types jsonb:='{}';hardware_ids jsonb:='{}';member jsonb;hardware public.source_receipts%ROWTYPE;
 estimate bigint;total_bytes bigint:=0;sizing jsonb:=NULL;sizing_gap boolean:=false;controllers jsonb:='[]';controller_ref jsonb:=NULL;scope_ref jsonb:=NULL;receipt public.source_receipts%ROWTYPE;revision public.source_revisions%ROWTYPE;
 native jsonb;group_record jsonb;members jsonb;refs jsonb:='[]';reasons jsonb:='[]';source_key text;
BEGIN
 IF NOT public.commitment_portfolio_access(p_tenant) OR current_setting('transaction_isolation') IS DISTINCT FROM 'read committed' OR p_tenant IS DISTINCT FROM current_setting('app.tenant_id',true) THEN RAISE EXCEPTION 'optimization policy reader scope differs';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(p_tenant||':dependency-graph',0));
 request:=public.commitment_decision_request(p_tenant,p_request);
 IF request->>'purpose' IS DISTINCT FROM 'PREPARE' OR p_scope->>'tenant_id' IS DISTINCT FROM p_tenant OR p_scope->>'workload_id' IS DISTINCT FROM request->>'workload_id' OR p_scope->>'sha256' IS DISTINCT FROM public.fleet_history_json_hash(p_scope||'{"sha256":""}') THEN RAISE EXCEPTION 'optimization policy exact preparation required';END IF;
 base:=public.commitment_decision_base(p_tenant,request->>'workload_id',request->'selection');
 IF public.fleet_history_json_hash(base) IS DISTINCT FROM request->>'input_sha256' THEN RAISE EXCEPTION 'optimization current inputs changed';END IF;
 ownership:=public.commitment_decision_ownership_assert(p_tenant,request->>'workload_id',p_scope->'ownership_ref',(p_scope->'history_period'->>'start')::timestamptz,(p_scope->'history_period'->>'end')::timestamptz);
 PERFORM pg_advisory_xact_lock_shared(hashtextextended(p_tenant||':commitment-optimization-policy:'||(request->>'workload_id'),0));
 SELECT * INTO policy FROM public.commitment_optimization_policies p WHERE p.tenant_id=p_tenant AND p.workload_id=request->>'workload_id' ORDER BY p.revision DESC LIMIT 1;
 IF policy.id IS NULL OR EXISTS(SELECT 1 FROM public.commitment_optimization_policy_revocations r WHERE(r.tenant_id,r.id,r.revision)=(policy.tenant_id,policy.id,policy.revision)) OR (policy.document->>'valid_until')::timestamptz<=clock_timestamp() THEN RETURN jsonb_build_object('policy',NULL,'policy_ref',NULL,'registry_actor','','sizing',NULL,'controllers','[]'::jsonb,'controller_discovery_ref',NULL,'controller_scope_reference',NULL,'current_refs','[]'::jsonb,'reason_codes',jsonb_build_array('CUSTOMER_APPROVED_OPTIMIZATION_POLICY_UNAVAILABLE'));END IF;
 p:=policy.document;
 IF p->>'ownership_scope_sha256' IS DISTINCT FROM public.fleet_history_json_hash(ownership->'scope') OR p->>'configuration_sha256' IS DISTINCT FROM p_scope->>'configuration_sha256' OR p->'resource_ids' IS DISTINCT FROM p_scope->'resource_ids' OR p->>'source_id' IS DISTINCT FROM base->'portfolio'->'selection'->>'source_id' THEN RAISE EXCEPTION 'optimization customer policy current scope differs';END IF;
 source_key:=p->>'source_id';
 policy_ref:=jsonb_build_object('kind','WORKLOAD_SIZE_CONSTRAINT','id',policy.id,'sha256',public.fleet_history_json_hash(p||jsonb_build_object('registry_actor',policy.registry_actor,'operator_recorded_at',policy.operator_recorded_at)));
 refs:=jsonb_build_array(policy_ref);
 FOR candidate IN SELECT value FROM jsonb_array_elements(p->'allowed_candidates') LOOP
 types:=types||jsonb_build_array(candidate->>'instance_type');
 SELECT r.id,r.assessment_request_id,r.capacity_request_id,d.document,d.content_hash INTO joint FROM public.fleet_joint_decision_requests r JOIN public.fleet_joint_decisions d ON d.tenant_id=r.tenant_id AND d.request_id=r.id WHERE r.tenant_id=p_tenant AND r.workload_id=request->>'workload_id' AND r.document->'selection'->'groups'->'old_configuration_proposal'->>'id'=p->>'old_proposal_id' AND r.document->'selection'->'groups'->'candidate_configuration_proposal'->>'id'=candidate->>'proposal_id' ORDER BY d.created_at DESC,d.id DESC LIMIT 1;
 IF joint.id IS NULL THEN sizing_gap:=true;CONTINUE;END IF;
 SELECT coalesce(sum(octet_length(m.raw_document)),0)+(SELECT coalesce(octet_length(a.raw_document),0) FROM public.fleet_native_assessments a WHERE a.tenant_id=p_tenant AND a.request_id=joint.assessment_request_id)+(SELECT coalesce(octet_length(s.raw_document),0) FROM public.fleet_native_capacity_scopes s WHERE s.tenant_id=p_tenant AND s.request_id=joint.capacity_request_id)+(SELECT coalesce(octet_length(b.raw_document),0) FROM public.fleet_native_capacity_batches b WHERE b.tenant_id=p_tenant AND b.request_id=joint.capacity_request_id) INTO estimate FROM public.fleet_native_capacity_members m WHERE m.tenant_id=p_tenant AND m.request_id=joint.capacity_request_id;
 IF estimate IS NULL OR estimate>8388608 OR total_bytes+estimate>33554432 THEN RAISE EXCEPTION 'optimization candidate input byte limit';END IF;total_bytes:=total_bytes+estimate;
 BEGIN input:=public.commitment_optimization_joint_inputs(p_tenant,joint.assessment_request_id,joint.capacity_request_id)||jsonb_build_object('request_id',joint.id);EXCEPTION WHEN raise_exception THEN sizing_gap:=true;CONTINUE;END;
 template:=input->'scope'->'candidate_template';
 IF template IS NULL OR template='null'::jsonb OR template->>'instance_type' IS DISTINCT FROM candidate->>'instance_type' OR template->>'id' IS DISTINCT FROM candidate->>'template_id' OR template->>'version' IS DISTINCT FROM candidate->>'template_version' OR template->>'image_id' IS DISTINCT FROM candidate->>'image_id' OR input->'scope'->'scope'->'current_member_ids' IS DISTINCT FROM p_scope->'resource_ids' OR input->'scope'->'scope'->'selection'->'groups'->'binding'->'old'->'target'->>'asg_arn' IS DISTINCT FROM p->>'asg_arn' THEN sizing_gap:=true;CONTINUE;END IF;
 FOR member IN SELECT value->'document' FROM jsonb_array_elements(input->'members') LOOP
 SELECT * INTO hardware FROM public.source_receipts h WHERE h.tenant_id=p_tenant AND h.id=member->'hardware'->>'receipt_id' AND h.kind='AWS_EC2_HARDWARE' AND h.writer_role='finops_ingester' AND h.source_id=source_key;
 IF hardware.id IS NULL OR hardware.document->'native'->'instance'->>'id' IS DISTINCT FROM member->>'instance_id' OR hardware.document->'native'->>'account_id' IS DISTINCT FROM p->>'account_id' OR hardware.document->'native'->>'region' IS DISTINCT FROM p->>'region' OR coalesce(hardware.document->'native'->'instance'->>'instance_type','')='' THEN sizing_gap:=true;EXIT;END IF;
 IF hardware_ids ? (member->>'instance_id') AND hardware_ids->>(member->>'instance_id') IS DISTINCT FROM hardware.id THEN sizing_gap:=true;EXIT;END IF;
 hardware_ids:=hardware_ids||jsonb_build_object(member->>'instance_id',hardware.id);current_types:=current_types||jsonb_build_object(member->>'instance_id',hardware.document->'native'->'instance'->>'instance_type');
 END LOOP;
 joins:=joins||jsonb_build_array(jsonb_build_object('Input',input,'Reference',jsonb_build_object('kind','FLEET_JOINT_DECISION','id',joint.id,'sha256',joint.content_hash),'ObservedAt',joint.document->'observed_at'));
 END LOOP;
 IF sizing_gap OR jsonb_array_length(joins) IS DISTINCT FROM jsonb_array_length(types) OR (SELECT count(*) FROM jsonb_object_keys(current_types)) IS DISTINCT FROM jsonb_array_length(p_scope->'resource_ids') OR EXISTS(SELECT 1 FROM jsonb_each_text(current_types) t WHERE NOT(types ? t.value)) THEN reasons:=reasons||jsonb_build_array('RIGHTSIZE_CURRENT_PASS_AND_ALL_APPROVED_ALTERNATIVES_UNAVAILABLE');ELSE sizing:=jsonb_build_object('Reference',policy_ref,'ConfigurationSHA256',p_scope->>'configuration_sha256','AllowedInstanceTypes',types,'CurrentInstanceTypes',current_types,'Joins',joins);END IF;
 -- Positive native association for the entire scope is mandatory. An absent
 -- ASG row never implies unmanaged, and customer scope remains a separate ref.
 IF p->>'controller_scope'='CUSTOMER_REVIEWED_CONFIGURATION_ASG_ONLY' THEN
 SELECT * INTO receipt FROM public.source_receipts r WHERE r.tenant_id=p_tenant AND r.source_id=source_key AND r.kind='AWS_CONTROLLER_DISCOVERY' AND r.document->'binding'->>'workload_id'=request->>'workload_id' ORDER BY (r.document->>'collected_at')::timestamptz DESC,r.created_at DESC,r.id DESC LIMIT 1;
 IF receipt.id IS NOT NULL THEN
 SELECT * INTO revision FROM public.source_revisions r WHERE r.tenant_id=p_tenant AND r.id=receipt.revision_id;
 native:=receipt.document->'native';
 IF native->>'schema_version'='1' AND native->>'provider'='AWS' AND native->>'observation_basis'='BOUNDED_NON_ATOMIC_ASG_POINT_READ' AND receipt.document->'binding' IS NOT DISTINCT FROM jsonb_build_object('tenant_id',p_tenant,'workload_id',request->>'workload_id','provider','AWS','account_id',p->>'account_id','region',p->>'region') AND receipt.document->>'source_id'=source_key AND receipt.document->>'revision_id'=revision.id AND receipt.document->'collected_at'=native->'collected_at' AND (SELECT jsonb_agg(to_jsonb(m->>'instance_id') ORDER BY m->>'instance_id') FROM jsonb_array_elements(native->'memberships') m)=p_scope->'resource_ids' AND jsonb_array_length(native->'callers') BETWEEN 1 AND 100 AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(native->'callers') c WHERE c->>'account_id' IS DISTINCT FROM p->>'account_id' OR NOT starts_with(c->>'arn','arn:aws:sts::'||(p->>'account_id')||':assumed-role/')) AND receipt.writer_role='finops_ingester' AND revision.writer_role='finops_ingester' AND revision.source_id=source_key AND revision.document->>'kind'='AWS_CONTROLLER_DISCOVERY' AND receipt.document->>'config_hash'=base->'portfolio_inputs'->'checkpoint'->>'config_hash' AND receipt.document->'registration_version'=base->'portfolio_inputs'->'registration'->'version' AND revision.document->>'config_hash'=receipt.document->>'config_hash' AND revision.document->'registration_version'=receipt.document->'registration_version' AND native->>'account_id'=p->>'account_id' AND native->>'region'=p->>'region' AND native->'registered_instance_ids'=p_scope->'resource_ids' AND receipt.document->'resource_ids'=p_scope->'resource_ids' AND native->>'raw_sha256'=receipt.document->'raw_object'->>'body_sha256' AND revision.document->'raw_object'->>'body_sha256'=native->>'raw_sha256' AND coalesce(receipt.document->'raw_object'->>'version_id','') NOT IN('','null') AND coalesce(revision.document->'raw_object'->>'version_id','') NOT IN('','null') AND jsonb_typeof(native->'collected_at')='string' AND (native->>'collected_at')::timestamptz>=clock_timestamp()-interval '5 minutes' AND (native->>'collected_at')::timestamptz<=clock_timestamp()+interval '5 seconds' AND jsonb_array_length(native->'groups')=1 AND jsonb_array_length(native->'memberships')=jsonb_array_length(p_scope->'resource_ids') AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(native->'memberships') m WHERE m->>'status' IS DISTINCT FROM 'ASG_MEMBER_OBSERVED' OR m->>'group_arn' IS DISTINCT FROM p->>'asg_arn') AND NOT EXISTS(SELECT 1 FROM public.source_receipts n WHERE n.tenant_id=receipt.tenant_id AND n.source_id=receipt.source_id AND n.kind=receipt.kind AND n.document->'binding'->>'workload_id'=request->>'workload_id' AND (n.document->>'collected_at')::timestamptz=(receipt.document->>'collected_at')::timestamptz AND n.document->'raw_object'->>'body_sha256' IS DISTINCT FROM receipt.document->'raw_object'->>'body_sha256') THEN
 group_record:=native->'groups'->0->'group';SELECT jsonb_agg(to_jsonb(m->>'instance_id') ORDER BY m->>'instance_id') INTO members FROM jsonb_array_elements(group_record->'members') m;
 IF group_record->>'arn'=p->>'asg_arn' AND members=p_scope->'resource_ids' AND jsonb_typeof(group_record->'minimum')='number' AND jsonb_typeof(group_record->'maximum')='number' AND jsonb_typeof(group_record->'desired')='number' THEN
 controller_ref:=jsonb_build_object('kind','AWS_CONTROLLER_DISCOVERY','id',receipt.id,'sha256',public.fleet_history_json_hash(receipt.document||jsonb_build_object('writer_role',receipt.writer_role,'created_at',receipt.created_at)));
 scope_ref:=policy_ref||jsonb_build_object('kind','WORKLOAD_CONTROLLER_SCOPE');
 controllers:=jsonb_build_array(jsonb_build_object('Reference',controller_ref,'ConfigurationSHA256',p_scope->>'configuration_sha256','MemberIDs',members,'Minimum',group_record->'minimum','Maximum',group_record->'maximum','Desired',group_record->'desired'));refs:=refs||jsonb_build_array(controller_ref,scope_ref);
 END IF;END IF;END IF;END IF;
 IF controller_ref IS NULL THEN reasons:=reasons||jsonb_build_array('AUTOSCALE_POSITIVE_NATIVE_ASG_AND_APPROVED_CONFIGURATION_SCOPE_UNAVAILABLE');END IF;
 RETURN jsonb_build_object('policy',p,'policy_ref',policy_ref,'registry_actor',policy.registry_actor,'sizing',sizing,'controllers',controllers,'controller_discovery_ref',controller_ref,'controller_scope_reference',scope_ref,'current_refs',refs,'reason_codes',reasons);
END $$;
REVOKE ALL ON FUNCTION commitment_optimization_policy_inputs(text,text,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION commitment_optimization_policy_inputs(text,text,jsonb) TO finops_commitment_portfolio;

-- Owner-only mirror of the private Go factory, using the exact currently
-- selected source rows. No caller-supplied physical/status verdict is accepted.
CREATE FUNCTION commitment_optimization_policy_stage(p_tenant text,p_request text,p_scope jsonb,p_stage text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE selected jsonb;sizing jsonb;candidate jsonb;actual jsonb;member jsonb;controller jsonb;profile public.workload_safety_profiles%ROWTYPE;
 disposition text:='UNAVAILABLE';reasons jsonb;refs jsonb:='[]';seen jsonb:='{}';instance_id text;instance_type text;current_type text;slot text;minimum integer:=0;population integer;
BEGIN
 IF p_stage NOT IN('RIGHTSIZE','AUTOSCALE') THEN RAISE EXCEPTION 'optimization supported policy stage required';END IF;
 selected:=public.commitment_optimization_policy_inputs(p_tenant,p_request,p_scope);population:=jsonb_array_length(p_scope->'resource_ids');
 <<assessment>>
 BEGIN
 IF p_stage='RIGHTSIZE' THEN
 sizing:=selected->'sizing';reasons:='["RIGHTSIZE_EXHAUSTIVE_APPROVED_CATALOG_AND_MEMBER_ASSESSMENTS_UNAVAILABLE"]';
 IF sizing IS NULL OR sizing='null'::jsonb THEN EXIT assessment;END IF;
 refs:=jsonb_build_array(sizing->'Reference');
 FOR candidate IN SELECT value FROM jsonb_array_elements(sizing->'Joins') LOOP
 SELECT d.document INTO actual FROM public.fleet_joint_decisions d WHERE d.tenant_id=p_tenant AND d.request_id=candidate->'Reference'->>'id' AND d.content_hash=candidate->'Reference'->>'sha256' AND d.writer_role='finops_group_decision';
 IF actual IS NULL OR jsonb_array_length(actual->'members') IS DISTINCT FROM population OR actual->>'observed_at' IS DISTINCT FROM candidate->>'ObservedAt' THEN RAISE EXCEPTION 'optimization exact physical decision differs';END IF;
 instance_type:=candidate->'Input'->'scope'->'candidate_template'->>'instance_type';
 FOR member IN SELECT value FROM jsonb_array_elements(actual->'members') LOOP
 instance_id:=member->>'instance_id';current_type:=sizing->'CurrentInstanceTypes'->>instance_id;slot:=instance_id||':'||instance_type;
 IF NOT(p_scope->'resource_ids' ? instance_id) OR current_type IS NULL OR NOT(sizing->'AllowedInstanceTypes' ? instance_type) OR seen ? slot THEN RAISE EXCEPTION 'optimization physical member population differs';END IF;seen:=seen||jsonb_build_object(slot,true);
 IF instance_type=current_type AND member->>'status' IS DISTINCT FROM 'PASS' OR instance_type<>current_type AND member->>'status' IS DISTINCT FROM 'FAIL' THEN reasons:='["RIGHTSIZE_CURRENT_OR_ALTERNATIVE_PHYSICAL_VERDICT_UNRESOLVED"]';EXIT assessment;END IF;
 END LOOP;
 refs:=refs||jsonb_build_array(candidate->'Reference');
 END LOOP;
 FOR instance_id IN SELECT value FROM jsonb_array_elements_text(p_scope->'resource_ids') LOOP
 FOR instance_type IN SELECT value FROM jsonb_array_elements_text(sizing->'AllowedInstanceTypes') LOOP
 IF NOT(seen ? (instance_id||':'||instance_type)) THEN reasons:='["RIGHTSIZE_CANDIDATE_OR_MEMBER_POPULATION_INCOMPLETE"]';EXIT assessment;END IF;
 END LOOP;END LOOP;
 disposition:='EVIDENCED_NO_CHANGE';reasons:='["ALL_OTHER_APPROVED_CANDIDATES_HAVE_AN_OBSERVED_PHYSICAL_FAILURE"]';
 ELSE
 reasons:='["AUTOSCALE_COMPLETE_CONTROLLER_AND_POLICY_SCOPE_UNAVAILABLE"]';
 SELECT * INTO profile FROM public.workload_safety_profiles p WHERE p.tenant_id=p_tenant AND p.workload_id=p_scope->>'workload_id' ORDER BY version DESC LIMIT 1;
 IF profile.id IS NULL OR selected->'controller_discovery_ref' IS NULL OR selected->'controller_discovery_ref'='null'::jsonb OR selected->'controller_scope_reference' IS NULL OR selected->'controller_scope_reference'='null'::jsonb THEN EXIT assessment;END IF;
 refs:=jsonb_build_array(jsonb_build_object('kind','WORKLOAD_SAFETY_PROFILE','id',profile.id,'sha256',public.fleet_history_json_hash(profile.document)),selected->'controller_discovery_ref',selected->'controller_scope_reference');
 FOR controller IN SELECT value FROM jsonb_array_elements(selected->'controllers') LOOP
 IF controller->>'ConfigurationSHA256' IS DISTINCT FROM p_scope->>'configuration_sha256' OR (controller->>'Minimum')::integer<1 OR (controller->>'Maximum')::integer<(controller->>'Minimum')::integer OR (controller->>'Desired')::integer<(controller->>'Minimum')::integer OR (controller->>'Desired')::integer>(controller->>'Maximum')::integer OR jsonb_array_length(controller->'MemberIDs') IS DISTINCT FROM (controller->>'Desired')::integer THEN RAISE EXCEPTION 'optimization native controller constraints differ';END IF;
 FOR instance_id IN SELECT value FROM jsonb_array_elements_text(controller->'MemberIDs') LOOP
 IF NOT(p_scope->'resource_ids' ? instance_id) OR seen ? instance_id THEN RAISE EXCEPTION 'optimization native controller population differs';END IF;seen:=seen||jsonb_build_object(instance_id,true);
 END LOOP;
 minimum:=minimum+(controller->>'Minimum')::integer;refs:=refs||jsonb_build_array(controller->'Reference');
 END LOOP;
 IF (SELECT count(*) FROM jsonb_object_keys(seen)) IS DISTINCT FROM population THEN reasons:='["AUTOSCALE_CONTROLLER_MEMBERSHIP_INCOMPLETE"]';EXIT assessment;END IF;
 IF minimum IS DISTINCT FROM (profile.document->>'min_replicas')::integer OR minimum<>population THEN reasons:='["AUTOSCALE_CAPACITY_ABOVE_MINIMUM_REQUIRES_OPTIMIZATION"]';EXIT assessment;END IF;
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(selected->'controllers') c WHERE c->'Maximum' IS DISTINCT FROM c->'Minimum') THEN reasons:='["AUTOSCALE_DYNAMIC_POLICY_ASSESSMENT_REQUIRED"]';EXIT assessment;END IF;
 disposition:='EVIDENCED_NO_CHANGE';reasons:='["NATIVE_FIXED_CAPACITY_EQUALS_OWNER_REQUIRED_REPLICA_FLOOR"]';
 END IF;
 END assessment;
 SELECT coalesce(jsonb_agg(v ORDER BY v->>'kind',v->>'id'),'[]') INTO refs FROM(SELECT DISTINCT v FROM jsonb_array_elements(refs) v) proofs;
 RETURN jsonb_build_object('disposition',disposition,'reason_codes',reasons,'input_refs',refs);
END $$;
REVOKE ALL ON FUNCTION commitment_optimization_policy_stage(text,text,jsonb,text) FROM PUBLIC;


-- CONNECTED ADDITIVE040: migrations/040_history_extension.sql.fragment
-- Merge after040's live/archive ownership union. No001--039 migration edits.
-- The existing immutable private evidence relation stores the checked closure;
-- no analyst UPDATE, cloud, CH, source-write, signing or ledger grant is added.

CREATE FUNCTION commitment_decision_history_context(p_tenant text,p_request text,p_query jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE request jsonb;base jsonb;selection jsonb;scope jsonb;training jsonb;ownership jsonb;
 accounts jsonb;resources jsonb;offers jsonb;native_offer jsonb;projection_start timestamptz;
 ending timestamptz;beginning timestamptz;gap_hours bigint;required_days bigint;BEGIN
 IF NOT public.commitment_portfolio_access(p_tenant) OR current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION 'decision history inputs changed';END IF;
 IF NOT public.commitment_portfolio_keys(p_query,ARRAY['selection','scope','training_period','ownership_ref']) OR octet_length(p_query::text)>65536 THEN RAISE EXCEPTION 'decision history query differs';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(p_tenant||':dependency-graph',0));
 request:=public.commitment_decision_request(p_tenant,p_request);
 IF request->>'purpose' IS DISTINCT FROM 'PREPARE' OR request->>'id' IS DISTINCT FROM p_request THEN RAISE EXCEPTION 'decision history query differs';END IF;
 base:=public.commitment_decision_base(p_tenant,request->>'workload_id',request->'selection');
 IF public.fleet_history_json_hash(base) IS DISTINCT FROM request->>'input_sha256' THEN RAISE EXCEPTION 'decision history inputs changed';END IF;
 selection:=base->'portfolio'->'selection';scope:=p_query->'scope';training:=p_query->'training_period';
 IF p_query->'selection' IS DISTINCT FROM selection OR NOT public.commitment_portfolio_keys(scope,ARRAY['tenant_id','workload_id','payer_account_id','usage_account_ids','resource_ids','class','currency','configuration_sha256','ownership_ref','history_period','projection_period','sha256']) OR NOT public.commitment_portfolio_keys(training,ARRAY['start','end']) OR NOT public.commitment_portfolio_keys(scope->'projection_period',ARRAY['start','end']) OR scope->>'tenant_id' IS DISTINCT FROM p_tenant OR scope->>'workload_id' IS DISTINCT FROM request->>'workload_id' OR scope->'history_period' IS DISTINCT FROM selection->'period' OR scope->>'sha256' IS DISTINCT FROM public.fleet_history_json_hash(scope||'{"sha256":""}') OR scope->'ownership_ref' IS DISTINCT FROM p_query->'ownership_ref' OR base->'ownership_scope' IS NULL OR base->'ownership_scope'='null'::jsonb THEN RAISE EXCEPTION 'decision history query differs';END IF;
 SELECT jsonb_agg(to_jsonb(v) ORDER BY v) INTO accounts FROM jsonb_array_elements_text(base->'portfolio_inputs'->'commitment'->'commitment_scope'->'usage_account_ids') v;
 SELECT jsonb_agg(to_jsonb(v->>'provider_resource_id') ORDER BY v->>'provider_resource_id') INTO resources FROM jsonb_array_elements(base->'resources') v;
 SELECT jsonb_agg(v->'native') INTO offers FROM jsonb_array_elements(base->'offer_revision'->'native'->'offerings') v WHERE v->'native'->>'offeringId'=base->'offer_receipt'->>'native_offering_id';
 IF jsonb_array_length(offers) IS DISTINCT FROM 1 THEN RAISE EXCEPTION 'decision history inputs changed';END IF;native_offer:=offers->0;
 IF coalesce(native_offer->>'planType','') NOT IN('Compute','EC2Instance') OR native_offer->>'paymentOption' IS DISTINCT FROM 'No Upfront' OR native_offer->'durationSeconds' IS DISTINCT FROM '31536000'::jsonb THEN RAISE EXCEPTION 'decision history inputs changed';END IF;
 IF scope->'usage_account_ids' IS DISTINCT FROM accounts OR scope->'resource_ids' IS DISTINCT FROM resources OR jsonb_array_length(resources) NOT BETWEEN 1 AND 128 OR scope->>'payer_account_id' IS DISTINCT FROM base->'portfolio_inputs'->'registration'->>'payer_account_id' OR scope->>'configuration_sha256' IS DISTINCT FROM base->'ownership_scope'->>'configuration_sha256' OR scope->>'class' IS DISTINCT FROM (CASE native_offer->>'planType' WHEN 'Compute' THEN 'COMPUTE_SAVINGS_PLAN' WHEN 'EC2Instance' THEN 'EC2_INSTANCE_SAVINGS_PLAN' ELSE '' END) OR scope->>'currency' IS DISTINCT FROM native_offer->>'currency' OR coalesce(scope->>'currency','')!~'^[A-Z]{3}$' THEN RAISE EXCEPTION 'decision history inputs changed';END IF;
 IF jsonb_typeof(scope->'projection_period'->'start') IS DISTINCT FROM 'string' OR jsonb_typeof(scope->'projection_period'->'end') IS DISTINCT FROM 'string' OR jsonb_typeof(training->'start') IS DISTINCT FROM 'string' OR jsonb_typeof(training->'end') IS DISTINCT FROM 'string' OR scope->'projection_period'->>'start'!~'(Z|[+]00:00)$' OR scope->'projection_period'->>'end'!~'(Z|[+]00:00)$' OR training->>'start'!~'(Z|[+]00:00)$' OR training->>'end'!~'(Z|[+]00:00)$' THEN RAISE EXCEPTION 'decision history query differs';END IF;
 projection_start:=(scope->'projection_period'->>'start')::timestamptz;ending:=(selection->'period'->>'end')::timestamptz;
 IF projection_start<clock_timestamp() OR projection_start>=clock_timestamp()+interval '1 hour' OR date_trunc('hour',projection_start AT TIME ZONE 'UTC') IS DISTINCT FROM (projection_start AT TIME ZONE 'UTC') OR (scope->'projection_period'->>'end')::timestamptz-projection_start<>interval '8760 hours' OR ending>clock_timestamp() OR ending<clock_timestamp()-interval '48 hours' THEN RAISE EXCEPTION 'decision history unavailable';END IF;
 gap_hours:=(extract(epoch FROM projection_start-ending)/3600)::bigint;
 required_days:=ceil((23376+2*gap_hours)::numeric/24)::bigint;beginning:=ending-required_days*interval '24 hours';
 IF (training->>'start')::timestamptz IS DISTINCT FROM beginning OR (training->>'end')::timestamptz IS DISTINCT FROM ending OR beginning<clock_timestamp()-interval '5 years' THEN RAISE EXCEPTION 'decision history query differs';END IF;
 ownership:=public.commitment_decision_ownership_assert(p_tenant,request->>'workload_id',p_query->'ownership_ref',beginning,ending);
 IF ownership->'scope' IS DISTINCT FROM base->'ownership_scope' OR ownership->'reference' IS DISTINCT FROM p_query->'ownership_ref' THEN RAISE EXCEPTION 'decision history inputs changed';END IF;
 RETURN jsonb_build_object('request',request,'base',base,'selection',selection,'scope',scope,'training_period',training,'ownership',ownership);
END $$;
REVOKE ALL ON FUNCTION commitment_decision_history_context(text,text,jsonb) FROM PUBLIC;

CREATE FUNCTION commitment_decision_history_page(p_tenant text,p_request text,p_query jsonb,p_after timestamptz) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE context jsonb;selection jsonb;inputs jsonb;source_key text;config text;head jsonb;receipt text;
 starting timestamptz;ending timestamptz;month_start timestamptz;month_end timestamptz;chunk_end timestamptz;
 chunks jsonb:='[]';answer jsonb;candidate jsonb;estimated bigint;BEGIN
 PERFORM public.commitment_ownership_machine(p_tenant);
 context:=public.commitment_decision_history_context(p_tenant,p_request,p_query);selection:=context->'selection';
 source_key:=selection->>'source_id';config:=context->'base'->'portfolio_inputs'->'checkpoint'->>'config_hash';
 starting:=(context->'training_period'->>'start')::timestamptz;ending:=(context->'training_period'->>'end')::timestamptz;
 IF p_after IS NULL OR p_after<starting OR p_after>=ending OR (p_after<>starting AND date_trunc('month',p_after AT TIME ZONE 'UTC') IS DISTINCT FROM (p_after AT TIME ZONE 'UTC')) THEN RAISE EXCEPTION 'decision history query differs';END IF;
 starting:=p_after;
 FOR i IN 1..2 LOOP
 month_start:=date_trunc('month',starting AT TIME ZONE 'UTC') AT TIME ZONE 'UTC';month_end:=((month_start AT TIME ZONE 'UTC')+interval '1 month') AT TIME ZONE 'UTC';chunk_end:=least(month_end,ending);
 SELECT c.document INTO head FROM public.source_checkpoints c WHERE c.tenant_id=p_tenant AND c.source_id=source_key AND c.checkpoint_key='month:'||config||':'||to_char(month_start AT TIME ZONE 'UTC','YYYY-MM');
 IF head IS NULL OR head ? 'ambiguous_at' OR coalesce(head->>'receipt_id','')='' THEN RAISE EXCEPTION 'decision history unavailable';END IF;receipt:=head->>'receipt_id';
 IF month_start<(selection->'period'->>'end')::timestamptz AND month_end>(selection->'period'->>'start')::timestamptz AND NOT (selection->'billing_receipt_ids' ? receipt) THEN RAISE EXCEPTION 'decision history inputs changed';END IF;
 SELECT octet_length(r.document::text)+octet_length(v.document::text)+octet_length(j.document::text) INTO estimated FROM public.source_receipts r JOIN public.source_revisions v ON v.tenant_id=r.tenant_id AND v.id=r.revision_id JOIN public.entities j ON j.tenant_id=r.tenant_id AND j.kind='ingestion_jobs' AND j.id=r.document->>'ingestion_job_id' WHERE r.tenant_id=p_tenant AND r.source_id=source_key AND r.id=receipt AND r.kind='AWS_CUR2' AND r.writer_role='finops_ingester' AND v.writer_role='finops_ingester';
 IF estimated IS NULL THEN RAISE EXCEPTION 'decision history unavailable';END IF;
 IF estimated>33554432 THEN RAISE EXCEPTION 'decision history byte limit';END IF;
 IF jsonb_array_length(chunks)>0 AND octet_length(chunks::text)+estimated+octet_length((context->'base'->'portfolio_inputs'->'commitment')::text)+octet_length((context->'base'->'portfolio_inputs'->'registration')::text)+65536>33554432 THEN EXIT;END IF;
 -- The unmodified original job is resolved by039. No filtered/resealed job
 -- or customer-provided historical receipt is created for this selection.
 inputs:=public.commitment_portfolio_resolve(p_tenant,jsonb_build_object('source_id',source_key,'commitment_receipt_id',selection->>'commitment_receipt_id','billing_receipt_ids',jsonb_build_array(receipt),'period',jsonb_build_object('start',starting,'end',chunk_end)));
 candidate:=chunks||jsonb_build_array(inputs);IF octet_length(candidate::text)+128>33554432 THEN RAISE EXCEPTION 'decision history byte limit';END IF;chunks:=candidate;
 starting:=chunk_end;IF starting>=ending THEN EXIT;END IF;
 END LOOP;
 answer:=jsonb_build_object('chunks',chunks,'next_after',CASE WHEN starting<ending THEN to_jsonb(starting) ELSE NULL END);
 IF octet_length(answer::text)>33554432 THEN RAISE EXCEPTION 'decision history byte limit';END IF;RETURN answer;
END $$;
REVOKE ALL ON FUNCTION commitment_decision_history_page(text,text,jsonb,timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION commitment_decision_history_page(text,text,jsonb,timestamptz) TO finops_commitment_portfolio;

CREATE FUNCTION commitment_decision_history_assert(p_tenant text,p_request text,p_query jsonb,p_pins jsonb) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE context jsonb;inputs jsonb;selection jsonb;pin jsonb;head jsonb;receipt public.source_receipts%ROWTYPE;revision public.source_revisions%ROWTYPE;job jsonb;
 source_key text;config text;month_start timestamptz;month_end timestamptz;ending timestamptz;proof jsonb;hours bigint;native_count bigint:=0;total_bytes bigint:=0;estimate bigint;counted integer:=0;BEGIN
 context:=public.commitment_decision_history_context(p_tenant,p_request,p_query);inputs:=context->'base'->'portfolio_inputs';selection:=context->'selection';
 source_key:=selection->>'source_id';config:=inputs->'checkpoint'->>'config_hash';
 IF NOT public.commitment_portfolio_keys(p_pins,ARRAY['source_id','registration_version','configuration_sha256','registration_sha256','checkpoint_sha256','commitment_ref','ownership_ref','training_period','revisions','native_record_count','historical_hour_count']) OR octet_length(p_pins::text)>1048576 OR p_pins->>'source_id' IS DISTINCT FROM source_key OR p_pins->'registration_version' IS DISTINCT FROM inputs->'registration'->'version' OR p_pins->>'configuration_sha256' IS DISTINCT FROM config OR p_pins->>'registration_sha256' IS DISTINCT FROM public.fleet_history_json_hash(inputs->'registration') OR p_pins->>'checkpoint_sha256' IS DISTINCT FROM public.fleet_history_json_hash(inputs->'checkpoint') OR p_pins->'commitment_ref' IS DISTINCT FROM jsonb_build_object('kind','AWS_COMMITMENT','id',selection->>'commitment_receipt_id','sha256',public.fleet_history_json_hash(inputs->'commitment')) OR p_pins->'ownership_ref' IS DISTINCT FROM p_query->'ownership_ref' OR p_pins->'training_period' IS DISTINCT FROM p_query->'training_period' OR jsonb_typeof(p_pins->'revisions') IS DISTINCT FROM 'array' OR jsonb_array_length(p_pins->'revisions') NOT BETWEEN 1 AND 64 THEN RAISE EXCEPTION 'decision history proof differs';END IF;
 month_start:=date_trunc('month',(p_query->'training_period'->>'start')::timestamptz AT TIME ZONE 'UTC') AT TIME ZONE 'UTC';ending:=(p_query->'training_period'->>'end')::timestamptz;
 FOR pin IN SELECT value FROM jsonb_array_elements(p_pins->'revisions') LOOP
 counted:=counted+1;month_end:=((month_start AT TIME ZONE 'UTC')+interval '1 month') AT TIME ZONE 'UTC';
 IF month_start>=ending OR NOT public.commitment_portfolio_keys(pin,ARRAY['billing_month','receipt','revision','job']) OR NOT public.commitment_portfolio_keys(pin->'billing_month',ARRAY['start','end']) OR (pin->'billing_month'->>'start')::timestamptz IS DISTINCT FROM month_start OR (pin->'billing_month'->>'end')::timestamptz IS DISTINCT FROM month_end THEN RAISE EXCEPTION 'decision history proof differs';END IF;
 SELECT c.document INTO head FROM public.source_checkpoints c WHERE c.tenant_id=p_tenant AND c.source_id=source_key AND c.checkpoint_key='month:'||config||':'||to_char(month_start AT TIME ZONE 'UTC','YYYY-MM');
 IF head IS NULL OR head ? 'ambiguous_at' OR head->>'receipt_id' IS DISTINCT FROM pin->'receipt'->>'id' THEN RAISE EXCEPTION 'decision history inputs changed';END IF;
 IF month_start<(selection->'period'->>'end')::timestamptz AND month_end>(selection->'period'->>'start')::timestamptz AND NOT (selection->'billing_receipt_ids' ? (head->>'receipt_id')) THEN RAISE EXCEPTION 'decision history inputs changed';END IF;
 SELECT octet_length(r.document::text)+octet_length(v.document::text)+octet_length(j.document::text) INTO estimate FROM public.source_receipts r JOIN public.source_revisions v ON v.tenant_id=r.tenant_id AND v.id=r.revision_id JOIN public.entities j ON j.tenant_id=r.tenant_id AND j.kind='ingestion_jobs' AND j.id=r.document->>'ingestion_job_id' WHERE r.tenant_id=p_tenant AND r.id=head->>'receipt_id' AND r.source_id=source_key;
 IF estimate IS NULL OR estimate>33554432 OR total_bytes+estimate>134217728 THEN RAISE EXCEPTION 'decision history byte limit';END IF;total_bytes:=total_bytes+estimate;
 SELECT * INTO receipt FROM public.source_receipts r WHERE r.tenant_id=p_tenant AND r.id=head->>'receipt_id' AND r.source_id=source_key AND r.kind='AWS_CUR2' AND r.writer_role='finops_ingester';
 SELECT * INTO revision FROM public.source_revisions v WHERE v.tenant_id=p_tenant AND v.id=receipt.revision_id AND v.source_id=source_key AND v.writer_role='finops_ingester';
 SELECT e.document INTO job FROM public.entities e WHERE e.tenant_id=p_tenant AND e.kind='ingestion_jobs' AND e.id=receipt.document->>'ingestion_job_id';proof:=receipt.document->'source_proof';
 IF receipt.id IS NULL OR revision.id IS NULL OR job IS NULL OR receipt.document->>'config_hash' IS DISTINCT FROM config OR receipt.document->'registration_version' IS DISTINCT FROM p_pins->'registration_version' OR revision.document->>'config_hash' IS DISTINCT FROM config OR job->>'status' IS DISTINCT FROM 'PERSISTED' OR job->>'source_provenance' IS DISTINCT FROM 'AWS_CUR2_AUTHENTICATED' OR job->>'source_receipt_id' IS DISTINCT FROM receipt.id OR job->>'source_revision_id' IS DISTINCT FROM revision.id OR pin->'receipt' IS DISTINCT FROM jsonb_build_object('kind','AWS_CUR2','id',receipt.id,'sha256',public.fleet_history_json_hash(receipt.document||jsonb_build_object('writer_role',receipt.writer_role))) OR pin->'revision' IS DISTINCT FROM jsonb_build_object('kind','AWS_CUR2_REVISION','id',revision.id,'sha256',public.fleet_history_json_hash(revision.document||jsonb_build_object('writer_role',revision.writer_role))) OR pin->'job' IS DISTINCT FROM jsonb_build_object('kind','AWS_CUR2_INGESTION_JOB','id',job->>'id','sha256',public.fleet_history_json_hash(job)) THEN RAISE EXCEPTION 'decision history inputs changed';END IF;
 IF jsonb_typeof(proof->'period_start') IS DISTINCT FROM 'string' OR jsonb_typeof(proof->'period_end') IS DISTINCT FROM 'string' OR jsonb_typeof(proof->'billing_period_start') IS DISTINCT FROM 'string' OR jsonb_typeof(proof->'billing_period_end') IS DISTINCT FROM 'string' OR (proof->>'billing_period_start')::timestamptz IS DISTINCT FROM month_start OR (proof->>'billing_period_end')::timestamptz IS DISTINCT FROM month_end OR (proof->>'period_start')::timestamptz>greatest(month_start,(p_query->'training_period'->>'start')::timestamptz) OR (proof->>'period_end')::timestamptz<least(month_end,ending) OR coalesce(proof->>'state','') NOT IN('COMPLETE','FINAL') OR jsonb_typeof(job->'raw'->'records') IS DISTINCT FROM 'array' OR jsonb_typeof(job->'canonical'->'records') IS DISTINCT FROM 'array' OR jsonb_array_length(job->'raw'->'records') IS DISTINCT FROM jsonb_array_length(job->'canonical'->'records') OR proof->'row_count' IS DISTINCT FROM to_jsonb(jsonb_array_length(job->'raw'->'records')) OR proof->'verified_row_count' IS DISTINCT FROM proof->'row_count' THEN RAISE EXCEPTION 'decision history proof differs';END IF;
 native_count:=native_count+jsonb_array_length(job->'raw'->'records');IF native_count>100000 THEN RAISE EXCEPTION 'decision history population limit';END IF;
 month_start:=month_end;
 END LOOP;
 hours:=(extract(epoch FROM ending-(p_query->'training_period'->>'start')::timestamptz)/3600)::bigint;
 IF month_start<ending OR p_pins->'native_record_count' IS DISTINCT FROM to_jsonb(native_count) OR jsonb_typeof(p_pins->'historical_hour_count') IS DISTINCT FROM 'number' OR coalesce(p_pins->>'historical_hour_count','')!~'^[1-9][0-9]{0,5}$' OR (p_pins->>'historical_hour_count')::bigint NOT BETWEEN hours AND 100000 OR (p_pins->>'historical_hour_count')::bigint%hours<>0 OR (p_pins->>'historical_hour_count')::bigint/hours>jsonb_array_length(p_query->'scope'->'resource_ids') THEN RAISE EXCEPTION 'decision history proof differs';END IF;
 RETURN true;
END $$;
REVOKE ALL ON FUNCTION commitment_decision_history_assert(text,text,jsonb,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION commitment_decision_history_assert(text,text,jsonb,jsonb) TO finops_commitment_portfolio;

CREATE FUNCTION commitment_decision_history_publish(p_tenant text,p_request text,p_query jsonb,p_pins jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE payload jsonb;identity text;digest text;refs jsonb;proof_ref jsonb;envelope jsonb;BEGIN
 PERFORM public.commitment_ownership_machine(p_tenant);
 PERFORM public.commitment_decision_history_assert(p_tenant,p_request,p_query,p_pins);
 payload:=jsonb_build_object('request_id',p_request,'query',p_query,'pins',p_pins);identity:=public.fleet_history_json_hash(payload);digest:=identity;
 proof_ref:=jsonb_build_object('kind','HISTORICAL_USAGE','id',identity,'sha256',digest);
 SELECT jsonb_agg(v ORDER BY v->>'kind',v->>'id') INTO refs FROM(SELECT DISTINCT v FROM(SELECT p_pins->'commitment_ref' v UNION ALL SELECT p_pins->'ownership_ref' UNION ALL SELECT r->'receipt' FROM jsonb_array_elements(p_pins->'revisions') r UNION ALL SELECT r->'revision' FROM jsonb_array_elements(p_pins->'revisions') r UNION ALL SELECT r->'job' FROM jsonb_array_elements(p_pins->'revisions') r UNION ALL SELECT proof_ref) q) deduplicated;
 envelope:=jsonb_build_object('id',identity,'kind','HISTORICAL_USAGE','request_id',p_request,'workload_id',public.commitment_decision_request(p_tenant,p_request)->>'workload_id','payload',payload,'payload_sha256',digest,'input_refs',refs,'writer_role','finops_commitment_portfolio');
 INSERT INTO public.entities(tenant_id,kind,id,document) VALUES(p_tenant,'commitment_decision_evidence',identity,envelope) ON CONFLICT(tenant_id,kind,id) DO NOTHING;
 IF NOT EXISTS(SELECT 1 FROM public.entities e WHERE e.tenant_id=p_tenant AND e.kind='commitment_decision_evidence' AND e.id=identity AND e.document=envelope) THEN RAISE EXCEPTION 'decision history proof differs';END IF;
 RETURN jsonb_build_object('reference',proof_ref,'input_refs',refs);
END $$;
REVOKE ALL ON FUNCTION commitment_decision_history_publish(text,text,jsonb,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION commitment_decision_history_publish(text,text,jsonb,jsonb) TO finops_commitment_portfolio;

-- Internal hook for preparation publication AND later Finance/currentness.
-- No API EXECUTE grant; enclosing existing security-definer functions call it.
CREATE FUNCTION commitment_decision_history_current(p_tenant text,p_request text,p_ref jsonb,p_scope jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE evidence jsonb;payload jsonb;BEGIN
 IF NOT public.commitment_portfolio_access(p_tenant) OR NOT public.commitment_portfolio_keys(p_ref,ARRAY['kind','id','sha256']) OR p_ref->>'kind' IS DISTINCT FROM 'HISTORICAL_USAGE' THEN RAISE EXCEPTION 'decision history proof differs';END IF;
 SELECT document INTO evidence FROM public.entities e WHERE e.tenant_id=p_tenant AND e.kind='commitment_decision_evidence' AND e.id=p_ref->>'id' AND e.document->>'kind'='HISTORICAL_USAGE' AND e.document->>'request_id'=p_request;
 payload:=evidence->'payload';
 IF evidence IS NULL OR evidence->>'writer_role' IS DISTINCT FROM 'finops_commitment_portfolio' OR evidence->>'payload_sha256' IS DISTINCT FROM p_ref->>'sha256' OR public.fleet_history_json_hash(payload) IS DISTINCT FROM p_ref->>'sha256' OR evidence->'payload'->'query'->'scope' IS DISTINCT FROM p_scope THEN RAISE EXCEPTION 'decision history proof differs';END IF;
 PERFORM public.commitment_decision_history_assert(p_tenant,p_request,payload->'query',payload->'pins');
 RETURN evidence->'input_refs';
END $$;
REVOKE ALL ON FUNCTION commitment_decision_history_current(text,text,jsonb,jsonb) FROM PUBLIC;


-- CONNECTED ADDITIVE040: migrations/040_financial_currentness.sql.fragment
-- Additive040-only compatibility. Original039 requests/results and signatures
-- are immutable. Only newly queued039 analyses receive a server-derived private
-- input snapshot; no old row is updated or manufactured during this migration.
ALTER TABLE commitment_portfolio_requests ADD COLUMN input_snapshot jsonb;
ALTER TABLE commitment_portfolio_requests ADD CONSTRAINT portfolio_private_snapshot_bound CHECK(input_snapshot IS NULL OR octet_length(input_snapshot::text)<=33554432);

CREATE OR REPLACE FUNCTION guard_commitment_portfolio_request() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE inputs jsonb;refs jsonb;BEGIN
 IF current_user<>'finops_api' OR NEW.creator_id='' OR octet_length(NEW.idempotency_key) NOT BETWEEN 8 AND 200 THEN RAISE EXCEPTION 'portfolio API request required';END IF;
 inputs:=public.commitment_portfolio_resolve(NEW.tenant_id,NEW.selection);
 SELECT jsonb_build_array(jsonb_build_object('kind','AWS_COMMITMENT','id',inputs->'commitment'->>'id','sha256',public.fleet_history_json_hash(inputs->'commitment')))||coalesce(jsonb_agg(jsonb_build_object('kind','AWS_CUR2','id',v->'receipt'->>'id','sha256',public.fleet_history_json_hash(v->'receipt')) ORDER BY v->'receipt'->>'id'),'[]') INTO refs FROM jsonb_array_elements(inputs->'billing') v;
 NEW.input_hash:=public.fleet_history_json_hash(inputs);NEW.input_refs:=refs;NEW.input_snapshot:=inputs;NEW.created_at:=clock_timestamp();RETURN NEW;
END $$;

-- These rows assert ONLY exact native point renewal. They never assert interval
-- ownership, a calibrated forecast, a future guaranteed price or authority.
CREATE TABLE commitment_financial_renewals(
 tenant_id text NOT NULL,id text NOT NULL,portfolio_request_id text NOT NULL,source_id text NOT NULL,
 original_receipt_id text NOT NULL,current_receipt_id text NOT NULL,document jsonb NOT NULL,
 content_hash text NOT NULL,checked_by name NOT NULL DEFAULT session_user,checked_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,id),FOREIGN KEY(tenant_id,portfolio_request_id) REFERENCES commitment_portfolio_requests(tenant_id,id),
 CHECK(octet_length(document::text)<=65536),CHECK(content_hash~'^[a-f0-9]{64}$')
);
ALTER TABLE commitment_financial_renewals ENABLE ROW LEVEL SECURITY;
ALTER TABLE commitment_financial_renewals FORCE ROW LEVEL SECURITY;
DO $$ BEGIN EXECUTE format('CREATE POLICY operator_scope ON commitment_financial_renewals TO %I USING(true) WITH CHECK(true)',current_user);END $$;
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE ON commitment_financial_renewals FOR EACH ROW EXECUTE FUNCTION deny_evidence_mutation();
REVOKE ALL ON commitment_financial_renewals FROM PUBLIC,finops_api,finops_commitment_portfolio,finops_ingester;

-- Internal to existing owner-defined040 readers/publication/Finance currentness.
-- Snapshot bytes are historical. Currentness is separately checked at actual
-- DB time under graph/source/credential fences, never injected into those bytes.
CREATE FUNCTION commitment_decision_financial_current(p_tenant text,p_portfolio text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE request public.commitment_portfolio_requests%ROWTYPE;analysis public.commitment_portfolio_results%ROWTYPE;
 snapshot jsonb;current_inputs jsonb;current_selection jsonb;checkpoint jsonb;original_native jsonb;current_native jsonb;
 proof jsonb;identity text;source_key text;BEGIN
 IF NOT public.commitment_portfolio_access(p_tenant) OR current_setting('transaction_isolation') IS DISTINCT FROM 'read committed' THEN RAISE EXCEPTION 'decision financial currentness scope differs';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(p_tenant||':dependency-graph',0));
 SELECT * INTO request FROM public.commitment_portfolio_requests r WHERE r.tenant_id=p_tenant AND r.id=p_portfolio;
 SELECT * INTO analysis FROM public.commitment_portfolio_results x WHERE x.tenant_id=p_tenant AND x.request_id=p_portfolio AND x.status='ASSESSED';
 snapshot:=request.input_snapshot;source_key:=request.selection->>'source_id';
 IF request.id IS NULL OR analysis.request_id IS NULL OR snapshot IS NULL OR octet_length(snapshot::text)>33554432 OR public.fleet_history_json_hash(snapshot) IS DISTINCT FROM request.input_hash OR snapshot->'selection' IS DISTINCT FROM request.selection OR snapshot->>'tenant_id' IS DISTINCT FROM p_tenant OR analysis.document->>'request_id' IS DISTINCT FROM request.id OR analysis.content_hash IS DISTINCT FROM public.fleet_history_json_hash(analysis.document) THEN RAISE EXCEPTION 'decision original financial snapshot unavailable';END IF;
 IF NOT pg_try_advisory_xact_lock_shared(hashtextextended(p_tenant||':trusted-source:'||source_key,0)) THEN RAISE EXCEPTION 'portfolio source busy';END IF;
 -- Original039resolve independently enforces the fresh HEALTHY point, exact
 -- source registration/account scope, credential fence and selected CUR heads.
 SELECT c.document INTO checkpoint FROM public.source_checkpoints c WHERE c.tenant_id=p_tenant AND c.source_id=source_key AND c.checkpoint_key='status';
 IF checkpoint IS NULL OR coalesce(checkpoint->>'commitment_receipt_id','')='' THEN RAISE EXCEPTION 'decision current native inventory unavailable';END IF;
 current_selection:=request.selection||jsonb_build_object('commitment_receipt_id',checkpoint->>'commitment_receipt_id');
 current_inputs:=public.commitment_portfolio_resolve(p_tenant,current_selection);
 IF current_inputs->'registration'->'version' IS DISTINCT FROM snapshot->'registration'->'version' OR current_inputs->'checkpoint'->>'config_hash' IS DISTINCT FROM snapshot->'checkpoint'->>'config_hash' OR current_inputs->'registration'->>'id' IS DISTINCT FROM snapshot->'registration'->>'id' OR current_inputs->'billing' IS DISTINCT FROM snapshot->'billing' THEN RAISE EXCEPTION 'decision financial source or billing changed';END IF;
 original_native:=snapshot->'commitment'->'commitment_scope';current_native:=current_inputs->'commitment'->'commitment_scope';
 IF jsonb_typeof(original_native) IS DISTINCT FROM 'object' OR jsonb_typeof(current_native) IS DISTINCT FROM 'object' OR original_native-ARRAY['receipt_id','observed_at'] IS DISTINCT FROM current_native-ARRAY['receipt_id','observed_at'] THEN RAISE EXCEPTION 'decision native financial inventory changed';END IF;
 proof:=jsonb_build_object('schema_version','1','basis','EXACT_NATIVE_COMMITMENT_RENEWAL_V1','portfolio_request_id',request.id,'source_id',source_key,'original_input_sha256',request.input_hash,'source_configuration_sha256',snapshot->'checkpoint'->>'config_hash','registration_version',snapshot->'registration'->'version','native_scope_sha256',public.fleet_history_json_hash(original_native-ARRAY['receipt_id','observed_at']),'original_commitment_ref',jsonb_build_object('kind','AWS_COMMITMENT','id',snapshot->'commitment'->>'id','sha256',public.fleet_history_json_hash(snapshot->'commitment')),'current_commitment_ref',jsonb_build_object('kind','AWS_COMMITMENT','id',current_inputs->'commitment'->>'id','sha256',public.fleet_history_json_hash(current_inputs->'commitment')),'execution_authorized',false,'verified_saving',NULL);
 identity:=public.fleet_history_json_hash(proof);
 INSERT INTO public.commitment_financial_renewals(tenant_id,id,portfolio_request_id,source_id,original_receipt_id,current_receipt_id,document,content_hash) VALUES(p_tenant,identity,request.id,source_key,snapshot->'commitment'->>'id',current_inputs->'commitment'->>'id',proof,identity) ON CONFLICT(tenant_id,id) DO NOTHING;
 IF NOT EXISTS(SELECT 1 FROM public.commitment_financial_renewals r WHERE r.tenant_id=p_tenant AND r.id=identity AND r.document=proof AND r.content_hash=identity) THEN RAISE EXCEPTION 'decision immutable financial renewal differs';END IF;
 RETURN jsonb_build_object('snapshot',snapshot,'analysis_observed_at',analysis.document->'observed_at','renewal_ref',jsonb_build_object('kind','FINANCIAL_CURRENTNESS_RENEWAL','id',identity,'sha256',identity),'current_commitment_id',current_inputs->'commitment'->>'id');
END $$;
REVOKE ALL ON FUNCTION commitment_decision_financial_current(text,text) FROM PUBLIC;

-- Resolve whole original monthly jobs using the current equivalent inventory,
-- then restore ONLY the authenticated immutable financial snapshot components.
-- No original CUR receipt/job/period is filtered, edited or resealed here.
CREATE FUNCTION commitment_decision_financial_inputs(p_tenant text,p_portfolio text,p_selection jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE value jsonb;snapshot jsonb;current_inputs jsonb;BEGIN
 value:=public.commitment_decision_financial_current(p_tenant,p_portfolio);snapshot:=value->'snapshot';
 IF p_selection->>'source_id' IS DISTINCT FROM snapshot->'selection'->>'source_id' OR p_selection->>'commitment_receipt_id' IS DISTINCT FROM snapshot->'selection'->>'commitment_receipt_id' THEN RAISE EXCEPTION 'decision original financial selection differs';END IF;
 current_inputs:=public.commitment_portfolio_resolve(p_tenant,p_selection||jsonb_build_object('commitment_receipt_id',value->>'current_commitment_id'));
 RETURN current_inputs||jsonb_build_object('selection',p_selection,'registration',snapshot->'registration','checkpoint',snapshot->'checkpoint','commitment',snapshot->'commitment');
END $$;
REVOKE ALL ON FUNCTION commitment_decision_financial_inputs(text,text,jsonb) FROM PUBLIC;

-- Bounded Finance selector status uses the same real currentness gate. It does
-- not infer equivalence from nonempty IDs or catch transport/permission errors.
CREATE FUNCTION commitment_decision_financial_available(p_tenant text,p_portfolio text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
BEGIN
 PERFORM public.commitment_decision_financial_current(p_tenant,p_portfolio);RETURN true;
 EXCEPTION WHEN raise_exception THEN
 IF SQLERRM IN('decision original financial snapshot unavailable','decision current native inventory unavailable','decision financial source or billing changed','decision native financial inventory changed','portfolio source not current','portfolio inventory changed','portfolio billing changed') THEN RETURN false;END IF;
 RAISE;
END $$;
REVOKE ALL ON FUNCTION commitment_decision_financial_available(text,text) FROM PUBLIC;


-- CONNECTED ADDITIVE040: migrations/040_preparation_connected.sql.fragment
-- Merge after ownership union, stage and history private extensions.
-- The numerical producer's completion is an output, never its own input ref.
CREATE FUNCTION commitment_recalculation_stage(p_tenant text,p_request text,p_scope jsonb,p_forecast jsonb,p_stage jsonb,p_publish boolean) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE request jsonb;decision jsonb;outcome jsonb;decision_ref jsonb;outcome_ref jsonb;expected_stage jsonb;payload jsonb;envelope jsonb;evidence_kind text;BEGIN
 IF NOT public.commitment_portfolio_access(p_tenant) OR current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION 'decision recalculation scope differs';END IF;
 IF p_publish THEN PERFORM public.commitment_ownership_machine(p_tenant);END IF;
 request:=public.commitment_decision_request(p_tenant,p_request);
 IF request->>'purpose' IS DISTINCT FROM 'PREPARE' OR p_scope->>'workload_id' IS DISTINCT FROM request->>'workload_id' OR p_forecast->>'request_id' IS DISTINCT FROM p_request OR p_forecast->>'scope_sha256' IS DISTINCT FROM p_scope->>'sha256' OR p_forecast->>'status' IS DISTINCT FROM 'CALIBRATED' OR p_forecast->'calibration' IS NULL OR p_forecast->'calibration'='null'::jsonb OR p_forecast->>'id' IS DISTINCT FROM public.fleet_history_json_hash(p_forecast||'{"id":""}') OR jsonb_typeof(p_stage->'completed_at') IS DISTINCT FROM 'string' OR (p_stage->>'completed_at')::timestamptz<(p_forecast->>'recalculated_at')::timestamptz OR (p_stage->>'completed_at')::timestamptz>clock_timestamp() THEN RAISE EXCEPTION 'decision actual recalculation differs';END IF;
 IF p_publish AND (p_stage->>'completed_at')::timestamptz<clock_timestamp()-interval '5 minutes' THEN RAISE EXCEPTION 'decision actual recalculation expired';END IF;
 decision:=jsonb_build_object('request_id',p_request,'stage','RECALCULATE_STABLE_DEMAND','scope_sha256',p_scope->>'sha256','forecast_sha256',public.fleet_history_json_hash(p_forecast),'calibration_sha256',public.fleet_history_json_hash(p_forecast->'calibration'),'completed_at',p_stage->'completed_at');
 decision_ref:=jsonb_build_object('kind','OPTIMIZATION_DECISION','id',public.fleet_history_json_hash(decision),'sha256',public.fleet_history_json_hash(decision));
 outcome:=jsonb_build_object('request_id',p_request,'stage','RECALCULATE_STABLE_DEMAND','scope_sha256',p_scope->>'sha256','decision_ref',decision_ref,'disposition','COMPLETED','completed_at',p_stage->'completed_at','reason_codes',jsonb_build_array('ACTUAL_TERM_FORECAST_AND_EMPIRICAL_CALIBRATION_PUBLISHED'));
 outcome_ref:=jsonb_build_object('kind','OPTIMIZATION_OUTCOME','id',public.fleet_history_json_hash(outcome),'sha256',public.fleet_history_json_hash(outcome));
 expected_stage:=jsonb_build_object('stage','RECALCULATE_STABLE_DEMAND','disposition','COMPLETED','decision_ref',decision_ref,'outcome_ref',outcome_ref,'scope_sha256',p_scope->>'sha256','completed_at',p_stage->'completed_at','reason_codes',outcome->'reason_codes');
 IF p_stage IS DISTINCT FROM expected_stage THEN RAISE EXCEPTION 'decision exact recalculation outcome differs';END IF;
 FOREACH evidence_kind IN ARRAY ARRAY['OPTIMIZATION_DECISION','OPTIMIZATION_OUTCOME'] LOOP
 payload:=CASE evidence_kind WHEN 'OPTIMIZATION_DECISION' THEN decision ELSE outcome END;
 envelope:=jsonb_build_object('id',public.fleet_history_json_hash(payload),'kind',evidence_kind,'request_id',p_request,'workload_id',request->>'workload_id','selection',request->'selection','base_sha256',request->>'input_sha256','scope_sha256',p_scope->>'sha256','payload',payload,'payload_sha256',public.fleet_history_json_hash(payload),'calibration_ref',NULL,'writer_role','finops_commitment_portfolio');
 IF p_publish THEN INSERT INTO public.entities(tenant_id,kind,id,document) VALUES(p_tenant,'commitment_decision_evidence',envelope->>'id',envelope) ON CONFLICT(tenant_id,kind,id) DO NOTHING;END IF;
 IF NOT EXISTS(SELECT 1 FROM public.entities e WHERE e.tenant_id=p_tenant AND e.kind='commitment_decision_evidence' AND e.id=envelope->>'id' AND e.document=envelope) THEN RAISE EXCEPTION 'decision immutable recalculation closure differs';END IF;
 END LOOP;
 RETURN jsonb_build_array(decision_ref,outcome_ref);
END $$;
REVOKE ALL ON FUNCTION commitment_recalculation_stage(text,text,jsonb,jsonb,jsonb,boolean) FROM PUBLIC;

-- PRIVATE CONNECTED OVERRIDES
CREATE OR REPLACE FUNCTION commitment_decision_publish_preparation(p_tenant text,p_request text,p_assessment jsonb,p_forecast jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE request jsonb;base jsonb;evidence_kind text;payload jsonb;identity text;envelope jsonb;calibration jsonb;calibration_ref jsonb:=NULL;answer jsonb;ownership jsonb;expected_refs jsonb;forecast_refs jsonb;history_refs jsonb;history_ref jsonb;prefix jsonb;fifth_refs jsonb;BEGIN
 IF current_setting('role',true)<>'finops_commitment_portfolio' OR NOT public.commitment_portfolio_scope(p_tenant) THEN RAISE EXCEPTION 'decision analytical publisher required';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(p_tenant||':dependency-graph',0));
 request:=public.commitment_decision_request(p_tenant,p_request);
 IF request->>'purpose' IS DISTINCT FROM 'PREPARE' THEN RAISE EXCEPTION 'decision preparation request required';END IF;
 base:=public.commitment_decision_base(p_tenant,request->>'workload_id',request->'selection');
 IF public.fleet_history_json_hash(base) IS DISTINCT FROM request->>'input_sha256' OR octet_length(p_assessment::text)>1048576 OR octet_length(p_forecast::text)>8388608 THEN RAISE EXCEPTION 'decision issued inputs changed';END IF;
 IF NOT public.commitment_portfolio_keys(p_assessment,ARRAY['schema_version','id','request_id','scope','status','optimization_order','input_refs','reason_codes','observed_at','execution_authorized','verified_saving']) OR p_assessment->>'schema_version' IS DISTINCT FROM '2' OR p_assessment->>'request_id' IS DISTINCT FROM p_request OR p_assessment->>'id' IS DISTINCT FROM public.fleet_history_json_hash(p_assessment||'{"id":""}') OR p_assessment->'scope'->>'workload_id' IS DISTINCT FROM request->>'workload_id' OR p_assessment->'scope'->>'tenant_id' IS DISTINCT FROM p_tenant OR p_assessment->'scope'->>'payer_account_id' IS DISTINCT FROM base->'portfolio_inputs'->'registration'->>'payer_account_id' OR p_assessment->'scope'->'history_period' IS DISTINCT FROM base->'portfolio'->'selection'->'period' OR p_assessment->'execution_authorized' IS DISTINCT FROM 'false'::jsonb OR p_assessment->'verified_saving' IS DISTINCT FROM 'null'::jsonb OR NOT public.commitment_portfolio_strings(p_assessment->'reason_codes',128) OR coalesce(p_assessment->>'status','') NOT IN('BLOCKED','ASSESSED') THEN RAISE EXCEPTION 'decision assessment differs';END IF;
 expected_refs:=base->'input_refs';
 IF p_assessment->'scope'->'ownership_ref'->>'kind'='HISTORICAL_OWNERSHIP' THEN
 ownership:=public.commitment_decision_ownership_assert(p_tenant,request->>'workload_id',p_assessment->'scope'->'ownership_ref',(p_assessment->'scope'->'history_period'->>'start')::timestamptz,(p_assessment->'scope'->'history_period'->>'end')::timestamptz);
 IF ownership->'scope' IS DISTINCT FROM base->'ownership_scope' OR ownership->'scope'->>'configuration_sha256' IS DISTINCT FROM p_assessment->'scope'->>'configuration_sha256' THEN RAISE EXCEPTION 'decision ownership evidence missing';END IF;
 expected_refs:=expected_refs||ownership->'input_refs';
 END IF;
 IF jsonb_typeof(p_assessment->'optimization_order') IS DISTINCT FROM 'array' OR jsonb_array_length(p_assessment->'optimization_order')<>5 THEN RAISE EXCEPTION 'decision exact optimization order required';END IF;
 IF p_assessment->'optimization_order'->0->'decision_ref'->>'kind'='OPTIMIZATION_DECISION' THEN
 SELECT jsonb_agg(v ORDER BY ord) INTO prefix FROM jsonb_array_elements(p_assessment->'optimization_order') WITH ORDINALITY a(v,ord) WHERE ord<=4;
 expected_refs:=expected_refs||public.commitment_optimization_prefix_current(p_tenant,p_request,p_assessment->'scope',prefix);
 ELSIF p_assessment->>'status' IS DISTINCT FROM 'BLOCKED' THEN RAISE EXCEPTION 'decision issued optimization prefix required';END IF;
 IF (SELECT count(*) FROM jsonb_array_elements(p_forecast->'input_refs') v WHERE v->>'kind'='HISTORICAL_USAGE')>1 THEN RAISE EXCEPTION 'decision exact history ref required';END IF;
 SELECT v INTO history_ref FROM jsonb_array_elements(p_forecast->'input_refs') v WHERE v->>'kind'='HISTORICAL_USAGE';
 IF history_ref IS NOT NULL THEN
 IF NOT (p_assessment->'input_refs' @> jsonb_build_array(history_ref)) THEN RAISE EXCEPTION 'decision shared history ref required';END IF;
 history_refs:=public.commitment_decision_history_current(p_tenant,p_request,history_ref,p_assessment->'scope');expected_refs:=expected_refs||history_refs;
 ELSIF p_forecast->>'status'='CALIBRATED' THEN RAISE EXCEPTION 'decision issued training history required';END IF;
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(expected_refs) v GROUP BY v->>'kind',v->>'id' HAVING count(DISTINCT v->>'sha256')>1) THEN RAISE EXCEPTION 'decision conflicting preparation proof';END IF;
 SELECT jsonb_agg(v ORDER BY v->>'kind',v->>'id') INTO forecast_refs FROM(SELECT DISTINCT v FROM jsonb_array_elements(expected_refs) v) proofs;
 IF p_forecast->'input_refs' IS DISTINCT FROM forecast_refs THEN RAISE EXCEPTION 'decision forecast proof closure differs';END IF;
 IF p_forecast->>'status'='CALIBRATED' THEN
 fifth_refs:=public.commitment_recalculation_stage(p_tenant,p_request,p_assessment->'scope',p_forecast,p_assessment->'optimization_order'->4,true);expected_refs:=expected_refs||fifth_refs;
 END IF;
 SELECT jsonb_agg(v ORDER BY v->>'kind',v->>'id') INTO expected_refs FROM(SELECT DISTINCT v FROM jsonb_array_elements(expected_refs) v) proofs;
 IF p_assessment->'input_refs' IS DISTINCT FROM expected_refs THEN RAISE EXCEPTION 'decision assessment proof closure differs';END IF;
 IF NOT public.commitment_portfolio_keys(p_forecast,ARRAY['schema_version','id','request_id','scope_sha256','recalculated_at','status','hours','calibration','reason_codes','input_refs']) OR p_forecast->>'schema_version' IS DISTINCT FROM '2' OR p_forecast->>'request_id' IS DISTINCT FROM p_request OR p_forecast->>'id' IS DISTINCT FROM public.fleet_history_json_hash(p_forecast||'{"id":""}') OR p_forecast->>'scope_sha256' IS DISTINCT FROM p_assessment->'scope'->>'sha256' OR NOT public.commitment_portfolio_strings(p_forecast->'reason_codes',128) OR coalesce(p_forecast->>'status','') NOT IN('CALIBRATED','UNAVAILABLE') OR jsonb_typeof(p_forecast->'hours') IS DISTINCT FROM 'array' OR jsonb_array_length(p_forecast->'hours')>100000 THEN RAISE EXCEPTION 'decision forecast differs';END IF;
 IF p_forecast->>'status'='UNAVAILABLE' THEN
 IF p_forecast->'calibration' IS DISTINCT FROM 'null'::jsonb OR p_forecast->'hours' IS DISTINCT FROM '[]'::jsonb OR jsonb_array_length(p_forecast->'reason_codes')=0 THEN RAISE EXCEPTION 'decision forecast gap differs';END IF;
 ELSE
 IF p_assessment->>'status' IS DISTINCT FROM 'ASSESSED' OR p_forecast->'calibration'='null'::jsonb OR jsonb_array_length(p_forecast->'hours')=0 THEN RAISE EXCEPTION 'decision forecast calibration differs';END IF;
 calibration:=p_forecast->'calibration';
 calibration_ref:=jsonb_build_object('kind','FORECAST_CALIBRATION','id',public.fleet_history_json_hash(calibration),'sha256',public.fleet_history_json_hash(calibration));
 END IF;
 FOREACH evidence_kind IN ARRAY ARRAY['OPTIMIZATION_ASSESSMENT','POST_OPTIMIZATION_FORECAST','FORECAST_CALIBRATION'] LOOP
 payload:=CASE evidence_kind WHEN 'OPTIMIZATION_ASSESSMENT' THEN p_assessment WHEN 'POST_OPTIMIZATION_FORECAST' THEN p_forecast ELSE calibration END;
 IF payload IS NULL THEN CONTINUE;END IF;
 identity:=CASE WHEN evidence_kind='FORECAST_CALIBRATION' THEN public.fleet_history_json_hash(payload) ELSE payload->>'id' END;
 envelope:=jsonb_build_object('id',identity,'kind',evidence_kind,'request_id',p_request,'workload_id',request->>'workload_id','selection',request->'selection','base_sha256',request->>'input_sha256','scope_sha256',p_assessment->'scope'->>'sha256','payload',payload,'payload_sha256',public.fleet_history_json_hash(payload),'calibration_ref',CASE WHEN evidence_kind='POST_OPTIMIZATION_FORECAST' THEN calibration_ref ELSE NULL END,'writer_role','finops_commitment_portfolio');
 INSERT INTO public.entities(tenant_id,kind,id,document) VALUES(p_tenant,'commitment_decision_evidence',identity,envelope) ON CONFLICT(tenant_id,kind,id) DO NOTHING;
 IF NOT EXISTS(SELECT 1 FROM public.entities e WHERE e.tenant_id=p_tenant AND e.kind='commitment_decision_evidence' AND e.id=identity AND e.document=envelope) THEN RAISE EXCEPTION 'decision immutable evidence conflict';END IF;
 END LOOP;
 answer:=jsonb_build_object('request_id',p_request,'post_optimization_assessment_id',p_assessment->>'id','forecast_id',p_forecast->>'id','input_refs',p_assessment->'input_refs','reason_codes',p_assessment->'reason_codes','observed_at',p_assessment->'observed_at','execution_authorized',false,'verified_saving',NULL);
 RETURN answer;
END $$;

CREATE OR REPLACE FUNCTION commitment_decision_base(p_tenant text,p_workload text,p_selection jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE request public.commitment_portfolio_requests%ROWTYPE;analysis public.commitment_portfolio_results%ROWTYPE;
 offer public.source_receipts%ROWTYPE;revision public.source_revisions%ROWTYPE;workload jsonb;resources jsonb;inputs jsonb;checkpoint jsonb;
 assessment jsonb;forecast jsonb;refs jsonb;byte_count bigint;ownership jsonb;history_ref jsonb;prefix jsonb;BEGIN
 IF NOT public.commitment_portfolio_access(p_tenant) THEN RAISE EXCEPTION 'decision credential scope differs';END IF;
 IF NOT public.commitment_portfolio_keys(p_selection,ARRAY['portfolio_analysis_request_id','offer_receipt_id']) AND NOT public.commitment_portfolio_keys(p_selection,ARRAY['portfolio_analysis_request_id','offer_receipt_id','post_optimization_assessment_id','forecast_id']) THEN RAISE EXCEPTION 'decision IDs-only selection differs';END IF;
 IF EXISTS(SELECT 1 FROM jsonb_each(p_selection) e WHERE jsonb_typeof(e.value)<>'string' OR e.value#>>'{}'!~'^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$') OR p_workload!~'^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$' THEN RAISE EXCEPTION 'decision IDs-only selection differs';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(p_tenant||':dependency-graph',0));
 SELECT * INTO request FROM public.commitment_portfolio_requests WHERE tenant_id=p_tenant AND id=p_selection->>'portfolio_analysis_request_id';
 SELECT * INTO analysis FROM public.commitment_portfolio_results WHERE tenant_id=p_tenant AND request_id=request.id AND status='ASSESSED';
 IF request.id IS NULL OR analysis.request_id IS NULL THEN RAISE EXCEPTION 'decision issued portfolio required';END IF;
 inputs:=public.commitment_portfolio_resolve(p_tenant,request.selection);
 IF public.fleet_history_json_hash(inputs) IS DISTINCT FROM request.input_hash OR analysis.document->>'request_id' IS DISTINCT FROM request.id OR analysis.content_hash IS DISTINCT FROM public.fleet_history_json_hash(analysis.document) THEN RAISE EXCEPTION 'decision portfolio changed';END IF;
 SELECT document||jsonb_build_object('id',id,'version',version) INTO workload FROM public.entities WHERE tenant_id=p_tenant AND kind='workloads' AND id=p_workload;
 IF workload IS NULL THEN RAISE EXCEPTION 'decision workload missing';END IF;
 SELECT coalesce(sum(octet_length(document::text)),0) INTO byte_count FROM public.entities WHERE tenant_id=p_tenant AND kind='resources' AND document->>'workload_id'=p_workload;
 IF byte_count>2097152 OR (SELECT count(*) FROM public.entities WHERE tenant_id=p_tenant AND kind='resources' AND document->>'workload_id'=p_workload)>2000 THEN RAISE EXCEPTION 'decision input byte limit';END IF;
 SELECT coalesce(jsonb_agg(document||jsonb_build_object('id',id,'version',version) ORDER BY id),'[]') INTO resources FROM public.entities WHERE tenant_id=p_tenant AND kind='resources' AND document->>'workload_id'=p_workload;
 SELECT * INTO offer FROM public.source_receipts WHERE tenant_id=p_tenant AND id=p_selection->>'offer_receipt_id' AND source_id=request.selection->>'source_id' AND kind='AWS_SAVINGS_PLAN_OFFER' AND writer_role='finops_ingester';
 SELECT * INTO revision FROM public.source_revisions WHERE tenant_id=p_tenant AND id=offer.revision_id AND source_id=offer.source_id AND writer_role='finops_ingester';
 SELECT document INTO checkpoint FROM public.source_checkpoints WHERE tenant_id=p_tenant AND source_id=offer.source_id AND checkpoint_key='savings-plan-quotes';
 IF offer.id IS NULL OR revision.id IS NULL OR offer.document->>'config_hash' IS DISTINCT FROM inputs->'checkpoint'->>'config_hash' OR checkpoint->>'revision_id' IS DISTINCT FROM revision.id OR offer.document->>'native_offering_id' IS NULL OR offer.document->>'projection' IS DISTINCT FROM 'AWS_SAVINGS_PLAN_RATE_QUOTES_V1' OR (offer.document->>'collected_at')::timestamptz<clock_timestamp()-interval '5 minutes' OR (offer.document->>'collected_at')::timestamptz>clock_timestamp()+interval '5 seconds' THEN RAISE EXCEPTION 'decision native offer not current';END IF;
 IF octet_length(revision.document::text)>16777216 OR octet_length(offer.document::text)>65536 THEN RAISE EXCEPTION 'decision input byte limit';END IF;
 refs:=request.input_refs||jsonb_build_array(jsonb_build_object('kind','COMMITMENT_PORTFOLIO_ANALYSIS','id',request.id,'sha256',analysis.content_hash),jsonb_build_object('kind','AWS_SAVINGS_PLAN_OFFER','id',offer.id,'sha256',public.fleet_history_json_hash(offer.document||jsonb_build_object('writer_role',offer.writer_role))),jsonb_build_object('kind','AWS_SAVINGS_PLAN_RATES','id',revision.id,'sha256',public.fleet_history_json_hash(revision.document||jsonb_build_object('writer_role',revision.writer_role))));
 IF p_selection ? 'post_optimization_assessment_id' THEN
 SELECT document INTO assessment FROM public.entities WHERE tenant_id=p_tenant AND kind='commitment_decision_evidence' AND id=p_selection->>'post_optimization_assessment_id' AND document->>'kind'='OPTIMIZATION_ASSESSMENT';
 SELECT document INTO forecast FROM public.entities WHERE tenant_id=p_tenant AND kind='commitment_decision_evidence' AND id=p_selection->>'forecast_id' AND document->>'kind'='POST_OPTIMIZATION_FORECAST';
 IF assessment IS NULL OR forecast IS NULL OR assessment->>'workload_id' IS DISTINCT FROM p_workload OR forecast->>'workload_id' IS DISTINCT FROM p_workload OR assessment->'selection' IS DISTINCT FROM p_selection-ARRAY['post_optimization_assessment_id','forecast_id'] OR forecast->'selection' IS DISTINCT FROM assessment->'selection' OR forecast->>'request_id' IS DISTINCT FROM assessment->>'request_id' OR forecast->>'base_sha256' IS DISTINCT FROM assessment->>'base_sha256' THEN RAISE EXCEPTION 'decision preparation scope differs';END IF;
 IF assessment->'payload'->>'status' IS DISTINCT FROM 'ASSESSED' OR forecast->'payload'->>'status' IS DISTINCT FROM 'CALIBRATED' OR assessment->'payload'->'scope'->'ownership_ref'->>'kind' IS DISTINCT FROM 'HISTORICAL_OWNERSHIP' THEN RAISE EXCEPTION 'decision issued inputs unavailable';END IF;
 ownership:=public.commitment_decision_ownership_assert(p_tenant,p_workload,assessment->'payload'->'scope'->'ownership_ref',(assessment->'payload'->'scope'->'history_period'->>'start')::timestamptz,(assessment->'payload'->'scope'->'history_period'->>'end')::timestamptz);
 IF ownership->'scope' IS DISTINCT FROM public.commitment_ownership_scope(p_tenant,p_workload) THEN RAISE EXCEPTION 'decision ownership evidence missing';END IF;
 IF jsonb_array_length(assessment->'payload'->'optimization_order')<>5 THEN RAISE EXCEPTION 'decision exact optimization order required';END IF;
 SELECT jsonb_agg(v ORDER BY ord) INTO prefix FROM jsonb_array_elements(assessment->'payload'->'optimization_order') WITH ORDINALITY a(v,ord) WHERE ord<=4;
 PERFORM public.commitment_optimization_prefix_current(p_tenant,assessment->>'request_id',assessment->'payload'->'scope',prefix);
 IF (SELECT count(*) FROM jsonb_array_elements(forecast->'payload'->'input_refs') v WHERE v->>'kind'='HISTORICAL_USAGE')<>1 THEN RAISE EXCEPTION 'decision issued training history required';END IF;
 SELECT v INTO history_ref FROM jsonb_array_elements(forecast->'payload'->'input_refs') v WHERE v->>'kind'='HISTORICAL_USAGE';
 PERFORM public.commitment_decision_history_current(p_tenant,assessment->>'request_id',history_ref,assessment->'payload'->'scope');
 PERFORM public.commitment_recalculation_stage(p_tenant,assessment->>'request_id',assessment->'payload'->'scope',forecast->'payload',assessment->'payload'->'optimization_order'->4,false);
 IF assessment->>'base_sha256' IS DISTINCT FROM public.fleet_history_json_hash(public.commitment_decision_base(p_tenant,p_workload,p_selection-ARRAY['post_optimization_assessment_id','forecast_id'])) THEN RAISE EXCEPTION 'decision preparation scope differs';END IF;
 refs:=refs||jsonb_build_array(jsonb_build_object('kind','OPTIMIZATION_ASSESSMENT','id',assessment->>'id','sha256',assessment->>'payload_sha256'),jsonb_build_object('kind','POST_OPTIMIZATION_FORECAST','id',forecast->>'id','sha256',forecast->>'payload_sha256'));
 IF forecast->'calibration_ref'<>'null'::jsonb THEN refs:=refs||jsonb_build_array(forecast->'calibration_ref');END IF;
 refs:=refs||(assessment->'payload'->'input_refs')||(forecast->'payload'->'input_refs');
 END IF;
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(refs) v GROUP BY v->>'kind',v->>'id' HAVING count(DISTINCT v->>'sha256')>1) THEN RAISE EXCEPTION 'decision conflicting immutable proof';END IF;
 SELECT coalesce(jsonb_agg(v ORDER BY v->>'kind',v->>'id'),'[]') INTO refs FROM(SELECT DISTINCT v FROM jsonb_array_elements(refs) v) proofs;
 RETURN jsonb_build_object('tenant_id',p_tenant,'workload_id',p_workload,'selection',p_selection,'workload',workload,'resources',resources,'portfolio',analysis.document,'portfolio_inputs',inputs,'offer_receipt',offer.document||jsonb_build_object('writer_role',offer.writer_role),'offer_revision',revision.document||jsonb_build_object('writer_role',revision.writer_role),'assessment',assessment,'forecast',forecast,'input_refs',refs,'ownership_scope',public.commitment_ownership_scope(p_tenant,p_workload));
END $$;


-- CONNECTED ADDITIVE040: migrations/040_financial_consumers.sql.fragment
-- Consumer hooks after connected040 overrides; all inputs remain server selected.
CREATE OR REPLACE FUNCTION commitment_decision_base(p_tenant text,p_workload text,p_selection jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE request public.commitment_portfolio_requests%ROWTYPE;analysis public.commitment_portfolio_results%ROWTYPE;
 offer public.source_receipts%ROWTYPE;revision public.source_revisions%ROWTYPE;workload jsonb;resources jsonb;inputs jsonb;checkpoint jsonb;
 assessment jsonb;forecast jsonb;refs jsonb;byte_count bigint;ownership jsonb;history_ref jsonb;prefix jsonb;BEGIN
 IF NOT public.commitment_portfolio_access(p_tenant) THEN RAISE EXCEPTION 'decision credential scope differs';END IF;
 IF NOT public.commitment_portfolio_keys(p_selection,ARRAY['portfolio_analysis_request_id','offer_receipt_id']) AND NOT public.commitment_portfolio_keys(p_selection,ARRAY['portfolio_analysis_request_id','offer_receipt_id','post_optimization_assessment_id','forecast_id']) THEN RAISE EXCEPTION 'decision IDs-only selection differs';END IF;
 IF EXISTS(SELECT 1 FROM jsonb_each(p_selection) e WHERE jsonb_typeof(e.value)<>'string' OR e.value#>>'{}'!~'^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$') OR p_workload!~'^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$' THEN RAISE EXCEPTION 'decision IDs-only selection differs';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(p_tenant||':dependency-graph',0));
 SELECT * INTO request FROM public.commitment_portfolio_requests WHERE tenant_id=p_tenant AND id=p_selection->>'portfolio_analysis_request_id';
 SELECT * INTO analysis FROM public.commitment_portfolio_results WHERE tenant_id=p_tenant AND request_id=request.id AND status='ASSESSED';
 IF request.id IS NULL OR analysis.request_id IS NULL THEN RAISE EXCEPTION 'decision issued portfolio required';END IF;
 inputs:=public.commitment_decision_financial_inputs(p_tenant,request.id,request.selection);
 IF public.fleet_history_json_hash(inputs) IS DISTINCT FROM request.input_hash OR analysis.document->>'request_id' IS DISTINCT FROM request.id OR analysis.content_hash IS DISTINCT FROM public.fleet_history_json_hash(analysis.document) THEN RAISE EXCEPTION 'decision portfolio changed';END IF;
 SELECT document||jsonb_build_object('id',id,'version',version) INTO workload FROM public.entities WHERE tenant_id=p_tenant AND kind='workloads' AND id=p_workload;
 IF workload IS NULL THEN RAISE EXCEPTION 'decision workload missing';END IF;
 SELECT coalesce(sum(octet_length(document::text)),0) INTO byte_count FROM public.entities WHERE tenant_id=p_tenant AND kind='resources' AND document->>'workload_id'=p_workload;
 IF byte_count>2097152 OR (SELECT count(*) FROM public.entities WHERE tenant_id=p_tenant AND kind='resources' AND document->>'workload_id'=p_workload)>2000 THEN RAISE EXCEPTION 'decision input byte limit';END IF;
 SELECT coalesce(jsonb_agg(document||jsonb_build_object('id',id,'version',version) ORDER BY id),'[]') INTO resources FROM public.entities WHERE tenant_id=p_tenant AND kind='resources' AND document->>'workload_id'=p_workload;
 SELECT * INTO offer FROM public.source_receipts WHERE tenant_id=p_tenant AND id=p_selection->>'offer_receipt_id' AND source_id=request.selection->>'source_id' AND kind='AWS_SAVINGS_PLAN_OFFER' AND writer_role='finops_ingester';
 SELECT * INTO revision FROM public.source_revisions WHERE tenant_id=p_tenant AND id=offer.revision_id AND source_id=offer.source_id AND writer_role='finops_ingester';
 SELECT document INTO checkpoint FROM public.source_checkpoints WHERE tenant_id=p_tenant AND source_id=offer.source_id AND checkpoint_key='savings-plan-quotes';
 IF offer.id IS NULL OR revision.id IS NULL OR offer.document->>'config_hash' IS DISTINCT FROM inputs->'checkpoint'->>'config_hash' OR checkpoint->>'revision_id' IS DISTINCT FROM revision.id OR offer.document->>'native_offering_id' IS NULL OR offer.document->>'projection' IS DISTINCT FROM 'AWS_SAVINGS_PLAN_RATE_QUOTES_V1' OR (offer.document->>'collected_at')::timestamptz<clock_timestamp()-interval '5 minutes' OR (offer.document->>'collected_at')::timestamptz>clock_timestamp()+interval '5 seconds' THEN RAISE EXCEPTION 'decision native offer not current';END IF;
 IF octet_length(revision.document::text)>16777216 OR octet_length(offer.document::text)>65536 THEN RAISE EXCEPTION 'decision input byte limit';END IF;
 refs:=request.input_refs||jsonb_build_array(jsonb_build_object('kind','COMMITMENT_PORTFOLIO_ANALYSIS','id',request.id,'sha256',analysis.content_hash),jsonb_build_object('kind','AWS_SAVINGS_PLAN_OFFER','id',offer.id,'sha256',public.fleet_history_json_hash(offer.document||jsonb_build_object('writer_role',offer.writer_role))),jsonb_build_object('kind','AWS_SAVINGS_PLAN_RATES','id',revision.id,'sha256',public.fleet_history_json_hash(revision.document||jsonb_build_object('writer_role',revision.writer_role))));
 IF p_selection ? 'post_optimization_assessment_id' THEN
 SELECT document INTO assessment FROM public.entities WHERE tenant_id=p_tenant AND kind='commitment_decision_evidence' AND id=p_selection->>'post_optimization_assessment_id' AND document->>'kind'='OPTIMIZATION_ASSESSMENT';
 SELECT document INTO forecast FROM public.entities WHERE tenant_id=p_tenant AND kind='commitment_decision_evidence' AND id=p_selection->>'forecast_id' AND document->>'kind'='POST_OPTIMIZATION_FORECAST';
 IF assessment IS NULL OR forecast IS NULL OR assessment->>'workload_id' IS DISTINCT FROM p_workload OR forecast->>'workload_id' IS DISTINCT FROM p_workload OR assessment->'selection' IS DISTINCT FROM p_selection-ARRAY['post_optimization_assessment_id','forecast_id'] OR forecast->'selection' IS DISTINCT FROM assessment->'selection' OR forecast->>'request_id' IS DISTINCT FROM assessment->>'request_id' OR forecast->>'base_sha256' IS DISTINCT FROM assessment->>'base_sha256' THEN RAISE EXCEPTION 'decision preparation scope differs';END IF;
 IF assessment->'payload'->>'status' IS DISTINCT FROM 'ASSESSED' OR forecast->'payload'->>'status' IS DISTINCT FROM 'CALIBRATED' OR assessment->'payload'->'scope'->'ownership_ref'->>'kind' IS DISTINCT FROM 'HISTORICAL_OWNERSHIP' THEN RAISE EXCEPTION 'decision issued inputs unavailable';END IF;
 ownership:=public.commitment_decision_ownership_assert(p_tenant,p_workload,assessment->'payload'->'scope'->'ownership_ref',(assessment->'payload'->'scope'->'history_period'->>'start')::timestamptz,(assessment->'payload'->'scope'->'history_period'->>'end')::timestamptz);
 IF ownership->'scope' IS DISTINCT FROM public.commitment_ownership_scope(p_tenant,p_workload) THEN RAISE EXCEPTION 'decision ownership evidence missing';END IF;
 IF jsonb_array_length(assessment->'payload'->'optimization_order')<>5 THEN RAISE EXCEPTION 'decision exact optimization order required';END IF;
 SELECT jsonb_agg(v ORDER BY ord) INTO prefix FROM jsonb_array_elements(assessment->'payload'->'optimization_order') WITH ORDINALITY a(v,ord) WHERE ord<=4;
 PERFORM public.commitment_optimization_prefix_current(p_tenant,assessment->>'request_id',assessment->'payload'->'scope',prefix);
 IF (SELECT count(*) FROM jsonb_array_elements(forecast->'payload'->'input_refs') v WHERE v->>'kind'='HISTORICAL_USAGE')<>1 THEN RAISE EXCEPTION 'decision issued training history required';END IF;
 SELECT v INTO history_ref FROM jsonb_array_elements(forecast->'payload'->'input_refs') v WHERE v->>'kind'='HISTORICAL_USAGE';
 PERFORM public.commitment_decision_history_current(p_tenant,assessment->>'request_id',history_ref,assessment->'payload'->'scope');
 PERFORM public.commitment_recalculation_stage(p_tenant,assessment->>'request_id',assessment->'payload'->'scope',forecast->'payload',assessment->'payload'->'optimization_order'->4,false);
 IF assessment->>'base_sha256' IS DISTINCT FROM public.fleet_history_json_hash(public.commitment_decision_base(p_tenant,p_workload,p_selection-ARRAY['post_optimization_assessment_id','forecast_id'])) THEN RAISE EXCEPTION 'decision preparation scope differs';END IF;
 refs:=refs||jsonb_build_array(jsonb_build_object('kind','OPTIMIZATION_ASSESSMENT','id',assessment->>'id','sha256',assessment->>'payload_sha256'),jsonb_build_object('kind','POST_OPTIMIZATION_FORECAST','id',forecast->>'id','sha256',forecast->>'payload_sha256'));
 IF forecast->'calibration_ref'<>'null'::jsonb THEN refs:=refs||jsonb_build_array(forecast->'calibration_ref');END IF;
 refs:=refs||(assessment->'payload'->'input_refs')||(forecast->'payload'->'input_refs');
 END IF;
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(refs) v GROUP BY v->>'kind',v->>'id' HAVING count(DISTINCT v->>'sha256')>1) THEN RAISE EXCEPTION 'decision conflicting immutable proof';END IF;
 SELECT coalesce(jsonb_agg(v ORDER BY v->>'kind',v->>'id'),'[]') INTO refs FROM(SELECT DISTINCT v FROM jsonb_array_elements(refs) v) proofs;
 RETURN jsonb_build_object('tenant_id',p_tenant,'workload_id',p_workload,'selection',p_selection,'workload',workload,'resources',resources,'portfolio',analysis.document,'portfolio_inputs',inputs,'offer_receipt',offer.document||jsonb_build_object('writer_role',offer.writer_role),'offer_revision',revision.document||jsonb_build_object('writer_role',revision.writer_role),'assessment',assessment,'forecast',forecast,'input_refs',refs,'ownership_scope',public.commitment_ownership_scope(p_tenant,p_workload));
END $$;

CREATE OR REPLACE FUNCTION commitment_decision_history_page(p_tenant text,p_request text,p_query jsonb,p_after timestamptz) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE context jsonb;selection jsonb;inputs jsonb;source_key text;config text;head jsonb;receipt text;
 starting timestamptz;ending timestamptz;month_start timestamptz;month_end timestamptz;chunk_end timestamptz;
 chunks jsonb:='[]';answer jsonb;candidate jsonb;estimated bigint;BEGIN
 PERFORM public.commitment_ownership_machine(p_tenant);
 context:=public.commitment_decision_history_context(p_tenant,p_request,p_query);selection:=context->'selection';
 source_key:=selection->>'source_id';config:=context->'base'->'portfolio_inputs'->'checkpoint'->>'config_hash';
 starting:=(context->'training_period'->>'start')::timestamptz;ending:=(context->'training_period'->>'end')::timestamptz;
 IF p_after IS NULL OR p_after<starting OR p_after>=ending OR (p_after<>starting AND date_trunc('month',p_after AT TIME ZONE 'UTC') IS DISTINCT FROM (p_after AT TIME ZONE 'UTC')) THEN RAISE EXCEPTION 'decision history query differs';END IF;
 starting:=p_after;
 FOR i IN 1..2 LOOP
 month_start:=date_trunc('month',starting AT TIME ZONE 'UTC') AT TIME ZONE 'UTC';month_end:=((month_start AT TIME ZONE 'UTC')+interval '1 month') AT TIME ZONE 'UTC';chunk_end:=least(month_end,ending);
 SELECT c.document INTO head FROM public.source_checkpoints c WHERE c.tenant_id=p_tenant AND c.source_id=source_key AND c.checkpoint_key='month:'||config||':'||to_char(month_start AT TIME ZONE 'UTC','YYYY-MM');
 IF head IS NULL OR head ? 'ambiguous_at' OR coalesce(head->>'receipt_id','')='' THEN RAISE EXCEPTION 'decision history unavailable';END IF;receipt:=head->>'receipt_id';
 IF month_start<(selection->'period'->>'end')::timestamptz AND month_end>(selection->'period'->>'start')::timestamptz AND NOT (selection->'billing_receipt_ids' ? receipt) THEN RAISE EXCEPTION 'decision history inputs changed';END IF;
 SELECT octet_length(r.document::text)+octet_length(v.document::text)+octet_length(j.document::text) INTO estimated FROM public.source_receipts r JOIN public.source_revisions v ON v.tenant_id=r.tenant_id AND v.id=r.revision_id JOIN public.entities j ON j.tenant_id=r.tenant_id AND j.kind='ingestion_jobs' AND j.id=r.document->>'ingestion_job_id' WHERE r.tenant_id=p_tenant AND r.source_id=source_key AND r.id=receipt AND r.kind='AWS_CUR2' AND r.writer_role='finops_ingester' AND v.writer_role='finops_ingester';
 IF estimated IS NULL THEN RAISE EXCEPTION 'decision history unavailable';END IF;
 IF estimated>33554432 THEN RAISE EXCEPTION 'decision history byte limit';END IF;
 IF jsonb_array_length(chunks)>0 AND octet_length(chunks::text)+estimated+octet_length((context->'base'->'portfolio_inputs'->'commitment')::text)+octet_length((context->'base'->'portfolio_inputs'->'registration')::text)+65536>33554432 THEN EXIT;END IF;
 -- The unmodified original job is resolved by039. No filtered/resealed job
 -- or customer-provided historical receipt is created for this selection.
 inputs:=public.commitment_decision_financial_inputs(p_tenant,context->'base'->'portfolio'->>'request_id',jsonb_build_object('source_id',source_key,'commitment_receipt_id',selection->>'commitment_receipt_id','billing_receipt_ids',jsonb_build_array(receipt),'period',jsonb_build_object('start',starting,'end',chunk_end)));
 candidate:=chunks||jsonb_build_array(inputs);IF octet_length(candidate::text)+128>33554432 THEN RAISE EXCEPTION 'decision history byte limit';END IF;chunks:=candidate;
 starting:=chunk_end;IF starting>=ending THEN EXIT;END IF;
 END LOOP;
 answer:=jsonb_build_object('snapshot_observed_at',context->'base'->'portfolio'->'observed_at','chunks',chunks,'next_after',CASE WHEN starting<ending THEN to_jsonb(starting) ELSE NULL END);
 IF octet_length(answer::text)>33554432 THEN RAISE EXCEPTION 'decision history byte limit';END IF;RETURN answer;
END $$;


CREATE OR REPLACE FUNCTION commitment_decision_choices(p_tenant text,p_workload text,p_kind text,p_after text,p_limit integer) RETURNS TABLE(value jsonb)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
BEGIN
 IF current_setting('role',true)<>'finops_api' OR NOT public.commitment_portfolio_access(p_tenant) OR p_limit NOT BETWEEN 1 AND 21 OR NOT EXISTS(SELECT 1 FROM public.entities WHERE tenant_id=p_tenant AND kind='workloads' AND id=p_workload) THEN RAISE EXCEPTION 'decision selector scope differs';END IF;
 IF p_kind='PORTFOLIO_ANALYSIS' THEN
 RETURN QUERY SELECT jsonb_build_object('id',r.id,'kind',p_kind,'label',r.selection->>'source_id'||' / '||r.id,'status',CASE WHEN public.commitment_decision_financial_available(p_tenant,r.id) THEN 'CURRENT' ELSE 'STALE' END,'scope_sha256',NULL,'period',r.selection->'period','input_refs',r.input_refs,'reason_codes','[]'::jsonb) FROM public.commitment_portfolio_requests r JOIN public.commitment_portfolio_results x ON x.tenant_id=r.tenant_id AND x.request_id=r.id AND x.status='ASSESSED' JOIN public.source_registrations s ON s.tenant_id=r.tenant_id AND s.id=r.selection->>'source_id' LEFT JOIN public.source_checkpoints c ON c.tenant_id=s.tenant_id AND c.source_id=s.id AND c.checkpoint_key='status' WHERE r.tenant_id=p_tenant AND r.id>p_after ORDER BY r.id LIMIT p_limit;
 ELSIF p_kind='OFFER' THEN
 RETURN QUERY SELECT jsonb_build_object('id',r.id,'kind',p_kind,'label',r.document->>'native_offering_id'||' / '||r.id,'status',CASE WHEN s.document->'enabled'='true'::jsonb AND s.document->'revoked' IS DISTINCT FROM 'true'::jsonb AND c.document->>'revision_id'=r.revision_id AND (r.document->>'collected_at')::timestamptz>=clock_timestamp()-interval '5 minutes' THEN 'CURRENT' ELSE 'STALE' END,'scope_sha256',NULL,'period',NULL,'input_refs',jsonb_build_array(jsonb_build_object('kind','AWS_SAVINGS_PLAN_OFFER','id',r.id,'sha256',public.fleet_history_json_hash(r.document||jsonb_build_object('writer_role',r.writer_role)))),'reason_codes','[]'::jsonb) FROM public.source_receipts r JOIN public.source_registrations s ON s.tenant_id=r.tenant_id AND s.id=r.source_id LEFT JOIN public.source_checkpoints c ON c.tenant_id=r.tenant_id AND c.source_id=r.source_id AND c.checkpoint_key='savings-plan-quotes' WHERE r.tenant_id=p_tenant AND r.kind='AWS_SAVINGS_PLAN_OFFER' AND r.writer_role='finops_ingester' AND r.id>p_after ORDER BY r.id LIMIT p_limit;
 ELSIF p_kind IN('POST_OPTIMIZATION_ASSESSMENT','FORECAST') THEN
 RETURN QUERY SELECT jsonb_build_object('id',e.id,'kind',p_kind,'label',e.document->>'kind'||' / '||e.id,'status',CASE WHEN coalesce(e.document->'payload'->>'status','') NOT IN('ASSESSED','CALIBRATED') THEN 'UNAVAILABLE' WHEN public.commitment_decision_current(p_tenant,e.document->>'request_id') THEN 'CURRENT' ELSE 'STALE' END,'scope_sha256',e.document->>'scope_sha256','period',NULL,'input_refs',coalesce(e.document->'payload'->'input_refs','[]'),'reason_codes',coalesce(e.document->'payload'->'reason_codes','[]')) FROM public.entities e WHERE e.tenant_id=p_tenant AND e.kind='commitment_decision_evidence' AND e.document->>'workload_id'=p_workload AND e.document->>'kind'=CASE p_kind WHEN 'FORECAST' THEN 'POST_OPTIMIZATION_FORECAST' ELSE 'OPTIMIZATION_ASSESSMENT' END AND e.id>p_after ORDER BY e.id LIMIT p_limit;
 ELSE RAISE EXCEPTION 'decision selector kind differs';END IF;
END $$;


-- CONNECTED ADDITIVE040: migrations/040_capacity_baseline.sql.fragment
-- Additive analytical baseline discriminator. Migration036 and its issued rows
-- stay immutable. All existing native/model/no-authority guards remain active.
DO $baseline$
DECLARE definition text;original text;needle text;replacement text;BEGIN
 SELECT pg_get_functiondef('public.guard_fleet_capacity_member()'::regprocedure) INTO definition;
 original:=definition;
 needle:='NOT IN(''MAPPING_OBSERVATION'',''MODEL_REQUEST'')';
 IF (length(definition)-length(replace(definition,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION 'baseline input-kind guard shape differs';END IF;
 definition:=replace(definition,needle,'NOT IN(''MAPPING_OBSERVATION'',''MODEL_REQUEST'',''CURRENT_CONFIGURATION_BASELINE_MODEL_REQUEST'')');
 needle:='NEW.document->>''input_kind'' IS DISTINCT FROM ''MODEL_REQUEST''';
 IF (length(definition)-length(replace(definition,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION 'baseline model guard shape differs';END IF;
 definition:=replace(definition,needle,'NEW.document->>''input_kind'' NOT IN(''MODEL_REQUEST'',''CURRENT_CONFIGURATION_BASELINE_MODEL_REQUEST'')');
 needle:=' IF NEW.document->''model_evaluated''=''true''::jsonb THEN';
 IF (length(definition)-length(replace(definition,needle,'')))/length(needle)<>1 THEN RAISE EXCEPTION 'baseline native guard insertion differs';END IF;
 replacement:=$checks$
 IF NEW.document->>'input_kind'='CURRENT_CONFIGURATION_BASELINE_MODEL_REQUEST' THEN
 DECLARE catalog jsonb:=NEW.document->'hardware_mapping'->'current';type_count bigint;memory_mib numeric;observed_cpu numeric;BEGIN
  IF hw.id IS NULL OR NEW.document->'model_requested' IS DISTINCT FROM 'true'::jsonb OR jsonb_typeof(catalog) IS DISTINCT FROM 'object' OR jsonb_typeof(NEW.document->'hardware_mapping'->'candidates') IS DISTINCT FROM 'array' OR jsonb_array_length(NEW.document->'hardware_mapping'->'candidates')<>1 OR catalog IS DISTINCT FROM NEW.document->'hardware_mapping'->'candidates'->0 OR NOT(NEW.document->'reason_codes' ? 'CURRENT_CONFIGURATION_BASELINE_ONLY') OR catalog->>'id' IS DISTINCT FROM hw.document->'native'->'instance'->>'instance_type' OR catalog->>'id' IS DISTINCT FROM NEW.document->'candidate_template'->>'instance_type' OR catalog->'count' IS DISTINCT FROM '1'::jsonb OR catalog->'source_ref'->>'receipt_id' IS DISTINCT FROM hw.id OR catalog->'source_ref'->'binding' IS DISTINCT FROM NEW.document->'binding' OR catalog->'source_ref'->>'sha256' IS DISTINCT FROM hw.document->'native'->>'raw_sha256' OR catalog->'pricing' IS DISTINCT FROM 'null'::jsonb OR catalog->'commitment_compatible' IS DISTINCT FROM 'null'::jsonb THEN RAISE EXCEPTION 'current baseline catalog or no-authority identity differs';END IF;
  IF coalesce(hw.document->'native'->'instance'->'cpu_options'->>'core_count','')!~'^[1-9][0-9]*$' OR coalesce(hw.document->'native'->'instance'->'cpu_options'->>'threads_per_core','')!~'^[1-9][0-9]*$' OR coalesce(catalog->'capacity'->>'cpu','')!~'^[0-9]+(\.[0-9]{1,12})?$' OR coalesce(catalog->'capacity'->>'memory','')!~'^[0-9]+(\.[0-9]{1,12})?$' THEN RAISE EXCEPTION 'current baseline observed CPU or memory unavailable';END IF;
  observed_cpu:=(hw.document->'native'->'instance'->'cpu_options'->>'core_count')::numeric*(hw.document->'native'->'instance'->'cpu_options'->>'threads_per_core')::numeric;
  SELECT count(*),max((t->'memory'->>'size_in_mib')::numeric) INTO type_count,memory_mib FROM jsonb_array_elements(hw.document->'native'->'types') t WHERE t->>'name'=catalog->>'id';
  IF type_count<>1 OR memory_mib IS NULL OR memory_mib<=0 OR (catalog->'capacity'->>'cpu')::numeric IS DISTINCT FROM observed_cpu OR (catalog->'capacity'->>'memory')::numeric IS DISTINCT FROM memory_mib*1048576 THEN RAISE EXCEPTION 'current baseline substituted hypothetical physical capacity';END IF;
 END;
 ELSIF NEW.document->'reason_codes' ? 'CURRENT_CONFIGURATION_BASELINE_ONLY' OR NEW.document->>'input_kind'='MODEL_REQUEST' AND NEW.document->'candidate_template'->>'instance_type' IS NOT DISTINCT FROM hw.document->'native'->'instance'->>'instance_type' THEN
  RAISE EXCEPTION 'current baseline marker stripped or reused for a candidate';
 END IF;
$checks$||needle;
 definition:=replace(definition,needle,replacement);
 IF definition=original THEN RAISE EXCEPTION 'baseline member guard unchanged';END IF;
 EXECUTE definition;
END $baseline$;


-- CONNECTED ADDITIVE040: migrations/040_baseline_stage_guards.sql.fragment
-- Additive baseline-only RIGHTSIZE consumer; ordinary alternatives retain MODEL_REQUEST semantics.
CREATE OR REPLACE FUNCTION commitment_optimization_policy_stage(p_tenant text,p_request text,p_scope jsonb,p_stage text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE selected jsonb;sizing jsonb;candidate jsonb;actual jsonb;member jsonb;controller jsonb;profile public.workload_safety_profiles%ROWTYPE;
 physical_member jsonb; disposition text:='UNAVAILABLE';reasons jsonb;refs jsonb:='[]';seen jsonb:='{}';instance_id text;instance_type text;current_type text;slot text;minimum integer:=0;population integer;
BEGIN
 IF p_stage NOT IN('RIGHTSIZE','AUTOSCALE') THEN RAISE EXCEPTION 'optimization supported policy stage required';END IF;
 selected:=public.commitment_optimization_policy_inputs(p_tenant,p_request,p_scope);population:=jsonb_array_length(p_scope->'resource_ids');
 <<assessment>>
 BEGIN
 IF p_stage='RIGHTSIZE' THEN
 sizing:=selected->'sizing';reasons:='["RIGHTSIZE_EXHAUSTIVE_APPROVED_CATALOG_AND_MEMBER_ASSESSMENTS_UNAVAILABLE"]';
 IF sizing IS NULL OR sizing='null'::jsonb THEN EXIT assessment;END IF;
 refs:=jsonb_build_array(sizing->'Reference');
 FOR candidate IN SELECT value FROM jsonb_array_elements(sizing->'Joins') LOOP
 SELECT d.document INTO actual FROM public.fleet_joint_decisions d WHERE d.tenant_id=p_tenant AND d.request_id=candidate->'Reference'->>'id' AND d.content_hash=candidate->'Reference'->>'sha256' AND d.writer_role='finops_group_decision';
 IF actual IS NULL OR jsonb_array_length(actual->'members') IS DISTINCT FROM population OR actual->>'observed_at' IS DISTINCT FROM candidate->>'ObservedAt' THEN RAISE EXCEPTION 'optimization exact physical decision differs';END IF;
 instance_type:=candidate->'Input'->'scope'->'candidate_template'->>'instance_type';
 FOR member IN SELECT value FROM jsonb_array_elements(actual->'members') LOOP
 instance_id:=member->>'instance_id';current_type:=sizing->'CurrentInstanceTypes'->>instance_id;slot:=instance_id||':'||instance_type;
 IF NOT(p_scope->'resource_ids' ? instance_id) OR current_type IS NULL OR NOT(sizing->'AllowedInstanceTypes' ? instance_type) OR seen ? slot THEN RAISE EXCEPTION 'optimization physical member population differs';END IF;seen:=seen||jsonb_build_object(slot,true);
 IF instance_type=current_type AND member->>'status' IS DISTINCT FROM 'PASS' OR instance_type<>current_type AND member->>'status' IS DISTINCT FROM 'FAIL' THEN reasons:='["RIGHTSIZE_CURRENT_OR_ALTERNATIVE_PHYSICAL_VERDICT_UNRESOLVED"]';EXIT assessment;END IF;
 SELECT m.document INTO physical_member FROM public.fleet_native_capacity_members m WHERE m.tenant_id=p_tenant AND m.id=member->'result'->>'id' AND m.content_hash=member->'result'->>'sha256' AND m.writer_role='finops_group_capacity';
 IF physical_member IS NULL THEN RAISE EXCEPTION 'optimization exact capacity member unavailable';END IF;
 IF instance_type=current_type THEN
 IF physical_member->>'input_kind' IS DISTINCT FROM 'CURRENT_CONFIGURATION_BASELINE_MODEL_REQUEST' OR NOT(physical_member->'reason_codes' ? 'CURRENT_CONFIGURATION_BASELINE_ONLY') OR physical_member->'hardware_mapping'->'current' IS DISTINCT FROM physical_member->'hardware_mapping'->'candidates'->0 OR physical_member->'hardware_mapping'->'current'->>'id' IS DISTINCT FROM current_type OR physical_member->'candidate_template'->>'instance_type' IS DISTINCT FROM current_type OR actual->'scenario'->>'status'='OBSERVED_CONDITIONAL' THEN RAISE EXCEPTION 'optimization current baseline marker differs';END IF;
 ELSE
 IF physical_member->>'input_kind' IS DISTINCT FROM 'MODEL_REQUEST' OR physical_member->'reason_codes' ? 'CURRENT_CONFIGURATION_BASELINE_ONLY' THEN RAISE EXCEPTION 'optimization counterfactual model marker differs';END IF;
 END IF;
 END LOOP;
 refs:=refs||jsonb_build_array(candidate->'Reference');
 END LOOP;
 FOR instance_id IN SELECT value FROM jsonb_array_elements_text(p_scope->'resource_ids') LOOP
 FOR instance_type IN SELECT value FROM jsonb_array_elements_text(sizing->'AllowedInstanceTypes') LOOP
 IF NOT(seen ? (instance_id||':'||instance_type)) THEN reasons:='["RIGHTSIZE_CANDIDATE_OR_MEMBER_POPULATION_INCOMPLETE"]';EXIT assessment;END IF;
 END LOOP;END LOOP;
 disposition:='EVIDENCED_NO_CHANGE';reasons:='["ALL_OTHER_APPROVED_CANDIDATES_HAVE_AN_OBSERVED_PHYSICAL_FAILURE"]';
 ELSE
 reasons:='["AUTOSCALE_COMPLETE_CONTROLLER_AND_POLICY_SCOPE_UNAVAILABLE"]';
 SELECT * INTO profile FROM public.workload_safety_profiles p WHERE p.tenant_id=p_tenant AND p.workload_id=p_scope->>'workload_id' ORDER BY version DESC LIMIT 1;
 IF profile.id IS NULL OR selected->'controller_discovery_ref' IS NULL OR selected->'controller_discovery_ref'='null'::jsonb OR selected->'controller_scope_reference' IS NULL OR selected->'controller_scope_reference'='null'::jsonb THEN EXIT assessment;END IF;
 refs:=jsonb_build_array(jsonb_build_object('kind','WORKLOAD_SAFETY_PROFILE','id',profile.id,'sha256',public.fleet_history_json_hash(profile.document)),selected->'controller_discovery_ref',selected->'controller_scope_reference');
 FOR controller IN SELECT value FROM jsonb_array_elements(selected->'controllers') LOOP
 IF controller->>'ConfigurationSHA256' IS DISTINCT FROM p_scope->>'configuration_sha256' OR (controller->>'Minimum')::integer<1 OR (controller->>'Maximum')::integer<(controller->>'Minimum')::integer OR (controller->>'Desired')::integer<(controller->>'Minimum')::integer OR (controller->>'Desired')::integer>(controller->>'Maximum')::integer OR jsonb_array_length(controller->'MemberIDs') IS DISTINCT FROM (controller->>'Desired')::integer THEN RAISE EXCEPTION 'optimization native controller constraints differ';END IF;
 FOR instance_id IN SELECT value FROM jsonb_array_elements_text(controller->'MemberIDs') LOOP
 IF NOT(p_scope->'resource_ids' ? instance_id) OR seen ? instance_id THEN RAISE EXCEPTION 'optimization native controller population differs';END IF;seen:=seen||jsonb_build_object(instance_id,true);
 END LOOP;
 minimum:=minimum+(controller->>'Minimum')::integer;refs:=refs||jsonb_build_array(controller->'Reference');
 END LOOP;
 IF (SELECT count(*) FROM jsonb_object_keys(seen)) IS DISTINCT FROM population THEN reasons:='["AUTOSCALE_CONTROLLER_MEMBERSHIP_INCOMPLETE"]';EXIT assessment;END IF;
 IF minimum IS DISTINCT FROM (profile.document->>'min_replicas')::integer OR minimum<>population THEN reasons:='["AUTOSCALE_CAPACITY_ABOVE_MINIMUM_REQUIRES_OPTIMIZATION"]';EXIT assessment;END IF;
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(selected->'controllers') c WHERE c->'Maximum' IS DISTINCT FROM c->'Minimum') THEN reasons:='["AUTOSCALE_DYNAMIC_POLICY_ASSESSMENT_REQUIRED"]';EXIT assessment;END IF;
 disposition:='EVIDENCED_NO_CHANGE';reasons:='["NATIVE_FIXED_CAPACITY_EQUALS_OWNER_REQUIRED_REPLICA_FLOOR"]';
 END IF;
 END assessment;
 SELECT coalesce(jsonb_agg(v ORDER BY v->>'kind',v->>'id'),'[]') INTO refs FROM(SELECT DISTINCT v FROM jsonb_array_elements(refs) v) proofs;
 RETURN jsonb_build_object('disposition',disposition,'reason_codes',reasons,'input_refs',refs);
END $$;
REVOKE ALL ON FUNCTION commitment_optimization_policy_stage(text,text,jsonb,text) FROM PUBLIC;


-- CONNECTED ADDITIVE040: migrations/040_controller_renewal.sql.fragment
-- Private currentness proof. Acquisition and transport identity may renew;
-- the actual parsed ASG graph, registered role, source and whole roster may not.
CREATE FUNCTION commitment_controller_semantics(p_native jsonb) RETURNS jsonb
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,public,pg_temp AS $$
 SELECT (p_native-ARRAY['started_at','collected_at','raw_sha256','callers','memberships','groups'])||jsonb_build_object(
 'memberships',(SELECT jsonb_agg(v-'raw_page_sha256' ORDER BY v->>'instance_id') FROM jsonb_array_elements(p_native->'memberships') v),
 'groups',(SELECT jsonb_agg(v-'raw_page_sha256' ORDER BY v->'group'->>'arn') FROM jsonb_array_elements(p_native->'groups') v),
 -- A renewed STS session may have another session suffix. Its authenticated
 -- account, assumed role and stable role principal must remain the same.
 'callers',(SELECT jsonb_agg(v ORDER BY v->>'account_id',v->>'role_arn',v->>'role_principal') FROM(
 SELECT DISTINCT jsonb_build_object('account_id',c->>'account_id','role_arn',regexp_replace(c->>'arn','/[^/]+$',''),'role_principal',split_part(c->>'user_id',':',1)) v
 FROM jsonb_array_elements(p_native->'callers') c) principals));
$$;
REVOKE ALL ON FUNCTION commitment_controller_semantics(jsonb) FROM PUBLIC;

-- No direct EXECUTE grant. The policy resolver supplies its authenticated
-- current policy/scope and an original ref selected from actual sealed rows.
-- This function independently checks both ingester receipts and fresh source
-- state under the same graph/source fences; it never republishes old facts.
CREATE FUNCTION commitment_controller_current(p_tenant text,p_source text,p_workload text,p_scope jsonb,p_policy jsonb,p_original_ref jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE original public.source_receipts%ROWTYPE;latest public.source_receipts%ROWTYPE;receipt public.source_receipts%ROWTYPE;
 revision public.source_revisions%ROWTYPE;registration public.source_registrations%ROWTYPE;checkpoint jsonb;roster jsonb;
 current_ref jsonb;original_ref jsonb;native jsonb;semantics jsonb;original_semantics jsonb;document_scope jsonb;original_scope jsonb;
 expected_members jsonb;actual_members jsonb;stamp timestamptz;checked timestamptz;candidate text;count_rows bigint;size_bytes bigint;
BEGIN
 IF NOT public.commitment_portfolio_access(p_tenant) OR current_setting('transaction_isolation') IS DISTINCT FROM 'read committed' OR p_tenant IS DISTINCT FROM current_setting('app.tenant_id',true) THEN RAISE EXCEPTION 'optimization controller reader scope differs';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(p_tenant||':dependency-graph',0));
 IF NOT pg_try_advisory_xact_lock_shared(hashtextextended(p_tenant||':trusted-source:'||p_source,0)) THEN RAISE EXCEPTION 'optimization controller source busy';END IF;
 SELECT * INTO registration FROM public.source_registrations WHERE tenant_id=p_tenant AND id=p_source;
 SELECT document INTO checkpoint FROM public.source_checkpoints WHERE tenant_id=p_tenant AND source_id=p_source AND checkpoint_key='status';
 IF registration.id IS NULL OR registration.kind IS DISTINCT FROM 'AWS_CUR2' OR registration.document->'enabled' IS DISTINCT FROM 'true'::jsonb OR registration.document->'revoked'='true'::jsonb OR coalesce(registration.document->>'read_role_binding_id','')='' OR registration.document->>'region' IS DISTINCT FROM p_policy->>'region' OR NOT(registration.document->>'payer_account_id'=p_policy->>'account_id' OR coalesce(registration.document->'usage_account_ids' ? (p_policy->>'account_id'),false)) OR checkpoint->>'status' IS DISTINCT FROM 'HEALTHY' OR jsonb_typeof(checkpoint->'last_sync_at') IS DISTINCT FROM 'string' OR (checkpoint->>'last_sync_at')::timestamptz NOT BETWEEN clock_timestamp()-interval '5 minutes' AND clock_timestamp()+interval '5 seconds' OR checkpoint->>'config_hash' IS DISTINCT FROM public.fleet_history_source_config(registration.document) THEN RAISE EXCEPTION 'optimization controller current source differs';END IF;
 SELECT count(*),coalesce(sum(octet_length(document::text)),0) INTO count_rows,size_bytes FROM public.entities WHERE tenant_id=p_tenant AND kind='resources' AND document->>'resource_type'='EC2' AND document->>'workload_id'=p_workload AND document->>'provider'='AWS' AND document->>'account_id'=p_policy->>'account_id' AND document->>'region'=p_policy->>'region';
 IF count_rows NOT BETWEEN 1 AND 256 OR count_rows IS DISTINCT FROM jsonb_array_length(p_scope->'resource_ids') OR size_bytes>2097152 THEN RAISE EXCEPTION 'optimization controller current roster differs';END IF;
 SELECT jsonb_agg(document||jsonb_build_object('id',id,'version',version) ORDER BY id) INTO roster FROM public.entities WHERE tenant_id=p_tenant AND kind='resources' AND document->>'resource_type'='EC2' AND document->>'workload_id'=p_workload AND document->>'provider'='AWS' AND document->>'account_id'=p_policy->>'account_id' AND document->>'region'=p_policy->>'region';
 SELECT jsonb_agg(v->'provider_resource_id' ORDER BY v->>'provider_resource_id') INTO expected_members FROM jsonb_array_elements(roster) v;
 IF expected_members IS DISTINCT FROM p_scope->'resource_ids' OR EXISTS(SELECT 1 FROM jsonb_array_elements(roster) v WHERE coalesce(v->>'provider_resource_id','')!~'^i-([a-f0-9]{8}|[a-f0-9]{17})$') THEN RAISE EXCEPTION 'optimization controller current roster differs';END IF;
 SELECT * INTO latest FROM public.source_receipts r WHERE r.tenant_id=p_tenant AND r.source_id=p_source AND r.kind='AWS_CONTROLLER_DISCOVERY' AND r.document->'binding'->>'workload_id'=p_workload ORDER BY (r.document->>'collected_at')::timestamptz DESC,r.created_at DESC,r.id DESC LIMIT 1;
 IF latest.id IS NULL THEN RETURN NULL;END IF;
 IF p_original_ref IS NULL THEN original:=latest;ELSE
 IF NOT public.commitment_portfolio_keys(p_original_ref,ARRAY['kind','id','sha256']) OR p_original_ref->>'kind' IS DISTINCT FROM 'AWS_CONTROLLER_DISCOVERY' OR coalesce(p_original_ref->>'sha256','')!~'^[a-f0-9]{64}$' THEN RAISE EXCEPTION 'optimization original controller reference differs';END IF;
 SELECT * INTO original FROM public.source_receipts WHERE tenant_id=p_tenant AND id=p_original_ref->>'id' AND source_id=p_source AND kind='AWS_CONTROLLER_DISCOVERY';
 IF original.id IS NULL OR public.fleet_history_json_hash(original.document||jsonb_build_object('writer_role',original.writer_role,'created_at',original.created_at)) IS DISTINCT FROM p_original_ref->>'sha256' THEN RAISE EXCEPTION 'optimization original controller reference differs';END IF;END IF;
 FOREACH candidate IN ARRAY ARRAY[original.id,latest.id] LOOP
 SELECT * INTO receipt FROM public.source_receipts WHERE tenant_id=p_tenant AND id=candidate;
 SELECT * INTO revision FROM public.source_revisions WHERE tenant_id=p_tenant AND id=receipt.revision_id AND source_id=p_source;
 native:=receipt.document->'native';
 IF octet_length(receipt.document::text)>8388608 OR octet_length(revision.document::text)>8388608 OR receipt.writer_role IS DISTINCT FROM 'finops_ingester' OR revision.writer_role IS DISTINCT FROM 'finops_ingester' OR revision.document->>'kind' IS DISTINCT FROM 'AWS_CONTROLLER_DISCOVERY' OR receipt.document->>'id' IS DISTINCT FROM receipt.id OR receipt.document->>'source_id' IS DISTINCT FROM p_source OR receipt.document->>'revision_id' IS DISTINCT FROM revision.id OR receipt.document->'execution_authorized' IS DISTINCT FROM 'false'::jsonb OR receipt.document->>'config_hash' IS DISTINCT FROM checkpoint->>'config_hash' OR receipt.document->'registration_version' IS DISTINCT FROM to_jsonb(registration.version) OR receipt.document->>'read_role_binding_id' IS DISTINCT FROM registration.document->>'read_role_binding_id' OR receipt.document->>'roster_sha256' IS DISTINCT FROM public.fleet_history_json_hash(roster) OR receipt.document->'roster_snapshot' IS DISTINCT FROM roster OR receipt.document->'resource_ids' IS DISTINCT FROM expected_members OR receipt.document->'binding' IS DISTINCT FROM jsonb_build_object('tenant_id',p_tenant,'workload_id',p_workload,'provider','AWS','account_id',p_policy->>'account_id','region',p_policy->>'region') OR coalesce(receipt.document->>'binding_id','')='' OR coalesce(receipt.document->>'target_sha256','')!~'^[a-f0-9]{64}$' OR coalesce(receipt.document->>'controller_graph_sha256','')!~'^[a-f0-9]{64}$' THEN RAISE EXCEPTION 'optimization controller issued source scope differs';END IF;
 IF revision.document->'registration_version' IS DISTINCT FROM receipt.document->'registration_version' OR revision.document->'read_role_binding_id' IS DISTINCT FROM receipt.document->'read_role_binding_id' OR revision.document->'config_hash' IS DISTINCT FROM receipt.document->'config_hash' OR revision.document->'binding_id' IS DISTINCT FROM receipt.document->'binding_id' OR revision.document->'binding' IS DISTINCT FROM receipt.document->'binding' OR revision.document->'resource_ids' IS DISTINCT FROM receipt.document->'resource_ids' OR revision.document->'roster_sha256' IS DISTINCT FROM receipt.document->'roster_sha256' OR revision.document->'target_sha256' IS DISTINCT FROM receipt.document->'target_sha256' OR revision.document->'controller_graph_sha256' IS DISTINCT FROM receipt.document->'controller_graph_sha256' OR coalesce(revision.document->'raw_object'->>'version_id','') IN('','null') OR coalesce(receipt.document->'raw_object'->>'version_id','') IN('','null') OR coalesce(receipt.document->'raw_object'->>'body_sha256','')!~'^[a-f0-9]{64}$' OR revision.document->'raw_object'->>'body_sha256' IS DISTINCT FROM receipt.document->'raw_object'->>'body_sha256' THEN RAISE EXCEPTION 'optimization controller issued revision differs';END IF;
 IF native->>'schema_version' IS DISTINCT FROM '1' OR native->>'provider' IS DISTINCT FROM 'AWS' OR native->>'observation_basis' IS DISTINCT FROM 'BOUNDED_NON_ATOMIC_ASG_POINT_READ' OR native->>'account_id' IS DISTINCT FROM p_policy->>'account_id' OR native->>'region' IS DISTINCT FROM p_policy->>'region' OR native->'registered_instance_ids' IS DISTINCT FROM expected_members OR native->>'raw_sha256' IS DISTINCT FROM receipt.document->'raw_object'->>'body_sha256' OR receipt.document->'collected_at' IS DISTINCT FROM native->'collected_at' OR jsonb_typeof(native->'collected_at') IS DISTINCT FROM 'string' OR jsonb_typeof(native->'started_at') IS DISTINCT FROM 'string' OR (native->>'started_at')::timestamptz>(native->>'collected_at')::timestamptz OR jsonb_typeof(native->'groups') IS DISTINCT FROM 'array' OR jsonb_array_length(native->'groups')<>1 OR jsonb_typeof(native->'memberships') IS DISTINCT FROM 'array' OR jsonb_array_length(native->'memberships') IS DISTINCT FROM jsonb_array_length(expected_members) OR jsonb_typeof(native->'callers') IS DISTINCT FROM 'array' OR jsonb_array_length(native->'callers') NOT BETWEEN 1 AND 100 OR EXISTS(SELECT 1 FROM jsonb_array_elements(native->'callers') c WHERE c->>'account_id' IS DISTINCT FROM p_policy->>'account_id' OR coalesce(c->>'arn','')!~('^arn:aws:sts::'||(p_policy->>'account_id')||':assumed-role/[^/]+/[^/]+$') OR coalesce(c->>'user_id','')!~'^[^:]+:.+$' OR coalesce(c->>'raw_page_sha256','')!~'^[a-f0-9]{64}$') THEN RAISE EXCEPTION 'optimization controller native scope differs';END IF;
 SELECT jsonb_agg(v->'instance_id' ORDER BY v->>'instance_id') INTO actual_members FROM jsonb_array_elements(native->'memberships') v;
 IF actual_members IS DISTINCT FROM expected_members OR EXISTS(SELECT 1 FROM jsonb_array_elements(native->'memberships') v WHERE v->>'status' IS DISTINCT FROM 'ASG_MEMBER_OBSERVED' OR v->>'group_arn' IS DISTINCT FROM p_policy->>'asg_arn') OR native->'groups'->0->'group'->>'arn' IS DISTINCT FROM p_policy->>'asg_arn' THEN RAISE EXCEPTION 'optimization controller native membership differs';END IF;
 SELECT jsonb_agg(v->'instance_id' ORDER BY v->>'instance_id') INTO actual_members FROM jsonb_array_elements(native->'groups'->0->'group'->'members') v;
 IF actual_members IS DISTINCT FROM expected_members THEN RAISE EXCEPTION 'optimization controller native membership differs';END IF;
 semantics:=public.commitment_controller_semantics(native);
 document_scope:=receipt.document-ARRAY['id','revision_id','native','collected_at','raw_object'];
 IF candidate=original.id THEN original_semantics:=semantics;original_scope:=document_scope;
 ELSIF semantics IS DISTINCT FROM original_semantics OR document_scope IS DISTINCT FROM original_scope THEN RAISE EXCEPTION 'optimization controller observation changed';END IF;
 END LOOP;
 checked:=clock_timestamp();stamp:=(latest.document->>'collected_at')::timestamptz;
 IF stamp<checked-interval '2 minutes' OR stamp>checked+interval '5 seconds' OR (original.document->>'collected_at')::timestamptz>stamp OR EXISTS(SELECT 1 FROM public.source_receipts n WHERE n.tenant_id=p_tenant AND n.source_id=p_source AND n.kind='AWS_CONTROLLER_DISCOVERY' AND n.document->'binding'->>'workload_id'=p_workload AND (n.document->>'collected_at')::timestamptz=stamp AND (public.commitment_controller_semantics(n.document->'native') IS DISTINCT FROM semantics OR n.document->'controller_graph_sha256' IS DISTINCT FROM latest.document->'controller_graph_sha256')) THEN RAISE EXCEPTION 'optimization controller current observation differs';END IF;
 original_ref:=jsonb_build_object('kind','AWS_CONTROLLER_DISCOVERY','id',original.id,'sha256',public.fleet_history_json_hash(original.document||jsonb_build_object('writer_role',original.writer_role,'created_at',original.created_at)));
 current_ref:=jsonb_build_object('kind','AWS_CONTROLLER_DISCOVERY','id',latest.id,'sha256',public.fleet_history_json_hash(latest.document||jsonb_build_object('writer_role',latest.writer_role,'created_at',latest.created_at)));
 RETURN jsonb_build_object('original_receipt_id',original.id,'proof',jsonb_build_object('original_ref',original_ref,'latest_ref',current_ref,'observed_at',latest.document->'collected_at','checked_at',checked,'semantic_sha256',public.fleet_history_json_hash(semantics)));
END $$;
REVOKE ALL ON FUNCTION commitment_controller_current(text,text,text,jsonb,jsonb,jsonb) FROM PUBLIC;

-- Preserve policy/sizing semantics; only controller renewal selection changes.
CREATE OR REPLACE FUNCTION commitment_optimization_policy_inputs(p_tenant text,p_request text,p_scope jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE request jsonb;base jsonb;ownership jsonb;policy public.commitment_optimization_policies%ROWTYPE;p jsonb;policy_ref jsonb;
 candidate jsonb;joint record;input jsonb;template jsonb;joins jsonb:='[]';types jsonb:='[]';current_types jsonb:='{}';hardware_ids jsonb:='{}';member jsonb;hardware public.source_receipts%ROWTYPE;
 estimate bigint;total_bytes bigint:=0;sizing jsonb:=NULL;sizing_gap boolean:=false;controllers jsonb:='[]';controller_ref jsonb:=NULL;scope_ref jsonb:=NULL;receipt public.source_receipts%ROWTYPE;revision public.source_revisions%ROWTYPE;
 native jsonb;group_record jsonb;members jsonb;controller_current jsonb:=NULL;controller_selection jsonb;retained jsonb;retained_payload jsonb;retained_ref jsonb:=NULL;retained_count bigint;refs jsonb:='[]';reasons jsonb:='[]';source_key text;
BEGIN
 IF NOT public.commitment_portfolio_access(p_tenant) OR current_setting('transaction_isolation') IS DISTINCT FROM 'read committed' OR p_tenant IS DISTINCT FROM current_setting('app.tenant_id',true) THEN RAISE EXCEPTION 'optimization policy reader scope differs';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(p_tenant||':dependency-graph',0));
 request:=public.commitment_decision_request(p_tenant,p_request);
 IF request->>'purpose' IS DISTINCT FROM 'PREPARE' OR p_scope->>'tenant_id' IS DISTINCT FROM p_tenant OR p_scope->>'workload_id' IS DISTINCT FROM request->>'workload_id' OR p_scope->>'sha256' IS DISTINCT FROM public.fleet_history_json_hash(p_scope||'{"sha256":""}') THEN RAISE EXCEPTION 'optimization policy exact preparation required';END IF;
 base:=public.commitment_decision_base(p_tenant,request->>'workload_id',request->'selection');
 IF public.fleet_history_json_hash(base) IS DISTINCT FROM request->>'input_sha256' THEN RAISE EXCEPTION 'optimization current inputs changed';END IF;
 ownership:=public.commitment_decision_ownership_assert(p_tenant,request->>'workload_id',p_scope->'ownership_ref',(p_scope->'history_period'->>'start')::timestamptz,(p_scope->'history_period'->>'end')::timestamptz);
 PERFORM pg_advisory_xact_lock_shared(hashtextextended(p_tenant||':commitment-optimization-policy:'||(request->>'workload_id'),0));
 SELECT * INTO policy FROM public.commitment_optimization_policies p WHERE p.tenant_id=p_tenant AND p.workload_id=request->>'workload_id' ORDER BY p.revision DESC LIMIT 1;
 IF policy.id IS NULL OR EXISTS(SELECT 1 FROM public.commitment_optimization_policy_revocations r WHERE(r.tenant_id,r.id,r.revision)=(policy.tenant_id,policy.id,policy.revision)) OR (policy.document->>'valid_until')::timestamptz<=clock_timestamp() THEN RETURN jsonb_build_object('policy',NULL,'policy_ref',NULL,'registry_actor','','sizing',NULL,'controllers','[]'::jsonb,'controller_discovery_ref',NULL,'controller_scope_reference',NULL,'current_refs','[]'::jsonb,'reason_codes',jsonb_build_array('CUSTOMER_APPROVED_OPTIMIZATION_POLICY_UNAVAILABLE'));END IF;
 p:=policy.document;
 IF p->>'ownership_scope_sha256' IS DISTINCT FROM public.fleet_history_json_hash(ownership->'scope') OR p->>'configuration_sha256' IS DISTINCT FROM p_scope->>'configuration_sha256' OR p->'resource_ids' IS DISTINCT FROM p_scope->'resource_ids' OR p->>'source_id' IS DISTINCT FROM base->'portfolio'->'selection'->>'source_id' THEN RAISE EXCEPTION 'optimization customer policy current scope differs';END IF;
 source_key:=p->>'source_id';
 policy_ref:=jsonb_build_object('kind','WORKLOAD_SIZE_CONSTRAINT','id',policy.id,'sha256',public.fleet_history_json_hash(p||jsonb_build_object('registry_actor',policy.registry_actor,'operator_recorded_at',policy.operator_recorded_at)));
 refs:=jsonb_build_array(policy_ref);
 FOR candidate IN SELECT value FROM jsonb_array_elements(p->'allowed_candidates') LOOP
 types:=types||jsonb_build_array(candidate->>'instance_type');
 SELECT r.id,r.assessment_request_id,r.capacity_request_id,d.document,d.content_hash INTO joint FROM public.fleet_joint_decision_requests r JOIN public.fleet_joint_decisions d ON d.tenant_id=r.tenant_id AND d.request_id=r.id WHERE r.tenant_id=p_tenant AND r.workload_id=request->>'workload_id' AND r.document->'selection'->'groups'->'old_configuration_proposal'->>'id'=p->>'old_proposal_id' AND r.document->'selection'->'groups'->'candidate_configuration_proposal'->>'id'=candidate->>'proposal_id' ORDER BY d.created_at DESC,d.id DESC LIMIT 1;
 IF joint.id IS NULL THEN sizing_gap:=true;CONTINUE;END IF;
 SELECT coalesce(sum(octet_length(m.raw_document)),0)+(SELECT coalesce(octet_length(a.raw_document),0) FROM public.fleet_native_assessments a WHERE a.tenant_id=p_tenant AND a.request_id=joint.assessment_request_id)+(SELECT coalesce(octet_length(s.raw_document),0) FROM public.fleet_native_capacity_scopes s WHERE s.tenant_id=p_tenant AND s.request_id=joint.capacity_request_id)+(SELECT coalesce(octet_length(b.raw_document),0) FROM public.fleet_native_capacity_batches b WHERE b.tenant_id=p_tenant AND b.request_id=joint.capacity_request_id) INTO estimate FROM public.fleet_native_capacity_members m WHERE m.tenant_id=p_tenant AND m.request_id=joint.capacity_request_id;
 IF estimate IS NULL OR estimate>8388608 OR total_bytes+estimate>33554432 THEN RAISE EXCEPTION 'optimization candidate input byte limit';END IF;total_bytes:=total_bytes+estimate;
 BEGIN input:=public.commitment_optimization_joint_inputs(p_tenant,joint.assessment_request_id,joint.capacity_request_id)||jsonb_build_object('request_id',joint.id);EXCEPTION WHEN raise_exception THEN sizing_gap:=true;CONTINUE;END;
 template:=input->'scope'->'candidate_template';
 IF template IS NULL OR template='null'::jsonb OR template->>'instance_type' IS DISTINCT FROM candidate->>'instance_type' OR template->>'id' IS DISTINCT FROM candidate->>'template_id' OR template->>'version' IS DISTINCT FROM candidate->>'template_version' OR template->>'image_id' IS DISTINCT FROM candidate->>'image_id' OR input->'scope'->'scope'->'current_member_ids' IS DISTINCT FROM p_scope->'resource_ids' OR input->'scope'->'scope'->'selection'->'groups'->'binding'->'old'->'target'->>'asg_arn' IS DISTINCT FROM p->>'asg_arn' THEN sizing_gap:=true;CONTINUE;END IF;
 FOR member IN SELECT value->'document' FROM jsonb_array_elements(input->'members') LOOP
 SELECT * INTO hardware FROM public.source_receipts h WHERE h.tenant_id=p_tenant AND h.id=member->'hardware'->>'receipt_id' AND h.kind='AWS_EC2_HARDWARE' AND h.writer_role='finops_ingester' AND h.source_id=source_key;
 IF hardware.id IS NULL OR hardware.document->'native'->'instance'->>'id' IS DISTINCT FROM member->>'instance_id' OR hardware.document->'native'->>'account_id' IS DISTINCT FROM p->>'account_id' OR hardware.document->'native'->>'region' IS DISTINCT FROM p->>'region' OR coalesce(hardware.document->'native'->'instance'->>'instance_type','')='' THEN sizing_gap:=true;EXIT;END IF;
 IF hardware_ids ? (member->>'instance_id') AND hardware_ids->>(member->>'instance_id') IS DISTINCT FROM hardware.id THEN sizing_gap:=true;EXIT;END IF;
 hardware_ids:=hardware_ids||jsonb_build_object(member->>'instance_id',hardware.id);current_types:=current_types||jsonb_build_object(member->>'instance_id',hardware.document->'native'->'instance'->>'instance_type');
 END LOOP;
 joins:=joins||jsonb_build_array(jsonb_build_object('Input',input,'Reference',jsonb_build_object('kind','FLEET_JOINT_DECISION','id',joint.id,'sha256',joint.content_hash),'ObservedAt',joint.document->'observed_at'));
 END LOOP;
 IF sizing_gap OR jsonb_array_length(joins) IS DISTINCT FROM jsonb_array_length(types) OR (SELECT count(*) FROM jsonb_object_keys(current_types)) IS DISTINCT FROM jsonb_array_length(p_scope->'resource_ids') OR EXISTS(SELECT 1 FROM jsonb_each_text(current_types) t WHERE NOT(types ? t.value)) THEN reasons:=reasons||jsonb_build_array('RIGHTSIZE_CURRENT_PASS_AND_ALL_APPROVED_ALTERNATIVES_UNAVAILABLE');ELSE sizing:=jsonb_build_object('Reference',policy_ref,'ConfigurationSHA256',p_scope->>'configuration_sha256','AllowedInstanceTypes',types,'CurrentInstanceTypes',current_types,'Joins',joins);END IF;
 -- Positive native association for the entire scope is mandatory. An absent
 -- ASG row never implies unmanaged, and customer scope remains a separate ref.
 IF p->>'controller_scope'='CUSTOMER_REVIEWED_CONFIGURATION_ASG_ONLY' THEN
 -- The original ref comes only from the server-published retained AUTOSCALE
 -- decision. A caller cannot choose an older receipt to mask changed facts.
 SELECT count(*) INTO retained_count FROM public.entities e WHERE e.tenant_id=p_tenant AND e.kind='commitment_decision_evidence' AND e.document->>'request_id'=p_request AND e.document->>'kind'='OPTIMIZATION_DECISION' AND e.document->'payload'->>'stage'='AUTOSCALE';
 IF retained_count>1 THEN RAISE EXCEPTION 'optimization retained controller decision ambiguous';END IF;
 IF retained_count=1 THEN
 SELECT e.document INTO retained FROM public.entities e WHERE e.tenant_id=p_tenant AND e.kind='commitment_decision_evidence' AND e.document->>'request_id'=p_request AND e.document->>'kind'='OPTIMIZATION_DECISION' AND e.document->'payload'->>'stage'='AUTOSCALE';
 retained_payload:=retained->'payload';
 IF retained->>'writer_role' IS DISTINCT FROM 'finops_commitment_portfolio' OR retained->>'workload_id' IS DISTINCT FROM request->>'workload_id' OR retained->'selection' IS DISTINCT FROM request->'selection' OR retained->>'base_sha256' IS DISTINCT FROM request->>'input_sha256' OR retained->>'scope_sha256' IS DISTINCT FROM p_scope->>'sha256' OR retained->>'payload_sha256' IS DISTINCT FROM public.fleet_history_json_hash(retained_payload) OR retained->>'id' IS DISTINCT FROM retained_payload->>'id' OR retained_payload->>'id' IS DISTINCT FROM public.fleet_history_json_hash(retained_payload||'{"id":""}') OR retained_payload->>'request_id' IS DISTINCT FROM p_request OR retained_payload->>'scope_sha256' IS DISTINCT FROM p_scope->>'sha256' OR retained_payload->'execution_authorized' IS DISTINCT FROM 'false'::jsonb OR retained_payload->'verified_saving' IS DISTINCT FROM 'null'::jsonb OR jsonb_typeof(retained_payload->'input_refs') IS DISTINCT FROM 'array' THEN RAISE EXCEPTION 'optimization retained controller decision differs';END IF;
 SELECT count(*) INTO retained_count FROM jsonb_array_elements(retained_payload->'input_refs') v WHERE v->>'kind'='AWS_CONTROLLER_DISCOVERY';
 IF retained_count>1 THEN RAISE EXCEPTION 'optimization retained controller reference ambiguous';END IF;
 IF retained_count=1 THEN SELECT v INTO retained_ref FROM jsonb_array_elements(retained_payload->'input_refs') v WHERE v->>'kind'='AWS_CONTROLLER_DISCOVERY';END IF;
 END IF;
 controller_selection:=public.commitment_controller_current(p_tenant,source_key,request->>'workload_id',p_scope,p,retained_ref);
 IF controller_selection IS NOT NULL THEN
 SELECT * INTO receipt FROM public.source_receipts r WHERE r.tenant_id=p_tenant AND r.id=controller_selection->>'original_receipt_id';
 native:=receipt.document->'native';group_record:=native->'groups'->0->'group';
 SELECT jsonb_agg(to_jsonb(m->>'instance_id') ORDER BY m->>'instance_id') INTO members FROM jsonb_array_elements(group_record->'members') m;
 IF group_record->>'arn'=p->>'asg_arn' AND members=p_scope->'resource_ids' AND jsonb_typeof(group_record->'minimum')='number' AND jsonb_typeof(group_record->'maximum')='number' AND jsonb_typeof(group_record->'desired')='number' THEN
 controller_ref:=controller_selection->'proof'->'original_ref';controller_current:=controller_selection->'proof';
 scope_ref:=policy_ref||jsonb_build_object('kind','WORKLOAD_CONTROLLER_SCOPE');
 controllers:=jsonb_build_array(jsonb_build_object('Reference',controller_ref,'ConfigurationSHA256',p_scope->>'configuration_sha256','MemberIDs',members,'Minimum',group_record->'minimum','Maximum',group_record->'maximum','Desired',group_record->'desired'));refs:=refs||jsonb_build_array(controller_ref,scope_ref);
 END IF;END IF;END IF;
 IF controller_ref IS NULL THEN reasons:=reasons||jsonb_build_array('AUTOSCALE_POSITIVE_NATIVE_ASG_AND_APPROVED_CONFIGURATION_SCOPE_UNAVAILABLE');END IF;
 RETURN jsonb_build_object('policy',p,'policy_ref',policy_ref,'registry_actor',policy.registry_actor,'sizing',sizing,'controllers',controllers,'controller_discovery_ref',controller_ref,'controller_current',controller_current,'controller_scope_reference',scope_ref,'current_refs',refs,'reason_codes',reasons);
END $$;
REVOKE ALL ON FUNCTION commitment_optimization_policy_inputs(text,text,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION commitment_optimization_policy_inputs(text,text,jsonb) TO finops_commitment_portfolio;



-- CONNECTED ADDITIVE040: migrations/040_artifact_resource_binding.sql.fragment
-- Decision-only attestor projection. Existing artifact metadata, signatures and
-- old NULL rows remain immutable/visible; NULL never establishes new advice.
ALTER TABLE public.configuration_artifact_readback_proofs ADD COLUMN resource_binding jsonb;

CREATE FUNCTION commitment_artifact_resource_binding_assert(p_tenant text,p_receipt jsonb,p_binding jsonb) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE metadata jsonb:=p_receipt->'metadata';cfg jsonb;resource jsonb;BEGIN
 IF p_binding IS NULL OR NOT public.commitment_portfolio_keys(p_binding,ARRAY['schema_version','basis','terraform_address','binding','resource_arn','instance_type','state_lineage','state_serial','bundle_sha256','state_sha256'])
 OR p_binding->>'schema_version' IS DISTINCT FROM '1' OR p_binding->>'basis' IS DISTINCT FROM 'ATTESTED_TERRAFORM_AWS_INSTANCE_CURRENT_STATE'
 OR jsonb_typeof(p_binding->'terraform_address') IS DISTINCT FROM 'string' OR p_binding->>'terraform_address'='' OR octet_length(p_binding->>'terraform_address')>1024
 OR p_binding->'binding' IS DISTINCT FROM metadata->'binding' OR p_binding->'binding'->>'tenant_id' IS DISTINCT FROM p_tenant OR p_binding->'binding'->>'provider' IS DISTINCT FROM 'AWS'
 OR coalesce(p_binding->'binding'->>'provider_resource_id','')!~'^i-[a-f0-9]{17}$'
 OR p_binding->>'resource_arn' IS DISTINCT FROM 'arn:aws:ec2:'||(metadata->'binding'->>'region')||':'||(metadata->'binding'->>'account_id')||':instance/'||(metadata->'binding'->>'provider_resource_id')
 OR coalesce(p_binding->>'instance_type','')!~'^[a-z][a-z0-9-]*\.[a-z0-9]+$'
 OR p_binding->>'state_lineage' IS DISTINCT FROM metadata->'state'->>'lineage' OR p_binding->'state_serial' IS DISTINCT FROM metadata->'state'->'serial'
 OR p_binding->>'bundle_sha256' IS DISTINCT FROM metadata->>'bundle_sha256' OR p_binding->>'state_sha256' IS DISTINCT FROM metadata->>'state_sha256'
 OR metadata->'execution_authorized' IS DISTINCT FROM 'false'::jsonb OR metadata->'verified_saving' IS DISTINCT FROM 'null'::jsonb
 OR jsonb_typeof(metadata->'reason_codes') IS DISTINCT FROM 'array'
 OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(metadata->'reason_codes') r WHERE starts_with(r,'CONFIGURATION_') AND r<>'CONFIGURATION_EXTERNAL_PROVIDER_UNSUPPORTED')
 THEN RAISE EXCEPTION 'ownership artifact resource binding unobserved';END IF;
 cfg:=public.configuration_artifact_current(p_tenant,metadata->>'registration_id',(metadata->>'registration_version')::bigint);
 IF cfg->'binding' IS DISTINCT FROM p_binding->'binding' OR NOT(cfg->'declaration'->'terraform'->'addresses' ? (p_binding->>'terraform_address')) THEN RAISE EXCEPTION 'ownership artifact declared address differs';END IF;
 SELECT document INTO resource FROM public.entities WHERE tenant_id=p_tenant AND kind='resources' AND id=metadata->'binding'->>'resource_id';
 IF resource IS NULL OR resource->>'provider_resource_id' IS DISTINCT FROM metadata->'binding'->>'provider_resource_id' OR resource->>'account_id' IS DISTINCT FROM metadata->'binding'->>'account_id' OR resource->>'region' IS DISTINCT FROM metadata->'binding'->>'region'
 OR resource->>'instance_type' IS DISTINCT FROM p_binding->>'instance_type' THEN RAISE EXCEPTION 'ownership artifact current native resource differs';END IF;
END $$;
REVOKE ALL ON FUNCTION commitment_artifact_resource_binding_assert(text,jsonb,jsonb) FROM PUBLIC;

CREATE FUNCTION guard_commitment_artifact_resource_binding() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$ BEGIN
 IF current_setting('role',true) IS DISTINCT FROM 'finops_configuration_attestor' OR NEW.tenant_id IS DISTINCT FROM current_setting('app.tenant_id',true) THEN RAISE EXCEPTION 'authenticated artifact attestor required';END IF;
 IF NEW.resource_binding IS NOT NULL THEN PERFORM public.commitment_artifact_resource_binding_assert(NEW.tenant_id,NEW.receipt,NEW.resource_binding);END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION guard_commitment_artifact_resource_binding() FROM PUBLIC;
CREATE TRIGGER resource_binding BEFORE INSERT ON public.configuration_artifact_readback_proofs FOR EACH ROW EXECUTE FUNCTION guard_commitment_artifact_resource_binding();

CREATE OR REPLACE FUNCTION commitment_ownership_artifact_assert(p_tenant text,p_id text,p_sha text,p_archive jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE proof public.configuration_artifact_readback_proofs%ROWTYPE;receipt public.configuration_artifact_receipts%ROWTYPE;cfg jsonb;BEGIN
 SELECT * INTO proof FROM public.configuration_artifact_readback_proofs WHERE tenant_id=p_tenant AND receipt_id=p_id;
 SELECT * INTO receipt FROM public.configuration_artifact_receipts WHERE tenant_id=p_tenant AND id=p_id AND writer_role='finops_configuration_attestor';
 IF receipt.id IS NULL OR proof.receipt_id IS NULL OR proof.writer_role<>'finops_configuration_attestor' OR public.fleet_history_json_hash(proof.receipt) IS DISTINCT FROM p_sha OR proof.receipt_sha256 IS DISTINCT FROM p_sha OR proof.metadata_sha256 IS DISTINCT FROM public.fleet_history_json_hash(receipt.document->'metadata') OR proof.archive IS DISTINCT FROM p_archive OR receipt.document->'archive' IS DISTINCT FROM p_archive OR octet_length(proof.ciphertext) IS DISTINCT FROM (p_archive->>'bytes')::bigint OR encode(sha256(proof.ciphertext),'hex') IS DISTINCT FROM p_archive->>'sha256' THEN RAISE EXCEPTION 'ownership attested readback differs';END IF;
 cfg:=public.configuration_artifact_current(p_tenant,proof.registration_id,proof.registration_version);
 IF receipt.document->'metadata'->>'registration_hash' IS DISTINCT FROM (SELECT r.content_hash FROM public.configuration_artifact_registrations r WHERE r.tenant_id=p_tenant AND r.id=proof.registration_id AND r.version=proof.registration_version) OR receipt.document->'metadata'->'binding' IS DISTINCT FROM cfg->'binding' OR receipt.document->'metadata'->>'authority_id' IS DISTINCT FROM cfg->>'authority_id' OR receipt.document->'metadata'->>'authority_hash' IS DISTINCT FROM cfg->>'authority_hash' THEN RAISE EXCEPTION 'ownership artifact registration changed';END IF;
 PERFORM public.commitment_artifact_resource_binding_assert(p_tenant,proof.receipt,proof.resource_binding);
 RETURN proof.receipt;
END $$;
REVOKE ALL ON FUNCTION commitment_ownership_artifact_assert(text,text,text,jsonb) FROM PUBLIC;
