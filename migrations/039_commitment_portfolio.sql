-- Isolated candidate: read-only analysis of already-issued commitments/CUR.
-- No changes to legacy receipt issuance, execution or financial-ledger grants.
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='finops_commitment_portfolio') THEN
 CREATE ROLE finops_commitment_portfolio NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
 ELSIF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='finops_commitment_portfolio' AND (rolcanlogin OR rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls)) THEN
 RAISE EXCEPTION 'portfolio shared analytical role attributes differ';
 END IF;
END $$;
GRANT USAGE ON SCHEMA public TO finops_commitment_portfolio;
CREATE TABLE commitment_portfolio_credentials(
 id uuid PRIMARY KEY,database_login name NOT NULL,role_oid oid NOT NULL UNIQUE,
 tenant_id text NOT NULL CHECK(tenant_id~'^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'),
 installed_by name NOT NULL DEFAULT session_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),UNIQUE(database_login,role_oid)
);
CREATE TABLE commitment_portfolio_revocations(credential_id uuid PRIMARY KEY REFERENCES commitment_portfolio_credentials(id),reason_code text NOT NULL CHECK(reason_code~'^[A-Z][A-Z0-9_]{0,127}$'),created_at timestamptz NOT NULL DEFAULT clock_timestamp());
REVOKE ALL ON commitment_portfolio_credentials,commitment_portfolio_revocations FROM PUBLIC,finops_api,finops_commitment_portfolio;
CREATE FUNCTION commitment_portfolio_scope(p_tenant text) RETURNS boolean LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
 SELECT coalesce(current_setting('transaction_isolation')='read committed' AND p_tenant=current_setting('app.tenant_id',true) AND EXISTS(
 SELECT 1 FROM public.commitment_portfolio_credentials c JOIN pg_roles r ON r.oid=c.role_oid AND r.rolname=c.database_login
 WHERE c.tenant_id=p_tenant AND r.rolname=session_user AND r.rolcanlogin AND NOT(r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolbypassrls OR r.rolreplication)
 AND pg_has_role(r.oid,'finops_commitment_portfolio','MEMBER') AND NOT EXISTS(SELECT 1 FROM pg_roles x WHERE pg_has_role(r.oid,x.oid,'MEMBER') AND x.rolname NOT IN(r.rolname,'finops_commitment_portfolio'))
 AND NOT EXISTS(SELECT 1 FROM public.commitment_portfolio_revocations v WHERE v.credential_id=c.id)),false)
$$;
CREATE FUNCTION commitment_portfolio_access(p_tenant text) RETURNS boolean LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
 SELECT p_tenant=current_setting('app.tenant_id',true) AND CASE WHEN pg_has_role(session_user,'finops_commitment_portfolio','MEMBER') THEN public.commitment_portfolio_scope(p_tenant)
 ELSE current_setting('role',true)='finops_api' AND pg_has_role(session_user,'finops_api','MEMBER') END
$$;
REVOKE ALL ON FUNCTION commitment_portfolio_scope(text),commitment_portfolio_access(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION commitment_portfolio_scope(text) TO finops_commitment_portfolio;
GRANT EXECUTE ON FUNCTION commitment_portfolio_access(text) TO finops_commitment_portfolio,finops_api;
CREATE FUNCTION guard_commitment_portfolio_credential() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE r pg_roles%ROWTYPE;binding public.commitment_portfolio_credentials%ROWTYPE;BEGIN
 IF TG_TABLE_NAME='commitment_portfolio_credentials' THEN
 NEW.installed_by:=session_user;NEW.created_at:=clock_timestamp();
 SELECT * INTO r FROM pg_roles WHERE oid=NEW.role_oid;
 IF r.rolname IS DISTINCT FROM NEW.database_login OR NOT r.rolcanlogin OR r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolbypassrls OR r.rolreplication OR NOT pg_has_role(r.oid,'finops_commitment_portfolio','MEMBER') OR EXISTS(SELECT 1 FROM pg_roles x WHERE pg_has_role(r.oid,x.oid,'MEMBER') AND x.rolname NOT IN(r.rolname,'finops_commitment_portfolio')) THEN RAISE EXCEPTION 'portfolio dedicated login/OID required';END IF;
 ELSE SELECT * INTO binding FROM public.commitment_portfolio_credentials WHERE id=NEW.credential_id;IF binding.id IS NULL THEN RAISE EXCEPTION 'portfolio credential missing';END IF;PERFORM pg_advisory_xact_lock(hashtextextended('commitment-portfolio-credential:'||binding.database_login::text,0));END IF;RETURN NEW;
END $$;
CREATE TRIGGER portfolio_credential_install BEFORE INSERT ON commitment_portfolio_credentials FOR EACH ROW EXECUTE FUNCTION guard_commitment_portfolio_credential();
CREATE TRIGGER portfolio_credential_revoke BEFORE INSERT ON commitment_portfolio_revocations FOR EACH ROW EXECUTE FUNCTION guard_commitment_portfolio_credential();

CREATE TABLE commitment_portfolio_requests(
 tenant_id text NOT NULL,id text NOT NULL,creator_id text NOT NULL,idempotency_key text NOT NULL,
 selection jsonb NOT NULL,input_refs jsonb NOT NULL,input_hash text NOT NULL CHECK(input_hash~'^[a-f0-9]{64}$'),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(tenant_id,id),UNIQUE(tenant_id,creator_id,idempotency_key),
 CHECK(octet_length(selection::text)<=8192 AND octet_length(input_refs::text)<=65536)
);
CREATE TABLE commitment_portfolio_results(
 tenant_id text NOT NULL,request_id text NOT NULL,status text NOT NULL CHECK(status IN('ASSESSED','REFUSED')),
 document jsonb NOT NULL,content_hash text NOT NULL CHECK(content_hash~'^[a-f0-9]{64}$'),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),writer_role name NOT NULL DEFAULT current_user,
 PRIMARY KEY(tenant_id,request_id),FOREIGN KEY(tenant_id,request_id) REFERENCES commitment_portfolio_requests(tenant_id,id),CHECK(octet_length(document::text)<=2097152)
);
DO $$ DECLARE tab text;BEGIN
 FOREACH tab IN ARRAY ARRAY['commitment_portfolio_credentials','commitment_portfolio_revocations'] LOOP
 EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',tab);EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',tab);
 EXECUTE format('CREATE POLICY operator_only ON public.%I TO %I USING(true) WITH CHECK(true)',tab,current_user);
 EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON public.%I FOR EACH ROW EXECUTE FUNCTION public.deny_evidence_mutation()',tab||'_immutable',tab);
 END LOOP;
 FOREACH tab IN ARRAY ARRAY['commitment_portfolio_requests','commitment_portfolio_results'] LOOP
 EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',tab);EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',tab);
 EXECUTE format('CREATE POLICY tenant_scope ON public.%I USING(public.commitment_portfolio_access(tenant_id)) WITH CHECK(public.commitment_portfolio_access(tenant_id))',tab);
 EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON public.%I FOR EACH ROW EXECUTE FUNCTION public.deny_evidence_mutation()',tab||'_immutable',tab);
 END LOOP;
END $$;
GRANT SELECT,INSERT ON commitment_portfolio_requests TO finops_api;
GRANT SELECT ON commitment_portfolio_requests,commitment_portfolio_results TO finops_commitment_portfolio,finops_api;
GRANT INSERT ON commitment_portfolio_results TO finops_commitment_portfolio;
GRANT EXECUTE ON FUNCTION fleet_history_json_hash(jsonb),fleet_history_json_text(jsonb) TO finops_commitment_portfolio;

CREATE FUNCTION commitment_portfolio_keys(value jsonb,allowed text[]) RETURNS boolean LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,public,pg_temp AS $$ SELECT coalesce(jsonb_typeof(value)='object' AND (SELECT count(*) FROM jsonb_object_keys(value))=cardinality(allowed) AND NOT EXISTS(SELECT 1 FROM jsonb_object_keys(value) key WHERE NOT key=ANY(allowed)),false) $$;
CREATE FUNCTION commitment_portfolio_strings(value jsonb,maximum integer) RETURNS boolean LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,public,pg_temp AS $$ SELECT CASE WHEN jsonb_typeof(value)='array' THEN jsonb_array_length(value)<=maximum AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(value) v WHERE jsonb_typeof(v)<>'string' OR length(v#>>'{}') NOT BETWEEN 1 AND 1024) ELSE false END $$;
REVOKE ALL ON FUNCTION commitment_portfolio_keys(jsonb,text[]),commitment_portfolio_strings(jsonb,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION commitment_portfolio_keys(jsonb,text[]),commitment_portfolio_strings(jsonb,integer) TO finops_api,finops_commitment_portfolio;

-- Select source-owned facts only. No API DTO can supply an amount or proof.
CREATE FUNCTION commitment_portfolio_resolve(p_tenant text,p_selection jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE reg public.source_registrations%ROWTYPE;checkpoint jsonb;commitment public.source_receipts%ROWTYPE;receipt public.source_receipts%ROWTYPE;revision public.source_revisions%ROWTYPE;job jsonb;billing jsonb:='[]';rid text;source_id text:=p_selection->>'source_id';bytes bigint:=0;BEGIN
 IF NOT public.commitment_portfolio_access(p_tenant) THEN RAISE EXCEPTION 'portfolio credential scope differs';END IF;
 IF NOT public.commitment_portfolio_keys(p_selection,ARRAY['source_id','commitment_receipt_id','billing_receipt_ids','period']) OR NOT public.commitment_portfolio_keys(p_selection->'period',ARRAY['start','end']) OR p_selection->>'source_id'!~'^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$' OR p_selection->>'commitment_receipt_id'!~'^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$' OR NOT public.commitment_portfolio_strings(p_selection->'billing_receipt_ids',24) OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(p_selection->'billing_receipt_ids') id GROUP BY id HAVING count(*)>1) THEN RAISE EXCEPTION 'portfolio selection differs';END IF;
 IF (p_selection->'period'->>'start')!~'(Z|[+]00:00)$' OR (p_selection->'period'->>'end')!~'(Z|[+]00:00)$' OR (p_selection->'period'->>'end')::timestamptz>clock_timestamp() OR (p_selection->'period'->>'end')::timestamptz-(p_selection->'period'->>'start')::timestamptz NOT BETWEEN interval '1 day' AND interval '31 days' OR date_trunc('day',(p_selection->'period'->>'start')::timestamptz AT TIME ZONE 'UTC') IS DISTINCT FROM ((p_selection->'period'->>'start')::timestamptz AT TIME ZONE 'UTC') OR date_trunc('day',(p_selection->'period'->>'end')::timestamptz AT TIME ZONE 'UTC') IS DISTINCT FROM ((p_selection->'period'->>'end')::timestamptz AT TIME ZONE 'UTC') THEN RAISE EXCEPTION 'portfolio UTC days differ';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(p_tenant||':dependency-graph',0));
 IF NOT pg_try_advisory_xact_lock_shared(hashtextextended(p_tenant||':trusted-source:'||source_id,0)) THEN RAISE EXCEPTION 'portfolio source busy';END IF;
 IF pg_has_role(session_user,'finops_commitment_portfolio','MEMBER') THEN
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('commitment-portfolio-credential:'||session_user::text,0));IF NOT public.commitment_portfolio_scope(p_tenant) THEN RAISE EXCEPTION 'portfolio credential revoked';END IF;END IF;
 SELECT * INTO reg FROM public.source_registrations WHERE tenant_id=p_tenant AND id=source_id;
 SELECT document INTO checkpoint FROM public.source_checkpoints WHERE tenant_id=p_tenant AND source_checkpoints.source_id=reg.id AND checkpoint_key='status';
 IF reg.id IS NULL OR reg.kind<>'AWS_CUR2' OR reg.document->'enabled' IS DISTINCT FROM 'true'::jsonb OR reg.document->'revoked'='true'::jsonb OR checkpoint->>'status' IS DISTINCT FROM 'HEALTHY' OR checkpoint->>'last_sync_at' IS NULL OR (checkpoint->>'last_sync_at')::timestamptz<clock_timestamp()-interval '5 minutes' OR (checkpoint->>'last_sync_at')::timestamptz>clock_timestamp()+interval '5 seconds' THEN RAISE EXCEPTION 'portfolio source not current';END IF;
 SELECT octet_length(document::text) INTO bytes FROM public.source_receipts WHERE tenant_id=p_tenant AND id=p_selection->>'commitment_receipt_id';IF coalesce(bytes,0)>33554432 THEN RAISE EXCEPTION 'portfolio input byte limit';END IF;
 SELECT * INTO commitment FROM public.source_receipts WHERE tenant_id=p_tenant AND id=p_selection->>'commitment_receipt_id' AND source_receipts.source_id=reg.id AND kind='AWS_COMMITMENT' AND writer_role='finops_ingester';
 IF commitment.id IS NULL OR checkpoint->>'commitment_receipt_id' IS DISTINCT FROM commitment.id OR commitment.document->>'config_hash' IS DISTINCT FROM checkpoint->>'config_hash' THEN RAISE EXCEPTION 'portfolio inventory changed';END IF;
 bytes:=octet_length(commitment.document::text);
 IF jsonb_typeof(p_selection->'billing_receipt_ids') IS DISTINCT FROM 'array' OR jsonb_array_length(p_selection->'billing_receipt_ids')>24 THEN RAISE EXCEPTION 'portfolio receipt limit';END IF;
 FOR rid IN SELECT jsonb_array_elements_text(p_selection->'billing_receipt_ids') LOOP
 IF bytes+coalesce((SELECT octet_length(r.document::text)+octet_length(v.document::text)+octet_length(j.document::text) FROM public.source_receipts r JOIN public.source_revisions v ON v.tenant_id=r.tenant_id AND v.id=r.revision_id JOIN public.entities j ON j.tenant_id=r.tenant_id AND j.kind='ingestion_jobs' AND j.id=r.document->>'ingestion_job_id' WHERE r.tenant_id=p_tenant AND r.id=rid),0)>33554432 THEN RAISE EXCEPTION 'portfolio input byte limit';END IF;
 SELECT * INTO receipt FROM public.source_receipts WHERE tenant_id=p_tenant AND id=rid AND source_receipts.source_id=reg.id AND kind='AWS_CUR2' AND writer_role='finops_ingester';
 SELECT * INTO revision FROM public.source_revisions WHERE tenant_id=p_tenant AND id=receipt.revision_id AND source_revisions.source_id=reg.id AND writer_role='finops_ingester';
 SELECT document INTO job FROM public.entities WHERE tenant_id=p_tenant AND kind='ingestion_jobs' AND id=receipt.document->>'ingestion_job_id';
 IF receipt.id IS NULL OR revision.id IS NULL OR job IS NULL OR job->>'status'<>'PERSISTED' OR receipt.document->>'config_hash' IS DISTINCT FROM commitment.document->>'config_hash' OR NOT EXISTS(SELECT 1 FROM public.source_checkpoints c WHERE c.tenant_id=p_tenant AND c.source_id=reg.id AND c.checkpoint_key LIKE 'month:'||(commitment.document->>'config_hash')||':%' AND c.document->>'receipt_id'=rid) THEN RAISE EXCEPTION 'portfolio billing changed';END IF;
 bytes:=bytes+octet_length(job::text)+octet_length(receipt.document::text)+octet_length(revision.document::text);IF bytes>33554432 THEN RAISE EXCEPTION 'portfolio input byte limit';END IF;
 billing:=billing||jsonb_build_array(jsonb_build_object('receipt',receipt.document||jsonb_build_object('writer_role',receipt.writer_role),'revision',revision.document||jsonb_build_object('writer_role',revision.writer_role),'job',job,'current_receipt_id',rid));
 END LOOP;
 RETURN jsonb_build_object('tenant_id',p_tenant,'selection',p_selection,'registration',reg.document||checkpoint||jsonb_build_object('id',reg.id,'tenant_id',p_tenant,'version',reg.version),'checkpoint',checkpoint,'commitment',commitment.document||jsonb_build_object('writer_role',commitment.writer_role),'billing',billing);
END $$;
REVOKE ALL ON FUNCTION commitment_portfolio_resolve(text,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION commitment_portfolio_resolve(text,jsonb) TO finops_api,finops_commitment_portfolio;

CREATE FUNCTION guard_commitment_portfolio_request() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE inputs jsonb;refs jsonb;BEGIN
 IF current_user<>'finops_api' OR NEW.creator_id='' OR octet_length(NEW.idempotency_key) NOT BETWEEN 8 AND 200 THEN RAISE EXCEPTION 'portfolio API request required';END IF;
 inputs:=public.commitment_portfolio_resolve(NEW.tenant_id,NEW.selection);
 SELECT jsonb_build_array(jsonb_build_object('kind','AWS_COMMITMENT','id',inputs->'commitment'->>'id','sha256',public.fleet_history_json_hash(inputs->'commitment')))||coalesce(jsonb_agg(jsonb_build_object('kind','AWS_CUR2','id',v->'receipt'->>'id','sha256',public.fleet_history_json_hash(v->'receipt')) ORDER BY v->'receipt'->>'id'),'[]') INTO refs FROM jsonb_array_elements(inputs->'billing') v;
 NEW.input_hash:=public.fleet_history_json_hash(inputs);NEW.input_refs:=refs;NEW.created_at:=clock_timestamp();RETURN NEW;
END $$;
CREATE TRIGGER portfolio_request BEFORE INSERT ON commitment_portfolio_requests FOR EACH ROW EXECUTE FUNCTION guard_commitment_portfolio_request();
CREATE FUNCTION guard_commitment_portfolio_result() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE request public.commitment_portfolio_requests%ROWTYPE;inputs jsonb;v jsonb;item jsonb;BEGIN
 IF current_user<>'finops_commitment_portfolio' THEN RAISE EXCEPTION 'portfolio analyst required';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id||':dependency-graph',0));
 SELECT * INTO request FROM public.commitment_portfolio_requests WHERE tenant_id=NEW.tenant_id AND id=NEW.request_id;
 IF request.id IS NULL THEN RAISE EXCEPTION 'portfolio issued request required';END IF;
 IF jsonb_typeof(NEW.document->'observed_at') IS DISTINCT FROM 'string' OR (NEW.document->>'observed_at')::timestamptz<request.created_at OR (NEW.document->>'observed_at')::timestamptz>clock_timestamp()+interval '5 seconds' THEN RAISE EXCEPTION 'portfolio observation time differs';END IF;
 -- Both terminal paths take the credential fence; revocation cannot race a
 -- result written using a retained snapshot or a forged tenant setting.
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('commitment-portfolio-credential:'||session_user::text,0));
 IF NOT public.commitment_portfolio_scope(NEW.tenant_id) THEN RAISE EXCEPTION 'portfolio credential scope differs';END IF;
 IF NEW.status='ASSESSED' THEN
 IF NOT public.commitment_portfolio_keys(NEW.document,ARRAY['unmatched_billing','schema_version','id','request_id','selection','input_refs','observed_at','inventory_status','billing_status','positions','partitions','optimization_order','recommendation_status','reason_codes','expected_savings','estimated_saving','verified_saving','recommendation_authorized','purchase_authorized','execution_authorized']) OR octet_length(NEW.document::text)>2097152 OR NEW.document->>'schema_version' IS DISTINCT FROM '1' OR NEW.document->>'id'!~'^[a-f0-9]{64}$' OR NOT public.commitment_portfolio_strings(NEW.document->'reason_codes',256) OR jsonb_typeof(NEW.document->'positions') IS DISTINCT FROM 'array' OR jsonb_array_length(NEW.document->'positions')>2000 OR jsonb_typeof(NEW.document->'partitions') IS DISTINCT FROM 'array' OR jsonb_array_length(NEW.document->'partitions')>2000 OR jsonb_typeof(NEW.document->'unmatched_billing') IS DISTINCT FROM 'array' OR jsonb_array_length(NEW.document->'unmatched_billing')>100000 OR jsonb_typeof(NEW.document->'optimization_order') IS DISTINCT FROM 'array' OR jsonb_array_length(NEW.document->'optimization_order')<>5 THEN RAISE EXCEPTION 'portfolio analysis shape differs';END IF;
 FOR v IN SELECT jsonb_array_elements(NEW.document->'positions') LOOP
 IF NOT public.commitment_portfolio_keys(v,ARRAY['expiry','position','observed_billed_cost','observed_allocated_cost','allocated_cost_basis','commitment_cost_basis','observed_committed_cost','observed_used_commitment','observed_unused_commitment','utilization','coverage','effective_discount','downside_if_zero_usage_observed_window','break_even_utilization','remaining_value','cash_requirement','expected_utilization','confidence_interval','status','reason_codes']) OR NOT public.commitment_portfolio_keys(v->'position',ARRAY['reserved_instance_terms','id','account_id','class','state','region','instance_family','currency','start','end','term_seconds','hourly_commitment','upfront_amount','recurring_amount','recurring_amount_unit','payment_option','native_ref','reason_codes']) OR NOT public.commitment_portfolio_keys(v->'expiry',ARRAY['status','remaining_seconds','within_days','expires_within_window']) OR NOT public.commitment_portfolio_strings(v->'reason_codes',256) OR NOT public.commitment_portfolio_strings(v->'position'->'reason_codes',256) OR v->>'status' NOT IN('UNKNOWN','OBSERVED_PARTIAL') OR v->'coverage' IS DISTINCT FROM 'null'::jsonb OR v->'effective_discount' IS DISTINCT FROM 'null'::jsonb OR v->'break_even_utilization' IS DISTINCT FROM 'null'::jsonb OR v->'remaining_value' IS DISTINCT FROM 'null'::jsonb OR v->'cash_requirement' IS DISTINCT FROM 'null'::jsonb OR v->'expected_utilization' IS DISTINCT FROM 'null'::jsonb OR v->'confidence_interval' IS DISTINCT FROM 'null'::jsonb THEN RAISE EXCEPTION 'portfolio position shape differs';END IF;
 IF v->'position'->'reserved_instance_terms'<>'null'::jsonb AND NOT public.commitment_portfolio_keys(v->'position'->'reserved_instance_terms',ARRAY['offering_class','offering_type','scope','duration_seconds','currency_code','fixed_price','usage_price','instance_count','instance_type','instance_tenancy','product_description','availability_zone','availability_zone_id','recurring_charges']) THEN RAISE EXCEPTION 'portfolio RI terms differ';END IF;
 END LOOP;
 FOR v IN SELECT jsonb_array_elements(NEW.document->'partitions') LOOP
 IF NOT public.commitment_portfolio_keys(v,ARRAY['class','currency','account_id','region','instance_family','position_ids','position_count','observed_committed_cost','observed_used_commitment','observed_unused_commitment','utilization','expiring_position_ids','hourly_commitment_rate','hourly_commitment_rate_unit','position_shares','concentration_basis','observed_billed_cost']) OR NOT public.commitment_portfolio_strings(v->'position_ids',2000) OR NOT public.commitment_portfolio_strings(v->'expiring_position_ids',2000) OR jsonb_typeof(v->'position_shares') IS DISTINCT FROM 'array' OR jsonb_array_length(v->'position_shares')>2000 OR v->>'hourly_commitment_rate_unit' IS DISTINCT FROM 'currency/hour' OR v->>'concentration_basis' IS DISTINCT FROM 'NATIVE_HOURLY_COMMITMENT_RATE' THEN RAISE EXCEPTION 'portfolio partition differs';END IF;
 FOR item IN SELECT jsonb_array_elements(v->'position_shares') LOOP IF NOT public.commitment_portfolio_keys(item,ARRAY['position_id','share']) THEN RAISE EXCEPTION 'portfolio share differs';END IF;END LOOP;
 END LOOP;
 FOR v IN SELECT jsonb_array_elements(NEW.document->'unmatched_billing') LOOP IF NOT public.commitment_portfolio_keys(v,ARRAY['commitment_id','account_id','currency','line_ids','observed_billed_cost','reason_codes']) OR NOT public.commitment_portfolio_strings(v->'line_ids',100000) OR v->'reason_codes' IS DISTINCT FROM '["COMMITMENT_NOT_IN_SELECTED_NATIVE_POINT"]'::jsonb THEN RAISE EXCEPTION 'portfolio unmatched billing differs';END IF;END LOOP;
 FOR v IN SELECT jsonb_array_elements(NEW.document->'optimization_order') LOOP IF NOT public.commitment_portfolio_keys(v,ARRAY['stage','status','decision_ref','outcome_ref','scope_sha256','reason_codes']) OR v->>'status' IS DISTINCT FROM 'BLOCKED' OR v->'decision_ref' IS DISTINCT FROM 'null'::jsonb OR v->'outcome_ref' IS DISTINCT FROM 'null'::jsonb OR v->'scope_sha256' IS DISTINCT FROM 'null'::jsonb OR NOT public.commitment_portfolio_strings(v->'reason_codes',256) THEN RAISE EXCEPTION 'portfolio optimization authority differs';END IF;END LOOP;
 inputs:=public.commitment_portfolio_resolve(NEW.tenant_id,request.selection);
 IF public.fleet_history_json_hash(inputs)<>request.input_hash OR NEW.document->>'request_id' IS DISTINCT FROM NEW.request_id OR NEW.document->'selection' IS DISTINCT FROM request.selection OR NEW.document->'input_refs' IS DISTINCT FROM request.input_refs OR NEW.document->>'recommendation_status' IS DISTINCT FROM 'BLOCKED' OR NEW.document->'purchase_authorized' IS DISTINCT FROM 'false'::jsonb OR NEW.document->'recommendation_authorized' IS DISTINCT FROM 'false'::jsonb OR NEW.document->'execution_authorized' IS DISTINCT FROM 'false'::jsonb OR NEW.document->'expected_savings' IS DISTINCT FROM 'null'::jsonb OR NEW.document->'estimated_saving' IS DISTINCT FROM 'null'::jsonb OR NEW.document->'verified_saving' IS DISTINCT FROM 'null'::jsonb THEN RAISE EXCEPTION 'portfolio analysis cannot grant authority';END IF;
 ELSE IF NEW.document->>'reason_code' NOT IN('ISSUED_INPUTS_CHANGED','ISSUED_INPUT_FORMAT_UNSUPPORTED','PORTFOLIO_MODEL_EVIDENCE_UNSUPPORTED') OR (SELECT count(*) FROM jsonb_object_keys(NEW.document))<>2 OR NOT NEW.document ? 'observed_at' THEN RAISE EXCEPTION 'portfolio refusal differs';END IF;END IF;
 NEW.content_hash:=public.fleet_history_json_hash(NEW.document);NEW.created_at:=clock_timestamp();NEW.writer_role:=current_user;RETURN NEW;
END $$;
CREATE TRIGGER portfolio_result BEFORE INSERT ON commitment_portfolio_results FOR EACH ROW EXECUTE FUNCTION guard_commitment_portfolio_result();
REVOKE ALL ON FUNCTION guard_commitment_portfolio_request(),guard_commitment_portfolio_result(),guard_commitment_portfolio_credential() FROM PUBLIC;

-- Small selector projections never return raw exports, evidence bodies, role
-- bindings or unbounded source/receipt arrays to a browser.
CREATE FUNCTION commitment_portfolio_choices(p_tenant text,p_kind text,p_source text,p_receipt_kind text,p_after text,p_limit integer) RETURNS TABLE(value jsonb) LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
BEGIN
 IF current_setting('role',true)<>'finops_api' OR NOT pg_has_role(session_user,'finops_api','MEMBER') OR p_tenant IS DISTINCT FROM current_setting('app.tenant_id',true) OR p_limit NOT BETWEEN 1 AND 21 THEN RAISE EXCEPTION 'portfolio selector scope differs';END IF;
 IF p_kind='sources' THEN
 RETURN QUERY SELECT jsonb_build_object('id',s.id,'version',s.version,'status',CASE WHEN s.document->'enabled' IS DISTINCT FROM 'true'::jsonb OR s.document->'revoked'='true'::jsonb THEN 'REVOKED' ELSE coalesce(c.document->>'status','UNKNOWN') END,'payer_account_id',s.document->>'payer_account_id','usage_account_count',coalesce(jsonb_array_length(s.document->'usage_account_ids'),0),'region',s.document->>'region','commitment_receipt_id',c.document->>'commitment_receipt_id') FROM public.source_registrations s LEFT JOIN public.source_checkpoints c ON c.tenant_id=s.tenant_id AND c.source_id=s.id AND c.checkpoint_key='status' WHERE s.tenant_id=p_tenant AND s.kind='AWS_CUR2' AND s.id>p_after ORDER BY s.id LIMIT p_limit;
 ELSIF p_kind='receipts' AND p_receipt_kind IN('AWS_COMMITMENT','AWS_CUR2') THEN
 RETURN QUERY SELECT jsonb_build_object('id',r.id,'kind',r.kind,'source_id',r.source_id,'observed_at',r.document->>'observed_at','current',CASE WHEN r.kind='AWS_COMMITMENT' THEN c.document->>'commitment_receipt_id'=r.id ELSE EXISTS(SELECT 1 FROM public.source_checkpoints x WHERE x.tenant_id=r.tenant_id AND x.source_id=r.source_id AND x.checkpoint_key LIKE 'month:'||(r.document->>'config_hash')||':%' AND x.document->>'receipt_id'=r.id) END,'period',CASE WHEN r.kind='AWS_CUR2' AND r.document->'source_proof' ? 'period_start' AND r.document->'source_proof' ? 'period_end' THEN jsonb_build_object('start',r.document->'source_proof'->>'period_start','end',r.document->'source_proof'->>'period_end') ELSE NULL END,'proof_state',CASE WHEN r.kind='AWS_COMMITMENT' THEN CASE WHEN r.document->'commitment_scope'->'complete'='true'::jsonb THEN 'COMPLETE' ELSE 'PARTIAL' END WHEN r.document->'source_proof'->>'state' IN('COMPLETE','FINAL') THEN r.document->'source_proof'->>'state' ELSE 'UNKNOWN' END) FROM public.source_receipts r LEFT JOIN public.source_checkpoints c ON c.tenant_id=r.tenant_id AND c.source_id=r.source_id AND c.checkpoint_key='status' WHERE r.tenant_id=p_tenant AND r.source_id=p_source AND r.kind=p_receipt_kind AND r.writer_role='finops_ingester' AND r.id>p_after ORDER BY r.id LIMIT p_limit;
 ELSE RAISE EXCEPTION 'portfolio selector kind differs';END IF;
END $$;
REVOKE ALL ON FUNCTION commitment_portfolio_choices(text,text,text,text,text,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION commitment_portfolio_choices(text,text,text,text,text,integer) TO finops_api;
