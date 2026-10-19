-- Private ISOLATED_FIXTURE recovery observation. SQL enforces independent
-- observer provenance and release closure. The trusted observer ingress also
-- verifies Ed25519 and actual raw health semantics in Go; SQL is not an HTTP
-- instrument or an Ed25519 implementation. Existing migration bytes stay fixed.
DO $$ BEGIN
 IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='finops_group_health_observer') THEN CREATE ROLE finops_group_health_observer NOLOGIN;END IF;
END $$;
GRANT USAGE ON SCHEMA public TO finops_group_health_observer;

-- One-time additive compatibility boundary. Only chains that actually issued
-- an intent before this migration retain the old resolved-duty release rule.
-- They become recovery-only; no app role may create or extend an exemption.
CREATE TABLE public.fleet_group_recovery_health_legacy (
 tenant_id text NOT NULL,chain_id text NOT NULL,head_hash text NOT NULL,
 reason text NOT NULL CHECK(reason='PRE034_ISSUED_INTENT_RECOVERY_ONLY'),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(tenant_id,chain_id),
 FOREIGN KEY(tenant_id,chain_id,head_hash) REFERENCES public.fleet_group_journal_heads(tenant_id,chain_id,content_hash)
);
INSERT INTO public.fleet_group_recovery_health_legacy(tenant_id,chain_id,head_hash,reason)
 SELECT w.tenant_id,w.chain_id,c.head_hash,'PRE034_ISSUED_INTENT_RECOVERY_ONLY' FROM public.fleet_group_workspace_keys w JOIN public.fleet_group_journal_current c ON c.tenant_id=w.tenant_id AND c.chain_id=w.chain_id WHERE EXISTS(SELECT 1 FROM public.fleet_group_journal_records r WHERE r.tenant_id=w.tenant_id AND r.chain_id=w.chain_id AND r.kind='APPLY_INTENT');
ALTER TABLE public.fleet_group_recovery_health_legacy ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.fleet_group_recovery_health_legacy FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON public.fleet_group_recovery_health_legacy USING(tenant_id=current_setting('app.tenant_id',true)) WITH CHECK(tenant_id=current_setting('app.tenant_id',true));
REVOKE ALL ON public.fleet_group_recovery_health_legacy FROM PUBLIC;
GRANT SELECT ON public.fleet_group_recovery_health_legacy TO finops_group_ledger;
CREATE FUNCTION public.guard_group_recovery_health_legacy() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$ BEGIN RAISE EXCEPTION 'migration-pinned recovery compatibility is immutable';END $$;
CREATE TRIGGER guard_group_recovery_health_legacy BEFORE INSERT OR UPDATE OR DELETE ON public.fleet_group_recovery_health_legacy FOR EACH ROW EXECUTE FUNCTION public.guard_group_recovery_health_legacy();
REVOKE ALL ON FUNCTION public.guard_group_recovery_health_legacy() FROM PUBLIC;

CREATE TABLE public.fleet_group_recovery_health_observers (
 tenant_id text NOT NULL,chain_id text NOT NULL,id text NOT NULL,
 profile_id text NOT NULL,profile_generation text NOT NULL,image_sha256 text NOT NULL,
 database_login text NOT NULL,source_id text NOT NULL,issuer text NOT NULL,subject text NOT NULL,audience text NOT NULL,
 public_key bytea NOT NULL CHECK(octet_length(public_key)=32),limits jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,chain_id,id),UNIQUE(tenant_id,chain_id,database_login),
 FOREIGN KEY(tenant_id,chain_id) REFERENCES public.fleet_group_workspace_keys(tenant_id,chain_id)
);
CREATE TABLE public.fleet_group_recovery_health_observations (
 tenant_id text NOT NULL,chain_id text NOT NULL,id text NOT NULL,observer_id text NOT NULL,
 workspace_generation text NOT NULL,phase text NOT NULL CHECK(phase IN('BASELINE','RESTORATION')),
 attempt_id text,command_id text NOT NULL,artifact_id text NOT NULL,receipt_hash text NOT NULL,
 document jsonb NOT NULL,raw_document bytea NOT NULL,content_hash text NOT NULL,
 writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,chain_id,id),UNIQUE(tenant_id,chain_id,observer_id,receipt_hash),
 FOREIGN KEY(tenant_id,chain_id,observer_id) REFERENCES public.fleet_group_recovery_health_observers(tenant_id,chain_id,id),
 FOREIGN KEY(tenant_id,chain_id,workspace_generation) REFERENCES public.fleet_group_workspaces(tenant_id,chain_id,generation),
 CHECK(octet_length(raw_document) BETWEEN 1 AND 262144)
);
CREATE TABLE public.fleet_group_recovery_health_baselines (
 tenant_id text NOT NULL,chain_id text NOT NULL,id text NOT NULL,anchor_id text NOT NULL,
 document jsonb NOT NULL,raw_document bytea NOT NULL,content_hash text NOT NULL,
 writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,chain_id),UNIQUE(tenant_id,chain_id,id),
 FOREIGN KEY(tenant_id,chain_id) REFERENCES public.fleet_group_journal_roots(tenant_id,chain_id),
 CHECK(octet_length(raw_document) BETWEEN 1 AND 131072)
);
CREATE TABLE public.fleet_group_recovery_health_attempts (
 tenant_id text NOT NULL,chain_id text NOT NULL,id text NOT NULL,observer_id text NOT NULL,baseline_id text NOT NULL,
 previous_outcome_id text,workspace_generation text NOT NULL,command_id text NOT NULL,terminal_id text NOT NULL,
 state_sha256 text NOT NULL,ordinal numeric(20,0) NOT NULL CHECK(ordinal BETWEEN 1 AND 18446744073709551615),
 document jsonb NOT NULL,raw_document bytea NOT NULL,content_hash text NOT NULL,
 writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,chain_id,id),UNIQUE(tenant_id,chain_id,ordinal),
 UNIQUE(tenant_id,chain_id,previous_outcome_id),
 FOREIGN KEY(tenant_id,chain_id,observer_id) REFERENCES public.fleet_group_recovery_health_observers(tenant_id,chain_id,id),
 FOREIGN KEY(tenant_id,chain_id,baseline_id) REFERENCES public.fleet_group_recovery_health_baselines(tenant_id,chain_id,id),
 FOREIGN KEY(tenant_id,chain_id,workspace_generation) REFERENCES public.fleet_group_workspaces(tenant_id,chain_id,generation),
 FOREIGN KEY(tenant_id,chain_id,terminal_id) REFERENCES public.fleet_group_native_terminals(tenant_id,chain_id,id),
 CHECK(octet_length(raw_document) BETWEEN 1 AND 16384)
);
CREATE TABLE public.fleet_group_recovery_health_outcomes (
 tenant_id text NOT NULL,chain_id text NOT NULL,id text NOT NULL,attempt_id text NOT NULL,observer_id text NOT NULL,
 status text NOT NULL CHECK(status IN('OBSERVED','BREACH','INVALID','ABANDONED')),artifact_id text NOT NULL,
 document jsonb NOT NULL,raw_document bytea NOT NULL,content_hash text NOT NULL,
 writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,chain_id,id),UNIQUE(tenant_id,chain_id,attempt_id),
 FOREIGN KEY(tenant_id,chain_id,attempt_id) REFERENCES public.fleet_group_recovery_health_attempts(tenant_id,chain_id,id),
 FOREIGN KEY(tenant_id,chain_id,observer_id) REFERENCES public.fleet_group_recovery_health_observers(tenant_id,chain_id,id),
 CHECK(octet_length(raw_document) BETWEEN 1 AND 131072)
);
ALTER TABLE public.fleet_group_recovery_health_attempts ADD FOREIGN KEY(tenant_id,chain_id,previous_outcome_id) REFERENCES public.fleet_group_recovery_health_outcomes(tenant_id,chain_id,id);
ALTER TABLE public.fleet_group_recovery_health_observations ADD FOREIGN KEY(tenant_id,chain_id,attempt_id) REFERENCES public.fleet_group_recovery_health_attempts(tenant_id,chain_id,id);
CREATE TABLE public.fleet_group_recovery_health_selections (
 tenant_id text NOT NULL,chain_id text NOT NULL,outcome_id text NOT NULL,
 writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,chain_id,outcome_id),
 FOREIGN KEY(tenant_id,chain_id,outcome_id) REFERENCES public.fleet_group_recovery_health_outcomes(tenant_id,chain_id,id)
);

CREATE FUNCTION public.fleet_group_recovery_observer_access(p_tenant text,p_chain text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
 SELECT p_tenant=current_setting('app.tenant_id',true) AND EXISTS(SELECT 1 FROM public.fleet_group_recovery_health_observers WHERE tenant_id=p_tenant AND chain_id=p_chain AND database_login=session_user)
$$;
REVOKE ALL ON FUNCTION public.fleet_group_recovery_observer_access(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.fleet_group_recovery_observer_access(text,text) TO finops_group_health_observer,finops_group_ledger;
DO $$ DECLARE tab text;BEGIN
 FOREACH tab IN ARRAY ARRAY['fleet_group_recovery_health_observers','fleet_group_recovery_health_observations','fleet_group_recovery_health_baselines','fleet_group_recovery_health_attempts','fleet_group_recovery_health_outcomes','fleet_group_recovery_health_selections'] LOOP
  EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',tab);EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',tab);
  EXECUTE format('CREATE POLICY tenant_isolation ON public.%I USING(tenant_id=current_setting(''app.tenant_id'',true) AND (current_user=''finops_group_ledger'' OR public.fleet_group_recovery_observer_access(tenant_id,chain_id))) WITH CHECK(tenant_id=current_setting(''app.tenant_id'',true) AND (current_user=''finops_group_ledger'' OR public.fleet_group_recovery_observer_access(tenant_id,chain_id)))',tab);
  EXECUTE format('REVOKE ALL ON public.%I FROM PUBLIC',tab);
 END LOOP;
END $$;
GRANT SELECT ON public.fleet_group_recovery_health_observers,public.fleet_group_recovery_health_observations,public.fleet_group_recovery_health_baselines,public.fleet_group_recovery_health_attempts,public.fleet_group_recovery_health_outcomes,public.fleet_group_recovery_health_selections TO finops_group_ledger,finops_group_health_observer;
GRANT INSERT ON public.fleet_group_recovery_health_observations,public.fleet_group_recovery_health_attempts,public.fleet_group_recovery_health_outcomes TO finops_group_health_observer;
GRANT INSERT ON public.fleet_group_recovery_health_baselines,public.fleet_group_recovery_health_selections TO finops_group_ledger;

-- Operator installation is not an application capability. It cannot borrow
-- any deployment, pipeline, ledger or retirement signing key or mixed login.
CREATE FUNCTION public.guard_group_recovery_observer() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$ DECLARE who text;r public.fleet_group_journal_roots;k public.fleet_group_journal_key_bindings;w public.fleet_group_workspace_keys;BEGIN
 who:=coalesce(nullif(current_setting('role',true),'none'),session_user);
 IF TG_OP<>'INSERT' OR NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=who AND rolsuper) OR NEW.tenant_id IS DISTINCT FROM current_setting('app.tenant_id',true) THEN RAISE EXCEPTION 'operator-only immutable recovery observer';END IF;
 SELECT * INTO r FROM public.fleet_group_journal_roots WHERE tenant_id=NEW.tenant_id AND chain_id=NEW.chain_id;
 SELECT * INTO k FROM public.fleet_group_journal_key_bindings WHERE tenant_id=r.tenant_id AND id=r.key_binding_id;
 SELECT * INTO w FROM public.fleet_group_workspace_keys WHERE tenant_id=r.tenant_id AND chain_id=r.chain_id;
 IF r.chain_id IS NULL OR w.id IS NULL OR NEW.profile_id IS DISTINCT FROM w.profile_id OR NEW.profile_generation IS DISTINCT FROM w.profile_generation OR NEW.image_sha256 IS DISTINCT FROM w.image_sha256 OR NEW.public_key IN(k.signer_key,k.pipeline_key,k.ledger_key,w.public_key) OR coalesce(NEW.id,'')='' OR coalesce(NEW.source_id,'')='' OR coalesce(NEW.issuer,'')='' OR coalesce(NEW.subject,'')='' OR coalesce(NEW.audience,'')='' OR NOT EXISTS(SELECT 1 FROM pg_roles x WHERE x.rolname=NEW.database_login AND x.rolcanlogin AND NOT x.rolsuper AND NOT x.rolcreatedb AND NOT x.rolcreaterole AND NOT x.rolbypassrls AND NOT x.rolreplication AND pg_has_role(x.oid,'finops_group_health_observer','MEMBER') AND NOT EXISTS(SELECT 1 FROM pg_roles z WHERE pg_has_role(x.oid,z.oid,'MEMBER') AND z.rolname NOT IN(x.rolname,'finops_group_health_observer'))) THEN RAISE EXCEPTION 'recovery observer identity or installation differs';END IF;
 IF NEW.limits IS DISTINCT FROM jsonb_build_object('minimum_samples',30,'max_p95_ns',2000000000::bigint,'max_p99_ns',3000000000::bigint,'max_error_rate_ppm',10000,'min_availability_ppm',990000,'max_inflight',2,'max_backlog',0) THEN RAISE EXCEPTION 'fixed fixture health objectives required';END IF;
 IF EXISTS(SELECT 1 FROM public.fleet_group_journal_records WHERE tenant_id=NEW.tenant_id AND chain_id=NEW.chain_id AND kind='APPLY_INTENT') THEN RAISE EXCEPTION 'observer must be commissioned before initial dispatch';END IF;
 NEW.created_at:=clock_timestamp();RETURN NEW;
END $$;
CREATE TRIGGER guard_group_recovery_observers BEFORE INSERT OR UPDATE OR DELETE ON public.fleet_group_recovery_health_observers FOR EACH ROW EXECUTE FUNCTION public.guard_group_recovery_observer();
REVOKE ALL ON FUNCTION public.guard_group_recovery_observer() FROM PUBLIC;

-- This source/current-head fence deliberately does not require new forward
-- source health or parent lifetime. Those cannot erase an owned restoration.
CREATE FUNCTION public.fleet_group_recovery_health_scope(p_tenant text,p_chain text,p_observer text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$ DECLARE o public.fleet_group_recovery_health_observers;s jsonb;j jsonb;w jsonb;released boolean;who text;terminal text;BEGIN
 who:=coalesce(nullif(current_setting('role',true),'none'),session_user);
 IF p_tenant IS DISTINCT FROM current_setting('app.tenant_id',true) OR who NOT IN('finops_group_ledger','finops_group_health_observer') THEN RETURN NULL;END IF;
 SELECT * INTO o FROM public.fleet_group_recovery_health_observers WHERE tenant_id=p_tenant AND chain_id=p_chain AND id=p_observer;
 IF o.id IS NULL OR (who='finops_group_health_observer' AND o.database_login<>session_user) THEN RETURN NULL;END IF;
 s:=public.fleet_group_reconstruction_scope(p_tenant,p_chain);IF s IS NULL THEN RETURN NULL;END IF;
 j:=public.fleet_group_reconstruction_journal(p_tenant,p_chain);
 SELECT document INTO w FROM public.fleet_group_workspaces WHERE tenant_id=p_tenant AND chain_id=p_chain ORDER BY ordinal DESC LIMIT 1;
 SELECT released_at IS NOT NULL INTO released FROM public.fleet_group_journal_reservations WHERE tenant_id=p_tenant AND chain_id=p_chain;
 SELECT terminal_id INTO terminal FROM public.fleet_group_native_terminal_selections WHERE tenant_id=p_tenant AND chain_id=p_chain AND command_id=(SELECT document->'receipt'->'receipt'->>'command_id' FROM public.fleet_group_journal_records WHERE tenant_id=p_tenant AND chain_id=p_chain AND segment=0 AND kind='APPLIED' ORDER BY sequence DESC LIMIT 1);
 RETURN jsonb_build_object('scope',s,'journal',j,'workspace',w,'released',released,'terminal_id',coalesce(terminal,''),'observer',jsonb_build_object('id',o.id,'tenant_id',o.tenant_id,'chain_id',o.chain_id,'database_login',o.database_login,'identity',jsonb_build_object('source_id',o.source_id,'issuer',o.issuer,'subject',o.subject,'audience',o.audience),'public_key',encode(o.public_key,'base64'),'limits',o.limits));
END $$;
REVOKE ALL ON FUNCTION public.fleet_group_recovery_health_scope(text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.fleet_group_recovery_health_scope(text,text,text) TO finops_group_ledger,finops_group_health_observer;

CREATE FUNCTION public.fleet_group_recovery_health_artifact(p_tenant text,p_chain text,p_command text,p_kind text,p_id text) RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
 SELECT document->'artifact' FROM public.fleet_group_artifacts WHERE p_tenant=current_setting('app.tenant_id',true) AND (coalesce(nullif(current_setting('role',true),'none'),session_user)='finops_group_ledger' OR public.fleet_group_recovery_observer_access(p_tenant,p_chain)) AND tenant_id=p_tenant AND chain_id=p_chain AND command_id=p_command AND kind=p_kind AND kind IN('HEALTH_BASELINE','HEALTH_RECEIPT','HEALTH_VERDICT') AND id=p_id
$$;
REVOKE ALL ON FUNCTION public.fleet_group_recovery_health_artifact(text,text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.fleet_group_recovery_health_artifact(text,text,text,text,text) TO finops_group_ledger,finops_group_health_observer;

-- Recompute the measured span/population from separately issued raw observer
-- rows. A ledger's positive-looking JSON summary cannot supply elapsed time.
CREATE FUNCTION public.fleet_group_recovery_health_measurements(win jsonb,receipts jsonb,started timestamptz,asof timestamptz) RETURNS boolean LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,public,pg_temp AS $$ DECLARE first_at timestamptz;last_at timestamptz;mono numeric;samples bigint;hashes jsonb;BEGIN
 IF jsonb_typeof(receipts) IS DISTINCT FROM 'array' OR jsonb_array_length(receipts) NOT BETWEEN 1 AND 256 THEN RETURN false;END IF;
 IF jsonb_typeof(win) IS DISTINCT FROM 'object' OR NOT win ?& ARRAY['status','reason_codes','start','required_end','observed_through','receipt_sha256s','sample_count','p95_ns','p99_ns','baseline_p95_ns','baseline_p99_ns','error_rate_ppm','availability_ppm','backlog','inflight','definition','availability_basis','customer_execution_authorized','measurement_revision','monotonic_duration_ns'] OR win->>'status' IS DISTINCT FROM 'OBSERVED' OR win->'reason_codes' IS DISTINCT FROM '[]'::jsonb OR win->>'definition' IS DISTINCT FROM 'ISOLATED_HTTP_COMPLETED_OPERATION' OR win->>'availability_basis' IS DISTINCT FROM 'OBSERVED_HTTP_REQUEST_SUCCESS' OR win->'customer_execution_authorized' IS DISTINCT FROM 'false'::jsonb OR win->>'measurement_revision' IS DISTINCT FROM 'GO_MONOTONIC_HTTP_V2' THEN RETURN false;END IF;
 IF EXISTS(SELECT 1 FROM jsonb_each(win) x WHERE x.key=ANY(ARRAY['sample_count','p95_ns','p99_ns','baseline_p95_ns','baseline_p99_ns','error_rate_ppm','availability_ppm','backlog','inflight','monotonic_duration_ns']) AND (jsonb_typeof(x.value) IS DISTINCT FROM 'number' OR x.value::text!~'^[0-9]+$')) THEN RETURN false;END IF;
 IF EXISTS(SELECT 1 FROM (SELECT value,lag(value) OVER(ORDER BY (value->>'sequence')::numeric) prior,row_number() OVER(ORDER BY (value->>'sequence')::numeric) ordinal FROM jsonb_array_elements(receipts)) r WHERE (r.value->>'sequence')::numeric<>r.ordinal OR (r.ordinal=1 AND r.value->>'previous_sha256'<>'') OR (r.ordinal>1 AND (r.value->>'previous_sha256' IS DISTINCT FROM r.prior->>'sha256' OR r.value->'before' IS DISTINCT FROM r.prior->'after'))) THEN RETURN false;END IF;
 SELECT min((value->'before'->>'captured_at')::timestamptz),max((value->'after'->>'captured_at')::timestamptz),sum((value->'clock'->>'elapsed_ns')::numeric),sum(jsonb_array_length(value->'observations')),jsonb_agg(value->'sha256' ORDER BY (value->>'sequence')::numeric) INTO first_at,last_at,mono,samples,hashes FROM jsonb_array_elements(receipts);
 RETURN coalesce(started IS NOT NULL AND first_at>=started AND last_at<=asof+interval '5 seconds' AND last_at>=asof-interval '1 minute' AND last_at-first_at>=interval '900 seconds' AND mono>=900000000000 AND samples>=30 AND win->'receipt_sha256s'=hashes AND (win->>'start')::timestamptz=first_at AND (win->>'observed_through')::timestamptz=last_at AND (win->>'required_end')::timestamptz=first_at+interval '900 seconds' AND (win->>'monotonic_duration_ns')::numeric=mono AND (win->>'sample_count')::bigint=samples AND (win->>'p95_ns')::numeric BETWEEN 1 AND 2000000000 AND (win->>'p99_ns')::numeric BETWEEN 1 AND 3000000000 AND (win->>'baseline_p95_ns')::numeric>0 AND (win->>'baseline_p99_ns')::numeric>0 AND (win->>'p95_ns')::numeric*100<=(win->>'baseline_p95_ns')::numeric*115 AND (win->>'p99_ns')::numeric*100<=(win->>'baseline_p99_ns')::numeric*115 AND (win->>'error_rate_ppm')::numeric<=10000 AND (win->>'availability_ppm')::numeric>=990000 AND (win->>'backlog')::numeric=0 AND (win->>'inflight')::numeric<=2,false);
END $$;
REVOKE ALL ON FUNCTION public.fleet_group_recovery_health_measurements(jsonb,jsonb,timestamptz,timestamptz) FROM PUBLIC;
CREATE FUNCTION public.fleet_group_recovery_health_positive(p_tenant text,p_chain text,p_attempt text,p_body jsonb) RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$ DECLARE started timestamptz;receipts jsonb;BEGIN
 SELECT created_at INTO started FROM public.fleet_group_recovery_health_attempts WHERE tenant_id=p_tenant AND chain_id=p_chain AND id=p_attempt;
 SELECT jsonb_agg(document->'observation'->'receipt' ORDER BY (document->'observation'->'receipt'->>'sequence')::numeric,id) INTO receipts FROM public.fleet_group_recovery_health_observations WHERE tenant_id=p_tenant AND chain_id=p_chain AND attempt_id=p_attempt;
 RETURN public.fleet_group_recovery_health_measurements(p_body->'window',receipts,started,clock_timestamp());
END $$;
REVOKE ALL ON FUNCTION public.fleet_group_recovery_health_positive(text,text,text,jsonb) FROM PUBLIC;

CREATE FUNCTION public.guard_group_recovery_health() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$ DECLARE who text;scope jsonb;o public.fleet_group_recovery_health_observers;p jsonb;w jsonb;a public.fleet_group_recovery_health_attempts;last_a public.fleet_group_recovery_health_attempts;v jsonb;ref jsonb;stored jsonb;prior public.fleet_group_recovery_health_outcomes;BEGIN
 who:=coalesce(nullif(current_setting('role',true),'none'),session_user);
 IF TG_OP<>'INSERT' OR NEW.tenant_id IS DISTINCT FROM current_setting('app.tenant_id',true) THEN RAISE EXCEPTION 'recovery health immutable tenant required';END IF;
 IF TG_TABLE_NAME IN('fleet_group_recovery_health_baselines','fleet_group_recovery_health_selections') THEN
  IF who<>'finops_group_ledger' THEN RAISE EXCEPTION 'recovery health ledger selection required';END IF;
 ELSE
  IF who<>'finops_group_health_observer' THEN RAISE EXCEPTION 'independent recovery observer required';END IF;
  SELECT * INTO o FROM public.fleet_group_recovery_health_observers WHERE tenant_id=NEW.tenant_id AND chain_id=NEW.chain_id AND id=NEW.observer_id;
  IF o.id IS NULL OR o.database_login<>session_user THEN RAISE EXCEPTION 'commissioned observer login differs';END IF;
 END IF;
 PERFORM public.fleet_group_journal_lock(NEW.tenant_id,(SELECT workload_id FROM public.fleet_group_journal_roots WHERE tenant_id=NEW.tenant_id AND chain_id=NEW.chain_id));
 SELECT h.projection INTO p FROM public.fleet_group_journal_current c JOIN public.fleet_group_journal_heads h ON h.tenant_id=c.tenant_id AND h.chain_id=c.chain_id AND h.content_hash=c.head_hash WHERE c.tenant_id=NEW.tenant_id AND c.chain_id=NEW.chain_id AND c.document->>'kind'='ORIGINAL_JOURNAL' FOR UPDATE OF c;
 SELECT document->'workspace' INTO w FROM public.fleet_group_workspaces WHERE tenant_id=NEW.tenant_id AND chain_id=NEW.chain_id ORDER BY ordinal DESC LIMIT 1;
 IF p IS NULL OR w IS NULL OR EXISTS(SELECT 1 FROM public.fleet_group_journal_reservations WHERE tenant_id=NEW.tenant_id AND chain_id=NEW.chain_id AND released_at IS NOT NULL) THEN RAISE EXCEPTION 'held original recovery scope required';END IF;
 IF TG_TABLE_NAME='fleet_group_recovery_health_selections' THEN
  IF NOT EXISTS(SELECT 1 FROM public.fleet_group_recovery_health_outcomes x JOIN public.fleet_group_recovery_health_attempts y ON y.tenant_id=x.tenant_id AND y.chain_id=x.chain_id AND y.id=x.attempt_id WHERE x.tenant_id=NEW.tenant_id AND x.chain_id=NEW.chain_id AND x.id=NEW.outcome_id AND x.status='OBSERVED' AND y.workspace_generation=w->>'generation' AND y.state_sha256=p->'current'->>'state_sha256' AND y.ordinal=(SELECT max(ordinal) FROM public.fleet_group_recovery_health_attempts WHERE tenant_id=NEW.tenant_id AND chain_id=NEW.chain_id)) THEN RAISE EXCEPTION 'selected recovery result is not latest current positive';END IF;
 ELSE
  IF encode(sha256(NEW.raw_document),'hex') IS DISTINCT FROM NEW.content_hash OR NEW.content_hash!~'^[a-f0-9]{64}$' OR convert_from(NEW.raw_document,'UTF8')::jsonb IS DISTINCT FROM NEW.document THEN RAISE EXCEPTION 'recovery health canonical bytes differ';END IF;
  IF TG_TABLE_NAME='fleet_group_recovery_health_observations' THEN
   v:=NEW.document->'observation';ref:=v->'reference';
   IF octet_length(NEW.raw_document)+(SELECT coalesce(sum(octet_length(raw_document)),0) FROM public.fleet_group_recovery_health_observations WHERE tenant_id=NEW.tenant_id AND chain_id=NEW.chain_id AND phase=NEW.phase AND attempt_id IS NOT DISTINCT FROM NEW.attempt_id)>8388608 OR (SELECT count(*) FROM public.fleet_group_recovery_health_observations WHERE tenant_id=NEW.tenant_id AND chain_id=NEW.chain_id AND phase=NEW.phase AND attempt_id IS NOT DISTINCT FROM NEW.attempt_id)>=256 THEN RAISE EXCEPTION 'recovery health population unavailable at bounded limit';END IF;
   IF NEW.document->>'algorithm'<>'Ed25519/group-recovery-health/v1' OR coalesce(NEW.document->>'signature','')!~'^[A-Za-z0-9+/]{86}==$' OR v->'schema_version' IS DISTINCT FROM '"1"'::jsonb OR v->>'id' IS DISTINCT FROM NEW.id OR v->>'tenant_id' IS DISTINCT FROM NEW.tenant_id OR v->>'chain_id' IS DISTINCT FROM NEW.chain_id OR v->>'observer_id' IS DISTINCT FROM NEW.observer_id OR v->'workspace' IS DISTINCT FROM w OR NEW.workspace_generation IS DISTINCT FROM w->>'generation' OR v->>'command_id' IS DISTINCT FROM NEW.command_id OR v->>'phase' IS DISTINCT FROM NEW.phase OR nullif(v->>'attempt_id','') IS DISTINCT FROM NEW.attempt_id OR ref->>'id' IS DISTINCT FROM NEW.artifact_id OR v->'receipt'->>'sha256' IS DISTINCT FROM NEW.receipt_hash OR (v->>'signed_at')::timestamptz>clock_timestamp()+interval '5 seconds' OR (v->>'signed_at')::timestamptz<clock_timestamp()-interval '1 minute' THEN RAISE EXCEPTION 'signed recovery observation binding differs';END IF;
   SELECT document->'artifact' INTO stored FROM public.fleet_group_artifacts WHERE tenant_id=NEW.tenant_id AND chain_id=NEW.chain_id AND command_id=NEW.command_id AND kind=CASE NEW.phase WHEN 'BASELINE' THEN 'HEALTH_BASELINE' ELSE 'HEALTH_RECEIPT' END AND id=NEW.artifact_id;
   IF stored IS NULL OR stored IS DISTINCT FROM ref OR (v->'receipt'->>'schema_version')<>'2' OR (v->'receipt'->>'measurement_revision')<>'GO_MONOTONIC_HTTP_V2' THEN RAISE EXCEPTION 'signed raw health reference or revision differs';END IF;
   IF NEW.phase='BASELINE' THEN
    IF NEW.attempt_id IS NOT NULL OR EXISTS(SELECT 1 FROM public.fleet_group_journal_records WHERE tenant_id=NEW.tenant_id AND chain_id=NEW.chain_id AND kind='APPLY_INTENT') THEN RAISE EXCEPTION 'baseline cannot be backfilled after activation';END IF;
   ELSE
    SELECT * INTO a FROM public.fleet_group_recovery_health_attempts WHERE tenant_id=NEW.tenant_id AND chain_id=NEW.chain_id AND id=NEW.attempt_id;
    IF a.id IS NULL OR a.observer_id<>NEW.observer_id OR a.workspace_generation<>NEW.workspace_generation OR a.command_id<>NEW.command_id OR (v->'receipt'->'before'->>'captured_at')::timestamptz<a.created_at OR EXISTS(SELECT 1 FROM public.fleet_group_recovery_health_outcomes WHERE tenant_id=NEW.tenant_id AND chain_id=NEW.chain_id AND attempt_id=a.id) THEN RAISE EXCEPTION 'current health attempt closed or receipt precedes start';END IF;
   END IF;
  ELSIF TG_TABLE_NAME='fleet_group_recovery_health_baselines' THEN
   v:=NEW.document;ref:=v->'anchor_reference';
   SELECT document->'artifact' INTO stored FROM public.fleet_group_artifacts WHERE tenant_id=NEW.tenant_id AND chain_id=NEW.chain_id AND kind='HEALTH_VERDICT' AND id=NEW.anchor_id;
   IF v->'schema_version' IS DISTINCT FROM '"1"'::jsonb OR v->>'id' IS DISTINCT FROM NEW.id OR v->>'tenant_id' IS DISTINCT FROM NEW.tenant_id OR v->>'chain_id' IS DISTINCT FROM NEW.chain_id OR stored IS NULL OR stored IS DISTINCT FROM ref OR ref->>'id' IS DISTINCT FROM NEW.anchor_id OR jsonb_array_length(v->'observation_ids') NOT BETWEEN 1 AND 256 OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(v->'observation_ids') x WHERE NOT EXISTS(SELECT 1 FROM public.fleet_group_recovery_health_observations y WHERE y.tenant_id=NEW.tenant_id AND y.chain_id=NEW.chain_id AND y.id=x.value AND y.phase='BASELINE')) THEN RAISE EXCEPTION 'original signed baseline inputs differ';END IF;
  ELSIF TG_TABLE_NAME='fleet_group_recovery_health_attempts' THEN
   v:=NEW.document;SELECT * INTO last_a FROM public.fleet_group_recovery_health_attempts WHERE tenant_id=NEW.tenant_id AND chain_id=NEW.chain_id ORDER BY ordinal DESC LIMIT 1;
   IF coalesce(p->'pending','null'::jsonb) IS DISTINCT FROM 'null'::jsonb OR jsonb_array_length(p->'stack')<>0 OR p->'forward_aborted' IS DISTINCT FROM 'true'::jsonb OR v->'workspace' IS DISTINCT FROM w OR v->>'id' IS DISTINCT FROM NEW.id OR v->>'observer_id' IS DISTINCT FROM NEW.observer_id OR v->>'baseline_id' IS DISTINCT FROM NEW.baseline_id OR v->>'state_sha256' IS DISTINCT FROM NEW.state_sha256 OR NEW.state_sha256 IS DISTINCT FROM p->'current'->>'state_sha256' OR NEW.workspace_generation IS DISTINCT FROM w->>'generation' OR (v->>'started_at')::timestamptz<clock_timestamp()-interval '5 seconds' OR (v->>'started_at')::timestamptz>clock_timestamp()+interval '5 seconds' THEN RAISE EXCEPTION 'current restored health attempt differs';END IF;
   IF NOT EXISTS(SELECT 1 FROM public.fleet_group_native_terminals t JOIN public.fleet_group_native_terminal_selections s ON s.tenant_id=t.tenant_id AND s.chain_id=t.chain_id AND s.terminal_id=t.id WHERE t.tenant_id=NEW.tenant_id AND t.chain_id=NEW.chain_id AND t.id=NEW.terminal_id AND t.command_id=NEW.command_id AND t.workspace_generation=NEW.workspace_generation AND t.document->'terminal'->'after' IS NOT DISTINCT FROM p->'current') THEN RAISE EXCEPTION 'attempt lacks current-generation restored terminal';END IF;
   IF last_a.id IS NULL THEN
    IF NEW.ordinal<>1 OR NEW.previous_outcome_id IS NOT NULL THEN RAISE EXCEPTION 'first health attempt cannot borrow predecessor';END IF;
   ELSE
    SELECT * INTO prior FROM public.fleet_group_recovery_health_outcomes WHERE tenant_id=NEW.tenant_id AND chain_id=NEW.chain_id AND id=NEW.previous_outcome_id;
    IF NEW.ordinal<>last_a.ordinal+1 OR prior.attempt_id IS DISTINCT FROM last_a.id OR (prior.status='OBSERVED' AND (prior.document->'outcome'->'window'->>'observed_through')::timestamptz>=clock_timestamp()-interval '1 minute') THEN RAISE EXCEPTION 'retry requires exact persisted failed, abandoned, or stale positive predecessor';END IF;
   END IF;
  ELSIF TG_TABLE_NAME='fleet_group_recovery_health_outcomes' THEN
   v:=NEW.document->'outcome';SELECT * INTO a FROM public.fleet_group_recovery_health_attempts WHERE tenant_id=NEW.tenant_id AND chain_id=NEW.chain_id AND id=NEW.attempt_id;
   IF a.id IS NULL OR a.observer_id<>NEW.observer_id OR a.workspace_generation IS DISTINCT FROM w->>'generation' OR a.state_sha256 IS DISTINCT FROM p->'current'->>'state_sha256' OR NEW.document->>'algorithm'<>'Ed25519/group-recovery-health/v1' OR coalesce(NEW.document->>'signature','')!~'^[A-Za-z0-9+/]{86}==$' OR v->>'id' IS DISTINCT FROM NEW.id OR v->>'tenant_id' IS DISTINCT FROM NEW.tenant_id OR v->>'chain_id' IS DISTINCT FROM NEW.chain_id OR v->>'attempt_id' IS DISTINCT FROM NEW.attempt_id OR v->>'observer_id' IS DISTINCT FROM NEW.observer_id OR v->>'status' IS DISTINCT FROM NEW.status OR (v->>'signed_at')::timestamptz>clock_timestamp()+interval '5 seconds' OR (v->>'signed_at')::timestamptz<clock_timestamp()-interval '1 minute' OR jsonb_array_length(v->'observation_ids')>256 THEN RAISE EXCEPTION 'signed health outcome binding differs';END IF;
   SELECT document->'artifact' INTO stored FROM public.fleet_group_artifacts WHERE tenant_id=NEW.tenant_id AND chain_id=NEW.chain_id AND command_id=a.command_id AND kind='HEALTH_VERDICT' AND id=NEW.artifact_id;
   IF stored IS NULL OR stored->>'sha256' IS DISTINCT FROM NEW.content_hash OR (stored->>'size_bytes')::integer<>octet_length(NEW.raw_document) OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(v->'observation_ids') x WHERE NOT EXISTS(SELECT 1 FROM public.fleet_group_recovery_health_observations y WHERE y.tenant_id=NEW.tenant_id AND y.chain_id=NEW.chain_id AND y.attempt_id=a.id AND y.id=x.value)) OR jsonb_array_length(v->'observation_ids')<>(SELECT count(*) FROM public.fleet_group_recovery_health_observations WHERE tenant_id=NEW.tenant_id AND chain_id=NEW.chain_id AND attempt_id=a.id) THEN RAISE EXCEPTION 'outcome must retain complete issued attempt population';END IF;
   IF NEW.status='OBSERVED' AND (NOT public.fleet_group_recovery_health_positive(NEW.tenant_id,NEW.chain_id,NEW.attempt_id,v) OR (v->'window'->>'observed_through')::timestamptz<clock_timestamp()-interval '1 minute') THEN RAISE EXCEPTION 'positive recovery needs fresh full wall and monotonic900';END IF;
  END IF;
 END IF;
 NEW.writer_role:=who;NEW.created_at:=clock_timestamp();RETURN NEW;
END $$;
DO $$ DECLARE tab text;BEGIN FOREACH tab IN ARRAY ARRAY['fleet_group_recovery_health_observations','fleet_group_recovery_health_baselines','fleet_group_recovery_health_attempts','fleet_group_recovery_health_outcomes','fleet_group_recovery_health_selections'] LOOP EXECUTE format('CREATE TRIGGER guard_%I BEFORE INSERT OR UPDATE OR DELETE ON public.%I FOR EACH ROW EXECUTE FUNCTION public.guard_group_recovery_health()',tab,tab);END LOOP;END $$;
REVOKE ALL ON FUNCTION public.guard_group_recovery_health() FROM PUBLIC;

CREATE FUNCTION public.fleet_group_recovery_health_release(p_tenant text,p_chain text,p_head text) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$ DECLARE a public.fleet_group_recovery_health_attempts;o public.fleet_group_recovery_health_outcomes;p jsonb;w text;BEGIN
 IF p_tenant IS DISTINCT FROM current_setting('app.tenant_id',true) THEN RETURN false;END IF;
 IF NOT EXISTS(SELECT 1 FROM public.fleet_group_workspace_keys WHERE tenant_id=p_tenant AND chain_id=p_chain) THEN RETURN true;END IF;
 IF EXISTS(SELECT 1 FROM public.fleet_group_recovery_health_legacy WHERE tenant_id=p_tenant AND chain_id=p_chain) THEN RETURN true;END IF;
 SELECT h.projection INTO p FROM public.fleet_group_journal_current c JOIN public.fleet_group_journal_heads h ON h.tenant_id=c.tenant_id AND h.chain_id=c.chain_id AND h.content_hash=c.head_hash WHERE c.tenant_id=p_tenant AND c.chain_id=p_chain AND c.head_hash=p_head AND (h.document->'head'->>'valid_until')::timestamptz>=clock_timestamp() FOR UPDATE OF c;
 SELECT generation INTO w FROM public.fleet_group_workspaces WHERE tenant_id=p_tenant AND chain_id=p_chain ORDER BY ordinal DESC LIMIT 1;
 SELECT * INTO a FROM public.fleet_group_recovery_health_attempts WHERE tenant_id=p_tenant AND chain_id=p_chain ORDER BY ordinal DESC LIMIT 1;
 SELECT x.* INTO o FROM public.fleet_group_recovery_health_outcomes x JOIN public.fleet_group_recovery_health_selections s ON s.tenant_id=x.tenant_id AND s.chain_id=x.chain_id AND s.outcome_id=x.id WHERE x.tenant_id=p_tenant AND x.chain_id=p_chain AND x.attempt_id=a.id AND x.status='OBSERVED';
 RETURN p IS NOT NULL AND a.id IS NOT NULL AND o.id IS NOT NULL AND a.workspace_generation=w AND a.state_sha256=p->'current'->>'state_sha256' AND coalesce(p->'pending','null'::jsonb)='null'::jsonb AND jsonb_array_length(p->'stack')=0 AND p->'forward_aborted'='true'::jsonb AND public.fleet_group_recovery_health_positive(p_tenant,p_chain,a.id,o.document->'outcome') AND (o.document->'outcome'->'window'->>'observed_through')::timestamptz>=clock_timestamp()-interval '1 minute';
END $$;
REVOKE ALL ON FUNCTION public.fleet_group_recovery_health_release(text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.fleet_group_recovery_health_release(text,text,text) TO finops_group_ledger;
CREATE FUNCTION public.guard_group_recovery_health_release() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$ BEGIN
 IF OLD.released_at IS NULL AND NEW.released_at IS NOT NULL AND NOT coalesce(public.fleet_group_recovery_health_release(NEW.tenant_id,NEW.chain_id,NEW.release_head_hash),false) THEN RAISE EXCEPTION 'managed group recovery health not positively observed';END IF;RETURN NEW;
END $$;
CREATE TRIGGER guard_group_recovery_health_release BEFORE UPDATE ON public.fleet_group_journal_reservations FOR EACH ROW EXECUTE FUNCTION public.guard_group_recovery_health_release();
REVOKE ALL ON FUNCTION public.guard_group_recovery_health_release() FROM PUBLIC;

CREATE FUNCTION public.guard_group_recovery_forward() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$ DECLARE command jsonb;legacy boolean;baseline_span interval;mono numeric;BEGIN
 IF NEW.kind<>'APPLY_INTENT' OR NOT EXISTS(SELECT 1 FROM public.fleet_group_workspace_keys WHERE tenant_id=NEW.tenant_id AND chain_id=NEW.chain_id) THEN RETURN NEW;END IF;
 SELECT h.projection->'pending'->'command' INTO command FROM public.fleet_group_journal_current c JOIN public.fleet_group_journal_heads h ON h.tenant_id=c.tenant_id AND h.chain_id=c.chain_id AND h.content_hash=c.head_hash WHERE c.tenant_id=NEW.tenant_id AND c.chain_id=NEW.chain_id FOR UPDATE OF c;
 IF command->'preparation'->>'mode'<>'FORWARD' THEN RETURN NEW;END IF;
 SELECT EXISTS(SELECT 1 FROM public.fleet_group_recovery_health_legacy WHERE tenant_id=NEW.tenant_id AND chain_id=NEW.chain_id) INTO legacy;
 IF legacy THEN RAISE EXCEPTION 'pre034 native group is permanently recovery only';END IF;
 IF NOT EXISTS(SELECT 1 FROM public.fleet_group_recovery_health_observers WHERE tenant_id=NEW.tenant_id AND chain_id=NEW.chain_id) THEN RAISE EXCEPTION 'new managed forward requires commissioned health observer';END IF;
 IF (command->'preparation'->>'sequence')::numeric=1 THEN
  SELECT max((document->'observation'->'receipt'->'after'->>'captured_at')::timestamptz)-min((document->'observation'->'receipt'->'before'->>'captured_at')::timestamptz),sum((document->'observation'->'receipt'->'clock'->>'elapsed_ns')::numeric) INTO baseline_span,mono FROM public.fleet_group_recovery_health_observations WHERE tenant_id=NEW.tenant_id AND chain_id=NEW.chain_id AND phase='BASELINE';
  IF coalesce(baseline_span,interval '0 seconds')<interval '120 seconds' OR coalesce(mono,0)<120000000000 THEN RAISE EXCEPTION 'initial forward requires original120s observer baseline';END IF;
 ELSIF NOT EXISTS(SELECT 1 FROM public.fleet_group_recovery_health_baselines WHERE tenant_id=NEW.tenant_id AND chain_id=NEW.chain_id) THEN RAISE EXCEPTION 'later forward requires immutable original activated baseline';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER guard_group_recovery_forward BEFORE INSERT ON public.fleet_group_journal_records FOR EACH ROW EXECUTE FUNCTION public.guard_group_recovery_forward();
REVOKE ALL ON FUNCTION public.guard_group_recovery_forward() FROM PUBLIC;
