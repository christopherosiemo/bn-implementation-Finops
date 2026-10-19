-- Private reconstruction metadata. Go verifies commissioned signatures and
-- authenticated object readback; SQL cannot establish Docker removal or parse
-- Terraform. No HTTP/API role can install a runtime or select native evidence.
DO $$ BEGIN
 IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='finops_group_workspace_controller') THEN CREATE ROLE finops_group_workspace_controller NOLOGIN;END IF;
END $$;
GRANT USAGE ON SCHEMA public TO finops_group_workspace_controller;

CREATE TABLE public.fleet_group_workspace_keys (
 tenant_id text NOT NULL,chain_id text NOT NULL,id text NOT NULL,
 profile_id text NOT NULL,profile_generation text NOT NULL,image_sha256 text NOT NULL CHECK(image_sha256~'^[a-f0-9]{64}$'),
 public_key bytea NOT NULL CHECK(octet_length(public_key)=32),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,chain_id),UNIQUE(tenant_id,chain_id,id),
 FOREIGN KEY(tenant_id,chain_id) REFERENCES public.fleet_group_journal_roots(tenant_id,chain_id)
);
CREATE TABLE public.fleet_group_workspaces (
 tenant_id text NOT NULL,chain_id text NOT NULL,generation text NOT NULL,
 ordinal numeric(20,0) NOT NULL CHECK(ordinal BETWEEN 0 AND 18446744073709551615),
 runtime_id text NOT NULL CHECK(runtime_id~'^[a-f0-9]{64}$'),image_sha256 text NOT NULL CHECK(image_sha256~'^[a-f0-9]{64}$'),
 key_binding_id text NOT NULL,previous_generation text,
 document jsonb NOT NULL,raw_document bytea NOT NULL,content_hash text NOT NULL CHECK(content_hash~'^[a-f0-9]{64}$'),
 writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,chain_id,generation),UNIQUE(tenant_id,chain_id,ordinal),UNIQUE(tenant_id,chain_id,runtime_id),
 FOREIGN KEY(tenant_id,chain_id,key_binding_id) REFERENCES public.fleet_group_workspace_keys(tenant_id,chain_id,id),
 FOREIGN KEY(tenant_id,chain_id,previous_generation) REFERENCES public.fleet_group_workspaces(tenant_id,chain_id,generation),
 CHECK(octet_length(raw_document) BETWEEN 1 AND 16384),CHECK((ordinal=0 AND previous_generation IS NULL) OR (ordinal>0 AND previous_generation IS NOT NULL))
);
CREATE TABLE public.fleet_group_native_terminals (
 tenant_id text NOT NULL,chain_id text NOT NULL,id text NOT NULL,command_id text NOT NULL,
 operation_id text NOT NULL,fence numeric(20,0) NOT NULL,workspace_generation text NOT NULL,
 head_hash text NOT NULL,artifact_id text NOT NULL,
 review_id text NOT NULL,capture_id text NOT NULL,after_id text NOT NULL,
 document jsonb NOT NULL,raw_document bytea NOT NULL,content_hash text NOT NULL CHECK(content_hash~'^[a-f0-9]{64}$'),
 writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,chain_id,id),UNIQUE(tenant_id,chain_id,command_id,id),
 FOREIGN KEY(tenant_id,chain_id,command_id,operation_id,fence) REFERENCES public.fleet_group_journal_operations(tenant_id,chain_id,command_id,operation_id,fence),
 FOREIGN KEY(tenant_id,chain_id,workspace_generation) REFERENCES public.fleet_group_workspaces(tenant_id,chain_id,generation),
 FOREIGN KEY(tenant_id,chain_id,head_hash) REFERENCES public.fleet_group_journal_heads(tenant_id,chain_id,content_hash),
 CHECK(octet_length(raw_document) BETWEEN 1 AND 65535)
);
CREATE TABLE public.fleet_group_native_terminal_selections (
 tenant_id text NOT NULL,chain_id text NOT NULL,command_id text NOT NULL,terminal_id text NOT NULL,
 writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,chain_id,command_id),
 FOREIGN KEY(tenant_id,chain_id,command_id,terminal_id) REFERENCES public.fleet_group_native_terminals(tenant_id,chain_id,command_id,id)
);
DO $$ DECLARE tab text;BEGIN
 FOREACH tab IN ARRAY ARRAY['fleet_group_workspace_keys','fleet_group_workspaces','fleet_group_native_terminals','fleet_group_native_terminal_selections'] LOOP
  EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',tab);
  EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',tab);
  EXECUTE format('CREATE POLICY tenant_isolation ON public.%I USING(tenant_id=current_setting(''app.tenant_id'',true)) WITH CHECK(tenant_id=current_setting(''app.tenant_id'',true))',tab);
  EXECUTE format('REVOKE ALL ON public.%I FROM PUBLIC',tab);
 END LOOP;
END $$;
GRANT SELECT ON public.fleet_group_workspace_keys,public.fleet_group_workspaces,public.fleet_group_native_terminals,public.fleet_group_native_terminal_selections TO finops_group_ledger;
GRANT SELECT,INSERT ON public.fleet_group_native_terminals TO finops_group_pipeline;
GRANT SELECT ON public.fleet_group_workspaces TO finops_group_pipeline;
GRANT INSERT ON public.fleet_group_workspaces TO finops_group_workspace_controller;
GRANT SELECT ON public.fleet_group_workspaces,public.fleet_group_native_terminals,public.fleet_group_native_terminal_selections TO finops_group_workspace_controller;
GRANT INSERT ON public.fleet_group_native_terminal_selections TO finops_group_ledger;

-- Narrow historical root/installation scope. This does not re-authorize a
-- forward action and remains available for an already owned restoration.
CREATE FUNCTION public.fleet_group_reconstruction_scope(p_tenant text,p_chain text) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$ DECLARE out jsonb;BEGIN
 IF coalesce(p_tenant,'')='' OR p_tenant IS DISTINCT FROM current_setting('app.tenant_id',true) OR coalesce(p_chain,'')='' THEN RETURN NULL;END IF;
 SELECT jsonb_build_object('root',r.document,'keys',jsonb_build_object('signer',encode(j.signer_key,'base64'),'pipeline',encode(j.pipeline_key,'base64'),'ledger',encode(j.ledger_key,'base64')),'proposal',p.document,'program_raw',encode(g.program_raw,'base64'),'journal_review_raw',encode(g.journal_review_raw,'base64'),'program_sha256',g.program_hash,'authorization_sha256',r.authorization_hash,'proof_hash',g.proof_hash,'artifact_refs',g.artifact_refs,'controller_key_id',k.id,'controller_key',encode(k.public_key,'base64')) INTO out
 FROM public.fleet_group_journal_roots r JOIN public.fleet_fixture_prepared_programs g ON g.tenant_id=r.tenant_id AND g.id=r.prepared_program_id
 JOIN public.fleet_fixture_proposals p ON p.tenant_id=g.tenant_id AND p.id=g.proposal_id
 JOIN public.fleet_group_workspace_keys k ON k.tenant_id=r.tenant_id AND k.chain_id=r.chain_id
 JOIN public.fleet_group_journal_key_bindings j ON j.tenant_id=r.tenant_id AND j.id=r.key_binding_id
 WHERE r.tenant_id=p_tenant AND r.chain_id=p_chain;
 RETURN out;
END $$;
REVOKE ALL ON FUNCTION public.fleet_group_reconstruction_scope(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.fleet_group_reconstruction_scope(text,text) TO finops_group_pipeline,finops_group_ledger,finops_group_workspace_controller;

-- Exact immutable replays serialize without requiring a newly fresh head.
CREATE FUNCTION public.fleet_group_reconstruction_lock(p_tenant text,p_chain text) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$ DECLARE s jsonb;BEGIN
 s:=public.fleet_group_reconstruction_scope(p_tenant,p_chain);IF s IS NULL THEN RETURN false;END IF;
 PERFORM public.fleet_group_journal_lock(p_tenant,s->'proposal'->>'workload_id');RETURN true;
END $$;
REVOKE ALL ON FUNCTION public.fleet_group_reconstruction_lock(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.fleet_group_reconstruction_lock(text,text) TO finops_group_pipeline,finops_group_ledger,finops_group_workspace_controller;

-- Private readers receive signed canonical bytes, not a SQL-created ownership
-- projection. The Go verifier must replay every issued record/checkpoint.
CREATE FUNCTION public.fleet_group_reconstruction_journal(p_tenant text,p_chain text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$ DECLARE scope jsonb;out jsonb;head text;BEGIN
 scope:=public.fleet_group_reconstruction_scope(p_tenant,p_chain);IF scope IS NULL THEN RETURN NULL;END IF;
 PERFORM public.fleet_group_journal_lock(p_tenant,scope->'proposal'->>'workload_id');
 SELECT c.head_hash INTO head FROM public.fleet_group_journal_current c WHERE c.tenant_id=p_tenant AND c.chain_id=p_chain AND c.document->>'kind'='ORIGINAL_JOURNAL' FOR UPDATE;
 IF head IS NULL THEN RETURN NULL;END IF;
 SELECT jsonb_build_object('head',encode(h.raw_document,'base64'),'records',coalesce((SELECT jsonb_agg(jsonb_build_object('record',encode(r.raw_document,'base64'),'head',encode(r.raw_head,'base64')) ORDER BY r.sequence) FROM public.fleet_group_journal_records r WHERE r.tenant_id=p_tenant AND r.chain_id=p_chain AND r.segment=0),'[]'::jsonb)) INTO out FROM public.fleet_group_journal_heads h WHERE h.tenant_id=p_tenant AND h.chain_id=p_chain AND h.content_hash=head;
 RETURN out;
END $$;
REVOKE ALL ON FUNCTION public.fleet_group_reconstruction_journal(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.fleet_group_reconstruction_journal(text,text) TO finops_group_pipeline,finops_group_ledger,finops_group_workspace_controller;

-- Pipeline has SELECT, never UPDATE, on the outbox. This narrow tenant/chain
-- helper can lock only an issued APPLY row, under the same graph/current order,
-- without granting mutation or reusable dispatch authority.
CREATE FUNCTION public.fleet_group_reconstruction_delivery(p_tenant text,p_chain text,p_command text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$ DECLARE s jsonb;d public.fleet_group_journal_outbox;BEGIN
 s:=public.fleet_group_reconstruction_scope(p_tenant,p_chain);IF s IS NULL OR coalesce(p_command,'')='' THEN RETURN NULL;END IF;
 PERFORM public.fleet_group_journal_lock(p_tenant,s->'proposal'->>'workload_id');
 PERFORM 1 FROM public.fleet_group_journal_current c WHERE c.tenant_id=p_tenant AND c.chain_id=p_chain AND c.document->>'kind'='ORIGINAL_JOURNAL' FOR UPDATE;
 IF NOT FOUND THEN RETURN NULL;END IF;
 SELECT * INTO d FROM public.fleet_group_journal_outbox WHERE tenant_id=p_tenant AND chain_id=p_chain AND command_id=p_command AND action='APPLY' FOR UPDATE;
 IF d.id IS NULL THEN RETURN NULL;END IF;
 RETURN jsonb_build_object('raw',encode(d.raw_document,'base64'),'state',d.state,'attempt',coalesce(d.attempt_id,''),'command_hash',d.command_hash);
END $$;
REVOKE ALL ON FUNCTION public.fleet_group_reconstruction_delivery(text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.fleet_group_reconstruction_delivery(text,text,text) TO finops_group_pipeline,finops_group_ledger;

CREATE FUNCTION public.fleet_group_reconstruction_terminal_ref(p_tenant text,p_chain text,p_command text,p_id text) RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
 SELECT a.document->'artifact' FROM public.fleet_group_artifacts a WHERE coalesce(p_tenant,'')<>'' AND p_tenant=current_setting('app.tenant_id',true) AND a.tenant_id=p_tenant AND a.chain_id=p_chain AND a.command_id=p_command AND a.kind='NATIVE_OPERATION_PROOF' AND a.id=p_id AND EXISTS(SELECT 1 FROM public.fleet_group_native_terminals t WHERE t.tenant_id=a.tenant_id AND t.chain_id=a.chain_id AND t.command_id=a.command_id AND t.artifact_id=a.id)
$$;
REVOKE ALL ON FUNCTION public.fleet_group_reconstruction_terminal_ref(text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.fleet_group_reconstruction_terminal_ref(text,text,text,text) TO finops_group_pipeline,finops_group_ledger,finops_group_workspace_controller;

CREATE FUNCTION public.guard_group_workspace_key() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$ DECLARE p jsonb;k public.fleet_group_journal_key_bindings;BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'workspace commissioning is immutable';END IF;
 IF coalesce(NEW.tenant_id,'')='' OR NEW.tenant_id IS DISTINCT FROM current_setting('app.tenant_id',true) OR coalesce(NEW.id,'')='' THEN RAISE EXCEPTION 'workspace commissioning requires exact tenant';END IF;
 SELECT r.document INTO p FROM public.fleet_group_journal_roots r WHERE r.tenant_id=NEW.tenant_id AND r.chain_id=NEW.chain_id;
 SELECT x.* INTO k FROM public.fleet_group_journal_key_bindings x WHERE x.tenant_id=NEW.tenant_id AND x.id=p->>'key_binding_id';
 IF p IS NULL OR k.id IS NULL OR NEW.profile_id IS DISTINCT FROM p->'parent'->'program'->'realm'->>'fixture_id' OR NEW.profile_generation IS DISTINCT FROM p->'parent'->'program'->'realm'->>'generation' OR NEW.image_sha256 IS DISTINCT FROM (SELECT f.document->'installation'->>'toolchain_image_sha256' FROM public.fleet_fixture_profiles f WHERE f.id=NEW.profile_id AND f.generation=NEW.profile_generation) OR NEW.public_key IN(k.signer_key,k.pipeline_key,k.ledger_key) THEN RAISE EXCEPTION 'workspace commissioning differs from independently issued installation';END IF;
 NEW.created_at:=clock_timestamp();RETURN NEW;
END $$;
CREATE TRIGGER guard_group_workspace_keys BEFORE INSERT OR UPDATE OR DELETE ON public.fleet_group_workspace_keys FOR EACH ROW EXECUTE FUNCTION public.guard_group_workspace_key();
REVOKE ALL ON FUNCTION public.guard_group_workspace_key() FROM PUBLIC;

CREATE FUNCTION public.guard_group_workspace() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$ DECLARE old public.fleet_group_workspaces;scope jsonb;w jsonb;r jsonb;who text;BEGIN
 -- SECURITY DEFINER only permits narrow historical joins. The effective
 -- submitting role is captured by the row's untrusted default and then checked
 -- against the invoker role setting; it is never accepted as a writer label.
 who:=coalesce(nullif(current_setting('role',true),'none'),session_user);
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'workspace generations are immutable';END IF;
 IF coalesce(NEW.tenant_id,'')='' OR NEW.tenant_id IS DISTINCT FROM current_setting('app.tenant_id',true) THEN RAISE EXCEPTION 'workspace generation requires exact tenant';END IF;
 scope:=public.fleet_group_reconstruction_scope(NEW.tenant_id,NEW.chain_id);
 IF scope IS NULL OR NEW.key_binding_id IS DISTINCT FROM scope->>'controller_key_id' OR NEW.image_sha256 IS DISTINCT FROM scope->'proposal'->'profile'->'installation'->>'toolchain_image_sha256' THEN RAISE EXCEPTION 'workspace generation installation differs';END IF;
 PERFORM public.fleet_group_journal_lock(NEW.tenant_id,scope->'proposal'->>'workload_id');
 SELECT * INTO old FROM public.fleet_group_workspaces WHERE tenant_id=NEW.tenant_id AND chain_id=NEW.chain_id ORDER BY ordinal DESC LIMIT 1;
 w:=NEW.document->'workspace';r:=NEW.document->'retirement';
 IF NEW.document->'schema_version' IS DISTINCT FROM '"1"'::jsonb OR w IS DISTINCT FROM jsonb_build_object('generation',NEW.generation,'runtime_id',NEW.runtime_id,'image_sha256',NEW.image_sha256) OR NEW.generation!~'^[A-Za-z0-9][A-Za-z0-9_.-]{0,255}$' OR encode(sha256(NEW.raw_document),'hex') IS DISTINCT FROM NEW.content_hash OR convert_from(NEW.raw_document,'UTF8')::jsonb IS DISTINCT FROM NEW.document OR EXISTS(SELECT 1 FROM jsonb_object_keys(NEW.document) x WHERE x<>ALL(ARRAY['schema_version','workspace','terminal_id','retirement'])) THEN RAISE EXCEPTION 'workspace generation body differs';END IF;
 IF NEW.ordinal=0 THEN
  IF old.generation IS NOT NULL OR r IS DISTINCT FROM 'null'::jsonb OR NEW.document->>'terminal_id' IS DISTINCT FROM '' OR NOT EXISTS(SELECT 1 FROM public.fleet_group_journal_current c WHERE c.tenant_id=NEW.tenant_id AND c.chain_id=NEW.chain_id AND c.document->>'kind'='ORIGINAL_JOURNAL' AND c.document->>'record_count'='0') OR NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=who AND rolsuper) THEN RAISE EXCEPTION 'only operator may install initial zero-head workspace';END IF;
 ELSE
  IF who<>'finops_group_workspace_controller' OR old.generation IS NULL OR NEW.previous_generation IS DISTINCT FROM old.generation OR NEW.ordinal<>old.ordinal+1 OR r->'retirement'->'schema_version' IS DISTINCT FROM '"1"'::jsonb OR r->'retirement'->>'tenant_id' IS DISTINCT FROM NEW.tenant_id OR r->'retirement'->>'chain_id' IS DISTINCT FROM NEW.chain_id OR r->'retirement'->>'program_sha256' IS DISTINCT FROM scope->>'program_sha256' OR r->'retirement'->>'method' IS DISTINCT FROM 'OWNED_DOCKER_CONTAINER_REMOVAL_CONFIRMED' OR r->'retirement'->'old' IS DISTINCT FROM old.document->'workspace' OR r->'retirement'->'new' IS DISTINCT FROM w OR NEW.runtime_id=old.runtime_id OR NEW.image_sha256<>old.image_sha256 OR r->>'algorithm' IS DISTINCT FROM 'Ed25519/group-fixture-native/v1' OR coalesce(r->>'signature','')!~'^[A-Za-z0-9+/]{86}==$' OR (r->'retirement'->>'observed_at')::timestamptz>clock_timestamp()+interval '5 seconds' OR NOT EXISTS(SELECT 1 FROM public.fleet_group_native_terminal_selections s JOIN public.fleet_group_native_terminals t ON t.tenant_id=s.tenant_id AND t.chain_id=s.chain_id AND t.id=s.terminal_id WHERE s.tenant_id=NEW.tenant_id AND s.chain_id=NEW.chain_id AND t.id=NEW.document->>'terminal_id' AND t.workspace_generation=old.generation AND (t.document->'terminal'->>'observed_at')::timestamptz<=(r->'retirement'->>'observed_at')::timestamptz) THEN RAISE EXCEPTION 'replacement requires exact commissioned removal proof';END IF;
 END IF;
 NEW.writer_role:=who;NEW.created_at:=clock_timestamp();RETURN NEW;
END $$;
CREATE TRIGGER guard_group_workspaces BEFORE INSERT OR UPDATE OR DELETE ON public.fleet_group_workspaces FOR EACH ROW EXECUTE FUNCTION public.guard_group_workspace();
REVOKE ALL ON FUNCTION public.guard_group_workspace() FROM PUBLIC;

CREATE FUNCTION public.guard_group_native_terminal() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$ DECLARE who text;s jsonb;t jsonb;h public.fleet_group_journal_heads;current_projection jsonb;delivery public.fleet_group_journal_outbox;c jsonb;w public.fleet_group_workspaces;v_kind text;ref jsonb;rid text;stored jsonb;BEGIN
 who:=coalesce(nullif(current_setting('role',true),'none'),session_user);
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'native terminal inspections are immutable';END IF;
 IF who<>'finops_group_pipeline' OR coalesce(NEW.tenant_id,'')='' OR NEW.tenant_id IS DISTINCT FROM current_setting('app.tenant_id',true) THEN RAISE EXCEPTION 'native terminal requires private pipeline tenant';END IF;
 s:=public.fleet_group_artifact_scope(NEW.tenant_id,NEW.chain_id,NEW.command_id);t:=NEW.document->'terminal';
 PERFORM public.fleet_group_journal_lock(NEW.tenant_id,(SELECT workload_id FROM public.fleet_group_journal_roots WHERE tenant_id=NEW.tenant_id AND chain_id=NEW.chain_id));
 SELECT * INTO h FROM public.fleet_group_journal_heads WHERE tenant_id=NEW.tenant_id AND chain_id=NEW.chain_id AND content_hash=NEW.head_hash;
 SELECT * INTO w FROM public.fleet_group_workspaces WHERE tenant_id=NEW.tenant_id AND chain_id=NEW.chain_id ORDER BY ordinal DESC LIMIT 1;
 SELECT x.projection INTO current_projection FROM public.fleet_group_journal_current q JOIN public.fleet_group_journal_heads x ON x.tenant_id=q.tenant_id AND x.chain_id=q.chain_id AND x.content_hash=q.head_hash WHERE q.tenant_id=NEW.tenant_id AND q.chain_id=NEW.chain_id AND q.document->>'kind'='ORIGINAL_JOURNAL' FOR UPDATE OF q;
 c:=h.projection->'pending'->'command';
 SELECT * INTO delivery FROM public.fleet_group_journal_outbox WHERE tenant_id=NEW.tenant_id AND chain_id=NEW.chain_id AND command_id=NEW.command_id AND action='APPLY' FOR UPDATE;
 IF current_projection->'pending'->'command' IS DISTINCT FROM c OR current_projection->'pending'->'apply_intent' IS DISTINCT FROM 'true'::jsonb OR current_projection->'pending'->'no_apply' IS NOT NULL OR current_projection->'pending'->'git_repair' IS NOT NULL OR delivery.id IS NULL OR delivery.state NOT IN('ATTEMPTED','RECONCILE','COMPLETE') OR coalesce(delivery.attempt_id,'')='' OR delivery.attempted_at IS NULL OR delivery.document->'command' IS DISTINCT FROM c OR t->>'command_sha256' IS DISTINCT FROM delivery.command_hash THEN RAISE EXCEPTION 'native terminal requires exact current claimed apply obligation';END IF;
 IF s IS NULL OR c->>'id' IS DISTINCT FROM NEW.command_id OR h.projection->'pending'->'apply_intent' IS DISTINCT FROM 'true'::jsonb OR h.projection->'pending'->'no_apply' IS NOT NULL OR h.projection->'pending'->'git_repair' IS NOT NULL OR NEW.document->>'algorithm' IS DISTINCT FROM 'Ed25519/group-fixture-native/v1' OR coalesce(NEW.document->>'signature','')!~'^[A-Za-z0-9+/]{86}==$' OR t->'schema_version' IS DISTINCT FROM '"1"'::jsonb OR t->>'id' IS DISTINCT FROM NEW.id OR t->>'chain_id' IS DISTINCT FROM NEW.chain_id OR t->>'tenant_id' IS DISTINCT FROM NEW.tenant_id OR t->>'operation_id' IS DISTINCT FROM NEW.operation_id OR (t->>'fence')::numeric IS DISTINCT FROM NEW.fence OR t->'head' IS DISTINCT FROM h.document OR t->'workspace' IS DISTINCT FROM w.document->'workspace' OR NEW.workspace_generation IS DISTINCT FROM w.generation OR t->'before' IS DISTINCT FROM c->'before' OR t->'after'->>'state_sha256' IS DISTINCT FROM t->'references'->'after'->>'sha256' OR encode(sha256(NEW.raw_document),'hex') IS DISTINCT FROM NEW.content_hash OR convert_from(NEW.raw_document,'UTF8')::jsonb IS DISTINCT FROM NEW.document THEN RAISE EXCEPTION 'native terminal issued operation, head or generation differs';END IF;
 IF jsonb_typeof(t->'fence') IS DISTINCT FROM 'number' OR coalesce(t->>'fence','')!~'^[0-9]+$' OR jsonb_typeof(t->'references') IS DISTINCT FROM 'object' OR NOT (t->'references') ?& ARRAY['review','capture','after'] OR EXISTS(SELECT 1 FROM jsonb_object_keys(t->'references') k WHERE k<>ALL(ARRAY['review','capture','after'])) OR EXISTS(SELECT 1 FROM jsonb_each(t) e WHERE e.key IN('schema_version','id','tenant_id','chain_id','program_sha256','authorization_sha256','command_sha256','operation_id','artifact_sha256','preparation_sha256','observed_at') AND jsonb_typeof(e.value) IS DISTINCT FROM 'string') OR jsonb_typeof(t->'before') IS DISTINCT FROM 'object' OR jsonb_typeof(t->'after') IS DISTINCT FROM 'object' OR jsonb_typeof(t->'head') IS DISTINCT FROM 'object' OR jsonb_typeof(t->'workspace') IS DISTINCT FROM 'object' OR NOT (t->'after') ?& ARRAY['revision','state_lineage','state_serial','state_sha256','model'] OR jsonb_typeof(t->'after'->'state_serial') IS DISTINCT FROM 'number' OR coalesce(t->'after'->>'state_serial','')!~'^[0-9]+$' OR (t->'after'->>'state_serial')::numeric NOT BETWEEN 0 AND 18446744073709551615 OR t->'after'->>'state_lineage' IS DISTINCT FROM c->'before'->>'state_lineage' OR t->'after'->'revision' IS DISTINCT FROM coalesce(c->'forward'->'child'->'artifact'->'revision',c->'recovery'->'recovery'->'artifact'->'revision') OR t->'after'->'model' IS DISTINCT FROM coalesce(c->'forward'->'child'->'artifact'->'after',c->'recovery'->'recovery'->'artifact'->'after') THEN RAISE EXCEPTION 'native terminal typed state or references differ';END IF;
 IF t->>'program_sha256' IS DISTINCT FROM (SELECT g.program_hash FROM public.fleet_group_journal_roots r JOIN public.fleet_fixture_prepared_programs g ON g.tenant_id=r.tenant_id AND g.id=r.prepared_program_id WHERE r.tenant_id=NEW.tenant_id AND r.chain_id=NEW.chain_id) OR t->>'authorization_sha256' IS DISTINCT FROM (SELECT authorization_hash FROM public.fleet_group_journal_roots WHERE tenant_id=NEW.tenant_id AND chain_id=NEW.chain_id) OR (t->>'observed_at')::timestamptz<h.created_at-interval '5 seconds' OR (t->>'observed_at')::timestamptz>clock_timestamp()+interval '5 seconds' THEN RAISE EXCEPTION 'native terminal original authority or observation time differs';END IF;
 IF jsonb_typeof(NEW.document) IS DISTINCT FROM 'object' OR NOT NEW.document ?& ARRAY['terminal','algorithm','signature'] OR EXISTS(SELECT 1 FROM jsonb_object_keys(NEW.document) x WHERE x<>ALL(ARRAY['terminal','algorithm','signature'])) OR jsonb_typeof(t) IS DISTINCT FROM 'object' OR NOT t ?& ARRAY['schema_version','id','tenant_id','chain_id','program_sha256','authorization_sha256','command_sha256','operation_id','fence','artifact_sha256','preparation_sha256','workspace','references','before','after','head','observed_at'] OR EXISTS(SELECT 1 FROM jsonb_object_keys(t) x WHERE x<>ALL(ARRAY['schema_version','id','tenant_id','chain_id','program_sha256','authorization_sha256','command_sha256','operation_id','fence','artifact_sha256','preparation_sha256','workspace','references','before','after','head','observed_at'])) OR EXISTS(SELECT 1 FROM jsonb_each_text(t) x WHERE x.key IN('program_sha256','authorization_sha256','command_sha256','artifact_sha256','preparation_sha256') AND coalesce(x.value,'')!~'^[a-f0-9]{64}$') THEN RAISE EXCEPTION 'native terminal bounded typed body differs';END IF;
 IF EXISTS(SELECT 1 FROM jsonb_object_keys(t->'after') x WHERE x<>ALL(ARRAY['revision','state_lineage','state_serial','state_sha256','model'])) THEN RAISE EXCEPTION 'native terminal state has unrecognized fields';END IF;
 FOR v_kind,ref,rid IN SELECT 'NATIVE_ARTIFACT_REVIEW',t->'references'->'review',NEW.review_id UNION ALL SELECT 'NATIVE_CAPTURE',t->'references'->'capture',NEW.capture_id UNION ALL SELECT 'AFTER_NATIVE_STATE',t->'references'->'after',NEW.after_id UNION ALL SELECT 'NATIVE_OPERATION_PROOF',jsonb_build_object('id',NEW.artifact_id),NEW.artifact_id LOOP
  SELECT a.document->'artifact' INTO stored FROM public.fleet_group_artifacts a WHERE a.tenant_id=NEW.tenant_id AND a.chain_id=NEW.chain_id AND a.command_id=NEW.command_id AND a.kind=v_kind AND a.id=rid;
  IF stored IS NULL OR stored->>'id' IS DISTINCT FROM ref->>'id' OR (v_kind<>'NATIVE_OPERATION_PROOF' AND stored IS DISTINCT FROM ref) OR (v_kind='NATIVE_OPERATION_PROOF' AND (stored->>'sha256' IS DISTINCT FROM NEW.content_hash OR (stored->>'size_bytes')::integer<>octet_length(NEW.raw_document))) THEN RAISE EXCEPTION 'native terminal lacks exact pinned archive references';END IF;
 END LOOP;
 NEW.writer_role:=who;NEW.created_at:=clock_timestamp();RETURN NEW;
END $$;
CREATE TRIGGER guard_group_native_terminals BEFORE INSERT OR UPDATE OR DELETE ON public.fleet_group_native_terminals FOR EACH ROW EXECUTE FUNCTION public.guard_group_native_terminal();
REVOKE ALL ON FUNCTION public.guard_group_native_terminal() FROM PUBLIC;

CREATE FUNCTION public.guard_group_terminal_selection() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$ DECLARE who text;p jsonb;t public.fleet_group_native_terminals;BEGIN
 who:=coalesce(nullif(current_setting('role',true),'none'),session_user);
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'native terminal selection is immutable';END IF;
 IF who<>'finops_group_ledger' OR coalesce(NEW.tenant_id,'')='' OR NEW.tenant_id IS DISTINCT FROM current_setting('app.tenant_id',true) THEN RAISE EXCEPTION 'native terminal selection requires private ledger tenant';END IF;
 PERFORM public.fleet_group_journal_lock(NEW.tenant_id,(SELECT workload_id FROM public.fleet_group_journal_roots WHERE tenant_id=NEW.tenant_id AND chain_id=NEW.chain_id));
 SELECT h.projection INTO p FROM public.fleet_group_journal_current c JOIN public.fleet_group_journal_heads h ON h.tenant_id=c.tenant_id AND h.chain_id=c.chain_id AND h.content_hash=c.head_hash WHERE c.tenant_id=NEW.tenant_id AND c.chain_id=NEW.chain_id FOR UPDATE OF c;
 SELECT * INTO t FROM public.fleet_group_native_terminals WHERE tenant_id=NEW.tenant_id AND chain_id=NEW.chain_id AND id=NEW.terminal_id;
 IF t.id IS NULL OR t.command_id IS DISTINCT FROM NEW.command_id OR p->'pending'->'command'->>'id' IS DISTINCT FROM NEW.command_id OR p->'pending'->'apply_intent' IS DISTINCT FROM 'true'::jsonb OR p->'pending'->'no_apply' IS NOT NULL OR p->'pending'->'git_repair' IS NOT NULL OR p->'pending'->'command' IS DISTINCT FROM (SELECT h.projection->'pending'->'command' FROM public.fleet_group_journal_heads h WHERE h.tenant_id=t.tenant_id AND h.chain_id=t.chain_id AND h.content_hash=t.head_hash) THEN RAISE EXCEPTION 'native terminal selection requires actual current apply obligation';END IF;
 NEW.writer_role:=who;NEW.created_at:=clock_timestamp();RETURN NEW;
END $$;
CREATE TRIGGER guard_group_native_terminal_selections BEFORE INSERT OR UPDATE OR DELETE ON public.fleet_group_native_terminal_selections FOR EACH ROW EXECUTE FUNCTION public.guard_group_terminal_selection();
REVOKE ALL ON FUNCTION public.guard_group_terminal_selection() FROM PUBLIC;

-- Existing unregistered protocol histories retain their original semantics.
-- A newly operator-installed reconstruction chain must pin its positive native
-- terminal BEFORE publishing APPLIED; missing/UNKNOWN is never NO_APPLY.
CREATE FUNCTION public.guard_group_managed_applied() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$ BEGIN
 IF NEW.kind='APPLIED' AND EXISTS(SELECT 1 FROM public.fleet_group_workspaces WHERE tenant_id=NEW.tenant_id AND chain_id=NEW.chain_id) THEN
  IF NOT EXISTS(SELECT 1 FROM public.fleet_group_native_terminal_selections s JOIN public.fleet_group_native_terminals t ON t.tenant_id=s.tenant_id AND t.chain_id=s.chain_id AND t.id=s.terminal_id WHERE s.tenant_id=NEW.tenant_id AND s.chain_id=NEW.chain_id AND s.command_id=NEW.document->'receipt'->'receipt'->>'command_id' AND t.document->'terminal'->>'operation_id'=NEW.document->'receipt'->'receipt'->>'operation_id' AND t.document->'terminal'->'fence'=NEW.document->'receipt'->'receipt'->'fence' AND t.document->'terminal'->>'artifact_sha256'=NEW.document->'receipt'->'receipt'->>'artifact_sha256' AND t.document->'terminal'->>'preparation_sha256'=NEW.document->'receipt'->'receipt'->>'preparation_sha256' AND t.document->'terminal'->'before'=NEW.document->'receipt'->'receipt'->'before' AND t.document->'terminal'->'after'=NEW.document->'receipt'->'receipt'->'after') THEN RAISE EXCEPTION 'managed native apply requires selected positive terminal';END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER guard_group_managed_applied BEFORE INSERT ON public.fleet_group_journal_records FOR EACH ROW EXECUTE FUNCTION public.guard_group_managed_applied();
REVOKE ALL ON FUNCTION public.guard_group_managed_applied() FROM PUBLIC;
