-- Private capture references, not artifact attestation, a health decision or
-- delivery authority. The trusted producer must first perform exact-version
-- encrypted object readback; PostgreSQL cannot perform that operation.
CREATE UNIQUE INDEX fleet_group_operation_artifact_binding ON public.fleet_group_journal_operations(tenant_id,chain_id,command_id,operation_id,fence);
CREATE TABLE public.fleet_group_artifacts (
 tenant_id text NOT NULL,chain_id text NOT NULL,command_id text NOT NULL,
 operation_id text NOT NULL,fence numeric(20,0) NOT NULL,
 kind text NOT NULL CHECK(kind IN('SAVED_PLAN','PLAN_JSON','BEFORE_NATIVE_STATE','AFTER_NATIVE_STATE','NATIVE_CAPTURE','NATIVE_ARTIFACT_REVIEW','NATIVE_OPERATION_PROOF','HEALTH_RECEIPT','HEALTH_BASELINE','HEALTH_VERDICT','GIT_PROOF_SET','FIXTURE_CURRENT','FIXTURE_DEPENDENCY','FIXTURE_SLO')),
 id text NOT NULL CHECK(id~'^[A-Za-z0-9][A-Za-z0-9_.-]{0,255}$'),
 content_hash text NOT NULL CHECK(content_hash~'^[a-f0-9]{64}$'),
 document jsonb NOT NULL,raw_document bytea NOT NULL CHECK(octet_length(raw_document) BETWEEN 1 AND 16384),
 writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,chain_id,command_id,kind,id),
 FOREIGN KEY(tenant_id,chain_id,command_id,operation_id,fence) REFERENCES public.fleet_group_journal_operations(tenant_id,chain_id,command_id,operation_id,fence)
);
ALTER TABLE public.fleet_group_artifacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.fleet_group_artifacts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON public.fleet_group_artifacts USING(tenant_id=current_setting('app.tenant_id',true)) WITH CHECK(tenant_id=current_setting('app.tenant_id',true));
REVOKE ALL ON public.fleet_group_artifacts FROM PUBLIC;
GRANT SELECT,INSERT ON public.fleet_group_artifacts TO finops_group_pipeline;
GRANT SELECT ON public.fleet_group_artifacts TO finops_group_ledger;

-- The pipeline may resolve only an actually issued operation. In particular it
-- cannot supply its own proposal, installation generation, image or key roots.
-- These historical bindings remain readable during owned recovery after source
-- revocation; fresh forward admission is a separate current-source gate.
CREATE FUNCTION public.fleet_group_artifact_scope(p_tenant text,p_chain text,p_command text) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$ DECLARE out jsonb;BEGIN
 IF coalesce(p_tenant,'')='' OR p_tenant IS DISTINCT FROM current_setting('app.tenant_id',true) OR coalesce(p_chain,'')='' OR coalesce(p_command,'')='' THEN RETURN NULL;END IF;
 SELECT jsonb_build_object('schema_version','1','tenant_id',r.tenant_id,'chain_id',r.chain_id,'command_id',o.command_id,'operation_id',o.operation_id,'fence',o.fence,'prepared_program_id',r.prepared_program_id,'proposal_id',p.id,'profile_id',p.profile_id,'profile_generation',p.profile_generation,'producer_image_sha256',f.document->'installation'->>'toolchain_image_sha256','key_binding_id',k.id,'pipeline_id',k.pipeline_id,'pipeline_key_sha256',encode(sha256(k.pipeline_key),'hex'),'source_id',k.source_id,'issuer',k.issuer,'subject',k.subject,'audience',k.audience)
 INTO out FROM public.fleet_group_journal_roots r
 JOIN public.fleet_group_journal_operations o ON o.tenant_id=r.tenant_id AND o.chain_id=r.chain_id
 JOIN public.fleet_fixture_prepared_programs g ON g.tenant_id=r.tenant_id AND g.id=r.prepared_program_id
 JOIN public.fleet_fixture_proposals p ON p.tenant_id=g.tenant_id AND p.id=g.proposal_id
 JOIN public.fleet_fixture_profiles f ON f.id=p.profile_id AND f.generation=p.profile_generation
 JOIN public.fleet_group_journal_key_bindings k ON k.tenant_id=r.tenant_id AND k.id=r.key_binding_id AND k.profile_id=p.profile_id AND k.profile_generation=p.profile_generation
 WHERE r.tenant_id=p_tenant AND r.chain_id=p_chain AND o.command_id=p_command;
 RETURN out;
END $$;
REVOKE ALL ON FUNCTION public.fleet_group_artifact_scope(text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.fleet_group_artifact_scope(text,text,text) TO finops_group_pipeline;

-- A selected capture becomes usable only when the consumer matches it to the
-- exact CURRENT finalized command. Old captures remain immutable/auditable but
-- cannot authorize a re-finalized command. This is not a dispatch permit.
CREATE FUNCTION public.fleet_group_artifact_finalized(p_tenant text,p_chain text,p_command text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$ DECLARE p jsonb;c jsonb;head text;BEGIN
 IF coalesce(p_tenant,'')='' OR p_tenant IS DISTINCT FROM current_setting('app.tenant_id',true) OR coalesce(p_chain,'')='' OR coalesce(p_command,'')='' THEN RETURN NULL;END IF;
 SELECT c.head_hash INTO head FROM public.fleet_group_journal_current c WHERE c.tenant_id=p_tenant AND c.chain_id=p_chain FOR SHARE;
 SELECT h.projection INTO p FROM public.fleet_group_journal_heads h WHERE h.tenant_id=p_tenant AND h.chain_id=p_chain AND h.content_hash=head;
 IF p->'pending'->'command'->>'id'=p_command THEN
  c:=p->'pending'->'command';
  RETURN coalesce(c->'forward'->'child'->'artifact',c->'recovery'->'recovery'->'artifact',p->'pending'->'finalized'->'finalization'->'artifact');
 ELSIF p->'original_pending'->'command'->>'id'=p_command THEN
  c:=p->'original_pending'->'command';RETURN coalesce(c->'forward'->'child'->'artifact',c->'recovery'->'recovery'->'artifact');
 END IF;
 RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION public.fleet_group_artifact_finalized(text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.fleet_group_artifact_finalized(text,text,text) TO finops_group_pipeline,finops_group_ledger;

CREATE FUNCTION public.guard_fleet_group_artifact() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$ DECLARE scope jsonb;ref jsonb;BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'group artifact references are immutable';END IF;
 IF current_user<>'finops_group_pipeline' OR coalesce(NEW.tenant_id,'')='' OR NEW.tenant_id IS DISTINCT FROM current_setting('app.tenant_id',true) THEN RAISE EXCEPTION 'group artifact requires commissioned private pipeline tenant';END IF;
 scope:=public.fleet_group_artifact_scope(NEW.tenant_id,NEW.chain_id,NEW.command_id);ref:=NEW.document->'artifact';
 IF scope IS NULL OR NEW.document->'scope' IS DISTINCT FROM scope OR NEW.document->>'kind' IS DISTINCT FROM NEW.kind OR NEW.operation_id IS DISTINCT FROM scope->>'operation_id' OR NEW.fence IS DISTINCT FROM (scope->>'fence')::numeric OR NEW.document->'schema_version' IS DISTINCT FROM '"1"'::jsonb OR jsonb_typeof(NEW.document) IS DISTINCT FROM 'object' OR EXISTS(SELECT 1 FROM jsonb_object_keys(NEW.document) k WHERE k<>ALL(ARRAY['schema_version','scope','kind','artifact'])) OR NOT NEW.document ?& ARRAY['schema_version','scope','kind','artifact'] THEN RAISE EXCEPTION 'group artifact issued operation or scope differs';END IF;
 IF jsonb_typeof(ref) IS DISTINCT FROM 'object' OR NOT ref ?& ARRAY['id','bucket','key','version_id','sha256','size_bytes'] OR EXISTS(SELECT 1 FROM jsonb_object_keys(ref) k WHERE k<>ALL(ARRAY['id','bucket','key','version_id','sha256','size_bytes'])) OR EXISTS(SELECT 1 FROM jsonb_each(ref) e WHERE e.key<>'size_bytes' AND jsonb_typeof(e.value)<>'string') OR jsonb_typeof(ref->'size_bytes') IS DISTINCT FROM 'number' OR (ref->>'size_bytes') !~ '^[0-9]+$' OR (ref->>'size_bytes')::numeric NOT BETWEEN 1 AND 16777216 OR ref->>'id' IS DISTINCT FROM NEW.id OR coalesce(ref->>'bucket','')!~'^[A-Za-z0-9][A-Za-z0-9_.-]{0,255}$' OR coalesce(ref->>'sha256','')!~'^[a-f0-9]{64}$' OR length(coalesce(ref->>'version_id','')) NOT BETWEEN 1 AND 1024 OR ref->>'version_id'='null' OR ref->>'version_id'~'[^!-~]' OR ref->>'key' IS DISTINCT FROM 'tenant/'||NEW.tenant_id||'/fleet-group-fixture/'||(scope->>'proposal_id')||'/'||(scope->>'profile_generation')||'/'||NEW.id||'.encrypted' THEN RAISE EXCEPTION 'group artifact pinned encrypted object reference differs';END IF;
 IF encode(sha256(NEW.raw_document),'hex') IS DISTINCT FROM NEW.content_hash OR convert_from(NEW.raw_document,'UTF8')::jsonb IS DISTINCT FROM NEW.document THEN RAISE EXCEPTION 'group artifact canonical raw hash differs';END IF;
 NEW.writer_role:=current_user;NEW.created_at:=clock_timestamp();RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION public.guard_fleet_group_artifact() FROM PUBLIC;
CREATE TRIGGER guard_fleet_group_artifacts BEFORE INSERT OR UPDATE OR DELETE ON public.fleet_group_artifacts FOR EACH ROW EXECUTE FUNCTION public.guard_fleet_group_artifact();
