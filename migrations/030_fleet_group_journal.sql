-- Private fixture journal repository. SQL enforces storage/identity boundaries;
-- the dedicated Go ledger verifies Ed25519 and the frozen transition algebra.
-- These tables do not confer native, financial, public API or execution authority.
DO $$ BEGIN
 IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='finops_group_ledger') THEN CREATE ROLE finops_group_ledger NOLOGIN; END IF;
 IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='finops_group_pipeline') THEN CREATE ROLE finops_group_pipeline NOLOGIN; END IF;
END $$;
GRANT USAGE ON SCHEMA public TO finops_group_ledger,finops_group_pipeline;

-- Commissioned by the database operator, separately from the fixture producer,
-- signer, ledger and pipeline. Only public keys and exact machine identity live
-- here. Application roles have no installation or mutation privilege.
CREATE TABLE fleet_group_journal_key_bindings (
 tenant_id text NOT NULL,id text NOT NULL,profile_id text NOT NULL,profile_generation text NOT NULL,
 realm jsonb NOT NULL,pipeline_id text NOT NULL,source_id text NOT NULL,
 issuer text NOT NULL,subject text NOT NULL,audience text NOT NULL,
 signer_key bytea NOT NULL CHECK(octet_length(signer_key)=32),
 pipeline_key bytea NOT NULL CHECK(octet_length(pipeline_key)=32),
 ledger_key bytea NOT NULL CHECK(octet_length(ledger_key)=32),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,id),UNIQUE(tenant_id,profile_id,profile_generation,pipeline_id),
 CHECK(signer_key<>pipeline_key AND signer_key<>ledger_key AND pipeline_key<>ledger_key),
 CHECK(length(tenant_id) BETWEEN 1 AND 256 AND length(id) BETWEEN 1 AND 256 AND length(source_id) BETWEEN 1 AND 256),
 CHECK(length(issuer) BETWEEN 1 AND 2048 AND length(subject) BETWEEN 1 AND 512 AND length(audience) BETWEEN 1 AND 256)
);
CREATE FUNCTION guard_fleet_group_key_binding() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$ BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'commissioned group keys are immutable';END IF;
 IF jsonb_typeof(NEW.realm) IS DISTINCT FROM 'object' OR NEW.realm->>'kind' IS DISTINCT FROM 'ISOLATED_FIXTURE' OR NEW.realm->>'fixture_id' IS DISTINCT FROM NEW.profile_id OR NEW.realm->>'generation' IS DISTINCT FROM NEW.profile_generation OR NOT EXISTS(SELECT 1 FROM public.fleet_fixture_profiles WHERE id=NEW.profile_id AND generation=NEW.profile_generation AND document->>'model_sha256'=NEW.realm->>'model_sha256') THEN RAISE EXCEPTION 'commissioned group profile differs';END IF;
 NEW.created_at:=clock_timestamp();RETURN NEW;
END $$;
ALTER TABLE fleet_group_journal_key_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE fleet_group_journal_key_bindings FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON fleet_group_journal_key_bindings USING(tenant_id=current_setting('app.tenant_id',true)) WITH CHECK(tenant_id=current_setting('app.tenant_id',true));
CREATE TRIGGER guard_fleet_group_key_binding BEFORE INSERT OR UPDATE OR DELETE ON fleet_group_journal_key_bindings FOR EACH ROW EXECUTE FUNCTION guard_fleet_group_key_binding();
REVOKE ALL ON FUNCTION guard_fleet_group_key_binding() FROM PUBLIC;
GRANT SELECT ON fleet_group_journal_key_bindings TO finops_group_ledger,finops_group_pipeline;

CREATE TABLE fleet_group_journal_authority_drafts (
 tenant_id text NOT NULL,id text NOT NULL,chain_id text NOT NULL,kind text NOT NULL CHECK(kind IN('JOURNAL','CONTINUATION')),
 prepared_program_id text NOT NULL,key_binding_id text NOT NULL,parent_hash text NOT NULL CHECK(parent_hash~'^[a-f0-9]{64}$'),
 content_hash text NOT NULL CHECK(content_hash~'^[a-f0-9]{64}$'),document jsonb NOT NULL,raw_document bytea NOT NULL,
 writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,id),UNIQUE(tenant_id,chain_id,kind,content_hash),
 FOREIGN KEY(tenant_id,prepared_program_id) REFERENCES fleet_fixture_prepared_programs(tenant_id,id),
 FOREIGN KEY(tenant_id,key_binding_id) REFERENCES fleet_group_journal_key_bindings(tenant_id,id),
 CHECK(octet_length(raw_document) BETWEEN 1 AND 1048576)
);
CREATE TABLE fleet_group_journal_authority_approvals (
 tenant_id text NOT NULL,id text NOT NULL,draft_id text NOT NULL,actor_id text NOT NULL,
 body_hash text NOT NULL CHECK(body_hash~'^[a-f0-9]{64}$'),role text NOT NULL DEFAULT 'fleet_approver' CHECK(role='fleet_approver'),
 writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,id),UNIQUE(tenant_id,draft_id),
 FOREIGN KEY(tenant_id,draft_id) REFERENCES fleet_group_journal_authority_drafts(tenant_id,id),CHECK(length(actor_id) BETWEEN 1 AND 256)
);
ALTER TABLE fleet_group_journal_authority_drafts ENABLE ROW LEVEL SECURITY;
ALTER TABLE fleet_group_journal_authority_drafts FORCE ROW LEVEL SECURITY;
ALTER TABLE fleet_group_journal_authority_approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE fleet_group_journal_authority_approvals FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON fleet_group_journal_authority_drafts USING(tenant_id=current_setting('app.tenant_id',true)) WITH CHECK(tenant_id=current_setting('app.tenant_id',true));
CREATE POLICY tenant_isolation ON fleet_group_journal_authority_approvals USING(tenant_id=current_setting('app.tenant_id',true)) WITH CHECK(tenant_id=current_setting('app.tenant_id',true));
GRANT SELECT ON fleet_group_journal_authority_drafts,fleet_group_journal_authority_approvals TO finops_api,finops_group_ledger;
GRANT INSERT ON fleet_group_journal_authority_drafts TO finops_group_ledger;
GRANT INSERT ON fleet_group_journal_authority_approvals TO finops_api;

CREATE TABLE fleet_group_journal_roots (
 tenant_id text NOT NULL,chain_id text NOT NULL,workload_id text NOT NULL,
 prepared_program_id text NOT NULL,approval_id text NOT NULL,key_binding_id text NOT NULL,
 parent_hash text NOT NULL CHECK(parent_hash~'^[a-f0-9]{64}$'),
 authorization_hash text NOT NULL CHECK(authorization_hash~'^[a-f0-9]{64}$'),
 content_hash text NOT NULL CHECK(content_hash~'^[a-f0-9]{64}$'),
 document jsonb NOT NULL,raw_document bytea NOT NULL,
 writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,chain_id),UNIQUE(tenant_id,parent_hash),
 FOREIGN KEY(tenant_id,prepared_program_id) REFERENCES fleet_fixture_prepared_programs(tenant_id,id),
 FOREIGN KEY(tenant_id,approval_id) REFERENCES fleet_fixture_approvals(tenant_id,id),
 FOREIGN KEY(tenant_id,key_binding_id) REFERENCES fleet_group_journal_key_bindings(tenant_id,id),
 CHECK(octet_length(raw_document) BETWEEN 1 AND 2097152)
);
CREATE TABLE fleet_group_journal_chain_authorizations (
 tenant_id text NOT NULL,chain_id text NOT NULL,content_hash text NOT NULL CHECK(content_hash~'^[a-f0-9]{64}$'),
 document jsonb NOT NULL,raw_document bytea NOT NULL,writer_role text NOT NULL DEFAULT current_user,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(tenant_id,chain_id),
 FOREIGN KEY(tenant_id,chain_id) REFERENCES fleet_group_journal_roots(tenant_id,chain_id),
 CHECK(octet_length(raw_document) BETWEEN 1 AND 1048576)
);
CREATE TABLE fleet_group_journal_segments (
 tenant_id text NOT NULL,chain_id text NOT NULL,segment numeric(20,0) NOT NULL CHECK(segment BETWEEN 0 AND 18446744073709551615),
 kind text NOT NULL CHECK(kind IN('ORIGINAL_JOURNAL','RECOVERY_SEGMENT')),
 checkpoint_hash text NOT NULL,document jsonb NOT NULL,raw_document bytea NOT NULL,
 writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,chain_id,segment),FOREIGN KEY(tenant_id,chain_id) REFERENCES fleet_group_journal_roots(tenant_id,chain_id),
 CHECK((segment=0 AND kind='ORIGINAL_JOURNAL' AND checkpoint_hash='') OR (segment>0 AND kind='RECOVERY_SEGMENT' AND checkpoint_hash~'^[a-f0-9]{64}$')),
 CHECK(octet_length(raw_document) BETWEEN 1 AND 8388608)
);
CREATE TABLE fleet_group_journal_records (
 tenant_id text NOT NULL,chain_id text NOT NULL,segment numeric(20,0) NOT NULL,sequence integer NOT NULL CHECK(sequence BETWEEN 1 AND 512),
 kind text NOT NULL,content_hash text NOT NULL CHECK(content_hash~'^[a-f0-9]{64}$'),
 document jsonb NOT NULL,raw_document bytea NOT NULL,
 head_hash text NOT NULL CHECK(head_hash~'^[a-f0-9]{64}$'),head jsonb NOT NULL,raw_head bytea NOT NULL,
 writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,chain_id,segment,sequence),FOREIGN KEY(tenant_id,chain_id,segment) REFERENCES fleet_group_journal_segments(tenant_id,chain_id,segment),
 CHECK(octet_length(raw_document) BETWEEN 1 AND 65535),CHECK(octet_length(raw_head) BETWEEN 1 AND 16384)
);
CREATE TABLE fleet_group_journal_heads (
 tenant_id text NOT NULL,chain_id text NOT NULL,content_hash text NOT NULL CHECK(content_hash~'^[a-f0-9]{64}$'),
 segment numeric(20,0) NOT NULL,record_count integer NOT NULL CHECK(record_count BETWEEN 0 AND 512),
 document jsonb NOT NULL,raw_document bytea NOT NULL,projection jsonb NOT NULL,raw_projection bytea NOT NULL,
 cursor_document jsonb NOT NULL,raw_cursor bytea NOT NULL,
 writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,chain_id,content_hash),FOREIGN KEY(tenant_id,chain_id,segment) REFERENCES fleet_group_journal_segments(tenant_id,chain_id,segment),
 CHECK(octet_length(raw_document) BETWEEN 1 AND 16384),CHECK(octet_length(raw_projection) BETWEEN 1 AND 8388608),CHECK(octet_length(raw_cursor) BETWEEN 1 AND 16384)
);
CREATE TABLE fleet_group_journal_current (
 tenant_id text NOT NULL,chain_id text NOT NULL,version bigint NOT NULL CHECK(version>0),
 head_hash text NOT NULL,document jsonb NOT NULL,raw_document bytea NOT NULL,
 writer_role text NOT NULL DEFAULT current_user,updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,chain_id),FOREIGN KEY(tenant_id,chain_id,head_hash) REFERENCES fleet_group_journal_heads(tenant_id,chain_id,content_hash)
);
CREATE TABLE fleet_group_journal_identities (
 tenant_id text NOT NULL,chain_id text NOT NULL,namespace text NOT NULL CHECK(namespace IN('COMMAND_ID','OPERATION_ID','COMMAND_KEY','SIGNED_ID','NONCE','RECEIPT_ID','RECEIPT_KEY')),
 identity text NOT NULL CHECK(length(identity) BETWEEN 1 AND 512 AND identity!~E'[\\n\\r]'),
 ordinal numeric(20,0) NOT NULL CHECK(ordinal BETWEEN 1 AND 18446744073709551615),
 content_hash text NOT NULL CHECK(content_hash~'^[a-f0-9]{64}$'),root_hash text NOT NULL CHECK(root_hash~'^[a-f0-9]{64}$'),
 raw_step bytea NOT NULL CHECK(octet_length(raw_step) BETWEEN 1 AND 2048),
 writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,chain_id,namespace,identity),UNIQUE(tenant_id,chain_id,ordinal),
 FOREIGN KEY(tenant_id,chain_id) REFERENCES fleet_group_journal_roots(tenant_id,chain_id)
);
CREATE TABLE fleet_group_journal_reservations (
 tenant_id text NOT NULL,chain_id text NOT NULL,workload_id text NOT NULL,
 obligation_hash text NOT NULL CHECK(obligation_hash~'^[a-f0-9]{64}$'),
 released_at timestamptz,release_head_hash text,writer_role text NOT NULL DEFAULT current_user,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(tenant_id,chain_id),
 FOREIGN KEY(tenant_id,chain_id) REFERENCES fleet_group_journal_roots(tenant_id,chain_id),
 FOREIGN KEY(tenant_id,chain_id,release_head_hash) REFERENCES fleet_group_journal_heads(tenant_id,chain_id,content_hash)
);
CREATE INDEX fleet_group_journal_active_workloads ON fleet_group_journal_reservations(tenant_id,workload_id) WHERE released_at IS NULL;
CREATE TABLE fleet_group_pipeline_inbox (
 tenant_id text NOT NULL,chain_id text NOT NULL,id text NOT NULL,receipt_key text NOT NULL,command_id text NOT NULL,
 source_id text NOT NULL,issuer text NOT NULL,subject text NOT NULL,audience text NOT NULL,
 kind text NOT NULL CHECK(kind IN('ORIGINAL_JOURNAL','RECOVERY_SEGMENT')),
 body_hash text NOT NULL CHECK(body_hash~'^[a-f0-9]{64}$'),document jsonb NOT NULL,raw_body bytea NOT NULL,
 writer_role text NOT NULL DEFAULT current_user,received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,chain_id,id),UNIQUE(tenant_id,chain_id,receipt_key),
 FOREIGN KEY(tenant_id,chain_id) REFERENCES fleet_group_journal_roots(tenant_id,chain_id),CHECK(octet_length(raw_body) BETWEEN 1 AND 65536)
);
CREATE TABLE fleet_group_journal_operations (
 tenant_id text NOT NULL,chain_id text NOT NULL,command_id text NOT NULL,operation_id text NOT NULL,
 fence numeric(20,0) NOT NULL CHECK(fence BETWEEN 1 AND 18446744073709551615),command_hash text NOT NULL CHECK(command_hash~'^[a-f0-9]{64}$'),
 document jsonb NOT NULL,raw_document bytea NOT NULL,writer_role text NOT NULL DEFAULT current_user,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(tenant_id,chain_id,command_id),UNIQUE(tenant_id,chain_id,operation_id),UNIQUE(tenant_id,chain_id,fence),
 FOREIGN KEY(tenant_id,chain_id) REFERENCES fleet_group_journal_roots(tenant_id,chain_id),CHECK(octet_length(raw_document) BETWEEN 1 AND 65535)
);
CREATE TABLE fleet_group_journal_outbox (
 tenant_id text NOT NULL,chain_id text NOT NULL,id text NOT NULL,command_id text NOT NULL,
 action text NOT NULL CHECK(action IN('GIT_ADVANCE','APPLY','GIT_REPAIR','RECONCILE')),
 command_hash text NOT NULL CHECK(command_hash~'^[a-f0-9]{64}$'),head_hash text NOT NULL,
 document jsonb NOT NULL,raw_document bytea NOT NULL,
 state text NOT NULL DEFAULT 'PENDING' CHECK(state IN('PENDING','ATTEMPTED','RECONCILE','COMPLETE')),
 attempt_id text,attempted_at timestamptz,lease_until timestamptz,
 writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,chain_id,id),UNIQUE(tenant_id,chain_id,command_id,action),
 FOREIGN KEY(tenant_id,chain_id,command_id) REFERENCES fleet_group_journal_operations(tenant_id,chain_id,command_id),
 FOREIGN KEY(tenant_id,chain_id,head_hash) REFERENCES fleet_group_journal_heads(tenant_id,chain_id,content_hash),CHECK(octet_length(raw_document) BETWEEN 1 AND 131072)
);

CREATE FUNCTION fleet_group_pipeline_binding(p_tenant text,p_chain text,p_source text,p_issuer text,p_subject text,p_audience text,p_command text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
 SELECT p_tenant IS NOT NULL AND p_tenant<>'' AND p_tenant=current_setting('app.tenant_id',true) AND EXISTS(SELECT 1 FROM public.fleet_group_journal_roots r JOIN public.fleet_group_journal_key_bindings k ON k.tenant_id=r.tenant_id AND k.id=r.key_binding_id JOIN public.fleet_group_journal_operations o ON o.tenant_id=r.tenant_id AND o.chain_id=r.chain_id WHERE r.tenant_id=p_tenant AND r.chain_id=p_chain AND k.source_id=p_source AND k.issuer=p_issuer AND k.subject=p_subject AND k.audience=p_audience AND o.command_id=p_command)
$$;
REVOKE ALL ON FUNCTION fleet_group_pipeline_binding(text,text,text,text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION fleet_group_pipeline_binding(text,text,text,text,text,text,text) TO finops_group_pipeline;

-- Currentness is server-selected from immutable prepared IDs; it is not a
-- caller-supplied source-status array. No broad selector/source table grants.
CREATE FUNCTION fleet_group_prepared_current(p_tenant text,p_prepared text) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$ DECLARE p jsonb;g public.fleet_fixture_prepared_programs;BEGIN
 IF coalesce(p_tenant,'')='' OR p_tenant IS DISTINCT FROM current_setting('app.tenant_id',true) OR coalesce(p_prepared,'')='' THEN RETURN false;END IF;
 SELECT * INTO g FROM public.fleet_fixture_prepared_programs WHERE tenant_id=p_tenant AND id=p_prepared;IF g.id IS NULL THEN RETURN false;END IF;
 p:=public.fleet_fixture_proposal_current(p_tenant,g.proposal_id);
 RETURN p IS NOT NULL AND g.program->'binding' IS NOT DISTINCT FROM p->'binding' AND g.program->'realm' IS NOT DISTINCT FROM p->'realm' AND g.program->>'creator_id' IS NOT DISTINCT FROM p->>'creator_id';
END $$;
REVOKE ALL ON FUNCTION fleet_group_prepared_current(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION fleet_group_prepared_current(text,text) TO finops_group_ledger,finops_signer,finops_api;

CREATE FUNCTION fleet_group_zero_current(p_tenant text,p_chain text) RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
 SELECT coalesce(p_tenant,'')<>'' AND p_tenant=current_setting('app.tenant_id',true) AND EXISTS(SELECT 1 FROM public.fleet_group_journal_current c WHERE c.tenant_id=p_tenant AND c.chain_id=p_chain AND c.document->>'kind'='ORIGINAL_JOURNAL' AND (c.document->>'record_count')::integer=0)
$$;
REVOKE ALL ON FUNCTION fleet_group_zero_current(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION fleet_group_zero_current(text,text) TO finops_api,finops_group_ledger;

CREATE FUNCTION guard_fleet_group_authority_review() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$ DECLARE d public.fleet_group_journal_authority_drafts;p public.fleet_fixture_prepared_programs;w text;BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'group authority reviews are immutable';END IF;
 IF NEW.tenant_id IS DISTINCT FROM current_setting('app.tenant_id',true) THEN RAISE EXCEPTION 'group authority review tenant differs';END IF;
 IF TG_TABLE_NAME='fleet_group_journal_authority_drafts' THEN
  IF current_user<>'finops_group_ledger' THEN RAISE EXCEPTION 'group authority drafts require ledger';END IF;
  SELECT * INTO p FROM public.fleet_fixture_prepared_programs WHERE tenant_id=NEW.tenant_id AND id=NEW.prepared_program_id;
  IF p.id IS NULL OR convert_from(NEW.raw_document,'UTF8')::jsonb IS DISTINCT FROM NEW.document OR encode(sha256(NEW.raw_document),'hex') IS DISTINCT FROM NEW.content_hash OR NEW.document->>'parent_envelope_sha256' IS DISTINCT FROM NEW.parent_hash THEN RAISE EXCEPTION 'group authority draft body differs';END IF;
  IF (NEW.document->>'created_at')::timestamptz IS NULL OR (NEW.document->>'created_at')::timestamptz<clock_timestamp()-interval '5 seconds' OR (NEW.document->>'created_at')::timestamptz>clock_timestamp()+interval '5 seconds' THEN RAISE EXCEPTION 'group authority draft must use current server time';END IF;
  PERFORM public.fleet_group_journal_lock(NEW.tenant_id,p.program->'binding'->'old'->'target'->>'workload_id');
  IF NOT public.fleet_group_prepared_current(NEW.tenant_id,NEW.prepared_program_id) THEN RAISE EXCEPTION 'group authority selection no longer current';END IF;
  IF NOT EXISTS(SELECT 1 FROM public.fleet_group_journal_key_bindings k WHERE k.tenant_id=NEW.tenant_id AND k.id=NEW.key_binding_id AND k.realm=p.program->'realm' AND k.pipeline_id=p.program->'artifact_context'->>'pipeline_id' AND NEW.document->>'pipeline_key_sha256'=encode(sha256(k.pipeline_key),'hex') AND NEW.document->>'ledger_key_sha256'=encode(sha256(k.ledger_key),'hex')) THEN RAISE EXCEPTION 'group authority draft commissioned keys differ';END IF;
  IF NEW.kind='JOURNAL' THEN
   IF NEW.document->>'schema_version' IS DISTINCT FROM '1' OR NEW.document->>'kind' IS DISTINCT FROM 'ISOLATED_GROUP_TRANSITION_JOURNAL' OR NEW.document->>'parent_sha256' IS DISTINCT FROM p.program_hash OR NEW.document->'base' IS DISTINCT FROM p.journal_review->'base' OR NEW.document->>'ref' IS DISTINCT FROM p.journal_review->>'ref' OR NEW.document->>'pipeline_id' IS DISTINCT FROM p.journal_review->>'pipeline_id' OR (NEW.document->>'maximum_effects')::numeric IS DISTINCT FROM (p.journal_review->>'max_effects')::numeric OR (NEW.document->>'maximum_records')::numeric IS DISTINCT FROM (p.journal_review->>'max_records')::numeric OR (NEW.document->>'expires_at')::timestamptz IS DISTINCT FROM (p.journal_review->>'expires_at')::timestamptz THEN RAISE EXCEPTION 'journal draft exceeds reviewed program';END IF;
  ELSE
   IF NEW.document->>'chain_id' IS DISTINCT FROM NEW.chain_id OR NOT EXISTS(SELECT 1 FROM public.fleet_group_journal_roots r JOIN public.fleet_group_journal_current c ON c.tenant_id=r.tenant_id AND c.chain_id=r.chain_id WHERE r.tenant_id=NEW.tenant_id AND r.chain_id=NEW.chain_id AND r.parent_hash=NEW.parent_hash AND r.prepared_program_id=NEW.prepared_program_id AND r.key_binding_id=NEW.key_binding_id AND c.document->>'kind'='ORIGINAL_JOURNAL' AND (c.document->>'record_count')::integer=0 AND NEW.document->>'journal_authorization_sha256'=r.authorization_hash) THEN RAISE EXCEPTION 'continuation draft requires actual zero-record root';END IF;
   IF NEW.document->'bootstrap_head' IS DISTINCT FROM (SELECT h.document FROM public.fleet_group_journal_current c JOIN public.fleet_group_journal_heads h ON h.tenant_id=c.tenant_id AND h.chain_id=c.chain_id AND h.content_hash=c.head_hash WHERE c.tenant_id=NEW.tenant_id AND c.chain_id=NEW.chain_id) THEN RAISE EXCEPTION 'continuation draft requires actual issued zero head';END IF;
  END IF;
 ELSE
  IF current_user<>'finops_api' THEN RAISE EXCEPTION 'group authority approval requires API';END IF;
  SELECT * INTO d FROM public.fleet_group_journal_authority_drafts WHERE tenant_id=NEW.tenant_id AND id=NEW.draft_id;
  SELECT * INTO p FROM public.fleet_fixture_prepared_programs WHERE tenant_id=NEW.tenant_id AND id=d.prepared_program_id;
  IF d.id IS NULL OR p.id IS NULL OR NEW.actor_id=p.program->>'creator_id' OR NEW.actor_id!~'^[!-~]+$' OR NEW.body_hash IS DISTINCT FROM d.content_hash THEN RAISE EXCEPTION 'independent exact group authority approval required';END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id||':dependency-graph',0));
  PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id||':fleet-workload:'||(p.program->'binding'->'old'->'target'->>'workload_id'),0));
  IF NOT public.fleet_group_prepared_current(NEW.tenant_id,p.id) OR coalesce(d.document->>'expires_at',d.document->>'forward_expires_at')::timestamptz<=clock_timestamp() THEN RAISE EXCEPTION 'group authority draft no longer approvable';END IF;
  IF (d.document->>'created_at')::timestamptz IS NULL OR (d.document->>'created_at')::timestamptz>clock_timestamp()+interval '5 seconds' OR clock_timestamp()>(d.document->>'created_at')::timestamptz+interval '30 minutes' THEN RAISE EXCEPTION 'group authority draft review window expired';END IF;
  IF d.kind='CONTINUATION' AND NOT public.fleet_group_zero_current(NEW.tenant_id,d.chain_id) THEN RAISE EXCEPTION 'continuation approval requires current zero-record head';END IF;
 END IF;
 NEW.writer_role:=current_user;NEW.created_at:=clock_timestamp();RETURN NEW;
END $$;
CREATE TRIGGER guard_fleet_group_authority_drafts BEFORE INSERT OR UPDATE OR DELETE ON fleet_group_journal_authority_drafts FOR EACH ROW EXECUTE FUNCTION guard_fleet_group_authority_review();
CREATE TRIGGER guard_fleet_group_authority_approvals BEFORE INSERT OR UPDATE OR DELETE ON fleet_group_journal_authority_approvals FOR EACH ROW EXECUTE FUNCTION guard_fleet_group_authority_review();
REVOKE ALL ON FUNCTION guard_fleet_group_authority_review() FROM PUBLIC;

CREATE FUNCTION fleet_group_authority_approved(p_tenant text,p_chain text,p_prepared text,p_key text,p_parent text,p_kind text,p_body jsonb,p_approvals jsonb) RETURNS boolean LANGUAGE plpgsql STABLE SET search_path=pg_catalog,public,pg_temp AS $$ BEGIN
 IF jsonb_typeof(p_approvals) IS DISTINCT FROM 'array' OR jsonb_array_length(p_approvals)<>1 THEN RETURN false;END IF;
 RETURN EXISTS(SELECT 1 FROM public.fleet_group_journal_authority_drafts d JOIN public.fleet_group_journal_authority_approvals a ON a.tenant_id=d.tenant_id AND a.draft_id=d.id WHERE d.tenant_id=p_tenant AND d.chain_id=p_chain AND d.prepared_program_id=p_prepared AND d.key_binding_id=p_key AND d.parent_hash=p_parent AND d.kind=p_kind AND d.document=p_body AND a.body_hash=d.content_hash AND a.writer_role='finops_api' AND p_approvals->0->>'id'=a.id AND p_approvals->0->>'tenant_id'=a.tenant_id AND p_approvals->0->>'actor_id'=a.actor_id AND p_approvals->0->>'role'=a.role AND p_approvals->0->>'authorization_sha256'=a.body_hash AND (p_approvals->0->>'approved_at')::timestamptz=a.created_at);
END $$;
REVOKE ALL ON FUNCTION fleet_group_authority_approved(text,text,text,text,text,text,jsonb,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION fleet_group_authority_approved(text,text,text,text,text,text,jsonb,jsonb) TO finops_group_ledger;

CREATE FUNCTION fleet_group_journal_lock(p_tenant text,p_workload text) RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$ BEGIN
 IF coalesce(p_tenant,'')='' OR p_tenant IS DISTINCT FROM current_setting('app.tenant_id',true) OR coalesce(p_workload,'')='' THEN RAISE EXCEPTION 'group journal tenant or workload mismatch';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(p_tenant||':dependency-graph',0));
 PERFORM pg_advisory_xact_lock(hashtextextended(p_tenant||':fleet-workload:'||p_workload,0));
END $$;
CREATE FUNCTION fleet_group_admission(p_tenant text,p_workload text,p_family text,p_owned_chain text DEFAULT NULL) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$ BEGIN
 IF p_family IS NULL OR p_family NOT IN('R1','V4','GROUP') THEN RAISE EXCEPTION 'group admission family invalid';END IF;
 PERFORM public.fleet_group_journal_lock(p_tenant,p_workload);
 IF p_owned_chain IS NOT NULL AND (p_family<>'GROUP' OR NOT pg_has_role(session_user,'finops_group_ledger','MEMBER') OR NOT EXISTS(SELECT 1 FROM public.fleet_group_journal_roots j JOIN public.fleet_group_journal_reservations r ON r.tenant_id=j.tenant_id AND r.chain_id=j.chain_id WHERE j.tenant_id=p_tenant AND j.chain_id=p_owned_chain AND j.workload_id=p_workload AND r.workload_id=p_workload AND r.released_at IS NULL)) THEN RAISE EXCEPTION 'group admission owned binding invalid';END IF;
 IF EXISTS(SELECT 1 FROM public.fleet_group_journal_reservations WHERE tenant_id=p_tenant AND workload_id=p_workload AND released_at IS NULL AND chain_id IS DISTINCT FROM p_owned_chain) THEN RETURN false;END IF;
 IF p_family IN('R1','GROUP') AND EXISTS(SELECT 1 FROM public.fleet_reservations WHERE tenant_id=p_tenant AND workload_id=p_workload AND released_at IS NULL) THEN RETURN false;END IF;
 IF p_family IN('V4','GROUP') AND EXISTS(SELECT 1 FROM public.provider_operations o LEFT JOIN public.signed_plans s ON s.tenant_id=o.tenant_id AND s.nonce=o.document->>'nonce' WHERE o.tenant_id=p_tenant AND (o.stop_intent OR o.stop_owned) AND NOT o.restored AND (s.plan_id IS NULL OR s.envelope->'plan'->>'workload_id'=p_workload)) THEN RETURN false;END IF;
 RETURN true;
END $$;
REVOKE ALL ON FUNCTION fleet_group_journal_lock(text,text),fleet_group_admission(text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION fleet_group_journal_lock(text,text) TO finops_group_ledger;
GRANT EXECUTE ON FUNCTION fleet_group_admission(text,text,text,text) TO finops_api,finops_signer,finops_worker,finops_executor,finops_group_ledger;

CREATE FUNCTION fleet_group_cursor_valid(d jsonb,p_chain text) RETURNS boolean LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,public,pg_temp AS $$ DECLARE k text;n numeric;BEGIN
 IF jsonb_typeof(d) IS DISTINCT FROM 'object' OR NOT d ?& ARRAY['chain_id','kind','segment','record_count','global_count','head_sha256','checkpoint_sha256','projection_sha256','identities'] OR d-ARRAY['chain_id','kind','segment','record_count','global_count','head_sha256','checkpoint_sha256','projection_sha256','identities']<>'{}'::jsonb OR d->>'chain_id' IS DISTINCT FROM p_chain OR coalesce(p_chain,'')='' THEN RETURN false;END IF;
 IF d->>'kind' IS NULL OR d->>'kind' NOT IN('ORIGINAL_JOURNAL','RECOVERY_SEGMENT') OR coalesce(d->>'head_sha256','')!~'^[a-f0-9]{64}$' OR coalesce(d->>'projection_sha256','')!~'^[a-f0-9]{64}$' THEN RETURN false;END IF;
 FOREACH k IN ARRAY ARRAY['segment','record_count','global_count'] LOOP
  IF jsonb_typeof(d->k) IS DISTINCT FROM 'number' OR coalesce(d->>k,'')!~'^(0|[1-9][0-9]*)$' THEN RETURN false;END IF;
  n:=(d->>k)::numeric;IF n<0 OR n>18446744073709551615 OR k='record_count' AND n>512 THEN RETURN false;END IF;
 END LOOP;
 IF (d->>'global_count')::numeric<(d->>'record_count')::numeric OR jsonb_typeof(d->'identities') IS DISTINCT FROM 'object' OR NOT(d->'identities') ?& ARRAY['chain_id','count','sha256'] OR (d->'identities')-ARRAY['chain_id','count','sha256']<>'{}'::jsonb OR d->'identities'->>'chain_id' IS DISTINCT FROM p_chain OR jsonb_typeof(d->'identities'->'count') IS DISTINCT FROM 'number' OR coalesce(d->'identities'->>'count','')!~'^(0|[1-9][0-9]*)$' OR (d->'identities'->>'count')::numeric>18446744073709551615 THEN RETURN false;END IF;
 IF d->>'kind'='ORIGINAL_JOURNAL' THEN RETURN (d->>'segment')::numeric=0 AND d->>'checkpoint_sha256'='' AND (d->'identities'->>'count')::numeric=0 AND d->'identities'->>'sha256'='';END IF;
 RETURN (d->>'segment')::numeric>0 AND coalesce(d->>'checkpoint_sha256','')~'^[a-f0-9]{64}$' AND coalesce(d->'identities'->>'sha256','')~'^[a-f0-9]{64}$';
END $$;
REVOKE ALL ON FUNCTION fleet_group_cursor_valid(jsonb,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION fleet_group_cursor_valid(jsonb,text) TO finops_group_ledger;

CREATE FUNCTION guard_fleet_group_journal() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$ DECLARE actor text:=current_user;root jsonb;headrow public.fleet_group_journal_heads;v jsonb;raw bytea;hash text;used bigint;old_cursor jsonb;prior_head public.fleet_group_journal_heads;seg public.fleet_group_journal_segments;expected_previous text;BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'group journal records are immutable';END IF;
 IF coalesce(NEW.tenant_id,'')='' OR NEW.tenant_id IS DISTINCT FROM current_setting('app.tenant_id',true) THEN RAISE EXCEPTION 'group journal tenant mismatch';END IF;
 IF TG_TABLE_NAME='fleet_group_pipeline_inbox' THEN
  IF actor<>'finops_group_pipeline' THEN RAISE EXCEPTION 'pipeline inbox writer required';END IF;
  IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'pipeline inbox immutable';END IF;
  IF jsonb_typeof(NEW.document) IS DISTINCT FROM 'object' OR convert_from(NEW.raw_body,'UTF8')::jsonb IS DISTINCT FROM NEW.document OR encode(sha256(NEW.raw_body),'hex') IS DISTINCT FROM NEW.body_hash THEN RAISE EXCEPTION 'pipeline raw body differs';END IF;
  IF NOT public.fleet_group_pipeline_binding(NEW.tenant_id,NEW.chain_id,NEW.source_id,NEW.issuer,NEW.subject,NEW.audience,NEW.command_id) THEN RAISE EXCEPTION 'pipeline identity differs from commissioned binding';END IF;
  IF NEW.document->'receipt'->>'id' IS DISTINCT FROM NEW.id OR NEW.document->'receipt'->>'idempotency_key' IS DISTINCT FROM NEW.receipt_key OR NEW.document->'receipt'->>'command_id' IS DISTINCT FROM NEW.command_id OR NOT EXISTS(SELECT 1 FROM public.fleet_group_journal_operations o WHERE o.tenant_id=NEW.tenant_id AND o.chain_id=NEW.chain_id AND o.command_id=NEW.command_id AND o.operation_id=NEW.document->'receipt'->>'operation_id' AND o.fence=(NEW.document->'receipt'->>'fence')::numeric) THEN RAISE EXCEPTION 'pipeline command or receipt binding differs';END IF;
  NEW.writer_role:=actor;NEW.received_at:=clock_timestamp();RETURN NEW;
 END IF;
 IF actor<>'finops_group_ledger' THEN RAISE EXCEPTION 'dedicated group ledger writer required';END IF;
 IF TG_OP='UPDATE' AND TG_TABLE_NAME NOT IN('fleet_group_journal_current','fleet_group_journal_reservations','fleet_group_journal_outbox') THEN RAISE EXCEPTION 'group journal record immutable';END IF;
 IF TG_OP='UPDATE' AND (NEW.tenant_id<>OLD.tenant_id OR NEW.chain_id<>OLD.chain_id OR NEW.writer_role<>OLD.writer_role) THEN RAISE EXCEPTION 'group journal identity immutable';END IF;
 IF TG_TABLE_NAME='fleet_group_journal_roots' THEN
  IF NEW.document->>'chain_id' IS DISTINCT FROM NEW.chain_id OR NEW.document->>'prepared_program_id' IS DISTINCT FROM NEW.prepared_program_id OR NEW.document->>'approval_id' IS DISTINCT FROM NEW.approval_id OR NEW.document->'parent'->'program'->'binding'->'old'->'target'->>'tenant_id' IS DISTINCT FROM NEW.tenant_id OR NEW.document->'parent'->'program'->'binding'->'candidate'->'target'->>'tenant_id' IS DISTINCT FROM NEW.tenant_id OR NEW.document->'parent'->'program'->'binding'->'old'->'target'->>'workload_id' IS DISTINCT FROM NEW.workload_id OR NEW.document->'parent'->'program'->'binding'->'candidate'->'target'->>'workload_id' IS DISTINCT FROM NEW.workload_id OR NEW.document->'parent'->'program'->'realm'->>'kind' IS DISTINCT FROM 'ISOLATED_FIXTURE' THEN RAISE EXCEPTION 'group bootstrap binding differs';END IF;
  IF NOT EXISTS(SELECT 1 FROM public.fleet_fixture_prepared_programs p JOIN public.fleet_fixture_approvals a ON a.tenant_id=p.tenant_id AND a.prepared_program_id=p.id WHERE p.tenant_id=NEW.tenant_id AND p.id=NEW.prepared_program_id AND a.id=NEW.approval_id AND p.program IS NOT DISTINCT FROM NEW.document->'parent'->'program' AND a.program_hash=p.program_hash AND a.manifest_hash=p.manifest_hash AND a.journal_review_hash=p.journal_review_hash) THEN RAISE EXCEPTION 'group prepared approval differs';END IF;
  IF jsonb_typeof(NEW.document->'parent'->'approvals') IS DISTINCT FROM 'array' OR jsonb_array_length(NEW.document->'parent'->'approvals')<>1 OR NOT EXISTS(SELECT 1 FROM public.fleet_fixture_approvals a WHERE a.tenant_id=NEW.tenant_id AND a.id=NEW.approval_id AND NEW.document->'parent'->'approvals'->0->>'id'=a.id AND NEW.document->'parent'->'approvals'->0->>'tenant_id'=a.tenant_id AND NEW.document->'parent'->'approvals'->0->>'actor_id'=a.actor_id AND NEW.document->'parent'->'approvals'->0->>'role'=a.document->>'role' AND NEW.document->'parent'->'approvals'->0->>'program_sha256'=a.program_hash AND (NEW.document->'parent'->'approvals'->0->>'approved_at')::timestamptz=a.created_at) THEN RAISE EXCEPTION 'group parent approval is not exact persisted approval';END IF;
  IF NOT public.fleet_group_authority_approved(NEW.tenant_id,NEW.chain_id,NEW.prepared_program_id,NEW.key_binding_id,NEW.parent_hash,'JOURNAL',NEW.document->'authorization'->'authorization',NEW.document->'authorization'->'approvals') THEN RAISE EXCEPTION 'group exact independent journal approval missing';END IF;
  IF NOT EXISTS(SELECT 1 FROM public.fleet_fixture_prepared_programs p WHERE p.tenant_id=NEW.tenant_id AND p.id=NEW.prepared_program_id AND NEW.document->'authorization'->'authorization'->'base' IS NOT DISTINCT FROM p.journal_review->'base' AND NEW.document->'authorization'->'authorization'->>'pipeline_id'=p.journal_review->>'pipeline_id' AND NEW.document->'authorization'->'authorization'->>'ref'=p.journal_review->>'ref' AND NEW.document->'authorization'->'authorization'->>'pipeline_key_sha256'=p.journal_review->>'pipeline_key_sha256' AND NEW.document->'authorization'->'authorization'->>'ledger_key_sha256'=p.journal_review->>'ledger_key_sha256' AND (NEW.document->'authorization'->'authorization'->>'maximum_effects')::numeric=(p.journal_review->>'max_effects')::numeric AND (NEW.document->'authorization'->'authorization'->>'maximum_records')::numeric=(p.journal_review->>'max_records')::numeric AND (NEW.document->'authorization'->'authorization'->>'expires_at')::timestamptz=(p.journal_review->>'expires_at')::timestamptz) THEN RAISE EXCEPTION 'group journal differs from independently approved review';END IF;
  IF NEW.document->>'key_binding_id' IS DISTINCT FROM NEW.key_binding_id OR NOT EXISTS(SELECT 1 FROM public.fleet_group_journal_key_bindings k JOIN public.fleet_fixture_proposals p ON p.tenant_id=k.tenant_id AND p.profile_id=k.profile_id AND p.profile_generation=k.profile_generation JOIN public.fleet_fixture_prepared_programs g ON g.tenant_id=p.tenant_id AND g.proposal_id=p.id WHERE k.tenant_id=NEW.tenant_id AND k.id=NEW.key_binding_id AND g.id=NEW.prepared_program_id AND k.realm IS NOT DISTINCT FROM NEW.document->'parent'->'program'->'realm' AND k.pipeline_id=NEW.document->'parent'->'program'->'artifact_context'->>'pipeline_id' AND decode(NEW.document->'keys'->>'signer','base64')=k.signer_key AND decode(NEW.document->'keys'->>'pipeline','base64')=k.pipeline_key AND decode(NEW.document->'keys'->>'ledger','base64')=k.ledger_key) THEN RAISE EXCEPTION 'group trust keys differ from commissioned binding';END IF;
  PERFORM public.fleet_group_journal_lock(NEW.tenant_id,NEW.workload_id);
  IF NOT public.fleet_group_prepared_current(NEW.tenant_id,NEW.prepared_program_id) THEN RAISE EXCEPTION 'group prepared selection no longer current';END IF;
 ELSE
  SELECT document INTO root FROM public.fleet_group_journal_roots WHERE tenant_id=NEW.tenant_id AND chain_id=NEW.chain_id;
  IF root IS NULL THEN RAISE EXCEPTION 'group journal root missing';END IF;
  PERFORM public.fleet_group_journal_lock(NEW.tenant_id,root->'parent'->'program'->'binding'->'old'->'target'->>'workload_id');
 END IF;
 IF TG_TABLE_NAME IN('fleet_group_journal_roots','fleet_group_journal_chain_authorizations','fleet_group_journal_segments','fleet_group_journal_records','fleet_group_journal_heads','fleet_group_journal_operations','fleet_group_journal_outbox') THEN
  v:=NEW.document;raw:=NEW.raw_document;
  IF jsonb_typeof(v) IS DISTINCT FROM 'object' OR convert_from(raw,'UTF8')::jsonb IS DISTINCT FROM v THEN RAISE EXCEPTION 'group canonical bytes differ';END IF;
  IF TG_TABLE_NAME IN('fleet_group_journal_roots','fleet_group_journal_chain_authorizations','fleet_group_journal_records','fleet_group_journal_heads') THEN
   IF encode(sha256(raw),'hex') IS DISTINCT FROM NEW.content_hash THEN RAISE EXCEPTION 'group content hash differs';END IF;
  END IF;
 END IF;
 IF TG_TABLE_NAME='fleet_group_journal_chain_authorizations' THEN
  SELECT document INTO old_cursor FROM public.fleet_group_journal_current WHERE tenant_id=NEW.tenant_id AND chain_id=NEW.chain_id FOR UPDATE;
  IF NOT coalesce(public.fleet_group_cursor_valid(old_cursor,NEW.chain_id),false) OR old_cursor->>'kind'<>'ORIGINAL_JOURNAL' OR (old_cursor->>'record_count')::integer<>0 OR NEW.document->'authorization'->>'chain_id' IS DISTINCT FROM NEW.chain_id OR NEW.document->'authorization'->'bootstrap_head'->'head'->'ref' IS DISTINCT FROM root->'bootstrap_head'->'head'->'ref' OR NEW.document->'authorization'->'bootstrap_head'->'head'->>'authorization_sha256' IS DISTINCT FROM root->'bootstrap_head'->'head'->>'authorization_sha256' OR NEW.document->'authorization'->'bootstrap_head'->'head'->>'journal_id' IS DISTINCT FROM root->'bootstrap_head'->'head'->>'journal_id' OR NEW.document->'authorization'->'bootstrap_head'->'head'->>'projection_sha256' IS DISTINCT FROM root->'bootstrap_head'->'head'->>'projection_sha256' OR NEW.document->'authorization'->>'parent_envelope_sha256' IS DISTINCT FROM (SELECT parent_hash FROM public.fleet_group_journal_roots WHERE tenant_id=NEW.tenant_id AND chain_id=NEW.chain_id) OR NEW.document->'authorization'->>'journal_authorization_sha256' IS DISTINCT FROM (SELECT authorization_hash FROM public.fleet_group_journal_roots WHERE tenant_id=NEW.tenant_id AND chain_id=NEW.chain_id) THEN RAISE EXCEPTION 'continuation authorization must bind actual zero-record bootstrap';END IF;
  IF NOT public.fleet_group_authority_approved(NEW.tenant_id,NEW.chain_id,root->>'prepared_program_id',root->>'key_binding_id',(SELECT parent_hash FROM public.fleet_group_journal_roots WHERE tenant_id=NEW.tenant_id AND chain_id=NEW.chain_id),'CONTINUATION',NEW.document->'authorization',NEW.document->'approvals') THEN RAISE EXCEPTION 'group exact independent continuation approval missing';END IF;
 ELSIF TG_TABLE_NAME='fleet_group_journal_segments' THEN
  SELECT document INTO old_cursor FROM public.fleet_group_journal_current WHERE tenant_id=NEW.tenant_id AND chain_id=NEW.chain_id FOR UPDATE;
  IF NEW.segment=0 THEN
   IF old_cursor IS NOT NULL THEN RAISE EXCEPTION 'original segment already initialized';END IF;
  ELSE
   IF old_cursor IS NULL OR NEW.segment<>(old_cursor->>'segment')::numeric+1 OR NEW.document->'checkpoint'->>'source_head_sha256' IS DISTINCT FROM old_cursor->>'head_sha256' OR (NEW.document->'checkpoint'->>'global_count')::numeric IS DISTINCT FROM (old_cursor->>'global_count')::numeric OR NEW.document->'checkpoint'->>'source_kind' IS DISTINCT FROM old_cursor->>'kind' OR encode(sha256(NEW.raw_document),'hex') IS DISTINCT FROM NEW.checkpoint_hash THEN RAISE EXCEPTION 'continuation checkpoint differs from actual current segment';END IF;
   SELECT * INTO prior_head FROM public.fleet_group_journal_heads WHERE tenant_id=NEW.tenant_id AND chain_id=NEW.chain_id AND content_hash=old_cursor->>'head_sha256';
   IF old_cursor->>'kind'='ORIGINAL_JOURNAL' THEN
    IF NEW.document->'checkpoint'->'original_head' IS DISTINCT FROM prior_head.document OR NEW.document->'checkpoint'->'original_projection' IS DISTINCT FROM prior_head.projection THEN RAISE EXCEPTION 'continuation original duties differ';END IF;
   ELSIF NEW.document->'checkpoint'->'prior_head' IS DISTINCT FROM prior_head.document OR NEW.document->'checkpoint'->'prior_projection' IS DISTINCT FROM prior_head.projection THEN RAISE EXCEPTION 'continuation prior duties differ';END IF;
  END IF;
 ELSIF TG_TABLE_NAME='fleet_group_journal_records' THEN
  SELECT document INTO old_cursor FROM public.fleet_group_journal_current WHERE tenant_id=NEW.tenant_id AND chain_id=NEW.chain_id FOR UPDATE;
  IF NOT coalesce(public.fleet_group_cursor_valid(old_cursor,NEW.chain_id),false) OR (old_cursor->>'segment')::numeric IS DISTINCT FROM NEW.segment OR (old_cursor->>'record_count')::integer+1 IS DISTINCT FROM NEW.sequence OR (NEW.document->>'sequence')::numeric IS DISTINCT FROM NEW.sequence OR NEW.document->>'kind' IS DISTINCT FROM NEW.kind THEN RAISE EXCEPTION 'group record order differs';END IF;
  SELECT * INTO prior_head FROM public.fleet_group_journal_heads WHERE tenant_id=NEW.tenant_id AND chain_id=NEW.chain_id AND content_hash=old_cursor->>'head_sha256';
  IF NEW.segment=0 THEN expected_previous:=prior_head.document->'head'->'ref'->>'last_record_sha256';
  ELSE expected_previous:=prior_head.document->'head'->>'last_record_sha256';END IF;
  IF NEW.document->>'previous_sha256' IS DISTINCT FROM expected_previous THEN RAISE EXCEPTION 'group record previous head differs';END IF;
  IF NEW.document ? 'receipt' AND NOT EXISTS(SELECT 1 FROM public.fleet_group_pipeline_inbox i WHERE i.tenant_id=NEW.tenant_id AND i.chain_id=NEW.chain_id AND i.id=NEW.document->'receipt'->'receipt'->>'id' AND i.document=NEW.document->'receipt' AND i.kind=CASE WHEN NEW.segment=0 THEN 'ORIGINAL_JOURNAL' ELSE 'RECOVERY_SEGMENT' END) THEN RAISE EXCEPTION 'group pipeline receipt not issued by inbox';END IF;
  IF NEW.document ? 'original_receipt' AND NOT EXISTS(SELECT 1 FROM public.fleet_group_pipeline_inbox i WHERE i.tenant_id=NEW.tenant_id AND i.chain_id=NEW.chain_id AND i.id=NEW.document->'original_receipt'->'receipt'->>'id' AND i.document=NEW.document->'original_receipt' AND i.kind='ORIGINAL_JOURNAL') THEN RAISE EXCEPTION 'group original receipt not issued by inbox';END IF;
  IF NEW.segment=0 AND NEW.kind IN('PREPARING','RESERVED') AND NEW.document->'command'->'preparation'->>'mode'='FORWARD' AND NOT public.fleet_group_prepared_current(NEW.tenant_id,root->>'prepared_program_id') THEN RAISE EXCEPTION 'group new forward source no longer current';END IF;
  SELECT coalesce(sum(octet_length(raw_document)+1),0) INTO used FROM public.fleet_group_journal_records WHERE tenant_id=NEW.tenant_id AND chain_id=NEW.chain_id AND segment=NEW.segment;
  IF used+octet_length(NEW.raw_document)+1>33554432 THEN RAISE EXCEPTION 'group segment byte limit';END IF;
  IF NEW.segment>0 AND NOT EXISTS(SELECT 1 FROM public.fleet_group_journal_chain_authorizations a WHERE a.tenant_id=NEW.tenant_id AND a.chain_id=NEW.chain_id AND NEW.sequence<=(a.document->'authorization'->>'record_limit')::integer AND used+octet_length(NEW.raw_document)+1<=(a.document->'authorization'->>'byte_limit')::integer) THEN RAISE EXCEPTION 'group approved segment limit reached';END IF;
  IF convert_from(NEW.raw_head,'UTF8')::jsonb IS DISTINCT FROM NEW.head OR encode(sha256(NEW.raw_head),'hex') IS DISTINCT FROM NEW.head_hash THEN RAISE EXCEPTION 'group issued head differs';END IF;
 ELSIF TG_TABLE_NAME='fleet_group_journal_heads' THEN
  IF NOT coalesce(public.fleet_group_cursor_valid(NEW.cursor_document,NEW.chain_id),false) OR convert_from(NEW.raw_projection,'UTF8')::jsonb IS DISTINCT FROM NEW.projection OR convert_from(NEW.raw_cursor,'UTF8')::jsonb IS DISTINCT FROM NEW.cursor_document OR NEW.cursor_document->>'head_sha256' IS DISTINCT FROM NEW.content_hash OR (NEW.cursor_document->>'segment')::numeric IS DISTINCT FROM NEW.segment OR (NEW.cursor_document->>'record_count')::integer IS DISTINCT FROM NEW.record_count OR NEW.cursor_document->>'projection_sha256' IS DISTINCT FROM encode(sha256(NEW.raw_projection),'hex') OR NEW.document->'head'->>'projection_sha256' IS DISTINCT FROM NEW.cursor_document->>'projection_sha256' THEN RAISE EXCEPTION 'group head projection closure differs';END IF;
  IF NEW.segment=0 THEN
   IF (NEW.document->'head'->'ref'->>'record_count')::integer IS DISTINCT FROM NEW.record_count OR (NEW.document->'head'->'ref'->>'version')::numeric IS DISTINCT FROM NEW.record_count+1 OR NEW.document->'head'->>'authorization_sha256' IS DISTINCT FROM (SELECT authorization_hash FROM public.fleet_group_journal_roots WHERE tenant_id=NEW.tenant_id AND chain_id=NEW.chain_id) THEN RAISE EXCEPTION 'original issued head binding differs';END IF;
  ELSE
   SELECT * INTO seg FROM public.fleet_group_journal_segments WHERE tenant_id=NEW.tenant_id AND chain_id=NEW.chain_id AND segment=NEW.segment;
   IF (NEW.document->'head'->>'segment')::numeric IS DISTINCT FROM NEW.segment OR (NEW.document->'head'->>'record_count')::integer IS DISTINCT FROM NEW.record_count OR (NEW.document->'head'->>'global_count')::numeric IS DISTINCT FROM (NEW.cursor_document->>'global_count')::numeric OR (NEW.document->'head'->>'global_count')::numeric IS DISTINCT FROM (seg.document->'checkpoint'->>'global_count')::numeric+NEW.record_count OR NEW.document->'head'->>'checkpoint_sha256' IS DISTINCT FROM seg.checkpoint_hash OR NEW.cursor_document->>'checkpoint_sha256' IS DISTINCT FROM seg.checkpoint_hash OR NEW.document->'head'->'identities' IS DISTINCT FROM NEW.cursor_document->'identities' OR NEW.projection->'identities' IS DISTINCT FROM NEW.cursor_document->'identities' THEN RAISE EXCEPTION 'continuation issued head binding differs';END IF;
   IF NOT EXISTS(SELECT 1 FROM public.fleet_group_journal_identities WHERE tenant_id=NEW.tenant_id AND chain_id=NEW.chain_id AND ordinal=(NEW.cursor_document->'identities'->>'count')::numeric AND root_hash=NEW.cursor_document->'identities'->>'sha256') THEN RAISE EXCEPTION 'continuation issued identity prefix missing';END IF;
  END IF;
  IF NEW.segment=0 THEN expected_previous:=NEW.document->'head'->'ref'->>'last_record_sha256';ELSE expected_previous:=NEW.document->'head'->>'last_record_sha256';END IF;
  IF NEW.record_count>0 AND NOT EXISTS(SELECT 1 FROM public.fleet_group_journal_records WHERE tenant_id=NEW.tenant_id AND chain_id=NEW.chain_id AND segment=NEW.segment AND sequence=NEW.record_count AND content_hash=expected_previous) THEN RAISE EXCEPTION 'issued head has no exact record';END IF;
 ELSIF TG_TABLE_NAME='fleet_group_journal_current' THEN
  SELECT * INTO headrow FROM public.fleet_group_journal_heads WHERE tenant_id=NEW.tenant_id AND chain_id=NEW.chain_id AND content_hash=NEW.head_hash;
  IF headrow.content_hash IS NULL OR NEW.document IS DISTINCT FROM headrow.cursor_document OR NEW.raw_document IS DISTINCT FROM headrow.raw_cursor THEN RAISE EXCEPTION 'group current head differs';END IF;
  IF TG_OP='INSERT' AND NEW.version<>1 OR TG_OP='UPDATE' AND NEW.version<>OLD.version+1 THEN RAISE EXCEPTION 'group current CAS version differs';END IF;
  IF TG_OP='INSERT' THEN
   IF NEW.document->>'kind' IS DISTINCT FROM 'ORIGINAL_JOURNAL' OR (NEW.document->>'segment')::numeric IS DISTINCT FROM 0 OR (NEW.document->>'record_count')::integer IS DISTINCT FROM 0 OR (NEW.document->>'global_count')::numeric IS DISTINCT FROM 0 THEN RAISE EXCEPTION 'group current must start at original bootstrap';END IF;
  ELSE
   IF (NEW.document->>'segment')::numeric=(OLD.document->>'segment')::numeric THEN
    IF (NEW.document->>'record_count')::integer=(OLD.document->>'record_count')::integer THEN
     IF NEW.document-'head_sha256' IS DISTINCT FROM OLD.document-'head_sha256' THEN RAISE EXCEPTION 'head renewal changed cursor authority';END IF;
    ELSIF (NEW.document->>'record_count')::integer<>(OLD.document->>'record_count')::integer+1 OR (NEW.document->>'global_count')::numeric<>(OLD.document->>'global_count')::numeric+1 OR NOT EXISTS(SELECT 1 FROM public.fleet_group_journal_records WHERE tenant_id=NEW.tenant_id AND chain_id=NEW.chain_id AND segment=(NEW.document->>'segment')::numeric AND sequence=(NEW.document->>'record_count')::integer AND head_hash=NEW.head_hash) THEN RAISE EXCEPTION 'group current record rewind or skip';END IF;
   ELSIF (NEW.document->>'segment')::numeric=(OLD.document->>'segment')::numeric+1 THEN
    SELECT * INTO seg FROM public.fleet_group_journal_segments WHERE tenant_id=NEW.tenant_id AND chain_id=NEW.chain_id AND segment=(NEW.document->>'segment')::numeric;
    IF NEW.document->>'kind' IS DISTINCT FROM 'RECOVERY_SEGMENT' OR (NEW.document->>'record_count')::integer IS DISTINCT FROM 0 OR (NEW.document->>'global_count')::numeric IS DISTINCT FROM (OLD.document->>'global_count')::numeric OR NEW.document->>'checkpoint_sha256' IS DISTINCT FROM seg.checkpoint_hash OR seg.document->'checkpoint'->>'source_head_sha256' IS DISTINCT FROM OLD.head_hash THEN RAISE EXCEPTION 'group current continuation checkpoint differs';END IF;
   ELSE RAISE EXCEPTION 'group current segment rewind or skip';END IF;
  END IF;
  NEW.updated_at:=clock_timestamp();
 ELSIF TG_TABLE_NAME='fleet_group_journal_reservations' THEN
  IF NEW.workload_id IS DISTINCT FROM root->'parent'->'program'->'binding'->'old'->'target'->>'workload_id' THEN RAISE EXCEPTION 'group reservation workload differs';END IF;
  IF TG_OP='INSERT' AND (NEW.released_at IS NOT NULL OR NEW.release_head_hash IS NOT NULL OR NOT public.fleet_group_admission(NEW.tenant_id,NEW.workload_id,'GROUP',NULL)) THEN RAISE EXCEPTION 'group workload already reserved';END IF;
  IF TG_OP='UPDATE' THEN
   IF OLD.released_at IS NOT NULL OR NEW.workload_id<>OLD.workload_id OR NEW.created_at<>OLD.created_at OR NEW.obligation_hash<>OLD.obligation_hash OR NEW.release_head_hash IS NULL THEN RAISE EXCEPTION 'group reservation cannot be rewritten';END IF;
   IF NEW.release_head_hash IS DISTINCT FROM (SELECT head_hash FROM public.fleet_group_journal_current WHERE tenant_id=NEW.tenant_id AND chain_id=NEW.chain_id) THEN RAISE EXCEPTION 'group release requires actual current head';END IF;
   SELECT * INTO headrow FROM public.fleet_group_journal_heads WHERE tenant_id=NEW.tenant_id AND chain_id=NEW.chain_id AND content_hash=NEW.release_head_hash;
   IF headrow.content_hash IS NULL OR NOT(coalesce((headrow.projection->>'forward_aborted')::boolean,false) OR coalesce((headrow.projection->>'recovery_only')::boolean,false)) THEN RAISE EXCEPTION 'group release cannot renew future forward authority';END IF;
   IF headrow.projection->'pending' IS NOT NULL AND headrow.projection->'pending'<>'null'::jsonb OR headrow.projection->'original_pending' IS NOT NULL AND headrow.projection->'original_pending'<>'null'::jsonb OR headrow.projection->'git_duty' IS NOT NULL AND headrow.projection->'git_duty'<>'null'::jsonb OR jsonb_array_length(coalesce(headrow.projection->'stack','[]'::jsonb))<>0 THEN RAISE EXCEPTION 'group duty remains unresolved';END IF;
   NEW.released_at:=clock_timestamp();
  END IF;
 ELSIF TG_TABLE_NAME='fleet_group_journal_identities' THEN
  IF NEW.ordinal=1 THEN SELECT encode(sha256(convert_to('{"Domain":"fleet-group-continuation-identities-v1","Chain":"'||content_hash||'"}','UTF8')),'hex') INTO expected_previous FROM public.fleet_group_journal_chain_authorizations WHERE tenant_id=NEW.tenant_id AND chain_id=NEW.chain_id;
  ELSE SELECT root_hash INTO expected_previous FROM public.fleet_group_journal_identities WHERE tenant_id=NEW.tenant_id AND chain_id=NEW.chain_id AND ordinal=NEW.ordinal-1;END IF;
  v:=convert_from(NEW.raw_step,'UTF8')::jsonb;
  IF expected_previous IS NULL OR v IS DISTINCT FROM jsonb_build_object('Previous',expected_previous,'Entry',jsonb_build_object('key',jsonb_build_object('namespace',NEW.namespace,'id',NEW.identity),'sha256',NEW.content_hash)) OR encode(sha256(NEW.raw_step),'hex') IS DISTINCT FROM NEW.root_hash THEN RAISE EXCEPTION 'group identity prefix chain differs';END IF;
 ELSIF TG_TABLE_NAME='fleet_group_journal_operations' THEN
  IF NEW.document->>'id' IS DISTINCT FROM NEW.command_id OR NEW.document->>'operation_id' IS DISTINCT FROM NEW.operation_id OR (NEW.document->>'fence')::numeric IS DISTINCT FROM NEW.fence OR encode(sha256(NEW.raw_document),'hex') IS DISTINCT FROM NEW.command_hash OR NOT EXISTS(SELECT 1 FROM public.fleet_group_journal_records r JOIN public.fleet_group_journal_current c ON c.tenant_id=r.tenant_id AND c.chain_id=r.chain_id WHERE r.tenant_id=NEW.tenant_id AND r.chain_id=NEW.chain_id AND r.segment=(c.document->>'segment')::numeric AND r.sequence=(c.document->>'record_count')::integer+1 AND r.kind='PREPARING' AND r.document->'command'=NEW.document) THEN RAISE EXCEPTION 'group operation lacks exact preparing record';END IF;
 ELSIF TG_TABLE_NAME='fleet_group_journal_outbox' AND TG_OP='INSERT' THEN
  SELECT * INTO headrow FROM public.fleet_group_journal_heads WHERE tenant_id=NEW.tenant_id AND chain_id=NEW.chain_id AND content_hash=NEW.head_hash;
  IF NEW.head_hash IS DISTINCT FROM (SELECT head_hash FROM public.fleet_group_journal_current WHERE tenant_id=NEW.tenant_id AND chain_id=NEW.chain_id) OR NEW.document->'cursor' IS DISTINCT FROM headrow.cursor_document OR NEW.document->>'id' IS DISTINCT FROM NEW.id OR NEW.document->>'chain_id' IS DISTINCT FROM NEW.chain_id OR NEW.document->>'command_id' IS DISTINCT FROM NEW.command_id OR NEW.document->>'action' IS DISTINCT FROM NEW.action OR NEW.document->>'command_hash' IS DISTINCT FROM NEW.command_hash OR NEW.document->'command' IS DISTINCT FROM headrow.projection->'pending'->'command' THEN RAISE EXCEPTION 'group outbox lacks exact current command';END IF;
  IF NEW.state<>'PENDING' OR NEW.attempt_id IS NOT NULL OR NEW.attempted_at IS NOT NULL OR NEW.lease_until IS NOT NULL THEN RAISE EXCEPTION 'group outbox starts pending only';END IF;
 ELSIF TG_TABLE_NAME='fleet_group_journal_outbox' AND TG_OP='UPDATE' THEN
  IF NEW.id<>OLD.id OR NEW.command_id<>OLD.command_id OR NEW.action<>OLD.action OR NEW.command_hash<>OLD.command_hash OR NEW.head_hash<>OLD.head_hash OR NEW.document<>OLD.document OR NEW.raw_document<>OLD.raw_document OR NEW.created_at<>OLD.created_at THEN RAISE EXCEPTION 'group delivery identity immutable';END IF;
  IF OLD.state='PENDING' AND NEW.state='ATTEMPTED' THEN
   SELECT * INTO headrow FROM public.fleet_group_journal_heads WHERE tenant_id=NEW.tenant_id AND chain_id=NEW.chain_id AND content_hash=(SELECT head_hash FROM public.fleet_group_journal_current WHERE tenant_id=NEW.tenant_id AND chain_id=NEW.chain_id);
   IF NEW.action='RECONCILE' OR NEW.document->'command' IS DISTINCT FROM headrow.projection->'pending'->'command' THEN RAISE EXCEPTION 'group stale outbox command cannot dispatch';END IF;
   IF NEW.document->'command'->'preparation'->>'mode'='FORWARD' AND NOT public.fleet_group_prepared_current(NEW.tenant_id,root->>'prepared_program_id') THEN RAISE EXCEPTION 'group actual forward source no longer current';END IF;
   NEW.attempted_at:=clock_timestamp();
   IF NEW.attempt_id IS NULL OR length(NEW.attempt_id)<8 OR NEW.lease_until IS NULL OR NEW.lease_until<=NEW.attempted_at OR NEW.lease_until>clock_timestamp()+interval '30 seconds' THEN RAISE EXCEPTION 'group delivery attempt invalid';END IF;
  ELSIF NOT(OLD.state IN('ATTEMPTED','RECONCILE') AND NEW.state IN('RECONCILE','COMPLETE') AND NEW.attempt_id IS NOT DISTINCT FROM OLD.attempt_id AND NEW.attempted_at IS NOT DISTINCT FROM OLD.attempted_at AND NEW.lease_until IS NOT DISTINCT FROM OLD.lease_until) THEN RAISE EXCEPTION 'group delivery cannot be retried';END IF;
 END IF;
 NEW.writer_role:=actor;
 IF TG_OP='INSERT' AND TG_TABLE_NAME<>'fleet_group_journal_current' THEN NEW.created_at:=clock_timestamp();END IF;
 RETURN NEW;
END $$;

DO $$ DECLARE tab text;BEGIN FOREACH tab IN ARRAY ARRAY['fleet_group_journal_roots','fleet_group_journal_chain_authorizations','fleet_group_journal_segments','fleet_group_journal_records','fleet_group_journal_heads','fleet_group_journal_current','fleet_group_journal_identities','fleet_group_journal_reservations','fleet_group_pipeline_inbox','fleet_group_journal_operations','fleet_group_journal_outbox'] LOOP
 EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',tab);EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',tab);
 EXECUTE format('CREATE POLICY tenant_isolation ON public.%I USING(tenant_id=current_setting(''app.tenant_id'',true)) WITH CHECK(tenant_id=current_setting(''app.tenant_id'',true))',tab);
 EXECUTE format('CREATE TRIGGER guard_%I BEFORE INSERT OR UPDATE OR DELETE ON public.%I FOR EACH ROW EXECUTE FUNCTION public.guard_fleet_group_journal()',tab,tab);
 EXECUTE format('GRANT SELECT ON public.%I TO finops_group_ledger',tab);
 IF tab<>'fleet_group_pipeline_inbox' THEN EXECUTE format('GRANT INSERT ON public.%I TO finops_group_ledger',tab);END IF;
END LOOP;END $$;
GRANT UPDATE ON fleet_group_journal_current,fleet_group_journal_reservations,fleet_group_journal_outbox TO finops_group_ledger;
GRANT INSERT,SELECT ON fleet_group_pipeline_inbox TO finops_group_pipeline;
GRANT SELECT ON fleet_group_journal_operations,fleet_group_journal_outbox TO finops_group_pipeline;
GRANT SELECT ON fleet_fixture_prepared_programs,fleet_fixture_approvals,fleet_fixture_proposals TO finops_group_ledger;
REVOKE ALL ON FUNCTION guard_fleet_group_journal() FROM PUBLIC;

-- Safe inspection does not expose the private signed commands, state, public
-- key bindings or artifact locations, and confers no mutation capability.
CREATE FUNCTION fleet_group_fixture_runs(p_tenant text,p_proposal text,p_after text,p_limit integer) RETURNS SETOF jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$ BEGIN
 IF p_limit IS NULL OR p_limit<1 OR p_limit>101 THEN RAISE EXCEPTION 'group run page limit invalid';END IF;
 IF coalesce(p_tenant,'')='' OR p_tenant IS DISTINCT FROM current_setting('app.tenant_id',true) OR coalesce(p_proposal,'')='' THEN RETURN;END IF;
 RETURN QUERY SELECT jsonb_build_object('id',r.chain_id,'proposal_id',p.id,'workload_id',r.workload_id,'created_at',r.created_at,'realm',r.document->'parent'->'program'->'realm','segment',c.document->>'segment','record_count',c.document->'record_count','global_count',c.document->>'global_count','head_sha256',c.head_hash,'owned_effect_count',jsonb_array_length(h.projection->'stack'),'pending_phase',coalesce(h.projection->'pending'->>'phase',h.projection->'original_pending'->>'phase'),'forward_aborted',coalesce((h.projection->>'forward_aborted')::boolean,false),'recovery_only',coalesce((h.projection->>'recovery_only')::boolean,false),'obligation_released',coalesce(o.released_at IS NOT NULL,false),'customer_execution_authorized',false,'financial_disposition',CASE WHEN coalesce((h.projection->>'forward_aborted')::boolean,false) OR coalesce((h.projection->>'recovery_only')::boolean,false) THEN 'DISQUALIFIED' ELSE 'UNAVAILABLE' END)
 FROM public.fleet_group_journal_roots r JOIN public.fleet_fixture_prepared_programs g ON g.tenant_id=r.tenant_id AND g.id=r.prepared_program_id JOIN public.fleet_fixture_proposals p ON p.tenant_id=g.tenant_id AND p.id=g.proposal_id JOIN public.fleet_group_journal_current c ON c.tenant_id=r.tenant_id AND c.chain_id=r.chain_id JOIN public.fleet_group_journal_heads h ON h.tenant_id=c.tenant_id AND h.chain_id=c.chain_id AND h.content_hash=c.head_hash LEFT JOIN public.fleet_group_journal_reservations o ON o.tenant_id=r.tenant_id AND o.chain_id=r.chain_id
 WHERE r.tenant_id=p_tenant AND p.id=p_proposal AND (coalesce(p_after,'')='' OR (r.created_at,r.chain_id)<(SELECT x.created_at,x.chain_id FROM public.fleet_group_journal_roots x JOIN public.fleet_fixture_prepared_programs z ON z.tenant_id=x.tenant_id AND z.id=x.prepared_program_id WHERE x.tenant_id=p_tenant AND z.proposal_id=p_proposal AND x.chain_id=p_after)) ORDER BY r.created_at DESC,r.chain_id DESC LIMIT p_limit;
END $$;
REVOKE ALL ON FUNCTION fleet_group_fixture_runs(text,text,text,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION fleet_group_fixture_runs(text,text,text,integer) TO finops_api;
