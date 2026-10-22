-- R2 is an independent customer-pipeline protocol. These records confer no
-- cloud credential, and no callback/health assertion is accepted from a console
-- identity. Uncertain changes retain their per-workload disruption reservation.
DO $$ BEGIN IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='finops_deployment_observer') THEN CREATE ROLE finops_deployment_observer NOLOGIN;END IF;END $$;
GRANT USAGE ON SCHEMA public TO finops_deployment_observer;
CREATE TABLE fleet_proof_sets(tenant_id text NOT NULL,id text NOT NULL,kind text NOT NULL,version text NOT NULL,content_hash text NOT NULL CHECK(content_hash~'^[a-f0-9]{64}$'),document jsonb NOT NULL,writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(tenant_id,id),CHECK(pg_column_size(document)<=131072));
CREATE TABLE fleet_plans(tenant_id text NOT NULL,id text NOT NULL,workload_id text NOT NULL,content_hash text NOT NULL CHECK(content_hash~'^[a-f0-9]{64}$'),document jsonb NOT NULL,writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(tenant_id,id),CHECK(pg_column_size(document)<=131072));
CREATE TABLE fleet_approvals(tenant_id text NOT NULL,id text NOT NULL,parent_id text NOT NULL,actor_id text NOT NULL,document jsonb NOT NULL,writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(tenant_id,id),UNIQUE(tenant_id,parent_id,actor_id),FOREIGN KEY(tenant_id,parent_id) REFERENCES fleet_plans(tenant_id,id));
CREATE TABLE fleet_controls(tenant_id text NOT NULL,id text NOT NULL,parent_id text NOT NULL,version bigint NOT NULL,status text NOT NULL CHECK(status IN('ACTIVE','PAUSED','REVOKED')),document jsonb NOT NULL,writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(tenant_id,id),UNIQUE(tenant_id,parent_id,version),FOREIGN KEY(tenant_id,parent_id) REFERENCES fleet_plans(tenant_id,id));
CREATE TABLE fleet_envelopes(tenant_id text NOT NULL,id text NOT NULL,content_hash text NOT NULL CHECK(content_hash~'^[a-f0-9]{64}$'),document jsonb NOT NULL,writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(tenant_id,id),FOREIGN KEY(tenant_id,id) REFERENCES fleet_plans(tenant_id,id));
CREATE TABLE fleet_children(tenant_id text NOT NULL,id text NOT NULL,parent_id text NOT NULL,stage_id text NOT NULL,content_hash text NOT NULL CHECK(content_hash~'^[a-f0-9]{64}$'),compensation_for text,ownership_receipt_id text,document jsonb NOT NULL,writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(tenant_id,id),FOREIGN KEY(tenant_id,parent_id) REFERENCES fleet_envelopes(tenant_id,id),FOREIGN KEY(tenant_id,compensation_for) REFERENCES fleet_children(tenant_id,id),CHECK(pg_column_size(document)<=131072));
CREATE TABLE fleet_observer_sources(tenant_id text NOT NULL,id text NOT NULL,document jsonb NOT NULL,writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(tenant_id,id),CHECK(pg_column_size(document)<=16384));
CREATE TABLE fleet_observer_revocations(tenant_id text NOT NULL,id text NOT NULL,source_id text NOT NULL,document jsonb NOT NULL,writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(tenant_id,id),UNIQUE(tenant_id,source_id),FOREIGN KEY(tenant_id,source_id) REFERENCES fleet_observer_sources(tenant_id,id));
CREATE TABLE fleet_executions(tenant_id text NOT NULL,id text NOT NULL,parent_id text NOT NULL,workload_id text NOT NULL,idempotency_key text NOT NULL,document jsonb NOT NULL,status text NOT NULL DEFAULT 'PENDING' CHECK(status IN('PENDING','RUNNING','FAILED','COMPLETED','ROLLED_BACK','RECOVERY_REQUIRED')),recovery_only boolean NOT NULL DEFAULT false,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(tenant_id,id),UNIQUE(tenant_id,parent_id,idempotency_key),FOREIGN KEY(tenant_id,parent_id) REFERENCES fleet_envelopes(tenant_id,id));
CREATE TABLE fleet_commands(tenant_id text NOT NULL,id text NOT NULL,execution_id text NOT NULL,child_id text NOT NULL,parent_id text NOT NULL,workload_id text NOT NULL,idempotency_key text NOT NULL,operation text NOT NULL CHECK(operation IN('APPLY','ROLLBACK')),document jsonb NOT NULL,writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(tenant_id,id),UNIQUE(tenant_id,child_id),UNIQUE(tenant_id,execution_id,idempotency_key),FOREIGN KEY(tenant_id,execution_id) REFERENCES fleet_executions(tenant_id,id),FOREIGN KEY(tenant_id,child_id) REFERENCES fleet_children(tenant_id,id));
CREATE TABLE fleet_command_states(tenant_id text NOT NULL,command_id text NOT NULL,dispatch_intent boolean NOT NULL DEFAULT false,dispatched_at timestamptz,outcome text NOT NULL DEFAULT 'PREPARED',owned_receipt_id text,health_evidence_id text,restored boolean NOT NULL DEFAULT false,updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(tenant_id,command_id),FOREIGN KEY(tenant_id,command_id) REFERENCES fleet_commands(tenant_id,id));
CREATE TABLE fleet_reservations(tenant_id text NOT NULL,command_id text NOT NULL,workload_id text NOT NULL,in_flight integer NOT NULL CHECK(in_flight BETWEEN 0 AND 2),unavailable integer NOT NULL CHECK(unavailable BETWEEN 0 AND 2),max_in_flight integer NOT NULL CHECK(max_in_flight BETWEEN 1 AND 2),max_unavailable integer NOT NULL CHECK(max_unavailable BETWEEN 1 AND 2),shared_with text,released_at timestamptz,release_reason text,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(tenant_id,command_id),FOREIGN KEY(tenant_id,command_id) REFERENCES fleet_commands(tenant_id,id),FOREIGN KEY(tenant_id,shared_with) REFERENCES fleet_reservations(tenant_id,command_id));
CREATE INDEX fleet_budget_active ON fleet_reservations(tenant_id,workload_id) WHERE released_at IS NULL;
CREATE UNIQUE INDEX fleet_parent_execution_once ON fleet_executions(tenant_id,parent_id);
CREATE UNIQUE INDEX fleet_child_sequence_once ON fleet_children(tenant_id,parent_id,((document->'plan'->>'sequence')::numeric));
CREATE TABLE fleet_callbacks(tenant_id text NOT NULL,id text NOT NULL,command_id text NOT NULL,source_id text NOT NULL,idempotency_key text NOT NULL,issuer text NOT NULL,subject text NOT NULL,audience text NOT NULL,body_sha256 text NOT NULL CHECK(body_sha256~'^[a-f0-9]{64}$'),owned_hash text,raw_body bytea NOT NULL,payload jsonb NOT NULL,document jsonb NOT NULL DEFAULT '{}',writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(tenant_id,id),UNIQUE(tenant_id,command_id,idempotency_key),FOREIGN KEY(tenant_id,command_id) REFERENCES fleet_commands(tenant_id,id),FOREIGN KEY(tenant_id,source_id) REFERENCES fleet_observer_sources(tenant_id,id),CHECK(octet_length(raw_body)<=1048576));
ALTER TABLE fleet_children ADD FOREIGN KEY(tenant_id,ownership_receipt_id) REFERENCES fleet_callbacks(tenant_id,id);
CREATE TABLE fleet_health_evidence(tenant_id text NOT NULL,id text NOT NULL,command_id text NOT NULL,content_hash text NOT NULL CHECK(content_hash~'^[a-f0-9]{64}$'),document jsonb NOT NULL,writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(tenant_id,id),FOREIGN KEY(tenant_id,command_id) REFERENCES fleet_commands(tenant_id,id),CHECK(pg_column_size(document)<=131072));
CREATE TABLE fleet_release_events(tenant_id text NOT NULL,id text NOT NULL,command_id text NOT NULL,evidence_id text NOT NULL,document jsonb NOT NULL DEFAULT '{}',writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(tenant_id,id),UNIQUE(tenant_id,command_id,evidence_id),FOREIGN KEY(tenant_id,command_id) REFERENCES fleet_commands(tenant_id,id),FOREIGN KEY(tenant_id,evidence_id) REFERENCES fleet_health_evidence(tenant_id,id));
CREATE TABLE fleet_execution_events(tenant_id text NOT NULL,id text NOT NULL,execution_id text NOT NULL,document jsonb NOT NULL,writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(tenant_id,id),FOREIGN KEY(tenant_id,execution_id) REFERENCES fleet_executions(tenant_id,id));
DO $$ DECLARE tab text;BEGIN FOREACH tab IN ARRAY ARRAY['fleet_proof_sets','fleet_plans','fleet_approvals','fleet_controls','fleet_envelopes','fleet_children','fleet_observer_sources','fleet_observer_revocations','fleet_executions','fleet_commands','fleet_command_states','fleet_reservations','fleet_callbacks','fleet_health_evidence','fleet_release_events','fleet_execution_events'] LOOP
 EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',tab);EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',tab);
 EXECUTE format('CREATE POLICY tenant_isolation ON %I USING(tenant_id=current_setting(''app.tenant_id'',true)) WITH CHECK(tenant_id=current_setting(''app.tenant_id'',true))',tab);
 EXECUTE format('GRANT SELECT ON %I TO finops_api,finops_worker,finops_signer',tab);
 IF tab NOT IN('fleet_executions','fleet_command_states','fleet_reservations') THEN EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION deny_evidence_mutation()',tab||'_immutable',tab);END IF;
END LOOP;END $$;
GRANT SELECT ON fleet_observer_sources,fleet_observer_revocations,fleet_commands,fleet_command_states,fleet_reservations,fleet_children,fleet_envelopes,fleet_callbacks TO finops_deployment_observer;
GRANT SELECT ON fleet_plans,fleet_children TO finops_ingester;
GRANT INSERT ON fleet_proof_sets,fleet_plans,fleet_approvals,fleet_controls,fleet_observer_sources,fleet_observer_revocations,fleet_executions,fleet_health_evidence TO finops_api;
GRANT INSERT ON fleet_envelopes,fleet_children TO finops_signer;
GRANT INSERT ON fleet_commands,fleet_release_events,fleet_execution_events TO finops_worker;
GRANT UPDATE(status,recovery_only,updated_at) ON fleet_executions TO finops_worker;
GRANT UPDATE(dispatch_intent,dispatched_at,updated_at) ON fleet_command_states TO finops_worker;
GRANT INSERT ON fleet_callbacks TO finops_deployment_observer;

CREATE FUNCTION fleet_lock(p_tenant text,p_workload text) RETURNS void LANGUAGE plpgsql AS $$ BEGIN
 IF p_tenant IS DISTINCT FROM current_setting('app.tenant_id',true) THEN RAISE EXCEPTION 'fleet tenant mismatch';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(p_tenant||':dependency-graph',0));PERFORM pg_advisory_xact_lock(hashtextextended(p_tenant||':fleet-workload:'||p_workload,0));
END $$;
CREATE FUNCTION fleet_source_current_lock(p_tenant text,p_source text) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=public,pg_temp AS $$ BEGIN
 IF p_tenant IS DISTINCT FROM current_setting('app.tenant_id',true) THEN RAISE EXCEPTION 'fleet source tenant mismatch';END IF;
 PERFORM 1 FROM source_registrations WHERE tenant_id=p_tenant AND id=p_source FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'fleet source not found';END IF;
END $$;
REVOKE ALL ON FUNCTION fleet_source_current_lock(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION fleet_source_current_lock(text,text) TO finops_ingester;
CREATE FUNCTION fleet_forward_deadline(p jsonb) RETURNS timestamptz LANGUAGE sql IMMUTABLE STRICT AS $$ SELECT least((p->>'expires_at')::timestamptz,(p->>'created_at')::timestamptz+((p->'budget'->>'maximum_duration_seconds')::integer*interval '1 second')) $$;
CREATE FUNCTION fleet_forward_authority(p_tenant text,p_parent text) RETURNS jsonb LANGUAGE plpgsql AS $$ DECLARE p jsonb;control text;BEGIN
 SELECT document INTO p FROM fleet_plans WHERE tenant_id=p_tenant AND id=p_parent;PERFORM fleet_lock(p_tenant,p->'binding'->>'workload_id');
 SELECT status INTO control FROM fleet_controls WHERE tenant_id=p_tenant AND parent_id=p_parent ORDER BY version DESC LIMIT 1;
 IF p IS NULL OR (p->>'expires_at')::timestamptz<=clock_timestamp() OR coalesce(control,'ACTIVE')<>'ACTIVE' OR p->'governance'->>'risk_class'<>'R2' OR p->'governance'->>'enabled'<>'true' THEN RAISE EXCEPTION 'fleet forward authority expired paused or revoked';END IF;
 IF coalesce((p->'budget'->>'maximum_duration_seconds')::integer,0)<1 OR fleet_forward_deadline(p) IS NULL OR fleet_forward_deadline(p)<=clock_timestamp() OR (SELECT coalesce(sum((s->>'minimum_observation_seconds')::integer),0) FROM jsonb_array_elements(p->'stages') s)>(p->'budget'->>'maximum_duration_seconds')::integer THEN RAISE EXCEPTION 'fleet forward modeled duration exhausted or observations cannot fit';END IF;
 RETURN p;
END $$;
CREATE FUNCTION guard_fleet_metadata() RETURNS trigger LANGUAGE plpgsql AS $$ DECLARE p jsonb;existing jsonb;v bigint;binding jsonb;BEGIN
 NEW.created_at:=clock_timestamp();NEW.writer_role:='finops_api';
 IF TG_TABLE_NAME='fleet_proof_sets' THEN
  IF NEW.document->'binding'->>'tenant_id' IS DISTINCT FROM NEW.tenant_id OR NEW.document->>'kind' IS DISTINCT FROM NEW.kind OR NEW.document->>'version' IS DISTINCT FROM NEW.version OR jsonb_typeof(NEW.document->'source_refs') IS DISTINCT FROM 'array' OR jsonb_array_length(NEW.document->'source_refs')<1 THEN RAISE EXCEPTION 'fleet proof factory source references required';END IF;
 ELSIF TG_TABLE_NAME='fleet_plans' THEN
  p:=NEW.document;PERFORM fleet_lock(NEW.tenant_id,NEW.workload_id);
  IF p->>'schema_version'<>'4' OR p->>'kind'<>'STATELESS_FLEET_RIGHTSIZING' OR p->>'id' IS DISTINCT FROM NEW.id OR p->'binding'->>'tenant_id' IS DISTINCT FROM NEW.tenant_id OR p->'binding'->>'workload_id' IS DISTINCT FROM NEW.workload_id OR p->'binding'->>'provider'<>'AWS' OR p->'binding'->>'region'<>'eu-west-1' OR p->'binding'->>'account_id'!~'^[0-9]{12}$' OR p->'old'->>'id' IS DISTINCT FROM p->'binding'->>'provider_resource_id' OR p->'governance'->>'risk_class'<>'R2' OR p->'governance'->>'approver_role'<>'fleet_approver' THEN RAISE EXCEPTION 'fleet plan binding invalid';END IF;
 ELSIF TG_TABLE_NAME='fleet_approvals' THEN
  p:=fleet_forward_authority(NEW.tenant_id,NEW.parent_id);
  IF NEW.document->>'tenant_id' IS DISTINCT FROM NEW.tenant_id OR NEW.document->>'actor_id' IS DISTINCT FROM NEW.actor_id OR NEW.actor_id=p->>'creator_id' OR NEW.document->>'role'<>'fleet_approver' OR NEW.document->>'plan_sha256' IS DISTINCT FROM (SELECT content_hash FROM fleet_plans WHERE tenant_id=NEW.tenant_id AND id=NEW.parent_id) THEN RAISE EXCEPTION 'fleet independent R2 approval invalid';END IF;
 ELSIF TG_TABLE_NAME='fleet_controls' THEN
  SELECT document INTO p FROM fleet_plans WHERE tenant_id=NEW.tenant_id AND id=NEW.parent_id;PERFORM fleet_lock(NEW.tenant_id,p->'binding'->>'workload_id');
  SELECT coalesce(max(version),0)+1 INTO v FROM fleet_controls WHERE tenant_id=NEW.tenant_id AND parent_id=NEW.parent_id;
  IF NEW.version<>v OR EXISTS(SELECT 1 FROM fleet_controls WHERE tenant_id=NEW.tenant_id AND parent_id=NEW.parent_id AND status='REVOKED') THEN RAISE EXCEPTION 'fleet control stale or terminal revoked';END IF;
  NEW.document:=NEW.document||jsonb_build_object('parent_id',NEW.parent_id,'version',NEW.version,'status',NEW.status);
 ELSIF TG_TABLE_NAME='fleet_envelopes' THEN
  NEW.writer_role:='finops_signer';p:=fleet_forward_authority(NEW.tenant_id,NEW.id);
  IF NEW.document->'plan' IS DISTINCT FROM p OR NEW.document->>'algorithm'<>'Ed25519-Fleet-v4' OR coalesce(NEW.document->>'signature','')='' OR jsonb_array_length(NEW.document->'approvals')<1 THEN RAISE EXCEPTION 'fleet envelope differs from registered plan';END IF;
  FOR existing IN SELECT value FROM jsonb_array_elements(NEW.document->'approvals') LOOP
   IF NOT EXISTS(SELECT 1 FROM fleet_approvals WHERE tenant_id=NEW.tenant_id AND parent_id=NEW.id AND id=existing->>'id' AND document=existing) THEN RAISE EXCEPTION 'fleet envelope approval not persisted';END IF;
  END LOOP;
  FOR existing IN SELECT value FROM jsonb_array_elements(p->'proofs') LOOP
   IF NOT EXISTS(SELECT 1 FROM fleet_proof_sets s WHERE s.tenant_id=NEW.tenant_id AND s.id=existing->>'id' AND s.kind=existing->>'kind' AND s.version=existing->>'version' AND s.content_hash=existing->>'sha256' AND s.document->'binding'=p->'binding' AND (s.document->>'expires_at')::timestamptz>clock_timestamp()) THEN RAISE EXCEPTION 'fleet parent proof not sealed by private scoped factory';END IF;
  END LOOP;
 ELSIF TG_TABLE_NAME='fleet_observer_sources' THEN
  binding:=NEW.document->'binding';
  IF binding->>'tenant_id' IS DISTINCT FROM NEW.tenant_id OR binding->>'provider'<>'AWS' OR binding->>'region'<>'eu-west-1' OR binding->>'account_id'!~'^[0-9]{12}$' OR coalesce(NEW.document->>'pipeline_id','')='' OR coalesce(NEW.document->>'issuer','')='' OR coalesce(NEW.document->>'subject','')='' OR coalesce(NEW.document->>'audience','')='' OR NEW.document->>'audience'='finops' THEN RAISE EXCEPTION 'fleet observer dedicated machine binding invalid';END IF;
 ELSIF TG_TABLE_NAME='fleet_observer_revocations' THEN
  IF coalesce(NEW.document->>'reason','')='' THEN RAISE EXCEPTION 'fleet source revocation reason required';END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER fleet_plan_writer BEFORE INSERT ON fleet_plans FOR EACH ROW EXECUTE FUNCTION guard_fleet_metadata();
CREATE TRIGGER fleet_proof_writer BEFORE INSERT ON fleet_proof_sets FOR EACH ROW EXECUTE FUNCTION guard_fleet_metadata();
CREATE TRIGGER fleet_approval_writer BEFORE INSERT ON fleet_approvals FOR EACH ROW EXECUTE FUNCTION guard_fleet_metadata();
CREATE TRIGGER fleet_control_writer BEFORE INSERT ON fleet_controls FOR EACH ROW EXECUTE FUNCTION guard_fleet_metadata();
CREATE TRIGGER fleet_envelope_writer BEFORE INSERT ON fleet_envelopes FOR EACH ROW EXECUTE FUNCTION guard_fleet_metadata();
CREATE TRIGGER fleet_observer_writer BEFORE INSERT ON fleet_observer_sources FOR EACH ROW EXECUTE FUNCTION guard_fleet_metadata();
CREATE TRIGGER fleet_observer_revocation_writer BEFORE INSERT ON fleet_observer_revocations FOR EACH ROW EXECUTE FUNCTION guard_fleet_metadata();

CREATE FUNCTION guard_fleet_child() RETURNS trigger LANGUAGE plpgsql AS $$ DECLARE p jsonb;c jsonb;original jsonb;receipt jsonb;proof jsonb;BEGIN
 SELECT document->'plan' INTO p FROM fleet_envelopes WHERE tenant_id=NEW.tenant_id AND id=NEW.parent_id;PERFORM fleet_lock(NEW.tenant_id,p->'binding'->>'workload_id');c:=NEW.document->'plan';
 IF c->>'id' IS DISTINCT FROM NEW.id OR c->>'parent_id' IS DISTINCT FROM NEW.parent_id OR c->>'stage_id' IS DISTINCT FROM NEW.stage_id OR c->'binding' IS DISTINCT FROM p->'binding' OR c->>'parent_sha256' IS DISTINCT FROM (SELECT content_hash FROM fleet_plans WHERE tenant_id=NEW.tenant_id AND id=NEW.parent_id) OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(p->'stages') s WHERE s->>'id'=NEW.stage_id) THEN RAISE EXCEPTION 'fleet child signed binding invalid';END IF;
 IF NEW.compensation_for IS NULL THEN
  PERFORM fleet_forward_authority(NEW.tenant_id,NEW.parent_id);
  IF NEW.document->>'algorithm'<>'Ed25519-Fleet-v4-child' OR coalesce(c->>'compensation_for','')<>'' OR NEW.ownership_receipt_id IS NOT NULL THEN RAISE EXCEPTION 'fleet forward child invalid';END IF;
  FOR proof IN SELECT value FROM jsonb_array_elements(c->'proofs') LOOP
   IF NOT EXISTS(SELECT 1 FROM fleet_proof_sets s WHERE s.tenant_id=NEW.tenant_id AND s.id=proof->>'id' AND s.kind=proof->>'kind' AND s.version=proof->>'version' AND s.content_hash=proof->>'sha256' AND s.document->'binding'=p->'binding' AND (s.document->>'expires_at')::timestamptz>clock_timestamp()) THEN RAISE EXCEPTION 'fleet child proof not sealed by private scoped factory';END IF;
  END LOOP;
 ELSE
  SELECT document->'plan' INTO original FROM fleet_children WHERE tenant_id=NEW.tenant_id AND id=NEW.compensation_for AND parent_id=NEW.parent_id AND compensation_for IS NULL;
  SELECT document INTO receipt FROM fleet_callbacks WHERE tenant_id=NEW.tenant_id AND id=NEW.ownership_receipt_id;
  IF original IS NULL OR receipt IS NULL OR receipt->>'outcome'<>'APPLIED' OR receipt->>'child_id' IS DISTINCT FROM NEW.compensation_for OR c->>'compensation_for' IS DISTINCT FROM NEW.compensation_for OR c->>'compensation_receipt_sha256' IS DISTINCT FROM receipt->'owned_receipt'->>'hash' OR NEW.document->>'algorithm'<>'Ed25519-Fleet-v4-owned-recovery' THEN RAISE EXCEPTION 'fleet compensation ownership invalid';END IF;
 END IF;
 IF coalesce(NEW.document->>'signature','')='' OR (c->>'expires_at')::timestamptz<=clock_timestamp() OR (c->>'created_at')::timestamptz<clock_timestamp()-interval '5 minutes' THEN RAISE EXCEPTION 'fleet child freshness invalid';END IF;
 NEW.writer_role:='finops_signer';NEW.created_at:=clock_timestamp();RETURN NEW;
END $$;
CREATE TRIGGER fleet_child_writer BEFORE INSERT ON fleet_children FOR EACH ROW EXECUTE FUNCTION guard_fleet_child();

CREATE FUNCTION fleet_observation_elapsed(dispatched timestamptz,observed timestamptz,minimum_seconds integer) RETURNS boolean LANGUAGE sql IMMUTABLE STRICT AS $$ SELECT minimum_seconds>=0 AND observed>=dispatched+(minimum_seconds*interval '1 second') $$;
CREATE FUNCTION guard_fleet_execution() RETURNS trigger LANGUAGE plpgsql AS $$ DECLARE p jsonb;last_child jsonb;last_health jsonb;terminal jsonb;last_dispatched timestamptz;BEGIN
 IF TG_OP='INSERT' THEN
  p:=fleet_forward_authority(NEW.tenant_id,NEW.parent_id);NEW.workload_id:=p->'binding'->>'workload_id';NEW.status:='PENDING';NEW.recovery_only:=false;NEW.created_at:=clock_timestamp();NEW.document:=jsonb_build_object('id',NEW.id,'tenant_id',NEW.tenant_id,'parent_id',NEW.parent_id,'workload_id',NEW.workload_id,'workflow_id','fleet-v4-'||NEW.id,'idempotency_key',NEW.idempotency_key,'created_at',NEW.created_at);
 ELSE
  IF (NEW.tenant_id,NEW.id,NEW.parent_id,NEW.workload_id,NEW.idempotency_key,NEW.document,NEW.created_at) IS DISTINCT FROM (OLD.tenant_id,OLD.id,OLD.parent_id,OLD.workload_id,OLD.idempotency_key,OLD.document,OLD.created_at) OR OLD.recovery_only AND NOT NEW.recovery_only THEN RAISE EXCEPTION 'fleet execution immutable binding or recovery latch';END IF;
  IF OLD.status IN('COMPLETED','ROLLED_BACK') AND NEW.status<>OLD.status THEN RAISE EXCEPTION 'fleet terminal execution cannot restart';END IF;
  PERFORM fleet_lock(NEW.tenant_id,NEW.workload_id);
  IF NEW.status IN('FAILED','RECOVERY_REQUIRED','ROLLED_BACK') THEN NEW.recovery_only:=true;END IF;
  IF NEW.status='COMPLETED' AND NEW.recovery_only THEN RAISE EXCEPTION 'failed fleet execution cannot revive as completed';END IF;
  IF NEW.status IN('COMPLETED','ROLLED_BACK') AND EXISTS(SELECT 1 FROM fleet_reservations r JOIN fleet_commands c ON c.tenant_id=r.tenant_id AND c.id=r.command_id WHERE c.tenant_id=NEW.tenant_id AND c.execution_id=NEW.id AND r.released_at IS NULL) THEN RAISE EXCEPTION 'fleet execution has unresolved reservations';END IF;
  IF NEW.status='ROLLED_BACK' AND EXISTS(SELECT 1 FROM fleet_commands c JOIN fleet_command_states s ON s.tenant_id=c.tenant_id AND s.command_id=c.id WHERE c.tenant_id=NEW.tenant_id AND c.execution_id=NEW.id AND c.operation='APPLY' AND s.owned_receipt_id IS NOT NULL AND NOT s.restored) THEN RAISE EXCEPTION 'fleet rollback still has owned unapplied compensation';END IF;
  IF NEW.status='COMPLETED' THEN
   SELECT document INTO p FROM fleet_plans WHERE tenant_id=NEW.tenant_id AND id=NEW.parent_id;
   terminal:=p->'stages'->(jsonb_array_length(p->'stages')-1);
   SELECT ch.document->'plan',h.document,s.dispatched_at INTO last_child,last_health,last_dispatched FROM fleet_commands c JOIN fleet_children ch ON ch.tenant_id=c.tenant_id AND ch.id=c.child_id JOIN fleet_command_states s ON s.tenant_id=c.tenant_id AND s.command_id=c.id LEFT JOIN fleet_health_evidence h ON h.tenant_id=s.tenant_id AND h.id=s.health_evidence_id WHERE c.tenant_id=NEW.tenant_id AND c.execution_id=NEW.id AND c.operation='APPLY' ORDER BY (ch.document->'plan'->>'sequence')::numeric DESC LIMIT 1;
   IF last_child IS NULL OR last_health IS NULL OR last_health->>'status' IS DISTINCT FROM 'HEALTHY' OR last_child->>'stage_id' IS DISTINCT FROM terminal->>'id' OR (last_child->'transition'->>'candidate_after')::integer IS DISTINCT FROM (terminal->>'target_candidate_count')::integer OR (last_child->'transition'->>'traffic_after')::integer IS DISTINCT FROM (terminal->>'target_traffic_percent')::integer OR (terminal->>'kind'='DRAIN_OLD' AND (last_child->'transition'->>'old_after')::integer<>0) OR (last_health->>'created_at')::timestamptz<clock_timestamp()-interval '2 minutes' THEN RAISE EXCEPTION 'fleet completion requires fresh final-stage health';END IF;
   IF fleet_observation_elapsed(last_dispatched,(last_health->>'created_at')::timestamptz,(terminal->>'minimum_observation_seconds')::integer) IS DISTINCT FROM true THEN RAISE EXCEPTION 'fleet final-stage observation interval incomplete';END IF;
  END IF;
 END IF;NEW.updated_at:=clock_timestamp();RETURN NEW;
END $$;
CREATE TRIGGER fleet_execution_writer BEFORE INSERT OR UPDATE ON fleet_executions FOR EACH ROW EXECUTE FUNCTION guard_fleet_execution();
CREATE TRIGGER fleet_execution_no_delete BEFORE DELETE ON fleet_executions FOR EACH ROW EXECUTE FUNCTION deny_evidence_mutation();

CREATE FUNCTION guard_fleet_command() RETURNS trigger LANGUAGE plpgsql AS $$ DECLARE p jsonb;c jsonb;e fleet_executions;original_command text;owner_res fleet_reservations;used_flight integer;used_unavailable integer;cap_flight integer;cap_unavailable integer;flight integer;unavailable integer;previous jsonb;previous_command fleet_commands;previous_state fleet_command_states;stage jsonb;previous_stage jsonb;health jsonb;BEGIN
 SELECT * INTO e FROM fleet_executions WHERE tenant_id=NEW.tenant_id AND id=NEW.execution_id;PERFORM fleet_lock(NEW.tenant_id,e.workload_id);
 SELECT document->'plan' INTO c FROM fleet_children WHERE tenant_id=NEW.tenant_id AND id=NEW.child_id AND parent_id=e.parent_id;
 SELECT document INTO p FROM fleet_plans WHERE tenant_id=NEW.tenant_id AND id=e.parent_id;
 IF c IS NULL OR (c->>'expires_at')::timestamptz<=clock_timestamp() OR (c->>'created_at')::timestamptz<clock_timestamp()-interval '5 minutes' THEN RAISE EXCEPTION 'fleet command child missing or stale';END IF;
 NEW.operation:=CASE WHEN coalesce(c->>'compensation_for','')='' THEN 'APPLY' ELSE 'ROLLBACK' END;
 IF NEW.operation='APPLY' THEN PERFORM fleet_forward_authority(NEW.tenant_id,e.parent_id);IF e.recovery_only OR e.status IN('FAILED','RECOVERY_REQUIRED','ROLLED_BACK','COMPLETED') THEN RAISE EXCEPTION 'fleet execution forward action disabled';END IF;
  SELECT cmd.* INTO previous_command FROM fleet_commands cmd JOIN fleet_children ch ON ch.tenant_id=cmd.tenant_id AND ch.id=cmd.child_id WHERE cmd.tenant_id=NEW.tenant_id AND cmd.execution_id=NEW.execution_id ORDER BY (ch.document->'plan'->>'sequence')::numeric DESC LIMIT 1;
  SELECT value INTO stage FROM jsonb_array_elements(p->'stages') WHERE value->>'id'=c->>'stage_id';
  IF previous_command.id IS NULL THEN
   IF c->>'stage_id' IS DISTINCT FROM p->'stages'->0->>'id' OR (c->'transition'->>'old_before')::integer IS DISTINCT FROM (p->'old'->>'desired_count')::integer OR (c->'transition'->>'candidate_before')::integer<>0 OR (c->'transition'->>'traffic_before')::integer<>0 THEN RAISE EXCEPTION 'fleet execution must start at signed zero-candidate preparation';END IF;
  ELSE
   SELECT document->'plan' INTO previous FROM fleet_children WHERE tenant_id=NEW.tenant_id AND id=previous_command.child_id;
   SELECT * INTO previous_state FROM fleet_command_states WHERE tenant_id=NEW.tenant_id AND command_id=previous_command.id;
   SELECT document INTO health FROM fleet_health_evidence WHERE tenant_id=NEW.tenant_id AND id=previous_state.health_evidence_id;
   IF (c->>'sequence')::numeric<=(previous->>'sequence')::numeric OR previous_state.outcome NOT IN('APPLIED','NO_OP') OR previous_state.outcome='APPLIED' AND (health IS NULL OR health->>'status' IS DISTINCT FROM 'HEALTHY' OR (health->>'created_at')::timestamptz<clock_timestamp()-interval '2 minutes') OR (previous->'transition'->>'old_after')::integer IS DISTINCT FROM (c->'transition'->>'old_before')::integer OR (previous->'transition'->>'candidate_after')::integer IS DISTINCT FROM (c->'transition'->>'candidate_before')::integer OR (previous->'transition'->>'traffic_after')::integer IS DISTINCT FROM (c->'transition'->>'traffic_before')::integer THEN RAISE EXCEPTION 'fleet child requires previous resolved healthy state and increasing sequence';END IF;
   IF previous->>'stage_id' IS DISTINCT FROM c->>'stage_id' THEN
    SELECT value INTO previous_stage FROM jsonb_array_elements(p->'stages') WHERE value->>'id'=previous->>'stage_id';
    IF NOT (stage->'depends_on' ? (previous->>'stage_id')) OR (previous->'transition'->>'candidate_after')::integer IS DISTINCT FROM (previous_stage->>'target_candidate_count')::integer OR (previous->'transition'->>'traffic_after')::integer IS DISTINCT FROM (previous_stage->>'target_traffic_percent')::integer OR (previous_stage->>'kind'='DRAIN_OLD' AND (previous->'transition'->>'old_after')::integer<>0) OR coalesce((health->>'created_at')::timestamptz,previous_state.dispatched_at)<previous_state.dispatched_at+((previous_stage->>'minimum_observation_seconds')::integer * interval '1 second') THEN RAISE EXCEPTION 'fleet stage predecessor target or observation incomplete';END IF;
   END IF;
  END IF;
 ELSE
  SELECT cmd.id INTO original_command FROM fleet_commands cmd JOIN fleet_command_states s ON s.tenant_id=cmd.tenant_id AND s.command_id=cmd.id WHERE cmd.tenant_id=NEW.tenant_id AND cmd.child_id=c->>'compensation_for' AND cmd.execution_id=NEW.execution_id AND s.owned_receipt_id IS NOT NULL AND NOT s.restored;
  IF original_command IS NULL THEN RAISE EXCEPTION 'fleet recovery has no owned command';END IF;
  SELECT * INTO owner_res FROM fleet_reservations WHERE tenant_id=NEW.tenant_id AND command_id=original_command AND released_at IS NULL;
 END IF;
 cap_flight:=(p->'budget'->>'max_in_flight')::integer;cap_unavailable:=(p->'budget'->>'max_unavailable')::integer;flight:=(c->'transition'->>'in_flight')::integer;unavailable:=(c->'transition'->>'unavailable')::integer;
 IF flight<abs((c->'transition'->>'old_after')::integer-(c->'transition'->>'old_before')::integer)+abs((c->'transition'->>'candidate_after')::integer-(c->'transition'->>'candidate_before')::integer) OR flight NOT BETWEEN 0 AND 2 OR unavailable NOT BETWEEN 0 AND 2 OR cap_flight NOT BETWEEN 1 AND 2 OR cap_unavailable NOT BETWEEN 1 AND 2 THEN RAISE EXCEPTION 'fleet disruption counts invalid';END IF;
 IF owner_res.command_id IS NOT NULL THEN IF owner_res.in_flight<flight OR owner_res.unavailable<unavailable THEN RAISE EXCEPTION 'fleet recovery shared reservation insufficient';END IF;flight:=0;unavailable:=0;END IF;
 SELECT coalesce(sum(r.in_flight),0),coalesce(sum(r.unavailable),0),least(cap_flight,coalesce(min(r.max_in_flight),cap_flight)),least(cap_unavailable,coalesce(min(r.max_unavailable),cap_unavailable)) INTO used_flight,used_unavailable,cap_flight,cap_unavailable FROM fleet_reservations r WHERE r.tenant_id=NEW.tenant_id AND r.workload_id=e.workload_id AND r.released_at IS NULL;
 IF used_flight+flight>cap_flight OR used_unavailable+unavailable>cap_unavailable THEN RAISE EXCEPTION 'fleet global workload disruption budget exceeded';END IF;
 NEW.parent_id:=e.parent_id;NEW.workload_id:=e.workload_id;NEW.writer_role:='finops_worker';NEW.created_at:=clock_timestamp();NEW.document:=jsonb_build_object('id',NEW.id,'tenant_id',NEW.tenant_id,'execution_id',NEW.execution_id,'parent_id',NEW.parent_id,'child_id',NEW.child_id,'child_sha256',(SELECT content_hash FROM fleet_children WHERE tenant_id=NEW.tenant_id AND id=NEW.child_id),'workload_id',NEW.workload_id,'operation',NEW.operation,'idempotency_key',NEW.idempotency_key,'binding',c->'binding','saved_plan_sha256',c->>'saved_plan_sha256','child_nonce',c->>'nonce','pipeline_id',c->'iac'->>'pipeline_id','state_lineage',c->'iac'->>'state_lineage','state_serial',c->'iac'->'state_serial','transition',c->'transition','reservation_in_flight',flight,'reservation_unavailable',unavailable,'shared_reservation',owner_res.command_id,'created_at',NEW.created_at,'writer_role',NEW.writer_role);RETURN NEW;
END $$;
CREATE TRIGGER fleet_command_writer BEFORE INSERT ON fleet_commands FOR EACH ROW EXECUTE FUNCTION guard_fleet_command();
CREATE FUNCTION initialize_fleet_command() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=public,pg_temp AS $$ DECLARE p jsonb;BEGIN
 IF NEW.tenant_id IS DISTINCT FROM current_setting('app.tenant_id',true) THEN RAISE EXCEPTION 'fleet command tenant mismatch';END IF;
 SELECT document INTO p FROM fleet_plans WHERE tenant_id=NEW.tenant_id AND id=NEW.parent_id;
 INSERT INTO fleet_command_states(tenant_id,command_id) VALUES(NEW.tenant_id,NEW.id);
 INSERT INTO fleet_reservations(tenant_id,command_id,workload_id,in_flight,unavailable,max_in_flight,max_unavailable,shared_with) VALUES(NEW.tenant_id,NEW.id,NEW.workload_id,(NEW.document->>'reservation_in_flight')::integer,(NEW.document->>'reservation_unavailable')::integer,(p->'budget'->>'max_in_flight')::integer,(p->'budget'->>'max_unavailable')::integer,NEW.document->>'shared_reservation');RETURN NEW;
END $$;
CREATE TRIGGER fleet_command_initialize AFTER INSERT ON fleet_commands FOR EACH ROW EXECUTE FUNCTION initialize_fleet_command();
CREATE FUNCTION guard_fleet_dispatch() RETURNS trigger LANGUAGE plpgsql AS $$ DECLARE cmd fleet_commands;child jsonb;BEGIN
 IF (NEW.tenant_id,NEW.command_id) IS DISTINCT FROM (OLD.tenant_id,OLD.command_id) OR OLD.dispatch_intent AND NOT NEW.dispatch_intent THEN RAISE EXCEPTION 'fleet dispatch intent immutable';END IF;
  IF OLD.dispatch_intent AND NEW.dispatched_at IS DISTINCT FROM OLD.dispatched_at OR NOT NEW.dispatch_intent AND NEW.dispatched_at IS NOT NULL THEN RAISE EXCEPTION 'fleet original dispatch time immutable';END IF;
 IF NOT OLD.dispatch_intent AND NEW.dispatch_intent THEN
  SELECT * INTO cmd FROM fleet_commands WHERE tenant_id=NEW.tenant_id AND id=NEW.command_id;PERFORM fleet_lock(NEW.tenant_id,cmd.workload_id);
  SELECT document->'plan' INTO child FROM fleet_children WHERE tenant_id=NEW.tenant_id AND id=cmd.child_id;
  IF cmd.operation='APPLY' THEN PERFORM fleet_forward_authority(NEW.tenant_id,cmd.parent_id);IF EXISTS(SELECT 1 FROM fleet_executions WHERE tenant_id=NEW.tenant_id AND id=cmd.execution_id AND recovery_only) THEN RAISE EXCEPTION 'fleet execution recovery only';END IF;END IF;
  IF (child->>'expires_at')::timestamptz<=clock_timestamp() OR (child->>'created_at')::timestamptz<clock_timestamp()-interval '5 minutes' THEN RAISE EXCEPTION 'fleet dispatch child expired';END IF;
  NEW.dispatched_at:=clock_timestamp();
 END IF;NEW.updated_at:=clock_timestamp();RETURN NEW;
END $$;
CREATE TRIGGER fleet_dispatch_guard BEFORE UPDATE ON fleet_command_states FOR EACH ROW EXECUTE FUNCTION guard_fleet_dispatch();
CREATE TRIGGER fleet_state_no_delete BEFORE DELETE ON fleet_command_states FOR EACH ROW EXECUTE FUNCTION deny_evidence_mutation();

CREATE FUNCTION guard_fleet_callback() RETURNS trigger LANGUAGE plpgsql AS $$ DECLARE cmd fleet_commands;source jsonb;p jsonb;state fleet_command_states;owned jsonb;BEGIN
 SELECT * INTO cmd FROM fleet_commands WHERE tenant_id=NEW.tenant_id AND id=NEW.command_id;PERFORM fleet_lock(NEW.tenant_id,cmd.workload_id);
 SELECT document INTO source FROM fleet_observer_sources WHERE tenant_id=NEW.tenant_id AND id=NEW.source_id;SELECT * INTO state FROM fleet_command_states WHERE tenant_id=NEW.tenant_id AND command_id=NEW.command_id;
 p:=convert_from(NEW.raw_body,'UTF8')::jsonb;
 IF source IS NULL OR EXISTS(SELECT 1 FROM fleet_observer_revocations WHERE tenant_id=NEW.tenant_id AND source_id=NEW.source_id) OR source->>'issuer' IS DISTINCT FROM NEW.issuer OR source->>'subject' IS DISTINCT FROM NEW.subject OR source->>'audience' IS DISTINCT FROM NEW.audience OR source->>'pipeline_id' IS DISTINCT FROM cmd.document->>'pipeline_id' OR source->'binding' IS DISTINCT FROM cmd.document->'binding' OR NOT state.dispatch_intent THEN RAISE EXCEPTION 'fleet callback dedicated identity or intent invalid';END IF;
 IF p IS DISTINCT FROM NEW.payload OR encode(sha256(NEW.raw_body),'hex') IS DISTINCT FROM NEW.body_sha256 OR p->>'schema_version' IS DISTINCT FROM '4' OR p->>'command_id' IS DISTINCT FROM NEW.command_id OR p->>'child_id' IS DISTINCT FROM cmd.child_id OR p->>'child_sha256' IS DISTINCT FROM cmd.document->>'child_sha256' OR p->>'saved_plan_sha256' IS DISTINCT FROM cmd.document->>'saved_plan_sha256' OR p->>'child_nonce' IS DISTINCT FROM cmd.document->>'child_nonce' OR p->>'state_lineage' IS DISTINCT FROM cmd.document->>'state_lineage' OR (p->>'before_state_serial')::numeric IS DISTINCT FROM (cmd.document->>'state_serial')::numeric OR coalesce(p->>'outcome','') NOT IN('APPLIED','DEFINITELY_NOT_APPLIED','UNKNOWN','NO_OP') OR (p->>'observed_at')::timestamptz IS NULL OR (p->>'observed_at')::timestamptz>clock_timestamp()+interval '5 seconds' OR (p->>'observed_at')::timestamptz<cmd.created_at-interval '5 seconds' THEN RAISE EXCEPTION 'fleet callback original artifact binding invalid';END IF;
 IF state.outcome IN('DEFINITELY_NOT_APPLIED','NO_OP') AND p->>'outcome'='APPLIED' THEN RAISE EXCEPTION 'fleet contradictory definitive callback';END IF;
  IF state.owned_receipt_id IS NOT NULL AND p->>'outcome' IN('DEFINITELY_NOT_APPLIED','NO_OP') THEN RAISE EXCEPTION 'fleet owned callback cannot become definitely unapplied';END IF;
 IF p->>'outcome'='APPLIED' AND ((p->>'after_state_serial')::numeric<=(p->>'before_state_serial')::numeric OR jsonb_typeof(p->'old_instance_ids') IS DISTINCT FROM 'array' OR jsonb_typeof(p->'candidate_instance_ids') IS DISTINCT FROM 'array' OR coalesce(NEW.owned_hash,'')!~'^[a-f0-9]{64}$') THEN RAISE EXCEPTION 'fleet applied callback lacks state or cohort evidence';END IF;
 IF p->>'outcome'='APPLIED' AND (jsonb_array_length(p->'old_instance_ids')<>(cmd.document->'transition'->>'old_after')::integer OR jsonb_array_length(p->'candidate_instance_ids')<>(cmd.document->'transition'->>'candidate_after')::integer OR (SELECT count(DISTINCT value) FROM jsonb_array_elements_text((p->'old_instance_ids')||(p->'candidate_instance_ids')))<>jsonb_array_length(p->'old_instance_ids')+jsonb_array_length(p->'candidate_instance_ids') OR EXISTS(SELECT 1 FROM jsonb_array_elements_text((p->'old_instance_ids')||(p->'candidate_instance_ids')) x WHERE x!~'^i-([a-f0-9]{8}|[a-f0-9]{17})$')) THEN RAISE EXCEPTION 'fleet callback physical cohort membership invalid';END IF;
  IF p->>'outcome'='NO_OP' AND (EXISTS(SELECT 1 FROM fleet_children c,jsonb_array_elements(c.document->'plan'->'changes') a WHERE c.tenant_id=NEW.tenant_id AND c.id=cmd.child_id AND a->>'action'<>'no-op') OR cmd.document->'transition'->'old_before' IS DISTINCT FROM cmd.document->'transition'->'old_after' OR cmd.document->'transition'->'candidate_before' IS DISTINCT FROM cmd.document->'transition'->'candidate_after' OR cmd.document->'transition'->'traffic_before' IS DISTINCT FROM cmd.document->'transition'->'traffic_after') THEN RAISE EXCEPTION 'fleet NO_OP contradicts signed changes';END IF;
 NEW.created_at:=clock_timestamp();NEW.writer_role:='finops_deployment_observer';NEW.document:=p||jsonb_build_object('id',NEW.id,'tenant_id',NEW.tenant_id,'source_id',NEW.source_id,'body_sha256',NEW.body_sha256,'received_at',NEW.created_at,'writer_role',NEW.writer_role);
 IF p->>'outcome'='APPLIED' THEN
   NEW.document:=NEW.document||jsonb_build_object('old_instance_ids',coalesce((SELECT jsonb_agg(value ORDER BY value) FROM jsonb_array_elements_text(p->'old_instance_ids')),'[]'::jsonb),'candidate_instance_ids',coalesce((SELECT jsonb_agg(value ORDER BY value) FROM jsonb_array_elements_text(p->'candidate_instance_ids')),'[]'::jsonb));
  owned:=jsonb_build_object('id',NEW.id,'parent_id',cmd.parent_id,'child_id',cmd.child_id,'child_sha256',cmd.document->>'child_sha256','binding',cmd.document->'binding','pipeline_id',cmd.document->>'pipeline_id','saved_plan_sha256',cmd.document->>'saved_plan_sha256','status','APPLIED','before_state_serial',p->'before_state_serial','after_state_serial',p->'after_state_serial','observed_at',p->'observed_at','hash',NEW.owned_hash);NEW.document:=NEW.document||jsonb_build_object('owned_receipt',owned);
 END IF;RETURN NEW;
END $$;
CREATE TRIGGER fleet_callback_writer BEFORE INSERT ON fleet_callbacks FOR EACH ROW EXECUTE FUNCTION guard_fleet_callback();
CREATE FUNCTION apply_fleet_callback() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=public,pg_temp AS $$ DECLARE cmd fleet_commands;state fleet_command_states;BEGIN
 IF NEW.tenant_id IS DISTINCT FROM current_setting('app.tenant_id',true) THEN RAISE EXCEPTION 'fleet callback tenant mismatch';END IF;
 SELECT * INTO cmd FROM fleet_commands WHERE tenant_id=NEW.tenant_id AND id=NEW.command_id;SELECT * INTO state FROM fleet_command_states WHERE tenant_id=NEW.tenant_id AND command_id=NEW.command_id;
 IF NEW.payload->>'outcome'='APPLIED' THEN
  UPDATE fleet_command_states SET outcome='APPLIED',owned_receipt_id=coalesce(owned_receipt_id,NEW.id) WHERE tenant_id=NEW.tenant_id AND command_id=NEW.command_id;
 ELSIF NEW.payload->>'outcome' IN('DEFINITELY_NOT_APPLIED','NO_OP') AND state.owned_receipt_id IS NULL THEN
  UPDATE fleet_command_states SET outcome=NEW.payload->>'outcome' WHERE tenant_id=NEW.tenant_id AND command_id=NEW.command_id;
  UPDATE fleet_reservations SET released_at=clock_timestamp(),release_reason=NEW.payload->>'outcome' WHERE tenant_id=NEW.tenant_id AND command_id=NEW.command_id AND released_at IS NULL;
  IF NEW.payload->>'outcome'='DEFINITELY_NOT_APPLIED' THEN UPDATE fleet_executions SET recovery_only=true,status='FAILED' WHERE tenant_id=NEW.tenant_id AND id=cmd.execution_id;END IF;
 ELSIF state.owned_receipt_id IS NULL AND state.outcome NOT IN('DEFINITELY_NOT_APPLIED','NO_OP') THEN UPDATE fleet_command_states SET outcome='UNKNOWN' WHERE tenant_id=NEW.tenant_id AND command_id=NEW.command_id;END IF;RETURN NEW;
END $$;
CREATE TRIGGER fleet_callback_apply AFTER INSERT ON fleet_callbacks FOR EACH ROW EXECUTE FUNCTION apply_fleet_callback();

CREATE FUNCTION guard_fleet_health() RETURNS trigger LANGUAGE plpgsql AS $$ DECLARE cmd fleet_commands;callback jsonb;membership source_receipts;registration source_registrations;revision source_revisions;parent jsonb;member text;n jsonb;ev jsonb;cohort jsonb;BEGIN
 SELECT * INTO cmd FROM fleet_commands WHERE tenant_id=NEW.tenant_id AND id=NEW.command_id;PERFORM fleet_lock(NEW.tenant_id,cmd.workload_id);SELECT document INTO parent FROM fleet_plans WHERE tenant_id=NEW.tenant_id AND id=cmd.parent_id;
 IF NEW.document->>'command_id' IS DISTINCT FROM NEW.command_id OR coalesce(NEW.document->>'status','') NOT IN('HEALTHY','UNHEALTHY','UNKNOWN') THEN RAISE EXCEPTION 'fleet health binding invalid';END IF;
 IF NEW.document->>'status'='HEALTHY' THEN
  SELECT c.document INTO callback FROM fleet_callbacks c JOIN fleet_command_states s ON s.tenant_id=c.tenant_id AND s.owned_receipt_id=c.id WHERE s.tenant_id=NEW.tenant_id AND s.command_id=NEW.command_id;
  SELECT * INTO membership FROM source_receipts WHERE tenant_id=NEW.tenant_id AND id=NEW.document->>'membership_receipt_id' AND kind='AWS_FLEET_MEMBERSHIP' AND writer_role='finops_ingester';
  SELECT * INTO registration FROM source_registrations WHERE tenant_id=NEW.tenant_id AND id=membership.source_id;
  SELECT * INTO revision FROM source_revisions WHERE tenant_id=NEW.tenant_id AND id=membership.revision_id AND source_id=membership.source_id;
  IF membership.document->>'position' IS DISTINCT FROM 'AFTER' OR membership.document->>'child_id' IS DISTINCT FROM cmd.child_id OR membership.document->>'child_sha256' IS DISTINCT FROM cmd.document->>'child_sha256' OR (membership.document->>'collected_at')::timestamptz<(SELECT dispatched_at FROM fleet_command_states WHERE tenant_id=NEW.tenant_id AND command_id=NEW.command_id) THEN RAISE EXCEPTION 'fleet post-apply membership not bound to this dispatched child';END IF;
  IF callback IS NULL OR membership.id IS NULL OR revision.id IS NULL OR registration.document->>'enabled' IS DISTINCT FROM 'true' OR registration.document->>'revoked'='true' OR coalesce(registration.document->>'read_role_binding_id','')='' OR membership.document->>'read_role_binding_id' IS DISTINCT FROM registration.document->>'read_role_binding_id' OR (membership.document->>'registration_version')::bigint IS DISTINCT FROM registration.version OR membership.document->>'config_hash' IS DISTINCT FROM revision.document->>'config_hash' OR membership.document->'binding' IS DISTINCT FROM cmd.document->'binding' OR membership.document->>'old_asg' IS DISTINCT FROM parent->'old'->>'id' OR membership.document->>'candidate_asg' IS DISTINCT FROM parent->'candidate'->>'id' OR NOT (registration.document->>'payer_account_id'=cmd.document->'binding'->>'account_id' OR registration.document->'usage_account_ids' ? (cmd.document->'binding'->>'account_id')) OR (membership.document->>'collected_at')::timestamptz<clock_timestamp()-interval '5 minutes' OR (membership.document->>'collected_at')::timestamptz>clock_timestamp()+interval '5 seconds' OR membership.document->'old_instance_ids' IS DISTINCT FROM callback->'old_instance_ids' OR membership.document->'candidate_instance_ids' IS DISTINCT FROM callback->'candidate_instance_ids' OR jsonb_array_length(membership.document->'old_instance_ids')<>(cmd.document->'transition'->>'old_after')::integer OR jsonb_array_length(membership.document->'candidate_instance_ids')<>(cmd.document->'transition'->>'candidate_after')::integer THEN RAISE EXCEPTION 'fleet health native membership provenance invalid';END IF;
  IF membership.document->>'collected_at' IS NULL OR coalesce(membership.document->'raw_object'->>'version_id','') IN('','null') OR coalesce(membership.document->'raw_object'->>'body_sha256','')!~'^[a-f0-9]{64}$' OR NOT starts_with(coalesce(membership.document->'raw_object'->>'key',''),'tenant/'||NEW.tenant_id||'/fleet/') OR position('..' IN membership.document->'raw_object'->>'key')>0 OR coalesce(membership.document->'raw_object'->>'bucket','')='' THEN RAISE EXCEPTION 'fleet membership raw provenance missing';END IF;
  IF coalesce(membership.document->>'config_hash','')!~'^[a-f0-9]{64}$' OR revision.writer_role IS DISTINCT FROM 'finops_ingester' OR revision.document->>'registration_version' IS DISTINCT FROM registration.version::text OR coalesce(registration.document->>'payer_account_id'=cmd.document->'binding'->>'account_id',false)=false AND coalesce(registration.document->'usage_account_ids' ? (cmd.document->'binding'->>'account_id'),false)=false OR jsonb_typeof(membership.document->'old_instance_ids') IS DISTINCT FROM 'array' OR jsonb_typeof(membership.document->'candidate_instance_ids') IS DISTINCT FROM 'array' THEN RAISE EXCEPTION 'fleet membership source registration scope incomplete';END IF;
  FOR member IN SELECT jsonb_array_elements_text((membership.document->'old_instance_ids')||(membership.document->'candidate_instance_ids')) LOOP
   n:=NULL;
   FOR ev IN SELECT e.document FROM telemetry_evaluations e WHERE e.tenant_id=NEW.tenant_id AND e.id IN(SELECT jsonb_array_elements_text(NEW.document->'native_evaluation_ids')) LOOP
    IF ev->'binding'->>'provider_resource_id'=member AND ev->'binding'->>'workload_id'=cmd.workload_id AND ev->'binding'->>'account_id'=cmd.document->'binding'->>'account_id' AND ev->'binding'->>'region'=cmd.document->'binding'->>'region' AND ev->'evaluation'->>'status'='READY' AND (ev->'evaluation'->>'end')::timestamptz>=clock_timestamp()-interval '2 minutes' AND (ev->>'created_at')::timestamptz>=clock_timestamp()-interval '5 minutes' AND NOT EXISTS(SELECT 1 FROM telemetry_source_revocations v WHERE v.tenant_id=NEW.tenant_id AND v.revision_id=ev->>'revision_id') AND NOT EXISTS(SELECT 1 FROM telemetry_source_revisions r JOIN telemetry_connections c ON c.tenant_id=r.tenant_id AND c.id=r.connection_id WHERE r.tenant_id=NEW.tenant_id AND r.id=ev->>'revision_id' AND c.version>r.connection_version) THEN n:=ev;END IF;
   END LOOP;
   IF n IS NULL THEN RAISE EXCEPTION 'fleet health requires current native evidence for every physical member';END IF;
  END LOOP;
  IF NEW.document->>'cohort_slo_status' IS DISTINCT FROM 'CLEAR' OR jsonb_typeof(NEW.document->'slo_evaluation_ids') IS DISTINCT FROM 'array' OR jsonb_array_length(NEW.document->'slo_evaluation_ids')<1 THEN RAISE EXCEPTION 'fleet explicit cohort SLO comparison required';END IF;
  SELECT document INTO cohort FROM fleet_proof_sets WHERE tenant_id=NEW.tenant_id AND id=NEW.document->>'cohort_proof_id' AND kind='COHORT_HEALTH' AND writer_role='finops_api';
  IF cohort IS NULL OR cohort->>'status' IS DISTINCT FROM 'CLEAR' OR cohort->'binding' IS DISTINCT FROM cmd.document->'binding' OR cohort->>'command_id' IS DISTINCT FROM NEW.command_id OR cohort->>'child_sha256' IS DISTINCT FROM cmd.document->>'child_sha256' OR cohort->>'membership_receipt_id' IS DISTINCT FROM membership.id OR cohort->'native_evaluation_ids' IS DISTINCT FROM NEW.document->'native_evaluation_ids' OR cohort->'slo_evaluation_ids' IS DISTINCT FROM NEW.document->'slo_evaluation_ids' OR (cohort->>'expires_at')::timestamptz IS NULL OR (cohort->>'expires_at')::timestamptz<=clock_timestamp() OR coalesce(cohort->>'comparison_sha256','')!~'^[a-f0-9]{64}$' OR jsonb_typeof(cohort->'baseline_evaluation_ids') IS DISTINCT FROM 'array' OR jsonb_array_length(cohort->'baseline_evaluation_ids')<1 THEN RAISE EXCEPTION 'fleet current explicit blue green control comparison factory proof required';END IF;
  FOR member IN SELECT jsonb_array_elements_text(NEW.document->'slo_evaluation_ids') LOOP
   SELECT document INTO ev FROM slo_evaluations WHERE tenant_id=NEW.tenant_id AND id=member;
   IF ev IS NULL OR ev->>'workload_id' IS DISTINCT FROM cmd.workload_id OR ev->'evaluation'->>'status'<>'CLEAR' OR (ev->'evaluation'->>'window_end')::timestamptz<clock_timestamp()-interval '2 minutes' THEN RAISE EXCEPTION 'fleet current SLO evidence invalid';END IF;
  END LOOP;
 END IF;
 NEW.writer_role:='finops_api';NEW.created_at:=clock_timestamp();NEW.document:=NEW.document||jsonb_build_object('id',NEW.id,'tenant_id',NEW.tenant_id,'hash',NEW.content_hash,'created_at',NEW.created_at,'writer_role',NEW.writer_role);RETURN NEW;
END $$;
CREATE TRIGGER fleet_health_writer BEFORE INSERT ON fleet_health_evidence FOR EACH ROW EXECUTE FUNCTION guard_fleet_health();
CREATE FUNCTION apply_fleet_health_failure() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=public,pg_temp AS $$ BEGIN
 IF NEW.tenant_id IS DISTINCT FROM current_setting('app.tenant_id',true) THEN RAISE EXCEPTION 'fleet health tenant mismatch';END IF;
 IF NEW.document->>'status'='UNHEALTHY' THEN UPDATE fleet_executions SET recovery_only=true,status='FAILED' WHERE tenant_id=NEW.tenant_id AND id=(SELECT execution_id FROM fleet_commands WHERE tenant_id=NEW.tenant_id AND id=NEW.command_id);END IF;RETURN NEW;
END $$;
CREATE TRIGGER fleet_health_failure AFTER INSERT ON fleet_health_evidence FOR EACH ROW EXECUTE FUNCTION apply_fleet_health_failure();
CREATE FUNCTION apply_fleet_release() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=public,pg_temp AS $$ DECLARE evidence jsonb;cmd fleet_commands;child jsonb;original text;BEGIN
 IF NEW.tenant_id IS DISTINCT FROM current_setting('app.tenant_id',true) THEN RAISE EXCEPTION 'fleet release tenant mismatch';END IF;
 SELECT * INTO cmd FROM fleet_commands WHERE tenant_id=NEW.tenant_id AND id=NEW.command_id;PERFORM fleet_lock(NEW.tenant_id,cmd.workload_id);
 SELECT document INTO evidence FROM fleet_health_evidence WHERE tenant_id=NEW.tenant_id AND id=NEW.evidence_id AND command_id=NEW.command_id;
 IF evidence IS NULL OR evidence->>'status'<>'HEALTHY' OR (evidence->>'created_at')::timestamptz<clock_timestamp()-interval '2 minutes' THEN RAISE EXCEPTION 'fleet release requires fresh authoritative healthy evidence';END IF;
 UPDATE fleet_reservations SET released_at=clock_timestamp(),release_reason='HEALTHY' WHERE tenant_id=NEW.tenant_id AND command_id=NEW.command_id AND released_at IS NULL;
 UPDATE fleet_command_states SET health_evidence_id=NEW.evidence_id WHERE tenant_id=NEW.tenant_id AND command_id=NEW.command_id;
 IF cmd.operation='ROLLBACK' THEN
  SELECT document->'plan' INTO child FROM fleet_children WHERE tenant_id=NEW.tenant_id AND id=cmd.child_id;
  SELECT id INTO original FROM fleet_commands WHERE tenant_id=NEW.tenant_id AND execution_id=cmd.execution_id AND child_id=child->>'compensation_for';
  UPDATE fleet_reservations SET released_at=clock_timestamp(),release_reason='OWNED_ROLLBACK_HEALTHY' WHERE tenant_id=NEW.tenant_id AND command_id=original AND released_at IS NULL;
  UPDATE fleet_command_states SET restored=true WHERE tenant_id=NEW.tenant_id AND command_id=original;
 END IF;
 NEW.writer_role:='finops_worker';NEW.created_at:=clock_timestamp();NEW.document:=jsonb_build_object('id',NEW.id,'tenant_id',NEW.tenant_id,'command_id',NEW.command_id,'evidence_id',NEW.evidence_id,'created_at',NEW.created_at,'writer_role',NEW.writer_role);RETURN NEW;
END $$;
CREATE TRIGGER fleet_release_writer BEFORE INSERT ON fleet_release_events FOR EACH ROW EXECUTE FUNCTION apply_fleet_release();
CREATE FUNCTION guard_fleet_reservation_update() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF TG_OP='DELETE' OR (NEW.tenant_id,NEW.command_id,NEW.workload_id,NEW.in_flight,NEW.unavailable,NEW.max_in_flight,NEW.max_unavailable,NEW.shared_with,NEW.created_at) IS DISTINCT FROM (OLD.tenant_id,OLD.command_id,OLD.workload_id,OLD.in_flight,OLD.unavailable,OLD.max_in_flight,OLD.max_unavailable,OLD.shared_with,OLD.created_at) OR OLD.released_at IS NOT NULL THEN RAISE EXCEPTION 'fleet reservation immutable obligation';END IF;RETURN NEW;
END $$;
CREATE TRIGGER fleet_reservation_guard BEFORE UPDATE OR DELETE ON fleet_reservations FOR EACH ROW EXECUTE FUNCTION guard_fleet_reservation_update();
