-- Bind only the private037 analytical decision credential. API tenant selection
-- remains authenticated service authority; no execution/financial grant changes.
CREATE TABLE fleet_decision_credentials (
 id uuid PRIMARY KEY, database_login name NOT NULL, role_oid oid NOT NULL,
 tenant_id text NOT NULL CHECK(tenant_id~'^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'),
 purpose text NOT NULL DEFAULT 'group-decision-reader' CHECK(purpose='group-decision-reader'),
 installed_by name NOT NULL DEFAULT session_user,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(database_login,role_oid),UNIQUE(role_oid)
);
CREATE TABLE fleet_decision_credential_revocations (
 credential_id uuid PRIMARY KEY REFERENCES fleet_decision_credentials(id),
 reason_code text NOT NULL CHECK(reason_code~'^[A-Z][A-Z0-9_]{0,127}$'),
 installed_by name NOT NULL DEFAULT session_user,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON fleet_decision_credentials,fleet_decision_credential_revocations FROM PUBLIC,finops_api,finops_group_decision;
DO $$ DECLARE tab text;BEGIN
 FOREACH tab IN ARRAY ARRAY['fleet_decision_credentials','fleet_decision_credential_revocations'] LOOP
  EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',tab);
  EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',tab);
  EXECUTE format('CREATE POLICY operator_only ON public.%I TO %I USING(true) WITH CHECK(true)',tab,current_user);
  EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON public.%I FOR EACH ROW EXECUTE FUNCTION public.deny_evidence_mutation()',tab||'_immutable',tab);
 END LOOP;
END $$;

CREATE FUNCTION guard_fleet_decision_credential_installation() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE actual pg_roles%ROWTYPE;binding public.fleet_decision_credentials%ROWTYPE;BEGIN
 IF TG_TABLE_NAME='fleet_decision_credentials' THEN
  SELECT * INTO actual FROM pg_roles WHERE oid=NEW.role_oid;
  IF actual.oid IS NULL OR actual.rolname IS DISTINCT FROM NEW.database_login OR NOT actual.rolcanlogin
   OR actual.rolsuper OR actual.rolcreatedb OR actual.rolcreaterole OR actual.rolreplication OR actual.rolbypassrls
   OR NOT pg_has_role(actual.oid,'finops_group_decision','MEMBER')
   OR EXISTS(SELECT 1 FROM pg_roles r WHERE pg_has_role(actual.oid,r.oid,'MEMBER') AND r.rolname NOT IN(actual.rolname,'finops_group_decision'))
   THEN RAISE EXCEPTION 'decision credential dedicated login/OID required';END IF;
 ELSE
  SELECT * INTO binding FROM public.fleet_decision_credentials WHERE id=NEW.credential_id;
  IF binding.id IS NULL THEN RAISE EXCEPTION 'decision credential binding missing';END IF;
  -- Publication takes graph then shared credential fence. Revocation takes
  -- only this exclusive fence, so it never reverses graph/source ordering.
  PERFORM pg_advisory_xact_lock(hashtextextended('fleet-decision-credential:'||binding.database_login::text,0));
 END IF;
 NEW.installed_by:=session_user;NEW.created_at:=clock_timestamp();RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION guard_fleet_decision_credential_installation() FROM PUBLIC;
CREATE TRIGGER fleet_decision_credential_install BEFORE INSERT ON fleet_decision_credentials FOR EACH ROW EXECUTE FUNCTION guard_fleet_decision_credential_installation();
CREATE TRIGGER fleet_decision_credential_revoke BEFORE INSERT ON fleet_decision_credential_revocations FOR EACH ROW EXECUTE FUNCTION guard_fleet_decision_credential_installation();

-- SESSION_USER survives SET/RESET ROLE. The live pg_roles OID/name join prevents
-- a dropped/recreated login from inheriting its predecessor's commissioning.
-- A retained REPEATABLE READ snapshot could otherwise hide a committed
-- revocation after waiting for its fence. The worker uses READ COMMITTED.
CREATE FUNCTION fleet_decision_credential_scope(p_tenant text) RETURNS boolean
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
 SELECT coalesce(current_setting('transaction_isolation')='read committed' AND p_tenant<>'' AND p_tenant=current_setting('app.tenant_id',true) AND EXISTS(
  SELECT 1 FROM public.fleet_decision_credentials c JOIN pg_roles r ON r.oid=c.role_oid AND r.rolname=c.database_login
  WHERE c.tenant_id=p_tenant AND r.rolname=session_user AND r.rolcanlogin
   AND NOT(r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls)
   AND pg_has_role(r.oid,'finops_group_decision','MEMBER')
   AND NOT EXISTS(SELECT 1 FROM pg_roles inherited WHERE pg_has_role(r.oid,inherited.oid,'MEMBER') AND inherited.rolname NOT IN(r.rolname,'finops_group_decision'))
   AND NOT EXISTS(SELECT 1 FROM public.fleet_decision_credential_revocations revoked WHERE revoked.credential_id=c.id)
 ),false)
$$;
REVOKE ALL ON FUNCTION fleet_decision_credential_scope(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION fleet_decision_credential_scope(text) TO finops_group_decision;

CREATE FUNCTION fleet_joint_decision_tenant_access(p_tenant text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE who text:=coalesce(nullif(current_setting('role',true),'none'),session_user);machine boolean;BEGIN
 IF p_tenant IS NULL OR p_tenant='' OR p_tenant IS DISTINCT FROM current_setting('app.tenant_id',true) THEN RETURN false;END IF;
 SELECT pg_has_role(session_user,'finops_group_decision','MEMBER') OR EXISTS(
  SELECT 1 FROM public.fleet_decision_credentials c JOIN pg_roles r ON r.oid=c.role_oid AND r.rolname=c.database_login WHERE r.rolname=session_user
 ) INTO machine;
 IF machine THEN RETURN public.fleet_decision_credential_scope(p_tenant);END IF;
 RETURN who='finops_api' AND pg_has_role(session_user,'finops_api','MEMBER');
END $$;
REVOKE ALL ON FUNCTION fleet_joint_decision_tenant_access(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION fleet_joint_decision_tenant_access(text) TO finops_api,finops_group_decision;
DO $$ DECLARE tab text;BEGIN
 FOREACH tab IN ARRAY ARRAY['fleet_joint_decision_requests','fleet_joint_decisions','fleet_joint_decision_refusals'] LOOP
  EXECUTE format('DROP POLICY tenant_isolation ON public.%I',tab);
  EXECUTE format('CREATE POLICY tenant_isolation ON public.%I USING(public.fleet_joint_decision_tenant_access(tenant_id)) WITH CHECK(public.fleet_joint_decision_tenant_access(tenant_id))',tab);
 END LOOP;
END $$;

-- Preserve every037 input/currentness check byte-for-byte behind an owner-only
-- implementation. Both this SECURITY DEFINER entry and direct table policies
-- independently require the authenticated decision session's commissioned scope.
ALTER FUNCTION fleet_joint_decision_inputs(text,text,text) RENAME TO fleet_joint_decision_inputs_v037_private;
REVOKE ALL ON FUNCTION fleet_joint_decision_inputs_v037_private(text,text,text) FROM PUBLIC,finops_api,finops_group_decision;
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM pg_proc p CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
  WHERE p.oid='public.fleet_joint_decision_inputs_v037_private(text,text,text)'::regprocedure AND a.grantee<>p.proowner)
 THEN RAISE EXCEPTION 'private decision resolver has nonowner grant';END IF;
END $$;

CREATE FUNCTION fleet_joint_decision_inputs(p_tenant text,p_assessment text,p_capacity text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE who text:=coalesce(nullif(current_setting('role',true),'none'),session_user);BEGIN
 IF NOT public.fleet_joint_decision_tenant_access(p_tenant) THEN RAISE EXCEPTION 'decision credential tenant scope differs';END IF;
 IF who='finops_group_decision' THEN
  PERFORM pg_advisory_xact_lock(hashtextextended(p_tenant||':dependency-graph',0));
  PERFORM pg_advisory_xact_lock_shared(hashtextextended('fleet-decision-credential:'||session_user::text,0));
  IF NOT public.fleet_decision_credential_scope(p_tenant) THEN RAISE EXCEPTION 'decision credential revoked or changed';END IF;
 END IF;
 RETURN public.fleet_joint_decision_inputs_v037_private(p_tenant,p_assessment,p_capacity);
END $$;
REVOKE ALL ON FUNCTION fleet_joint_decision_inputs(text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION fleet_joint_decision_inputs(text,text,text) TO finops_api,finops_group_decision;

-- Refusal reasons other than stale-input do not call the input resolver. Guard
-- BOTH terminal paths explicitly, including revocation racing a publication.
CREATE FUNCTION guard_fleet_joint_decision_credential() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id||':dependency-graph',0));
 PERFORM pg_advisory_xact_lock_shared(hashtextextended('fleet-decision-credential:'||session_user::text,0));
 IF NOT public.fleet_decision_credential_scope(NEW.tenant_id) THEN RAISE EXCEPTION 'decision credential publication scope differs';END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION guard_fleet_joint_decision_credential() FROM PUBLIC;
CREATE TRIGGER fleet_joint_credential_guard BEFORE INSERT ON fleet_joint_decisions FOR EACH ROW EXECUTE FUNCTION guard_fleet_joint_decision_credential();
CREATE TRIGGER fleet_joint_credential_guard BEFORE INSERT ON fleet_joint_decision_refusals FOR EACH ROW EXECUTE FUNCTION guard_fleet_joint_decision_credential();
