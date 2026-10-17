CREATE TABLE readiness_evidence (
 tenant_id text NOT NULL, kind text NOT NULL CHECK(kind IN ('baseline','measurement','measurement_snapshot','readiness')),
 id text NOT NULL, resource_id text NOT NULL, document jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(tenant_id,kind,id)
);
CREATE INDEX readiness_evidence_resource ON readiness_evidence(tenant_id,resource_id,kind,created_at DESC);
ALTER TABLE readiness_evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE readiness_evidence FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON readiness_evidence USING(tenant_id=current_setting('app.tenant_id',true)) WITH CHECK(tenant_id=current_setting('app.tenant_id',true));
CREATE TRIGGER readiness_evidence_immutable BEFORE UPDATE OR DELETE ON readiness_evidence FOR EACH ROW EXECUTE FUNCTION deny_evidence_mutation();
GRANT SELECT ON readiness_evidence TO finops_api,finops_worker,finops_signer,finops_executor,finops_ingester;
GRANT INSERT ON readiness_evidence TO finops_api,finops_worker,finops_ingester;
CREATE FUNCTION guard_readiness_writer() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname=current_user) THEN
  IF pg_has_role(current_user,'finops_worker','MEMBER') AND NEW.kind<>'measurement' THEN RAISE EXCEPTION 'workflow cannot forge baseline or readiness evidence'; END IF;
  IF pg_has_role(current_user,'finops_ingester','MEMBER') AND NEW.kind NOT IN ('baseline','measurement_snapshot') THEN RAISE EXCEPTION 'ingestion cannot authorize execution'; END IF;
 END IF;
 IF NEW.document->>'tenant_id' IS DISTINCT FROM NEW.tenant_id OR NEW.document->>'resource_id' IS DISTINCT FROM NEW.resource_id THEN RAISE EXCEPTION 'evidence binding mismatch'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER readiness_writer BEFORE INSERT ON readiness_evidence FOR EACH ROW EXECUTE FUNCTION guard_readiness_writer();
