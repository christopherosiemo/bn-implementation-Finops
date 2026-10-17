DO $$ BEGIN
 IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='finops_ingester') THEN CREATE ROLE finops_ingester NOLOGIN; END IF;
END $$;
GRANT USAGE ON SCHEMA public TO finops_ingester;
GRANT SELECT ON tenant_registry TO finops_ingester;
DO $$ BEGIN
 IF NOT EXISTS(SELECT FROM pg_policies WHERE tablename='tenant_registry' AND policyname='ingester_tenant_routing') THEN
  CREATE POLICY ingester_tenant_routing ON tenant_registry FOR SELECT TO finops_ingester USING(true);
 END IF;
END $$;
GRANT SELECT,INSERT,UPDATE ON entities TO finops_ingester;
GRANT SELECT,INSERT ON audit_events TO finops_ingester;
GRANT SELECT,INSERT ON outbox TO finops_ingester;
REVOKE INSERT ON savings_ledger FROM finops_worker;
ALTER TABLE savings_ledger ADD COLUMN IF NOT EXISTS verified_amount numeric(38,12) GENERATED ALWAYS AS (NULLIF(document->>'verified_saving','')::numeric) STORED;
ALTER TABLE savings_ledger ADD COLUMN IF NOT EXISTS baseline_amount numeric(38,12) GENERATED ALWAYS AS (NULLIF(document->>'expected_baseline_cost','')::numeric) STORED;
ALTER TABLE savings_ledger ADD COLUMN IF NOT EXISTS actual_amount numeric(38,12) GENERATED ALWAYS AS (NULLIF(document->>'actual_cost','')::numeric) STORED;
ALTER TABLE savings_ledger ADD COLUMN IF NOT EXISTS currency text GENERATED ALWAYS AS (document->>'currency') STORED;
CREATE INDEX IF NOT EXISTS savings_claim_lookup ON savings_ledger(tenant_id,(document->>'resource_id'),(document->>'claim_key'),created_at DESC);

ALTER TABLE entities ADD COLUMN IF NOT EXISTS writer_role text NOT NULL DEFAULT current_user;
CREATE OR REPLACE FUNCTION guard_entity_writer() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE actor text := current_user; k text; BEGIN
 IF (SELECT rolsuper FROM pg_roles WHERE rolname=current_user) THEN actor := 'migration_admin';
 ELSIF pg_has_role(current_user,'finops_ingester','MEMBER') THEN actor := 'finops_ingester';
 ELSIF pg_has_role(current_user,'finops_worker','MEMBER') THEN actor := 'finops_worker';
 ELSIF pg_has_role(current_user,'finops_api','MEMBER') THEN actor := 'finops_api'; END IF;
 k := CASE WHEN TG_OP='DELETE' THEN OLD.kind ELSE NEW.kind END;
 IF TG_OP='INSERT' THEN NEW.writer_role := actor;
 ELSIF TG_OP='UPDATE' THEN
  IF NEW.tenant_id<>OLD.tenant_id OR NEW.kind<>OLD.kind OR NEW.id<>OLD.id OR NEW.writer_role<>OLD.writer_role THEN
   RAISE EXCEPTION 'entity identity and provenance are immutable';
  END IF;
 END IF;
 IF actor='finops_ingester' AND k NOT IN ('cloud_accounts','resources','ingestion_jobs','audit_archives','data_quality','metric_evidence','billing_evidence') THEN
  RAISE EXCEPTION 'ingestion identity cannot write control or approval state';
 END IF;
 IF actor='finops_worker' THEN
  IF TG_OP='INSERT' AND k NOT IN ('change_plans','approvals','executions') THEN
   RAISE EXCEPTION 'workflow identity cannot create policy or ingestion state';
  END IF;
  IF TG_OP='UPDATE' AND k NOT IN ('change_plans','executions','resources','schedules') THEN
   RAISE EXCEPTION 'workflow identity cannot modify policy or approval state';
  END IF;
  IF k='approvals' AND (TG_OP<>'INSERT' OR NEW.document->>'approved_by' NOT LIKE 'policy:%') THEN
   RAISE EXCEPTION 'workflow identity cannot create human approvals';
  END IF;
  IF TG_OP='UPDATE' AND k='schedules' AND
    (NEW.document - ARRAY['version','last_occurrence_date','skip_next_stop']) IS DISTINCT FROM
    (OLD.document - ARRAY['version','last_occurrence_date','skip_next_stop']) THEN
   RAISE EXCEPTION 'workflow identity cannot change schedule authorization';
  END IF;
  IF TG_OP='UPDATE' AND k='resources' AND
    (NEW.document - ARRAY['version','state','last_seen_at']) IS DISTINCT FROM
    (OLD.document - ARRAY['version','state','last_seen_at']) THEN
   RAISE EXCEPTION 'workflow identity cannot change resource authority';
  END IF;
 END IF;
 IF TG_OP='UPDATE' AND k='change_plans' AND NEW.document->'payload' IS DISTINCT FROM OLD.document->'payload' THEN
  RAISE EXCEPTION 'change plan payload is immutable';
 END IF;
 IF TG_OP='UPDATE' AND k='approvals' THEN
  RAISE EXCEPTION 'approval evidence is immutable';
 END IF;
 IF TG_OP='DELETE' THEN RETURN OLD; END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS entities_writer_boundary ON entities;
CREATE TRIGGER entities_writer_boundary BEFORE INSERT OR UPDATE OR DELETE ON entities FOR EACH ROW EXECUTE FUNCTION guard_entity_writer();
