-- Additive migration: signed historical plans and owned restoration are retained.
ALTER TABLE readiness_evidence DROP CONSTRAINT readiness_evidence_kind_check;
ALTER TABLE readiness_evidence ADD CONSTRAINT readiness_evidence_kind_check
 CHECK(kind IN ('baseline','measurement','measurement_snapshot','readiness','proof_set'));
CREATE OR REPLACE FUNCTION guard_readiness_writer() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname=current_user) THEN
  IF pg_has_role(current_user,'finops_worker','MEMBER') AND NEW.kind<>'measurement' THEN RAISE EXCEPTION 'workflow cannot forge baseline or readiness evidence'; END IF;
  IF pg_has_role(current_user,'finops_ingester','MEMBER') AND NEW.kind NOT IN ('baseline','measurement_snapshot') THEN RAISE EXCEPTION 'ingestion cannot authorize execution'; END IF;
 END IF;
 IF NEW.document->>'tenant_id' IS DISTINCT FROM NEW.tenant_id OR NEW.document->>'resource_id' IS DISTINCT FROM NEW.resource_id THEN RAISE EXCEPTION 'evidence binding mismatch'; END IF;
 RETURN NEW;
END $$;
