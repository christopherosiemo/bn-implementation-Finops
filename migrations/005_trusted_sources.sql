CREATE TABLE source_registrations (
 tenant_id text NOT NULL,id text NOT NULL,version bigint NOT NULL DEFAULT 1,
 kind text NOT NULL,document jsonb NOT NULL,created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(tenant_id,id)
);
CREATE TABLE source_revisions (
 tenant_id text NOT NULL,id text NOT NULL,source_id text NOT NULL,revision_hash text NOT NULL,
 document jsonb NOT NULL,writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(tenant_id,id),UNIQUE(tenant_id,source_id,revision_hash),
 FOREIGN KEY(tenant_id,source_id) REFERENCES source_registrations(tenant_id,id)
);
CREATE TABLE source_receipts (
 tenant_id text NOT NULL,id text NOT NULL,source_id text NOT NULL,revision_id text,kind text NOT NULL,
 document jsonb NOT NULL,writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(tenant_id,id),
 FOREIGN KEY(tenant_id,source_id) REFERENCES source_registrations(tenant_id,id),
 FOREIGN KEY(tenant_id,revision_id) REFERENCES source_revisions(tenant_id,id)
);
CREATE TABLE source_checkpoints (
 tenant_id text NOT NULL,source_id text NOT NULL,checkpoint_key text NOT NULL,document jsonb NOT NULL,
 updated_at timestamptz NOT NULL DEFAULT now(),PRIMARY KEY(tenant_id,source_id,checkpoint_key),
 FOREIGN KEY(tenant_id,source_id) REFERENCES source_registrations(tenant_id,id)
);
CREATE INDEX source_receipts_lookup ON source_receipts(tenant_id,source_id,kind,created_at DESC);
DO $$ DECLARE t text; BEGIN FOREACH t IN ARRAY ARRAY['source_registrations','source_revisions','source_receipts','source_checkpoints'] LOOP
 EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',t);
 EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',t);
 EXECUTE format('CREATE POLICY tenant_isolation ON %I USING(tenant_id=current_setting(''app.tenant_id'',true)) WITH CHECK(tenant_id=current_setting(''app.tenant_id'',true))',t);
 END LOOP; END $$;
CREATE TRIGGER source_revisions_immutable BEFORE UPDATE OR DELETE ON source_revisions FOR EACH ROW EXECUTE FUNCTION deny_evidence_mutation();
CREATE TRIGGER source_receipts_immutable BEFORE UPDATE OR DELETE ON source_receipts FOR EACH ROW EXECUTE FUNCTION deny_evidence_mutation();
CREATE FUNCTION source_evidence_writer() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname=current_user) AND NOT pg_has_role(current_user,'finops_ingester','MEMBER') THEN RAISE EXCEPTION 'trusted source receipts require ingestion identity'; END IF;
 NEW.writer_role := CASE WHEN pg_has_role(current_user,'finops_ingester','MEMBER') THEN 'finops_ingester' ELSE 'migration_admin' END;
 IF NEW.document->>'tenant_id' IS DISTINCT FROM NEW.tenant_id OR NEW.document->>'source_id' IS DISTINCT FROM NEW.source_id THEN RAISE EXCEPTION 'source identity mismatch'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER source_revision_writer BEFORE INSERT ON source_revisions FOR EACH ROW EXECUTE FUNCTION source_evidence_writer();
CREATE TRIGGER source_receipt_writer BEFORE INSERT ON source_receipts FOR EACH ROW EXECUTE FUNCTION source_evidence_writer();
GRANT SELECT ON source_registrations,source_revisions,source_receipts TO finops_api,finops_ingester,finops_worker,finops_signer,finops_executor;
GRANT INSERT,UPDATE ON source_registrations TO finops_api;
GRANT INSERT ON source_revisions,source_receipts TO finops_ingester;
GRANT SELECT,INSERT,UPDATE ON source_checkpoints TO finops_ingester;
GRANT SELECT ON source_checkpoints TO finops_api,finops_worker,finops_signer,finops_executor;
