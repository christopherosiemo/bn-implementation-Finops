DO $$ BEGIN
 IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='finops_api') THEN CREATE ROLE finops_api NOLOGIN; END IF;
 IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='finops_worker') THEN CREATE ROLE finops_worker NOLOGIN; END IF;
 IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='finops_signer') THEN CREATE ROLE finops_signer NOLOGIN; END IF;
 IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='finops_executor') THEN CREATE ROLE finops_executor NOLOGIN; END IF;
END $$;
CREATE TABLE IF NOT EXISTS entities (
 tenant_id text NOT NULL, kind text NOT NULL, id text NOT NULL,
 version bigint NOT NULL DEFAULT 1, document jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(tenant_id,kind,id)
);
CREATE INDEX IF NOT EXISTS entities_lookup ON entities(tenant_id,kind,created_at);
CREATE UNIQUE INDEX IF NOT EXISTS resource_provider_identity ON entities(tenant_id,(document->>'provider'),(document->>'account_id'),(document->>'region'),(document->>'provider_resource_id')) WHERE kind='resources';
CREATE UNIQUE INDEX IF NOT EXISTS execution_plan_identity ON entities(tenant_id,(document->>'change_plan_id')) WHERE kind='executions';
CREATE TABLE IF NOT EXISTS tenant_registry(tenant_id text PRIMARY KEY,created_at timestamptz NOT NULL DEFAULT now());
ALTER TABLE tenant_registry ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_registry FORCE ROW LEVEL SECURITY;
DO $$ BEGIN IF NOT EXISTS(SELECT FROM pg_policies WHERE tablename='tenant_registry' AND policyname='tenant_registration') THEN
 CREATE POLICY tenant_registration ON tenant_registry USING(tenant_id=current_setting('app.tenant_id',true)) WITH CHECK(tenant_id=current_setting('app.tenant_id',true));
 CREATE POLICY worker_tenant_routing ON tenant_registry FOR SELECT TO finops_worker USING(true);
END IF;END $$;
GRANT SELECT,INSERT ON tenant_registry TO finops_api;
GRANT SELECT ON tenant_registry TO finops_worker;
CREATE TABLE IF NOT EXISTS audit_events (
 tenant_id text NOT NULL,id text NOT NULL,actor text NOT NULL,action text NOT NULL,
 resource text NOT NULL,document jsonb NOT NULL,created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(tenant_id,id)
);
CREATE TABLE IF NOT EXISTS savings_ledger (
 tenant_id text NOT NULL,id text NOT NULL,execution_id text NOT NULL,fingerprint text NOT NULL,
 document jsonb NOT NULL,created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(tenant_id,id),UNIQUE(tenant_id,fingerprint)
);
CREATE TABLE IF NOT EXISTS idempotency (
 tenant_id text NOT NULL,key text NOT NULL,request_hash text NOT NULL,status integer,
 response jsonb,created_at timestamptz NOT NULL DEFAULT now(),PRIMARY KEY(tenant_id,key)
);
CREATE TABLE IF NOT EXISTS signed_plans (
 tenant_id text NOT NULL,plan_id text NOT NULL,nonce text NOT NULL,envelope jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),PRIMARY KEY(tenant_id,plan_id),UNIQUE(tenant_id,nonce)
);
CREATE TABLE IF NOT EXISTS provider_operations (
 tenant_id text NOT NULL,execution_id text NOT NULL,resource_id text NOT NULL,
 stop_intent boolean NOT NULL DEFAULT false,stop_owned boolean NOT NULL DEFAULT false,
 restored boolean NOT NULL DEFAULT false,document jsonb NOT NULL DEFAULT '{}',
 updated_at timestamptz NOT NULL DEFAULT now(),PRIMARY KEY(tenant_id,execution_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS one_active_occurrence ON provider_operations(tenant_id,resource_id) WHERE stop_intent AND NOT restored;
CREATE TABLE IF NOT EXISTS outbox (
 tenant_id text NOT NULL,id text NOT NULL,event_type text NOT NULL,payload jsonb NOT NULL,
 delivered_at timestamptz,attempts integer NOT NULL DEFAULT 0,next_attempt timestamptz NOT NULL DEFAULT now(),
 created_at timestamptz NOT NULL DEFAULT now(),PRIMARY KEY(tenant_id,id)
);
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['entities','audit_events','savings_ledger','idempotency','signed_plans','provider_operations','outbox'] LOOP
  EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',t);
  IF NOT EXISTS(SELECT FROM pg_policies WHERE tablename=t AND policyname='tenant_isolation') THEN
   EXECUTE format('CREATE POLICY tenant_isolation ON %I USING(tenant_id = current_setting(''app.tenant_id'',true)) WITH CHECK(tenant_id = current_setting(''app.tenant_id'',true))',t);
  END IF;
 END LOOP;
END $$;
CREATE OR REPLACE FUNCTION deny_evidence_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'append-only evidence'; END $$;
DO $$ DECLARE t text; BEGIN FOREACH t IN ARRAY ARRAY['audit_events','savings_ledger','signed_plans'] LOOP
 IF NOT EXISTS(SELECT FROM pg_trigger WHERE tgname=t||'_immutable') THEN
 EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION deny_evidence_mutation()',t||'_immutable',t);
 END IF; END LOOP; END $$;
GRANT USAGE ON SCHEMA public TO finops_api,finops_worker,finops_signer,finops_executor;
GRANT SELECT,INSERT,UPDATE ON entities TO finops_api,finops_worker;
GRANT DELETE ON entities TO finops_api;
GRANT SELECT ON entities TO finops_signer,finops_executor;
GRANT SELECT,INSERT ON audit_events TO finops_api,finops_worker,finops_signer,finops_executor;
GRANT SELECT,INSERT ON savings_ledger TO finops_api,finops_worker;
GRANT SELECT,INSERT,UPDATE ON idempotency TO finops_api;
GRANT SELECT ON signed_plans TO finops_api,finops_worker,finops_executor;
GRANT SELECT,INSERT ON signed_plans TO finops_signer;
GRANT SELECT,INSERT,UPDATE ON provider_operations TO finops_executor;
GRANT SELECT ON provider_operations TO finops_worker,finops_api,finops_signer;
GRANT SELECT,INSERT,UPDATE ON outbox TO finops_api,finops_worker;
