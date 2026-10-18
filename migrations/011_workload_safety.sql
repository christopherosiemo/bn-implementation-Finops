CREATE TABLE workload_safety_profiles (
 tenant_id text NOT NULL,
 id text NOT NULL,
 workload_id text NOT NULL,
 version bigint NOT NULL CHECK(version>0),
 content_hash text NOT NULL CHECK(content_hash ~ '^[a-f0-9]{64}$'),
 document jsonb NOT NULL,
 writer_role text NOT NULL DEFAULT current_user,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,id),UNIQUE(tenant_id,workload_id,version)
);
ALTER TABLE workload_safety_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE workload_safety_profiles FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON workload_safety_profiles USING(tenant_id=current_setting('app.tenant_id',true)) WITH CHECK(tenant_id=current_setting('app.tenant_id',true));
CREATE TRIGGER workload_safety_immutable BEFORE UPDATE OR DELETE ON workload_safety_profiles FOR EACH ROW EXECUTE FUNCTION deny_evidence_mutation();
GRANT SELECT ON workload_safety_profiles TO finops_api,finops_worker,finops_ingester,finops_signer,finops_executor,finops_telemetry_reader,finops_telemetry_ingress;
GRANT INSERT ON workload_safety_profiles TO finops_api;
CREATE FUNCTION guard_workload_safety_profile() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM entities WHERE tenant_id=NEW.tenant_id AND kind='workloads' AND id=NEW.workload_id) THEN RAISE EXCEPTION 'workload safety requires existing workload';END IF;
 IF NEW.document->>'schema_version' IS DISTINCT FROM '1' OR NEW.document->>'id' IS DISTINCT FROM NEW.id OR NEW.document->>'workload_id' IS DISTINCT FROM NEW.workload_id OR (NEW.document->>'version')::bigint IS DISTINCT FROM NEW.version THEN RAISE EXCEPTION 'workload safety binding mismatch';END IF;
 IF NEW.document->>'criticality' NOT IN ('TIER_0','TIER_1','TIER_2','TIER_3','NON_PRODUCTION') OR NEW.document->>'statefulness' NOT IN ('STATELESS','STATEFUL','UNKNOWN') THEN RAISE EXCEPTION 'workload safety classification invalid';END IF;
 NEW.writer_role:='finops_api';NEW.created_at:=clock_timestamp();
 NEW.document:=NEW.document||jsonb_build_object('tenant_id',NEW.tenant_id,'hash',NEW.content_hash,'created_at',NEW.created_at,'writer_role',NEW.writer_role);
 RETURN NEW;
END $$;
CREATE TRIGGER workload_safety_writer BEFORE INSERT ON workload_safety_profiles FOR EACH ROW EXECUTE FUNCTION guard_workload_safety_profile();
