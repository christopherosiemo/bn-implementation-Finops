-- Capacity assessments are analytical evidence. This increment deliberately
-- permits BLOCKED records only: native provider hardware and contracted prices
-- are not yet registered, and no assessment grants mutation authority.
CREATE TABLE capacity_assessments (
 tenant_id text NOT NULL,
 id text NOT NULL,
 workload_id text NOT NULL,
 resource_id text NOT NULL,
 connection_id text NOT NULL,
 revision_id text NOT NULL,
 safety_profile_id text NOT NULL,
 content_hash text NOT NULL CHECK(content_hash ~ '^[a-f0-9]{64}$'),
 document jsonb NOT NULL CHECK(pg_column_size(document)<=1048576),
 writer_role text NOT NULL DEFAULT current_user,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,id),
 FOREIGN KEY(tenant_id,revision_id) REFERENCES telemetry_source_revisions(tenant_id,id),
 FOREIGN KEY(tenant_id,safety_profile_id) REFERENCES workload_safety_profiles(tenant_id,id)
);
CREATE INDEX capacity_assessment_workload ON capacity_assessments(tenant_id,workload_id,id);
ALTER TABLE capacity_assessments ENABLE ROW LEVEL SECURITY;
ALTER TABLE capacity_assessments FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON capacity_assessments USING(tenant_id=current_setting('app.tenant_id',true)) WITH CHECK(tenant_id=current_setting('app.tenant_id',true));
CREATE TRIGGER capacity_assessment_immutable BEFORE UPDATE OR DELETE ON capacity_assessments FOR EACH ROW EXECUTE FUNCTION deny_evidence_mutation();
GRANT SELECT ON capacity_assessments TO finops_api,finops_worker,finops_signer,finops_executor;
GRANT INSERT ON capacity_assessments TO finops_api;
CREATE FUNCTION guard_capacity_assessment() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE cfg jsonb;p jsonb;rid text;r jsonb;
BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id||':dependency-graph',0));
 cfg:=telemetry_active_config(NEW.tenant_id,NEW.connection_id,NEW.revision_id);
 SELECT document INTO p FROM workload_safety_profiles WHERE tenant_id=NEW.tenant_id AND workload_id=NEW.workload_id ORDER BY version DESC LIMIT 1;
 IF p IS NULL OR p->>'id' IS DISTINCT FROM NEW.safety_profile_id OR cfg->'binding'->>'workload_id' IS DISTINCT FROM NEW.workload_id OR cfg->'binding'->>'resource_id' IS DISTINCT FROM NEW.resource_id THEN RAISE EXCEPTION 'capacity assessment binding invalid';END IF;
 IF NEW.document->>'schema_version' IS DISTINCT FROM '1' OR NEW.document->>'status' IS DISTINCT FROM 'BLOCKED' OR NEW.document->'execution_authorized' IS DISTINCT FROM 'false'::jsonb OR NEW.document->'estimated_saving' IS DISTINCT FROM 'null'::jsonb OR NEW.document->'verified_saving' IS DISTINCT FROM 'null'::jsonb THEN RAISE EXCEPTION 'capacity assessment cannot grant authority or savings';END IF;
 IF NEW.document->>'workload_id' IS DISTINCT FROM NEW.workload_id OR NEW.document->>'resource_id' IS DISTINCT FROM NEW.resource_id OR NEW.document->>'connection_id' IS DISTINCT FROM NEW.connection_id OR NEW.document->>'revision_id' IS DISTINCT FROM NEW.revision_id OR NEW.document->>'config_hash' IS DISTINCT FROM (SELECT config_hash FROM telemetry_source_revisions WHERE tenant_id=NEW.tenant_id AND id=NEW.revision_id) OR NEW.document->>'safety_profile_id' IS DISTINCT FROM NEW.safety_profile_id OR NEW.document->'safety_profile_version' IS DISTINCT FROM p->'version' OR NEW.document->>'safety_profile_hash' IS DISTINCT FROM p->>'hash' OR coalesce(NEW.document->>'population_hash','')!~'^[a-f0-9]{64}$' THEN RAISE EXCEPTION 'capacity assessment evidence selection changed';END IF;
 IF jsonb_typeof(NEW.document->'reason_codes') IS DISTINCT FROM 'array' OR jsonb_array_length(NEW.document->'reason_codes')<1 OR jsonb_typeof(NEW.document->'receipt_ids') IS DISTINCT FROM 'array' OR jsonb_array_length(NEW.document->'receipt_ids')>2048 OR jsonb_path_exists(NEW.document,'$.**.points') OR jsonb_path_exists(NEW.document,'$.**.segments') OR jsonb_path_exists(NEW.document,'$.**.samples') THEN RAISE EXCEPTION 'capacity assessment requires bounded metadata, not native points';END IF;
 FOR rid IN SELECT jsonb_array_elements_text(NEW.document->'receipt_ids') LOOP
  SELECT document INTO r FROM telemetry_receipts WHERE tenant_id=NEW.tenant_id AND id=rid AND connection_id=NEW.connection_id AND revision_id=NEW.revision_id;
  IF r IS NULL OR r->'binding' IS DISTINCT FROM cfg->'binding' THEN RAISE EXCEPTION 'capacity receipt mismatch';END IF;
 END LOOP;
 NEW.writer_role:='finops_api';NEW.created_at:=clock_timestamp();
 NEW.document:=NEW.document||jsonb_build_object('id',NEW.id,'tenant_id',NEW.tenant_id,'hash',NEW.content_hash,'writer_role',NEW.writer_role,'created_at',NEW.created_at);
 RETURN NEW;
END $$;
CREATE TRIGGER capacity_assessment_writer BEFORE INSERT ON capacity_assessments FOR EACH ROW EXECUTE FUNCTION guard_capacity_assessment();
