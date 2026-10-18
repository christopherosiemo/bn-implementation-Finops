-- Operator declarations are intentionally separate from machine observations.
-- Neither this table nor a blocked proposal authorizes any cloud/Git mutation.
CREATE TABLE configuration_authority_revisions (
 tenant_id text NOT NULL,id text NOT NULL,resource_id text NOT NULL,workload_id text NOT NULL,
 version bigint NOT NULL CHECK(version>0),resource_version bigint NOT NULL CHECK(resource_version>0),
 resource_snapshot_hash text NOT NULL CHECK(resource_snapshot_hash ~ '^[a-f0-9]{64}$'),
 resource_snapshot jsonb NOT NULL,content_hash text NOT NULL CHECK(content_hash ~ '^[a-f0-9]{64}$'),
 document jsonb NOT NULL CHECK(pg_column_size(document)<=65536),
 writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,id),UNIQUE(tenant_id,resource_id,version)
);
CREATE INDEX configuration_authority_resource_page ON configuration_authority_revisions(tenant_id,resource_id,id);
ALTER TABLE configuration_authority_revisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE configuration_authority_revisions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON configuration_authority_revisions USING(tenant_id=current_setting('app.tenant_id',true)) WITH CHECK(tenant_id=current_setting('app.tenant_id',true));
CREATE TRIGGER configuration_authority_immutable BEFORE UPDATE OR DELETE ON configuration_authority_revisions FOR EACH ROW EXECUTE FUNCTION deny_evidence_mutation();
GRANT SELECT,INSERT ON configuration_authority_revisions TO finops_api;

CREATE FUNCTION guard_configuration_authority() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE resource jsonb;rv bigint;v bigint;binding jsonb;address text;
BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id||':dependency-graph',0));
 SELECT document,version INTO resource,rv FROM entities WHERE tenant_id=NEW.tenant_id AND kind='resources' AND id=NEW.resource_id;
 SELECT coalesce(max(version),0)+1 INTO v FROM configuration_authority_revisions WHERE tenant_id=NEW.tenant_id AND resource_id=NEW.resource_id;
 IF resource IS NULL OR rv IS DISTINCT FROM NEW.resource_version OR NEW.resource_snapshot IS DISTINCT FROM (resource||jsonb_build_object('id',NEW.resource_id,'version',rv)) OR resource->>'workload_id' IS DISTINCT FROM NEW.workload_id OR NOT EXISTS(SELECT 1 FROM entities WHERE tenant_id=NEW.tenant_id AND kind='workloads' AND id=NEW.workload_id) THEN RAISE EXCEPTION 'configuration current resource binding invalid';END IF;
 binding:=jsonb_build_object('tenant_id',NEW.tenant_id,'resource_id',NEW.resource_id,'workload_id',NEW.workload_id,'provider',resource->>'provider','provider_resource_id',resource->>'provider_resource_id','account_id',resource->>'account_id','region',resource->>'region','resource_version',rv,'resource_snapshot_hash',NEW.resource_snapshot_hash);
 IF NEW.version<>v OR NEW.document->>'schema_version' IS DISTINCT FROM '1' OR NEW.document->>'authority' IS DISTINCT FROM 'TERRAFORM' OR NEW.document->>'id' IS DISTINCT FROM NEW.id OR NEW.document->'version' IS DISTINCT FROM to_jsonb(NEW.version) OR NEW.document->'binding' IS DISTINCT FROM binding THEN RAISE EXCEPTION 'configuration revision identity invalid';END IF;
 IF NEW.document-ARRAY['schema_version','authority','repository','pipeline','terraform','id','version','binding','status','reason_codes','execution_authorized','observed_commit','observed_state_serial','declared_by']<>'{}'::jsonb OR NEW.document->>'status' IS DISTINCT FROM 'DECLARED_NOT_ATTESTED' OR NEW.document->'execution_authorized' IS DISTINCT FROM 'false'::jsonb OR NEW.document->'observed_commit' IS DISTINCT FROM 'null'::jsonb OR NEW.document->'observed_state_serial' IS DISTINCT FROM 'null'::jsonb OR coalesce(NEW.document->>'declared_by','')='' THEN RAISE EXCEPTION 'operator declaration cannot attest or execute';END IF;
 IF jsonb_typeof(NEW.document->'reason_codes') IS DISTINCT FROM 'array' OR NOT(NEW.document->'reason_codes' @> '["PIPELINE_ATTESTATION_REQUIRED","CONFIGURATION_STATE_UNOBSERVED"]'::jsonb) THEN RAISE EXCEPTION 'configuration attestation blockers required';END IF;
 IF coalesce(resource->>'provider','') NOT IN ('AWS','AZURE','GCP') OR coalesce(resource->>'account_id','')='' OR coalesce(resource->>'region','')='' OR coalesce(resource->>'provider_resource_id','')='' THEN RAISE EXCEPTION 'configuration provider identity required';END IF;
 IF (resource->>'provider'<>'AWS' OR resource->>'region'<>'eu-west-1') AND NOT(NEW.document->'reason_codes' @> '["PROVIDER_ACTION_NOT_ENABLED"]'::jsonb) THEN RAISE EXCEPTION 'configuration provider execution disabled';END IF;
 IF jsonb_typeof(NEW.document->'repository') IS DISTINCT FROM 'object' OR (NEW.document->'repository')-ARRAY['url','ref','directory']<>'{}'::jsonb OR coalesce(NEW.document->'repository'->>'url','')!~'^https://[^/@?#[:space:]]+(/[^?#[:space:]]*)?$' OR coalesce(NEW.document->'repository'->>'ref','')='' OR coalesce(NEW.document->'repository'->>'directory','')='' THEN RAISE EXCEPTION 'configuration repository metadata invalid';END IF;
 IF jsonb_typeof(NEW.document->'pipeline') IS DISTINCT FROM 'object' OR (NEW.document->'pipeline')-ARRAY['system','identity']<>'{}'::jsonb OR coalesce(NEW.document->'pipeline'->>'system','') NOT IN ('GITHUB_ACTIONS','GITLAB_CI','BITBUCKET_PIPELINES','OTHER') OR jsonb_typeof(NEW.document->'pipeline'->'identity') IS DISTINCT FROM 'object' OR (NEW.document->'pipeline'->'identity')-ARRAY['issuer','audience','subject','pipeline_id']<>'{}'::jsonb OR coalesce(NEW.document->'pipeline'->'identity'->>'issuer','')!~'^https://[^/@?#[:space:]]+(/[^?#[:space:]]*)?$' OR NEW.document->'pipeline'->'identity'->>'audience' IS DISTINCT FROM 'finops-deployment-observer' OR coalesce(NEW.document->'pipeline'->'identity'->>'subject','')='' OR coalesce(NEW.document->'pipeline'->'identity'->>'pipeline_id','')='' THEN RAISE EXCEPTION 'configuration dedicated pipeline identity required';END IF;
 IF jsonb_typeof(NEW.document->'terraform') IS DISTINCT FROM 'object' OR (NEW.document->'terraform')-ARRAY['workspace','state_lineage','addresses']<>'{}'::jsonb OR coalesce(NEW.document->'terraform'->>'workspace','')!~'^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$' OR coalesce(NEW.document->'terraform'->>'state_lineage','')!~'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' OR jsonb_typeof(NEW.document->'terraform'->'addresses') IS DISTINCT FROM 'array' OR jsonb_array_length(NEW.document->'terraform'->'addresses') NOT BETWEEN 1 AND 32 OR (SELECT count(DISTINCT a) FROM jsonb_array_elements_text(NEW.document->'terraform'->'addresses') a)<>jsonb_array_length(NEW.document->'terraform'->'addresses') THEN RAISE EXCEPTION 'configuration declared Terraform state invalid';END IF;
 FOR address IN SELECT jsonb_array_elements_text(NEW.document->'terraform'->'addresses') LOOP
  IF length(address)>512 OR address!~'^(module\.[A-Za-z_][A-Za-z0-9_-]*(\[(0|[1-9][0-9]*)\]|\["[A-Za-z0-9_-]+"\])?\.)*(aws|azurerm|google)_[a-z0-9_]+\.[A-Za-z_][A-Za-z0-9_-]*(\[(0|[1-9][0-9]*)\]|\["[A-Za-z0-9_-]+"\])?$' OR (resource->>'provider'='AWS' AND address!~'(^|\.)aws_[^.]+\.') OR (resource->>'provider'='AZURE' AND address!~'(^|\.)azurerm_[^.]+\.') OR (resource->>'provider'='GCP' AND address!~'(^|\.)google_[^.]+\.') THEN RAISE EXCEPTION 'configuration managed address invalid';END IF;
 END LOOP;
 NEW.writer_role:='finops_api';NEW.created_at:=clock_timestamp();
 NEW.document:=NEW.document||jsonb_build_object('tenant_id',NEW.tenant_id,'hash',NEW.content_hash,'created_at',NEW.created_at,'writer_role',NEW.writer_role);
 RETURN NEW;
END $$;
CREATE TRIGGER configuration_authority_writer BEFORE INSERT ON configuration_authority_revisions FOR EACH ROW EXECUTE FUNCTION guard_configuration_authority();

CREATE TABLE configuration_proposals (
 tenant_id text NOT NULL,id text NOT NULL,workload_id text NOT NULL,resource_id text NOT NULL,
 authority_id text NOT NULL,capacity_assessment_id text NOT NULL,
 content_hash text NOT NULL CHECK(content_hash ~ '^[a-f0-9]{64}$'),document jsonb NOT NULL CHECK(pg_column_size(document)<=65536),
 writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,id),
 FOREIGN KEY(tenant_id,authority_id) REFERENCES configuration_authority_revisions(tenant_id,id),
 FOREIGN KEY(tenant_id,capacity_assessment_id) REFERENCES capacity_assessments(tenant_id,id)
);
CREATE INDEX configuration_proposal_workload_page ON configuration_proposals(tenant_id,workload_id,id);
ALTER TABLE configuration_proposals ENABLE ROW LEVEL SECURITY;
ALTER TABLE configuration_proposals FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON configuration_proposals USING(tenant_id=current_setting('app.tenant_id',true)) WITH CHECK(tenant_id=current_setting('app.tenant_id',true));
CREATE TRIGGER configuration_proposal_immutable BEFORE UPDATE OR DELETE ON configuration_proposals FOR EACH ROW EXECUTE FUNCTION deny_evidence_mutation();
GRANT SELECT,INSERT ON configuration_proposals TO finops_api;

CREATE FUNCTION guard_configuration_proposal() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE authority configuration_authority_revisions;assessment jsonb;profile jsonb;resource jsonb;rv bigint;cfg jsonb;
BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id||':dependency-graph',0));
 SELECT * INTO authority FROM configuration_authority_revisions WHERE tenant_id=NEW.tenant_id AND resource_id=NEW.resource_id ORDER BY version DESC LIMIT 1;
 SELECT document,version INTO resource,rv FROM entities WHERE tenant_id=NEW.tenant_id AND kind='resources' AND id=NEW.resource_id;
 SELECT document INTO assessment FROM capacity_assessments WHERE tenant_id=NEW.tenant_id AND id=NEW.capacity_assessment_id AND workload_id=NEW.workload_id AND resource_id=NEW.resource_id;
 SELECT document INTO profile FROM workload_safety_profiles WHERE tenant_id=NEW.tenant_id AND workload_id=NEW.workload_id ORDER BY version DESC LIMIT 1;
 IF authority.id IS NULL OR authority.id IS DISTINCT FROM NEW.authority_id OR authority.workload_id IS DISTINCT FROM NEW.workload_id OR resource IS NULL OR rv IS DISTINCT FROM authority.resource_version OR authority.resource_snapshot IS DISTINCT FROM(resource||jsonb_build_object('id',NEW.resource_id,'version',rv)) OR assessment IS NULL OR profile IS NULL THEN RAISE EXCEPTION 'configuration proposal current binding invalid';END IF;
 cfg:=telemetry_active_config(NEW.tenant_id,assessment->>'connection_id',assessment->>'revision_id');
 IF cfg->'binding' IS DISTINCT FROM ((authority.document->'binding')-ARRAY['resource_version','resource_snapshot_hash']) OR assessment->>'safety_profile_id' IS DISTINCT FROM profile->>'id' OR assessment->'safety_profile_version' IS DISTINCT FROM profile->'version' OR assessment->>'safety_profile_hash' IS DISTINCT FROM profile->>'hash' OR assessment->>'status' IS DISTINCT FROM 'BLOCKED' OR assessment->'execution_authorized' IS DISTINCT FROM 'false'::jsonb THEN RAISE EXCEPTION 'configuration proposal evidence superseded';END IF;
 IF NEW.document-ARRAY['schema_version','binding','workload_id','resource_id','authority_id','authority_version','authority_hash','capacity_assessment_id','capacity_assessment_hash','population_hash','connection_id','connection_version','revision_id','config_hash','safety_profile_id','safety_profile_version','safety_profile_hash','status','reason_codes','execution_authorized','estimated_saving','verified_saving','change_plan_id','proposed_by']<>'{}'::jsonb OR NEW.document->>'schema_version' IS DISTINCT FROM '1' OR NEW.document->>'status' IS DISTINCT FROM 'BLOCKED' OR NEW.document->'execution_authorized' IS DISTINCT FROM 'false'::jsonb OR NEW.document->'estimated_saving' IS DISTINCT FROM 'null'::jsonb OR NEW.document->'verified_saving' IS DISTINCT FROM 'null'::jsonb OR NEW.document->'change_plan_id' IS DISTINCT FROM 'null'::jsonb OR coalesce(NEW.document->>'proposed_by','')='' THEN RAISE EXCEPTION 'configuration proposal cannot execute or claim savings';END IF;
 IF NEW.document->'binding' IS DISTINCT FROM authority.document->'binding' OR NEW.document->>'workload_id' IS DISTINCT FROM NEW.workload_id OR NEW.document->>'resource_id' IS DISTINCT FROM NEW.resource_id OR NEW.document->>'authority_id' IS DISTINCT FROM NEW.authority_id OR NEW.document->'authority_version' IS DISTINCT FROM to_jsonb(authority.version) OR NEW.document->>'authority_hash' IS DISTINCT FROM authority.content_hash OR NEW.document->>'capacity_assessment_id' IS DISTINCT FROM NEW.capacity_assessment_id OR NEW.document->>'capacity_assessment_hash' IS DISTINCT FROM assessment->>'hash' OR NEW.document->>'population_hash' IS DISTINCT FROM assessment->>'population_hash' THEN RAISE EXCEPTION 'configuration proposal evidence selection invalid';END IF;
 IF NEW.document->>'connection_id' IS DISTINCT FROM assessment->>'connection_id' OR NEW.document->'connection_version' IS DISTINCT FROM assessment->'connection_version' OR NEW.document->>'revision_id' IS DISTINCT FROM assessment->>'revision_id' OR NEW.document->>'config_hash' IS DISTINCT FROM assessment->>'config_hash' OR NEW.document->>'safety_profile_id' IS DISTINCT FROM profile->>'id' OR NEW.document->'safety_profile_version' IS DISTINCT FROM profile->'version' OR NEW.document->>'safety_profile_hash' IS DISTINCT FROM profile->>'hash' THEN RAISE EXCEPTION 'configuration proposal current references invalid';END IF;
 IF jsonb_typeof(NEW.document->'reason_codes') IS DISTINCT FROM 'array' OR NOT(NEW.document->'reason_codes' @> '["DECLARED_NOT_ATTESTED","CONFIGURATION_STATE_UNOBSERVED","NATIVE_CAPACITY_NOT_VALIDATED","NATIVE_PRICE_UNAVAILABLE"]'::jsonb) THEN RAISE EXCEPTION 'configuration proposal blockers required';END IF;
 NEW.writer_role:='finops_api';NEW.created_at:=clock_timestamp();
 NEW.document:=NEW.document||jsonb_build_object('id',NEW.id,'tenant_id',NEW.tenant_id,'hash',NEW.content_hash,'created_at',NEW.created_at,'writer_role',NEW.writer_role);
 RETURN NEW;
END $$;
CREATE TRIGGER configuration_proposal_writer BEFORE INSERT ON configuration_proposals FOR EACH ROW EXECUTE FUNCTION guard_configuration_proposal();
