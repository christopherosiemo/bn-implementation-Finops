-- Immutable, analytical AWS service observations. No action or mutation authority.
CREATE TABLE aws_service_evidence_snapshots(
 tenant_id text NOT NULL,id text NOT NULL,resource_id text NOT NULL,source_id text NOT NULL,
 registration_version bigint NOT NULL CHECK(registration_version>0),generation_id text NOT NULL,
 family text NOT NULL CHECK(family IN('ECS','EKS','ELASTICACHE','DYNAMODB','ELB')),
 account_id text NOT NULL CHECK(account_id~'^[0-9]{12}$'),region text NOT NULL,
 config_hash text NOT NULL CHECK(config_hash~'^[a-f0-9]{64}$'),content_hash text NOT NULL CHECK(content_hash~'^[a-f0-9]{64}$'),
 document jsonb NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),writer_role name NOT NULL DEFAULT current_user,
 PRIMARY KEY(tenant_id,id),FOREIGN KEY(tenant_id,source_id) REFERENCES source_registrations(tenant_id,id),
 UNIQUE(tenant_id,source_id,registration_version,generation_id,resource_id,content_hash),CHECK(octet_length(document::text)<=262144)
);
CREATE INDEX aws_service_evidence_resource ON aws_service_evidence_snapshots(tenant_id,resource_id,created_at DESC,id DESC);
ALTER TABLE aws_service_evidence_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE aws_service_evidence_snapshots FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON aws_service_evidence_snapshots USING(tenant_id=current_setting('app.tenant_id',true)) WITH CHECK(tenant_id=current_setting('app.tenant_id',true));
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE ON aws_service_evidence_snapshots FOR EACH ROW EXECUTE FUNCTION deny_evidence_mutation();
GRANT SELECT ON aws_service_evidence_snapshots TO finops_api,finops_ingester;
GRANT INSERT ON aws_service_evidence_snapshots TO finops_ingester;
CREATE FUNCTION guard_aws_service_evidence() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname=current_user) AND current_user<>'finops_ingester' THEN RAISE EXCEPTION 'AWS service evidence requires ingestion identity'; END IF;
 IF NEW.tenant_id IS DISTINCT FROM current_setting('app.tenant_id',true)
 OR NEW.document->>'schema_version' IS DISTINCT FROM '1' OR NEW.document->>'kind' IS DISTINCT FROM 'AWS_SERVICE_NATIVE_SNAPSHOT_V1'
 OR NEW.document->>'resource_id' IS DISTINCT FROM NEW.resource_id OR NEW.document->>'source_id' IS DISTINCT FROM NEW.source_id
 OR (NEW.document->>'registration_version')::bigint IS DISTINCT FROM NEW.registration_version
 OR NEW.document->>'generation_id' IS DISTINCT FROM NEW.generation_id OR NEW.document->>'family' IS DISTINCT FROM NEW.family
 OR NEW.document->>'account_id' IS DISTINCT FROM NEW.account_id OR NEW.document->>'region' IS DISTINCT FROM NEW.region
 OR NEW.document->>'config_hash' IS DISTINCT FROM NEW.config_hash OR NEW.document->>'content_hash' IS DISTINCT FROM NEW.content_hash
 OR coalesce(NEW.document->'archive'->>'version_id','') IN('','null') OR coalesce(NEW.document->'archive'->>'bucket','')=''
 OR NOT starts_with(coalesce(NEW.document->'archive'->>'key',''),'tenant/'||NEW.tenant_id||'/native/') OR NEW.document->'archive'->>'body_sha256' IS DISTINCT FROM NEW.content_hash
 OR NEW.document->'execution_authorized' IS DISTINCT FROM 'false'::jsonb OR NEW.document->'verified_saving' IS DISTINCT FROM 'null'::jsonb
 OR NOT EXISTS(SELECT FROM source_registrations s WHERE s.tenant_id=NEW.tenant_id AND s.id=NEW.source_id AND s.version=NEW.registration_version AND s.kind='AWS_SERVICE_NATIVE_V1' AND s.document->'enabled'='true'::jsonb AND s.document->'revoked' IS DISTINCT FROM 'true'::jsonb AND s.document->>'account_id'=NEW.account_id AND s.document->>'region'=NEW.region AND s.document->'service_families' ? NEW.family)
 OR NOT EXISTS(SELECT FROM entities r WHERE r.tenant_id=NEW.tenant_id AND r.kind='resources' AND r.id=NEW.resource_id AND r.document->>'provider'='AWS' AND r.document->>'service_family'=NEW.family AND r.document->>'account_id'=NEW.account_id AND r.document->>'region'=NEW.region AND jsonb_typeof(r.document->'aws_service_configuration')='object')
 THEN RAISE EXCEPTION 'AWS service native evidence binding invalid'; END IF;
 NEW.writer_role:=current_user;NEW.created_at:=clock_timestamp();RETURN NEW;
END $$;
CREATE TRIGGER aws_service_evidence_writer BEFORE INSERT ON aws_service_evidence_snapshots FOR EACH ROW EXECUTE FUNCTION guard_aws_service_evidence();
