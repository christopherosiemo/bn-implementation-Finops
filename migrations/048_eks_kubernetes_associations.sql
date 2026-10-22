-- Point-in-time identity relationships only; no capacity cost or execution authority.
CREATE TABLE eks_kubernetes_associations(
 tenant_id text NOT NULL,id text NOT NULL,resource_id text NOT NULL,source_id text NOT NULL,
 source_version bigint NOT NULL CHECK(source_version>0),native_source_id text NOT NULL,
 native_source_version bigint NOT NULL CHECK(native_source_version>0),config_hash text NOT NULL,
 content_hash text NOT NULL CHECK(content_hash~'^[a-f0-9]{64}$'),document jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),writer_role name NOT NULL DEFAULT current_user,
 PRIMARY KEY(tenant_id,id),FOREIGN KEY(tenant_id,source_id) REFERENCES source_registrations(tenant_id,id),
 FOREIGN KEY(tenant_id,native_source_id) REFERENCES source_registrations(tenant_id,id),
 UNIQUE(tenant_id,source_id,source_version,resource_id,content_hash),CHECK(octet_length(document::text)<=262144)
);
CREATE INDEX eks_associations_resource ON eks_kubernetes_associations(tenant_id,resource_id,created_at DESC,id DESC);
ALTER TABLE eks_kubernetes_associations ENABLE ROW LEVEL SECURITY;
ALTER TABLE eks_kubernetes_associations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON eks_kubernetes_associations USING(tenant_id=current_setting('app.tenant_id',true)) WITH CHECK(tenant_id=current_setting('app.tenant_id',true));
CREATE TRIGGER immutable BEFORE UPDATE OR DELETE ON eks_kubernetes_associations FOR EACH ROW EXECUTE FUNCTION deny_evidence_mutation();
GRANT SELECT ON eks_kubernetes_associations TO finops_api,finops_ingester;
GRANT INSERT ON eks_kubernetes_associations TO finops_ingester;
CREATE FUNCTION guard_eks_association() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname=current_user) AND current_user<>'finops_ingester' THEN RAISE EXCEPTION 'EKS association requires ingestion identity'; END IF;
 IF NEW.tenant_id IS DISTINCT FROM current_setting('app.tenant_id',true)
 OR NEW.document->>'resource_id' IS DISTINCT FROM NEW.resource_id OR NEW.document->>'source_id' IS DISTINCT FROM NEW.source_id
 OR (NEW.document->>'source_version')::bigint IS DISTINCT FROM NEW.source_version
 OR NEW.document->>'native_source_id' IS DISTINCT FROM NEW.native_source_id OR (NEW.document->>'native_source_version')::bigint IS DISTINCT FROM NEW.native_source_version
 OR NEW.document->>'config_hash' IS DISTINCT FROM NEW.config_hash OR NEW.document->>'content_hash' IS DISTINCT FROM NEW.content_hash
 OR NEW.document->'execution_authorized' IS DISTINCT FROM 'false'::jsonb OR NEW.document->'verified_saving' IS DISTINCT FROM 'null'::jsonb
 OR NEW.document->>'cost_attribution' IS DISTINCT FROM 'RELATIONSHIP_ONLY_NO_ADDITIONAL_COST'
 OR coalesce(NEW.document->'archive'->>'version_id','') IN('','null') OR NOT starts_with(coalesce(NEW.document->'archive'->>'key',''),'tenant/'||NEW.tenant_id||'/native/')
 OR NEW.document->'archive'->>'body_sha256' IS DISTINCT FROM NEW.content_hash
 OR NOT EXISTS(SELECT FROM source_registrations s WHERE s.tenant_id=NEW.tenant_id AND s.id=NEW.source_id AND s.version=NEW.source_version AND s.kind='AWS_EKS_KUBERNETES_V1' AND s.document->'enabled'='true'::jsonb AND s.document->'revoked' IS DISTINCT FROM 'true'::jsonb)
 OR NOT EXISTS(SELECT FROM source_registrations s WHERE s.tenant_id=NEW.tenant_id AND s.id=NEW.native_source_id AND s.version=NEW.native_source_version AND s.kind='AWS_SERVICE_NATIVE_V1' AND s.document->'enabled'='true'::jsonb AND s.document->'revoked' IS DISTINCT FROM 'true'::jsonb AND s.document->'service_families' ? 'EKS')
 OR NOT EXISTS(SELECT FROM entities r JOIN source_registrations s ON s.tenant_id=r.tenant_id AND s.id=NEW.source_id JOIN source_registrations n ON n.tenant_id=r.tenant_id AND n.id=NEW.native_source_id WHERE r.tenant_id=NEW.tenant_id AND r.id=NEW.resource_id AND r.kind='resources' AND r.document->>'provider'='AWS' AND r.document->>'resource_type'='EKS_CLUSTER' AND r.document->>'account_id'=s.document->>'account_id' AND r.document->>'region'=s.document->>'region' AND r.document->>'provider_resource_id'=s.document->>'cluster_arn' AND r.document->>'account_id'=n.document->>'account_id' AND r.document->>'region'=n.document->>'region' AND s.document->>'read_role_binding_id'=n.document->>'read_role_binding_id')
 THEN RAISE EXCEPTION 'EKS association binding invalid'; END IF;
 NEW.writer_role:=current_user;NEW.created_at:=clock_timestamp();RETURN NEW;
END $$;
CREATE TRIGGER eks_association_writer BEFORE INSERT ON eks_kubernetes_associations FOR EACH ROW EXECUTE FUNCTION guard_eks_association();
