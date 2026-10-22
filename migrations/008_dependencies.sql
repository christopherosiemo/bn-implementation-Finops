CREATE TABLE dependency_graph_revisions (
 tenant_id text NOT NULL,id text NOT NULL,version bigint NOT NULL CHECK(version>0),
 content_hash text NOT NULL CHECK(content_hash ~ '^[a-f0-9]{64}$'),document jsonb NOT NULL,
 writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,id),UNIQUE(tenant_id,version)
);
CREATE TABLE dependency_reviews (
 tenant_id text NOT NULL,id text NOT NULL,resource_id text NOT NULL,graph_version bigint NOT NULL,
 graph_hash text NOT NULL CHECK(graph_hash ~ '^[a-f0-9]{64}$'),inventory_hash text NOT NULL CHECK(inventory_hash ~ '^[a-f0-9]{64}$'),
 reviewed_by text NOT NULL CHECK(length(reviewed_by)>0),expires_at timestamptz NOT NULL,document jsonb NOT NULL,
 writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,id),FOREIGN KEY(tenant_id,graph_version) REFERENCES dependency_graph_revisions(tenant_id,version),
 CHECK(expires_at>created_at AND expires_at<=created_at+interval '24 hours')
);
CREATE INDEX dependency_reviews_resource ON dependency_reviews(tenant_id,resource_id,created_at DESC,id DESC);
ALTER TABLE dependency_graph_revisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE dependency_graph_revisions FORCE ROW LEVEL SECURITY;
ALTER TABLE dependency_reviews ENABLE ROW LEVEL SECURITY;
ALTER TABLE dependency_reviews FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON dependency_graph_revisions USING(tenant_id=current_setting('app.tenant_id',true)) WITH CHECK(tenant_id=current_setting('app.tenant_id',true));
CREATE POLICY tenant_isolation ON dependency_reviews USING(tenant_id=current_setting('app.tenant_id',true)) WITH CHECK(tenant_id=current_setting('app.tenant_id',true));
CREATE TRIGGER dependency_graph_immutable BEFORE UPDATE OR DELETE ON dependency_graph_revisions FOR EACH ROW EXECUTE FUNCTION deny_evidence_mutation();
CREATE TRIGGER dependency_review_immutable BEFORE UPDATE OR DELETE ON dependency_reviews FOR EACH ROW EXECUTE FUNCTION deny_evidence_mutation();
CREATE FUNCTION dependency_api_writer() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname=current_user) AND NOT pg_has_role(current_user,'finops_api','MEMBER') THEN RAISE EXCEPTION 'dependency declarations and owner reviews require API identity'; END IF;
 NEW.writer_role:=CASE WHEN pg_has_role(current_user,'finops_api','MEMBER') THEN 'finops_api' ELSE 'migration_admin' END;
 NEW.created_at:=clock_timestamp();
 NEW.document:=NEW.document||jsonb_build_object('tenant_id',NEW.tenant_id,'id',NEW.id,'created_at',NEW.created_at,'writer_role',NEW.writer_role);
 IF TG_TABLE_NAME='dependency_graph_revisions' THEN
  NEW.document:=NEW.document||jsonb_build_object('version',NEW.version,'content_hash',NEW.content_hash,'hash',NEW.content_hash);
 ELSE
  NEW.document:=NEW.document||jsonb_build_object('resource_id',NEW.resource_id,'graph_version',NEW.graph_version,'graph_hash',NEW.graph_hash,'inventory_hash',NEW.inventory_hash,'reviewed_by',NEW.reviewed_by,'expires_at',NEW.expires_at);
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER dependency_graph_writer BEFORE INSERT ON dependency_graph_revisions FOR EACH ROW EXECUTE FUNCTION dependency_api_writer();
CREATE TRIGGER dependency_review_writer BEFORE INSERT ON dependency_reviews FOR EACH ROW EXECUTE FUNCTION dependency_api_writer();
GRANT SELECT ON dependency_graph_revisions,dependency_reviews TO finops_api,finops_worker,finops_signer,finops_executor,finops_ingester;
GRANT INSERT ON dependency_graph_revisions,dependency_reviews TO finops_api;
