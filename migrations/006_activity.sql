DO $$ BEGIN
 IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='finops_activity') THEN CREATE ROLE finops_activity NOLOGIN; END IF;
END $$;
GRANT USAGE ON SCHEMA public TO finops_activity;
-- Production receive time has no caller-controlled override. Disposable tests
-- may replace this function only as the database owner; runtime roles cannot.
CREATE FUNCTION activity_receive_time() RETURNS timestamptz LANGUAGE sql VOLATILE AS $$ SELECT clock_timestamp() $$;
CREATE TABLE activity_sources (
 tenant_id text NOT NULL,id text NOT NULL,resource_id text NOT NULL,workload_id text NOT NULL,
 issuer text NOT NULL,subject text NOT NULL,document jsonb NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,id),UNIQUE(tenant_id,resource_id),UNIQUE(tenant_id,issuer,subject,resource_id)
);
CREATE TABLE activity_receipts (
 tenant_id text NOT NULL,id text NOT NULL,source_id text NOT NULL,resource_id text NOT NULL,
 sequence bigint NOT NULL CHECK(sequence>0),interval_start timestamptz NOT NULL,interval_end timestamptz NOT NULL,
 received_at timestamptz NOT NULL DEFAULT activity_receive_time(),body_sha256 text NOT NULL CHECK(length(body_sha256)=64),
 idempotency_key text NOT NULL,document jsonb NOT NULL,raw_body bytea NOT NULL,
 PRIMARY KEY(tenant_id,id),FOREIGN KEY(tenant_id,source_id) REFERENCES activity_sources(tenant_id,id),
 UNIQUE(tenant_id,source_id,sequence),UNIQUE(tenant_id,source_id,interval_start),UNIQUE(tenant_id,source_id,idempotency_key),
 CHECK(interval_end-interval_start=interval '1 minute')
);
CREATE INDEX activity_resource_time ON activity_receipts(tenant_id,resource_id,interval_end DESC);
ALTER TABLE activity_sources ENABLE ROW LEVEL SECURITY;
ALTER TABLE activity_sources FORCE ROW LEVEL SECURITY;
ALTER TABLE activity_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE activity_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON activity_sources USING(tenant_id=current_setting('app.tenant_id',true)) WITH CHECK(tenant_id=current_setting('app.tenant_id',true));
CREATE POLICY tenant_isolation ON activity_receipts USING(tenant_id=current_setting('app.tenant_id',true)) WITH CHECK(tenant_id=current_setting('app.tenant_id',true));
CREATE TRIGGER activity_sources_immutable BEFORE UPDATE OR DELETE ON activity_sources FOR EACH ROW EXECUTE FUNCTION deny_evidence_mutation();
CREATE TRIGGER activity_receipts_immutable BEFORE UPDATE OR DELETE ON activity_receipts FOR EACH ROW EXECUTE FUNCTION deny_evidence_mutation();
GRANT SELECT ON activity_sources,activity_receipts TO finops_api,finops_worker,finops_signer,finops_executor,finops_ingester,finops_activity;
GRANT INSERT ON activity_sources TO finops_api;
GRANT INSERT ON activity_receipts TO finops_activity;
CREATE FUNCTION guard_activity_receipt() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE source jsonb;BEGIN
 SELECT document INTO source FROM activity_sources WHERE tenant_id=NEW.tenant_id AND id=NEW.source_id;
 IF source IS NULL OR source->>'resource_id' IS DISTINCT FROM NEW.resource_id OR source->>'subject' IS DISTINCT FROM NEW.document->>'subject' OR source->'metric_definition' IS DISTINCT FROM NEW.document->'metric_definition' OR source->>'workload_id' IS DISTINCT FROM NEW.document->>'workload_id' OR source->>'enabled' IS DISTINCT FROM 'true' THEN RAISE EXCEPTION 'activity source binding mismatch'; END IF;
 IF NEW.document->>'tenant_id' IS DISTINCT FROM NEW.tenant_id OR NEW.document->>'resource_id' IS DISTINCT FROM NEW.resource_id OR NEW.document->>'source_id' IS DISTINCT FROM NEW.source_id OR NEW.document->>'body_sha256' IS DISTINCT FROM NEW.body_sha256 THEN RAISE EXCEPTION 'activity receipt binding mismatch'; END IF;
 IF NEW.interval_end>activity_receive_time()+interval '5 seconds' OR NEW.interval_end<activity_receive_time()-interval '2 minutes' OR date_trunc('minute',NEW.interval_start)<>NEW.interval_start THEN RAISE EXCEPTION 'activity interval outside receive window'; END IF;
 IF abs(extract(epoch FROM (NEW.received_at-activity_receive_time())))>5 THEN RAISE EXCEPTION 'activity receive timestamp must be current'; END IF;
 IF encode(sha256(NEW.raw_body),'hex') IS DISTINCT FROM NEW.body_sha256 OR (convert_from(NEW.raw_body,'UTF8')::jsonb - ARRAY['sequence','interval_start','interval_end']) IS DISTINCT FROM (NEW.document - ARRAY['id','tenant_id','subject','received_at','body_sha256','idempotency_key','previous_interval_end','previous_sequence','previous_idle','binding','sequence','interval_start','interval_end']) THEN RAISE EXCEPTION 'activity original body hash or fields differ'; END IF;
 IF ((convert_from(NEW.raw_body,'UTF8')::jsonb)->>'interval_start')::timestamptz IS DISTINCT FROM NEW.interval_start OR ((convert_from(NEW.raw_body,'UTF8')::jsonb)->>'interval_end')::timestamptz IS DISTINCT FROM NEW.interval_end OR ((convert_from(NEW.raw_body,'UTF8')::jsonb)->>'sequence')::bigint IS DISTINCT FROM NEW.sequence THEN RAISE EXCEPTION 'activity original interval mismatch'; END IF;
 IF (NEW.document->>'sequence')::bigint IS DISTINCT FROM NEW.sequence OR (NEW.document->>'interval_start')::timestamptz IS DISTINCT FROM NEW.interval_start OR (NEW.document->>'interval_end')::timestamptz IS DISTINCT FROM NEW.interval_end THEN RAISE EXCEPTION 'activity receipt column mismatch'; END IF;
 IF NEW.document->'binding' IS DISTINCT FROM jsonb_build_object('tenant_id',NEW.tenant_id,'resource_id',NEW.resource_id,'provider_resource_id',source->>'provider_resource_id','account_id',source->>'account_id','region',source->>'region') THEN RAISE EXCEPTION 'activity provider binding differs'; END IF;
 RETURN NEW;END $$;
CREATE TRIGGER activity_receipt_binding BEFORE INSERT ON activity_receipts FOR EACH ROW EXECUTE FUNCTION guard_activity_receipt();
