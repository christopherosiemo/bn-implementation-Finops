-- Current-ownership analytical allocation only. No native source, historical
-- ownership, finality, execution or savings authority is created here.
-- Stored hashes use this bounded PostgreSQL canonical form consistently. They
-- are opaque database bindings, independent of the pure engine's Go JSON hash.
CREATE FUNCTION allocation_json_canonical(d jsonb,p_depth integer DEFAULT 0) RETURNS text LANGUAGE plpgsql IMMUTABLE STRICT SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE result text;
BEGIN
 IF p_depth NOT BETWEEN 0 AND 12 OR pg_column_size(d)>67108864 THEN RAISE EXCEPTION 'allocation canonical JSON depth or size bound exceeded';END IF;
 IF jsonb_typeof(d)='object' THEN
  IF (SELECT count(*) FROM jsonb_object_keys(d))>64 OR EXISTS(SELECT 1 FROM jsonb_object_keys(d) k WHERE octet_length(k)>256) THEN RAISE EXCEPTION 'allocation canonical object bound exceeded';END IF;
  SELECT '{'||coalesce(string_agg(to_jsonb(key)::text||':'||allocation_json_canonical(value,p_depth+1),',' ORDER BY key COLLATE "C"),'')||'}' INTO result FROM jsonb_each(d);RETURN result;
 END IF;
 IF jsonb_typeof(d)='array' THEN
  IF jsonb_array_length(d)>25000 THEN RAISE EXCEPTION 'allocation canonical array bound exceeded';END IF;
  SELECT '['||coalesce(string_agg(allocation_json_canonical(value,p_depth+1),',' ORDER BY ordinal),'')||']' INTO result FROM jsonb_array_elements(d) WITH ORDINALITY element(value,ordinal);RETURN result;
 END IF;
 IF jsonb_typeof(d)='number' AND (d#>>'{}')!~'^-?(0|[1-9][0-9]{0,18})$' THEN RAISE EXCEPTION 'allocation JSON numbers must be bounded integers; money must be text';END IF;
 IF jsonb_typeof(d)='string' AND octet_length(d#>>'{}')>65536 THEN RAISE EXCEPTION 'allocation canonical scalar bound exceeded';END IF;
 RETURN d::text;
END $$;
CREATE FUNCTION allocation_json_hash(d jsonb) RETURNS text LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog,public,pg_temp AS $$ SELECT encode(sha256(convert_to(allocation_json_canonical(d),'UTF8')),'hex') $$;
CREATE TABLE allocation_policy_revisions(
 tenant_id text NOT NULL,id text NOT NULL,version bigint NOT NULL CHECK(version>0),content_hash text NOT NULL CHECK(content_hash~'^[a-f0-9]{64}$'),
 definition jsonb NOT NULL CHECK(pg_column_size(definition)<=262144),document jsonb NOT NULL DEFAULT '{}',created_by text NOT NULL CHECK(length(created_by) BETWEEN 1 AND 512),
 writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(tenant_id,id),UNIQUE(tenant_id,version)
);
CREATE TABLE allocation_reports(
 tenant_id text NOT NULL,id text NOT NULL,policy_id text NOT NULL,record_count integer NOT NULL CHECK(record_count BETWEEN 0 AND 5000),line_count integer NOT NULL CHECK(line_count BETWEEN 0 AND 25000),
 mapping_snapshot jsonb NOT NULL CHECK(pg_column_size(mapping_snapshot)<=4194304),document jsonb NOT NULL CHECK(pg_column_size(document)<=1048576),
 mapping_index jsonb NOT NULL DEFAULT '{}' CHECK(pg_column_size(mapping_index)<=4194304),policy_targets jsonb NOT NULL DEFAULT '{}' CHECK(pg_column_size(policy_targets)<=1048576),
 created_by text NOT NULL CHECK(length(created_by) BETWEEN 1 AND 512),writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,id),FOREIGN KEY(tenant_id,policy_id) REFERENCES allocation_policy_revisions(tenant_id,id)
);
CREATE TABLE allocation_observations(
 tenant_id text NOT NULL,report_id text NOT NULL,ordinal integer NOT NULL CHECK(ordinal BETWEEN 1 AND 5000),source_id text NOT NULL,source_version text NOT NULL,record_id text NOT NULL,
 currency text NOT NULL CHECK(currency~'^[A-Z]{3}$'),observed_amount decimal(38,12),document jsonb NOT NULL CHECK(pg_column_size(document)<=16384),
 writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(tenant_id,report_id,ordinal),
 UNIQUE(tenant_id,report_id,source_id,source_version,record_id),FOREIGN KEY(tenant_id,report_id) REFERENCES allocation_reports(tenant_id,id),
 CHECK(length(source_id)>0 AND length(source_version)>0 AND length(record_id)>0)
);
CREATE TABLE allocation_lines(
 tenant_id text NOT NULL,report_id text NOT NULL,ordinal integer NOT NULL CHECK(ordinal BETWEEN 1 AND 25000),observation_ordinal integer NOT NULL,
 currency text NOT NULL CHECK(currency~'^[A-Z]{3}$'),allocated_amount decimal(38,12),document jsonb NOT NULL CHECK(pg_column_size(document)<=16384),
 writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(tenant_id,report_id,ordinal),
 FOREIGN KEY(tenant_id,report_id,observation_ordinal) REFERENCES allocation_observations(tenant_id,report_id,ordinal)
);
CREATE INDEX allocation_lines_fact ON allocation_lines(tenant_id,report_id,observation_ordinal);
CREATE TABLE allocation_report_seals(
 tenant_id text NOT NULL,report_id text NOT NULL,writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,report_id),FOREIGN KEY(tenant_id,report_id) REFERENCES allocation_reports(tenant_id,id)
);

CREATE FUNCTION allocation_lock(p_tenant text) RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$ BEGIN
 IF p_tenant IS DISTINCT FROM current_setting('app.tenant_id',true) THEN RAISE EXCEPTION 'allocation tenant mismatch';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(p_tenant||':dependency-graph',0));
 PERFORM pg_advisory_xact_lock(hashtextextended(p_tenant||':allocation-policy',0));
END $$;
CREATE FUNCTION guard_allocation_policy() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE rule jsonb;recipient jsonb;resource text;prior bigint;
BEGIN
 IF current_user<>'finops_api' THEN RAISE EXCEPTION 'allocation API writer required';END IF;
 PERFORM allocation_lock(NEW.tenant_id);
 SELECT coalesce(max(version),0) INTO prior FROM allocation_policy_revisions WHERE tenant_id=NEW.tenant_id;
 IF NEW.version<>prior+1 OR NEW.content_hash IS DISTINCT FROM allocation_json_hash(NEW.definition) OR jsonb_typeof(NEW.definition) IS DISTINCT FROM 'object' OR NEW.definition-ARRAY['schema_version','name','rules']<>'{}'::jsonb OR NEW.definition->'schema_version' IS DISTINCT FROM '"1"'::jsonb OR jsonb_typeof(NEW.definition->'name') IS DISTINCT FROM 'string' OR length(btrim(coalesce(NEW.definition->>'name',''))) NOT BETWEEN 1 AND 80 OR jsonb_typeof(NEW.definition->'rules') IS DISTINCT FROM 'array' OR jsonb_array_length(NEW.definition->'rules')>100 THEN RAISE EXCEPTION 'allocation policy version or definition invalid';END IF;
 FOR rule IN SELECT value FROM jsonb_array_elements(NEW.definition->'rules') LOOP
  IF jsonb_typeof(rule) IS DISTINCT FROM 'object' OR rule-ARRAY['resource_ids','recipients']<>'{}'::jsonb OR jsonb_typeof(rule->'resource_ids') IS DISTINCT FROM 'array' OR jsonb_array_length(rule->'resource_ids') NOT BETWEEN 1 AND 256 OR jsonb_typeof(rule->'recipients') IS DISTINCT FROM 'array' OR jsonb_array_length(rule->'recipients') NOT BETWEEN 1 AND 100 OR EXISTS(SELECT 1 FROM jsonb_array_elements(rule->'resource_ids') item WHERE jsonb_typeof(item)<>'string') THEN RAISE EXCEPTION 'allocation rule invalid';END IF;
  FOR resource IN SELECT jsonb_array_elements_text(rule->'resource_ids') LOOP
   IF resource!~'^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$' OR NOT EXISTS(SELECT 1 FROM entities WHERE tenant_id=NEW.tenant_id AND kind='resources' AND id=resource) THEN RAISE EXCEPTION 'allocation resource unavailable';END IF;
  END LOOP;
  FOR recipient IN SELECT value FROM jsonb_array_elements(rule->'recipients') LOOP
   IF jsonb_typeof(recipient) IS DISTINCT FROM 'object' OR recipient-ARRAY['workload_id','weight_ppm']<>'{}'::jsonb OR jsonb_typeof(recipient->'workload_id') IS DISTINCT FROM 'string' OR coalesce(recipient->>'workload_id','')!~'^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$' OR jsonb_typeof(recipient->'weight_ppm') IS DISTINCT FROM 'number' OR (recipient->>'weight_ppm')::numeric<>trunc((recipient->>'weight_ppm')::numeric) OR (recipient->>'weight_ppm')::numeric NOT BETWEEN 1 AND 1000000 OR NOT EXISTS(SELECT 1 FROM entities WHERE tenant_id=NEW.tenant_id AND kind='workloads' AND id=recipient->>'workload_id') THEN RAISE EXCEPTION 'allocation recipient unavailable';END IF;
  END LOOP;
  IF (SELECT sum((value->>'weight_ppm')::numeric) FROM jsonb_array_elements(rule->'recipients'))<>1000000 OR (SELECT count(*)<>count(DISTINCT value->>'workload_id') FROM jsonb_array_elements(rule->'recipients')) THEN RAISE EXCEPTION 'allocation weights or recipients invalid';END IF;
 END LOOP;
 IF (SELECT count(*)>1024 OR count(*)<>count(DISTINCT id) FROM jsonb_array_elements(NEW.definition->'rules') r CROSS JOIN LATERAL jsonb_array_elements_text(r->'resource_ids') id) THEN RAISE EXCEPTION 'allocation selectors overlap or exceed bound';END IF;
 NEW.writer_role:='finops_api';NEW.created_at:=clock_timestamp();
 NEW.document:=jsonb_build_object('id',NEW.id,'version',NEW.version,'hash',NEW.content_hash,'definition',NEW.definition,'created_by',NEW.created_by,'created_at',NEW.created_at);RETURN NEW;
END $$;
CREATE TRIGGER writer BEFORE INSERT ON allocation_policy_revisions FOR EACH ROW EXECUTE FUNCTION guard_allocation_policy();

CREATE FUNCTION guard_allocation_report() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE current_policy text;expected_mapping jsonb;source jsonb;k text;v jsonb;receipt jsonb;registration jsonb;
BEGIN
 IF current_user<>'finops_api' THEN RAISE EXCEPTION 'allocation API writer required';END IF;
 PERFORM allocation_lock(NEW.tenant_id);
 SELECT id INTO current_policy FROM allocation_policy_revisions WHERE tenant_id=NEW.tenant_id ORDER BY version DESC LIMIT 1;
 IF current_policy IS DISTINCT FROM NEW.policy_id THEN RAISE EXCEPTION 'allocation policy superseded';END IF;
 IF (SELECT count(*) FROM entities WHERE tenant_id=NEW.tenant_id AND kind IN('resources','workloads'))>20000 THEN RAISE EXCEPTION 'allocation catalog bound exceeded';END IF;
 SELECT jsonb_build_object('resources',coalesce((SELECT jsonb_agg(jsonb_build_object('id',id,'provider',coalesce(document->>'provider',''),'account_id',coalesce(document->>'account_id',''),'region',coalesce(document->>'region',''),'provider_resource_id',coalesce(document->>'provider_resource_id',''),'workload_id',coalesce(document->>'workload_id',''),'version',version) ORDER BY id COLLATE "C") FROM entities WHERE tenant_id=NEW.tenant_id AND kind='resources'),'[]'::jsonb),'workloads',coalesce((SELECT jsonb_agg(id ORDER BY id COLLATE "C") FROM entities WHERE tenant_id=NEW.tenant_id AND kind='workloads'),'[]'::jsonb)) INTO expected_mapping;
 IF NEW.mapping_snapshot IS DISTINCT FROM expected_mapping OR NEW.document->>'mapping_hash' IS DISTINCT FROM allocation_json_hash(expected_mapping) THEN RAISE EXCEPTION 'allocation current mapping snapshot mismatch';END IF;
 SELECT coalesce(jsonb_object_agg(allocation_json_hash(jsonb_build_array(r->>'provider',r->>'account_id',r->>'region',r->>'provider_resource_id')),r),'{}'::jsonb) INTO NEW.mapping_index FROM jsonb_array_elements(expected_mapping->'resources') r WHERE coalesce(r->>'region','')<>'';
 IF (SELECT count(*) FROM jsonb_object_keys(NEW.mapping_index))<>(SELECT count(*) FROM jsonb_array_elements(expected_mapping->'resources') r WHERE coalesce(r->>'region','')<>'') THEN RAISE EXCEPTION 'allocation native resource identity ambiguous';END IF;
 SELECT coalesce(jsonb_object_agg(resource,rule->'recipients'),'{}'::jsonb) INTO NEW.policy_targets FROM allocation_policy_revisions p CROSS JOIN LATERAL jsonb_array_elements(p.definition->'rules') rule CROSS JOIN LATERAL jsonb_array_elements_text(rule->'resource_ids') resource WHERE p.tenant_id=NEW.tenant_id AND p.id=NEW.policy_id;
 source:=NEW.document->'source';
 IF source IS NULL OR jsonb_typeof(source) IS DISTINCT FROM 'object' OR source-ARRAY['kind','coverage','finality','execution_authorized','verified_saving','provenance','reason_code','source_connection_id','source_receipt_id','source_revision_id','billing_period_start','payer_account_id','source_proof_hash','ingestion_job_id','source_id','source_version','raw_hash','canonical_hash']<>'{}'::jsonb OR pg_column_size(source)>65536 OR coalesce(source->>'kind','') NOT IN('CUSTOMER_IMPORT','DETERMINISTIC_FIXTURE','AWS_CUR2_CONNECTION') OR coalesce(source->>'coverage','') NOT IN('UNKNOWN','AUTHENTICATED_EXPORT_REVISION') OR source->>'finality' IS DISTINCT FROM 'UNPROVEN' OR source->'execution_authorized' IS DISTINCT FROM 'false'::jsonb OR source->'verified_saving' IS DISTINCT FROM 'null'::jsonb THEN RAISE EXCEPTION 'allocation source metadata cannot grant authority';END IF;
 FOR k,v IN SELECT * FROM jsonb_each(source) LOOP IF k NOT IN('execution_authorized','verified_saving') AND (jsonb_typeof(v)<>'string' OR length(btrim(v#>>'{}'))=0 OR octet_length(v#>>'{}')>512) THEN RAISE EXCEPTION 'allocation source must contain bounded nonempty metadata only';END IF;END LOOP;
 IF NOT(source ?& ARRAY['provenance','reason_code','ingestion_job_id','source_id','source_version','raw_hash','canonical_hash']) OR coalesce(source->>'raw_hash','')!~'^[a-f0-9]{64}$' OR coalesce(source->>'canonical_hash','')!~'^[a-f0-9]{64}$' THEN RAISE EXCEPTION 'allocation complete source identity and hashes required';END IF;
 IF source->>'kind' IN('CUSTOMER_IMPORT','DETERMINISTIC_FIXTURE') THEN
  IF source->>'provenance' IS DISTINCT FROM source->>'kind' OR source->>'coverage' IS DISTINCT FROM 'UNKNOWN' OR source ?| ARRAY['source_connection_id','source_receipt_id','source_revision_id','billing_period_start','payer_account_id','source_proof_hash'] THEN RAISE EXCEPTION 'allocation import or fixture cannot claim native coverage';END IF;
 ELSE
  IF source->>'provenance' IS DISTINCT FROM 'AWS_CUR2_AUTHENTICATED' OR source->>'coverage' IS DISTINCT FROM 'AUTHENTICATED_EXPORT_REVISION' OR NOT(source ?& ARRAY['source_connection_id','source_receipt_id','source_revision_id','billing_period_start','payer_account_id','source_proof_hash']) OR coalesce(source->>'payer_account_id','')!~'^[0-9]{12}$' OR coalesce(source->>'source_proof_hash','')!~'^[a-f0-9]{64}$' OR coalesce(source->>'billing_period_start','')!~'^[0-9]{4}-(0[1-9]|1[0-2])-01T00:00:00Z$' THEN RAISE EXCEPTION 'allocation native source references required';END IF;
  -- This only validates the source classification against an existing issued
  -- receipt. The service additionally resolves current config and period head;
  -- neither this join nor allocation metadata creates financial authority.
  SELECT r.document,s.document INTO receipt,registration FROM source_receipts r JOIN source_revisions rev ON rev.tenant_id=r.tenant_id AND rev.id=r.revision_id AND rev.source_id=r.source_id JOIN source_registrations s ON s.tenant_id=r.tenant_id AND s.id=r.source_id WHERE r.tenant_id=NEW.tenant_id AND r.id=source->>'source_receipt_id' AND r.source_id=source->>'source_connection_id' AND r.revision_id=source->>'source_revision_id' AND r.kind='AWS_CUR2' AND r.writer_role='finops_ingester' AND rev.writer_role='finops_ingester' FOR SHARE OF s;
  IF receipt IS NULL OR registration->'enabled' IS DISTINCT FROM 'true'::jsonb OR registration->'revoked'='true'::jsonb OR registration->>'kind' IS DISTINCT FROM 'AWS_CUR2' OR registration->>'payer_account_id' IS DISTINCT FROM source->>'payer_account_id' OR source->>'source_id' IS DISTINCT FROM source->>'source_connection_id' OR receipt->>'registration_id' IS DISTINCT FROM source->>'source_connection_id' OR receipt->>'ingestion_job_id' IS DISTINCT FROM source->>'ingestion_job_id' OR receipt->>'source_version' IS DISTINCT FROM source->>'source_version' OR receipt->>'raw_hash' IS DISTINCT FROM source->>'raw_hash' OR receipt->>'canonical_hash' IS DISTINCT FROM source->>'canonical_hash' OR receipt->'source_proof'->>'billing_period_start' IS DISTINCT FROM source->>'billing_period_start' THEN RAISE EXCEPTION 'allocation native source issued receipt mismatch or revoked';END IF;
 END IF;
 IF NEW.document-ARRAY['id','version','schema_version','status','basis','reason_codes','policy_id','source','mapping_hash','input_hash','result_hash','record_count','line_count','totals','execution_authorized','verified_saving']<>'{}'::jsonb OR NEW.document->>'id' IS DISTINCT FROM NEW.id OR NEW.document->'version' IS DISTINCT FROM '1'::jsonb OR NEW.document->>'schema_version' IS DISTINCT FROM '1' OR NEW.document->>'basis' IS DISTINCT FROM 'CURRENT_OWNERSHIP_VIEW' OR NEW.document->>'policy_id' IS DISTINCT FROM NEW.policy_id OR NEW.document->'record_count' IS DISTINCT FROM to_jsonb(NEW.record_count) OR NEW.document->'line_count' IS DISTINCT FROM to_jsonb(NEW.line_count) OR NEW.document->'execution_authorized' IS DISTINCT FROM 'false'::jsonb OR NEW.document->'verified_saving' IS DISTINCT FROM 'null'::jsonb OR jsonb_typeof(NEW.document->'totals') IS DISTINCT FROM 'array' THEN RAISE EXCEPTION 'allocation report summary invalid';END IF;
 FOREACH k IN ARRAY ARRAY['mapping_hash','input_hash','result_hash'] LOOP IF coalesce(NEW.document->>k,'')!~'^[a-f0-9]{64}$' THEN RAISE EXCEPTION 'allocation immutable digest required';END IF;END LOOP;
 NEW.writer_role:='finops_api';NEW.created_at:=clock_timestamp();NEW.document:=NEW.document||jsonb_build_object('created_at',NEW.created_at,'mapping_as_of',NEW.created_at);RETURN NEW;
END $$;
CREATE TRIGGER writer BEFORE INSERT ON allocation_reports FOR EACH ROW EXECUTE FUNCTION guard_allocation_report();

CREATE FUNCTION guard_allocation_row() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE header allocation_reports;o allocation_observations;amount jsonb;k text;
BEGIN
 IF current_user<>'finops_api' OR NEW.tenant_id IS DISTINCT FROM current_setting('app.tenant_id',true) THEN RAISE EXCEPTION 'allocation API tenant writer required';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id||':allocation-report:'||NEW.report_id,0));
 SELECT * INTO header FROM allocation_reports WHERE tenant_id=NEW.tenant_id AND id=NEW.report_id;
 IF header.id IS NULL OR EXISTS(SELECT 1 FROM allocation_report_seals WHERE tenant_id=NEW.tenant_id AND report_id=NEW.report_id) THEN RAISE EXCEPTION 'allocation report missing or already sealed';END IF;
 IF TG_TABLE_NAME='allocation_observations' THEN
  amount:=NEW.document->'observed_billed_cost';
  IF NEW.source_id IS DISTINCT FROM header.document->'source'->>'source_id' OR NEW.source_version IS DISTINCT FROM header.document->'source'->>'source_version' THEN RAISE EXCEPTION 'allocation observation must match frozen source identity';END IF;
  FOREACH k IN ARRAY ARRAY['record_id','source_id','source_version','provider','account_id','region','provider_resource_id','currency'] LOOP IF jsonb_typeof(NEW.document->k) IS DISTINCT FROM 'string' THEN RAISE EXCEPTION 'allocation observation fields must be strings';END IF;END LOOP;
  IF NEW.ordinal>header.record_count OR NOT(NEW.document ?& ARRAY['record_id','source_id','source_version','provider','account_id','region','provider_resource_id','currency','observed_billed_cost']) OR NEW.document-ARRAY['record_id','source_id','source_version','provider','account_id','region','provider_resource_id','currency','observed_billed_cost']<>'{}'::jsonb OR NEW.document->>'record_id' IS DISTINCT FROM NEW.record_id OR NEW.document->>'source_id' IS DISTINCT FROM NEW.source_id OR NEW.document->>'source_version' IS DISTINCT FROM NEW.source_version OR NEW.document->>'currency' IS DISTINCT FROM NEW.currency OR coalesce(NEW.document->>'provider','')='' OR coalesce(NEW.document->>'account_id','')='' THEN RAISE EXCEPTION 'allocation observation binding invalid';END IF;
  IF amount IS DISTINCT FROM 'null'::jsonb AND (jsonb_typeof(amount)<>'string' OR (amount#>>'{}')!~'^-?(0|[1-9][0-9]{0,25})(\.[0-9]{1,12})?$') OR (amount#>>'{}')::numeric IS DISTINCT FROM NEW.observed_amount THEN RAISE EXCEPTION 'allocation observation must retain exact signed decimal or null';END IF;
 ELSE
  SELECT * INTO o FROM allocation_observations WHERE tenant_id=NEW.tenant_id AND report_id=NEW.report_id AND ordinal=NEW.observation_ordinal;
  amount:=NEW.document->'allocated_billed_cost';
  FOREACH k IN ARRAY ARRAY['record_id','source_id','source_version','provider_resource_id','currency','method','reason_code'] LOOP IF jsonb_typeof(NEW.document->k) IS DISTINCT FROM 'string' THEN RAISE EXCEPTION 'allocation line fields must be strings';END IF;END LOOP;
  FOREACH k IN ARRAY ARRAY['resource_id','workload_id'] LOOP IF NEW.document->k IS DISTINCT FROM 'null'::jsonb AND jsonb_typeof(NEW.document->k) IS DISTINCT FROM 'string' THEN RAISE EXCEPTION 'allocation optional ownership must be string or null';END IF;END LOOP;
  IF NEW.ordinal>header.line_count OR o.ordinal IS NULL OR NOT(NEW.document ?& ARRAY['record_id','source_id','source_version','resource_id','provider_resource_id','workload_id','currency','allocated_billed_cost','method','reason_code']) OR NEW.document-ARRAY['record_id','source_id','source_version','resource_id','provider_resource_id','workload_id','currency','allocated_billed_cost','method','reason_code']<>'{}'::jsonb OR NEW.document->>'record_id' IS DISTINCT FROM o.record_id OR NEW.document->>'source_id' IS DISTINCT FROM o.source_id OR NEW.document->>'source_version' IS DISTINCT FROM o.source_version OR NEW.currency IS DISTINCT FROM o.currency OR NEW.document->>'currency' IS DISTINCT FROM o.currency OR NEW.document->>'provider_resource_id' IS DISTINCT FROM o.document->>'provider_resource_id' THEN RAISE EXCEPTION 'allocation line source binding invalid';END IF;
  IF amount IS DISTINCT FROM 'null'::jsonb AND (jsonb_typeof(amount)<>'string' OR (amount#>>'{}')!~'^-?(0|[1-9][0-9]{0,25})(\.[0-9]{1,12})?$') OR (amount#>>'{}')::numeric IS DISTINCT FROM NEW.allocated_amount OR (NEW.allocated_amount IS NULL) IS DISTINCT FROM (o.observed_amount IS NULL) OR o.observed_amount=0 AND NEW.allocated_amount<>0 OR o.observed_amount>0 AND NEW.allocated_amount<0 OR o.observed_amount<0 AND NEW.allocated_amount>0 THEN RAISE EXCEPTION 'allocation line cannot invent a value or reverse its sign';END IF;
 END IF;
 NEW.writer_role:='finops_api';NEW.created_at:=clock_timestamp();RETURN NEW;
END $$;
CREATE TRIGGER writer BEFORE INSERT ON allocation_observations FOR EACH ROW EXECUTE FUNCTION guard_allocation_row();
CREATE TRIGGER writer BEFORE INSERT ON allocation_lines FOR EACH ROW EXECUTE FUNCTION guard_allocation_row();

-- Recompute each fact's exact largest-remainder split from frozen mappings.
-- Unknown costs stay null; neither a positive subtotal nor a global credit can
-- conceal a missing/wrong per-fact allocation at seal time.
CREATE FUNCTION allocation_expected_lines(p_tenant text,p_report text,p_ordinal integer) RETURNS TABLE(resource_id text,workload_id text,method text,reason_code text,amount numeric) LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE h allocation_reports;o allocation_observations;resource jsonb;definition jsonb;targets jsonb;kind text;units numeric;
BEGIN
 SELECT * INTO h FROM allocation_reports WHERE tenant_id=p_tenant AND id=p_report;
 SELECT * INTO o FROM allocation_observations WHERE tenant_id=p_tenant AND report_id=p_report AND ordinal=p_ordinal;
 resource:=h.mapping_index->allocation_json_hash(jsonb_build_array(o.document->>'provider',o.document->>'account_id',o.document->>'region',o.document->>'provider_resource_id'));
 IF o.observed_amount IS NULL THEN RETURN QUERY SELECT resource->>'id',NULL::text,'UNALLOCATED'::text,'BILLED_COST_UNAVAILABLE'::text,NULL::numeric;RETURN;END IF;
 targets:=h.policy_targets->(resource->>'id');
 kind:='POLICY_FIXED_SHARE';
 IF targets IS NULL AND coalesce(resource->>'workload_id','')<>'' THEN targets:=jsonb_build_array(jsonb_build_object('workload_id',resource->>'workload_id','weight_ppm',1000000));kind:='CURRENT_RESOURCE_OWNER';END IF;
 IF targets IS NULL THEN RETURN QUERY SELECT resource->>'id',NULL::text,'UNALLOCATED'::text,'RESOURCE_OWNER_UNAVAILABLE'::text,o.observed_amount;RETURN;END IF;
 units:=abs(o.observed_amount)*1000000000000;
 RETURN QUERY WITH shares AS(SELECT target->>'workload_id' AS wid,floor(units*(target->>'weight_ppm')::numeric/1000000) AS whole,mod(units*(target->>'weight_ppm')::numeric,1000000) AS remainder FROM jsonb_array_elements(targets) target),ranked AS(SELECT *,row_number() OVER(ORDER BY remainder DESC,wid COLLATE "C") AS place,units-sum(whole) OVER() AS leftover FROM shares)
 SELECT resource->>'id',wid,kind,'CURRENT_POLICY_MAPPING'::text,sign(o.observed_amount)*(whole+CASE WHEN place<=leftover THEN 1 ELSE 0 END)*0.000000000001 FROM ranked ORDER BY wid COLLATE "C";
END $$;

CREATE FUNCTION guard_allocation_seal() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE h allocation_reports;o allocation_observations;expected record;totals jsonb;status text;reasons jsonb;observations jsonb;lines jsonb;policy_hash text;input_doc jsonb;result_doc jsonb;
BEGIN
 IF current_user<>'finops_api' OR NEW.tenant_id IS DISTINCT FROM current_setting('app.tenant_id',true) THEN RAISE EXCEPTION 'allocation API tenant seal required';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id||':allocation-report:'||NEW.report_id,0));
 SELECT * INTO h FROM allocation_reports WHERE tenant_id=NEW.tenant_id AND id=NEW.report_id;
 IF h.id IS NULL OR (SELECT count(*) FROM allocation_observations WHERE tenant_id=NEW.tenant_id AND report_id=NEW.report_id)<>h.record_count OR (SELECT coalesce(max(ordinal),0) FROM allocation_observations WHERE tenant_id=NEW.tenant_id AND report_id=NEW.report_id)<>h.record_count OR (SELECT count(*) FROM allocation_lines WHERE tenant_id=NEW.tenant_id AND report_id=NEW.report_id)<>h.line_count OR (SELECT coalesce(max(ordinal),0) FROM allocation_lines WHERE tenant_id=NEW.tenant_id AND report_id=NEW.report_id)<>h.line_count THEN RAISE EXCEPTION 'allocation seal incomplete row counts or ordinals';END IF;
 FOR o IN SELECT * FROM allocation_observations WHERE tenant_id=NEW.tenant_id AND report_id=NEW.report_id LOOP
  IF (SELECT count(*) FROM allocation_lines WHERE tenant_id=NEW.tenant_id AND report_id=NEW.report_id AND observation_ordinal=o.ordinal)<>(SELECT count(*) FROM allocation_expected_lines(NEW.tenant_id,NEW.report_id,o.ordinal)) THEN RAISE EXCEPTION 'allocation fact split count invalid';END IF;
  FOR expected IN SELECT * FROM allocation_expected_lines(NEW.tenant_id,NEW.report_id,o.ordinal) LOOP
   IF (SELECT count(*) FROM allocation_lines l WHERE l.tenant_id=NEW.tenant_id AND l.report_id=NEW.report_id AND l.observation_ordinal=o.ordinal AND l.currency=o.currency AND l.document->>'resource_id' IS NOT DISTINCT FROM expected.resource_id AND l.document->>'workload_id' IS NOT DISTINCT FROM expected.workload_id AND l.document->>'method'=expected.method AND l.document->>'reason_code'=expected.reason_code AND l.allocated_amount IS NOT DISTINCT FROM expected.amount)<>1 THEN RAISE EXCEPTION 'allocation fact split differs from frozen policy or current ownership';END IF;
  END LOOP;
  IF o.observed_amount IS NOT NULL AND (SELECT sum(allocated_amount) FROM allocation_lines WHERE tenant_id=NEW.tenant_id AND report_id=NEW.report_id AND observation_ordinal=o.ordinal) IS DISTINCT FROM o.observed_amount THEN RAISE EXCEPTION 'allocation fact conservation failed';END IF;
 END LOOP;
 WITH observed AS(SELECT obs.currency,coalesce(sum(obs.observed_amount),0) AS known,count(*) FILTER(WHERE obs.observed_amount IS NULL) AS unknown_count FROM allocation_observations obs WHERE obs.tenant_id=NEW.tenant_id AND obs.report_id=NEW.report_id GROUP BY obs.currency),allocated AS(SELECT l.currency,coalesce(sum(l.allocated_amount) FILTER(WHERE l.document->>'workload_id' IS NOT NULL),0) AS allocated,coalesce(sum(l.allocated_amount) FILTER(WHERE l.document->>'workload_id' IS NULL),0) AS unallocated FROM allocation_lines l WHERE l.tenant_id=NEW.tenant_id AND l.report_id=NEW.report_id GROUP BY l.currency)
 SELECT coalesce(jsonb_agg(jsonb_build_object('currency',observed.currency,'observed_billed_total',CASE WHEN unknown_count=0 THEN known::numeric(38,12)::text ELSE NULL END,'known_billed_subtotal',known::numeric(38,12)::text,'allocated_subtotal',allocated.allocated::numeric(38,12)::text,'unallocated_subtotal',unallocated::numeric(38,12)::text,'unknown_record_count',unknown_count) ORDER BY observed.currency),'[]'::jsonb) INTO totals FROM observed JOIN allocated USING(currency);
 status:=CASE WHEN h.record_count=0 THEN 'NO_OBSERVATIONS' WHEN EXISTS(SELECT 1 FROM allocation_observations WHERE tenant_id=NEW.tenant_id AND report_id=NEW.report_id AND observed_amount IS NULL) THEN 'PARTIAL_OBSERVATIONS' ELSE 'ALLOCATED_OBSERVATIONS' END;
 reasons:='["PROVISIONAL_ALLOCATION_ONLY","HISTORICAL_OWNERSHIP_NOT_ASSERTED","VERIFIED_SAVINGS_NOT_ASSERTED"]'::jsonb;
 IF h.record_count=0 THEN reasons:=reasons||'["BILLING_OBSERVATIONS_UNAVAILABLE"]'::jsonb;END IF;
 IF h.document->'totals' IS DISTINCT FROM totals OR h.document->>'status' IS DISTINCT FROM status OR h.document->'reason_codes' IS DISTINCT FROM reasons THEN RAISE EXCEPTION 'allocation sealed totals or provisional status invalid';END IF;
 SELECT coalesce(jsonb_agg(document ORDER BY ordinal),'[]'::jsonb) INTO observations FROM allocation_observations WHERE tenant_id=NEW.tenant_id AND report_id=NEW.report_id;
 SELECT coalesce(jsonb_agg(document ORDER BY ordinal),'[]'::jsonb) INTO lines FROM allocation_lines WHERE tenant_id=NEW.tenant_id AND report_id=NEW.report_id;
 SELECT content_hash INTO policy_hash FROM allocation_policy_revisions WHERE tenant_id=NEW.tenant_id AND id=h.policy_id;
 input_doc:=jsonb_build_object('tenant_id',NEW.tenant_id,'policy_id',h.policy_id,'policy_hash',policy_hash,'source',h.document->'source','mapping_hash',h.document->'mapping_hash','records',observations);
 result_doc:=jsonb_build_object('schema_version','1','basis','CURRENT_OWNERSHIP_VIEW','status',status,'reason_codes',reasons,'record_count',h.record_count,'lines',lines,'observed_records',observations,'totals',totals,'execution_authorized',false,'verified_saving',NULL);
 IF h.document->>'input_hash' IS DISTINCT FROM allocation_json_hash(input_doc) OR h.document->>'result_hash' IS DISTINCT FROM allocation_json_hash(result_doc) THEN RAISE EXCEPTION 'allocation frozen input or result hash mismatch';END IF;
 NEW.writer_role:='finops_api';NEW.created_at:=clock_timestamp();RETURN NEW;
END $$;
CREATE TRIGGER writer BEFORE INSERT ON allocation_report_seals FOR EACH ROW EXECUTE FUNCTION guard_allocation_seal();

DO $$ DECLARE tab text;BEGIN
 FOREACH tab IN ARRAY ARRAY['allocation_policy_revisions','allocation_reports','allocation_observations','allocation_lines','allocation_report_seals'] LOOP
  EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',tab);EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',tab);
  EXECUTE format('CREATE POLICY tenant_isolation ON %I USING(tenant_id=current_setting(''app.tenant_id'',true)) WITH CHECK(tenant_id=current_setting(''app.tenant_id'',true))',tab);
  EXECUTE format('CREATE TRIGGER immutable BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION deny_evidence_mutation()',tab);
  EXECUTE format('GRANT SELECT,INSERT ON %I TO finops_api',tab);
 END LOOP;
END $$;
REVOKE ALL ON FUNCTION allocation_lock(text),allocation_expected_lines(text,text,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION allocation_lock(text),allocation_expected_lines(text,text,integer) TO finops_api;
REVOKE ALL ON FUNCTION allocation_json_canonical(jsonb,integer),allocation_json_hash(jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION allocation_json_canonical(jsonb,integer),allocation_json_hash(jsonb) TO finops_api;
REVOKE ALL ON FUNCTION guard_allocation_policy(),guard_allocation_report(),guard_allocation_row(),guard_allocation_seal() FROM PUBLIC;
