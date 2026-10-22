-- Private fleet-window factories. These records never approve, sign or apply a
-- change. Existing short-window SLO evaluations keep their original semantics.
CREATE TABLE fleet_member_slo_windows(
 tenant_id text NOT NULL,id text NOT NULL,objective_id text NOT NULL,source_id text NOT NULL,resource_id text NOT NULL,
 window_start timestamptz NOT NULL,window_end timestamptz NOT NULL,status text NOT NULL CHECK(status IN('CLEAR','BREACH','BLOCKED')),
 content_hash text NOT NULL CHECK(content_hash~'^[a-f0-9]{64}$'),document jsonb NOT NULL,writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,id),UNIQUE(tenant_id,content_hash),FOREIGN KEY(tenant_id,objective_id) REFERENCES slo_objectives(tenant_id,id),FOREIGN KEY(tenant_id,source_id) REFERENCES slo_sources(tenant_id,id),
 CHECK(window_end-window_start BETWEEN interval '2 minutes' AND interval '60 minutes'),CHECK(pg_column_size(document)<=65536)
);
CREATE TABLE fleet_cohort_baselines(
 tenant_id text NOT NULL,id text NOT NULL,workload_id text NOT NULL,objective_id text NOT NULL,membership_receipt_id text NOT NULL,
 content_hash text NOT NULL CHECK(content_hash~'^[a-f0-9]{64}$'),document jsonb NOT NULL,writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,id),UNIQUE(tenant_id,content_hash),FOREIGN KEY(tenant_id,objective_id) REFERENCES slo_objectives(tenant_id,id),FOREIGN KEY(tenant_id,membership_receipt_id) REFERENCES source_receipts(tenant_id,id),CHECK(pg_column_size(document)<=131072)
);
CREATE TABLE fleet_cohort_windows(
 tenant_id text NOT NULL,id text NOT NULL,command_id text NOT NULL,baseline_id text,mode text NOT NULL CHECK(mode IN('FORWARD','OWNED_RECOVERY')),
 status text NOT NULL CHECK(status IN('CLEAR','BREACH','BLOCKED')),content_hash text NOT NULL CHECK(content_hash~'^[a-f0-9]{64}$'),document jsonb NOT NULL,
 writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(tenant_id,id),UNIQUE(tenant_id,command_id,content_hash),
 FOREIGN KEY(tenant_id,command_id) REFERENCES fleet_commands(tenant_id,id),FOREIGN KEY(tenant_id,baseline_id) REFERENCES fleet_cohort_baselines(tenant_id,id),CHECK(pg_column_size(document)<=131072)
);
CREATE TABLE fleet_cohort_failures(
 tenant_id text NOT NULL,id text NOT NULL,execution_id text NOT NULL,command_id text NOT NULL,window_id text NOT NULL,document jsonb NOT NULL,
 writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(tenant_id,id),UNIQUE(tenant_id,execution_id),
 FOREIGN KEY(tenant_id,execution_id) REFERENCES fleet_executions(tenant_id,id),FOREIGN KEY(tenant_id,command_id) REFERENCES fleet_commands(tenant_id,id),FOREIGN KEY(tenant_id,window_id) REFERENCES fleet_cohort_windows(tenant_id,id),CHECK(pg_column_size(document)<=16384)
);
DO $$ DECLARE tab text;BEGIN
 FOREACH tab IN ARRAY ARRAY['fleet_member_slo_windows','fleet_cohort_baselines','fleet_cohort_windows','fleet_cohort_failures'] LOOP
  EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',tab);EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',tab);
  EXECUTE format('CREATE POLICY tenant_isolation ON %I USING(tenant_id=current_setting(''app.tenant_id'',true)) WITH CHECK(tenant_id=current_setting(''app.tenant_id'',true))',tab);
  EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION deny_evidence_mutation()',tab||'_immutable',tab);
  EXECUTE format('GRANT SELECT ON %I TO finops_api,finops_worker,finops_signer',tab);
 END LOOP;
END $$;
GRANT INSERT ON fleet_member_slo_windows,fleet_cohort_baselines,fleet_cohort_windows TO finops_api;
GRANT INSERT ON fleet_cohort_failures TO finops_api,finops_worker;

-- Every referenced minute is selected from the immutable dedicated SLI ingress.
-- An API summary cannot omit a receipt or change its financial/provider scope.
CREATE FUNCTION guard_fleet_member_window() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE objective slo_objectives;source slo_sources;resource jsonb;member jsonb;rid text;r slo_receipts;
 expected integer;observed integer:=0;previous_sequence bigint;cursor_time timestamptz;
 requests numeric:=0;errors_count numeric:=0;good numeric:=0;total numeric:=0;samples numeric:=0;
BEGIN
 SELECT * INTO objective FROM slo_objectives WHERE tenant_id=NEW.tenant_id AND id=NEW.objective_id;
 SELECT * INTO source FROM slo_sources WHERE tenant_id=NEW.tenant_id AND id=NEW.source_id;
 SELECT document INTO resource FROM entities WHERE tenant_id=NEW.tenant_id AND kind='resources' AND id=NEW.resource_id;
 member:=NEW.document->'member';expected:=extract(epoch FROM NEW.window_end-NEW.window_start)::integer/60;cursor_time:=NEW.window_start;
 IF NEW.document->>'schema_version' IS DISTINCT FROM '1' OR NEW.document->>'kind' IS DISTINCT FROM 'FLEET_MEMBER_SLO_WINDOW' OR NEW.document->>'status' IS DISTINCT FROM NEW.status OR NEW.document->>'hash' IS DISTINCT FROM NEW.content_hash
 OR (NEW.document->>'window_start')::timestamptz IS DISTINCT FROM NEW.window_start OR (NEW.document->>'window_end')::timestamptz IS DISTINCT FROM NEW.window_end
 OR date_trunc('minute',NEW.window_start) IS DISTINCT FROM NEW.window_start OR date_trunc('minute',NEW.window_end) IS DISTINCT FROM NEW.window_end
 OR objective.id IS NULL OR source.id IS NULL OR resource IS NULL OR source.objective_id IS DISTINCT FROM NEW.objective_id OR source.resource_id IS DISTINCT FROM NEW.resource_id
 OR source.document->>'enabled' IS DISTINCT FROM 'true' OR source.document->>'workload_id' IS DISTINCT FROM objective.workload_id
 OR member->>'objective_id' IS DISTINCT FROM NEW.objective_id OR (member->>'objective_version')::bigint IS DISTINCT FROM objective.version OR member->>'objective_sha256' IS DISTINCT FROM objective.content_hash
 OR member->>'source_id' IS DISTINCT FROM NEW.source_id OR member->>'instance_id' IS DISTINCT FROM source.document->>'provider_resource_id' OR member->>'instance_id'!~'^i-([a-f0-9]{8}|[a-f0-9]{17})$'
 OR member->'binding' IS DISTINCT FROM jsonb_build_object('tenant_id',NEW.tenant_id,'resource_id',NEW.resource_id,'workload_id',objective.workload_id,'provider','AWS','provider_resource_id',source.document->>'provider_resource_id','account_id',source.document->>'account_id','region',source.document->>'region')
 OR resource->>'workload_id' IS DISTINCT FROM objective.workload_id OR resource->>'provider' IS DISTINCT FROM 'AWS' OR resource->>'provider_resource_id' IS DISTINCT FROM source.document->>'provider_resource_id' OR resource->>'account_id' IS DISTINCT FROM source.document->>'account_id' OR resource->>'region' IS DISTINCT FROM source.document->>'region'
 OR jsonb_typeof(member->'receipt_ids') IS DISTINCT FROM 'array' OR jsonb_array_length(member->'receipt_ids')<>expected OR jsonb_typeof(NEW.document->'minute_checks') IS DISTINCT FROM 'array' OR jsonb_array_length(NEW.document->'minute_checks')<>expected
 THEN RAISE EXCEPTION 'fleet full-member window scope invalid';END IF;
 FOR rid IN SELECT jsonb_array_elements_text(member->'receipt_ids') LOOP
  SELECT * INTO r FROM slo_receipts WHERE tenant_id=NEW.tenant_id AND id=rid AND source_id=NEW.source_id AND objective_id=NEW.objective_id AND resource_id=NEW.resource_id;
  IF r.id IS NULL OR r.writer_role<>'finops_activity' OR r.interval_start IS DISTINCT FROM cursor_time OR r.interval_end>NEW.window_end OR previous_sequence IS NOT NULL AND r.sequence<>previous_sequence+1
  OR r.received_at<r.interval_end-interval '5 seconds' OR r.received_at>r.interval_end+interval '2 minutes' OR encode(sha256(r.raw_body),'hex') IS DISTINCT FROM r.body_sha256
  THEN RAISE EXCEPTION 'fleet full-member immutable receipt coverage invalid';END IF;
  IF NEW.status='CLEAR' AND ((r.document->>'request_count')::numeric<=0 OR (r.document->'latency'->>'sample_count')::numeric<=0
   OR (r.document->>'error_count')::numeric*1000000>(r.document->>'request_count')::numeric*(objective.document->'limits'->>'max_error_rate_ppm')::numeric
   OR (r.document->>'availability_good_seconds')::numeric*1000000<(r.document->>'availability_total_seconds')::numeric*(objective.document->'limits'->>'min_availability_ppm')::numeric
   OR (SELECT coalesce(sum((b->>'count')::numeric),0) FROM jsonb_array_elements(r.document->'latency'->'buckets') b WHERE (b->>'upper_bound_ms')::numeric<=(objective.document->'limits'->>'max_p95_latency_ms')::numeric)*100<(r.document->'latency'->>'sample_count')::numeric*95
   OR (SELECT coalesce(sum((b->>'count')::numeric),0) FROM jsonb_array_elements(r.document->'latency'->'buckets') b WHERE (b->>'upper_bound_ms')::numeric<=(objective.document->'limits'->>'max_p99_latency_ms')::numeric)*100<(r.document->'latency'->>'sample_count')::numeric*99
   OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(NEW.document->'minute_checks') c WHERE c->>'receipt_id'=rid AND c->>'status'='CLEAR' AND (c->>'start')::timestamptz=r.interval_start AND (c->>'end')::timestamptz=r.interval_end))
  THEN RAISE EXCEPTION 'fleet good aggregate conceals an unhealthy or quiet minute';END IF;
  requests:=requests+(r.document->>'request_count')::numeric;errors_count:=errors_count+(r.document->>'error_count')::numeric;
  good:=good+(r.document->>'availability_good_seconds')::numeric;total:=total+(r.document->>'availability_total_seconds')::numeric;samples:=samples+(r.document->'latency'->>'sample_count')::numeric;
  observed:=observed+1;previous_sequence:=r.sequence;cursor_time:=r.interval_end;
 END LOOP;
 IF observed<>expected OR cursor_time IS DISTINCT FROM NEW.window_end OR requests IS DISTINCT FROM (member->>'request_count')::numeric OR errors_count IS DISTINCT FROM (member->>'error_count')::numeric
 OR good IS DISTINCT FROM (member->>'availability_good_seconds')::numeric OR total IS DISTINCT FROM (member->>'availability_total_seconds')::numeric OR samples IS DISTINCT FROM (member->>'latency_samples')::numeric
 OR greatest(requests,errors_count,good,total,samples)>1000000000000 THEN RAISE EXCEPTION 'fleet member counters differ from original receipts';END IF;
 IF NEW.status='CLEAR' AND samples<(objective.document->'limits'->>'min_latency_samples')::numeric THEN RAISE EXCEPTION 'fleet member latency sample minimum not met';END IF;
 IF member->'latency_buckets' IS DISTINCT FROM (
  SELECT jsonb_agg(jsonb_build_object('upper_bound_ms',bound,'count',bucket_count) ORDER BY bound NULLS LAST) FROM (
   SELECT (b->>'upper_bound_ms')::numeric AS bound,sum((b->>'count')::numeric) AS bucket_count FROM slo_receipts original CROSS JOIN LATERAL jsonb_array_elements(original.document->'latency'->'buckets') b
   WHERE original.tenant_id=NEW.tenant_id AND original.id IN(SELECT jsonb_array_elements_text(member->'receipt_ids')) GROUP BY (b->>'upper_bound_ms')::numeric
  ) buckets
 ) THEN RAISE EXCEPTION 'fleet member histogram differs from original receipt buckets';END IF;
 NEW.writer_role:='finops_api';NEW.created_at:=clock_timestamp();NEW.document:=NEW.document||jsonb_build_object('id',NEW.id,'tenant_id',NEW.tenant_id,'created_at',NEW.created_at,'writer_role',NEW.writer_role);RETURN NEW;
END $$;
CREATE TRIGGER fleet_member_window_writer BEFORE INSERT ON fleet_member_slo_windows FOR EACH ROW EXECUTE FUNCTION guard_fleet_member_window();

CREATE FUNCTION guard_fleet_cohort_metadata() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE membership jsonb;cmd fleet_commands;objective slo_objectives;member fleet_member_slo_windows;wid text;ids jsonb;baseline fleet_cohort_baselines;
BEGIN
 NEW.writer_role:='finops_api';NEW.created_at:=clock_timestamp();
 IF TG_TABLE_NAME='fleet_cohort_baselines' THEN
  SELECT document INTO membership FROM source_receipts WHERE tenant_id=NEW.tenant_id AND id=NEW.membership_receipt_id AND kind='AWS_FLEET_MEMBERSHIP' AND writer_role='finops_ingester';
  SELECT * INTO objective FROM slo_objectives WHERE tenant_id=NEW.tenant_id AND id=NEW.objective_id AND workload_id=NEW.workload_id;
  IF membership IS NULL OR membership->>'position' NOT IN('DISCOVERY','BASELINE') OR objective.id IS NULL OR NEW.document->'binding' IS DISTINCT FROM membership->'binding'
  OR NEW.document->>'membership_receipt_id' IS DISTINCT FROM NEW.membership_receipt_id OR NEW.document->>'objective_id' IS DISTINCT FROM NEW.objective_id OR (NEW.document->>'objective_version')::bigint IS DISTINCT FROM objective.version OR NEW.document->>'objective_hash' IS DISTINCT FROM objective.content_hash
  OR jsonb_typeof(NEW.document->'member_window_ids') IS DISTINCT FROM 'array' OR jsonb_array_length(NEW.document->'member_window_ids')<1 OR NEW.document->>'status' IS DISTINCT FROM 'CLEAR'
  THEN RAISE EXCEPTION 'fleet baseline immutable membership or objective invalid';END IF;
  ids:='[]'::jsonb;
  FOR wid IN SELECT jsonb_array_elements_text(NEW.document->'member_window_ids') LOOP
   SELECT * INTO member FROM fleet_member_slo_windows WHERE tenant_id=NEW.tenant_id AND id=wid AND objective_id=NEW.objective_id AND status='CLEAR';
   IF member.id IS NULL OR member.window_start IS DISTINCT FROM (NEW.document->>'window_start')::timestamptz OR member.window_end IS DISTINCT FROM (NEW.document->>'window_end')::timestamptz THEN RAISE EXCEPTION 'fleet baseline member window missing';END IF;
   ids:=ids||jsonb_build_array(member.document->'member'->>'instance_id');
  END LOOP;
  IF (SELECT jsonb_agg(v ORDER BY v) FROM jsonb_array_elements_text(ids) v) IS DISTINCT FROM membership->'old_instance_ids' OR jsonb_array_length(ids)<>(SELECT count(DISTINCT v) FROM jsonb_array_elements_text(ids) v)
  THEN RAISE EXCEPTION 'fleet baseline physical members differ from native membership';END IF;
 ELSE
  SELECT * INTO cmd FROM fleet_commands WHERE tenant_id=NEW.tenant_id AND id=NEW.command_id;PERFORM fleet_lock(NEW.tenant_id,cmd.workload_id);
  IF cmd.id IS NULL OR NEW.document->>'command_id' IS DISTINCT FROM NEW.command_id OR NEW.document->>'mode' IS DISTINCT FROM NEW.mode OR NEW.document->>'status' IS DISTINCT FROM NEW.status OR NEW.document->'binding' IS DISTINCT FROM cmd.document->'binding'
  OR NEW.mode='FORWARD' AND (cmd.operation<>'APPLY' OR NEW.status='CLEAR' AND NEW.baseline_id IS NULL) OR NEW.mode='OWNED_RECOVERY' AND (cmd.operation<>'ROLLBACK' OR NEW.baseline_id IS NOT NULL)
  THEN RAISE EXCEPTION 'fleet cohort window command mode or binding invalid';END IF;
  IF NEW.mode='FORWARD' AND NEW.baseline_id IS NOT NULL THEN
   SELECT * INTO baseline FROM fleet_cohort_baselines WHERE tenant_id=NEW.tenant_id AND id=NEW.baseline_id;
   IF baseline.id IS NULL OR baseline.document->'binding' IS DISTINCT FROM cmd.document->'binding' THEN RAISE EXCEPTION 'fleet frozen baseline belongs to another scope';END IF;
  END IF;
  IF NEW.status='CLEAR' AND (jsonb_typeof(NEW.document->'native_evaluation_ids') IS DISTINCT FROM 'array' OR jsonb_array_length(NEW.document->'native_evaluation_ids')<1
  OR jsonb_typeof(NEW.document->'slo_evaluation_ids') IS DISTINCT FROM 'array' OR jsonb_array_length(NEW.document->'slo_evaluation_ids')<1 OR jsonb_typeof(NEW.document->'member_window_ids') IS DISTINCT FROM 'array' OR jsonb_array_length(NEW.document->'member_window_ids')<1
  OR coalesce(NEW.document->>'comparison_sha256','')!~'^[a-f0-9]{64}$' OR NEW.mode='FORWARD' AND EXISTS(SELECT 1 FROM fleet_cohort_failures WHERE tenant_id=NEW.tenant_id AND execution_id=cmd.execution_id))
  THEN RAISE EXCEPTION 'fleet cohort health evidence or permanent failure gate missing';END IF;
 END IF;
 NEW.document:=NEW.document||jsonb_build_object('id',NEW.id,'tenant_id',NEW.tenant_id,'hash',NEW.content_hash,'created_at',NEW.created_at,'writer_role',NEW.writer_role);RETURN NEW;
END $$;
CREATE TRIGGER fleet_cohort_baseline_writer BEFORE INSERT ON fleet_cohort_baselines FOR EACH ROW EXECUTE FUNCTION guard_fleet_cohort_metadata();
CREATE TRIGGER fleet_cohort_window_writer BEFORE INSERT ON fleet_cohort_windows FOR EACH ROW EXECUTE FUNCTION guard_fleet_cohort_metadata();

CREATE FUNCTION guard_fleet_cohort_failure() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=public,pg_temp AS $$
DECLARE cmd fleet_commands;window_doc jsonb;BEGIN
 IF NEW.tenant_id IS DISTINCT FROM current_setting('app.tenant_id',true) THEN RAISE EXCEPTION 'fleet cohort failure tenant mismatch';END IF;
 SELECT * INTO cmd FROM fleet_commands WHERE tenant_id=NEW.tenant_id AND id=NEW.command_id;PERFORM fleet_lock(NEW.tenant_id,cmd.workload_id);
 SELECT document INTO window_doc FROM fleet_cohort_windows WHERE tenant_id=NEW.tenant_id AND id=NEW.window_id AND command_id=NEW.command_id;
 IF cmd.id IS NULL OR cmd.execution_id IS DISTINCT FROM NEW.execution_id OR window_doc IS NULL OR window_doc->>'status' NOT IN('BREACH','BLOCKED')
 OR NOT EXISTS(SELECT 1 FROM fleet_command_states WHERE tenant_id=NEW.tenant_id AND command_id=NEW.command_id AND dispatch_intent)
 THEN RAISE EXCEPTION 'fleet failure requires an authoritative unsafe dispatched window';END IF;
	NEW.writer_role:=CASE WHEN current_setting('role',true)='finops_worker' OR current_setting('role',true) IN('none','') AND session_user='finops_worker' THEN 'finops_worker' ELSE 'finops_api' END;
 NEW.created_at:=clock_timestamp();NEW.document:=jsonb_build_object('id',NEW.id,'tenant_id',NEW.tenant_id,'execution_id',NEW.execution_id,'command_id',NEW.command_id,'window_id',NEW.window_id,'reason_codes',window_doc->'reason_codes','first_failed_at',NEW.created_at,'created_at',NEW.created_at,'writer_role',NEW.writer_role,'positive_savings_eligible',false);
	UPDATE fleet_executions SET recovery_only=true,status='RECOVERY_REQUIRED' WHERE tenant_id=NEW.tenant_id AND id=NEW.execution_id AND status NOT IN('COMPLETED','ROLLED_BACK');
 RETURN NEW;
END $$;
CREATE TRIGGER fleet_cohort_failure_writer BEFORE INSERT ON fleet_cohort_failures FOR EACH ROW EXECUTE FUNCTION guard_fleet_cohort_failure();

-- Additive health evidence must refer to a factory-owned full window. This gate
-- does not run on signing/dispatch of owned rollback and never renews a parent.
CREATE FUNCTION guard_fleet_cohort_proof() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE w fleet_cohort_windows;baseline jsonb;BEGIN
 IF NEW.kind='SLO_EVALUATION' AND NEW.document->>'cohort_baseline_id' IS NOT NULL THEN
  SELECT document INTO baseline FROM fleet_cohort_baselines WHERE tenant_id=NEW.tenant_id AND id=NEW.document->>'cohort_baseline_id' AND writer_role='finops_api';
  IF baseline IS NULL OR baseline->>'status' IS DISTINCT FROM 'CLEAR' OR NEW.document->'binding' IS DISTINCT FROM baseline->'binding' OR NEW.document->>'objective_id' IS DISTINCT FROM baseline->>'objective_id' OR NEW.document->>'objective_hash' IS DISTINCT FROM baseline->>'objective_hash' OR (NEW.document->>'expires_at')::timestamptz IS DISTINCT FROM (baseline->>'expires_at')::timestamptz THEN RAISE EXCEPTION 'fleet parent baseline proof requires a private frozen baseline';END IF;
 END IF;
 IF NEW.kind<>'COHORT_HEALTH' THEN RETURN NEW;END IF;
 SELECT * INTO w FROM fleet_cohort_windows WHERE tenant_id=NEW.tenant_id AND id=NEW.document->>'cohort_window_id' AND status='CLEAR' AND writer_role='finops_api';
 IF w.id IS NULL OR NEW.document->>'command_id' IS DISTINCT FROM w.command_id OR NEW.document->'binding' IS DISTINCT FROM w.document->'binding'
 OR NEW.document->>'mode' IS DISTINCT FROM w.mode OR NEW.document->>'membership_receipt_id' IS DISTINCT FROM w.document->>'membership_receipt_id'
 OR NEW.document->>'comparison_sha256' IS DISTINCT FROM w.document->>'comparison_sha256' OR NEW.document->'native_evaluation_ids' IS DISTINCT FROM w.document->'native_evaluation_ids'
 OR NEW.document->'slo_evaluation_ids' IS DISTINCT FROM w.document->'slo_evaluation_ids' OR NEW.document->>'status' IS DISTINCT FROM 'CLEAR'
 THEN RAISE EXCEPTION 'fleet cohort proof requires private full-window factory evidence';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER fleet_cohort_proof_factory BEFORE INSERT ON fleet_proof_sets FOR EACH ROW EXECUTE FUNCTION guard_fleet_cohort_proof();

CREATE FUNCTION fleet_cohort_native_authority(p_tenant text,p_id text,p_binding jsonb,p_start timestamptz,p_end timestamptz,p_profile jsonb,p_fresh boolean) RETURNS boolean LANGUAGE plpgsql AS $$
DECLARE native telemetry_evaluations;connection telemetry_connections;metric jsonb;metric_name text;BEGIN
 SELECT * INTO native FROM telemetry_evaluations WHERE tenant_id=p_tenant AND id=p_id;
 SELECT * INTO connection FROM telemetry_connections WHERE tenant_id=p_tenant AND id=native.connection_id ORDER BY version DESC LIMIT 1;
 IF native.id IS NULL OR native.document->'binding' IS DISTINCT FROM p_binding OR native.document->'evaluation'->>'status' IS DISTINCT FROM 'READY' OR coalesce((native.document->'evaluation'->>'history_days')::integer,0)<>0
 OR connection.id IS NULL OR connection.config->>'enabled' IS DISTINCT FROM 'true' OR connection.config_hash IS DISTINCT FROM native.document->>'config_hash'
 OR EXISTS(SELECT 1 FROM telemetry_source_revocations WHERE tenant_id=p_tenant AND revision_id=native.revision_id)
 OR EXISTS(SELECT 1 FROM telemetry_source_revisions revision WHERE revision.tenant_id=p_tenant AND revision.id=native.revision_id AND revision.connection_version<>connection.version)
 OR p_fresh AND ((native.document->'evaluation'->>'evaluated_at')::timestamptz<clock_timestamp()-interval '5 minutes' OR (native.document->'evaluation'->>'evaluated_at')::timestamptz>clock_timestamp()+interval '5 seconds')
 OR jsonb_typeof(native.document->'receipt_ids') IS DISTINCT FROM 'array' OR jsonb_array_length(native.document->'receipt_ids')=0
 OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(native.document->'receipt_ids') receipt_id WHERE NOT EXISTS(SELECT 1 FROM telemetry_receipts receipt WHERE receipt.tenant_id=p_tenant AND receipt.id=receipt_id AND receipt.revision_id=native.revision_id))
 THEN RETURN false;END IF;
 FOREACH metric_name IN ARRAY ARRAY['cpu_utilization','memory_utilization'] LOOP
  SELECT value INTO metric FROM jsonb_array_elements(native.document->'evaluation'->'metrics') m WHERE m->>'metric'=metric_name AND m->>'status'='READY' AND (m->>'coverage_ppm')::bigint=1000000 AND (m->>'unknown_duration_ns')::numeric=0 AND (m->>'observed_duration_ns')::numeric>=extract(epoch FROM p_end-p_start)*1000000000 AND (m->>'start')::timestamptz<=p_start AND (m->>'end')::timestamptz>=p_end;
  IF metric IS NULL OR metric->>'maximum' IS NULL OR metric->>'unit' NOT IN('ratio','percent') OR (metric->>'maximum')::numeric<0 OR (metric->>'maximum')::numeric*(CASE WHEN metric->>'unit'='ratio' THEN 1000000 ELSE 10000 END)>(CASE WHEN metric_name='cpu_utilization' THEN least((p_profile->'saturation'->>'cpu_p99_ppm')::numeric,1000000-(p_profile->'headroom'->>'cpu_free_ppm')::numeric) ELSE least((p_profile->'saturation'->>'memory_p99_ppm')::numeric,1000000-(p_profile->'headroom'->>'memory_free_ppm')::numeric) END) THEN RETURN false;END IF;
 END LOOP;
 RETURN true;
END $$;

CREATE FUNCTION fleet_cohort_membership_authority(p_tenant text,p_id text,p_binding jsonb,p_max_age interval) RETURNS boolean LANGUAGE plpgsql AS $$
DECLARE receipt source_receipts;registration source_registrations;revision source_revisions;prefix text;BEGIN
 SELECT * INTO receipt FROM source_receipts WHERE tenant_id=p_tenant AND id=p_id AND kind='AWS_FLEET_MEMBERSHIP' AND writer_role='finops_ingester';
 SELECT * INTO registration FROM source_registrations WHERE tenant_id=p_tenant AND id=receipt.source_id;
 SELECT * INTO revision FROM source_revisions WHERE tenant_id=p_tenant AND id=receipt.revision_id AND source_id=receipt.source_id AND writer_role='finops_ingester';
 prefix:='tenant/'||p_tenant||'/fleet/';
 RETURN receipt.id IS NOT NULL AND receipt.document->'binding'=p_binding AND registration.document->>'enabled'='true' AND coalesce(registration.document->>'revoked','false')<>'true'
 AND registration.version=(receipt.document->>'registration_version')::bigint AND (registration.document->>'payer_account_id'=p_binding->>'account_id' OR registration.document->'usage_account_ids' ? (p_binding->>'account_id'))
 AND receipt.document->>'read_role_binding_id'=registration.document->>'read_role_binding_id' AND revision.id IS NOT NULL AND revision.document->>'config_hash'=receipt.document->>'config_hash' AND (revision.document->>'registration_version')::bigint=registration.version
 AND coalesce(receipt.document->'raw_object'->>'bucket','')<>'' AND coalesce(receipt.document->'raw_object'->>'version_id','') NOT IN('','null') AND receipt.document->'raw_object'->>'body_sha256'~'^[a-f0-9]{64}$'
 AND left(receipt.document->'raw_object'->>'key',length(prefix))=prefix AND position('..' IN receipt.document->'raw_object'->>'key')=0
 AND (receipt.document->>'collected_at')::timestamptz BETWEEN clock_timestamp()-p_max_age AND clock_timestamp()+interval '5 seconds';
END $$;

CREATE FUNCTION guard_fleet_cohort_baseline_authority() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE profile jsonb;objective slo_objectives;member fleet_member_slo_windows;selected_id text;BEGIN
 SELECT document INTO profile FROM workload_safety_profiles WHERE tenant_id=NEW.tenant_id AND workload_id=NEW.workload_id ORDER BY version DESC LIMIT 1;
 SELECT * INTO objective FROM slo_objectives WHERE tenant_id=NEW.tenant_id AND workload_id=NEW.workload_id ORDER BY version DESC LIMIT 1;
 IF profile IS NULL OR profile->>'statefulness' IS DISTINCT FROM 'STATELESS' OR NEW.document->>'safety_profile_id' IS DISTINCT FROM profile->>'id' OR NEW.document->>'safety_profile_hash' IS DISTINCT FROM profile->>'hash'
 OR objective.id IS DISTINCT FROM NEW.objective_id OR objective.document->'regression'->>'enabled' IS DISTINCT FROM 'true'
 OR (NEW.document->>'window_end')::timestamptz IS DISTINCT FROM date_trunc('minute',clock_timestamp()) OR (NEW.document->>'window_start')::timestamptz IS DISTINCT FROM (NEW.document->>'window_end')::timestamptz-(objective.document->>'evaluation_minutes')::integer*interval '1 minute'
 OR (NEW.document->>'expires_at')::timestamptz IS DISTINCT FROM (NEW.document->>'window_end')::timestamptz+interval '6 hours'
 OR fleet_cohort_membership_authority(NEW.tenant_id,NEW.membership_receipt_id,NEW.document->'binding',interval '5 minutes') IS DISTINCT FROM true
 THEN RAISE EXCEPTION 'fleet frozen baseline needs fresh current native authority and exact requirements';END IF;
 FOR selected_id IN SELECT jsonb_array_elements_text(NEW.document->'member_window_ids') LOOP
  SELECT * INTO member FROM fleet_member_slo_windows WHERE tenant_id=NEW.tenant_id AND id=selected_id;
  IF NOT EXISTS(SELECT 1 FROM jsonb_array_elements_text(NEW.document->'native_evaluation_ids') native_id WHERE fleet_cohort_native_authority(NEW.tenant_id,native_id,member.document->'member'->'binding',member.window_start,member.window_end,profile,true)) THEN RAISE EXCEPTION 'fleet baseline full native member window missing';END IF;
 END LOOP;
 RETURN NEW;
END $$;
CREATE TRIGGER fleet_cohort_baseline_authority BEFORE INSERT ON fleet_cohort_baselines FOR EACH ROW EXECUTE FUNCTION guard_fleet_cohort_baseline_authority();

CREATE FUNCTION fleet_cohort_minimum_program_seconds(p jsonb) RETURNS bigint LANGUAGE plpgsql IMMUTABLE STRICT AS $$
DECLARE s jsonb;previous_count bigint:=0;target_count bigint;steps bigint;seconds bigint:=0;flight bigint;unavailable bigint;baseline bigint;BEGIN
 flight:=(p->'budget'->>'max_in_flight')::bigint;unavailable:=(p->'budget'->>'max_unavailable')::bigint;baseline:=(p->'budget'->>'baseline_count')::bigint;
 IF flight NOT BETWEEN 1 AND 2 OR unavailable NOT BETWEEN 1 AND 2 OR baseline NOT BETWEEN 1 AND 500000 THEN RETURN NULL;END IF;
 FOR s IN SELECT value FROM jsonb_array_elements(p->'stages') LOOP
  target_count:=(s->>'target_candidate_count')::bigint;
  IF target_count<previous_count OR target_count>baseline THEN RETURN NULL;END IF;
  CASE s->>'kind'
  WHEN 'PREPARE_CANDIDATE' THEN seconds:=seconds+300;
  WHEN 'CANARY_10','EXPAND_25','EXPAND_50','EXPAND_100' THEN
   steps:=(target_count-previous_count+flight-1)/flight;seconds:=seconds+steps*420+300+greatest(120,(s->>'minimum_observation_seconds')::bigint);
  WHEN 'DRAIN_OLD' THEN
   steps:=(baseline+least(flight,unavailable)-1)/least(flight,unavailable);seconds:=seconds+steps*300+(steps-1)*120+greatest(120,(s->>'minimum_observation_seconds')::bigint);
  ELSE RETURN NULL;
  END CASE;
  previous_count:=target_count;
 END LOOP;
 RETURN seconds;
END $$;

CREATE FUNCTION fleet_cohort_histogram_bounds(hist jsonb,percent integer) RETURNS jsonb LANGUAGE plpgsql IMMUTABLE STRICT AS $$
DECLARE b jsonb;n numeric;rank numeric;cumulative numeric:=0;lower_bound numeric:=0;BEGIN
 IF jsonb_typeof(hist)<>'array' OR percent NOT IN(95,99) THEN RETURN NULL;END IF;
 SELECT sum((v->>'count')::numeric) INTO n FROM jsonb_array_elements(hist) v;
 IF n IS NULL OR n<=0 OR n>1000000000000 THEN RETURN NULL;END IF;rank:=ceil(n*percent/100);
 FOR b IN SELECT value FROM jsonb_array_elements(hist) LOOP
  cumulative:=cumulative+(b->>'count')::numeric;
  IF cumulative>=rank THEN RETURN jsonb_build_object('lower',lower_bound,'upper',b->'upper_bound_ms');END IF;
  IF b->'upper_bound_ms'<>'null'::jsonb THEN lower_bound:=(b->>'upper_bound_ms')::numeric;END IF;
 END LOOP;
 RETURN NULL;
END $$;
CREATE FUNCTION fleet_cohort_regression_clear(current_hist jsonb,baseline_hist jsonb,maximum_percent integer) RETURNS boolean LANGUAGE plpgsql IMMUTABLE STRICT AS $$
DECLARE percentile integer;c jsonb;b jsonb;BEGIN
 IF maximum_percent NOT BETWEEN 0 AND 1000 THEN RETURN false;END IF;
 FOREACH percentile IN ARRAY ARRAY[95,99] LOOP
  c:=fleet_cohort_histogram_bounds(current_hist,percentile);b:=fleet_cohort_histogram_bounds(baseline_hist,percentile);
  IF c IS NULL OR b IS NULL OR c->'upper'='null'::jsonb OR b->'upper'='null'::jsonb OR (b->>'lower')::numeric<=0 OR (c->>'upper')::numeric*100>(b->>'lower')::numeric*(100+maximum_percent) THEN RETURN false;END IF;
 END LOOP;RETURN true;
END $$;
CREATE FUNCTION fleet_cohort_window_histogram(p_tenant text,ids jsonb) RETURNS jsonb LANGUAGE sql STABLE AS $$
 SELECT jsonb_agg(jsonb_build_object('upper_bound_ms',bound,'count',bucket_count) ORDER BY bound NULLS LAST) FROM (
  SELECT (b->>'upper_bound_ms')::numeric AS bound,sum((b->>'count')::numeric) AS bucket_count FROM fleet_member_slo_windows w CROSS JOIN LATERAL jsonb_array_elements(w.document->'member'->'latency_buckets') b
  WHERE w.tenant_id=p_tenant AND w.id IN(SELECT jsonb_array_elements_text(ids)) GROUP BY (b->>'upper_bound_ms')::numeric
 ) buckets
$$;

CREATE FUNCTION guard_fleet_cohort_window_authority() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE cmd fleet_commands;parent jsonb;child jsonb;owned jsonb;membership source_receipts;registration source_registrations;revision source_revisions;baseline fleet_cohort_baselines;
 objective slo_objectives;profile jsonb;member fleet_member_slo_windows;selected_id text;native jsonb;native_metric jsonb;current_slo jsonb;current_source jsonb;
 anchor timestamptz;first_minute timestamptz;last_minute timestamptz;minimum_seconds integer;is_terminal boolean;preparation boolean:=false;terminal_drain boolean:=false;prior_window jsonb;seen_ids jsonb:='[]'::jsonb;member_id text;
 base_hist jsonb;blue_hist jsonb;minute_control jsonb;receipt slo_receipts;maximum_regression integer;timeline jsonb;observation_time timestamptz;minute_time timestamptz;
BEGIN
 IF NEW.status<>'CLEAR' THEN RETURN NEW;END IF;
 SELECT * INTO cmd FROM fleet_commands WHERE tenant_id=NEW.tenant_id AND id=NEW.command_id;PERFORM fleet_lock(NEW.tenant_id,cmd.workload_id);
 SELECT document INTO parent FROM fleet_plans WHERE tenant_id=NEW.tenant_id AND id=cmd.parent_id;
 SELECT document->'plan' INTO child FROM fleet_children WHERE tenant_id=NEW.tenant_id AND id=cmd.child_id;
 SELECT c.document INTO owned FROM fleet_callbacks c JOIN fleet_command_states s ON s.tenant_id=c.tenant_id AND s.owned_receipt_id=c.id WHERE s.tenant_id=NEW.tenant_id AND s.command_id=NEW.command_id AND s.outcome='APPLIED' AND NOT s.restored;
 SELECT * INTO objective FROM slo_objectives WHERE tenant_id=NEW.tenant_id AND workload_id=cmd.workload_id ORDER BY version DESC LIMIT 1;
 SELECT document INTO profile FROM workload_safety_profiles WHERE tenant_id=NEW.tenant_id AND workload_id=cmd.workload_id ORDER BY version DESC LIMIT 1;
 IF owned IS NULL OR objective.id IS NULL OR profile IS NULL OR NEW.mode='FORWARD' AND profile->>'statefulness' IS DISTINCT FROM 'STATELESS' OR NEW.document->>'safety_profile_id' IS DISTINCT FROM profile->>'id' OR NEW.document->>'safety_profile_hash' IS DISTINCT FROM profile->>'hash' THEN RAISE EXCEPTION 'fleet cohort requires owned apply and current explicit requirements';END IF;
 anchor:=(owned->>'received_at')::timestamptz;anchor:=date_trunc('minute',anchor)+CASE WHEN anchor=date_trunc('minute',anchor) THEN interval '0' ELSE interval '1 minute' END;
 first_minute:=(NEW.document->>'window_start')::timestamptz;last_minute:=(NEW.document->>'window_end')::timestamptz;
 IF first_minute IS NULL OR last_minute IS NULL OR first_minute<anchor OR last_minute-first_minute NOT BETWEEN interval '2 minutes' AND interval '60 minutes' OR date_trunc('minute',first_minute) IS DISTINCT FROM first_minute OR date_trunc('minute',last_minute) IS DISTINCT FROM last_minute OR last_minute>clock_timestamp()+interval '5 seconds' OR last_minute<clock_timestamp()-interval '2 minutes' THEN RAISE EXCEPTION 'fleet cohort complete current observation bounds invalid';END IF;
 IF NEW.mode='FORWARD' THEN
  SELECT * INTO baseline FROM fleet_cohort_baselines WHERE tenant_id=NEW.tenant_id AND id=NEW.baseline_id;
  IF baseline.id IS NULL OR baseline.document->>'objective_id' IS DISTINCT FROM objective.id OR baseline.document->>'objective_hash' IS DISTINCT FROM objective.content_hash OR baseline.document->>'safety_profile_id' IS DISTINCT FROM profile->>'id' OR baseline.document->>'safety_profile_hash' IS DISTINCT FROM profile->>'hash' OR objective.document->'regression'->>'enabled' IS DISTINCT FROM 'true' THEN RAISE EXCEPTION 'fleet frozen objective or safety profile changed';END IF;
  IF fleet_cohort_membership_authority(NEW.tenant_id,baseline.document->>'membership_receipt_id',baseline.document->'binding',interval '24 hours') IS DISTINCT FROM true
  OR EXISTS(SELECT 1 FROM fleet_member_slo_windows baseline_member WHERE baseline_member.tenant_id=NEW.tenant_id AND baseline.document->'member_window_ids' ? baseline_member.id AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements_text(baseline.document->'native_evaluation_ids') native_id WHERE fleet_cohort_native_authority(NEW.tenant_id,native_id,baseline_member.document->'member'->'binding',baseline_member.window_start,baseline_member.window_end,profile,false)))
  THEN RAISE EXCEPTION 'fleet historical baseline source authority revoked or superseded';END IF;
  SELECT value INTO timeline FROM jsonb_array_elements(parent->'stages') WHERE value->>'id'=child->>'stage_id';
  preparation:=timeline->>'kind'='PREPARE_CANDIDATE' AND (child->'transition'->>'candidate_after')::integer=0 AND (child->'transition'->>'traffic_after')::integer=0;
  terminal_drain:=timeline->>'kind'='DRAIN_OLD' AND (child->'transition'->>'old_after')::integer=0;
  is_terminal:=(child->'transition'->>'candidate_after')::integer=(timeline->>'target_candidate_count')::integer AND (child->'transition'->>'traffic_after')::integer=(timeline->>'target_traffic_percent')::integer AND (timeline->>'kind'<>'DRAIN_OLD' OR (child->'transition'->>'old_after')::integer=0);
  minimum_seconds:=CASE WHEN is_terminal THEN greatest(120,(timeline->>'minimum_observation_seconds')::integer) ELSE 120 END;
  IF first_minute IS DISTINCT FROM anchor OR last_minute IS DISTINCT FROM anchor+ceil(minimum_seconds::numeric/60)*interval '1 minute' THEN RAISE EXCEPTION 'fleet signed stage window cannot slide or shorten';END IF;
  base_hist:=fleet_cohort_window_histogram(NEW.tenant_id,baseline.document->'member_window_ids');maximum_regression:=(objective.document->'regression'->>'max_percent')::integer;
 ELSE
  IF cmd.operation IS DISTINCT FROM 'ROLLBACK' OR NEW.baseline_id IS NOT NULL OR last_minute IS DISTINCT FROM date_trunc('minute',clock_timestamp()) OR last_minute-first_minute IS DISTINCT FROM (objective.document->>'evaluation_minutes')::integer*interval '1 minute' THEN RAISE EXCEPTION 'fleet owned recovery requires fresh independent hard-health window';END IF;
 END IF;
 SELECT * INTO membership FROM source_receipts WHERE tenant_id=NEW.tenant_id AND id=NEW.document->>'membership_receipt_id' AND kind='AWS_FLEET_MEMBERSHIP' AND writer_role='finops_ingester';
 SELECT * INTO registration FROM source_registrations WHERE tenant_id=NEW.tenant_id AND id=membership.source_id;
 SELECT * INTO revision FROM source_revisions WHERE tenant_id=NEW.tenant_id AND id=membership.revision_id AND source_id=membership.source_id;
 IF membership.id IS NULL OR membership.document->>'position' IS DISTINCT FROM 'AFTER' OR membership.document->>'child_id' IS DISTINCT FROM cmd.child_id OR membership.document->>'child_sha256' IS DISTINCT FROM cmd.document->>'child_sha256' OR membership.document->'binding' IS DISTINCT FROM cmd.document->'binding'
 OR membership.document->'old_instance_ids' IS DISTINCT FROM owned->'old_instance_ids' OR membership.document->'candidate_instance_ids' IS DISTINCT FROM owned->'candidate_instance_ids'
 OR registration.document->>'enabled' IS DISTINCT FROM 'true' OR registration.document->>'revoked'='true' OR registration.version IS DISTINCT FROM (membership.document->>'registration_version')::bigint OR revision.writer_role IS DISTINCT FROM 'finops_ingester' OR revision.document->>'config_hash' IS DISTINCT FROM membership.document->>'config_hash'
 THEN RAISE EXCEPTION 'fleet cohort current native membership authority invalid';END IF;
 IF fleet_cohort_membership_authority(NEW.tenant_id,membership.id,cmd.document->'binding',interval '5 minutes') IS DISTINCT FROM true THEN RAISE EXCEPTION 'fleet cohort requires versioned current native raw provenance';END IF;
 IF NOT EXISTS(SELECT 1 FROM jsonb_array_elements(membership.document->'groups') g WHERE g->>'name'=parent->'old'->>'id' AND (g->>'desired')::integer=jsonb_array_length(owned->'old_instance_ids') AND g->>'minimum'=g->>'desired' AND g->>'maximum'=g->>'desired')
 OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(membership.document->'groups') g WHERE g->>'name'=parent->'candidate'->>'id' AND (g->>'desired')::integer=jsonb_array_length(owned->'candidate_instance_ids') AND g->>'minimum'=g->>'desired' AND g->>'maximum'=g->>'desired')
 OR NEW.mode='FORWARD' AND NOT preparation AND jsonb_array_length(owned->'candidate_instance_ids')=0 OR NEW.mode='FORWARD' AND NOT terminal_drain AND jsonb_array_length(owned->'old_instance_ids')=0
 THEN RAISE EXCEPTION 'fleet native physical zero or counts must be explicit';END IF;
 IF terminal_drain THEN
  SELECT w.document INTO prior_window FROM fleet_cohort_windows w JOIN fleet_commands c ON c.tenant_id=w.tenant_id AND c.id=w.command_id JOIN fleet_children ch ON ch.tenant_id=c.tenant_id AND ch.id=c.child_id JOIN fleet_command_states state ON state.tenant_id=c.tenant_id AND state.command_id=c.id JOIN fleet_reservations reservation ON reservation.tenant_id=c.tenant_id AND reservation.command_id=c.id JOIN fleet_callbacks callback ON callback.tenant_id=c.tenant_id AND callback.id=state.owned_receipt_id
  WHERE w.tenant_id=NEW.tenant_id AND w.id=NEW.document->'comparison'->>'prior_control_window_id' AND w.content_hash=NEW.document->'comparison'->>'prior_control_window_hash' AND c.execution_id=cmd.execution_id AND (ch.document->'plan'->>'sequence')::numeric<(child->>'sequence')::numeric AND w.mode='FORWARD' AND w.status='CLEAR' AND c.operation='APPLY' AND (ch.document->'plan'->'transition'->>'traffic_after')::integer=100 AND (ch.document->'plan'->'transition'->>'old_after')::integer>0 AND reservation.released_at IS NOT NULL AND jsonb_array_length(callback.document->'old_instance_ids')>0 AND callback.document->'candidate_instance_ids'=owned->'candidate_instance_ids' AND w.document->'comparison'->'full_window' IS NOT NULL
  AND EXISTS(SELECT 1 FROM jsonb_array_elements(parent->'stages') stage WHERE stage->>'id'=ch.document->'plan'->>'stage_id' AND stage->>'kind'='EXPAND_100');
  IF prior_window IS NULL OR prior_window->>'objective_id' IS DISTINCT FROM objective.id OR prior_window->>'objective_hash' IS DISTINCT FROM objective.content_hash OR prior_window->>'safety_profile_id' IS DISTINCT FROM profile->>'id' OR prior_window->>'safety_profile_hash' IS DISTINCT FROM profile->>'hash'
  OR EXISTS(SELECT 1 FROM fleet_commands c JOIN fleet_children ch ON ch.tenant_id=c.tenant_id AND ch.id=c.child_id JOIN fleet_command_states state ON state.tenant_id=c.tenant_id AND state.command_id=c.id JOIN fleet_reservations reservation ON reservation.tenant_id=c.tenant_id AND reservation.command_id=c.id WHERE c.tenant_id=NEW.tenant_id AND c.execution_id=cmd.execution_id AND (ch.document->'plan'->>'sequence')::numeric<(child->>'sequence')::numeric AND (state.outcome NOT IN('APPLIED','NO_OP','DEFINITELY_NOT_APPLIED') OR state.dispatch_intent AND reservation.released_at IS NULL))
  THEN RAISE EXCEPTION 'fleet final drain requires preceding accepted identical green full control and resolved changes';END IF;
  IF fleet_cohort_membership_authority(NEW.tenant_id,prior_window->>'membership_receipt_id',cmd.document->'binding',interval '24 hours') IS DISTINCT FROM true
  OR EXISTS(SELECT 1 FROM jsonb_array_elements_text(prior_window->'native_evaluation_ids') native_id JOIN telemetry_evaluations native ON native.tenant_id=NEW.tenant_id AND native.id=native_id WHERE fleet_cohort_native_authority(NEW.tenant_id,native_id,native.document->'binding',(prior_window->>'window_start')::timestamptz,(prior_window->>'window_end')::timestamptz,profile,false) IS DISTINCT FROM true)
  THEN RAISE EXCEPTION 'fleet prior full control source authority changed';END IF;
 END IF;
 FOR minute_time IN SELECT generate_series(first_minute,last_minute-interval '1 minute',interval '1 minute') LOOP
  IF NOT EXISTS(SELECT 1 FROM source_receipts r WHERE r.tenant_id=NEW.tenant_id AND r.id IN(SELECT jsonb_array_elements_text(NEW.document->'membership_timeline_ids')) AND r.kind='AWS_FLEET_MEMBERSHIP' AND r.writer_role='finops_ingester' AND r.source_id=membership.source_id AND r.document->>'position'='AFTER' AND r.document->>'child_id'=cmd.child_id AND r.document->>'child_sha256'=cmd.document->>'child_sha256' AND r.document->'binding'=cmd.document->'binding' AND r.document->>'config_hash'=membership.document->>'config_hash' AND r.document->'old_instance_ids'=owned->'old_instance_ids' AND r.document->'candidate_instance_ids'=owned->'candidate_instance_ids' AND date_trunc('minute',(r.document->>'collected_at')::timestamptz)=minute_time AND fleet_cohort_membership_authority(NEW.tenant_id,r.id,cmd.document->'binding',interval '24 hours')) THEN RAISE EXCEPTION 'fleet native physical membership timeline has a gap';END IF;
 END LOOP;
 IF EXISTS(SELECT 1 FROM source_receipts r WHERE r.tenant_id=NEW.tenant_id AND r.id IN(SELECT jsonb_array_elements_text(NEW.document->'membership_timeline_ids')) AND (r.document->'old_instance_ids' IS DISTINCT FROM owned->'old_instance_ids' OR r.document->'candidate_instance_ids' IS DISTINCT FROM owned->'candidate_instance_ids')) THEN RAISE EXCEPTION 'fleet native physical membership changed within observation';END IF;
 FOR selected_id IN SELECT jsonb_array_elements_text(NEW.document->'member_window_ids') LOOP
  SELECT * INTO member FROM fleet_member_slo_windows WHERE tenant_id=NEW.tenant_id AND fleet_member_slo_windows.id=selected_id AND objective_id=objective.id AND status='CLEAR';
  IF member.id IS NULL OR member.window_start IS DISTINCT FROM first_minute OR member.window_end IS DISTINCT FROM last_minute OR member.document->'member'->'binding'->>'workload_id' IS DISTINCT FROM cmd.workload_id OR member.document->'member'->'binding'->>'account_id' IS DISTINCT FROM cmd.document->'binding'->>'account_id' OR member.document->'member'->'binding'->>'region' IS DISTINCT FROM cmd.document->'binding'->>'region' THEN RAISE EXCEPTION 'fleet member window belongs to another scope';END IF;
  member_id:=member.document->'member'->>'instance_id';seen_ids:=seen_ids||jsonb_build_array(member_id);
  SELECT e.document INTO native FROM telemetry_evaluations e WHERE e.tenant_id=NEW.tenant_id AND e.id IN(SELECT jsonb_array_elements_text(NEW.document->'native_evaluation_ids')) AND e.document->'binding'=member.document->'member'->'binding' AND e.document->'evaluation'->>'status'='READY' AND (e.document->'evaluation'->>'start')::timestamptz<=first_minute AND (e.document->'evaluation'->>'end')::timestamptz>=last_minute AND e.created_at>=clock_timestamp()-interval '5 minutes' AND NOT EXISTS(SELECT 1 FROM telemetry_source_revocations v WHERE v.tenant_id=e.tenant_id AND v.revision_id=e.revision_id) AND NOT EXISTS(SELECT 1 FROM telemetry_connections c JOIN telemetry_source_revisions r ON r.tenant_id=c.tenant_id AND r.connection_id=c.id WHERE r.tenant_id=e.tenant_id AND r.id=e.revision_id AND c.version>r.connection_version) ORDER BY e.created_at DESC LIMIT 1;
  IF native IS NULL THEN RAISE EXCEPTION 'fleet current native member window missing';END IF;
  IF fleet_cohort_native_authority(NEW.tenant_id,native->>'id',member.document->'member'->'binding',first_minute,last_minute,profile,true) IS DISTINCT FROM true THEN RAISE EXCEPTION 'fleet full native member authority or headroom changed';END IF;
  FOREACH member_id IN ARRAY ARRAY['cpu_utilization','memory_utilization'] LOOP
   SELECT value INTO native_metric FROM jsonb_array_elements(native->'evaluation'->'metrics') m WHERE m->>'metric'=member_id AND m->>'status'='READY' AND (m->>'coverage_ppm')::bigint=1000000 AND (m->>'unknown_duration_ns')::numeric=0 AND (m->>'start')::timestamptz<=first_minute AND (m->>'end')::timestamptz>=last_minute;
   IF native_metric IS NULL OR native_metric->>'maximum' IS NULL OR native_metric->>'unit' NOT IN('ratio','percent') OR (native_metric->>'maximum')::numeric<0 OR (native_metric->>'maximum')::numeric*(CASE WHEN native_metric->>'unit'='ratio' THEN 1000000 ELSE 10000 END)>(CASE WHEN member_id='cpu_utilization' THEN least((profile->'saturation'->>'cpu_p99_ppm')::numeric,1000000-(profile->'headroom'->>'cpu_free_ppm')::numeric) ELSE least((profile->'saturation'->>'memory_p99_ppm')::numeric,1000000-(profile->'headroom'->>'memory_free_ppm')::numeric) END) THEN RAISE EXCEPTION 'fleet native member headroom unknown or exceeded';END IF;
  END LOOP;
  SELECT document INTO current_slo FROM slo_evaluations e WHERE e.tenant_id=NEW.tenant_id AND e.id IN(SELECT jsonb_array_elements_text(NEW.document->'slo_evaluation_ids')) AND e.resource_id=member.resource_id AND e.objective_id=objective.id AND e.document->'evaluation'->>'status'='CLEAR' AND e.document->'evaluation'->>'objective_hash'=objective.content_hash AND e.document->'evaluation'->>'source_hash'=member.document->'member'->>'source_sha256' AND (e.document->'evaluation'->>'window_end')::timestamptz>=clock_timestamp()-interval '2 minutes' ORDER BY e.created_at DESC LIMIT 1;
  IF current_slo IS NULL THEN RAISE EXCEPTION 'fleet distinct fresh short-window SLO evaluation missing';END IF;
 END LOOP;
 IF (SELECT jsonb_agg(v ORDER BY v) FROM jsonb_array_elements_text(seen_ids) v) IS DISTINCT FROM (SELECT jsonb_agg(v ORDER BY v) FROM jsonb_array_elements_text((owned->'old_instance_ids')||(owned->'candidate_instance_ids')) v) OR jsonb_array_length(seen_ids)<>(SELECT count(DISTINCT v) FROM jsonb_array_elements_text(seen_ids) v) THEN RAISE EXCEPTION 'fleet every physical member requires an exact window';END IF;
 IF NEW.mode='FORWARD' THEN
  SELECT fleet_cohort_window_histogram(NEW.tenant_id,jsonb_agg(w.id)) INTO blue_hist FROM fleet_member_slo_windows w WHERE w.tenant_id=NEW.tenant_id AND w.id IN(SELECT jsonb_array_elements_text(NEW.document->'member_window_ids')) AND owned->'old_instance_ids' ? (w.document->'member'->>'instance_id');
  FOR selected_id IN SELECT jsonb_array_elements_text(NEW.document->'member_window_ids') LOOP
   SELECT * INTO member FROM fleet_member_slo_windows w WHERE w.tenant_id=NEW.tenant_id AND w.id=selected_id;
   IF fleet_cohort_regression_clear(member.document->'member'->'latency_buckets',base_hist,maximum_regression) IS DISTINCT FROM true OR NOT terminal_drain AND owned->'candidate_instance_ids' ? (member.document->'member'->>'instance_id') AND fleet_cohort_regression_clear(member.document->'member'->'latency_buckets',blue_hist,maximum_regression) IS DISTINCT FROM true THEN RAISE EXCEPTION 'fleet bounded cohort latency regression cannot prove clear';END IF;
   FOR receipt IN SELECT r.* FROM slo_receipts r WHERE r.tenant_id=NEW.tenant_id AND r.id IN(SELECT jsonb_array_elements_text(member.document->'member'->'receipt_ids')) LOOP
    SELECT jsonb_agg(jsonb_build_object('upper_bound_ms',bound,'count',bucket_count) ORDER BY bound NULLS LAST) INTO minute_control FROM (
     SELECT (bucket->>'upper_bound_ms')::numeric AS bound,sum((bucket->>'count')::numeric) AS bucket_count FROM slo_receipts r CROSS JOIN LATERAL jsonb_array_elements(r.document->'latency'->'buckets') bucket
     WHERE r.tenant_id=NEW.tenant_id AND r.objective_id=objective.id AND r.interval_start=receipt.interval_start AND r.document->'binding'->>'workload_id'=cmd.workload_id AND owned->'old_instance_ids' ? (r.document->'binding'->>'provider_resource_id') GROUP BY (bucket->>'upper_bound_ms')::numeric
    ) buckets;
    IF fleet_cohort_regression_clear(receipt.document->'latency'->'buckets',base_hist,maximum_regression) IS DISTINCT FROM true OR NOT terminal_drain AND owned->'candidate_instance_ids' ? (member.document->'member'->>'instance_id') AND fleet_cohort_regression_clear(receipt.document->'latency'->'buckets',minute_control,maximum_regression) IS DISTINCT FROM true THEN RAISE EXCEPTION 'fleet low-volume minute latency regression cannot be averaged away';END IF;
   END LOOP;
  END LOOP;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER fleet_cohort_window_authority BEFORE INSERT ON fleet_cohort_windows FOR EACH ROW EXECUTE FUNCTION guard_fleet_cohort_window_authority();

-- Releasing a global reservation is authority too: recheck source/objective and
-- the immutable failure latch under the same lock before the013 release runs.
CREATE FUNCTION guard_fleet_cohort_release() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=public,pg_temp AS $$
DECLARE cmd fleet_commands;health jsonb;window_doc jsonb;proof jsonb;membership source_receipts;registration source_registrations;objective slo_objectives;profile jsonb;BEGIN
 IF NEW.tenant_id IS DISTINCT FROM current_setting('app.tenant_id',true) THEN RAISE EXCEPTION 'fleet release tenant mismatch';END IF;
 SELECT * INTO cmd FROM fleet_commands WHERE tenant_id=NEW.tenant_id AND id=NEW.command_id;PERFORM fleet_lock(NEW.tenant_id,cmd.workload_id);
 SELECT document INTO health FROM fleet_health_evidence WHERE tenant_id=NEW.tenant_id AND id=NEW.evidence_id AND command_id=NEW.command_id;
 SELECT document INTO proof FROM fleet_proof_sets WHERE tenant_id=NEW.tenant_id AND id=health->>'cohort_proof_id' AND kind='COHORT_HEALTH';
 SELECT document INTO window_doc FROM fleet_cohort_windows WHERE tenant_id=NEW.tenant_id AND id=proof->>'cohort_window_id' AND command_id=NEW.command_id;
 IF health IS NULL OR proof IS NULL OR window_doc IS NULL OR health->>'status' IS DISTINCT FROM 'HEALTHY' OR proof->>'status' IS DISTINCT FROM 'CLEAR' OR window_doc->>'status' IS DISTINCT FROM 'CLEAR' OR (proof->>'expires_at')::timestamptz<=clock_timestamp() THEN RAISE EXCEPTION 'fleet release needs a fresh private cohort-health proof';END IF;
 IF cmd.operation='APPLY' AND EXISTS(SELECT 1 FROM fleet_cohort_failures WHERE tenant_id=NEW.tenant_id AND execution_id=cmd.execution_id) THEN RAISE EXCEPTION 'fleet safety latch retains forward reservation';END IF;
 IF cmd.operation='ROLLBACK' AND window_doc->>'mode' IS DISTINCT FROM 'OWNED_RECOVERY' THEN RAISE EXCEPTION 'fleet owned rollback needs distinct fresh recovery evidence';END IF;
 SELECT * INTO membership FROM source_receipts WHERE tenant_id=NEW.tenant_id AND id=health->>'membership_receipt_id';
 SELECT * INTO registration FROM source_registrations WHERE tenant_id=NEW.tenant_id AND id=membership.source_id FOR SHARE;
 SELECT * INTO objective FROM slo_objectives WHERE tenant_id=NEW.tenant_id AND workload_id=cmd.workload_id ORDER BY version DESC LIMIT 1;
 SELECT document INTO profile FROM workload_safety_profiles WHERE tenant_id=NEW.tenant_id AND workload_id=cmd.workload_id ORDER BY version DESC LIMIT 1;
 IF registration.document->>'enabled' IS DISTINCT FROM 'true' OR registration.document->>'revoked'='true' OR registration.version IS DISTINCT FROM (membership.document->>'registration_version')::bigint
 OR profile IS NULL OR cmd.operation='APPLY' AND profile->>'statefulness' IS DISTINCT FROM 'STATELESS' OR window_doc->>'safety_profile_id' IS DISTINCT FROM profile->>'id' OR window_doc->>'safety_profile_hash' IS DISTINCT FROM profile->>'hash' OR proof->>'safety_profile_id' IS DISTINCT FROM profile->>'id' OR proof->>'safety_profile_hash' IS DISTINCT FROM profile->>'hash'
 OR EXISTS(SELECT 1 FROM fleet_member_slo_windows member WHERE member.tenant_id=NEW.tenant_id AND member.id IN(SELECT jsonb_array_elements_text(window_doc->'member_window_ids')) AND member.objective_id IS DISTINCT FROM objective.id)
 OR EXISTS(SELECT 1 FROM telemetry_evaluations evaluation WHERE evaluation.tenant_id=NEW.tenant_id AND evaluation.id IN(SELECT jsonb_array_elements_text(window_doc->'native_evaluation_ids')) AND (EXISTS(SELECT 1 FROM telemetry_source_revocations revoked WHERE revoked.tenant_id=evaluation.tenant_id AND revoked.revision_id=evaluation.revision_id) OR EXISTS(SELECT 1 FROM telemetry_connections connection JOIN telemetry_source_revisions revision ON revision.tenant_id=connection.tenant_id AND revision.connection_id=connection.id WHERE revision.tenant_id=evaluation.tenant_id AND revision.id=evaluation.revision_id AND connection.version>revision.connection_version)))
 THEN RAISE EXCEPTION 'fleet release current evidence authority changed';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER fleet_cohort_release_guard BEFORE INSERT ON fleet_release_events FOR EACH ROW EXECUTE FUNCTION guard_fleet_cohort_release();

-- Preserve the013 native/source/current-SLO checks; owned recovery alone uses
-- a fresh hard-health window without requiring the failed forward baseline.
CREATE OR REPLACE FUNCTION guard_fleet_health() RETURNS trigger LANGUAGE plpgsql AS $$ DECLARE cmd fleet_commands;callback jsonb;membership source_receipts;registration source_registrations;revision source_revisions;parent jsonb;member text;n jsonb;ev jsonb;cohort jsonb;BEGIN
 SELECT * INTO cmd FROM fleet_commands WHERE tenant_id=NEW.tenant_id AND id=NEW.command_id;PERFORM fleet_lock(NEW.tenant_id,cmd.workload_id);SELECT document INTO parent FROM fleet_plans WHERE tenant_id=NEW.tenant_id AND id=cmd.parent_id;
 IF NEW.document->>'command_id' IS DISTINCT FROM NEW.command_id OR coalesce(NEW.document->>'status','') NOT IN('HEALTHY','UNHEALTHY','UNKNOWN') THEN RAISE EXCEPTION 'fleet health binding invalid';END IF;
 IF NEW.document->>'status'='HEALTHY' THEN
  SELECT c.document INTO callback FROM fleet_callbacks c JOIN fleet_command_states s ON s.tenant_id=c.tenant_id AND s.owned_receipt_id=c.id WHERE s.tenant_id=NEW.tenant_id AND s.command_id=NEW.command_id;
  SELECT * INTO membership FROM source_receipts WHERE tenant_id=NEW.tenant_id AND id=NEW.document->>'membership_receipt_id' AND kind='AWS_FLEET_MEMBERSHIP' AND writer_role='finops_ingester';
  SELECT * INTO registration FROM source_registrations WHERE tenant_id=NEW.tenant_id AND id=membership.source_id;
  SELECT * INTO revision FROM source_revisions WHERE tenant_id=NEW.tenant_id AND id=membership.revision_id AND source_id=membership.source_id;
  IF membership.document->>'position' IS DISTINCT FROM 'AFTER' OR membership.document->>'child_id' IS DISTINCT FROM cmd.child_id OR membership.document->>'child_sha256' IS DISTINCT FROM cmd.document->>'child_sha256' OR (membership.document->>'collected_at')::timestamptz<(SELECT dispatched_at FROM fleet_command_states WHERE tenant_id=NEW.tenant_id AND command_id=NEW.command_id) THEN RAISE EXCEPTION 'fleet post-apply membership not bound to this dispatched child';END IF;
  IF callback IS NULL OR membership.id IS NULL OR revision.id IS NULL OR registration.document->>'enabled' IS DISTINCT FROM 'true' OR registration.document->>'revoked'='true' OR coalesce(registration.document->>'read_role_binding_id','')='' OR membership.document->>'read_role_binding_id' IS DISTINCT FROM registration.document->>'read_role_binding_id' OR (membership.document->>'registration_version')::bigint IS DISTINCT FROM registration.version OR membership.document->>'config_hash' IS DISTINCT FROM revision.document->>'config_hash' OR membership.document->'binding' IS DISTINCT FROM cmd.document->'binding' OR membership.document->>'old_asg' IS DISTINCT FROM parent->'old'->>'id' OR membership.document->>'candidate_asg' IS DISTINCT FROM parent->'candidate'->>'id' OR NOT (registration.document->>'payer_account_id'=cmd.document->'binding'->>'account_id' OR registration.document->'usage_account_ids' ? (cmd.document->'binding'->>'account_id')) OR (membership.document->>'collected_at')::timestamptz<clock_timestamp()-interval '5 minutes' OR (membership.document->>'collected_at')::timestamptz>clock_timestamp()+interval '5 seconds' OR membership.document->'old_instance_ids' IS DISTINCT FROM callback->'old_instance_ids' OR membership.document->'candidate_instance_ids' IS DISTINCT FROM callback->'candidate_instance_ids' OR jsonb_array_length(membership.document->'old_instance_ids')<>(cmd.document->'transition'->>'old_after')::integer OR jsonb_array_length(membership.document->'candidate_instance_ids')<>(cmd.document->'transition'->>'candidate_after')::integer THEN RAISE EXCEPTION 'fleet health native membership provenance invalid';END IF;
  IF membership.document->>'collected_at' IS NULL OR coalesce(membership.document->'raw_object'->>'version_id','') IN('','null') OR coalesce(membership.document->'raw_object'->>'body_sha256','')!~'^[a-f0-9]{64}$' OR NOT starts_with(coalesce(membership.document->'raw_object'->>'key',''),'tenant/'||NEW.tenant_id||'/fleet/') OR position('..' IN membership.document->'raw_object'->>'key')>0 OR coalesce(membership.document->'raw_object'->>'bucket','')='' THEN RAISE EXCEPTION 'fleet membership raw provenance missing';END IF;
  IF coalesce(membership.document->>'config_hash','')!~'^[a-f0-9]{64}$' OR revision.writer_role IS DISTINCT FROM 'finops_ingester' OR revision.document->>'registration_version' IS DISTINCT FROM registration.version::text OR coalesce(registration.document->>'payer_account_id'=cmd.document->'binding'->>'account_id',false)=false AND coalesce(registration.document->'usage_account_ids' ? (cmd.document->'binding'->>'account_id'),false)=false OR jsonb_typeof(membership.document->'old_instance_ids') IS DISTINCT FROM 'array' OR jsonb_typeof(membership.document->'candidate_instance_ids') IS DISTINCT FROM 'array' THEN RAISE EXCEPTION 'fleet membership source registration scope incomplete';END IF;
  FOR member IN SELECT jsonb_array_elements_text((membership.document->'old_instance_ids')||(membership.document->'candidate_instance_ids')) LOOP
   n:=NULL;
   FOR ev IN SELECT e.document FROM telemetry_evaluations e WHERE e.tenant_id=NEW.tenant_id AND e.id IN(SELECT jsonb_array_elements_text(NEW.document->'native_evaluation_ids')) LOOP
    IF ev->'binding'->>'provider_resource_id'=member AND ev->'binding'->>'workload_id'=cmd.workload_id AND ev->'binding'->>'account_id'=cmd.document->'binding'->>'account_id' AND ev->'binding'->>'region'=cmd.document->'binding'->>'region' AND ev->'evaluation'->>'status'='READY' AND (ev->'evaluation'->>'end')::timestamptz>=clock_timestamp()-interval '2 minutes' AND (ev->>'created_at')::timestamptz>=clock_timestamp()-interval '5 minutes' AND NOT EXISTS(SELECT 1 FROM telemetry_source_revocations v WHERE v.tenant_id=NEW.tenant_id AND v.revision_id=ev->>'revision_id') AND NOT EXISTS(SELECT 1 FROM telemetry_source_revisions r JOIN telemetry_connections c ON c.tenant_id=r.tenant_id AND c.id=r.connection_id WHERE r.tenant_id=NEW.tenant_id AND r.id=ev->>'revision_id' AND c.version>r.connection_version) THEN n:=ev;END IF;
   END LOOP;
   IF n IS NULL THEN RAISE EXCEPTION 'fleet health requires current native evidence for every physical member';END IF;
  END LOOP;
  IF NEW.document->>'cohort_slo_status' IS DISTINCT FROM 'CLEAR' OR jsonb_typeof(NEW.document->'slo_evaluation_ids') IS DISTINCT FROM 'array' OR jsonb_array_length(NEW.document->'slo_evaluation_ids')<1 THEN RAISE EXCEPTION 'fleet explicit cohort SLO comparison required';END IF;
  SELECT document INTO cohort FROM fleet_proof_sets WHERE tenant_id=NEW.tenant_id AND id=NEW.document->>'cohort_proof_id' AND kind='COHORT_HEALTH' AND writer_role='finops_api';
  IF cohort IS NULL OR cohort->>'status' IS DISTINCT FROM 'CLEAR' OR cohort->'binding' IS DISTINCT FROM cmd.document->'binding' OR cohort->>'command_id' IS DISTINCT FROM NEW.command_id OR cohort->>'child_sha256' IS DISTINCT FROM cmd.document->>'child_sha256' OR cohort->>'membership_receipt_id' IS DISTINCT FROM membership.id OR cohort->'native_evaluation_ids' IS DISTINCT FROM NEW.document->'native_evaluation_ids' OR cohort->'slo_evaluation_ids' IS DISTINCT FROM NEW.document->'slo_evaluation_ids' OR (cohort->>'expires_at')::timestamptz IS NULL OR (cohort->>'expires_at')::timestamptz<=clock_timestamp() OR coalesce(cohort->>'comparison_sha256','')!~'^[a-f0-9]{64}$' OR (cmd.operation='APPLY' AND (jsonb_typeof(cohort->'baseline_evaluation_ids') IS DISTINCT FROM 'array' OR jsonb_array_length(cohort->'baseline_evaluation_ids')<1)) OR (cmd.operation='ROLLBACK' AND cohort->>'mode' IS DISTINCT FROM 'OWNED_RECOVERY') THEN RAISE EXCEPTION 'fleet current explicit blue green control comparison factory proof required';END IF;
  FOR member IN SELECT jsonb_array_elements_text(NEW.document->'slo_evaluation_ids') LOOP
   SELECT document INTO ev FROM slo_evaluations WHERE tenant_id=NEW.tenant_id AND id=member;
   IF ev IS NULL OR ev->>'workload_id' IS DISTINCT FROM cmd.workload_id OR ev->'evaluation'->>'status'<>'CLEAR' OR (ev->'evaluation'->>'window_end')::timestamptz<clock_timestamp()-interval '2 minutes' THEN RAISE EXCEPTION 'fleet current SLO evidence invalid';END IF;
  END LOOP;
 END IF;
 NEW.writer_role:='finops_api';NEW.created_at:=clock_timestamp();NEW.document:=NEW.document||jsonb_build_object('id',NEW.id,'tenant_id',NEW.tenant_id,'hash',NEW.content_hash,'created_at',NEW.created_at,'writer_role',NEW.writer_role);RETURN NEW;
END $$;

-- Forward-only feasibility and immutable failure checks. Owned compensation
-- intentionally does not call this function (the013 recovery contract remains).
CREATE OR REPLACE FUNCTION fleet_forward_authority(p_tenant text,p_parent text) RETURNS jsonb LANGUAGE plpgsql AS $$ DECLARE p jsonb;control text;BEGIN
 SELECT document INTO p FROM fleet_plans WHERE tenant_id=p_tenant AND id=p_parent;PERFORM fleet_lock(p_tenant,p->'binding'->>'workload_id');
 SELECT status INTO control FROM fleet_controls WHERE tenant_id=p_tenant AND parent_id=p_parent ORDER BY version DESC LIMIT 1;
 IF p IS NULL OR (p->>'expires_at')::timestamptz<=clock_timestamp() OR coalesce(control,'ACTIVE')<>'ACTIVE' OR p->'governance'->>'risk_class'<>'R2' OR p->'governance'->>'enabled'<>'true' THEN RAISE EXCEPTION 'fleet forward authority expired paused or revoked';END IF;
 IF coalesce((p->'budget'->>'maximum_duration_seconds')::integer,0)<1 OR fleet_forward_deadline(p) IS NULL OR fleet_forward_deadline(p)<=clock_timestamp() OR (SELECT coalesce(sum((s->>'minimum_observation_seconds')::integer),0) FROM jsonb_array_elements(p->'stages') s)>(p->'budget'->>'maximum_duration_seconds')::integer THEN RAISE EXCEPTION 'fleet forward modeled duration exhausted or observations cannot fit';END IF;
 IF fleet_cohort_minimum_program_seconds(p) IS NULL OR fleet_cohort_minimum_program_seconds(p)>(p->'budget'->>'maximum_duration_seconds')::bigint OR EXISTS(SELECT 1 FROM jsonb_array_elements(p->'proofs') proof WHERE (proof->>'expires_at')::timestamptz<fleet_forward_deadline(p)) THEN RAISE EXCEPTION 'fleet intermediate health delivery or immutable authority duration insufficient';END IF;
 IF EXISTS(SELECT 1 FROM fleet_cohort_failures failure JOIN fleet_executions execution ON execution.tenant_id=failure.tenant_id AND execution.id=failure.execution_id WHERE execution.tenant_id=p_tenant AND execution.parent_id=p_parent) THEN RAISE EXCEPTION 'fleet permanent safety failure disqualifies forward work and positive savings';END IF;
 RETURN p;
END $$;
