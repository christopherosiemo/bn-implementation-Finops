-- Additive interpretation of issued hardware v1 bytes. This does NOT alter
-- HardwareEvidence v1, assert creation/incarnation, or authorize any action.
CREATE FUNCTION hardware_identity_source_lock(p_tenant text,p_source text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$ BEGIN
 IF p_tenant IS DISTINCT FROM current_setting('app.tenant_id',true) THEN RAISE EXCEPTION 'hardware identity tenant mismatch';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(p_tenant||':dependency-graph',0));
 IF NOT pg_try_advisory_xact_lock_shared(hashtextextended(p_tenant||':trusted-source:'||p_source,0)) THEN RAISE EXCEPTION 'hardware identity source synchronization busy';END IF;
 PERFORM 1 FROM public.source_registrations WHERE tenant_id=p_tenant AND id=p_source FOR SHARE;
 RETURN FOUND;
END $$;
REVOKE ALL ON FUNCTION hardware_identity_source_lock(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION hardware_identity_source_lock(text,text) TO finops_ingester;

CREATE TABLE hardware_identity_derivations (
 tenant_id text NOT NULL,id text NOT NULL,source_id text NOT NULL,parent_receipt_id text NOT NULL,parent_revision_id text NOT NULL,
 resource_id text NOT NULL,workload_id text NOT NULL,decoder_version text NOT NULL,
 content_hash text NOT NULL CHECK(content_hash~'^[a-f0-9]{64}$'),document jsonb NOT NULL,raw_document bytea NOT NULL,
 writer_role text NOT NULL DEFAULT current_user,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,id),UNIQUE(tenant_id,parent_receipt_id,decoder_version),
 FOREIGN KEY(tenant_id,parent_receipt_id) REFERENCES source_receipts(tenant_id,id),
 FOREIGN KEY(tenant_id,parent_revision_id) REFERENCES source_revisions(tenant_id,id),
 FOREIGN KEY(tenant_id,source_id) REFERENCES source_registrations(tenant_id,id),
 CHECK(octet_length(raw_document)<=16384)
);
ALTER TABLE hardware_identity_derivations ENABLE ROW LEVEL SECURITY;
ALTER TABLE hardware_identity_derivations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON hardware_identity_derivations USING(tenant_id=current_setting('app.tenant_id',true)) WITH CHECK(tenant_id=current_setting('app.tenant_id',true));
CREATE TRIGGER hardware_identity_immutable BEFORE UPDATE OR DELETE ON hardware_identity_derivations FOR EACH ROW EXECUTE FUNCTION deny_evidence_mutation();
GRANT SELECT,INSERT ON hardware_identity_derivations TO finops_ingester;
GRANT SELECT ON hardware_identity_derivations TO finops_api;

CREATE FUNCTION guard_hardware_identity() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE parent public.source_receipts;revision public.source_revisions;registration public.source_registrations;
 resource jsonb;binding jsonb;identity jsonb;eni jsonb;k text;stamp timestamptz;
BEGIN
 IF current_user<>'finops_ingester' OR NEW.tenant_id IS DISTINCT FROM current_setting('app.tenant_id',true) THEN RAISE EXCEPTION 'hardware identity requires tenant ingestion identity';END IF;
 IF NOT public.hardware_identity_source_lock(NEW.tenant_id,NEW.source_id) THEN RAISE EXCEPTION 'hardware identity source unavailable';END IF;
 SELECT * INTO parent FROM public.source_receipts WHERE tenant_id=NEW.tenant_id AND id=NEW.parent_receipt_id;
 SELECT * INTO revision FROM public.source_revisions WHERE tenant_id=NEW.tenant_id AND id=NEW.parent_revision_id;
 SELECT * INTO registration FROM public.source_registrations WHERE tenant_id=NEW.tenant_id AND id=NEW.source_id;
 IF parent.id IS NULL OR parent.kind<>'AWS_EC2_HARDWARE' OR parent.writer_role<>'finops_ingester' OR parent.source_id<>NEW.source_id OR parent.revision_id<>NEW.parent_revision_id OR revision.id IS NULL OR revision.writer_role<>'finops_ingester' OR revision.source_id<>NEW.source_id OR revision.document->>'kind' IS DISTINCT FROM 'AWS_EC2_HARDWARE' THEN RAISE EXCEPTION 'hardware identity issued parent differs';END IF;
 IF registration.kind IS DISTINCT FROM 'AWS_CUR2' OR registration.document->'enabled' IS DISTINCT FROM 'true'::jsonb OR registration.document->>'revoked'='true' OR parent.document->>'config_hash' IS DISTINCT FROM public.fleet_history_source_config(registration.document) OR revision.document->>'config_hash' IS DISTINCT FROM parent.document->>'config_hash' OR (parent.document->>'registration_version')::bigint>registration.version OR parent.document->>'read_role_binding_id' IS DISTINCT FROM registration.document->>'read_role_binding_id' THEN RAISE EXCEPTION 'hardware identity current source differs';END IF;
 SELECT document INTO resource FROM public.entities WHERE tenant_id=NEW.tenant_id AND kind='resources' AND id=NEW.resource_id;
 binding:=jsonb_build_object('tenant_id',NEW.tenant_id,'resource_id',NEW.resource_id,'workload_id',resource->>'workload_id','provider',resource->>'provider','provider_resource_id',resource->>'provider_resource_id','account_id',resource->>'account_id','region',resource->>'region');
 IF resource IS NULL OR resource->>'provider' IS DISTINCT FROM 'AWS' OR resource->>'region' IS DISTINCT FROM 'eu-west-1' OR coalesce(resource->>'workload_id','')='' OR NEW.workload_id IS DISTINCT FROM resource->>'workload_id' OR parent.document->'binding' IS DISTINCT FROM binding OR NEW.document->'binding' IS DISTINCT FROM parent.document->'binding' THEN RAISE EXCEPTION 'hardware identity current mapped resource differs';END IF;
 IF NEW.document-ARRAY['schema_version','kind','decoder_version','tenant_id','source_id','source_config_hash','parent_receipt_id','parent_revision_id','parent_canonical_hash','parent_hash_version','parent_registration_version','parent_collected_at','parent_received_at','binding','raw_object','identity','status','incarnation_status','interval_ownership','execution_authorized','verified_saving']<>'{}'::jsonb OR NOT NEW.document ?& ARRAY['schema_version','kind','decoder_version','tenant_id','source_id','source_config_hash','parent_receipt_id','parent_revision_id','parent_canonical_hash','parent_hash_version','parent_registration_version','parent_collected_at','parent_received_at','binding','raw_object','identity','status','incarnation_status','interval_ownership','execution_authorized','verified_saving'] THEN RAISE EXCEPTION 'hardware identity metadata shape differs';END IF;
 IF NEW.document->>'schema_version' IS DISTINCT FROM '2' OR NEW.document->>'kind' IS DISTINCT FROM 'AWS_EC2_IDENTITY_DERIVATION' OR NEW.decoder_version<>'ec2-hardware-identity-v2' OR NEW.document->>'decoder_version' IS DISTINCT FROM NEW.decoder_version OR NEW.document->>'tenant_id' IS DISTINCT FROM NEW.tenant_id OR NEW.document->>'source_id' IS DISTINCT FROM NEW.source_id OR NEW.document->>'parent_receipt_id' IS DISTINCT FROM parent.id OR NEW.document->>'parent_revision_id' IS DISTINCT FROM revision.id OR NEW.document->>'source_config_hash' IS DISTINCT FROM parent.document->>'config_hash' OR NEW.document->>'parent_hash_version' IS DISTINCT FROM 'GO_JSON_V1' OR NEW.document->>'parent_canonical_hash' IS DISTINCT FROM public.fleet_history_json_hash(parent.document) OR NEW.document->'parent_registration_version' IS DISTINCT FROM parent.document->'registration_version' OR NEW.document->'parent_collected_at' IS DISTINCT FROM parent.document->'collected_at' OR (NEW.document->>'parent_received_at')::timestamptz IS DISTINCT FROM parent.created_at THEN RAISE EXCEPTION 'hardware identity immutable parent binding differs';END IF;
 IF NEW.document->'raw_object' IS DISTINCT FROM parent.document->'raw_object' OR coalesce(parent.document->'raw_object'->>'version_id','') IN('','null') OR parent.document->'raw_object'->>'body_sha256' IS DISTINCT FROM revision.document->'raw_object'->>'body_sha256' OR parent.document->'raw_object'->>'key' IS DISTINCT FROM revision.document->'raw_object'->>'key' OR parent.document->'raw_object'->>'bucket' IS DISTINCT FROM revision.document->'raw_object'->>'bucket' THEN RAISE EXCEPTION 'hardware identity pinned parent bytes differ';END IF;
 IF NEW.document->>'status' IS DISTINCT FROM 'OBSERVED_ONLY' OR NEW.document->>'incarnation_status' IS DISTINCT FROM 'UNKNOWN' OR NEW.document->>'interval_ownership' IS DISTINCT FROM 'UNPROVEN' OR NEW.document->'execution_authorized' IS DISTINCT FROM 'false'::jsonb OR NEW.document->'verified_saving' IS DISTINCT FROM 'null'::jsonb THEN RAISE EXCEPTION 'hardware identity cannot carry execution or financial authority';END IF;
 identity:=NEW.document->'identity';
 IF jsonb_typeof(identity) IS DISTINCT FROM 'object' OR identity-ARRAY['schema_version','decoder_version','provider','account_id','region','instance_id','collected_at','raw_sha256','last_start_time','primary_eni','reason_codes']<>'{}'::jsonb OR NOT identity ?& ARRAY['schema_version','decoder_version','provider','account_id','region','instance_id','collected_at','raw_sha256','last_start_time','primary_eni','reason_codes'] OR identity->>'schema_version' IS DISTINCT FROM '2' OR identity->>'decoder_version' IS DISTINCT FROM NEW.decoder_version OR identity->>'provider' IS DISTINCT FROM 'AWS' OR identity->>'account_id' IS DISTINCT FROM binding->>'account_id' OR identity->>'region' IS DISTINCT FROM binding->>'region' OR identity->>'instance_id' IS DISTINCT FROM binding->>'provider_resource_id' OR (identity->>'collected_at')::timestamptz IS DISTINCT FROM(parent.document->>'collected_at')::timestamptz OR identity->>'raw_sha256' IS DISTINCT FROM parent.document->'raw_object'->>'body_sha256' THEN RAISE EXCEPTION 'hardware identity decoder binding differs';END IF;
 IF jsonb_typeof(identity->'reason_codes') IS DISTINCT FROM 'array' OR jsonb_array_length(identity->'reason_codes')>16 OR EXISTS(SELECT 1 FROM jsonb_array_elements(identity->'reason_codes') x WHERE jsonb_typeof(x)<>'string' OR x#>>'{}'<>ALL(ARRAY['LAST_START_TIME_UNOBSERVED','PRIMARY_ENI_AMBIGUOUS','PRIMARY_ENI_DEVICE_INDEX_UNOBSERVED','PRIMARY_ENI_UNOBSERVED','PRIMARY_ENI_CARD_INDEX_AMBIGUOUS','PRIMARY_ENI_ATTACH_TIME_UNOBSERVED','PRIMARY_ENI_CARD_INDEX_UNOBSERVED','PRIMARY_ENI_ATTACHMENT_NOT_CONFIRMED'])) THEN RAISE EXCEPTION 'hardware identity unknown reason';END IF;
 IF identity->'last_start_time'<>'null'::jsonb THEN
  IF jsonb_typeof(identity->'last_start_time')<>'string' THEN RAISE EXCEPTION 'hardware identity last start invalid';END IF;
  stamp:=(identity->>'last_start_time')::timestamptz;
  IF NOT isfinite(stamp) OR stamp>(parent.document->>'collected_at')::timestamptz+interval '5 seconds' THEN RAISE EXCEPTION 'hardware identity last start future';END IF;
 END IF;
 eni:=identity->'primary_eni';
 IF eni<>'null'::jsonb THEN
  IF jsonb_typeof(eni)<>'object' OR eni-ARRAY['network_interface_id','attachment_id','device_index','network_card_index','attach_time','attachment_status','creator_account_id']<>'{}'::jsonb OR NOT eni ?& ARRAY['network_interface_id','attachment_id','device_index','network_card_index','attach_time','attachment_status','creator_account_id'] OR coalesce(eni->>'network_interface_id','')!~'^eni-[a-f0-9]{8}([a-f0-9]{9})?$' OR coalesce(eni->>'attachment_id','')!~'^eni-attach-[a-f0-9]{8}([a-f0-9]{9})?$' OR eni->'device_index' IS DISTINCT FROM '0'::jsonb OR (eni->'network_card_index'<>'null'::jsonb AND eni->'network_card_index'<>'0'::jsonb) THEN RAISE EXCEPTION 'hardware identity primary interface invalid';END IF;
  IF eni->'creator_account_id'<>'null'::jsonb AND coalesce(eni->>'creator_account_id','')!~'^[0-9]{12}$' THEN RAISE EXCEPTION 'hardware identity interface creator invalid';END IF;
  IF eni->'attachment_status'<>'null'::jsonb AND eni->>'attachment_status'<>ALL(ARRAY['attaching','attached','detaching','detached']) THEN RAISE EXCEPTION 'hardware identity attachment status invalid';END IF;
  IF eni->'attach_time'<>'null'::jsonb THEN
   IF jsonb_typeof(eni->'attach_time')<>'string' THEN RAISE EXCEPTION 'hardware identity attach time invalid';END IF;
   stamp:=(eni->>'attach_time')::timestamptz;
   IF NOT isfinite(stamp) OR stamp>(parent.document->>'collected_at')::timestamptz+interval '5 seconds' THEN RAISE EXCEPTION 'hardware identity attach time future';END IF;
  END IF;
 END IF;
 IF convert_from(NEW.raw_document,'UTF8')::jsonb IS DISTINCT FROM NEW.document OR encode(sha256(NEW.raw_document),'hex')<>NEW.content_hash OR NEW.id IS DISTINCT FROM 'hardware-identity-v2-'||NEW.content_hash THEN RAISE EXCEPTION 'hardware identity exact payload hash differs';END IF;
 -- SQL validates provenance/bindings and shape. Only the trusted versioned
 -- decoder can derive these new semantic fields from the pinned XML bytes.
 NEW.writer_role:='finops_ingester';NEW.created_at:=clock_timestamp();RETURN NEW;
END $$;
CREATE TRIGGER hardware_identity_guard BEFORE INSERT ON hardware_identity_derivations FOR EACH ROW EXECUTE FUNCTION guard_hardware_identity();
