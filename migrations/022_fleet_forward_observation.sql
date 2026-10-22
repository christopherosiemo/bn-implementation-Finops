-- A healthy result is forward authority too. A dispatched command keeps its
-- ownership/reservation after pause, revocation or expiry; only fresh owned
-- recovery may release it. Historical negative observations remain append-only.
CREATE FUNCTION fleet_forward_observation_available(p_tenant text,p_parent text) RETURNS boolean LANGUAGE plpgsql AS $$
BEGIN
 IF p_tenant IS DISTINCT FROM current_setting('app.tenant_id',true) THEN RETURN false;END IF;
 PERFORM fleet_forward_authority(p_tenant,p_parent);
 RETURN true;
EXCEPTION WHEN raise_exception THEN
 -- fleet_forward_authority uses P0001 only for expected domain refusal. Other
 -- SQL/transport failures propagate; they are never converted to safety proof.
 RETURN false;
END $$;

CREATE FUNCTION guard_fleet_forward_observation() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE cmd fleet_commands;command_id text;positive boolean:=false;
BEGIN
 IF NEW.tenant_id IS DISTINCT FROM current_setting('app.tenant_id',true) THEN RAISE EXCEPTION 'fleet forward observation tenant mismatch';END IF;
 IF TG_TABLE_NAME='fleet_cohort_windows' THEN
  command_id:=NEW.command_id;positive:=NEW.mode='FORWARD' AND NEW.status='CLEAR';
 ELSIF TG_TABLE_NAME='fleet_proof_sets' THEN
  IF NEW.kind<>'COHORT_HEALTH' THEN RETURN NEW;END IF;
  command_id:=NEW.document->>'command_id';positive:=NEW.document->>'status'='CLEAR';
 ELSIF TG_TABLE_NAME='fleet_health_evidence' THEN
  command_id:=NEW.command_id;positive:=NEW.document->>'status'='HEALTHY';
 ELSIF TG_TABLE_NAME='fleet_release_events' THEN
  command_id:=NEW.command_id;positive:=true;
 END IF;
 IF positive IS DISTINCT FROM true THEN RETURN NEW;END IF;
 SELECT * INTO cmd FROM fleet_commands WHERE tenant_id=NEW.tenant_id AND id=command_id;
 IF cmd.id IS NULL THEN RAISE EXCEPTION 'fleet forward observation command required';END IF;
 PERFORM fleet_lock(NEW.tenant_id,cmd.workload_id);
 -- Recovery is authorized by the exact owned inverse and fresh recovery health
 -- in013/018. Its authority does not depend on the expired forward parent.
 IF cmd.operation='APPLY' THEN PERFORM fleet_forward_authority(NEW.tenant_id,cmd.parent_id);END IF;
 RETURN NEW;
END $$;

-- Alphabetic ordering runs these guards before existing positive publication
-- or release handlers; their full native/member/profile checks still run.
CREATE TRIGGER fleet_00_forward_window BEFORE INSERT ON fleet_cohort_windows FOR EACH ROW EXECUTE FUNCTION guard_fleet_forward_observation();
CREATE TRIGGER fleet_00_forward_proof BEFORE INSERT ON fleet_proof_sets FOR EACH ROW EXECUTE FUNCTION guard_fleet_forward_observation();
CREATE TRIGGER fleet_00_forward_health BEFORE INSERT ON fleet_health_evidence FOR EACH ROW EXECUTE FUNCTION guard_fleet_forward_observation();
CREATE TRIGGER fleet_00_forward_release BEFORE INSERT ON fleet_release_events FOR EACH ROW EXECUTE FUNCTION guard_fleet_forward_observation();
