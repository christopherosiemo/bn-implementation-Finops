-- ROLLED_BACK is a customer-visible terminal claim, not the fact that an
-- inverse command was attempted. Require an owned compensation, fresh healthy
-- recovery evidence, and its durable release receipt before accepting it.
CREATE FUNCTION guard_fleet_verified_rollback() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.status='ROLLED_BACK' AND OLD.status IS DISTINCT FROM 'ROLLED_BACK' THEN
  PERFORM fleet_lock(NEW.tenant_id,NEW.workload_id);
  IF NOT EXISTS(
   SELECT 1
   FROM fleet_commands rollback
   JOIN fleet_command_states state ON state.tenant_id=rollback.tenant_id AND state.command_id=rollback.id
   JOIN fleet_children recovery ON recovery.tenant_id=rollback.tenant_id AND recovery.id=rollback.child_id AND recovery.compensation_for IS NOT NULL
   JOIN fleet_command_states original_state ON original_state.tenant_id=recovery.tenant_id
    AND original_state.command_id=(SELECT original.id FROM fleet_commands original WHERE original.tenant_id=recovery.tenant_id AND original.execution_id=rollback.execution_id AND original.child_id=recovery.compensation_for)
   JOIN fleet_health_evidence health ON health.tenant_id=state.tenant_id AND health.id=state.health_evidence_id AND health.command_id=rollback.id
   JOIN fleet_release_events release ON release.tenant_id=health.tenant_id AND release.command_id=rollback.id AND release.evidence_id=health.id
   WHERE rollback.tenant_id=NEW.tenant_id AND rollback.execution_id=NEW.id AND rollback.operation='ROLLBACK'
    AND state.outcome='APPLIED' AND state.owned_receipt_id IS NOT NULL AND original_state.restored
    AND health.document->>'status'='HEALTHY' AND health.document->>'mode'='OWNED_RECOVERY'
    AND health.created_at>=clock_timestamp()-interval '2 minutes'
  ) THEN
   RAISE EXCEPTION 'fleet rollback requires fresh healthy owned recovery evidence';
  END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER fleet_execution_rollback_verification
 BEFORE UPDATE OF status ON fleet_executions
 FOR EACH ROW EXECUTE FUNCTION guard_fleet_verified_rollback();
