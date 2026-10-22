-- Reuse authenticated historical native telemetry and its immutable archive
-- receipts. Analytical reads confer neither historical minute-ingress authority
-- nor provider, publication, signing, credential or execution privileges.
GRANT SELECT ON telemetry_connections,
 telemetry_source_revisions,telemetry_source_revocations,telemetry_batches,
 telemetry_checkpoints,telemetry_receipts TO finops_service_analyst;
