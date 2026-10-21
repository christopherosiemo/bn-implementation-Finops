# Supervised AWS read-only commissioning

This runbook follows Connections & quality → AWS read-only commissioning.
The readiness-closure sprint stops before connecting customer AWS credentials.
Local fixture results are labelled synthetic and do not establish real AWS
acceptance, customer savings or operational readiness.

1. Obtain customer approval for the exact read-only account, region, role,
   source destinations, retention and read surface. Product processing and
   retained evidence stay in Ireland (`eu-west-1`). Review deployment costs,
   encrypted remote state and registry/OIDC inputs before any future deployment.
2. In a separate approved customer change, deploy/review the existing
   `deploy/terraform/modules/customer-roles` read role. Keep execution disabled.
   Enable only the enumerated optional read families needed by the customer.
   The preflight reports optional denied reads; it never creates permissions.
3. Register an operator-approved opaque read binding. The API/console never
   accepts external IDs or credentials. Set safe
   `AWS_ACCOUNT_APPROVED_BINDINGS_JSON` metadata for API and ingester; set
   `AWS_ACCOUNT_READ_BINDINGS_JSON` only in the ingester's existing secret
   mechanism. Keep secret values outside tracked files, shell arguments and
   exports. In Helm use `sources.accountApprovedBindingsJSON` and an existing
   `sources.accountReadBindingsSecret`. The chart creates no customer IAM role.
   Use renewable IRSA source credentials and short-lived cross-account sessions.
4. Configure or approve the customer's existing hourly resource-level CUR 2.0
   Data Export under its own change process. Register the existing billing source
   in Connections; approve its payer/member scope, versioned destination and
   exporter-only delivery policy. No export falls back to public pricing.
5. Use **Connect AWS account**. Enter the account name, exact twelve-digit account
   and Ireland region; select its approved binding. Registering a binding grants
   no execution authority. Legacy accounts should be re-registered with an
   approved binding before commissioning; global legacy discovery configuration
   does not establish a preflight identity.
6. Select the account under **AWS read-only commissioning** and choose
   **Run read-only preflight**. The asynchronous ingester assumes only that
   approved read role and validates the caller identity before category probes.
   A successful external-ID-bound assumption establishes that the configured
   value was accepted; it does not prove the customer's IAM policy requires it.
7. Inspect all ten readiness dimensions and all thirteen inventory categories.
   A successful bounded read proves access to that operation, not a complete
   inventory. `DENIED`, `ERROR`, `PARTIAL` and missing configuration remain visible.
   `READ_ONLY_READY` does not mean economically ready. An unresolved billing or
   workload source prevents full recommendation readiness.
8. Inspect registered sources and resolve each specific blocker. Missing memory
   needs approved memory telemetry. Missing Inventory limits object analysis;
   Flow Log absence limits destination attribution. Missing CUR resource IDs,
   payer commitments or finalized invoices limits economics. Unknown IaC permits
   Observe/Recommend but blocks future declarative execution. A software-reader
   blocker must be fixed in the product; a customer declaration cannot replace it.
9. Begin genuine history collection. Preserve actual timestamps, completeness,
   source versions and gaps. Existing 14/30/90-day requirements and financial
   finality gates still apply; no commissioning bypass or historical backfill
   creates independent guarded activity observations.
10. Generate an existing read-only assessment once its evidence gates pass.
    Inspect the persisted recommendation and underlying customer economics.
    Export the authenticated immutable commissioning JSON for review. Re-run
    preflight after corrections; older reports remain unchanged, explicitly
    as-of. Live commissioning and customer operational acceptance require
    separate evidence before contractual maturity credit.

Coverage includes all services, global/resource-less charges and unowned
resources in the selected account. Positive spend has four exclusive partitions:
analysed, observation-only, blocked and unsupported. Unallocated spend is an
overlapping workload-attribution view. Credits and currencies remain separate.
Unknown, incomplete or zero positive denominators have no coverage percentage.
The report does not infer whether other processes hold execution credentials;
without an independent deployment attestation it reports `UNKNOWN`.

No step in this primary path requires purchasing, executing a plan, enabling an
execution role, changing workloads, enabling paid telemetry or claiming verified
savings. Customer decisions and genuine AWS/operational gates remain external.
