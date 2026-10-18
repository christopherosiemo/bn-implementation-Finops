# Commissioning dossier

This dossier collects the customer gates for the full preserved product contract. It is a preparation record, not permission to provision, spend, enable Autopilot or mutate a customer workload. Engineering continues while these inputs are unavailable. No cloud resources have been provisioned by the extended delivery increment.

The release candidate is the exact tested head of the existing pilot pull request. Its acceptance record, immutable progress reviews and all 233 requirement gates are maintained in [acceptance](acceptance.md), [progress](progress-ledger.json) and [traceability](traceability.md). Record the approved commit and container digests here before commissioning; a moving branch is insufficient. Native telemetry controls and remaining bounds are documented in [native telemetry](native-telemetry.md), and supervised AWS preparation remains in [sandbox readiness](sandbox-readiness.md).

The first hosted cell uses two separate sandbox accounts in `eu-west-1`: the control plane account and the qualifying workload account. The initial deployment is read-only, Autopilot disabled, with execution identities absent. Native global billing API reads do not move product storage or processing out of Ireland. Provisioning requires authenticated account access, expected account IDs, reviewed Terraform plans with no unintended deletion, OIDC configuration, operator CIDRs, EU image registry, encrypted remote state, secret sources, evidence retention and a reviewed cost estimate including retained evidence and encryption keys. Budget notifications monitor the approved spend; they do not approve deployment.

Consolidate these customer decisions for the final safe handover:

- Exact account and repository access; approved read-role and deployment pipeline identity bindings, external IDs and protected branches.
- Workload owners, explicit environment/classification, configuration authority, statelessness, dependency consumers and action-specific delegation.
- Business calendars, blackouts, known seasonal events, hard SLOs and regression allowances, required availability, RTO and RPO.
- Retention, data-residency requirements, incident contacts, budget/spending ceilings, approval separation and recovery takeover responsibility.
- Independent instrumentation locations and subjects, actual metric definitions and units, health endpoints, source/export ownership and invoice/commitment scope.
- Least-privilege execution approval for one exact supervised canary, its rollback, expiry and immediate pause afterward.

Before a first action, select an existing qualifying resource with genuine complete history or collect the required days. There is no commissioning bypass. Validate authentic source versions, delivery policy, independent observations, ownership, recovery and current safety. Demonstrate backup restoration, key rotation and the applicable incident/recovery procedures before their acceptance credit. A signed plan is not a customer deployment attestation; a pipeline success is not application readiness.

After an approved intervention, retain actual work-preservation and cost evidence through the complete observation period. Keep results provisional until native invoice finality, commitment exposure, workload normalization, attributable transition/continuing costs and reconciliation gates pass. Rollback permanently excludes the affected measurement from positive verified savings. Customer usability, security assurance and sustained production operation remain separate acceptance gates. Only evidence of the complete contractual workflow in customer use can earn 100%.
