# Pilot operations

## Before an execution window

Confirm the operator has the correct AWS account and eu-west-1 context, the instance is opted in and development-only, the signed plan is current, no incident/deployment conflicts, no active job, and required application health is passing. Check the scheduled start has enough lead time for startup and health validation. An EC2 state of `running` alone does not mean the development environment is ready. Monitor startup, stop and restore results through the execution record and audit trail. Keep an authorised human operator available during the live sandbox pilot.

## Pause and contain

Use the application's organisation/workload pause control to block new economic changes. Preserve the executor and existing durable workflow for compensating start/restoration. If the UI/API is unavailable, pause new worker dispatch and remove the customer role's StopInstances permission as a temporary containment action. **Retain StartInstances and Describe permissions while any owned stop awaits restoration.** Scaling the executor to zero or deleting execution permissions indiscriminately can prevent recovery of an already stopped instance.

Read the persisted execution/provider-operation record before manually acting. Record the incident and operator action; do not bypass the ledger by overwriting completed records. For an immediate application incident, notify the owner through your established incident channel and correlate the execution ID and exact cloud operation timestamps. Incident messaging credentials and routes must be configured explicitly.

## Failed scheduled startup

1. Block subsequent stop occurrences for this workload. Identify the expected instance, last successful stop, ownership of that stop, original running state and pending restoration state.
2. Inspect EC2 instance/status checks, CloudTrail request outcomes, capacity/permissions errors, attached EBS state and the application probe. Do not terminate/recreate the instance to resolve a generic timeout.
3. If this workflow owns the stop, retry the original StartInstances compensation with the durable execution identity, then verify application health. An ambiguous AWS API response requires Describe reconciliation before another action; never infer success from a client timeout.
4. Escalate capacity or application failure to the platform owner. An instance can be running while bootstrap, credentials, network or application readiness is broken. Preserve the instance/EBS and the previous configuration for diagnosis.
5. Mark the occurrence failed or restoration-required. Claim no positive verified saving from the failed/rolled-back occurrence. Record actual costs, including a negative result when applicable. Resume scheduling only after a successful supervised restoration and a fresh eligibility check.

Starting must respect the original ownership/precondition record: do not start an instance the customer had independently stopped before the workflow. Likewise a manual operator start must be recognised by reconciliation so a retry does not later stop the instance again.

## Trusted SLO breach or missing telemetry

For schema-3 plans with signed SLO authority, inspect the current objective/source/evaluation and the persisted violation reason alongside the original execution and provider-operation ownership. Preserve the off-instance observer, ingress, worker, executor and Temporal while recovery is pending. A breach, stale evidence or changed authority requests owned restoration; it must not cancel the existing START duty. `ALWAYS` availability blocks a new singleton stop. Changing a policy or receiving a later good minute cannot clear an immutable measurement violation.

The API corrects a prior financial claim by appending a current `BLOCKED` row with null verified saving; it preserves earlier positive and negative rows and their claim identity. Do not delete a violation, edit a financial row, reset collector sequence state or relabel old receipts to recover a positive claim. Use a newly reviewed objective/source/plan for a later change after the fault is understood. Check signed outbox receiver delivery separately from event persistence and route owner escalation through explicitly configured channels. The recent 2–60-minute SLO regression baseline does not replace the independent fourteen-day financial/workload baseline. See [trusted SLO scope and remaining gates](slo-safety.md); runtime/live acceptance is recorded separately.

## Service or control-plane failure

The worker must replay durable Temporal workflow state; the executor must reconcile its persisted cloud-operation intent with actual EC2 state. Restart services with the same database, Temporal namespace and signing verification key. Do not reset volumes or launch a new workflow ID to work around a paused occurrence. Check `/healthz`, database connectivity, Temporal namespace/worker pollers, signatures/expiry, secret versions and customer STS failures. Health endpoints are liveness signals; verify database migrations and durable work processing separately.

Use `kubectl -n finops get pods,events` and per-service logs scoped to the execution. Logs must contain IDs and error categories, not tokens, private keys or connection strings. For an AWS AccessDenied, inspect the actual caller role, external ID, region, instance allowlist and current tags. Restoring by widening IAM to `ec2:*` is not an acceptable pilot fix.

## Backup and restore

RDS automated backups retain 14 days and support point-in-time recovery within the available retention window. Deletion protection and a final snapshot are configured. Take an explicit manual snapshot before schema changes; keep backup encryption keys available and prohibit unplanned key deletion. RDS backups cover the application, Temporal and Temporal visibility databases on this instance. They do not cover external identity-provider configuration or Kubernetes secret values.

For a restore drill:

1. Pause new dispatch, preserve or complete owned restorations, and record a consistent target recovery time. Record current workflow IDs, outstanding stop intents, ledger version and S3 object/version references.
2. Restore RDS to a **new private instance** in eu-west-1 using point-in-time recovery/manual snapshot. Preserve encryption, isolated subnet group, TLS requirement and the approved security group. Do not overwrite the live database.
3. Validate schema/role grants and tenant isolation. Recover runtime credentials from the approved secret store or rotate them, update the existing per-service database Secrets to the new endpoint, and restart the applications with the same Temporal namespace.
4. Reconcile every incomplete execution with CloudTrail and EC2 state before allowing workers to resume. Database rollback can resurrect an old intent; restoring a snapshot must never justify repeating a provider mutation without reconciliation. Verify unique operation/nonce checks with the restored state.
5. Restore ClickHouse from raw/replayable analytics data or its separately tested backup. The pilot's encrypted gp3 PVC uses `Retain`; a retained disk is not a backup. If analytics is not replayable yet, pause verification and disclose the gap.
6. Verify the raw/audit buckets' retained versions, hashes and retention dates, plus application-to-object references. Do not delete a newer ledger revision to force agreement with an older database. Append reconciliation/correction evidence instead.
7. Run fixture and supervised sandbox health/recovery checks before lifting the pause. Record measured recovery time and data loss. This repository sets no untested RTO/RPO claim.

The same RDS instance contains application and Temporal histories, so whole-instance PITR can restore them to one target time. Never restore just one database and assume workflow/application state is aligned. For production architecture, establish independent backups, recovery isolation and a tested consistent recovery procedure. Temporal's 14-day workflow history retention is separate from financial/audit retention; retain final execution evidence outside expiring histories.

## Secret and signing-key rotation

Use separate service tokens, database identities and signer/execution KMS wrapping keys. Automatic KMS encryption-key rotation does not rotate the Ed25519 signing key or service tokens. Restrict secret retrieval and audit reads through Secrets Manager/CloudTrail; applications must never log decrypted values.

For signer/executor token rotation, pause dispatch and drain or safely pause in-progress calls, update the corresponding service Secret and the worker's matching token, then restart both ends and run authenticated health/execution tests before resuming. Do not substitute one global token. Rotate database credentials one role at a time, update only its Secret, roll that workload and verify its grants remain restricted.

For Ed25519 rotation, the initial pilot uses one verification key. Pause new plans and drain/expire every signed in-flight plan or complete its safe restoration before replacing that key. Generate a fresh keypair, replace the private key only in the signer and the public key in worker/executor, restart the three services and run a signature/expired-plan rejection test. Keep old audit signatures and public-key fingerprints as evidence. Multiple active verification keys/key IDs require explicit application support; do not assume zero-downtime key rotation exists.

Revocation during a suspected signing-key compromise requires pausing new mutation immediately, rejecting the compromised key for new plans, and separately supervising any required restoration. Do not discard the old execution records, nonces or cloud-operation evidence.

## Savings and billing corrections

The first scheduling model uses 14 complete baseline days and 14 complete post-change days with calendar and workload-volume matching. Zero workload demand is an observation; absent telemetry is not zero. Missing units, unresolved commitments, incomplete billing or concurrent changes prevent a positive verified claim. Instance running-hours are the intervention, not a valid substitute for workload output. Label provisional opportunity, measured savings and invoice-reconciled verified savings separately.

A stopped EBS-backed instance retains billable volumes and may retain billable IP resources. Never claim those costs disappeared. Commitment obligations can remain after shutdown; only demonstrate actual marginal avoided spend. See [AWS stop/start billing](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/how-ec2-instance-stop-start-works.html). Keep source-native currencies separate; this pilot does not perform FX conversion.

Reprocess revised billing exports by source identity/version, reconcile invoice totals and append superseding savings entries. Preserve the prior amount, reason, source version and negative corrections. AWS [can amend reports after invoice finalisation](https://docs.aws.amazon.com/cur/latest/userguide/what-is-cur.html); elapsed time alone is not a finality guarantee. Pause financial claims when source/ledger reconciliation fails, while continuing safety monitoring and owned restoration.

## Upgrades and teardown

Pin tested image digests and preserve the previous digests/Helm values. Back up before a migration, test compatibility against a restored database, then use the migration Job and a bounded rolling rollout. Helm rollback reverts manifests; it does not reverse SQL changes, AWS mutations or financial commitments. Schema rollback requires its own tested plan.

For teardown, pause schedules, finish owned restorations, archive the execution/ledger evidence and retain required backups and KMS keys. Deliberately remove RDS deletion protection only after the recovery/retention decision. S3 COMPLIANCE-locked versions cannot be removed early; leave the retained evidence and necessary keys until expiry. Do not run recursive force-delete workarounds or disable encryption keys needed to read retained evidence. Revoke customer cross-account trust after confirming no restoration remains pending. Remove unused EKS/NAT/RDS resources separately from retained evidence, with a reviewed Terraform plan.
