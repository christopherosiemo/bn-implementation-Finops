# Read-only EBS assessment

This package assesses AWS block storage. Every recommendation is non-executable, carries R3 risk, and has `execution_authorized=false`, `pre_execution_ready=false` and `verified_saving=null`. It adds no storage deletion, resizing, snapshot mutation, customer execution credentials or S3 optimisation. The previous [database package](rds-readonly-assessment.md) remains PARTIAL and closed. The [deferred commitment acceptance](commitment-acceptance-deferred.md) remains enabled and unchanged.

## Customer path

The ordinary read-role connector discovers volumes, snapshots, attached instances, native instance capabilities, modifications and discoverable snapshot dependencies. The normal inventory and resource details retain unknown ownership and configuration values. Existing workload mapping, safety policy, configuration-authority declarations and explicit dependency reviews supply separate customer context. Performance comparisons require continuous recorded AWS Config history and complete, bounded CloudTrail enumeration of recorder-management events. Missing or changed recorder evidence blocks comparison. CloudTrail event history has a 90-day bound and eventual availability; it does not prove exact physical transition times. A current configuration is not projected backwards.

An IDs-only `POST /v1/storage-assessments` freezes the selected immutable evidence and safety profile. The optional `storage-assessor` process consumes the existing PostgreSQL queue using its own analytical database identity and version-only evidence reader. It calls the separate authenticated Python economics service and publishes an immutable assessment and recommendation. It has no customer AWS role, signing identity or executor credentials. Reads and cursor pagination are scoped to the tenant, authenticated subject and query. Existing EC2 restoration ownership is independent of this queue.

The normal authenticated inventory, resource details, recommendations, workload-safety and coverage views expose configuration, attachment context, observation quality, component economics, candidates and blockers. No presentation route or public financial-upload body authorizes an assessment.

## Analysis boundaries

| Opportunity | Supported advice | Boundary |
|---|---|---|
| Unattached volume | Carrying cost, age, ownership, backup/dependency review and quarantine progression | Unattached never means disposable; no deletion authority |
| gp2 to gp3 | Same-GiB candidate with evidenced IOPS, throughput, headroom, attachment compatibility and native customer-rate comparison | Missing history, rate, policy, source or compatibility blocks validation |
| gp3 IOPS or throughput | Independent and combined reductions that preserve both observed demand and declared headroom | No GiB reduction or increase of an unrelated performance dimension |
| io1/io2 alternatives | Explicit comparison and equivalence blockers | Lower durability, latency or Multi-Attach assumptions cannot be silently waived |
| Snapshot retention | Distinguishes policy-required, AMI/restore-dependent, potentially redundant and unknown dependency | Unknown references prevent a deletion recommendation; all advice is read-only |
| Used-capacity migration | Separate `MIGRATION_OPPORTUNITY` model contract | Requires trustworthy filesystem-use observations and new volume, migration, filesystem handling, validation, cutover and rollback; ordinary discovery alone cannot qualify it |

Capabilities are an independently versioned selected-facts documentation asset, not a fabricated provider API response or price. [AWS volume types](https://docs.aws.amazon.com/ebs/latest/userguide/ebs-volume-types.html) and [volume modification constraints](https://docs.aws.amazon.com/ebs/latest/userguide/modify-volume-requirements.html) define the supported commercial-region comparison. Outposts and special-zone equivalence are unsupported. A fresh execution-stage modification budget would still be required by a later mutation package.

Native telemetry preserves dimensions, unit, statistic, period, sample count, source time, raw object version and hash. Hourly evaluation bins retain native minute maxima and counts; an hourly sum cannot establish a minute peak. Instance aggregates use their actual native monitoring cadence. Volume latency is the maximum of native period operation means, never a raw-operation percentile. Missing samples remain unknown. The required windows are 14 complete non-production days, 30 production days or 90 seasonal days. Application SLO evidence remains independent. Declared demand multipliers are conservative policy inputs, not calibrated forecasts.

Sustained instance limits constrain the volume. The entire observed instance aggregate plus headroom is reserved before assessing the selected volume against the remaining budget. This deliberately conservative comparison does not invent per-device attribution or let several volumes each claim the full instance capacity.

## Economics and coverage

Only a current authenticated, complete CUR export supplies customer rates. Native NET rate, quantity and cost must agree, with matching account, region, resource, currency, volume type and contractual dimensions. Native GiB/s-month quantities and rates are converted together to MiB/s-month; the original amount is unchanged. Public prices cannot substitute for missing customer rates. A compatible peer volume is a rate witness, not evidence of the assessed volume's demand.

Storage, provisioned IOPS and throughput are distinct from snapshot, Fast Snapshot Restore, archive and other continuing charges. Absence proofs require complete native scope and known attribution; missing resource identifiers or unresolved continuing charges do not become zero. Snapshot cost uses billed evidence, never the source volume's nominal size. Credits and negative results remain signed. Monthly and annual amounts are conditional 730/8760-hour estimates, not verified savings or calibrated demand forecasts.

Source corrections, changed configuration or policy, expired dependency reviews and changed configuration declarations invalidate currentness without rewriting historical advice. Terraform ownership is an actual registered declaration bound to the storage resource and address. It is labelled `DECLARED_NOT_ATTESTED`, points to declarative remediation and confers no saved-plan or apply authority. Its graph node is an explicit reference, not a discovered AWS resource.

The existing `/v1/coverage` denominator retains all detected AWS service charges, unowned resources and resource-less charges. Only canonical billing lines used by a current economically supported assessment count as analysed. Observation-only, blocked and unsupported spend remain visible; credits do not reduce the positive-spend denominator. Missing source scope and unknown or zero denominators make percentages unavailable.

## Installation and external gates

Fresh installations leave the `storage-assessment` Compose profile and Helm `storageAssessor.enabled` off. Explicit opt-in creates only the separate product analytical login and evidence reader. Customer-role Terraform adds enumerated read operations only. Hosted data and processing remain in eu-west-1. Credentials stay outside tracked files.

The existing EC2 forward safety checks may read only the immutable native attachment descriptors and configuration-declaration columns required by the dependency graph, under tenant RLS. A physical attachment can qualify only with current ingester evidence, matching account/region/workload, explicit non-production ownership, a single attached instance and no Multi-Attach or service management. Unknown or shared storage and actual service consumers remain blockers. Existing owned START restoration is unchanged.

Real AWS identity, native source access, genuine observation history, customer ownership and policy, independent SLO instrumentation, native rates and external dependency review require supervised customer acceptance. No provider or customer acceptance is inferred from deterministic transports. No cloud resources are provisioned by this package.

## Acceptance record

**COMPLETE — bounded deterministic performance-advice path.** Native provider-shaped discovery and collector persistence pass against actual versioned objects, ClickHouse and tenant-isolated PostgreSQL. Separately, server-selected native billing and storage evidence reach the actual API, restricted analyst, authenticated Python service and normal OIDC console. Positive gp2-to-gp3, gp3 IOPS and gp3 throughput results, missing-telemetry refusal, unattached review and unknown-snapshot review survive persisted readback. These complementary boundaries use synthetic provider transports; they do not constitute customer AWS acceptance.

| Gate | Result | Exact evidence boundary |
|---|---|---|
| Final native collector, provider and compatibility checks | PASS | `dde193e7-4cd6-4a78-a55b-7d99d4ed1ccd`: 25 selected Go tests, no skips/failures/OOM; actual raw/archive/ClickHouse/PG readback and four restricted-role graph reads, cross-tenant absence and denied writes. Receipt SHA-256 `cded7fc9ceaa1517cbd26697ccdeb856b739baf31272cc2e03ef37e2238afa61`. |
| Full current Python discovery | PASS | Same collector invocation: 165 tests in 78.084 seconds, no skips, within the original 120-second/512-MiB/one-CPU limit. This includes the 18 storage component checks; test count earns no credit. |
| Final actual API/analyst/model/OIDC console | PASS | `13de544b-8246-4bca-a4c0-8b69ea1e2824`: six native subcases and one normal browser case, no skips or retries. Independent Go persisted/currentness readback finished in 59.79 seconds within the unchanged 120-second parent deadline. TypeScript and Vite passed. Receipt SHA-256 `6982f421e5817937a22cbe9e4d228b0595fdca9198efa784a03c839a97e5715a`. |
| Final source binding and cleanup | PASS | Both preceding invocations captured the same 1,099-file manifest, SHA-256 `1fac09466754e0967d374cf4b30767b71311c43f183f25e8b9017a1560107dc5`. Owned helpers were removed, protected services and credentials stayed unchanged. The subsequent bank changes documentation and ledger only. |
| Read-role Terraform | PASS | Offline `9df3b533-8b8b-4a46-971f-783fd77e7fe0`: formatting, initialization, validation and both exact mock plans, network disabled and cleanup complete. Current files match its retained formatted outputs. No AWS calls or provisioned resources. Receipt SHA-256 `2579b8631ba96fa6be2f497cfffb7e5ae83dcfebf0aba182e3b03cddb1a0ef1c`. |
| Optional deployment and schema guards | PASS | Twelve Helm render/negative checks, 43 existing Node guards and 12 MinIO shell checks. Final 042 hash `4167cf4ec6df2112e8d8a9233ef005e0105dfb33bd51e413310433356d1aaa30`; all 001–041 bytes are unchanged and unknown 043 is refused. Final response types regenerate from OpenAPI; actual generation and typecheck passed. These are component boundaries, not hosted acceptance. |
| Final-source regression and installed release | Separate release gate | The existing 16 required jobs, security/dependency/secret checks, installed migration/restoration and ordinary browser checks are reported on the exact head of [the existing pilot PR](https://github.com/christopherosiemo/bn-implementation-Finops/pull/1). The deferred commitment job stays enabled. This component record does not call the overall release green. |

Earlier failures remain failures. Native attempt `5075fd63` exposed a typed configuration-binding rehash defect; its smallest product repair preserves the original issued binding type and hash. Attempt `351bdba3` passed native/browser components but failed the independent-readback bridge because the fixture supplied a doubled results path; the basename was corrected without increasing any deadline. Subsequent attempt `44ca5fff` passed before the final compatibility/schema deltas. Final `13de544b` above rechecks those deltas and supersedes neither the historical records nor their verdicts.

**PARTIAL — wider storage acceptance and the full product.** io1/io2 advice remains blocked without independently supported equivalence. Retention/quarantine progression and filesystem-use migration have bounded model checks but do not have a complete connected positive acceptance journey. No storage execution, deletion, recovery action or verified saving is accepted. Earlier database partial acceptance and deferred commitment acceptance remain closed and unchanged.

**EXTERNAL_ACCEPTANCE_REQUIRED — genuine AWS/customer operation.** Actual customer read-role commissioning, Config/CloudTrail scope, genuine history, customer rates, ownership/dependency review, policy and SLO requirements need supervised AWS acceptance. Sustained production operation and contractual completion remain outstanding.

The fixed-weight ledger advances **25.9% → 26.3%** by splitting one point of the existing 9.5-point unaccepted optimisation pool and accepting only bounded read-only EBS performance advice at deterministic maturity 40. The other 8.5 points remain at zero; shared foundations, review-only classes and test counts earn no additional credit. All 23 prior reviews and the full contractual denominator are preserved. The rough engineering range including previously verified partial work remains **27–31%**, without a fresh whole-product audit.
