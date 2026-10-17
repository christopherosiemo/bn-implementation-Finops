# Sandbox execution and financial readiness

The sandbox uses two independent decisions. `pre_execution_ready` authorizes consideration of a new stop; it does not establish realised savings. The readiness API reports `READY` or `BLOCKED`, with a separate `verification_status`. A frozen, complete baseline can be execution-ready while verification is `MEASURING`. Operational safety, exact-plan approval and fresh provider preflight still apply.

## Evidence version 2

New actions require a sealed baseline, a reserved measurement identifier and a sealed readiness report. Their identifiers and activation timestamp are signed into the immutable version-2 ChangePlan. Baselines retain tenant, internal resource, provider resource, AWS account, region, native currency, source version, canonical records, workload observations and schedule. Source hashes bind the snapshot to the persisted ingestion job. PostgreSQL forces tenant isolation and rejects snapshot update or deletion.

The private Python `/v2/evaluate` worker checks the same contract for fixtures and live evidence. It remaps original provider records and rejects changed canonical identities, timestamps or amounts. Fourteen complete local calendar days of actual billing and workload coverage establish the baseline; declared day counts and completeness flags have no authority. Explicit zero activity is valid. Missing activity is unknown. Covered or unknown commitment exposure blocks execution.

API uploads are labelled `CUSTOMER_IMPORT`. Persistence proves their immutability, not that AWS issued the invoice or that an independent workload collector observed the activity. Such uploads remain provisional and cannot make live execution ready or establish verified savings. A trusted provider export/invoice reader and independently authenticated workload collection remain required live integration gates. Fixture producer provenance is accepted only in fixture mode; logical fixture time is rejected in live mode. No submitted trust/completeness flag can bypass this gate.

Measurement starts after activation, references that baseline, and requires fourteen complete local days. Matching weekday/time windows use historical effective and contracted economics. Full-day activity must also be preserved, including work outside the scheduled idle windows. The financial window includes the startup lead through required availability. Actual compute, startup costs and attributable incremental charges reduce savings; retained storage and IP charges receive no avoided-cost credit. Reductions beyond executor-owned downtime are confounded. Manual shutdowns cannot supply ownership.

The implementation conservatively requires complete compute-record coverage. Standard exports that omit stopped intervals remain provisional until authoritative export completeness can establish those gaps; operators must not manufacture zero-cost records. Native contracted costs and uncovered commitment evidence must be present. Continuous payer-export harvesting, authoritative manifest integration, provider invoice finality and workload collector provenance remain outstanding integration work. Read-only discovery/inspection is usable without these financial integrations; a real stop remains blocked until they pass.

Invoice identity, issuance time, finality and at least 99.5% reconciliation are separate verification gates. Reconciliation uses the persisted source's canonical total, not a submitted reconciliation ratio. Unknown inventory costs display as unavailable. Estimated annual run-rate and verified period savings are separate values. Corrections append superseding ledger entries, preserve negative results and cannot overlap an existing resource/time claim.

## Migration and recovery

Legacy imports and ledger entries remain inspectable. Legacy evidence cannot authorize new stops or new verified claims. The console identifies unbound historical entries and excludes them from version-2 verified totals. No historical entry is rewritten.

An already-owned restoration remains authorized independently of the new evidence gates. Pause, approval expiry and evidence migration cannot strand the instance. A consumed restoration cannot start a later manually stopped instance.

## Deterministic acceptance clock

Fixture source data carries an explicit logical financial clock. Its baseline is 1–14 September 2026, activation is 15 September, and measurement is 16–29 September. A completed actual fixture provider cycle is mapped to one logical owned downtime interval: 16 September 20:00 through 17 September 06:45 UTC. Other intervals retain normal compute charges. Quarter-hour records preserve the same workload throughput as the hourly baseline. The normal validator derives £5.16 of synthetic period savings, including running startup time. The immutable mapping retains actual executor receipt timestamps alongside logical timestamps.

This clock is fixture-only. A live customer must collect genuine history, wait for the real subsequent observation period and satisfy billing finality. There is no commissioning bypass.

Use [sandbox deployment readiness](sandbox-readiness.md) for account inputs and rollout gates, and [acceptance](acceptance.md) for recorded checks. No AWS resources are provisioned by these checks.

The hosted credential design follows [AWS cross-account IRSA guidance](https://docs.aws.amazon.com/eks/latest/userguide/cross-account-access.html): trust exact service-account identities in the platform account and scope their role assumptions to the customer roles. [AWS Budgets documentation](https://docs.aws.amazon.com/cost-management/latest/userguide/budgets-managing-costs.html) documents delayed actual/forecast notifications; these monitor costs and do not replace the deployment estimate and approval gate.
