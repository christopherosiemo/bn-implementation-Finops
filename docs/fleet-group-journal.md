# Private issued journal and recovery component

The journal is a separate, explicitly approved fixture contract around an
unchanged schema-5.1 group program. It does not enable a public action or grant
an existing signer, worker or executor new database permissions. The original
single-child recovery validator remains strict. Neither a schema-5.1 parent
alone nor an uploaded hash chain can opt into composable recovery.

## Authority and currentness

Before the first command, an independent approval binds the journal policy to
the exact parent envelope, tenant/group/realm, pipeline, controlled Git ref,
base state and three distinct signer, pipeline and ledger keys. Future services
must resolve these keys and the latest head server-side. A valid old signature
does not establish currentness. An expected head supplied by an untrusted caller
would defeat this boundary.

The ledger head binds the complete ordered record prefix and its projected
state. Historical heads are checked at their recorded event times. The latest
independently selected head must also be fresh. Refreshing a head cannot erase
an unresolved command, change state, renew forward approval or consume an owned
effect. Historical parent validation remains separate from current forward
expiry and fresh recovery authority.

## Preparation, dispatch and uncertainty

Preparation is durable before a Git move. It binds a stable operation, command,
idempotency key, fence, approved revision and before/after model. The private
producer finalizes only after the real Git transition and fresh saved plan exist.
Finalization attaches that exact signed artifact to the same preparation;
replacing it invalidates earlier readiness. Actual delivery must select the
persisted command and reject a stale same-ID copy before either Git or Terraform
changes anything.

Positive signed pipeline evidence that an operation has not been dispatched
precedes apply intent. Both forward dispatch and recovery dispatch check their
own current expiry and evidence. Parent expiry prevents new forward work while
preserving existing recovery duties. Late factual terminal receipts can still
record what happened; their arrival cannot authorize another dispatch.

An uncertain outcome retains the command and blocks forward work. A durable,
authenticated terminal receipt can reconcile an already applied operation once
without invoking Terraform again. A timeout, absent callback or similar-looking
state cannot establish that nothing happened. Indeterminate operations remain
held for further reconciliation or audited takeover.

## Applied effects and Git-only duties

Confirmed changed forward effects form a strict LIFO stack. Each inverse binds
the current authenticated head, the top unconsumed original effect and receipt,
fresh state and exact inverse artifact. Its new commit has the current controlled
head as its sole parent. Completing that inverse consumes the duty once and
preserves all earlier duties. Reversing several effects therefore appends several
commits; it does not reset history to an old SHA. An unrelated same-model commit
has no admissible issued transition.

The recovery envelope retains distinct preparation and fresh signing-head
bindings. Replay checks the signing head against the exact prefix at
finalization, rather than treating the preparation head as fresh authority.

Definitive no-apply evidence after Git CAS leaves a separate configuration duty.
A typed signed Git-only repair appends a commit restoring the preparation's
before-desired values while preserving exact native state bytes, IDs and serial.
It invokes no Terraform apply. Its terminal receipt consumes only that Git duty
and permanently aborts forward progress under the old manifest. Earlier applied
effects remain recoverable. Missing pipeline evidence cannot authorize repair.

Duplicate terminal receipts cannot revive consumed effects. Conflicting receipt
bodies, operations, fences, scopes, wrapper kinds and changed saved-plan digests
fail closed. The bounded policy supports at most 32 effects and 512 records,
with explicit capacity for the complete default forward/inverse protocol and
uncertainty headroom. Larger programs remain unsupported. Each canonical record
is bounded to 64 KiB and the input journal to 32 MiB.

These are component replay bounds, not a lifetime limit on restoration duties.
Before connecting a runtime, deduplicate authenticated receipt IDs and bodies
before adding authority events; transport polling and delivery audit belong
outside that stream. Genuine repeated recovery attempts can still exhaust a
bounded segment. A runtime therefore needs authenticated append-only continuation
segments carrying the original authority, current head, unknown operations,
active duties and consumed-effect tombstones, or an audited operator takeover
before exhaustion. Continuation must never renew forward authority. This
component implements neither continuation nor takeover. Reaching a bound must
not be interpreted as permission to discard ownership, truncate history, reset
the approved base or stop pursuing an existing restoration duty.

## Local acceptance boundary

The separate file-backed fixture uses actual local Git, pinned Terraform and
pipeline subprocesses. Its adapter uses an exclusive nonblocking file lock,
canonical fsynced events and an atomically published fsynced current head.
Its file log has a stricter 4 MiB fixture bound than the core's 32 MiB input cap.
Malformed or torn tails and incomplete publication fail closed; the adapter
does not truncate history automatically. A distinct-key signed operation registry
provides positive dispatch outcomes. Private raw artifacts remain in tmpfs or
authenticated encrypted storage and are checked again after the producer exits.

This is a trusted private-file component. Its processes share a Unix UID and can
access private fixture key files; it is not OS-enforced identity separation.
The verifier subprocess omitting signing keys does not change that limitation.
The file lock is not a distributed workload lease. Journal algebra and an
`APPLIED` receipt do not establish application health, elapsed observation
windows or release operational disruption reservations.

Actual 025/027 source resolution, restricted PostgreSQL identities and RLS,
OIDC pipeline enrollment, transactional outbox, Temporal orchestration,
cross-family exclusion, complete default-duration execution and financial
verification remain connected acceptance gates. The fixture exercises three
changed effects and their inverses, not the complete twenty-six-operation
program. All customer execution, customer verified savings and production
recovery claims remain disabled.

Run the focused guards and separate native fixture with no alternate targets or
credentials:

```text
node --test scripts/tests/fleet-group-journal-lab.test.mjs
node scripts/fleet-group-journal-lab.mjs
```

Acceptance is recorded separately in [the release record](acceptance.md). An
implementation or passing component check alone earns no connected Fleet credit.
