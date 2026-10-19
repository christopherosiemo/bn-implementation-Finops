# Isolated file-journal Git/Terraform component

This new fixture is independent of the two accepted artifact labs. It uses the
same pinned official Terraform 1.16.0 and Go 1.27.2 images, a fresh local Git
repository, and only the built-in `terraform_data` model. It contacts no AWS,
application API, PostgreSQL, Temporal, OIDC issuer or external network.

The intended acceptance is a preparation no-op plus three real saved-plan
forward effects, followed by three strictly LIFO inverses. Every inverse is a
new commit. The complete approved 5.1 manifest remains immutable; this exercise
does not run all 26 forward operations or establish whole-program recovery.

An additional, explicitly approved journal contract precedes the first journal
command. Fixture approval, pipeline and ledger keys are distinct. The private
producer writes a preparation reservation before Git CAS, then finalizes the
captured plan on the same command. Positive signed `NOT_DISPATCHED` evidence
precedes the durable apply intent and exact binary-plan delivery. Missing
callbacks never prove that an apply did not happen.

Git advance, native apply and Git-only repair each require a fresh exact
current-head permit at their actual delivery boundary under the writer fence.
Renewing a head does not renew stale preparation, READY or apply intent. Expiry
negative probes use explicit logical time only as an additional refusal after
the mandatory real-time gate; they do not change persisted clocks, authorize an
effect, or establish elapsed native expiry/health-window acceptance.

The file adapter checks a separately resolved current head and full signed
hash chain under an exclusive nonblocking Linux file lock. Canonical event
lines are fsynced before an atomically published, fsynced head. Torn tails,
extra bytes, stale heads and incomplete head publication fail closed and are
never truncated automatically. A separate subprocess reopens the actual files
without loading signing keys on that code path; an invocation audit proves
terminal receipt reconciliation did not call Terraform again. Historical
checkpoint signatures and projections are checked in one reducer pass at their
event times, with currentness checked separately on the persisted final head.
An issuer-only renewal preserves that exact head reference and projection.
This is a file-backed fixture, not an implementation or acceptance of a
PostgreSQL journal service.

All fixture subprocesses run as the same private local UID. Although the
keys and signature domains are distinct, a verifier subprocess could access
the private fixture key file. This lab does not establish OS-enforced identity
separation, commissioned pipeline authentication or a production key boundary.

Negative cases include a competing writer, malformed/torn records, a stale
head, duplicate and conflicting callbacks, already consumed effects, and an
uncertain apply. UNKNOWN stays held across the actual process reopen until a
surviving authenticated terminal receipt is deliberately delivered. A separate
actual Git-CAS/process-exit cutpoint obtains definitive signed no-apply proof,
then uses a new sole-parent Git-only repair commit without any Terraform apply
or native state change. Repair permanently aborts forward progress while
retaining the three prior effects for their exact LIFO inverses. It cannot use
UNKNOWN or callback absence as no-apply evidence.

Plans, state, Git objects, signed events and diagnostic output are retained
only as private authenticated AES-256-GCM ciphertext. The local fixture key is
kept separately and is never printed. Both producer and host authenticate
every retained object. The runner pins the local Docker daemon, immutable
images, source snapshot, exact bind sources and owned cleanup. No host Docker
socket or credentials enter the test container; it has no network, published
ports, capabilities or writable root filesystem.

Run the focused guards before the actual lab:

```text
node --test scripts/tests/fleet-group-journal-lab.test.mjs
node scripts/fleet-group-journal-lab.mjs
```

No command-line targets or credentials are accepted. The result stays under
`work/private/fleet-group-journal/<run-id>/`. `PASS` is written only after the
exact owned container and tooling tag have been removed. No customer-native
authority, real health dwell, verified savings, commissioned independent
pipeline identity, PostgreSQL, Temporal or production crash-recovery claim is
earned by this component.
