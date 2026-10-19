# Private recovered application health

The [empty-workspace reconstruction lab](group-workspace-recovery.md) preserves
an uncertain apply and executes its owned inverse. Its original result correctly
retains a health obligation. The next private fixture extends that result with
independent observation and a database-enforced reservation release gate.

Migration 034 adds an operator-commissioned health observer with its own signing
key and exact PostgreSQL login. Its identity is bound to one tenant, chain and
versioned metric definition. It cannot sign deployment plans, publish pipeline
artifacts, retire runtimes or mutate the journal. The ledger can select an issued
health outcome; it cannot manufacture an observer outcome. Observer reads and
writes are restricted to its commissioned tenant and chain, including direct SQL.

Before losing the first worker, the lab freezes the original signed baseline
anchor, issued receipt references and observer public configuration. Their exact
bytes are pinned in the private handoff. The replacement uses that baseline
after reconstruction and its fresh inverse; it cannot recalibrate a more
convenient baseline.

Each observation attempt binds the current workspace generation, inverse
command, selected positive terminal, restored state and exact journal head.
Outcomes retain separate receipt-content hashes and complete archived-object
hashes. Authenticated archive publication and the restricted Go/SQL boundary
bind both. A host-side validator additionally checks the independently pinned
observer key, signatures, immutable references, timing and ciphertext population;
it does not independently recreate HTTP measurements from public CI receipts.

Losing the observer closes its attempt as an immutable signed abandonment. A
new process starts a new attempt. Previously observed elapsed time cannot count
toward the new full 900-second UTC and monotonic window. Hard health objectives
and the 15% regression allowance remain independent requirements. Until a current
positive outcome is selected, the reservation remains held. The database blocks
release as well as the high-level repository method.

Migration preserves already-owned recovery. An immutable migration snapshot
identifies older managed chains with existing dispatch intent; they retain owned
inverse and release authority while new forward intents stay blocked. New
managed chains require the commissioned observer and original baseline evidence.
Unrelated historical scheduling plans and older capped fixture schemas retain
their existing semantics.

## Acceptance boundary

Run `node scripts/group-workspace-health-lab.mjs` against the normal local fixture
source services. It creates isolated PostgreSQL, versioned objects, an exact
retired worker and an empty replacement. A distinct observer subprocess exits
during observation, a signed abandonment is persisted, and another process must
complete a fresh full health window before release. The original pending-health
result remains unchanged; the additional result records the new acceptance.
Only bounded acceptance or fixed-vocabulary failure receipts are uploaded by CI.
Private keys, state, bundles, raw observations and logs are excluded.

Implementation and local acceptance are recorded in [acceptance.md](acceptance.md)
after the corresponding checks pass. A component test or a shortened observation
does not establish this actual native gate.

Actual run `d865a860-5911-416f-9e2c-f762de214b35` passed: a signed abandonment
precedes a fresh 933-second dual-clock window and database-gated release. Its
73 encrypted versions and complete owned cleanup passed independent review.
The preceding failed interop attempt remains recorded separately.

The fixture subprocesses share a container user and private mounts. Their
credential-filtering and independent database roles do not establish production
OS credential isolation. Public fleet execution, a deployed recovery controller,
external alert delivery, repeated workspace loss, customer pipeline identity,
genuine demand/economics, verified fleet savings and production recovery
objectives remain outstanding. No AWS resources are created by this lab.
