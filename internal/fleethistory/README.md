# Fleet history domain, version 1

This package has no storage, network, credentials, public upload route, financial
model, execution permission or runtime registration. `Analyze` always returns
`BLOCKED` historical membership: a point read, including repeated equal snapshots,
cannot establish ownership of any intervening interval. Point cadence gaps and
the entire unproved membership interval are reported separately.

`Registration` binds a fleet identity, workload and exact AWS account/Ireland ASG
ARN. It does not invent an ASG inventory resource. Each member has a native EC2
ID, numbered template and optional individually resolved inventory resource ID.
Missing launch time/hardware remains null and preserves the truthful ASG point
with explicit unknown-incarnation reasons. A recreated group must use its new
ARN. A new versioned derivation may later bind original archived hardware bytes;
old receipt hashes must not change.

Source identities are `(source_system, source_id)` pairs. AWS mutable registry
versions, source configuration hashes, immutable native data revision IDs and
receipt IDs remain distinct. A benign status/sync version increment with the same
configuration hash does not erase historical captures. A backward version,
changed hash, missing/stale current projection, revocation or degradation cannot
be treated as a currently usable source. Current source states are supplied by
the trusted repository adapter, never an observation body.

AWS membership/hardware references require `VERSIONED_OBJECT` with an actual
data revision, raw and canonical hashes and a pinned tenant-scoped object version.
Guarded activity evidence uses `ACTIVITY_SOURCE`/`POSTGRES_RECEIPT`: original
receipt ID, raw-body hash and canonical hash, without inventing a data revision,
registry version, object version or counter epoch. The existing activity source
document is hash-bound; its native metric definition ID/version/unit and
`Completed` field must match exactly. The first real adapter must load those
original immutable guarded rows and authenticated source itself. No API may
accept caller-supplied raw counts, timestamps, source states or hashes as proof.

Demand semantics are an explicit versioned declaration with a semantic contract
ID/hash, completed business operation/unit, independent external source and
`SINGLE_EXTERNAL_TOTAL` aggregation. Merely naming a metric `request_count` does
not establish completed work. This package checks the declaration and provenance
bindings; it does not authenticate the business meaning or prove causal work
preservation. Activity accepts `COMPLETED`/`DELTA` only. Native counter support
retains actual epochs, observed endpoints and exact integer count text; it does
not apply `increase`, extrapolate, prorate, assume reset-to-zero, sum overlapping
intervals or aggregate uncommissioned partitions. Null remains missing and `0`
remains observed zero. `ObservedUnits` is a partial observed subtotal;
`WindowUnits` is null whenever a required native interval is unknown.

Corrections require explicit existing immutable logical-point references.
Forks, cycles, conflicting immutable IDs and contradictory same-time native
observations stay unknown rather than winning by receive/publication order.
Superseded predecessors cannot become current merely because a new head is
unavailable. The trusted source adapter must establish any correction relation
from genuine source provenance; a body flag is insufficient.

`InputHash` binds every supplied record, source projection and original instant,
including blocked and superseded inputs. `SnapshotHash` binds the whole derived
private analysis. Collection/member order and equivalent timestamp offsets do
not change its semantic identity. `ValidateSnapshot` checks that exact resolved
input, not the currentness of an old input; later use must resolve source state
again. Integration may persist compact roots/counts and paginate immutable refs
instead of storing this full private analysis document.

The package tests are deterministic domain acceptance only. Genuine customer
history, interval ownership, semantic source commissioning, actual restricted
PostgreSQL/storage publication and a connected operating loop remain separate
acceptance gates. No complete/attested flag or money/action field is available.
