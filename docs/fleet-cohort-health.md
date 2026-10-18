# Private Fleet cohort health

This component is private and is not registered in the Fleet runtime or public
API. It cannot approve, sign, dispatch or apply a customer change. Native
membership/telemetry metadata in its protocol tests are labelled doubles;
ordinary tests use actual PostgreSQL SLI and authenticated callback receive
clocks. They do not establish customer AWS, native transport, public operating
loop or financial acceptance.

The pre-plan factory freezes an approved read-only DISCOVERY receipt's blue
members, exact current SLO objective/version/hash, stateless workload profile,
original per-minute SLI receipts and full-window physical CPU/memory evidence.
The immutable baseline lasts six hours. Its underlying source registrations and
native revisions must remain authoritative for every new forward health proof.

The current factory accepts a stored command ID. It selects its signed parent,
child, owned APPLIED callback, native membership and all member observations.
The server callback receive time, rounded up to a complete UTC minute, fixes
the start of the forward window. Every signed terminal window is preserved;
capacity intermediates need two minutes before another bounded child. Neither
a later healthy tail nor an aggregate can hide a missing, quiet or unhealthy
member minute. Missing last-minute delivery remains pending for at most the
existing two-minute receive allowance; received breaches and settled gaps are
unsafe. CPU/memory coverage and native membership must cover that same window.

Each minute and whole window must meet hard error, availability, p95 and p99
limits. Bounded histogram regression compares the frozen blue baseline and,
for ordinary candidate stages, actual concurrent blue controls. Histogram
uncertainty blocks; no percentile is interpolated from bucket boundaries.
The legitimate current short-window SLO evaluation retains its original
objective duration and is separate from the full-stage calculation.

Preparation can prove an explicitly observed empty green ASG and healthy blue
members without inventing green telemetry. A final reviewed drain can prove
an explicitly observed empty blue ASG and healthy green members only when the
same execution has a preceding accepted100%-traffic full blue/green control
window with identical green members and objective/profile bindings. Changed,
missing or unresolved prior authority blocks this exception. The bounded
intermediate capacity and drain steps still apply.

Unsafe owned windows append an immutable execution failure. Later good evidence
cannot remove that latch or create another forward proof. This protocol flag
is **not financial ledger enforcement**. Fleet still has no signed financial
measurement/claim contract; R1 stop-owned measurements are not reused. That
contract and failure-to-ledger enforcement remain mandatory before Fleet can
create financial claims.

Financial commissioning additionally needs genuine historical ASG membership
and instance-incarnation coverage. Current member lists and periodic point
snapshots cannot prove unobserved churn. A controlled topology needs a complete
independently retained change journal, or an approved historical source must
prove those intervals. The workload's business-demand definition also needs its
own immutable source binding; per-member SLO request counts do not establish
preserved business work. Explicit observed zero demand on both sides is valid;
missing observations are unknown, and a unit-cost ratio is undefined at zero.
See the [commissioning dossier](commissioning-dossier.md) for these financial,
full-program transition-cost and cross-action claim-overlap gates. The R1 idle
stop counterfactual and measurements do not provide Fleet financial authority.

Owned recovery is distinct. It requires the exact owned inverse and fresh real
post-APPLIED member/native/hard-SLO evidence over the current objective's two to
sixty minutes. A failed original canary, expired or paused parent, revoked old
sources or an obsolete regression baseline does not replace this fresh recovery
path. Green zero is supported. The current structurally valid workload profile
still governs health/headroom, including a reclassification after inverse
APPLIED; it does not grant renewed forward STATELESS eligibility. Destructive
or unknown compensation still needs the separate data-safety/ownership factory
and operator takeover when that inverse cannot be proved safe.

All new tables force tenant RLS and preserve append-only history. API alone
publishes the small member/baseline/window snapshots; worker may append a
failure but cannot publish healthy windows. The deployment observer cannot
write health, release reservations or modify financial evidence. Release
rechecks current source, objective, profile and the permanent latch under the
same workload lock. A changed profile requires a new valid current proof.

Migration022 also requires current forward authority when publishing a CLEAR
forward window, its cohort proof, HEALTHY evidence, or a reservation release.
An expired, paused, revoked or exhausted parent cannot gain a positive result
from an earlier healthy observation. The private factory appends BLOCKED
evidence and a recovery-only latch while retaining the owned reservation.
Fresh OWNED_RECOVERY evidence remains independent of that forward authority.

## Local reproduction and acceptance boundary

The focused normal PostgreSQL tests create/drop their own databases from
`TEST_DATABASE_URL`; do not point them at a restricted application login. They
copy migrations001–018 plus022 before use, excluding019–021. Synthetic legacy
parent timestamps test expired recovery compatibility; original callback and
SLI receipt clocks remain the actual server clock.

```sh
go test ./internal/service -run 'TestFleet(Member|Private|OwnedRecovery|ForwardObservation|DurationDatabase|Continuous|Delivery|Signed|Intermediate|Native)' -count=1 -v -timeout=15m
```

Full default-policy positive drain acceptance is a separate opt-in real-clock
test. It traverses every bounded capacity/traffic/drain child, including the
default one-hour canary and fifteen-minute terminal windows. Its26 children
need160 minutes of observation plus minute alignment and processing, usually
about160–190 minutes. No default windows are shortened or receipts backdated.

```sh
TEST_FLEET_FULL_PROGRAM=true go test ./internal/service -run '^TestFleetFullProgramRealClockControlledDrain$' -count=1 -v -timeout=235m
```

`TEST_FLEET_TEST_POLICY=true` selects the separately named
`TestFleetFullProgramRealClockTestPolicy`, whose parent explicitly signs120s
test windows. It exercises the same bounded protocol in about75 minutes and
earns no default-duration acceptance. The manual
`Fleet private protocol acceptance` workflow supports both policies against
an ephemeral PostgreSQL17 service and preserves logs. Neither opt-in test
enables a runtime queue, cloud credentials, public signing or financial claims.

Before the separate workflow is registered on the default branch, dispatch the
existing `Pilot validation` workflow on the reviewed branch with
`fleet_protocol=DEFAULT` or `TEST_POLICY_120S`. Its default `OFF` keeps ordinary
CI bounded. The selected job preserves the signed policy durations and fails
on a test or pipeline error; the exact checkout SHA is recorded in the artifact.

Full default-policy drain acceptance is pending until its exact snapshot run
passes. Full customer-pipeline/public runtime and financial acceptance remain
outside this component even after that protocol test passes.

Earlier frozen001–018 clock runs remain evidence for that earlier snapshot
only. Current-schema default-duration acceptance requires the exact reviewed
commit with022; those earlier runs do not imply acceptance of its new guards.
