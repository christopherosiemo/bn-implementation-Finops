# Fleet configuration declarations and blocked proposals

The Fleet configuration family records operator intent for an existing Fleet-history registration. It uses that registration's tenant, workload, AWS account, Ireland region, Fleet ID and exact ASG ARN. It does not borrow a representative EC2 resource identity. A registration is an operator declaration; an ASG is observed only when separately issued native membership evidence is selected.

`configuration.FleetDeclaration` is metadata: Terraform repository/ref/directory, the intended deployment pipeline identity, workspace/state lineage, an ASG address, a launch-template address and an optional listener rule with two target-group addresses. Addresses name the intended configuration. They do not prove a native ARN-to-address mapping. Declaring a pipeline does not enroll an observer, trust callbacks, validate a Git revision, inspect Terraform state or authorize a plan.

The initial storage contract is additive migration `027_fleet_configuration.sql`. `FleetConfigurationAppend` appends a declaration revision with compare-and-swap against the latest declaration version for the registration. `Latest`, `Get` and registration-scoped `Page` return immutable documents. The declaration's `metadata` contains the typed input; the surrounding document contains server-selected group/source references and `DECLARED_NOT_ATTESTED`. Estimated and verified savings remain null and execution authorization remains false.

`FleetConfigurationProposalCreate` takes the registration, declaration and sealed Fleet-history scope IDs, the expected declaration version and the authenticated actor. It accepts no observations, amounts, prices, artifacts, state serials, commits or proof arrays. It resolves the stored documents and publishes a compact immutable `BLOCKED` proposal with hashes, the scope reference root, original history bounds and current source-state observations. Reference detail remains available through the existing scope pagination; it is not copied into a large proposal document.

Before publication, the repository holds the tenant dependency-graph lock, the Fleet-history registration lock, shared source-sync guards and source row locks. It checks the latest registration and declaration, exact source configuration and account/region, the latest demand definition, and the independent activity source's actual current resource/workload mapping. Revoked or changed source bindings, a superseded definition, a foreign scope, or a new in-window native point/correction absent from the selected scope prevents publication. A source synchronizing concurrently returns unavailable without borrowing an older healthy projection. Historical getters remain readable after revocation; they do not assert current readiness.

Missing intervals, sparse points, unobserved groups and degraded current source health remain explicit blockers. Legitimate blocked history can produce a blocked proposal. Equal membership points do not prove ownership between points. The independent `activity.Completed` definition remains a semantic declaration, not proof that work was preserved. The new hardware identity decoder's `last_start_time` is the latest EC2 start time and is never copied into Fleet-history incarnation fields.

Only the API database group can insert these two tables; the ingestion group can read them. Forced tenant RLS, append-only triggers, exact raw-document hashes, group/source closure and permanent no-authority fields are checked in PostgreSQL. Signer, executor and worker receive no new grants. Ingestion attestations, configuration artifacts, Fleet proof sets, FleetPlanV4 signatures, existing per-instance configuration contracts and Temporal command histories are unchanged.

FleetPlanV4 still requires an individual-resource binding. This group metadata family does not implement a bridge into that signed contract. A virtual EC2 resource or a representative member must not be manufactured to satisfy it. A future compatible signed family and migration need an explicit design that preserves existing signatures and durable replay behavior.

The authenticated public layer provides these registration-scoped resources:

- `GET/POST /v1/fleet-history-registrations/{id}/configuration-authorities`
- `GET/POST /v1/fleet-history-registrations/{id}/configuration-proposals`
- `GET /v1/fleet-history-registrations/{id}/configuration-proposals/{proposal_id}`

Platform administrators write metadata; reads recheck current workload access.
All mutations require `Idempotency-Key` and `If-Match` against the latest
**declaration** version, zero for the first declaration. A proposal request
contains exactly `declaration_id` and `scope_id`. The cursor-paginated
declaration response includes `latest` and `version`; proposals have a separate
query-bound cursor. Returning an immutable cached result still checks the
request's current route role. It does not renew captured source authority.

The console opens this family within a selected Fleet-history registration. It
shows declared addresses, frozen group/source/definition/scope hashes, exact
history bounds and captured source status. Historical or mismatched revisions
cannot appear as a saved current declaration. Legitimate blocked history remains
selectable to record its blockers. No UI flow uploads proof, enrolls a machine,
creates a plan or offers execution. Missing observations and money stay
unavailable, including genuine quiet periods with no complete history.

Local acceptance uses real restricted PostgreSQL logins, signed JWT/JWKS and
explicit native source fixtures. Seven database test families include positive
controls, 26 direct-SQL forgery refusals, concurrent revisions, current activity
mapping and native point/correction closure. The authenticated API regression
passed in 5.712 seconds and the console's four new isolated presentation cases
passed alongside the existing four Fleet-history cases. Connected browser and
process/migration recovery are separate release checks.

For an actual local upgrade recovery drill, first build the reviewed next Go
image while the retained fixture database still has a pending additive migration.
Run `node scripts/recovery-smoke.mjs --migrate-before-restart` serially. It
requires confirmed local fixture mode, the isolated other-tenant test identity,
unchanged applied migration hashes and a distinct prepared image. After the
original occurrence owns a stopped fixture instance, it stops API/worker, applies
the pending migrations, replaces those two processes and requires the same
occurrence to complete readiness with exactly one audited stop/start. It never
resets the original occurrence or manufactures new restoration authorization.
Both modes bind the HTTP fixture endpoints to the inspected local Docker daemon,
workspace/project, exact service roles, private network and database. Upgrade
mode also pins the prepared image and embedded migration manifest before any
mutation. An inert inspected migrator cannot execute DDL until original stopped
ownership and the signed-envelope hash are independently confirmed.
Ordinary recovery acceptance retains its existing command without this option
and does not require pending migrations or a prepared image. The actual
026-to-027 upgrade passed all seven checks before the full runtime suites.

These checks cannot establish customer Git/state authority, historical ASG
ownership, Fleet capacity, native future prices, work preservation, verified
savings or permission to execute a Fleet transition. Those gates stay unresolved
in every declaration and proposal.
