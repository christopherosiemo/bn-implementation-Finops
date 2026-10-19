# Native fleet evidence comparisons

The read-only comparison connects two captured fleet configuration proposals to
current provider evidence. It selects real group registrations and their native
ASG identities. An individual resource ID cannot represent a group.

`POST /v1/workloads/{id}/fleet-native-assessments` accepts only original and
candidate proposal IDs, an idempotency key and the current safety-profile version.
The server selects and freezes the group bindings and profile. A dedicated worker
reads authenticated, versioned source objects and appends a separate result.
`GET` on the workload collection uses scoped opaque cursors; the individual
request endpoint retains its historical result after source revocation. New
publication must still pass current source, registration, profile and correction
checks. Finance and workload authorization precede idempotent response reuse.

The worker authenticates both receipt and revision object versions. A repeated
capture may legitimately create two versions containing identical bytes; both
must read back and match their hashes. Billing references must bind the exact
current registration, source, revision and canonical records. The worker reparses
native inventory, hardware and CUR bytes rather than accepting monetary values
from the browser.

An observed comparison uses historical account rates, labelled
`HISTORICAL_ACCOUNT_RATE_ESTIMATE`, at the member count authenticated at capture.
Historical reads retain that observation time and its original validity period;
refreshing the view does not renew the evidence or establish current readiness.
Decimal strings retain their full precision, including zero and negative
differences. Missing prices remain unavailable. This comparison does not prove
contracted avoidable cost, capacity fit, preserved business work or savings.
Continuing storage, network, IP, commitments, shared fees, migration/overlap and
tax are excluded from this compute-rate scenario rather than silently treated
as savings. The result cannot issue an executable plan or financial claim.

Per-member capacity references remain separate. Missing hardware or member
results cannot shrink the authenticated member population into apparent complete
coverage. A current membership point does not establish historical interval
ownership. Historical ownership, complete independent demand, native capacity
approval, configuration authority and financial verification retain their own
gates.

The separate [group-selected capacity queue](native-hardware-capacity.md#group-selected-member-evaluation)
now evaluates every observed original member against the captured native candidate
configuration. Its immutable 036 records do not replace these 035 historical
comparisons or confer group capacity, execution or financial authority.

## Local worker

Run the normal bootstrap and migrations before opting in:

```powershell
node scripts/bootstrap.mjs
node scripts/fleet-assessment-compose-check.mjs
docker compose --profile fleet-assessment up -d fleet-assessment
```

The optional profile defaults off. It uses a separate `finops_group_assessor`
database login and dedicated versioned-object reader. Credentials are mounted
as individual files from ignored local configuration. Bootstrap atomically
publishes `database`, `access-key` and `secret-key` under
`work/private/fleet-assessment-secrets`, with an owner-only host directory and
read-only source files. A network-isolated initializer copies these into regular
`0444` files on a dedicated Linux volume; this avoids Windows projection changing
the executable bits. The worker mounts that volume read-only and retains its
strict file checks. Repeat bootstrap, run the initializer and restart this worker
after local credential rotation. The common signer,
executor and raw-writer environment is absent. The worker processes persisted
requests for the commissioned fixture tenant and exposes private health and
readiness endpoints. It cannot ingest source evidence, sign, execute Terraform
or mutate cloud resources.

Keep the local reader policy specific to `tenant-demo`. Local provider transport
is visibly a fixture and cannot establish native customer acceptance. The
rendered Compose check keeps resolved service secrets in memory and prints only
a bounded result. Do not redirect `docker compose config` into tracked files.

## Hosted commissioning

`fleetAssessment.enabled` also defaults false. Enabling the Ireland Helm
deployment requires an existing dedicated renewable IRSA identity, exact evidence
bucket owner, commissioned tenant, distinct verified-TLS database secret and
reviewed regional HTTPS/private RDS destinations. Provision nothing merely to
render or validate the chart.

The read identity needs versioned object reads for its tenant prefix and the
bucket-region read used at startup; encrypted objects additionally require
scoped decrypt access. It needs no source-export role assumption, object writes,
plan signing or execution permissions. The rendered chart accepts no static AWS
credentials and excludes this worker from general unrestricted HTTPS egress.
Review the existing role and KMS policy separately before enabling it.

The database secret is mounted as a single file so the worker does not follow a
projected-secret symlink. Restart this optional deployment after rotating that
secret. IRSA token renewal remains provider managed. Hosted identity, genuine
history and customer acceptance are separate from local deterministic tests.

Acceptance evidence belongs in [acceptance.md](acceptance.md); implementing this
comparison alone does not complete a native fleet execution or savings loop.
