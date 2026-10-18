# Native telemetry pilot

Native telemetry is an independently deployed evidence transport. It has no
signer or executor token, customer EC2 role, or permission to write approvals,
financial claims, current-minute workload activity, or SLO receipts. Existing
schema-3 owned restoration continues independently of this optional integration.

The local Compose stack runs a real instrumented gateway and Prometheus.
`node scripts/native-smoke.mjs` checks actual machine OIDC, current OTLP,
replay/conflict and tenant boundaries, immutable MinIO versions, ClickHouse
facts, real raw-range Prometheus observations, durable historical requests and
incomplete-history blocking. `node scripts/native-otel-smoke.mjs` additionally
runs the official collector at the pinned image digest in its source. It uses
OAuth2 client credentials from an ignored mounted file and stops its temporary
container afterward. The gateway records actual requests and native creation
epochs. This lab has no fabricated 14/30/90-day history and makes no hosted AWS
acceptance claim.

## Hosted configuration

The Helm integration defaults to `telemetry.enabled: false` so upgrades do not
silently create identities or require new credentials. Before enabling it:

1. Run the reviewed migrations with the existing migration identity. Provision
   separate login members of `finops_telemetry_reader` and
   `finops_telemetry_ingress`; neither login may own tables or have superuser,
   bypass-RLS or other application-role membership. Provide separate database
   Secrets, named in `database.secrets.telemetry-reader` and
   `database.secrets.telemetry-ingress`, each with `DATABASE_URL` and TLS CA.
2. In a reviewed offline Terraform plan, explicitly set `telemetry_tenant_id`.
   Its default is null. The resulting two IRSA roles can put only under
   `tenant/<tenant>/native/*` in the raw bucket. Only the reader can call
   `s3:GetObjectVersion` and KMS decrypt. Neither can list unrelated source
   evidence, read a current unpinned object, assume customer roles, read signing
   secrets or mutate compute. Copy `native_telemetry_role_arns` into the two
   distinct Helm telemetry role fields. This repository does not apply plans.
3. Supply a dedicated Secret containing `TELEMETRY_READER_TOKEN`. Only API and
   reader reference it. The independent ingress verifies a machine audience
   distinct from human and activity audiences; configure its issuer/JWKS and
   match the API registration issuer. No machine client secret enters the API.
4. Provide the reader-only `TELEMETRY_READ_BINDINGS_JSON` Secret and a separate,
   endpoint-free API `TELEMETRY_BINDING_CATALOG_JSON` Secret. Each mapping binds
   the exact tenant, workload, provider resource, account, region and required
   labels. Reader bindings add HTTPS port-443 endpoint, explicit allowed CIDRs
   and an optional credential-file path. Credential Secrets mount only in the
   reader at `/etc/finops/prometheus-credentials`; the API never receives them.
   DNS resolution is validated and connections use the validated IP; redirects,
   metadata/link-local targets, unapproved CIDRs and invalid certificates fail.
5. List approved HTTPS egress CIDRs for the regional S3 endpoint, machine JWKS
   and Prometheus. The native roles are excluded from general HTTPS egress.
   Allow collector pod labels explicitly, or opt in to the existing TLS ALB
   route with `telemetry.ingressEnabled`. The reader remains ClusterIP and only
   the API may reach it. External ClickHouse must use an approved HTTPS endpoint;
   the default internal ClickHouse uses its dedicated network-policy path.

Use the same tenant ID in Terraform, Helm live tenant binding, source registry
and machine registration. Source secrets and endpoints are operator-managed;
caller uploads cannot grant themselves trust. Keep raw bucket versioning and
the native ClickHouse tables from `config/clickhouse/001_facts.sql` enabled.
New receipts publish only after both persistence checkpoints complete. Those
checkpoints attest the isolated transport's work, not a PostgreSQL inspection
of external bytes. Replay resumes durable checkpoints and does not create new
observation time or historical receipt authority.

## Semantics and limits

Prometheus uses raw instant-query range selectors, exact bound labels and native
metadata. It does not use `query_range` held values or extrapolated `increase`.
Counter metadata families omit the `_total` sample suffix. Original declared
units remain intact: for example Prometheus `requests` and `seconds` may become
OTLP `requests` and UCUM `s`; no unit is silently relabelled. Cumulative counters
and explicit histograms need a real epoch. The local gateway provides native
`_created` timestamps, consumed by the official collector. Missing epochs,
counter resets, absent points, unsupported summaries/exponential histograms,
different same-timestamp values and layout changes remain visible blockers.
`up` is scrape health and is not application availability.

OTLP accepts current uncompressed HTTP/protobuf from a registered machine.
Actual point time controls freshness; a legitimate old cumulative epoch is
retained separately. Native intervals do not become strict UTC-minute SLI
receipts. Explicit histogram counts remain decimal uint64 strings and quantiles
are conservative bucket bounds. Zero demand has null latency. Gauges describe
observed sample distributions, and counter rates describe actual intervals.
Complete local calendar history uses 14, 30 or 90 days selected by workload
policy, with DST handled by its IANA timezone. Query completion establishes
transport range coverage; actual sample cadence and missing intervals still
determine whether an evaluation is ready.

Evaluation is bounded at 250,000 unique native samples and 2,048 proof receipts;
larger input returns an explicit limit error. Thus dense multistream 90-day
history currently needs a streaming evaluator or a deliberately registered
lower source cadence. It is never truncated or accepted as complete. Segment
references are previewed at 16 IDs with full count/hash; versioned canonical
objects retain the entire evidence. Aggregate histograms above the summary
budget are omitted from the small projection while their population and source
hashes remain in those objects.

Validate assets without AWS access using the Terraform mock tests and Helm
`ci/native-values.yaml` render fixture, then `deploy/check_chart.py` and
`deploy/tests/test_native_chart.py` against the rendered manifest. Hosted
connectivity, customer metric binding and genuine historical coverage still
require commissioning evidence before any live acceptance credit.
