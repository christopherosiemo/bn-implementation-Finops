# AWS network and NAT read-only assessment

## Release boundary

This increment adds a network Observe/Recommend path to the existing product.
It does not create or delete AWS resources, change routes or security controls,
enable Flow Logs, release addresses, create endpoints, or grant execution
credentials. Publications remain non-executable and cannot claim verified
savings. EBS, RDS/Aurora, object storage and commitments retain their existing
acceptance boundaries and outstanding failures.

The native collector, economic assessment and authenticated customer experience
are separate evidence boundaries. Passing their component checks does not by
itself demonstrate one commissioned AWS-to-customer operating journey.

## Native discovery and topology

The optional connector authenticates its concrete AWS caller account and assumed
role before reading the registered account and region. It uses a fixed signed
read-action allowlist, bounded pages and retries, refuses redirects, preserves
native responses, and rejects repeated pagination tokens and foreign ownership
or region evidence. Each collection records its own completeness or failure;
denied network reads do not suppress ordinary EC2 or S3 ingestion.

Discovery includes VPCs, subnets, Availability Zones, route tables and their
associations, NAT gateways and addresses, Elastic IPs, internet and egress-only
gateways, network interfaces, security-group context, endpoint placements and
service availability, peering, Transit Gateway attachments, existing Flow Log
configuration, load-balancer placement and AWS service prefix lists. Unsupported
or absent native fields remain unknown. Ownership, workload assignment and
configuration authority are preserved from existing customer records; tags and
names cannot manufacture authority.

Canonical resources retain native configuration and a topology hash. Network
relationships are analytical and do not modify EC2 stop/start execution
dependencies. Published assessments bind to configuration, topology, source and
billing evidence; changed or revoked evidence cannot silently remain current.

Native `availabilityMode` distinguishes zonal and regional NAT gateways. The
collector does not assign a hosting subnet or one AZ to a regional gateway when
AWS provides neither. It retains native address/AZ facts and automatic/manual
provisioning settings. Regional gateways can temporarily process traffic across
zones during expansion; the product does not treat one architecture as
universally cheapest or sufficient for customer resilience.

References: [Regional NAT gateways](https://docs.aws.amazon.com/vpc/latest/userguide/nat-gateways-regional.html),
[endpoint service availability](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeVpcEndpointServices.html),
[AWS service prefix lists](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribePrefixLists.html).

## NAT telemetry

The collector preserves native CloudWatch statistic, unit, timestamp, period,
sample count, dimensions and raw-page identity for all four byte and packet
directions, active/attempted/established connections, port allocation errors,
packet drops, idle timeouts and peak metrics. A missing period is never a zero.
Complete observed zeros require every selected period and positive native sample
counts.

The four byte series describe overlapping views. Economics uses the input pair
`BytesInFromSource` plus `BytesInFromDestination` for a non-overlapping total;
the output pair remains independently available for diagnostics. Peak metrics
retain AWS's documented `Count` unit and `Maximum` statistic rather than being
relabeled as exact raw-event rates.

Zonal requests use `NatGatewayId`. Regional requests additionally require a
native, explicitly selected `AvailabilityZone`. Current regional address records
do not prove a complete historical AZ footprint; that limitation remains a
blocker. The ordinary collector selects the last 30 complete UTC days at hourly
resolution, preserving CloudWatch retention constraints. It does not claim a
90-day seasonal history from this window.

References: [NAT metric semantics and dimensions](https://docs.aws.amazon.com/vpc/latest/userguide/metrics-dimensions-nat-gateway.html),
[CloudWatch retention](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/cloudwatch_concepts.html).

## Commissioned Flow Log sources

`AWS_VPC_FLOW_LOGS` registrations bind the tenant, account, source region, Flow
Log ID, native resource scope, read-role binding, field order, traffic type,
aggregation interval and exact destination bucket owner, region and prefix.
Public registration does not select credentials, a role ARN or an external ID.
The optional private network binding factory requires an exact tenant/account/
region/role match and a sufficiently scoped external ID.

Before report selection, the reader checks the existing native Flow Log
configuration, active/successful delivery state, destination, native text format
and delivery prefix. Trusted delivery requires a versioned destination and a
supported bucket writer policy restricted to `delivery.logs.amazonaws.com`, the
registered source account and regional log ARN. Customer AWS administrators
remain an explicit trust boundary. The configuration and policy hashes are
checked again after streaming. Parquet and Hive layouts are currently explicit
unsupported cases rather than being misread as text.

Object selection is confined to the registered report prefix. The server pins
versions, sizes and computed compressed-body SHA256 hashes; an ETag does not
become a full-object SHA256. Ingestion reopens those versions, validates gzip and
records, and rejects changed objects, malformed rows, account/region/resource
scope mismatches, interrupted delivery and altered boundaries.

Flow direction remains relative to the capture interface. Original packet
addresses, AWS source/destination service classification and native traffic-path
fields remain distinct. DNS names, IP membership alone, missing logs and a
single record cannot establish complete traffic or a safe route. Regional
service evidence requires the independent native service catalog and AWS prefix
list evidence in addition to native flow classification. Original client
addresses must match evidenced interfaces; a NAT interface's subnet is not the
client workload's subnet.

AWS Flow Logs are best effort. A validated delivery generation always retains
`complete_traffic_census=false`; `NODATA`, `SKIPDATA`, missing classification and
unobserved intervals remain visible. Native receipt completeness means the
selected objects were persisted and validated, not that all bucket, VPC or
account traffic was captured.

Reference: [Flow Log fields, capture semantics and limitations](https://docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html).

## Storage, replay and scale limits

Compressed reports stream through immutable 8 MiB archive chunks with readback.
Analytics writes use bounded 2,000-row ClickHouse batches. PostgreSQL retains
source registrations, immutable receipts, bounded cohort summaries, evaluation
snapshots and references; it does not contain raw Flow Log populations.

Native row IDs are hashes of the Flow Log identity and normalized native record,
independent of file names or delivery order. Replay uses deterministic batch
identities. Publication requires analytics readback of the expected unique rows
and variants, so overlapping or conflicting delivered records cannot inflate an
accepted generation after ClickHouse's retry deduplication window. File-level
checkpoints and deterministic replay preserve failed ingestion without issuing
a trusted partial receipt.

Current bounds include 10,000 selected objects, 32 GiB per compressed object,
4,096 returned traffic cohorts and 16 retained source/destination address samples
per cohort. Address-set truncation is explicit and blocks conclusions requiring
exhaustive membership. Bounded snapshots have an 8 MiB ceiling. Exceeding a bound
fails closed; these limits do not constitute large-customer scale acceptance.

The current selector enumerates commissioned-prefix objects; it does not yet
provide a general event-time window selection contract. Actual selected report
timestamps are preserved. Older prefix history or an incomplete Flow Log window
cannot be promoted to the collector's complete 30-day CloudWatch window. This is
an outstanding software/readiness gate, not merely a credential requirement.

## Economics and customer recommendations

The private Python evaluator separates NAT hourly and processing charges,
public IPv4, transfer, endpoint, Transit Gateway, PrivateLink and related
continuing components. Native pricing reads retain SKU/rate-code units, brackets
and technical dimensions, excluding public price amounts from interpreted
customer rates. Customer economics must resolve to matching immutable canonical
NET billing evidence; unknown components, missing scope or marginal pricing
remain unavailable.

The model produces read-only outcomes for gateway endpoint bypass, interface
endpoint alternatives, AZ/NAT path review, apparently idle NAT review, public
IPv4/EIP review, cross-AZ, cross-region and internet-egress review. It can reject
an uneconomic interface endpoint. It preserves security impact, resilience,
ownership, policy and declarative authority blockers; it does not promise a
replacement architecture solely because traffic is expensive. DR, replication,
retention and customer access requirements cannot be assumed away.

Existing Elastic IP resources are canonical inventory rows. EC2 and service
managed public IPv4 assignments are also retained explicitly within native
interface configuration; an assignment is not duplicated as a second EIP cost.
Native `DescribeAddresses` does not establish allocation age, which remains
unknown unless independent evidence supplies it.

## Read-only deployment and acceptance status

`enable_network_readonly` defaults to false. Its enumerated Describe,
CloudWatch, catalog and commissioned report/KMS reads attach only to the customer
read role. Report object access is limited to approved destination prefixes and
owners. It grants no NAT, route, endpoint, address, security-group, NACL, Flow Log
creation or execution permission. Optional analytical deployment remains off by
default, with a separate database identity and no provider, signing or execution
credentials. Product storage and processing remain in `eu-west-1`.

Component evidence available before the parent release run:

- Focused network tests pass for pagination, throttling, partial/denied reads,
  account/region confusion, regional dimensions, native zeros versus gaps,
  direction/service/path parsing, writer and object integrity boundaries,
  streaming/chunk bounds, interrupted ingestion, replay and private role binding.
- Existing provider, source and workflow package suites pass in the ordinary
  non-storage environment. Gated database/storage tests being skipped there are
  not counted as storage acceptance.
- Terraform module validation passes. The two new offline mock-plan cases remain
  enabled, but local execution has not been accepted: one selector produced no
  tests and a subsequent invocation encountered a provider checksum memory error.
- The new native collector storage test compiles. It is designed to use the
  existing owned PostgreSQL/MinIO/ClickHouse lab, a separate actual ingester
  login, provider-shaped synthetic native transports, immutable readback,
  replay/tenant isolation, API write refusal and source revocation.

**Final component parent acceptance: PASS**, as recorded below. Installed
migration/restoration, ordinary installed browser and final-source required CI
remain separate release gates. The collector fixture and assessment/browser fixture are explicitly separate
component boundaries. Their results must not be relabeled as genuine AWS
commissioning or an unrun single end-to-end evidence chain.

**External acceptance required:** real AWS read-role access and native report
commissioning, genuine observation history and customer rates, workload
ownership and configuration authority, security/DNS/access policy, resilience,
DR/compliance requirements, customer review and sustained operational acceptance.
Outstanding software and scale limits remain separately visible. No network
mutation or verified-savings acceptance is claimed by this release boundary.

## Banked economics and application scope

Network component maturity **20** is accepted, advancing official completion
**26.5% → 26.7%** within its reserved one-point scope. Focused PostgreSQL,
projection, financial and Python checks demonstrate components; they do not earn
full Network deterministic maturity 40. The complete native collector → retained
evidence → assessment → ordinary authenticated console path remains unaccepted.
The final parent run and release checks must be reported separately.

The implemented application boundary selects registered resource/policy IDs;
callers cannot submit authoritative observations or prices. A separate analytical
identity evaluates immutable native NET evidence through the private versioned
Python route and publishes read-only assessments. Economics retains exact integer
traffic-allocation ratios, rounds monetary outputs to decimal strings at twelve
places, separates observed charges from modelled allocations, preserves negative
results, and retains shared NAT hourly obligations in endpoint comparisons.
Server evidence/authority blockers remove positive candidate amounts and high
confidence from the result being published. Ordinary inventory, details,
recommendations and coverage views expose those results and their limitations.

| Family | Implemented component scope | Remaining native/application acceptance or software scope |
|---|---|---|
| A — S3/DynamoDB gateway bypass | Positive native-rate models, regional service/prefix and client-interface/route projection, existing-endpoint suppression, access/security and declarative-review blockers. | One accepted collector-to-console chain using the same collected population, complete comparable observation window and current customer billing proof. |
| B — Interface endpoint | Multi-AZ hourly/processing comparisons, native NET rate binding, positive and negative outcomes including `DO_NOT_CREATE_ENDPOINT`. | Generic service destination-region proof and unresolved native GB conversion must remain unavailable; the synthetic service-prefix witness does not establish native support. |
| C — AZ/NAT topology | Native zonal/regional distinctions, path/resilience constraints and burden review. | Complete alternative architecture costs, AZ footprint history, reliability and operational-complexity comparisons are not implemented acceptance. |
| D — Idle NAT | Complete observed zero differs from missing telemetry; dependency review is non-executable. | Regional historical AZ coverage remains unknown; no regional idle census, deletion saving or removal authority is claimed. |
| E — Public IPv4/EIP | Associated/unassociated EIP classification and carrying-burden review; public assignments are retained in interface inventory. | Broader EC2/service-managed IPv4 and BYOIP assessment/billing linkage, allocation-age evidence and complete connected acceptance remain partial. |
| F — Cross-AZ | Separately visible native transfer burden and resilience-preserving review. | Complete source/destination workload attribution and evidenced alternative topology economics remain incomplete. |
| G — Cross-region | Separately visible burden with DR, replication, compliance and geography safeguards. | Native destination-region/purpose attribution and justified architecture counterfactuals remain incomplete. |
| H — Internet egress | Attributable burden and conditional architecture review without promised replacement savings. | Complete workload/path attribution and independently modelled alternatives remain incomplete; CDN optimisation is outside this package. |

The persisted API/Python/browser component fixture supplies explicitly synthetic
canonical snapshots. Its interface-endpoint case also supplies a synthetic
Secrets Manager service-prefix witness. Native `DescribePrefixLists` collection
currently supports S3/DynamoDB gateway service prefixes; this fixture cannot be
presented as native generic PrivateLink destination proof. The separate native
collector component exercises provider-shaped transports, archive/ClickHouse
persistence and tenant-isolated receipts. Passing both separate components does
not establish a single native end-to-end chain.

Outstanding **software acceptance gates** include native GB-unit evidence where
unresolved, event-time Flow Log selection and exact comparable windows,
shared-NAT source-workload attribution, broader public IPv4 assessment linkage,
regional historical footprint evidence and complete architecture comparisons.
Actual customer credentials alone do not close these gates. Genuine AWS
commissioning, sufficient real history and customer NET rates, ownership,
security/DNS/access, retention/recovery/resilience decisions and sustained
operation remain **external acceptance gates**. All A–H publications remain
non-executable, with no network mutations or verified savings.

## Bounded acceptance receipts

| Gate | Result and retained boundary |
|---|---|
| All-source offline compilation and focused PostgreSQL/API/financial/projection checks | PASS, 20 top-level checks, no skipped/failed cases or OOM; run `ccc53ba5-79f2-4295-b747-808563897073`. Receipt SHA256 `5b3fcc4fd789a30b2be276a053fb0a211ba0e442c1197975f042cb9397ad3123`; source manifest `385fcdcb7ec71ead031274bab6dd6db8008dde6886cbbc70c487d92b6a81d775`. The earlier policy-table typo failure remains retained. |
| Exact additive schema and script regression suite | PASS: 29 schema guards and all 417 Linux script cases. Migrations 001–043 are unchanged; 044 SHA256 is `d6f6e453d424f06356fc45d1d53b5b64a76325168e393db249b37d9c301b895f`, and unknown 045 is refused. |
| Full Python, frontend build and supplementary UI components | PASS: 215 full Python cases in 99.845 seconds and again in 88.128 seconds under the unchanged 120-second limit; generated frontend types/typecheck/Vite build and 17 ordinary assessment presentation cases. Presentation tests do not supply persisted native/browser acceptance. |
| Native parent attempt 1 | FAIL, run `8fa13a06-12b3-4412-bc07-77e27f8a911a`, `FLOW_OBJECT_CHANGED` before publication. Receipt SHA256 `84d6f6b6d21e527234e7b29210d50ae4cc10d56983c6836e4c010060f92c4e9e`. Missing optional GET length had become zero. The fix preserves unknown length and still requires the pinned version, exact streamed byte count and SHA256. Focused wrong-length/size/hash cases pass. |
| Native parent attempt 2 | FAIL, run `4e764d3b-3fc0-41af-be94-72ba5814c2bc`, `NETWORK_FLOW_TOPOLOGY_BINDING_CHANGED` after successful native flow parsing/archive/analytics validation. Receipt SHA256 `58934ff2223d3ef7e087fd771853302e48dc4ff54c5d282fc68aa2a9927b8d27`. Re-serializing a typed JSON selection into sorted maps changed its byte hash. Both new Network readers now verify original bytes and retain configuration binding; focused raw-order/large-integer/tamper checks pass. |

Both failed parent runs cleaned up their owned helpers and preserved the source,
index, HEAD and original project services. Neither reached the API/Python/browser
stage. Original deadlines, retries and resource budgets remain unchanged. Final
parent, installed migration/restoration, ordinary browser and all required CI
results are separate release gates; consult the exact head of [the pilot PR](https://github.com/christopherosiemo/bn-implementation-Finops/pull/1/checks).

## Final component capture

**COMPLETE — the named component acceptance capture.** Run `355c77e7-e92b-49fd-a26f-193742627f81` passed under the original limits: all 215 Python tests (104.917 seconds), native collector storage/receipt acceptance (10.85 seconds), the separate persisted API/private-Python/real-OIDC console case (101.28 seconds), and independent stored-result readback. The browser passed one case with zero retries, skips or flaky results. Owned helpers cleaned up; source/index/HEAD and all original project services were preserved.

Receipt SHA256 `fdbcf3f420d1ef78a9c873adcb69ed166cfa11b876c2de807abc048f0d6a6a9d`; captured-source manifest SHA256 `14ef912fffb0a6810ec72870dcc21e374136868d337581f7723305373fc56e84`. Both earlier failures remain failures. No timeout, retry or resource-limit increase, fixture authority bypass, AWS provisioning, mutation or verified-savings claim supplied this result. The final code includes the exact-byte reader and unknown-length fixes described above.

**PARTIAL — the requested whole Network/NAT vertical.** The collector and explicitly synthetic canonical API/model/browser fixtures are two separate component boundaries. Their successful capture does not prove one complete native traffic/billing-to-console customer chain or close the A–H software gaps listed above. Official maturity remains 20 and completion remains **26.7%**; no additional credit is awarded for this capture.

The gateway comparison uses the versioned S3/DynamoDB gateway semantic rule documented by [AWS gateway endpoints](https://docs.aws.amazon.com/vpc/latest/privatelink/gateway-endpoints.html), independently of customer NET pricing. It retains continuing NAT hourly costs and requires scope, route, access and security evidence.
