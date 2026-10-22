# Private Fleet historical account-rate evidence

`internal/fleetbilling` is a private prerequisite broker. It has no public route,
provider credential acquisition, dispatch hook, parent-proof publication, R1
measurement reuse, savings write or cloud provisioning. `READY` means that a
conditional historical account-rate comparison was observed. Every stored row
retains `execution_authorized:false`, `verified_saving:null`, and
`hard_spend_cap:false`.

The ingester supplies a server-owned `Target` (tenant/resource/workload, exact AWS
account, eu-west-1, source registration, and existing old/candidate ASG names).
`Broker.Capture(ctx,tenant,resource,programDuration)` resolves issued AWS source
receipts and persists the result through the ingestion role. An unavailable
result has no issued ID. `Get`/`List` expose historical metadata under tenant RLS.
`Broker.Revalidate(ctx,tenant,issuedID,programEnd)` checks an issued snapshot
against current authority without renewing it. Future orchestration must still
perform its atomic current forward-action checks at dispatch; this component
does not install a Fleet executor integration.

Source health and complete payer/all linked accounts/all regions RI/SP scope
must be at most five minutes old. Any current RI or Savings Plan requires a
portfolio model and blocks this pilot. Current membership, exact numbered launch
templates, and independent hardware observations must also be fresh. Source
revocation and publication use an explicit registration row lock without giving
the ingester registration UPDATE permission. Migration 021 provides append-only,
forced-RLS storage: only the dedicated `finops_ingester` role inserts; API,
worker, signer and executor can read. A read does not revalidate authority.

The broker selects fourteen complete UTC billing days from the latest authenticated
CUR2 revisions. The covered end must be no more than 48 hours old. The old baseline
requires uninterrupted positive native instance-hour coverage for every **current**
old member. Its explicit basis is
`CURRENT_MEMBERS_NATIVE_BILLING_HISTORY`; membership at historical usage times,
workload preservation and workload allocation are unproved. No old baseline
cost is described as a verified or realizable saving.

Raw and canonical hashes, source/revision/job IDs, payer/account/region/currency,
record IDs, original provider fields, times and native costs must agree. The
current resource's known currency cannot be silently replaced. Full-payer rows
in the baseline are retained in the economic correction hash; cross-member,
global-region credits, fees and historical commitments block the pilot. A later
partial export cannot inherit the authority of a previously complete revision.

Current receipts alone do not supply an AMI's missing billing dimensions. The
broker reads exact pinned versions of the archived native DescribeInstances,
DescribeImages and DescribeLaunchTemplateVersions responses, verifies every
selector and returned identity, and compares their typed receipts to the same
bytes. Both image and reference instance must explicitly report Linux/UNIX and
RunInstances, with no product-code software. The launch template must explicitly
declare default tenancy, and the independently observed reference instance must
also have default tenancy. Native ASG subnet IDs and explicit native instance
subnet/VPC values must place the reference inside that target group's subnet
scope; a reference in another VPC cannot establish target tenancy. Spot/mixed
market options, reservation targeting, embedded template subnets and license
specifications remain unsupported. Missing fields, different AMIs without their own
matching hardware receipt, premium licensing, implicit tenancy, and changed
template versions remain unavailable. Terraform attestor 020 cannot supply these
native dimensions.

Native CUR rows must explicitly carry Compute Instance/AmazonEC2, Usage/OnDemand,
Linux, Shared tenancy, No License required, NA preinstalled software, instance
type, **that row's own SKU**, operation, usage type, Hrs and actual positive
usage/cost/rate. The candidate needs matching independently observed native
hardware and its own account billing sample on the latest complete billing day;
the old SKU is never copied onto the candidate. Public OnDemand list prices and
FOCUS ContractedCost are not price authority. Paired native net-unblended cost
and rate take precedence, otherwise native unblended cost/rate are used. Both
native net columns must have actually been
exported (an explicit blank pair permits the unblended fallback). Missing
columns never establish absence of account discounts. Nonzero discount metadata
without a native after-discount pair remains unavailable. Exact
rational arithmetic preserves native decimal precision. Unresolved native
rounding, gaps, overlaps, SKU/rate changes and nonterminating inferred decimals
block rather than silently rounding or averaging.

Candidate rates are labelled `HISTORICAL_ACCOUNT_RATE_ESTIMATE`. An observation
does not lock future AWS prices or discounts, guarantee a spend ceiling, or prove
future candidate utilization. The immutable `valid_until` horizon is bounded by
capture + 24 hours and billing end + 48 hours, and must cover the complete proposed
program. Fresh current authority is checked separately before forward use.
Neither refreshes nor recovery may silently renew a signed historical reference.

Current revalidation conservatively requires the original old-member set and
fresh original pricing-reference instance facts. It can reject a legitimate
owned old-capacity drain or the disappearance of an unrelated reference sample.
An eventual per-stage Fleet factory must add exact owned-transition and frozen
native-dimension authority before using this evidence across the whole program.
This private component does not claim that the 26-child runtime integration works.

Run the deterministic tests with `go test ./internal/fleetbilling` and `go vet
./internal/fleetbilling`. Run actual local fixture acceptance sequentially after
Compose bootstrap:

```sh
node --test scripts/tests/fleet-billing-price-lab.test.mjs
node scripts/fleet-billing-price-lab.mjs
```

The runner refuses a remote Docker context or live/foreign source stack, stages
ordinary Go source only, and privately obtains only the local PostgreSQL test
administration credential. It creates a labelled process and a uniquely owned
disposable database/login, applies 001/002/005/021 there, authenticates the writer
through the restricted runtime constructor, and verifies conditional rates,
immutable replay, tenant isolation, source revocation, global corrections and
SQL role/authority denials. Native AWS XML/CUR and pinned-object reads are
explicit doubles; this is not a customer AWS billing/price acceptance or an
actual S3/ClickHouse journey. Application rows and its migration history are
untouched. Direct execution requires `TEST_FLEET_BILLING_ADMIN_URL`; the dedicated
runner requires its actual test to PASS and refuses a silent skip.

Each run creates fresh, labelled Go module and build volumes. A separate
credential-free process on the local outbound bridge downloads dependencies
using only copied `go.mod` and `go.sum`. The credentialed acceptance then runs on
the private fixture network with those downloaded modules, an empty build cache,
and no outbound network. The runner removes only its exact labelled caches after
the test; shared developer caches are neither required nor modified.

Native field references: AWS documents actual after-discount net-unblended
[CUR2 line-item costs/rates](https://docs.aws.amazon.com/cur/latest/userguide/table-dictionary-cur2-line-item.html),
[pricing units and public list price fields](https://docs.aws.amazon.com/cur/latest/userguide/table-dictionary-cur2-pricing.html),
[product/SKU attributes](https://docs.aws.amazon.com/cur/latest/userguide/table-dictionary-cur2-product.html),
[AMI platform and usage operation](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_Image.html),
and [explicit launch-template tenancy](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_LaunchTemplatePlacement.html).
