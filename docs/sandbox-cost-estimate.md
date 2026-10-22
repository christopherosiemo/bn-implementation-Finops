# Ireland sandbox cost estimate

The checked reference infrastructure subtotal is **USD394.11 per 730 hours**, before traffic, evidence, logs, burst CPU credits and the other charges below. The complete estimate remains **unavailable** until the customer reviews those quantities. This preparation record authorizes no deployment, spend or customer action. It adds no implementation or production acceptance credit.

Prices were checked on **2026-10-18 at 20:25:33 UTC** against official AWS public On-Demand catalogues for **Europe (Ireland), `eu-west-1`**. All amounts retain native USD, excluding taxes, discounts, commitments, credits, free-tier assumptions and FX. These public planning rates are neither a customer `ContractedCost` nor a price guarantee. Reprice before commissioning. The [checked JSON](sandbox-cost-estimate.json) records immutable catalogue versions, selected SKUs, rates, units and unknown inputs; the [offline model](../scripts/sandbox-cost-estimate.mjs) performs exact rational arithmetic.

## What the reference buys

This follows [Terraform variables](../deploy/terraform/variables.tf), [platform resources](../deploy/terraform/platform.tf), [network](../deploy/terraform/network.tf), [evidence storage](../deploy/terraform/storage.tf) and [Helm defaults](../deploy/helm/finops/values.yaml), inspected against accepted commit `21e2e8c4f07435fa314c5efb730074def36c3757`. The hosted design has separate control-plane and workload accounts. The control-plane account gets one EKS cluster, its nodes and storage, one RDS deployment, one NAT and evidence buckets. The workload account contributes existing read-only sources and workloads; its bill is additional. IAM read roles do not require duplicating the cluster, database or NAT in that account.

The desired two nodes share the API, scheduling, ingestion, economics, web, Temporal and ClickHouse pods; they are not charged again per pod. This is an infrastructure quantity estimate, not proof that those nodes satisfy actual capacity or availability needs. One NAT and one ClickHouse replica do not establish production high availability. Read-only commissioning still needs reviewed live Helm values: the example's `dataMode` is `fixture`, external OIDC and EU registry images must be supplied, and workload execution must remain disabled/absent under the [commissioning dossier](commissioning-dossier.md).

| Reference item | Quantity and public rate | USD/730h |
|---|---|---:|
| EKS control plane, standard support |1×730h×0.10 |73.00 |
| Linux/shared On-Demand `m6i.large` nodes |2×730h×0.107 |156.22 |
| Node encrypted gp3 root volumes |2×50GB×0.088/GB-month |8.80 |
| ClickHouse gp3 PVC |30GB×0.088/GB-month |2.64 |
| RDS PostgreSQL `db.t4g.medium`, Multi-AZ one standby |730h×0.138 |100.74 |
| RDS Multi-AZ gp3 allocation |30GB×0.254/GB-month |7.62 |
| NAT gateway |1×730h×0.048 |35.04 |
| NAT public IPv4 |1×730h×0.005 |3.65 |
| Fresh customer-managed KMS keys |6×1/key-month |6.00 |
| RDS managed master-password secret |1×0.40/secret-month |0.40 |
| **Reference subtotal** | **Unpriced usage remains below** | **394.11** |

The RDS instance and storage rates each already cover the primary and one standby. Multiplying them by two again would double-count. Catalogue links: [EC2/EBS/NAT](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonEC2/20261015191316/eu-west-1/index.csv), [RDS](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonRDS/20261006224050/eu-west-1/index.json), [IPv4](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonVPC/20261016224321/eu-west-1/index.json), [KMS](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/awskms/20260911124601/eu-west-1/index.json), [Secrets Manager](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AWSSecretsManager/20260911124610/eu-west-1/index.json). EKS publishes its [support-tier rates](https://aws.amazon.com/eks/pricing/) separately.

730 hours is a comparison period, not the length of every billing month. The model prorates fixed GB-month/key-month/secret-month quantities by hours/730 for this estimate; actual AWS meters and calendar billing govern invoices. Volume sizes follow provisioned billing quantities; S3 inputs must come from native billable storage/byte-hour measurements rather than an assumed compressed application payload size. The fixed subtotal excludes storage growth, extra IOPS/throughput and upgrade surge.

## Quantities that can change the subtotal

| Isolated change, all other assumptions held | New subtotal USD/730h | Difference |
|---|---:|---:|
| Four nodes instead of desired two, including roots |559.13 |+165.02 |
| RDS provisioned storage grows from 30GB to 100GB |411.89 |+17.78 |
| One optional internal ALB averaging one LCU |418.346 |+24.236 |
| EKS enters extended support |759.11 |+365.00 |

Terraform sets node desired/minimum 2 and maximum 4, and RDS storage autoscaling up to 100GB. These settings are reviewed assumptions, not a bill ceiling; deployments, surge, overrides, additional volumes and actual retained storage can differ. The ALB is absent by default because ingress is disabled. The illustrative ALB rate is 0.0252/hour plus 0.008/LCU-hour; actual LCU usage, controller installation, certificates, DNS and any internet-facing public IPs need separate review. [Ireland ALB catalogue](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AWSELB/20260911124544/eu-west-1/index.json).

The Terraform default EKS version is **1.35**. Its standard support ends **2027-03-27 at 00:00 UTC**; version 1.34 ends **2026-12-02 at 00:00 UTC**. The model rejects a STANDARD assumption when the estimate starts at/after that date or crosses it. It also rejects an EXTENDED horizon beyond the recorded end: 2028-03-27 for 1.35, 2027-12-02 for 1.34. It does not upgrade the cluster or change its support policy. Confirm the approved version and current AWS calendar before deployment; EKS extended support is enabled by default unless explicitly changed. [AWS lifecycle calendar](https://docs.aws.amazon.com/eks/latest/userguide/kubernetes-versions.html).

## Usage charges remain unknown

The following rates can price approved quantities; all quantities default to `null`, not zero. These meters do not cover every possible charge.

| Meter | USD rate | Quantity still required |
|---|---:|---|
| RDS T4g/T3 surplus CPU credits |0.075/surplus vCPU-hour |Actual Unlimited surplus-credit consumption; not all used CPU hours |
| NAT data processing |0.048/GB |Bytes routed through NAT; transfer charges are separate |
| S3 Standard first 50TB tier |0.023/GB-month |All retained versions, apportioned billable GB-months |
| S3 PUT/COPY/POST/LIST |0.005/1000 requests |Writes, multipart-related operations and listing |
| S3 GET/other applicable Tier 2 requests |0.004/10000 requests |Readback and verification requests |
| KMS symmetric requests |0.03/10000 billable requests |After applicable account-level allowances, if any |
| Secrets Manager requests |0.05/10000 requests |Secret reads/rotation traffic |
| CloudWatch standard log ingestion |0.57/GB |EKS control-plane plus RDS/application logs |
| CloudWatch retained log storage |0.03/GB-month |Native chargeable storage, including retained exports |
| RDS excess backup storage |0.095/chargeable GB-month |Backup/snapshot storage above applicable allowance |

Sources: [RDS CPU-credit pricing](https://aws.amazon.com/rds/postgresql/pricing/), [S3 Ireland catalogue](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonS3/20261015173540/eu-west-1/index.json), [CloudWatch Ireland catalogue](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonCloudWatch/20261007115540/eu-west-1/index.json), and the catalogues above. Ten surplus vCPU-hours would add 0.75USD; no zero-credit assumption is made. Backup retention is 14 days, but that does not determine backup size. RDS's running-database allowance and retained/manual snapshots must be evaluated across the actual account. [AWS backup charging rules](https://docs.aws.amazon.com/aws-backup/latest/devguide/rds-backup.html).

Five EKS control-plane log categories are enabled with 30-day retention; RDS PostgreSQL/upgrade export log groups have no explicit retention in these assets. Log volume is unknown. CloudWatch metrics, `GetMetricData`, queries and alarms are additional. S3 gateway endpoint traffic avoids the NAT path for applicable S3 access and the gateway endpoint itself has no extra charge; it does not eliminate all NAT or transfer usage. The single NAT's placement can introduce cross-AZ paths. [Gateway endpoint charging](https://docs.aws.amazon.com/vpc/latest/privatelink/gateway-endpoints.html).

The S3 helper handles only an explicitly apportioned first-tier population; it rejects more than 51200GB-months and does not calculate account-wide tier aggregation. Review other tiers and populations separately. Bucket keys are enabled, but a one-request/one-KMS-call ratio is not assumed. [KMS pricing](https://aws.amazon.com/kms/pricing/) charges 1USD/month for each fresh key and an additional 1USD/month for each of its first two rotations, capped after the second. Six keys can therefore grow from 6 to 18USD/month before requests. Model quantity `kms_billable_key_units` counts these capped billable units, not every historical rotation. Count existing rotations and additional secret versions/rotations from the chosen production secret arrangement.

## Evidence survives the pilot

Both evidence buckets have versioning and COMPLIANCE ObjectLock: raw versions are locked for at least 90 days, audit versions for at least 365 days. These are **minimum retention**, not expiration policies. No lifecycle expiration is configured. Every version is a complete billable object; an overwritten key does not replace the older version's storage charge. Compliance-locked versions cannot be removed early, and legal holds/extensions can retain them longer. [ObjectLock rules](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html), [version storage](https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html).

An arithmetic illustration, not a forecast: a 30-day pilot uniformly adds 1 billable GB/day of raw versions and 0.1GB/day of audit versions. It ends with 33GB. Under the same 730-hour normalization and first-tier rate, storage during those 30 days is 0.374301USD; each subsequent 730h with no deletion adds 0.759USD. If every version were deleted exactly when its minimum retention expired, the model's minimum lifetime storage component is 2.869644USD; this is not a minimum actual invoice:

`(30×90 +3×365) GB-days ×24/730 ×0.023 USD/GB-month`.

The last raw/audit writes can remain locked until roughly 120/395 days after the first upload. The actual configuration leaves versions indefinitely unless an authorized operator later implements appropriate cleanup. The example excludes requests, KMS and any growth after day 30. ObjectLock itself has no separate feature charge; regular retained storage and applicable requests still cost money. [AWS ObjectLock cost explanation](https://aws.amazon.com/blogs/storage/flexibly-control-amazon-s3-object-lock-retention-based-on-real-business-events/).

Terraform also prevents destruction of evidence buckets/KMS keys, protects RDS deletion and retains a final snapshot; the ClickHouse storage class retains its volume. Keeping evidence readable requires retaining its encryption keys. Pilot-expiry tags do not stop resources or delete these retained costs. This estimate is not permission to shorten retention, delete evidence or destroy keys. A final snapshot, retained backup, PVC, key or secret can continue charging after compute teardown.

## Inputs still needed before a spend decision

Review exact account IDs, approved commit/digests and Terraform plan; hours, autoscaling/surge and database/storage sizes; EKS support tier; source volume, corrections/versions, retention and recovery copies; NAT/transfer/logs/metrics/credit usage; and the retained-resource cost horizon. Reconcile estimates to the customer's rate agreement and actual native currency without silently substituting public prices for discounted costs.

The subtotal does not include EU ECR image storage/scanning/transfer, builds and deployment pipelines; external OIDC, VPN/private operator access, DNS/domain/certificate choices; remote Terraform state storage/locking/encryption; extra secrets, audit services or security tooling; customer export-bucket storage/versions/requests/KMS; existing workload instances, continuing disks/IPs and source-account fees; cross-AZ/regional/internet transfer; support or taxes. Azure/GCP source readers are uncommissioned; BigQuery processing can be billable and needs separate approved query location, scope and maximum bytes. No cross-provider query cost is assumed zero.

Customer approval must cover the completed quantity/rate sheet and retained evidence/key obligations before provisioning. The positive account-wide Terraform budget input and notification recipients remain customer decisions. Budget notifications are alerts, not a hard cap, deployment permission or an assurance of affordability.

## Reproduce the arithmetic

```sh
node scripts/sandbox-cost-estimate.mjs
node --test scripts/tests/sandbox-cost-estimate.test.mjs
```

These commands are offline and use no credentials. Six tests check 394.11USD, single-count Multi-AZ pricing, node/storage/ALB/support sensitivities, unknown-versus-zero inputs, retention tails and source metadata. JSON outputs preserve exact fractions and rounded display values; `full_estimate_usd` and `contracted_cost` remain `null`, and deployment/budget approval remain `false`. This verifies arithmetic and explicit assumptions, not an AWS invoice or customer environment.
