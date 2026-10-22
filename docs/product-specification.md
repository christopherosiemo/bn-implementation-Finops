# AUTONOMOUS FINOPS

# CLOUD COST AUTOPILOT

## Product & Technical Specification

**Document status:** Normative engineering specification  
**Product class:** Enterprise SaaS / FinOps / Cloud Infrastructure Control Plane  
**Deployment model:** Multi-tenant SaaS with optional customer-hosted execution agents  
**Primary buyers:** CTO, CIO, VP Infrastructure, Head of Cloud Platform, Head of FinOps, CFO  
**Primary users:** FinOps, platform engineering, SRE, infrastructure engineering, finance, application owners

---

# 1. NORMATIVE LANGUAGE

The words:

**MUST**  
**MUST NOT**  
**SHOULD**  
**SHOULD NOT**  
**MAY**

are intentional.

A requirement marked MUST is part of the product contract.

It cannot be removed simply because an easier implementation exists.

---

# 2. PRODUCT DEFINITION

Cloud Cost Autopilot is an autonomous infrastructure economics control plane.

The product continuously answers:

> What infrastructure should this organisation be running right now, given its workload requirements, reliability requirements, security requirements, expected future demand, contractual commitments and cloud prices?

It must then be capable of making approved changes.

The operating loop is:

**Discover → Measure → Understand → Simulate → Recommend → Approve → Execute → Observe → Verify → Roll Back or Continue → Learn**

This loop is the product.

A dashboard that discovers waste but depends on engineers manually implementing every change is not the intended product.

---

# 3. CORE CUSTOMER PROMISE

The customer should be able to state:

> Maintain my application requirements while continuously minimising unnecessary cloud expenditure.

The system then manages infrastructure economics within explicitly configured boundaries.

The master optimisation problem is:

```text
minimise:
    expected_effective_cloud_cost
```

subject to:

```text
availability >= required_availability

capacity >= required_capacity

latency <= required_latency

error_rate <= allowed_error_rate

resource_headroom >= required_headroom

recovery_objectives satisfied

security_constraints satisfied

compliance_constraints satisfied

regional_constraints satisfied

architecture_constraints satisfied

commitment_constraints satisfied

maintenance_constraints satisfied
```

The cheapest infrastructure is NOT automatically the correct infrastructure.

The cheapest **valid** infrastructure is the target.

---

# 4. WHAT THE PRODUCT IS NOT

It is not:

- a generic cloud-cost dashboard;
- another tagging application;
- a collection of recommendations copied from AWS/Azure/GCP;
- a budgeting spreadsheet;
- a cloud invoice viewer;
- another Kubernetes cost dashboard;
- a chatbot that describes AWS bills;
- an alerting system without remediation;
- a simplistic “delete everything below 5% CPU” engine.

Those capabilities may exist within the product.

They are not the product.

---

# 5. PRODUCT SUCCESS CONDITION

The product succeeds when it can truthfully say:

> This workload previously cost £241,000/month.

> It requires 99.99% availability, p95 latency below 180ms and at least 30% burst headroom.

> We identified £68,000/month of avoidable cost.

> £11,000 came from idle infrastructure.

> £19,000 came from oversized Kubernetes requests.

> £23,000 came from oversized compute.

> £15,000 came from inefficient storage.

> We simulated the changes.

> Every required constraint passed.

> We automatically changed the infrastructure using your approved execution policy.

> Production remained inside its SLO.

> Cloud invoices confirm the workload now costs £174,000/month after normalising for traffic.

> £64,300/month of savings has been verified.

> £3,700 of expected savings did not materialise and has not been claimed.

That is the intended experience.

---

# 6. PRIMARY DIFFERENTIATOR

Cloud providers already generate native optimisation recommendations.

AWS Compute Optimizer, Azure Advisor and Google Cloud Recommender all provide forms of rightsizing, idle-resource detection and commitment recommendations.

AWS also now provides Compute Optimizer Automation for automatically applying qualifying recommendations.

Therefore:

**“We automate cloud recommendations” is insufficient differentiation.**

This product MUST instead provide:

1. provider-neutral optimisation;
2. workload-level rather than resource-only reasoning;
3. application SLO awareness;
4. cross-resource dependency understanding;
5. negotiated-price awareness;
6. commitment-aware economics;
7. IaC-aware remediation;
8. production safety controls;
9. automated rollback;
10. verified realised savings;
11. multi-cloud portfolio optimisation.

---

# 7. ECONOMIC UNIT

The fundamental object being optimised is NOT:

**an EC2 instance.**

It is:

# A workload.

A workload may consist of:

- compute instances;
- Kubernetes pods;
- Kubernetes nodes;
- load balancers;
- databases;
- caches;
- block storage;
- object storage;
- NAT;
- serverless functions;
- queues;
- data transfer;
- reserved capacity;
- support infrastructure.

Optimising one resource without understanding the workload can damage the application.

---

# 8. CORE ENTITY HIERARCHY

Organisation

→ Business Unit

→ Product

→ Application

→ Environment

→ Workload

→ Service

→ Cloud Resource.

Example:

```text
Acme Ltd
└── Consumer Products
    └── Marketplace
        └── Checkout
            └── Production
                └── payment-api
                    ├── EKS Deployment
                    ├── EC2 worker nodes
                    ├── RDS PostgreSQL
                    ├── ElastiCache
                    ├── ALB
                    └── EBS
```

Optimisation policies may apply at any hierarchy level.

---

# 9. TARGET CUSTOMER

Initial target:

Companies spending:

**£5m–£500m+ annually on public cloud.**

Minimum practical customer:

Approximately:

**£1m annual cloud expenditure**

unless cloud complexity is unusually high.

Ideal environment:

- AWS;
- Azure;
- Google Cloud;
- Kubernetes;
- Terraform or equivalent;
- dozens to thousands of applications;
- significant commitment purchases;
- distributed engineering teams.

---

# 10. PRIMARY PERSONAS

## FINOPS

Needs:

- spend;
- allocation;
- forecasting;
- optimisation;
- commitments;
- verified savings.

## PLATFORM ENGINEERING

Needs:

- safe infrastructure changes;
- capacity;
- reliability;
- policy;
- IaC integration;
- automation.

## SRE

Needs:

- SLO protection;
- rollback;
- incident avoidance;
- change audit.

## FINANCE

Needs:

- actual invoice cost;
- budget;
- forecast;
- commitments;
- realised savings.

## CTO

Needs:

- technology efficiency;
- infrastructure risk;
- cloud strategy;
- provider exposure.

## APPLICATION OWNER

Needs:

- workload economics;
- recommendations;
- change impact;
- application-level approvals.

---

# 11. PRODUCT MODES

Every organisation, workload and optimisation class must have an explicit execution mode.

## OBSERVE

Read-only.

Collect and analyse.

No changes.

## RECOMMEND

Generate recommendations.

No execution.

## ASSISTED EXECUTION

Generate exact implementation.

Customer approves.

System executes.

## AUTOPILOT

System executes qualifying actions automatically inside policy.

## FROZEN

No automated change allowed.

Useful during:

- incidents;
- peak periods;
- releases;
- audits;
- major migrations.

---

# 12. AUTOPILOT IS NOT ONE SWITCH

Autonomy MUST be configurable independently by action type.

Example:

```text
idle-dev-shutdown:
    AUTOPILOT

kubernetes-rightsizing:
    AUTOPILOT

production-vm-rightsizing:
    APPROVAL_REQUIRED

production-database-resize:
    APPROVAL_REQUIRED

resource-deletion:
    DISABLED

commitment-purchase:
    FINANCE_APPROVAL_REQUIRED
```

Never implement one organisation-wide:

`autopilot = true`

that unlocks every action.

---

# 13. ACTION RISK CLASSES

Every action receives one immutable risk class.

## R0 — OBSERVATIONAL

No mutation.

Example:

cost allocation.

## R1 — LOW RISK REVERSIBLE

Examples:

- scheduled shutdown of approved non-production workloads;
- adjust selected autoscaling boundaries;
- change non-production replica count.

May be autonomous.

## R2 — GUARDED REVERSIBLE

Examples:

- stateless compute rightsizing;
- Kubernetes resource-request changes;
- storage performance changes.

Requires validation and rollback.

## R3 — DISRUPTIVE

Examples:

- production VM resize requiring restart;
- database instance class change;
- large-scale node replacement.

Requires explicit policy and maintenance safeguards.

## R4 — DESTRUCTIVE OR FINANCIALLY BINDING

Examples:

- delete persistent data;
- terminate unprotected production DB;
- irreversible storage transformation;
- purchase multi-year commitment.

Default:

**never autonomously execute.**

Explicit customer policy may permit certain financial commitments, but destructive data deletion remains separately protected.

---

# 14. THREE SOURCES OF TRUTH

The platform must understand three separate truths.

## FINANCIAL TRUTH

What the provider actually charged.

## OPERATIONAL TRUTH

What infrastructure actually did.

## CONFIGURATION TRUTH

What infrastructure is supposed to look like.

All three are required.

Example:

AWS says:

EC2 = m6i.4xlarge.

Terraform says:

m6i.4xlarge.

Optimiser recommends:

m6i.2xlarge.

If Autopilot directly modifies AWS without modifying Terraform:

next Terraform apply may restore m6i.4xlarge.

Therefore direct mutation is incorrect.

---

# 15. INFRASTRUCTURE-AS-CODE OWNERSHIP

Every manageable resource needs:

```text
configuration_authority
```

Possible values:

```text
TERRAFORM
CLOUDFORMATION
BICEP
ARM
PULUMI
KUBERNETES
HELM
ARGOCD
FLUX
CLOUD_API
MANUAL
UNKNOWN
```

When configuration authority is declarative:

**modify the declaration first.**

Do NOT silently mutate the cloud resource.

---

# 16. IAC EXECUTION STRATEGY

For declarative infrastructure:

Optimiser

→ generate patch

→ open pull request

→ customer's CI validates

→ policy approval

→ merge

→ existing deployment pipeline applies

→ Autopilot observes rollout

→ verify

→ close recommendation.

Optional enterprise configuration may allow Autopilot to merge pre-approved change classes automatically.

---

# 17. DIRECT EXECUTION STRATEGY

Direct cloud mutation is allowed when:

1. resource is not declaratively managed;

OR

2. field is intentionally runtime-managed;

OR

3. customer explicitly permits direct mutation.

Examples:

- Auto Scaling desired capacity;
- scheduled dev stop/start;
- runtime Kubernetes scaling;
- certain cloud autoscaling parameters.

---

# 18. CONFIGURATION DRIFT

If runtime state differs from configuration authority:

detect:

```text
configuration_drift = true
```

Before optimisation, classify:

- intentional runtime drift;
- unauthorised drift;
- pending deployment;
- unknown.

Do not optimise unknown drift automatically.

---

# 19. CANONICAL FINANCIAL STANDARD

Use:

# FOCUS 1.4

as the internal vendor-neutral billing baseline.

FOCUS 1.4 is the latest published specification as of this specification, ratified June 4, 2026. It explicitly expands invoice reconciliation, commitment structures and commitment eligibility.

Provider-specific fields must still be preserved.

---

# 20. BILLING STORAGE MODEL

Keep:

## RAW PROVIDER DATA

Immutable.

## CANONICAL FOCUS DATA

Normalised.

## INTERNAL ALLOCATION DATA

Business ownership.

## OPTIMISATION ECONOMICS

Predicted alternative costs.

Never overwrite raw billing.

---

# 21. COST DEFINITIONS

Expose separately:

```text
ListCost
ContractedCost
BilledCost
EffectiveCost
AmortizedCost
MarginalCost
ForecastCost
AvoidableCost
VerifiedSavings
```

Do not collapse them into one ambiguous:

`cost`.

---

# 22. EFFECTIVE COST

Effective cost represents the organisation's economic cost after applicable:

- negotiated prices;
- credits;
- commitments;
- reserved capacity;
- discounts;
- amortisation.

Optimisation should generally operate on:

# Effective marginal cost.

Not public list price.

---

# 23. WHY EFFECTIVE MARGINAL COST MATTERS

Example:

AWS on-demand:

£10.

Alternative architecture:

£7.

But customer already purchased commitment covering the £10 resource.

Unused commitment after migration would cost:

£6.

True result:

Old economic position:

£10.

New provider/resource:

£7 + £6 stranded commitment.

= £13.

The apparently cheaper move increases cost.

The optimiser must reject it.

---

# 24. REQUIRED CLOUD PROVIDERS — GA

GA MUST support:

- AWS;
- Microsoft Azure;
- Google Cloud.

Kubernetes must be supported across all three.

---

# 25. AWS BILLING INTEGRATION

Primary financial source:

AWS Data Exports / CUR 2.0.

AWS currently recommends CUR 2.0 as the detailed cost-and-usage export format.

Collect:

- linked account;
- billing account;
- service;
- SKU;
- operation;
- usage type;
- resource ID;
- region;
- availability zone;
- tags;
- list cost;
- effective cost;
- credits;
- discounts;
- RI coverage;
- Savings Plan coverage;
- amortisation;
- commitment fees.

---

# 26. AWS INVENTORY

GA inventory support:

- EC2;
- Auto Scaling Groups;
- EBS;
- RDS;
- Aurora;
- ECS;
- Fargate;
- EKS;
- Lambda;
- S3;
- ElastiCache;
- DynamoDB;
- NAT Gateway;
- Elastic IP;
- load balancers;
- snapshots;
- Savings Plans;
- Reserved Instances.

Later:

- OpenSearch;
- Redshift;
- SageMaker;
- Neptune;
- DocumentDB;
- MemoryDB;
- WorkSpaces.

---

# 27. AWS NATIVE RECOMMENDATION INGESTION

Ingest Compute Optimizer as one evidence source.

It must NOT be treated as unquestionable truth.

Compute Optimizer currently supports recommendations across resources including EC2, Auto Scaling Groups, EBS, ECS, RDS and several other resource categories, and also exposes projected utilisation/performance risk for supported recommendation types.

Store:

```text
provider_recommendation
our_recommendation
difference
reason_for_difference
```

---

# 28. AZURE BILLING INTEGRATION

Use:

Azure Cost Management Exports.

Support:

- actual cost;
- amortised cost;
- price sheets;
- reservations;
- reservation transactions;
- reservation recommendations;
- FOCUS-formatted cost data where available.

Azure Cost Management currently supports recurring exports and FOCUS-format cost and usage exports.

---

# 29. AZURE INVENTORY

GA:

- Virtual Machines;
- VM Scale Sets;
- Managed Disks;
- Azure SQL;
- PostgreSQL;
- MySQL;
- AKS;
- App Service;
- Functions;
- Storage;
- Redis;
- Load Balancer;
- Application Gateway;
- Public IP;
- NAT;
- reservations;
- savings plans.

---

# 30. AZURE ADVISOR

Import Advisor recommendations.

Azure Advisor currently includes rightsizing/shutdown and other cost recommendations, but Microsoft explicitly notes that some VM rightsizing savings estimates use retail rates and can fail to account for existing reservations/savings plans.

Therefore our optimiser MUST recalculate economics against:

**the customer's actual effective position.**

---

# 31. GOOGLE CLOUD BILLING

Use:

- detailed Cloud Billing BigQuery export;
- pricing export;
- CUD metadata;
- FOCUS export where available.

Google currently exposes detailed usage billing exports, pricing data and commitment metadata through its billing export ecosystem.

---

# 32. GOOGLE CLOUD INVENTORY

GA:

- Compute Engine;
- Managed Instance Groups;
- Persistent Disk / Hyperdisk;
- GKE;
- Cloud SQL;
- Memorystore;
- Cloud Run;
- Cloud Functions;
- Cloud Storage;
- load balancing;
- static IP;
- networking;
- commitments/CUDs.

---

# 33. GOOGLE RECOMMENDER

Import:

- idle VM;
- rightsizing;
- idle disk;
- idle IP;
- commitment recommendations;
- relevant Active Assist recommendations.

Google currently generates idle-VM recommendations from historical CPU/network utilisation and machine-type rightsizing recommendations from recent monitoring data.

Again:

provider recommendation = evidence.

Not automatic truth.

---

# 34. CLOUD CREDENTIAL MODEL

Each cloud integration must support:

## READ ROLE

Inventory.

Billing.

Metrics.

Recommendations.

Tags.

## EXECUTION ROLE

Mutations.

Execution credential is optional.

Read role MUST be sufficient for Observe/Recommend modes.

Never require mutation privileges for onboarding.

---

# 35. EXECUTION CREDENTIAL SEPARATION

Execution credentials:

- stored separately;
- separately encrypted;
- separately audited;
- individually disable-able;
- privilege-scoped by action type.

Compromise of the analytical service should not automatically grant unlimited infrastructure mutation.

---

# 36. CUSTOMER-HOSTED EXECUTOR

Enterprise option:

run execution agent inside customer's cloud/VPC.

Control plane sends:

signed action request.

Agent verifies:

- signature;
- tenant;
- action;
- policy version;
- expiry;
- resource target.

Agent performs API call locally.

Benefits:

- credentials remain customer-side;
- private endpoints accessible;
- network isolation;
- improved enterprise trust.

This should become the preferred execution architecture for highly regulated customers.

---

# 37. RESOURCE GRAPH

All discovered resources must enter a resource graph.

Resource schema:

```text
resource_id
tenant_id

provider
provider_account
subscription_or_project
region
zone

resource_type
provider_resource_type
provider_resource_id

name

parent_resource_id
workload_id
application_id
environment

owner
team
cost_center

tags
labels

criticality

configuration_authority
iac_repository
iac_file
iac_address

state

created_at
last_seen_at

deletion_protection
backup_state

commitment_coverage

hourly_effective_cost
monthly_effective_cost
```

---

# 38. DEPENDENCY GRAPH

Graph edges include:

```text
RUNS_ON
ATTACHED_TO
ROUTES_TO
DEPENDS_ON
BACKED_BY
MEMBER_OF
MANAGED_BY
SCALES_WITH
PROTECTED_BY
CONFIGURED_BY
PAID_BY_COMMITMENT
```

Example:

```text
API Deployment
RUNS_ON
EKS Node

EKS Node
MEMBER_OF
Node Group

Node Group
PAID_BY_COMMITMENT
Savings Plan
```

---

# 39. OWNERSHIP RESOLUTION

Resolve workload ownership from:

1. explicit Cloud Autopilot metadata;
2. cloud tags;
3. Kubernetes labels;
4. IaC metadata;
5. CMDB;
6. service catalogue;
7. configured rule;
8. manual mapping.

Unowned resources must be visible.

---

# 40. REQUIRED OWNERSHIP FIELDS

Recommended enterprise policy requires:

```text
application
environment
owner
cost_center
criticality
```

Missing metadata may trigger governance recommendations.

Do NOT block infrastructure operation by default because a tag is missing.

---

# 41. METRIC INGESTION

AWS:

CloudWatch.

Azure:

Azure Monitor.

GCP:

Cloud Monitoring.

Kubernetes:

Prometheus/OpenTelemetry/metrics API.

Customer-provided:

Datadog, New Relic or equivalent connectors in later releases.

---

# 42. CORE COMPUTE METRICS

At minimum:

```text
cpu_utilization
memory_utilization
network_in
network_out
disk_iops
disk_throughput
disk_queue
gpu_utilization where applicable

request_rate
latency
error_rate

instance_health
```

Where memory is not available from cloud-native telemetry:

mark:

```text
memory_data_missing = true
```

Do not infer false precision.

---

# 43. APPLICATION METRICS

Cloud infrastructure metrics alone are not enough.

Support:

- OpenTelemetry;
- Prometheus;
- customer SLO source;
- custom metrics.

Examples:

```text
http_rps
queue_depth
p95_latency
p99_latency
error_rate
active_sessions
orders_per_minute
jobs_pending
```

These metrics can become optimisation constraints.

---

# 44. CRITICALITY

Each workload:

```text
TIER_0
TIER_1
TIER_2
TIER_3
NON_PRODUCTION
```

Example default:

TIER_0:

financial/critical infrastructure.

TIER_1:

customer production.

TIER_2:

internal production.

TIER_3:

low-criticality.

NON_PRODUCTION:

development/test.

Risk policy becomes stricter as criticality increases.

---

# 45. SERVICE OBJECTIVE

Each workload can define:

```text
min_availability

max_p95_latency
max_p99_latency

max_error_rate

min_replicas

min_zones

cpu_headroom

memory_headroom

capacity_headroom

rto
rpo

maintenance_window

blackout_windows
```

Autopilot cannot violate hard constraints.

---

# 46. DEFAULT HEADROOM

If customer has no explicit policy:

Production compute default:

```text
CPU p95 target <= 70%
Memory p95 target <= 75%
```

But these values are starting guardrails.

The system must learn workload burst behaviour.

Do NOT reduce capacity simply because average utilisation is low.

---

# 47. BURST ANALYSIS

Analyse:

- p50;
- p90;
- p95;
- p99;
- p99.9 where data volume permits;
- daily peaks;
- weekly peaks;
- seasonal peaks;
- scheduled business events.

Rightsizing must not rely on average CPU.

---

# 48. OBSERVATION WINDOW

Default:

Production:

**30 days**

High-seasonality:

**90 days**

Non-production:

**14 days**

Minimum production eligibility:

**7 complete days**

except obvious idle/orphan cases.

If insufficient history:

recommendation status:

```text
INSUFFICIENT_OBSERVATION
```

---

# 49. FORECASTING

Use historical data plus optional known events.

Forecast:

- demand;
- resource consumption;
- spend;
- commitment utilisation.

Support:

```text
7_day
30_day
90_day
annual
```

Output:

point estimate plus prediction interval.

---

# 50. KNOWN DEMAND EVENTS

Customer may declare:

```text
Black Friday
product launch
marketing campaign
month end
quarter end
payroll
tax filing deadline
```

During declared event window:

normal rightsizing can be suspended automatically.

---

# 51. FREEZE WINDOWS

Customer can define:

```text
no_automated_changes
```

between times.

Example:

December 15–January 3.

Autopilot can still detect/recommend.

It cannot execute.

---

# 52. OPTIMISATION CLASSES

GA engine must support:

1. idle resources;
2. orphan resources;
3. non-production scheduling;
4. VM rightsizing;
5. autoscaling group optimisation;
6. Kubernetes rightsizing;
7. Kubernetes node optimisation;
8. database rightsizing;
9. storage optimisation;
10. serverless optimisation;
11. commitment optimisation;
12. unused IP/network resources;
13. NAT/data-transfer inefficiency;
14. commitment waste;
15. resource-generation migration.

---

# 53. IDLE RESOURCE ENGINE

Detect resources with no meaningful work.

Examples:

- idle VMs;
- unattached disks;
- unused IPs;
- abandoned snapshots;
- idle load balancers;
- idle databases;
- idle Kubernetes clusters;
- unused NAT gateways.

Classification:

```text
IDLE
UNATTACHED
UNUSED
LOW_UTILIZATION
UNKNOWN
```

---

# 54. IDLE DOES NOT MEAN DELETE

Default progression:

```text
detected
→ owner notified
→ quarantine candidate
→ stop/deactivate where reversible
→ observation
→ deletion candidate
→ explicit deletion
```

For persistent resources:

deletion remains approval-controlled.

---

# 55. QUARANTINE

For eligible resources:

quarantine period default:

**14 days**

Process:

1. snapshot/backup if applicable;
2. stop/deactivate;
3. monitor dependency failures;
4. allow one-click restoration;
5. only later propose deletion.

Never immediately delete an unknown disk because it appears unattached.

---

# 56. NON-PRODUCTION SCHEDULING

Detect recurring idle windows.

Example:

Dev workload unused:

19:00–07:00 weekdays.

System can recommend:

automatic stop at 20:00.

automatic start at 06:30.

Calculate savings.

---

# 57. SCHEDULING AUTOPILOT

Eligible:

- explicitly non-production;
- owner configured;
- no active job;
- no current deployment;
- no override.

Provide:

```text
skip_next_stop
start_now
pause_schedule
```

to application owners.

---

# 58. VM RIGHTSIZING

For each VM:

evaluate compatible alternatives.

Constraints:

- architecture;
- operating system;
- disk;
- network;
- accelerator;
- local storage;
- licensing;
- region;
- zone;
- reservation compatibility;
- CPU;
- memory;
- IOPS;
- throughput.

Generate multiple candidates.

---

# 59. VM CANDIDATE SCORE

For candidate `c`:

```text
eligible(c) =
    capacity_ok
    AND architecture_ok
    AND storage_ok
    AND network_ok
    AND licensing_ok
    AND region_ok
    AND commitment_ok
    AND slo_ok
```

Then minimise:

```text
risk_adjusted_effective_cost(c)
```

---

# 60. VM PERFORMANCE RISK

Calculate:

```text
P(cpu_required > candidate_capacity)

P(memory_required > candidate_capacity)

P(network_required > candidate_capacity)

P(storage_required > candidate_capacity)
```

Default production candidate must have:

```text
estimated capacity-breach probability < 1%
```

for measured dimensions.

Customer can tighten.

---

# 61. SINGLETON VM SAFETY

A single-instance production workload is NOT automatically rightsized by default.

Reason:

rightsizing may require downtime.

AWS requires stopping an EBS-backed EC2 instance to change its instance type; GCP similarly requires stopped state for standard standalone VM machine-type changes; Azure VM resizing is disruptive and can require deallocation.

Therefore singleton production compute defaults:

**APPROVAL_REQUIRED.**

---

# 62. REDUNDANT COMPUTE CANARY

For replicated workloads:

Replace one replica first.

Example:

10-instance group.

Process:

```text
1 new-sized replica
→ validate
→ 20%
→ validate
→ 50%
→ validate
→ 100%
```

Old capacity should remain recoverable during rollout where practical.

---

# 63. AUTO SCALING GROUP OPTIMISATION

Optimise:

- instance type;
- instance mix;
- minimum size;
- desired size;
- maximum size;
- target utilisation;
- warm pool;
- spot/on-demand mix where permitted.

Do NOT merely shrink desired capacity if autoscaling will immediately restore it.

Optimise the governing configuration.

---

# 64. SPOT / PREEMPTIBLE POLICY

Spot/preemptible capacity requires workload explicit eligibility.

Customer sets:

```text
spot_allowed
max_spot_percentage
fallback_on_demand
interruption_tolerance
```

Default production:

`spot_allowed = false`

unless workload declares tolerance.

---

# 65. KUBERNETES SUPPORT

GA:

- EKS;
- AKS;
- GKE;
- generic Kubernetes with supported metrics.

Discover:

- cluster;
- node;
- node pool;
- namespace;
- workload;
- Deployment;
- StatefulSet;
- DaemonSet;
- pod;
- container;
- HPA;
- VPA;
- PDB;
- requests;
- limits.

---

# 66. KUBERNETES COST ATTRIBUTION

Allocate node cost to workloads using:

CPU request

memory request

accelerator request

plus:

shared/idle allocation.

Allow alternative views:

```text
requested_cost
used_cost
allocated_cost
```

---

# 67. KUBERNETES RIGHTSIZING

Optimise:

```text
cpu.requests
memory.requests
cpu.limits
memory.limits
```

based on:

- usage distribution;
- throttling;
- OOM;
- restart history;
- HPA behaviour;
- deployment pattern;
- workload criticality.

---

# 68. KUBERNETES VPA

The platform should integrate with, rather than blindly fight, Kubernetes vertical autoscaling.

Kubernetes VPA can automatically adjust workload resource requests based on historical utilisation and real-time events, while HPA adjusts replica count based on observed metrics.

Detect existing VPA.

If present:

optimise VPA policy rather than independently overriding it.

---

# 69. HPA INTERACTION

Critical rule:

Changing CPU requests changes CPU-utilisation percentages used by HPA when HPA targets utilisation.

Therefore before lowering CPU request:

simulate impact on HPA.

Otherwise:

lower request → utilisation percentage rises → HPA adds replicas → costs may increase.

---

# 70. KUBERNETES NODE ECONOMICS

Optimise:

- node types;
- node pool count;
- node pool boundaries;
- bin packing;
- architecture;
- spot/on-demand;
- idle nodes;
- fragmentation.

Do not duplicate a competent node autoscaler.

Understand and optimise its constraints.

---

# 71. KUBERNETES AUTOSCALERS

Kubernetes node autoscaling already provisions and consolidates capacity based on workload scheduling requirements, while HPA and VPA handle workload scaling.

If customer uses:

Cluster Autoscaler

or

Karpenter,

Autopilot should configure/optimise their policy rather than independently terminate nodes behind them.

---

# 72. POD DISRUPTION

All Kubernetes disruptive action MUST honour:

- PodDisruptionBudget;
- workload readiness;
- maintenance policy;
- minimum replicas.

PDBs are specifically designed to constrain voluntary disruption.

Never override a blocking PDB automatically.

---

# 73. KUBERNETES DEFAULT ROLLOUT

For resource-request changes:

1. patch IaC/Helm manifest;
2. deploy one rollout;
3. monitor readiness;
4. monitor latency;
5. monitor errors;
6. monitor OOM;
7. monitor CPU throttling;
8. continue or rollback.

---

# 74. DATABASE OPTIMISATION

Support initially:

AWS RDS/Aurora.

Azure managed SQL/PostgreSQL/MySQL.

GCP Cloud SQL.

Optimise:

- instance class;
- replicas;
- provisioned storage;
- IOPS;
- throughput;
- serverless capacity where applicable.

---

# 75. DATABASE SAFETY

Database recommendations require:

- CPU;
- memory;
- connections;
- IOPS;
- storage;
- replication lag;
- query latency;
- cache hit rate where available;
- failover architecture.

Never rightsize database based on CPU alone.

---

# 76. DATABASE CHANGE CLASS

Production DB compute resize default:

**R3 DISRUPTIVE**

and approval required.

Autopilot only allowed when:

- customer explicitly enables;
- HA/failover topology qualifies;
- tested execution method exists;
- rollback plan exists;
- maintenance policy permits.

---

# 77. RDS EXECUTION

Before RDS modification:

call valid-modification capability.

AWS exposes `DescribeValidDBInstanceModifications` specifically for determining permitted changes before `ModifyDBInstance`. Some RDS changes can be immediate, while others require maintenance windows or reboot.

Executor MUST inspect actual provider semantics before submission.

---

# 78. STORAGE OPTIMISATION

Optimise:

- volume type;
- provisioned IOPS;
- provisioned throughput;
- unused volumes;
- snapshot retention;
- object storage tier;
- lifecycle;
- replication where policy allows.

---

# 79. STORAGE SHRINKING

Never automatically reduce persistent volume capacity.

Many provider storage services allow increases but not direct shrinking.

AWS EBS, for example, supports changing volume type/performance and increasing size, but not decreasing volume size directly.

Storage downsizing therefore becomes a migration workflow, not a simple resize.

---

# 80. EBS OPTIMISATION

Potential safe optimisation:

io1/io2 → gp3

when:

- performance envelope satisfied;
- workload compatible;
- effective cost lower.

Before mutation:

snapshot recommended where risk policy demands.

Elastic Volumes may allow performance/type modifications without instance restart on eligible configurations.

---

# 81. OBJECT STORAGE

Analyse:

- object age;
- access frequency;
- retrieval frequency;
- storage tier;
- minimum-duration charges;
- retrieval charges.

Do not move object simply because it is old.

Calculate:

```text
storage_saving
-
expected_retrieval_cost
-
transition_cost
-
minimum_duration_penalty
```

---

# 82. SERVERLESS

AWS Lambda / Azure Functions / Cloud Functions / Cloud Run where applicable.

Optimisation areas:

- memory;
- provisioned concurrency;
- concurrency;
- idle provisioned capacity;
- architecture;
- execution duration;
- scaling bounds.

Evaluate cost-performance curve.

---

# 83. NETWORK COST

Analyse:

- cross-zone traffic;
- cross-region traffic;
- internet egress;
- NAT gateway cost;
- public/private path;
- unused IP;
- duplicate gateways.

Network optimisation may imply architecture changes.

Therefore most network topology changes begin as:

**Recommend.**

---

# 84. NAT DETECTION

Detect cases where major NAT expenditure is caused by traffic that could safely use:

- private endpoint;
- provider service endpoint;
- in-region path.

Recommendation must include:

current flow

target flow

security impact

estimated volume

cost difference.

---

# 85. COMMITMENT ENGINE

Supports:

AWS:

- Savings Plans;
- Reserved Instances.

Azure:

- Reservations;
- Savings Plan.

GCP:

- committed use discounts.

---

# 86. COMMITMENT ORDER OF OPERATIONS

Mandatory:

# 1. Remove idle resources.

# 2. Apply scheduling.

# 3. Rightsize workloads.

# 4. Optimise autoscaling.

# 5. Recalculate stable demand.

# 6. Only then recommend new commitments.

Azure explicitly recommends sequencing rightsizing/shutdown before reservation and savings-plan purchases because infrastructure optimisation changes the usage baseline on which commitment recommendations depend.

This is a product-wide rule.

---

# 87. COMMITMENT MODEL

For each commitment:

```text
provider
commitment_type

scope

start
end

term

upfront_amount
recurring_amount

eligible_usage
covered_usage

utilization
coverage

effective_discount

remaining_value
```

---

# 88. COMMITMENT FORECAST

Do NOT buy commitment based on average historical demand.

Model stable floor.

For each eligible commitment scope:

calculate demand distribution.

Default conservative commitment quantity target:

approximately:

```text
P90 confidence that committed capacity will be consumed
```

over forecast horizon.

Customer risk preference can configure:

```text
CONSERVATIVE
BALANCED
AGGRESSIVE
```

---

# 89. COMMITMENT RISK

Recommendation must show:

```text
expected_savings
downside_if_demand_drops
break_even_utilization
expected_utilization
confidence_interval
term
cash_requirement
```

---

# 90. COMMITMENT PURCHASE

Default:

**FINANCE APPROVAL REQUIRED.**

Do not autonomously sign a three-year financial obligation because a machine-learning model predicts usage.

Later customers may explicitly grant:

```text
max_commitment_purchase
approved_term
approved_provider
min_expected_utilization
```

for limited automated purchasing.

---

# 91. AWS SAVINGS PLANS

The engine must distinguish plan classes and coverage mechanics.

AWS currently offers multiple Savings Plan classes including Compute, EC2 Instance, Database and SageMaker AI plans, with varying scope/flexibility.

Never treat all commitments as fungible.

---

# 92. GOOGLE CUDS

Import and independently analyse provider recommendations.

Google currently models commitment recommendations using recent usage and provides both stable-usage and maximum-savings style recommendations for supported commitments.

Our product must apply:

customer-specific forecasts,

rightsizing plans,

multi-cloud migration plans,

and risk policy

before accepting a provider commitment recommendation.

---

# 93. OPTIMISATION RECOMMENDATION

Canonical schema:

```text
recommendation_id

tenant_id
workload_id

category
action_type
risk_class

resource_ids

current_state
proposed_state

current_effective_cost
predicted_effective_cost

monthly_saving
annual_saving
saving_percentage

performance_baseline
predicted_performance

constraints_checked

commitment_impact

implementation_method

configuration_authority

required_downtime

maintenance_window

rollback_supported
rollback_plan

confidence

evidence_window

status

created_at
expires_at
```

---

# 94. RECOMMENDATION STATUS

```text
DETECTED

ANALYSING

VALIDATED

BLOCKED

AWAITING_APPROVAL

APPROVED

EXECUTING

VERIFYING

VERIFIED

ROLLED_BACK

REJECTED

EXPIRED

SUPERSEDED
```

---

# 95. RECOMMENDATION EXPLANATION

Bad:

> Resize this instance and save £340.

Correct:

> `checkout-api` runs 12 `m6i.4xlarge` instances. Across the previous 30 days, per-instance CPU p99 was 46%, memory p99 52%, network p99 31% of available capacity, and no sustained throttling occurred. At current workload growth and a 30% safety reserve, `m6i.2xlarge` provides sufficient forecast capacity. Because this fleet is covered by a Compute Savings Plan, the recommendation accounts for commitment reallocation. Expected effective saving is £18,420/month. One replica will be replaced first. Rollback restores the existing launch-template version.

That is the required explanation quality.

---

# 96. RECOMMENDATION CONFIDENCE

Calculate confidence from:

- telemetry completeness;
- observation length;
- workload stability;
- seasonality;
- dependency confidence;
- pricing confidence;
- forecast uncertainty;
- configuration authority certainty.

Expose:

```text
VERY_LOW
LOW
MEDIUM
HIGH
VERY_HIGH
```

Only HIGH/VERY_HIGH may be default-autopilot candidates.

---

# 97. CHANGE PLAN

Every executable recommendation creates immutable:

```text
ChangePlan
```

Containing:

```text
change_plan_id

recommendation_id

preconditions

steps

health_checks

stop_conditions

rollback_steps

timeout

maintenance_window

approval_requirement

policy_version

created_at
```

Executor executes ChangePlan.

Not recommendation prose.

---

# 98. PRECONDITION CHECK

Immediately before execution, re-fetch:

- resource state;
- current configuration;
- latest metrics;
- active incident state;
- maintenance window;
- provider health;
- IaC state;
- commitment state;
- current deployment.

If conditions changed:

abort.

Mark:

```text
STALE_RECOMMENDATION
```

---

# 99. OPTIMISTIC CONCURRENCY

Mutation must include current-state identity/version where provider supports it.

Prevent:

recommendation built for version A

from applying blindly to version C.

---

# 100. EXECUTION LOCK

Acquire per-resource distributed lock.

Example:

```text
lock:
provider/resource-id
```

Only one Autopilot mutation can affect a resource at once.

Dependent-resource actions use ordered workflow locks.

---

# 101. EXECUTION WORKFLOW

Required lifecycle:

```text
PRECHECK

BACKUP_IF_REQUIRED

CANARY

HEALTH_CHECK

EXPAND

HEALTH_CHECK

COMMIT

VERIFY_ECONOMICS
```

If any mandatory step fails:

```text
ROLLBACK
```

---

# 102. CANARY

Where resources are replicated:

Autopilot must prefer subset rollout.

Default:

```text
10%
→ 25%
→ 50%
→ 100%
```

Customer configurable.

For tiny fleets:

one unit first.

---

# 103. CANARY HEALTH

Compare:

candidate cohort

versus

control cohort.

Evaluate:

- error rate;
- latency;
- CPU;
- memory;
- saturation;
- queue;
- availability;
- application SLO.

---

# 104. ROLLBACK CONDITIONS

Immediate rollback on:

- SLO violation;
- error spike;
- latency violation;
- failed health check;
- capacity saturation;
- failed deployment;
- dependency failure;
- customer emergency stop.

---

# 105. DEFAULT ERROR GUARD

Unless workload overrides:

rollback if:

```text
candidate_error_rate
>
max(
    baseline_error_rate + 0.5 percentage points,
    baseline_error_rate * 1.5
)
```

and statistically/operationally meaningful sample exists.

Critical workloads should define stricter thresholds.

---

# 106. DEFAULT LATENCY GUARD

Rollback if:

```text
candidate_p95
>
max(
    configured_SLO,
    baseline_p95 * 1.15
)
```

where relevant.

Explicit application SLO overrides generic threshold.

---

# 107. CAPACITY GUARD

Rollback/stop expansion if:

```text
cpu p99 > 85%
```

OR

```text
memory p99 > 90%
```

OR

configured resource saturation threshold is crossed.

These are defaults, not universal truths.

---

# 108. AUTOMATION COOLDOWN

After a successful change:

do not immediately optimise same dimension again.

Default:

VM rightsizing:

**7 days.**

Kubernetes requests:

**3 days.**

Autoscaling boundaries:

**3 days.**

Commitment purchase:

recompute after material topology changes.

Avoid oscillation.

---

# 109. FLAPPING PREVENTION

Maintain hysteresis.

Do not alternate:

large → small → large → small.

Candidate must deliver material benefit.

Default minimum change:

**10% cost reduction**

unless customer changes threshold.

---

# 110. MINIMUM SAVINGS

Default recommendation threshold:

```text
annual_saving >= £1,000
```

OR

```text
saving_percentage >= 15%
```

Individual low-value recommendations may be grouped.

Avoid overwhelming engineers with £8 optimisations.

---

# 111. BULK OPPORTUNITY

Group homogeneous resources.

Example:

481 dev VMs with identical schedule opportunity.

Present:

one recommendation.

Potential saving:

£412k/year.

Execution can still occur in controlled batches.

---

# 112. BLAST RADIUS

Every ChangePlan calculates:

```text
affected_resources

affected_workloads

affected_customers if known

maximum_simultaneous_instances

regional_scope

estimated_traffic_percentage
```

Policy can restrict:

```text
max_blast_radius
```

---

# 113. MAINTENANCE WINDOWS

Change class R3:

must execute only within approved window unless emergency override.

Customer timezone must be explicit.

Store timestamps UTC internally.

Display in customer locale.

---

# 114. EMERGENCY STOP

Organisation-wide:

# PAUSE AUTOPILOT

must immediately:

- block new mutations;
- allow safe in-progress rollback;
- preserve monitoring;
- preserve recommendations.

Also allow:

- cloud-specific pause;
- application-specific pause;
- action-class pause.

---

# 115. INCIDENT INTEGRATION

When application has active Sev-1/Sev-2 incident:

automated economic changes are suspended by default.

Integrate with:

- PagerDuty;
- Opsgenie equivalent;
- ServiceNow later;
- generic incident webhook.

---

# 116. DEPLOYMENT AWARENESS

When workload is actively deploying:

do not make unrelated infrastructure optimisation simultaneously unless explicitly allowed.

This preserves root-cause attribution.

---

# 117. CHANGE COLLISION

If application deployment occurs within Autopilot verification window:

mark savings/performance verification:

```text
CONFOUNDED
```

Extend or restart verification.

Do not claim causal savings when simultaneous changes prevent attribution.

---

# 118. SAVINGS TYPES

Distinguish:

```text
THEORETICAL

IDENTIFIED

VALIDATED

APPROVED

IMPLEMENTED

OBSERVED

VERIFIED
```

Only VERIFIED savings count in customer value reporting.

---

# 119. VERIFIED SAVINGS FORMULA

Naïve:

```text
before_spend - after_spend
```

is unacceptable.

Traffic may have changed.

Use normalised baseline.

For workload unit `u`:

```text
expected_baseline_cost_t
=
baseline_cost_per_unit
×
actual_units_t
```

Then:

```text
verified_savings_t
=
expected_baseline_cost_t
-
actual_effective_cost_t
```

after adjusting for known unrelated changes.

---

# 120. EXAMPLE SAVINGS

Before:

10m requests.

£100k.

Cost/request:

£0.010.

After:

15m requests.

£105k.

Spend rose £5k.

But expected baseline at old efficiency:

```text
15m × £0.010
=
£150k
```

Verified saving:

```text
£150k - £105k
=
£45k
```

The platform must correctly report:

**£45k efficiency saving.**

---

# 121. CONTROL GROUP

Where appropriate use unchanged comparable resources as control.

This improves causal inference.

Example:

20-service fleet.

10 optimised.

10 unchanged.

Compare performance/cost evolution.

---

# 122. SAVINGS LEDGER

Immutable record:

```text
savings_id

recommendation_id
change_plan_id

baseline_period
verification_period

baseline_model
normalization_unit

expected_baseline_cost
actual_cost

verified_saving

confidence

confounding_factors

status
```

---

# 123. NEGATIVE SAVINGS

If a change increases cost:

record negative savings.

Do not hide it.

Example:

```text
verified_saving = -£4,281
```

This is necessary for customer trust and optimiser learning.

---

# 124. OPTIMISER LEARNING

Successful/failed actions feed future decisions.

Store:

```text
workload_features
action
predicted_saving
actual_saving

predicted_performance
actual_performance

rollback
incident
```

Long-term moat:

knowing which optimisation is actually safe for which workload shape.

---

# 125. DO NOT TRAIN ON CUSTOMER SECRETS

Cross-customer learning:

must use privacy-preserving aggregate features.

Do not expose:

- resource names;
- account IDs;
- customer identities;
- application names;
- configurations revealing proprietary architecture.

---

# 126. BUDGET ENGINE

Budgets by:

- organisation;
- provider;
- account;
- business unit;
- application;
- team;
- environment.

Support:

monthly

quarterly

annual.

---

# 127. BUDGET ACTION

Budget breach should NOT automatically shut production infrastructure down.

Potential policy:

Non-production budget exceeded:

restrict new optional capacity or alert.

Production budget exceeded:

alert + optimisation escalation.

Budget is not equivalent to infrastructure safety policy.

---

# 128. FORECASTING

Dashboard:

```text
current_month_spend
forecast_month_end
budget
variance
confidence_interval
```

Forecast must account for:

- seasonality;
- planned optimisation;
- known commitment expiry;
- known growth event.

---

# 129. COST ANOMALY ENGINE

Detect unexpected change in:

- total cost;
- resource cost;
- application cost;
- unit cost;
- data transfer;
- resource count;
- commitment utilisation.

---

# 130. ROOT-CAUSE ANOMALY

Bad:

> AWS spend increased 37%.

Good:

> AWS spend increased £41,800 yesterday. £31,400 came from `analytics-prod`. Its EMR fleet increased from 18 to 53 nodes at 02:12 UTC following configuration change `git:98ac3c`. Workload throughput increased only 4%.

---

# 131. POLICY ENGINE

Policies are versioned declarative objects.

Example:

```yaml
application: checkout
environment: production

autopilot:
  vm_rightsize: true
  kubernetes_rightsize: true
  database_rightsize: false
  delete_resources: false

constraints:
  min_availability: 99.99
  min_replicas: 6
  min_zones: 3

  max_p95_latency_ms: 180

  cpu_headroom: 0.30
  memory_headroom: 0.25

change:
  max_fleet_percentage: 0.10
  maintenance_window: "Sun 01:00-04:00 Europe/London"

economics:
  min_annual_saving_gbp: 5000
```

---

# 132. POLICY PRECEDENCE

Precedence:

```text
resource
>
workload
>
application
>
business unit
>
organisation
>
system default
```

Most specific policy wins.

Hard organisation prohibition cannot be overridden lower unless explicitly marked override-able.

---

# 133. POLICY SIMULATION

Before activating a new policy:

show:

> Had this policy been active for the previous 30 days, 84 recommendations would have been auto-approved, affecting 312 resources and approximately £480k/year in projected savings.

Customer can inspect examples.

---

# 134. POLICY VERSIONING

Store:

```text
policy_id
version
author
created_at
approved_by
effective_from
supersedes
```

Every ChangePlan references exact policy version.

---

# 135. APPROVAL ENGINE

Support:

- one approver;
- two-person approval;
- application owner;
- FinOps;
- infrastructure;
- finance.

Example:

R3 change:

application owner + platform engineering.

Commitment:

FinOps + finance.

---

# 136. TEMPORARY APPROVAL

Customer may approve:

> Automatically perform production EC2 rightsizing below £20k annual affected spend for next 30 days.

Store expiration.

Do not silently leave temporary privileges permanent.

---

# 137. EXECUTIVE DASHBOARD

Above fold:

**Current cloud run-rate**

**Forecast month-end**

**Verified savings this month**

**Verified annualised savings**

**Validated savings available**

**Autopilot actions this month**

**Rollback count**

**Budget variance**

**Commitment utilisation**

**Major risks**

---

# 138. AUTOPILOT DASHBOARD

Show:

```text
Actions running now

Actions completed

Actions rolled back

Actions awaiting approval

Resources protected

Verified savings

Incidents caused
```

---

# 139. SAVINGS PAGE

Buckets:

```text
Verified
Measuring
Implemented
Approved
Validated
Identified
Blocked
Rejected
```

Never combine verified and theoretical numbers.

---

# 140. RESOURCE ECONOMICS PAGE

Every resource:

- cost;
- effective cost;
- commitment coverage;
- metrics;
- workload;
- owner;
- IaC source;
- recommendation;
- action history.

---

# 141. WORKLOAD PAGE

Central user object.

Display:

- total cost;
- cost trend;
- unit cost;
- architecture graph;
- resources;
- SLO;
- headroom;
- commitment position;
- optimisation opportunities;
- recent changes;
- verified savings.

---

# 142. COMMITMENT PAGE

Show:

- portfolio;
- utilisation;
- coverage;
- expiration;
- remaining value;
- stranded risk;
- recommended purchase;
- recommended non-purchase.

Important:

sometimes the best recommendation is:

# Do not buy more commitment.

---

# 143. CHANGE PAGE

Every execution shows:

```text
why

before

after

predicted_saving

affected_resources

risk

prechecks

execution_steps

live health

rollback

verification
```

Infrastructure engineers must be able to understand exactly what Autopilot did.

---

# 144. DATA QUALITY PAGE

Show:

- billing freshness;
- metrics freshness;
- missing agents;
- missing tags;
- reconciliation;
- unknown IaC;
- stale inventory;
- inaccessible resources.

Autopilot eligibility depends on data quality.

---

# 145. AUTOPILOT ELIGIBILITY

Action eligible only if:

```text
data_quality_pass
AND confidence_pass
AND policy_allows
AND resource_healthy
AND no_incident
AND no_conflicting_change
AND within_window
AND executor_available
AND rollback_ready
```

---

# 146. BILLING RECONCILIATION

Provider invoice is final financial truth.

FOCUS-normalised internal totals must reconcile.

After provider billing finality:

target:

**≥99.5% classified value.**

Unexplained variance:

**≤0.5%.**

---

# 147. COST CORRECTIONS

Cloud providers can update historical billing.

Never assume cost export is append-only.

Maintain:

```text
source_record_id
source_version
ingestion_version
correction_timestamp
```

Recalculate affected savings where necessary.

---

# 148. DATA FRESHNESS

Every metric carries:

```text
source_time
ingested_at
processed_at
freshness
finality
```

Statuses:

```text
LIVE
RECENT
DELAYED
PROVISIONAL
FINAL
```

---

# 149. MANAGEMENT API

Base:

```text
/v1
```

Core resources:

```text
/v1/organizations
/v1/cloud-accounts

/v1/applications
/v1/workloads
/v1/resources

/v1/costs
/v1/forecasts
/v1/budgets

/v1/recommendations
/v1/change-plans
/v1/executions

/v1/policies
/v1/approvals

/v1/commitments

/v1/savings
/v1/anomalies

/v1/audit
```

---

# 150. MUTATION API

All mutations MUST support:

```text
Idempotency-Key
```

Repeated submission cannot trigger duplicate infrastructure action.

---

# 151. API CONCURRENCY

Use resource version/ETag semantics.

Reject stale update with:

```text
409 CONFLICT
```

where appropriate.

---

# 152. WEBHOOKS

Required:

```text
recommendation.created
recommendation.validated

approval.required
approval.completed

execution.started
execution.stage_changed
execution.completed
execution.failed

rollback.started
rollback.completed

savings.verified

anomaly.detected

budget.threshold_crossed

integration.degraded
```

---

# 153. CHAT / WORKFLOW INTEGRATIONS

GA:

- Slack;
- Microsoft Teams;
- Jira;
- PagerDuty;
- generic webhook.

Example Slack action:

> `checkout-api` EC2 rightsize opportunity. £221k annual saving. High confidence. 10% canary. Production maintenance window Sunday 01:00.

Buttons:

**Approve**

**Reject**

**Open analysis**

---

# 154. GIT INTEGRATIONS

Support:

- GitHub;
- GitLab;
- Bitbucket.

Functions:

- discover IaC;
- open PR;
- annotate diff;
- read CI status;
- await merge;
- associate deployment.

---

# 155. IAC FORMATS

GA priority:

1. Terraform.
2. Kubernetes YAML / Helm.
3. CloudFormation.
4. Bicep/ARM.

Then:

Pulumi.

---

# 156. TERRAFORM

Map cloud resource to Terraform address.

Example:

```text
aws_instance.api[3]
```

Autopilot proposal:

```diff
-instance_type = "m6i.4xlarge"
+instance_type = "m6i.2xlarge"
```

PR description includes:

- evidence;
- saving;
- performance risk;
- rollback.

---

# 157. TERRAFORM PLAN

After patch:

run or consume:

```text
terraform plan
```

Plan MUST not contain unrelated destructive changes.

If unexpected destroy appears:

block automatic merge.

---

# 158. KUBERNETES GITOPS

If Argo CD/Flux-managed:

modify Git source.

Do not directly patch cluster configuration unless field is explicitly runtime-managed.

Observe GitOps sync to verify deployment.

---

# 159. SECURITY

Target:

- SOC 2 Type II;
- ISO 27001;
- GDPR;
- penetration testing;
- SBOM;
- SAST;
- dependency scanning;
- secret scanning;
- immutable audit logging.

---

# 160. IDENTITY

Support:

- SAML 2.0;
- OIDC;
- SCIM;
- enterprise IdP MFA.

Local authentication can be disabled.

---

# 161. RBAC

Default roles:

## ORGANISATION OWNER

Full control.

## FINOPS ADMIN

Costs/policies/recommendations.

## PLATFORM ADMIN

Execution/infrastructure.

## FINANCE

Billing/commitments/budgets.

## APPLICATION OWNER

Assigned applications.

## APPROVER

Specified change classes.

## VIEWER

Read-only.

## AUDITOR

Audit/security without mutation.

---

# 162. ABAC

Enterprise policy also needs attributes:

```text
environment
application
business_unit
provider
risk_class
```

Example:

User can approve R2 actions for Team X non-production only.

---

# 163. TWO-PERSON RULE

Optional requirement:

no person may both create execution policy and approve first high-risk use.

Enterprise customers can enforce separation of duties.

---

# 164. AUDIT EVENT

Every action:

```text
event_id
tenant_id

actor_type
actor_id

action

resource

before
after

policy
approval

timestamp

source_ip where relevant

execution_id
```

Audit log append-only.

---

# 165. MULTI-TENANCY

Every record:

```text
tenant_id
```

Tenant isolation at:

- identity;
- API;
- SQL;
- analytics;
- object storage;
- cache;
- queues;
- secrets;
- execution.

No tenant boundary relying only on UI filters.

---

# 166. ENCRYPTION

Transport:

TLS 1.2 minimum.

Prefer TLS 1.3.

At-rest:

AES-256 equivalent.

Enterprise roadmap:

customer-managed keys.

---

# 167. DATA RESIDENCY

Minimum:

EU

US.

Customer chooses control-plane data residency.

Customer-hosted executor can keep operational credentials entirely inside customer environment.

---

# 168. SECRET MANAGEMENT

Cloud execution secrets:

never plaintext.

Never log.

Rotate.

Audit reads.

Use workload identity/short-lived credentials wherever practical instead of permanent access keys.

---

# 169. AWS AUTHENTICATION

Preferred:

cross-account role with external ID.

Separate:

read role

and

execution role.

---

# 170. AZURE AUTHENTICATION

Use service principal / managed identity model with least-privileged roles.

Read and executor permissions separate.

---

# 171. GCP AUTHENTICATION

Prefer workload identity federation / service account impersonation.

Avoid long-lived static service-account keys where possible.

---

# 172. EXECUTION APPROVAL SIGNATURE

Approved ChangePlan becomes immutable signed payload.

Executor verifies signature.

Fields include:

```text
tenant
change_plan_id
resources
operations
policy_version
expires_at
nonce
```

Tampering invalidates request.

---

# 173. EXECUTION EXPIRATION

Approved plan expires.

Default:

R1/R2:

24 hours.

R3:

maintenance-window specific.

If expired:

rerun analysis/prechecks.

Do not execute week-old infrastructure assumptions.

---

# 174. PLATFORM ARCHITECTURE

Recommended services:

## CONNECTOR SERVICE

Cloud discovery.

## BILLING INGESTION

Cost.

## METRICS INGESTION

Operational telemetry.

## RESOURCE GRAPH

Topology.

## ECONOMICS ENGINE

Cost calculation.

## FORECAST ENGINE

Demand.

## OPTIMISER

Recommendations.

## POLICY ENGINE

Eligibility.

## CHANGE PLANNER

Implementation.

## EXECUTION ORCHESTRATOR

Workflow.

## EXECUTOR

Cloud mutation.

## VERIFICATION ENGINE

Performance/savings.

## SAVINGS LEDGER

Value.

## UI/API

Customer interaction.

---

# 175. REFERENCE STACK

Recommended:

Backend:

Go.

Optimisation/data science:

Python.

Frontend:

TypeScript + React.

Transactional:

PostgreSQL.

Analytics:

ClickHouse.

Graph:

PostgreSQL adjacency initially or dedicated graph solution if required.

Raw data:

object storage + Parquet.

Streaming:

Kafka-compatible.

Cache:

Redis.

Workflow:

Temporal-compatible durable workflows.

Metrics:

OpenTelemetry.

Infrastructure:

Kubernetes.

---

# 176. MONEY REPRESENTATION

Never binary floating point for money.

Use:

```text
DECIMAL(38,12)
```

or equivalent arbitrary/fixed-point type.

---

# 177. TIME SERIES STORAGE

Operational telemetry can use:

ClickHouse or dedicated metrics store.

Do not write every cloud metric sample into PostgreSQL.

---

# 178. SCALE TARGET

Design target:

**10 million cloud resources/platform-wide**

and:

**billions of metric samples/day.**

Per large enterprise:

**500,000 resources**

should be supportable without architecture replacement.

---

# 179. INVENTORY FRESHNESS

Normal resources:

p95:

**<15 minutes.**

Execution-sensitive resource:

refresh immediately before action.

---

# 180. BILLING FRESHNESS

Billing freshness depends on provider.

Never imply live billing if source isn't live.

Operational estimates may be live.

Provider reconciled cost may be delayed.

Show both.

---

# 181. CONTROL-PLANE SLO

API/UI:

**99.9%.**

---

# 182. EXECUTION SLO

Orchestrator:

**99.95%.**

Execution agent should remain capable of safely completing/rolling back in-progress workflow if control-plane connection is temporarily unavailable.

---

# 183. FAIL-SAFE RULE

When uncertain:

# Do nothing.

Autopilot must fail closed with respect to infrastructure mutation.

No policy service response:

no new action.

Unknown resource state:

no action.

Unknown SLO:

risk policy decides, but production R3 does not execute by default.

---

# 184. WORKFLOW DURABILITY

Execution must use durable state machine.

A service restart must not forget:

“VM is currently stopped while resizing.”

Workflow resumes from persisted step.

This is critical.

---

# 185. ACTION COMPENSATION

Every reversible execution step should define:

```text
do()
verify()
undo()
```

where technically possible.

Example:

```text
update_launch_template()
verify()
restore_previous_launch_template()
```

---

# 186. IRREVERSIBLE STEP

If no reliable `undo()` exists:

action risk increases.

Must be shown in approval.

Example:

purchasing three-year commitment.

---

# 187. PROVIDER RATE LIMITING

Connector and executor must implement:

- exponential backoff;
- jitter;
- provider quota awareness;
- concurrency limits;
- idempotency.

A 100,000-resource customer cannot hit provider APIs recklessly.

---

# 188. EXECUTION RATE LIMIT

Policy:

maximum concurrent changes per:

- provider;
- region;
- workload;
- application.

Default production:

no more than:

**10% of redundant fleet**

under active disruptive change simultaneously.

---

# 189. HEALTH SIGNAL

Autopilot must independently verify health.

Do not trust cloud API status alone.

A VM can be “running” while application is broken.

Use:

- infrastructure status;
- load balancer health;
- application metric;
- optional synthetic probe.

---

# 190. SYNTHETIC CHECKS

Customer can configure:

```text
GET /health
GET /checkout/synthetic
```

Expected:

HTTP status

latency

response predicate.

Changes fail if mandatory synthetic check fails.

---

# 191. INCIDENT ATTRIBUTION

If incident begins after Autopilot change:

immediately surface:

```text
possible_change_correlation
```

and offer:

**Rollback now.**

If policy allows:

automatic rollback.

---

# 192. AUTOPILOT INCIDENT KPI

Track:

```text
SEV1_caused
SEV2_caused
rollback_rate
failed_change_rate
```

The product should optimise not merely savings but:

# Savings × trust.

---

# 193. OPTIMISATION PRIORITY

Sort actions using:

```text
risk_adjusted_value
=
expected_verified_annual_saving
× confidence
× success_probability
/
change_risk
```

Exact scoring implementation may evolve.

But UI should prioritise high-value, high-confidence, low-risk actions.

---

# 194. CUSTOMER VALUE METRIC

Primary:

```text
verified_annualised_savings
```

Secondary:

```text
verified_savings
/
addressable_cloud_spend
```

Third:

```text
percentage_of_validated_savings_autonomously_realised
```

---

# 195. AUTONOMY METRIC

Measure:

```text
verified_savings_from_autonomous_actions
/
total_verified_savings
```

The long-term goal is increasing this without increasing incident rate.

---

# 196. RELEASE 1 — COMMERCIAL GA

Must include:

- AWS/Azure/GCP billing;
- resource inventory;
- FOCUS normalisation;
- ownership mapping;
- workload graph;
- AWS/Azure/GCP metrics;
- cost allocation;
- VM rightsizing;
- idle resources;
- non-production scheduling;
- Kubernetes rightsizing;
- Kubernetes node economics;
- EBS/disk recommendations;
- database recommendations;
- commitment analysis;
- policy engine;
- recommendation engine;
- approval workflows;
- IaC detection;
- Terraform PR execution;
- Kubernetes GitOps execution;
- low-risk direct execution;
- canary;
- rollback;
- savings verification;
- immutable audit.

A GA release without execution/verification is not this product.

---

# 197. GA AUTOPILOT ACTIONS

Initially allow autonomous execution only for mature action types:

- approved non-production schedules;
- pre-authorised stateless fleet rightsize;
- Kubernetes request changes;
- certain autoscaling adjustments;
- eligible storage performance/type optimisation;
- selected reversible idle-resource shutdown.

More dangerous changes begin Recommend/Assisted.

---

# 198. RELEASE 2

Add deeper automation:

- databases;
- serverless;
- networking;
- storage lifecycle;
- spot strategy;
- advanced commitments;
- workload forecasting;
- customer-hosted executor;
- GitLab/Bitbucket depth;
- Pulumi;
- CloudFormation/Bicep automated patching.

---

# 199. RELEASE 3

Target:

# Self-optimising cloud infrastructure.

Continuously adjust:

- resource size;
- fleet composition;
- Kubernetes requests;
- node shape;
- runtime schedule;
- capacity;
- pricing model;
- commitments.

within customer policy.

---

# 200. ACCEPTANCE TEST — FINANCIAL ACCURACY

Synthetic invoice:

£1,000,000.

Components:

£700k usage.

£150k commitment.

£80k credit.

£50k tax.

£20k adjustment.

System must reconcile exact source totals without double-counting.

---

# 201. ACCEPTANCE TEST — COMMITMENT AWARENESS

VM currently costs:

£10,000/month list.

Alternative:

£7,000.

But current resource consumes £6,000/month otherwise-stranded commitment.

Expected:

System must NOT claim £3,000 saving.

True economic migration result must include stranded commitment.

---

# 202. ACCEPTANCE TEST — RIGHTSIZING

VM fleet:

10 × current instance.

Observed:

CPU p99 40%.

Memory p99 50%.

Candidate provides:

30% headroom beyond forecast p99.

Network/disk compatible.

Effective monthly saving:

£8,000.

Expected:

recommendation valid.

---

# 203. ACCEPTANCE TEST — MEMORY FAILURE

CPU:

15%.

Memory:

95%.

Expected:

downsize rejected.

CPU alone cannot trigger rightsizing.

---

# 204. ACCEPTANCE TEST — SEASONALITY

11 months low load.

December 4× load.

90-day dataset includes annual event metadata.

Expected:

recommendation must preserve declared seasonal capacity requirement.

---

# 205. ACCEPTANCE TEST — IAC

Terraform says:

`m6i.4xlarge`.

Cloud currently:

`m6i.4xlarge`.

Optimiser proposes:

`m6i.2xlarge`.

Expected:

open Terraform PR.

Do not directly mutate EC2.

---

# 206. ACCEPTANCE TEST — UNKNOWN IAC

Resource appears declaratively managed but source cannot be found.

Expected:

`BLOCKED_CONFIGURATION_AUTHORITY_UNKNOWN`.

No autonomous change.

---

# 207. ACCEPTANCE TEST — KUBERNETES HPA

CPU request reduced 50%.

HPA target:

60%.

Simulation predicts replica count will increase enough that total cost increases.

Expected:

recommendation rejected.

---

# 208. ACCEPTANCE TEST — PDB

Node optimisation requires eviction.

PDB allows:

0 disruptions.

Expected:

execution waits/blocks.

Never bypass PDB.

---

# 209. ACCEPTANCE TEST — CANARY

Fleet:

20 instances.

Recommendation:

new type.

Policy max blast radius:

10%.

Expected:

at most two candidate instances initially.

---

# 210. ACCEPTANCE TEST — ROLLBACK

Candidate instance group shows:

p95 latency +35%.

Policy allows +15%.

Expected:

stop rollout.

Restore prior state.

Mark rolled back.

Notify owner.

No verified saving.

---

# 211. ACCEPTANCE TEST — INCIDENT

PagerDuty Sev-1 active for application.

Autopilot has scheduled rightsize.

Expected:

change does not start.

Status:

```text
BLOCKED_ACTIVE_INCIDENT
```

---

# 212. ACCEPTANCE TEST — STALE RECOMMENDATION

Recommendation created Monday.

Engineer manually resized workload Tuesday.

Autopilot tries execution Wednesday.

Precheck detects changed state.

Expected:

abort.

Reanalyse.

---

# 213. ACCEPTANCE TEST — DOUBLE EXECUTION

Same ChangePlan submitted twice.

Same Idempotency-Key.

Expected:

one infrastructure action.

---

# 214. ACCEPTANCE TEST — CONTROL PLANE FAILURE

Execution at 25% rollout.

Control plane becomes unavailable.

Customer-hosted/durable executor must:

either safely pause

or complete safe current step.

It must not lose execution state.

---

# 215. ACCEPTANCE TEST — SAVINGS NORMALISATION

Before:

10m requests.

£100k.

After:

15m requests.

£105k.

Expected:

Verified savings:

£45k relative to old £0.01/request baseline.

Not:

negative £5k.

---

# 216. ACCEPTANCE TEST — LOWER TRAFFIC

Before:

£100k at 10m transactions.

After:

£60k at 5m transactions.

Cost/unit worsened.

Expected:

do not claim £40k optimisation saving.

---

# 217. ACCEPTANCE TEST — NEGATIVE RESULT

Predicted saving:

£10k/month.

Actual normalised saving:

-£1k.

Expected:

ledger records:

```text
-£1,000
```

Recommendation considered unsuccessful.

---

# 218. ACCEPTANCE TEST — COMMITMENT ORDER

Customer has:

300 oversized instances.

Provider proposes new three-year commitment.

Expected:

system first models post-rightsize demand.

Commitment recommendation based on post-optimisation baseline.

---

# 219. ACCEPTANCE TEST — PRODUCTION SINGLETON

One production VM.

Resize requires restart.

No maintenance window.

Expected:

Autopilot cannot execute.

Recommendation marked approval/maintenance required.

---

# 220. ACCEPTANCE TEST — NON-PRODUCTION SCHEDULE

Dev environment unused overnight.

Approved schedule:

20:00 stop.

07:00 start.

Expected:

stop.

Verify stopped.

Start before schedule.

Verify healthy.

Record saving.

---

# 221. ACCEPTANCE TEST — DESTRUCTIVE RESOURCE

Unattached production disk appears idle.

Expected:

do not delete.

Enter quarantine workflow based on customer policy.

---

# 222. ACCEPTANCE TEST — TAGLESS RESOURCE

Resource has no ownership tags.

Expected:

cost remains visible.

Resource enters unallocated pool.

No fabricated owner.

---

# 223. PRODUCT KPI — FINANCIAL TRUST

Target:

after invoice finality:

**≥99.5% billing reconciliation.**

---

# 224. PRODUCT KPI — COVERAGE

Within mature customer:

**≥90% of addressable infrastructure spend analysed by optimiser.**

---

# 225. PRODUCT KPI — ACTIONABILITY

Target:

```text
implemented
/
validated_recommendations
```

increases over time.

---

# 226. PRODUCT KPI — SAVINGS REALISATION

Target:

```text
verified_savings
/
validated_savings
```

This is more important than theoretical opportunity volume.

---

# 227. PRODUCT KPI — SAFETY

Target:

# Zero Sev-1 incidents caused by Autopilot.

Track Sev-2 and rollback rate rigorously.

---

# 228. PRODUCT KPI — FALSE POSITIVE RATE

Track rejected recommendations caused by:

- insufficient context;
- incorrect ownership;
- hidden performance requirements;
- incorrect economics.

Use to improve optimiser.

---

# 229. NON-NEGOTIABLE DESIGN PRINCIPLE

The product must prefer:

**£1m of safely realised savings**

over:

**£10m of theoretical savings sitting in a dashboard.**

---

# 230. NON-NEGOTIABLE TRUST PRINCIPLE

The system must never exaggerate savings.

If uncertain:

show uncertainty.

If estimated:

say estimated.

If commitment affects result:

include it.

If traffic changed:

normalise.

If result is negative:

report it.

---

# 231. NON-NEGOTIABLE SAFETY PRINCIPLE

The system is authorised to optimise cost.

It is not authorised to sacrifice customer reliability unless the customer's explicit policy permits a stated trade-off.

---

# 232. END-TO-END DEFINITION OF DONE

The product is considered correctly implemented only when this exact workflow can occur.

Customer connects AWS, Azure and GCP.

The system imports billing.

It reconciles spend.

It discovers infrastructure.

It maps resources into workloads.

It discovers Terraform/Kubernetes configuration authority.

It imports application/cloud metrics.

It understands workload SLOs.

It identifies idle resources.

It identifies oversized resources.

It identifies Kubernetes waste.

It understands existing commitments.

It removes waste from the future-demand model.

It recalculates commitment needs.

It produces an optimisation recommendation.

It explains why the recommendation is safe.

It calculates effective rather than public-price savings.

It generates an exact ChangePlan.

It checks maintenance policy.

It checks incidents.

It checks configuration drift.

It checks current resource state.

It modifies IaC where IaC owns the resource.

It runs deployment validation.

It performs a canary.

It monitors infrastructure health.

It monitors application SLO.

It expands the rollout if healthy.

It automatically rolls back if unhealthy.

It measures actual post-change cost.

It normalises the result for workload volume.

It reconciles against provider billing.

It records verified savings.

It preserves an immutable audit trail.

If this chain does not work:

# the intended product has not yet been built.

---

# 233. FINAL PRODUCT CONTRACT

Cloud Cost Autopilot should eventually allow a CTO to establish a policy such as:

> Keep production availability above 99.99%.

> Keep checkout p95 latency below 180ms.

> Maintain at least 30% forecast burst capacity.

> Never move restricted workloads outside the EU.

> Never automatically modify databases.

> Never automatically purchase a commitment above £100k.

> Automatically optimise stateless compute, Kubernetes and approved non-production resources.

> Stop any action that violates SLOs.

> Roll back automatically if performance deteriorates.

> Optimise for actual contracted cloud economics, not public list prices.

The platform should then be capable of continuously operating inside those rules.

The long-term desired behaviour is:

> We detected £3.8m of annual addressable waste.

> £410k involved resources you prohibited us from changing.

> £620k requires engineering approval.

> £2.77m qualified for Autopilot.

> We executed 1,482 controlled changes.

> 1,443 succeeded.

> 39 were rolled back safely.

> No Sev-1 incidents occurred.

> Provider invoices and workload-normalised economics verify £2.46m of annualised savings.

> The remaining difference was not claimed.

> Based on the post-optimisation demand profile, we recommend a £4.2m one-year commitment instead of the provider's original £6.8m recommendation.

That is Cloud Cost Autopilot.

The product's value is not that it **finds cloud waste**.

Its value is that it can **remove cloud waste continuously, safely and provably.**