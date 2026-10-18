# AWS blue/green fleet reference — configuration and mocked plans only

This reference matches the separate `internal/fleet` schema-4 contract. It is
not a bootstrap deployment or authorization to import, apply or provision AWS
resources. No customer credentials or AWS resources are used in its tests.
`runtime_updates_enabled` defaults to `false`. Setting it to `true` only removes
an accidental-run guard; it creates no human approval, source proof, execution
lease, signed child, callback receipt or financial authority.

The customer must already own and separately commission these exact objects:

| Terraform address | Existing object |
| --- | --- |
| `aws_launch_template.old` | Original stateless application template and concrete version |
| `aws_launch_template.candidate` | Distinct, reviewed candidate template and concrete latest version |
| `aws_autoscaling_group.old` | Original group, initially twenty instances |
| `aws_autoscaling_group.candidate` | Existing empty candidate group, initially zero instances |
| `aws_lb_listener_rule.app` | Existing weighted-forward HTTPS application listener rule |

Both existing target groups, the HTTPS listener, private subnets, security groups,
application AMI, instance profile and root-volume KMS key are external inputs.
The reference creates no VPC, ALB, target group, IAM role or independent scaling
policy. Definitions must match imported state completely, including tags,
bootstrap, root volume, health configuration and listener condition. Import,
enrolment or convergence changes require separate customer review outside the
runtime fleet protocol. The first commissioned saved plan must be a no-op;
the runtime validator rejects creation, import, replacement and unrelated drift.

The initial configuration retains old=20/candidate=0 and traffic old=100% /
candidate=0%. Each group has `min_size=max_size=desired_capacity`, explicit
`desired_capacity_type=units`, no mixed-instance policy or instance refresh,
and no capacity rebalance or scale-in protection. All five membership tags
required by the native source factory propagate at launch. Autonomous unhealthy
replacement, AZ rebalance, refresh, scheduled scaling and alarm scaling are
suspended. Launch, Terminate, HealthCheck and AddToLoadBalancer remain available
for the supervised customer pipeline. Disabling native unhealthy replacement
requires an explicit operational owner and recovery procedure; this is not an
appropriate unattended default for a general-purpose ASG.

The exact AWS account is guarded by `allowed_account_ids` and observed caller
identity. The region is restricted to `eu-west-1`; private subnets must span two
availability zones in the same account/VPC. Launch templates use numeric version
pins, IMDSv2, no public IP, and only an encrypted disposable root EBS volume.
AMI/application state, statelessness, capacity sufficiency, SLOs and dependency
safety still require independent trusted evidence; tags are not substitutes.

## Runtime pipeline contract

Every capacity or traffic transition requires a **new** saved Terraform binary
and its exact `terraform show -json` rendering. The authenticated customer
pipeline must bind account, region, Git commit, configuration digest, workspace,
state lineage/serial, Terraform/provider locks, binary digest and rendered JSON
digest to a newly signed schema-4 child. Use the existing offline
`scripts/check-workload-plan.mjs` validator before any independently authorized
customer pipeline apply. The checker itself never applies a plan or reads cloud
credentials. An output from `terraform test` is not such a receipt.

Warm candidates in steps of at most two instances while retaining all twenty
old instances. Independently prove candidate membership, readiness, headroom,
workload preservation and per-cohort SLOs before raising traffic. The reviewed
traffic milestones are 10%, 25%, 50%, then 100%. Capacity and traffic changes are
separate signed children; a milestone's aggregate count never permits skipping
the intermediate two-instance blast-radius limit. The 10% canary needs the full
one-hour observation window. Later observations, portfolio budgets and source
freshness remain independent gates in the fleet contract.

Old capacity can decrease only after all twenty candidates are healthy and serve
100% of traffic, and after separately approved cleanup. Recovery retains the old
template and traffic destination, uses a fresh compensation plan and the same
customer pipeline, and stays available for genuinely owned incomplete changes
after new-change pause/expiry. Never replay an earlier saved binary for a later
stage or recovery. No reference output proves an apply, restoration or saving.

Target groups are a provider `set`, so JSON array order can change with weights.
The validator normalizes only the two approved ARNs to old=0/candidate=1 for
signed leaf paths, while retaining the original raw JSON and binary digests.
The complete ARN set and exact per-ARN weights remain bound; accepting an array
reorder must not authorize an ARN replacement. Stickiness is disabled here. Independent application and ALB
health must be commissioned before any traffic stage.

## Local validation

Run `terraform init -backend=false`, `terraform validate`, and `terraform test`
in this directory with the pinned provider. All tests use `mock_provider` and
`command=plan`; none use apply. They cover the disabled default, initial group
and traffic shape, native tags, controller isolation, warm-up/traffic separation,
wrong account/region, early old-cohort drain and traffic ahead of capacity.
No real state, saved plans, secrets or `.terraform/` directories belong in Git.

This does **not** complete fleet acceptance: there is no live AWS cohort,
authenticated customer deployment pipeline, real ALB canary, actual application
headroom comparison, hosted recovery or verified saving demonstrated here.

The reference follows primary provider documentation for
[ASG processes and capacity](https://registry.terraform.io/providers/hashicorp/aws/6.69.1/docs/resources/autoscaling_group),
[concrete launch-template versions](https://registry.terraform.io/providers/hashicorp/aws/6.69.1/docs/resources/launch_template),
[weighted listener rules](https://registry.terraform.io/providers/hashicorp/aws/6.69.1/docs/resources/lb_listener_rule),
and HashiCorp's [saved-plan workflow](https://developer.hashicorp.com/terraform/tutorials/cli/plan).
