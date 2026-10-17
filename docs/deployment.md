# AWS pilot deployment

This deployment targets the approved AWS development EC2 stop/start pilot in **eu-west-1**. It provides a regional control plane and a tightly scoped customer execution role. It is a pilot reference deployment; production capacity, availability, recovery objectives and security certification have not been established by these files. Terraform validation and Helm rendering do not establish successful deployment in an AWS account.

Complete the [sandbox input and rollout checklist](sandbox-readiness.md) first. Both Terraform stacks now require an exact `expected_account_id`, owner and expiry. The platform also requires an approved account-wide alert budget and recipients. Fresh customer-role installs default to read-only; existing installations must follow the checklist's state-preserving upgrade instructions before planning.

The selected live pilot uses two separate AWS sandbox accounts: one for the EKS control plane and one for customer workloads. Record distinct account IDs and trust only the specified role in the other account. Same-account customer principals/targets are rejected by Terraform; initial empty platform allowlists are supported. Local Compose is the developer fixture path.

## Boundaries and resources

`deploy/terraform` creates a two-AZ VPC, private EKS worker subnets, isolated RDS subnets, an encrypted PostgreSQL 16 RDS instance with managed administrator credentials, and separate raw and audit S3 buckets. The cluster API is private plus a public endpoint restricted to explicit operator CIDRs. Application services are ClusterIP only. The database accepts PostgreSQL from the EKS cluster security group and requires TLS.

There is one NAT gateway for this pilot. An AZ failure can interrupt outbound access for both worker subnets. EKS worker count and RDS Multi-AZ are configurable; default workers are two On-Demand m6i.large nodes and RDS Multi-AZ is enabled. Capacity for workload growth has not been benchmarked. ClickHouse and Temporal are single-replica regional pilot services; their availability does not equal that of the managed database.

Six independent KMS encryption keys separate database, raw data, audit evidence, signer-secret wrapping, execution-secret wrapping and Kubernetes secret encryption. The application signs with Ed25519 inside the isolated signer. **AWS KMS Sign is not implemented by this deployment.** The signer and executor IAM roles can retrieve only their respective externally created Secrets Manager secrets when their ARNs are configured. The chart references existing Kubernetes Secrets; it does not automatically fetch or synchronise Secrets Manager values. Use an approved secret-delivery controller or perform the explicit operator provisioning below.

Raw objects use S3 Object Lock COMPLIANCE retention for 90 days; audit objects default to 365 days. These are actual retention locks, including for administrators during the retention period. Retention, legal basis and expected storage costs must be decided before the first upload. Application IAM roles cannot delete object versions or bypass retention. Evidence buckets and encryption keys also have Terraform `prevent_destroy`; an ordinary teardown must not schedule key deletion before locked evidence expires. Repeated writes to a key create versions; producers must use unique evidence keys and preserve version IDs/checksums when an immutable reference is required. Bucket provisioning alone does not prove that application records have been archived there; validate actual object delivery in the pilot.

## Validate locally

Run from the repository root. These checks do not require AWS credentials:

```powershell
docker run --rm -v "${PWD}:/src" -w /src/deploy/terraform hashicorp/terraform:1.9.8 fmt -check -recursive
docker run --rm -v "${PWD}:/src" -w /src/deploy/terraform --entrypoint sh hashicorp/terraform:1.9.8 -ec 'terraform init -backend=false -input=false && terraform validate && terraform -chdir=modules/customer-roles init -backend=false -input=false && terraform -chdir=modules/customer-roles validate'
docker run --rm -v "${PWD}:/src" alpine/helm:3.17.2 lint /src/deploy/helm/finops --strict
docker run --rm -v "${PWD}:/src" alpine/helm:3.17.2 template finops /src/deploy/helm/finops --namespace finops
```

If Docker Hub image delivery fails, the same published tags are available through `mirror.gcr.io/hashicorp/terraform` and `mirror.gcr.io/alpine/helm`. Commit the generated `.terraform.lock.hcl` files after reviewing provider versions. Commit no `.terraform/`, state, plan, private key or secret value. CI performs these checks plus containerised Go tests, Python economics tests, frontend build/typecheck, generated OpenAPI drift checking and a Compose fixture smoke test.

## Provision the EU control plane

Use an operator session with temporary AWS credentials and an explicit target account. Do not run Terraform using the customer workload execution role. Prepare encrypted, access-restricted remote state before applying: `deploy/terraform/backend.tf.example` describes an S3 state backend and DynamoDB lock table. Bootstrap those separately and copy it to `backend.tf`. The pilot's raw/audit buckets must not be reused as Terraform state buckets. State contains external IDs and infrastructure metadata; treat it as sensitive even though this module generates no application private keys or passwords.

Copy `pilot.tfvars.example` to ignored `pilot.auto.tfvars`. Replace the account/role and documentation CIDR. The operator role must exist; Terraform explicitly creates its EKS access entry and disables implicit creator-admin access. Region is restricted to eu-west-1. Verify your selected EKS version remains supported before deployment; the default is 1.35. AWS documents [EKS 1.35 availability](https://aws.amazon.com/about-aws/whats-new/2026/01/amazon-eks-distro-kubernetes-version-1-35/).

```powershell
aws sts get-caller-identity
terraform -chdir=deploy/terraform init
terraform -chdir=deploy/terraform plan -out=pilot.tfplan
# Review the account, eu-west-1 region, network access, retention locks and cost.
terraform -chdir=deploy/terraform apply pilot.tfplan
aws eks update-kubeconfig --region eu-west-1 --name finops-pilot --role-arn YOUR_OPERATOR_ROLE_ARN
kubectl create namespace finops
```

Use the operator's installed Terraform or the same container with an explicit temporary credential mount; never put credentials in Terraform source or tfvars. Retention locks prevent immediate evidence destruction and Terraform defaults protect RDS deletion. This stack creates billable EKS, RDS, nodes, NAT, EBS and S3 resources.

## Database and secret provisioning

Retrieve the RDS master secret as an authorised deployment operator. Connect from a controlled pod/operator path to the private endpoint over TLS. Download the [AWS RDS regional CA bundle](https://truststore.pki.rds.amazonaws.com/eu-west-1/eu-west-1-bundle.pem), verify it through your normal trust process, then provision it as `finops-rds-ca` with key `ca.crt` in namespace `finops`. Applications mount it at `/etc/finops/rds/ca.crt`.

Run `deploy/bootstrap-database.sql` once on the `finops` database as the RDS administrator. It creates separate login identities and grants them the NOLOGIN permission roles used by the application migrations. Set passwords interactively using psql `\password ROLE_NAME`; do not add them to the SQL file or shell history. Retain migration CREATEROLE only for migration operations; runtime users must not have CREATEROLE, superuser, BYPASSRLS or ownership of application tables. Granting app table ownership to runtime identities weakens permission boundaries even with FORCE RLS.

Create the following existing Kubernetes Secrets using an approved secret store or `kubectl create secret --from-env-file` with restricted temporary files under ignored `work/secrets/`. Do not paste private keys or passwords into Helm values. Every `DATABASE_URL` must use the matching login and `sslmode=verify-full&sslrootcert=/etc/finops/rds/ca.crt` (URL-encode password characters). Reuse no administrator credentials in runtime pods.

| Secret | Required keys and identity |
| --- | --- |
| `finops-db-api` | `DATABASE_URL`, `finops_api_login` |
| `finops-db-worker` | `DATABASE_URL`, `finops_worker_login` |
| `finops-db-ingester` | `DATABASE_URL`, `finops_ingester_login` |
| `finops-db-signer` | `DATABASE_URL`, `finops_signer_login` |
| `finops-db-executor` | `DATABASE_URL`, `finops_executor_login` |
| `finops-db-migrate` | `DATABASE_URL`, `finops_migrator` |
| `finops-signer` | `SIGNING_PRIVATE_KEY` (base64 Ed25519), `SIGNER_TOKEN` |
| `finops-worker` | `SIGNING_PUBLIC_KEY`, `SIGNER_TOKEN`, `EXECUTOR_TOKEN`; optional `WEBHOOK_SECRET` only when notifications are enabled |
| `finops-executor` | `SIGNING_PUBLIC_KEY`, `EXECUTOR_TOKEN` |
| `finops-aws` | `AWS_EXTERNAL_ID`, unique to this customer |
| `finops-clickhouse` | `password`, a dedicated ClickHouse credential |
| `finops-temporal-db` | `username=finops_temporal`, `password` |
| `finops-economics` | `ECONOMICS_TOKEN`, shared only with API, ingester and economics |

Generate the Ed25519 keypair with a cryptographic library/tool and create independent random signer/executor tokens. Never copy the private key into API, worker, ingester, economics or web secrets. If Secrets Manager is your source, create the signer value encrypted with Terraform's signer KMS key and the executor value with its execution KMS key; pass only secret ARNs back to Terraform. Secrets Manager and external secret-delivery controller setup are deliberate operator steps. The chart itself contains no secret values.

Temporal auto-setup connects to the pre-created `temporal` and `temporal_visibility` databases using verified PostgreSQL TLS, skips database creation, and initialises its schema and a `finops` namespace with 14-day history retention. Confirm compatibility and take a backup before upgrading Temporal. Its startup environment follows the [official auto-setup implementation](https://github.com/temporalio/docker-builds/blob/main/docker/auto-setup.sh). ClickHouse initialises billing/metric tables from the chart's bundled copy of `config/clickhouse/001_facts.sql`; CI checks that this copy has not drifted. Initialisation files do not migrate an existing ClickHouse volume: apply reviewed additive DDL separately before upgrading an established database.

## Customer-account role installation

Instantiate `deploy/terraform/modules/customer-roles` in the **customer sandbox account**, using an independent Terraform state and its `pilot.tfvars.example`. Supply only the control-plane ingester as the read principal initially; the module defaults to `enable_execution=false` and creates no customer execution role/policy. Billing bucket access is optional for discovery. Later execution requires explicit `enable_execution=true`, executor principal and exact instance IDs. API, workflow worker and signer have no customer mutation role. Use a unique external ID at least 32 characters and the exact tenant; when adding billing, scope its S3 prefix and KMS access.

The execution role allows only instance/status/stop-protection descriptions and StartInstances/StopInstances in the selected region. Stopping requires all of these exact tags on an allowlisted instance:

```text
finops:tenant = YOUR_TENANT_ID
finops:autopilot = enabled
finops:environment = NON_PRODUCTION
```

It explicitly denies termination, attribute changes, tag mutation, IAM and Organisations actions. The executor cannot grant itself eligibility by retagging resources. IAM scope tags supplement the signed plan, database authorisation and application prechecks; they do not replace them. The read role is read-only, including bounded billing-object reads and optional customer KMS decryption. If billing is in a separate payer account, install/trust the appropriate read role there and explicitly extend the ingester's permitted assume-role list. This module is intentionally limited to the pilot's EC2 path.

Starting retains the exact instance allowlist, region, tenant and NON_PRODUCTION tag requirements, but does not require `finops:autopilot=enabled`. This permits safe restoration after an operator removes stop opt-in. The executor must still prove ownership of the original stop; IAM permission to start is not authorisation to start an independently stopped instance.

Pass the customer role ARNs into the control-plane `customer_read_role_arns` and `customer_execution_role_arns` lists and apply that reviewed policy update. The roles cannot assume arbitrary account roles. Test both allowed and denied AWS dry-run calls before authorising the first sandbox execution, including wrong tenant tag, production environment, removed opt-in tag and unlisted instance.

## Install application images and chart

Build `Dockerfile.backend`, `economics/Dockerfile` and `frontend/Dockerfile` using the repository root as the build context, review them and push to your EU image registry. Supply exact immutable image digests through `images.<component>.digest`; mutable `pilot` tags are local placeholders. CI uses Go 1.27.2. The frontend's Vite OIDC issuer/client are build-time inputs and must agree with the deployed issuer. Configure its public PKCE client with the final redirect/logout origins and `finops` token audience; do not enable a production password grant for the browser.

Prepare an ignored Helm values file with RDS endpoint, raw/audit bucket names, image repositories/digests, OIDC issuer and Terraform's workload role ARNs. A regional fixture deployment still needs the ingester's bucket IAM identity to persist synthetic evidence; `fixture` controls customer compute mutation/data selection, not the storage backend. Local Compose supplies its own fixture object store instead. Use a trusted external OIDC provider. No identity provider is created by this chart. Optional AWS ALB ingress is described below; a local operator tunnel is also available. The web container proxies the API using `API_UPSTREAM=finops-api:8080` and listens on 8080 behind service port 80.

```powershell
helm upgrade --install finops deploy/helm/finops --namespace finops --values work/pilot-values.yaml --wait --timeout 15m
kubectl -n finops get pods,services,pvc
kubectl -n finops logs job/finops-migrate-1
kubectl -n finops port-forward service/finops-api 8080:8080
```

Start in `dataMode: fixture`. Helm applies the schema using a separate pre-install/pre-upgrade migration Job. Application roles remain separated, and only the worker receives both service tokens. EKS VPC CNI network-policy enforcement is enabled; namespace policies default-deny and restrict signer/executor ingress to the worker. Inspect policy enforcement rather than assuming that a rendered NetworkPolicy is effective. HTTPS egress is allowed for AWS APIs and the OIDC provider; narrow it through an egress proxy if required by the customer. PostgreSQL uses verified TLS. Internal application/Temporal/ClickHouse links currently use private-network HTTP/gRPC; add and validate service-to-service TLS/mTLS before treating this reference as an unrestricted production control plane.

For read-only AWS onboarding, set `dataMode: aws`, `aws.readRoleArn`, `aws.ingesterRoleArn`, `aws.rawBucket`, `aws.auditBucket`, the unique external ID and `aws.tenantId`. The tenant must exactly match the authenticated `tenant_id` claim; the chart injects `AWS_TENANT_ID`. Keep `aws.executionRoleArn`, `aws.executorRoleArn` and `health.allowedHosts` empty. An existing customer read-only role is sufficient for discovery and evidence ingestion; customer execution credentials and mutation privileges are not required. Ingestion still writes the platform's raw/audit storage through its separate IAM identity. Keep control-plane `customer_execution_role_arns=[]` while execution is unconfigured. The executor cannot fall back to an implicit AWS mutation identity when its customer target role is empty.

Enable execution later by installing the scoped customer execution role and reviewed instance allowlist/tags, adding that explicit ARN to the control-plane's permitted execution targets, setting `aws.executionRoleArn` and `aws.executorRoleArn`, and configuring `health.allowedHosts`. Helm requires the executor IAM identity and exact HTTPS health hosts only when a nonempty customer execution target is supplied. Complete the application safety policy, explicit approval/opt-in and supervised sandbox checks before allowing a stop.

This live deployment intentionally binds **one customer tenant to its configured read role and optional execution role**. Missing or mismatching tenant identity must block live discovery and execution. The IAM `finops:tenant` tag and customer-role module `tenant_id` must match before enabling mutation. Provision separate ingester/executor identities and role configuration for another live customer; never share a global credential pair across JWT tenants. Fixture data still exercises multiple tenant partitions.

For execution health checks, use HTTPS endpoints reachable from the private workers. Inventory also expects explicit `finops:standalone=true`, `finops:runtime-stop-start=true`, `finops:stable-network=true`, and `finops:owner` evidence before stop eligibility; missing workload/billing evidence blocks optimisation eligibility without preventing discovery. AWS SDK web-identity variables including `AWS_ROLE_ARN` are reserved for IRSA; the customer target is `AWS_EXECUTION_ROLE_ARN`. `AWS_READ_ROLE_ARN` identifies the customer reader. AWS mode must never silently fall back to fixture data.

The EC2 telemetry adapter reads CloudWatch CPUUtilization, NetworkIn and NetworkOut hourly Maximum observations for a rolling 14-day window ending at the latest complete UTC hour. Missing datapoints remain absent and memory is not inferred. These are observed hourly maxima, not p99 estimates or workload forecasts. The EBS adapter discovers volume configuration and attachment topology without inventing price or deletion eligibility; retained disk cost still belongs in workload economics. See [CloudWatch statistics semantics](https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_GetMetricStatistics.html).

## Runtime contract

| Component | Runtime/port | Inputs |
| --- | --- | --- |
| API | Go, `APP_ROLE=api`, `PORT=8080`, `/healthz` | its `DATABASE_URL`, `OIDC_ISSUER`, optional `OIDC_JWKS_URL`, `OIDC_AUDIENCE=finops`, `TEMPORAL_ADDRESS`, `TEMPORAL_NAMESPACE`, `ECONOMICS_URL` |
| Worker | Go, `APP_ROLE=worker`, port 8080 | worker DB URL, Temporal, `SIGNER_URL`, `EXECUTOR_URL`, both service tokens and signing public key; no AWS or raw/analytics credentials |
| Ingester | Go, `APP_ROLE=ingester`, port 8080 | ingester DB URL, economics URL/token, customer read role/external ID, raw/audit S3 IAM identity, ClickHouse credentials; no execution/signer credentials |
| Signer | Go, `APP_ROLE=signer`, port 8080 | signer DB URL, signing private key, signer token |
| Executor | Go, `APP_ROLE=executor`, port 8080 | executor DB URL, public key, executor token, customer execution role/external ID |
| Migrator | Go, `APP_ROLE=migrate`, exits after schema | migration DB URL only |
| Economics | Python, port 8000, `/healthz` | no execution credentials or private signing key |
| Web | React/static server, port 8080, service 80 | build-time public OIDC configuration; `API_UPSTREAM` |

All application roles receive `DATA_MODE=fixture|aws`, `FIXTURE_MODE=true|false`, and `AWS_REGION=eu-west-1`; the chart derives both mode variables from one value. Service addresses are cluster-local. The dedicated ingester uses `OBJECT_ENDPOINT`, `OBJECT_REGION`, `OBJECT_BUCKET_RAW`, `OBJECT_BUCKET_AUDIT`, `CLICKHOUSE_URL`, `CLICKHOUSE_DATABASE`, `CLICKHOUSE_USER`, `CLICKHOUSE_PASSWORD`. For hosted AWS, leave the object endpoint empty and omit explicit access/secret key variables so the SDK uses IRSA. Static `OBJECT_ACCESS_KEY`/`OBJECT_SECRET_KEY` and `AUDIT_ACCESS_KEY`/`AUDIT_SECRET_KEY` are intended for the local fixture object store; the hosted chart does not inject them. Verify actual object delivery/version IDs and ClickHouse ingestion before claiming coverage. The bootstrap RDS password is not a runtime application input. Hosted database users are provisioned separately; local Compose bootstrap's `DB_INGESTER_PASSWORD` is not injected into any unrelated service.

## Optional signed outbox notifications

Set `notifications.webhookUrl` to an explicitly trusted operator/platform HTTPS receiver on port 443 and add a separate random `WEBHOOK_SECRET` key to the existing worker Secret. The chart injects `WEBHOOK_URL` and `WEBHOOK_SECRET` into the workflow worker only. When the URL is empty, it injects neither variable and no webhook secret key is required. Never reuse a signer/executor service token as the webhook secret.

This pilot has one operator-configured destination, not per-tenant webhook subscriptions. The receiver is trusted to receive all local fixture tenant events; live deployment uses the explicit single-customer `AWS_TENANT_ID` binding. Application users cannot select an arbitrary delivery URL. Enable delivery only for a receiver authorised for that scope.

The persisted outbox sends JSON with event ID, tenant ID, event type and event data. Verify the SHA-256 HMAC in `X-Autopilot-Signature` over the exact request body using the configured secret, and deduplicate the `Idempotency-Key`/event ID. Delivery is retried and may repeat after an uncertain response; acknowledge only after durable receiver acceptance. Do not log the secret or treat an unauthenticated request as an approval. Empty-secret or insecure-target configurations must fail closed. Outbox delivery setup does not itself install Slack/Teams integrations or grant notification permissions to other services.

## Optional role-scoped secret delivery

Install and pin an approved External Secrets Operator release and its `external-secrets.io/v1` CRDs. Set `externalSecrets.enabled=true`, the two existing Secrets Manager ARNs, and signer/executor IRSA role ARNs. The chart creates separate namespaced SecretStores using the matching signer/executor ServiceAccount and separate ExternalSecrets. Terraform grants each role GetSecretValue on only its own ARN and KMS Decrypt only through Secrets Manager with its purpose-specific key. Never give the worker access to a combined signer secret merely to extract its token: Secrets Manager IAM applies to the entire value, including the private key. Provision worker tokens/public key through its separate secret. Treat the secret-delivery controller's service-account TokenRequest privileges as trusted administrative access and scope its namespace/RBAC accordingly.

## Optional ALB HTTPS ingress

Terraform provisions a separate AWS Load Balancer Controller IRSA role. It vendors the upstream [v3.6.0 IAM policy](https://github.com/kubernetes-sigs/aws-load-balancer-controller/blob/v3.6.0/docs/install/iam_policy.json), SHA-256 `16f232c9d9f79366fe949c4550ad517a202380058a9e48d45a4e215044a20a6a`, and denies EC2/ELB/ACM operations outside eu-west-1. The controller can manage load-balancer networking; this role is never attached to the application or nodes. Review the policy before installation and update it with the pinned controller release.

Install the controller using [AWS's Helm procedure](https://docs.aws.amazon.com/eks/latest/userguide/lbc-helm.html), setting explicit region/VPC because worker IMDS access is restricted:

```powershell
helm repo add eks https://aws.github.io/eks-charts
helm repo update
helm upgrade --install aws-load-balancer-controller eks/aws-load-balancer-controller --version 3.6.0 --namespace kube-system --set clusterName=finops-pilot --set region=eu-west-1 --set vpcId=YOUR_VPC_ID --set serviceAccount.name=aws-load-balancer-controller --set serviceAccount.annotations."eks\.amazonaws\.com/role-arn"=YOUR_CONTROLLER_ROLE_ARN
```

Set `ingress.enabled=true`, an explicit hostname, an already issued **eu-west-1 ACM certificate ARN**, restricted `inboundCidrs`, and the real VPC CIDR. The default scheme is internal. The Ingress listens on HTTPS 443 with TLS 1.2/1.3 policy and sends traffic only to the web service, which proxies authenticated API traffic. No HTTP listener is created. Configure private DNS or the intended trusted DNS record for the ALB and finalise OIDC redirect origins. Certificate issuance and DNS record creation are separate operator steps; the chart does not request certificates or register a domain. Check target health, certificate chain, tenant authentication and denied CIDRs before enabling the sandbox execution. ALB deletion protection is enabled; disable it deliberately before an approved ingress teardown. TLS terminates at the ALB; internal TLS/mTLS remains a separate deployment requirement.

## Pilot exit evidence

Record image digests and infrastructure plan, login/tenant isolation checks, policy denials, a fixture complete execution/rollback path, then one explicitly approved sandbox stop/start. Demonstrate recovery after worker/executor restart, health failure after startup, duplicate submission and expired signatures. Check raw-object and audit-object delivery separately from database audit records. Perform a restore drill and confirm native-currency billing reconciliation and labelled savings finality. These checks establish the bounded pilot result; they do not certify the specification's full multi-cloud GA.
