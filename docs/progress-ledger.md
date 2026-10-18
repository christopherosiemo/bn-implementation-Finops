# Product scope progress ledger

Recorded 18 October 2026. **Approximately 21% → 22%** of the full product, using **21.0 → 22.2 weighted points** across the preserved 233-section specification, including GA obligations. The original 17.5-point baseline and all credit reviews remain in [progress-ledger.json](progress-ledger.json). Version-1 domain weights are fixed. This is engineering judgement based on accepted capability, not a count of tests, headings or endpoints.

| Domain | Fixed scope weight | Current area maturity | Contribution |
| --- | ---: | ---: | ---: |
| Billing, inventory and telemetry | 18% | 25% | 4.5 points |
| Workload graph, demand and SLO | 12% | 30% | 3.6 points |
| Optimisation, forecasting and commitments | 18% | 5% | 0.9 points |
| Execution, IaC and GitOps | 18% | 15% | 2.7 points |
| Reconciliation and verified savings | 10% | 40% | 4.0 points |
| Identity, tenancy, policy and audit | 10% | 35% | 3.5 points |
| Console, API and enterprise workflows | 6% | 30% | 1.8 points |
| Production operations | 8% | 15% | 1.2 points |
| **Total** | **100%** | | **22.2 points** |

Each domain is broken into acceptance packages. Maturity stages are 0 (absent), 20 (component), 40 (deterministic E2E), 70 (supervised live), 90 (production operations), and 100 (contract complete). The retained baseline package weights reproduce the original 17.5 points; all current credits use 0/20/40 only. Contributions multiply package scope weight by accepted stage. Shared foundations count once. No fixture package receives live credit, and incomplete delivery is never rounded to 100%.

This increment adds 1.2 points by advancing the bounded workload-mapping package from component acceptance to deterministic end-to-end acceptance. Server-selected mappings and typed declarations feed immutable, expiring reviews that bind new schema-3 plans and proof sets. Restricted PostgreSQL acceptance rejects stale or changed authority and serializes inventory/graph writers with STOP dispatch. The native-evidence fixture flow executes an approved occurrence and preserves owned restoration after graph invalidation; API and browser checks cover declarations, explicit review and blockers. Operator review remains a human trust boundary for undiscovered consumers. Complete dependency discovery, hard-SLO evaluation, live graph validation and customer operation earn no credit here. Shared identity, signing, console and restoration foundations are not counted again.

The previous evidence increment added 3.5 points for deterministic native billing ingestion through a current claim, the independent demand component and append-only claim corrections. The real PostgreSQL/Python test exercises provider-shaped delivery, guarded minute receipts, proof-bound execution, exactly £5.16 synthetic savings, replay and native invoice cancellation. Its archive/analytics callbacks and AWS transport are deterministic doubles; separate deployed fixture checks exercise object/analytics persistence, OIDC, Temporal and restart recovery. These checks support bounded engineering credit and do not prove live source delivery.

The delivered foundation is one AWS non-production EC2 scheduling slice with local OIDC, tenant isolation, separated process identities, approvals, signed plans, owned restoration, fixture financial verification and deployment assets. Version-3 native billing/source/activity contracts now have adversarial local test coverage. Source integration code and deployment templates still require customer-environment validation. No AWS deployment, customer verified savings, production SLO, tested customer recovery objective, certification or commercial GA acceptance is recorded.

The domain weights stay fixed in version 1; changing weights requires a separately explained model version rather than retroactive progress. Package maturity can change only when evidence changes. New code does not automatically increase this estimate. The v3 work is not credited as authentic customer history or live operational acceptance. The [acceptance record](acceptance.md) lists what was actually exercised; [traceability](traceability.md) preserves the much broader remaining obligations.

The next implementation gate is independent hard-SLO telemetry and action-specific evaluation; hourly CloudWatch maxima cannot stand in for p95/p99, and hard objectives remain separate from regression thresholds. Live gates include approval of an exact two-account budgeted deployment, supervised read-only validation of actual manifests/IAM/native invoice issuance, genuine fourteen-day baseline, one supervised eligible stop and owned restore followed by schedule pause, then genuine post-change observations and finalized native invoice reconciliation. Broader fleet/IaC, Kubernetes/GitOps, Azure/GCP and commercial/production acceptance follow the preserved traceability gates. Fixture acceleration cannot replace financial time, provider proof or customer use. Details are in [dependency safety](dependency-safety.md), [sandbox readiness](sandbox-readiness.md) and [evidence contracts](readiness-evidence.md).
