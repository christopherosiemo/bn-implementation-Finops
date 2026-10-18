# Product scope progress ledger

Recorded 18 October 2026. **Approximately 22% → 23%** of the full product, using **22.2 → 23.4 weighted points** across the preserved 233-section specification, including GA obligations. The original 17.5-point baseline and all credit reviews remain in [progress-ledger.json](progress-ledger.json). Version-1 domain weights are fixed. This is engineering judgement based on accepted capability, not a count of tests, headings or endpoints.

| Domain | Fixed scope weight | Current area maturity | Contribution |
| --- | ---: | ---: | ---: |
| Billing, inventory and telemetry | 18% | 25% | 4.5 points |
| Workload graph, demand and SLO | 12% | 40% | 4.8 points |
| Optimisation, forecasting and commitments | 18% | 5% | 0.9 points |
| Execution, IaC and GitOps | 18% | 15% | 2.7 points |
| Reconciliation and verified savings | 10% | 40% | 4.0 points |
| Identity, tenancy, policy and audit | 10% | 35% | 3.5 points |
| Console, API and enterprise workflows | 6% | 30% | 1.8 points |
| Production operations | 8% | 15% | 1.2 points |
| **Total** | **100%** | | **23.4 points** |

Each domain is broken into acceptance packages. Maturity stages are 0 (absent), 20 (component), 40 (deterministic E2E), 70 (supervised live), 90 (production operations), and 100 (contract complete). The retained baseline package weights reproduce the original 17.5 points; all current credits use 0/20/40 only. Contributions multiply package scope weight by accepted stage. Shared foundations count once. No fixture package receives live credit, and incomplete delivery is never rounded to 100%.

This increment adds 1.2 points by advancing the bounded independent-demand/SLO package from component acceptance to deterministic end-to-end acceptance. Registered machine observations feed immutable objectives and sealed pre-plan evaluations. Hard limits and enabled regression are independent; missing intervals, uncertain histogram bounds and incompatible availability windows block stops. A genuine minute-rollover PostgreSQL test records an owned failure and one notification, preserves restoration through expiry/pause, and retains the latch after later good state. Financial correction tests prevent sibling occurrences or re-verification from reviving the disqualified measurement. Collector, API and browser acceptance connect these components. Native instrumentation, longer SLI distributions, CPU/memory headroom, replica/AZ/RTO/RPO breadth, live and production acceptance earn no credit here. Shared signing, tenancy, console and restoration foundations are not counted again.

The previous graph increment added 1.2 points for bounded workload mapping through immutable reviews and plan binding. Operator review remains a human trust boundary for undiscovered consumers; complete automatic discovery and customer graph validation remain outstanding.

The previous evidence increment added 3.5 points for deterministic native billing ingestion through a current claim, the independent demand component and append-only claim corrections. The real PostgreSQL/Python test exercises provider-shaped delivery, guarded minute receipts, proof-bound execution, exactly £5.16 synthetic savings, replay and native invoice cancellation. Its archive/analytics callbacks and AWS transport are deterministic doubles; separate deployed fixture checks exercise object/analytics persistence, OIDC, Temporal and restart recovery. These checks support bounded engineering credit and do not prove live source delivery.

The delivered foundation is one AWS non-production EC2 scheduling slice with local OIDC, tenant isolation, separated process identities, approvals, signed plans, owned restoration, fixture financial verification and deployment assets. Version-3 native billing/source/activity contracts now have adversarial local test coverage. Source integration code and deployment templates still require customer-environment validation. No AWS deployment, customer verified savings, production SLO, tested customer recovery objective, certification or commercial GA acceptance is recorded.

The domain weights stay fixed in version 1; changing weights requires a separately explained model version rather than retroactive progress. Package maturity can change only when evidence changes. New code does not automatically increase this estimate. The v3 work is not credited as authentic customer history or live operational acceptance. The [acceptance record](acceptance.md) lists what was actually exercised; [traceability](traceability.md) preserves the much broader remaining obligations.

Remaining SLO gates include native instrumentation, broader action/capacity objectives and customer validation; hourly CloudWatch maxima still cannot stand in for p95/p99. The signed SLO regression baseline covers the recent 2–60 minute window and does not establish fourteen-day application distributions or seasonality. Independent fourteen-day financial/workload history remains required. Live gates include approval of an exact two-account budgeted deployment, supervised read-only validation of actual manifests/IAM/native invoice issuance, genuine baseline, one supervised eligible stop and owned restore followed by schedule pause, then genuine post-change observations and finalized native invoice reconciliation. Broader fleet/IaC, Kubernetes/GitOps, Azure/GCP and commercial/production acceptance follow the preserved traceability gates. Fixture acceleration cannot replace financial time, provider proof or customer use. Details are in [SLO safety](slo-safety.md), [dependency safety](dependency-safety.md), [sandbox readiness](sandbox-readiness.md) and [evidence contracts](readiness-evidence.md).
