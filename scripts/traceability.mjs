import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const source = readFileSync(path.join(root, 'docs/product-specification.md'), 'utf8');
const found = [...source.matchAll(/^# (\d+)\. (.+)\r?$/gm)];
const sections = []; let expected = 1;
for (const match of found) if (Number(match[1]) === expected) { sections.push({ id: expected++, title: match[2].trim() }); }
if (sections.length !== 233) throw new Error(`Expected 233 normative sections, found ${sections.length}`);
const between = (id, a, b) => id >= a && id <= b;
const nativeCoverage = {
  41: 'Registered Prometheus range-vector reads and machine OTLP/HTTP preserve native timestamps, temporality, units and immutable object/ClickHouse provenance. See docs/native-telemetry.md; streaming above explicit bounds and customer instrumentation remain gated.',
  42: 'Native metric definitions and bounded capacity input preserve missing CPU/memory/network/storage evidence as blockers. Provider hardware and contracted candidate-price catalogues are not yet connected.',
  43: 'Native request/error counters and histogram bounds have connected local instrumentation acceptance. Historical queries cannot backfill guarded minute activity/SLO receipts; broader customer SLIs remain gated.',
  46: 'Versioned workload requirements distinguish spare-capacity fractions from additive forecast reserve. Candidate capacity and recovery evidence are required independently; declaring a profile does not authorize execution.',
  47: 'Bounded capacity components preserve distributions, p95/p99 peaks and independent saturation guards. Wider resource metrics and native candidate-catalogue integration remain gated.',
  48: 'Native evaluation requires fourteen complete non-production days, thirty production-analysis days and ninety seasonal days from actual observations. Dense populations above explicit limits remain unavailable pending streaming evaluation.',
  49: 'Explainable weekday/hour forecasts, rolling backtests and prediction intervals have component acceptance. Unsupported horizons and uncalibrated breach probabilities remain unavailable; production forecast acceptance is outstanding.',
  50: 'Versioned demand events and explicit timezone requirements feed bounded capacity components. Customer calendars, genuine history and calibrated seasonal acceptance remain outstanding.',
  51: 'Versioned maintenance and recurring/absolute blackout requirements have calendar/DST acceptance. Runtime action-specific recovery and customer approval remain separate gates.',
};
function gate(id) {
  if (nativeCoverage[id]) return ['M2 native evidence / M3 capacity gates', nativeCoverage[id]];
  if ([62,63,156,157,205,206,209].includes(id)) return ['M3 — Fleet/IaC components; runtime acceptance gated', 'Separate signed FleetPlanV4, exact saved-plan validation, workload-wide disruption reservations and machine deployment receipts have component acceptance. Configuration declarations remain not attested; the v4 workflow is not enabled. Full-window health factories, customer pipeline, rollback and financial end-to-end acceptance remain required. See docs/fleet-and-kubernetes-components.md.'];
  if ([65,67,68,69,71,72,73,158,207,208].includes(id)) return ['M4 — Local Kubernetes components; hosted acceptance gated', 'Native read-only inventory/safety and a real isolated local Kubernetes lab cover exact Git revision rollout, explicit PDB blocking, failed readiness/owned Git rollback and HPA cost-growth simulation. The local controller is a labelled test double; hosted Argo/Flux execution, node economics and verified savings remain required. See docs/fleet-and-kubernetes-components.md.'];
  if ([24,28,29,30,31,32,33,170,171].includes(id)) return ['M5 — Provisional native read components; parity gated', 'Azure actual/amortized/FOCUS export and GCP detailed/pricing/spend-CUD read adapters plus native inventory/metrics have provider-shaped component acceptance. Snapshots remain provisional with unknown coverage, null unknown costs and no execution/savings authority. Credential commissioning, immutable publication, native invoices/complete commitments and complete onboarding-to-verification parity remain required. See internal/multicloud/README.md and INVENTORY_METRICS.md.'];
  if (between(id,65,73) || [207,208].includes(id)) return ['M4 — Kubernetes', 'Requests/HPA/VPA/node economics, GitOps rollout and PDB safety.'];
  if (between(id,58,64) || between(id,156,158) || [202,203,204,205,206,209,219].includes(id)) return ['M3 — Fleet/IaC', 'Stateless fleet rightsizing, Terraform pipeline, canary and rollback; no production mutation in M2.'];
  if ([36,82,83,84,90,92,124,125,126,127,128,129,130,142,153,154,155,160,163,166,167,178,181,182,198,199].includes(id) || between(id,74,92)) return ['M6 / Release 2–3', 'GA recommendations and required controls before commercial GA; deeper execution follows Releases 2–3.'];
  if (between(id,25,27) || between(id,34,57) || between(id,93,123) || between(id,131,151) || [152,169,172,173,184,185,187,189,190,200,201,210,211,212,213,214,215,216,217,220,221,222].includes(id)) return ['M2 — AWS scheduling pilot', 'Implement and validate for explicitly delegated non-production EC2 scheduling; broader resource/action coverage stays gated.'];
  if (between(id,159,176) || between(id,177,195) || between(id,223,233) || between(id,1,23) || [196,197,218].includes(id)) return ['M1/M2 foundation + GA gate', 'Pilot applies the principle/contracts; GA breadth, scale and operational SLO claims require later evidence.'];
  return ['Commercial GA gate', 'Retained normative requirement; not satisfied by a fixture demonstration alone.'];
}
const rows = sections.map(s => { const [milestone, coverage] = gate(s.id); return `| ${s.id} | ${s.title.replaceAll('|','\\|')} | ${milestone} | ${coverage} |`; });
const output = `# Specification traceability\n\nGenerated by \`node scripts/traceability.mjs\` from the preserved user specification. Every section is retained; this is a delivery-gate map, not a declaration that all GA requirements are implemented.\n\n- **M1:** contracts, tenancy/identity, separate execution identities, persistence and local tooling.\n- **M2:** complete AWS non-production scheduling loop and fixture acceptance.\n- **M3:** stateless compute fleets and Terraform execution.\n- **M4:** Kubernetes/GitOps and node economics.\n- **M5:** Azure and Google Cloud parity.\n- **M6:** remaining commercial GA features, enterprise integrations, scale, resilience and release validation.\n- **Release 2–3:** deeper action automation and customer-hosted executors as stated in the original specification.\n\nThe original text remains in [product-specification.md](product-specification.md). Apply documented arithmetic/safety errata in [decisions.md](decisions.md). Acceptance evidence and known limits are recorded in [acceptance.md](acceptance.md). The versioned [progress ledger](progress-ledger.md) counts accepted capability once against fixed full-product weights.\n\n| Section | Requirement | Delivery gate | Pilot coverage / outstanding obligation |\n| --- | --- | --- | --- |\n${rows.join('\n')}\n`;
const target = path.join(root, 'docs/traceability.md');
if (process.argv.includes('--check')) {
  if (readFileSync(target,'utf8') !== output) throw new Error('Traceability is stale; run node scripts/traceability.mjs');
  console.log('All 233 specification sections have delivery gates.');
} else { writeFileSync(target,output); console.log('Wrote delivery gates for all 233 specification sections.'); }
