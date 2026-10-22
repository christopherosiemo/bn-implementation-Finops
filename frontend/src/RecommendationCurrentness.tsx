import type { components } from "./api.generated";
import { Badge, dateTime, readable } from "./ui";

type Currentness = components["schemas"]["RecommendationCurrentness"];

export function RecommendationCurrentness({ value, historicalStatus }: { value?: Currentness; historicalStatus?: string }) {
  if (!value) return null;
  const current = value.status === "CURRENT";
  return <section className="configuration-stack" aria-label="Recommendation currentness" data-currentness={value.status}>
    <div className="row-actions"><Badge value={value.status} /><span>Checked {dateTime(value.checked_at)}</span></div>
    {historicalStatus && <p>Historical result: {readable(historicalStatus)}. The stored result is preserved.</p>}
    {value.context_version?.startsWith("LEGACY") && <p>Legacy evidence references remain visible. A fresh assessment is required wherever historical ownership, policy or other assumptions cannot be established.</p>}
    {!current && <p className="blocker-text">This recommendation is unavailable as a current validated opportunity. Execution readiness is blocked.</p>}
    {value.reason_codes.length > 0 && <ul>{value.reason_codes.map(reason => <li key={reason}>{readable(reason)}</li>)}</ul>}
    {value.changes.length > 0 && <dl className="definition-list">{value.changes.map((change, index) => <div key={`${change.dimension}:${change.reason_code}:${index}`}>
      <dt>{readable(change.dimension)}</dt><dd>{readable(change.reason_code)}{change.detected_at && <small>Detected {dateTime(change.detected_at)}</small>}</dd>
    </div>)}</dl>}
    {value.economics_recompute && <p>Recompute economics. Amounts in the retained result describe historical assumptions and must not be used as current savings estimates.</p>}
    {value.telemetry_recollect && <p>Recollect or revalidate telemetry before another assessment.</p>}
    {value.iac_changed && <p>Review the configured repository revision and reanalyse the declarative configuration.</p>}
    {!current && <p>Next action: {readable(value.next_action)}</p>}
  </section>;
}
