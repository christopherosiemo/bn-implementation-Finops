import { RecommendationCurrentness } from "./RecommendationCurrentness";
import { useState } from "react";
import type { components } from "./api.generated";
import type { Recommendation, Resource } from "./types";
import { RemotePage, useRemote } from "./RemoteData";
import { Badge, Button, Modal, Panel, Table, dateTime, readable, shortId, type RunMutation } from "./ui";

type S = components["schemas"];
type Assessment = S["DatabaseAssessment"];
type Record = S["DatabaseAssessmentRecord"];
type ObjectValue = S["DatabaseAssessmentObject"];
const encode = encodeURIComponent;
const utcTime = (value: string) => { const at = new Date(value); return Number.isNaN(at.getTime()) ? value : new Intl.DateTimeFormat("en-GB", { dateStyle: "medium", timeStyle: "short", timeZone: "UTC" }).format(at); };
const amount = (value: string | null, currency: string | null) => value === null || !currency ? "Unavailable" : `${value} ${currency}`;
const decimal = (value: string | null) => value === null ? "Unavailable" : value;

export function isDatabaseResource(resource: Pick<Resource, "resource_type">) {
  return resource.resource_type === "RDS_INSTANCE" || resource.resource_type === "RDS_CLUSTER";
}

function Reasons({ values }: { values: string[] }) {
  return values.length ? <ul>{values.map(value => <li key={value}>{readable(value)}</li>)}</ul> : null;
}

function Projection({ label, value }: { label: string; value: ObjectValue | null }) {
  return <details className="plan-operations"><summary>{label}</summary>{value === null
    ? <p>Unavailable</p>
    : <pre className="evidence-json">{JSON.stringify(value, null, 2)}</pre>}</details>;
}

export function DatabaseAssessmentEvidence({ assessment }: { assessment: Assessment }) {
  const economics = assessment.economics;
  const costs: [string, string | null][] = [
    ["Current hourly cost", economics.current_hourly_cost],
    ["Current monthly cost", economics.current_monthly_cost],
    ["Candidate hourly cost", economics.candidate_hourly_cost],
    ["Candidate monthly cost", economics.candidate_monthly_cost],
    ["Estimated monthly saving", economics.estimated_monthly_saving],
    ["Estimated annual saving", economics.estimated_annual_saving],
  ];
  return <div className="configuration-stack">
    <div className="row-actions"><Badge value={assessment.status} /><span>{readable(assessment.resource_kind)} · {assessment.engine || "Engine unavailable"}</span><Badge value="R3">R3 · Read-only proposal</Badge></div>
    <p className="form-note">Database changes require separate engineering review. This assessment cannot create a change plan, execute a database operation, or establish verified savings.</p>
    <p>{readable(assessment.recommendation_kind)}</p>
    {assessment.evidence_window ? <p>Evidence window: {utcTime(assessment.evidence_window.start)} — {utcTime(assessment.evidence_window.end)} · UTC, end exclusive</p> : <p>Evidence window unavailable.</p>}
    <section aria-label="Database evidence quality">
      <h4>Evidence quality: {readable(assessment.confidence.status)}</h4>
      <p className="form-note">This label describes evidence quality; it is not a probability or a guarantee.</p>
      {assessment.confidence.meaning && <p>{readable(assessment.confidence.meaning)}</p>}
      <Reasons values={assessment.confidence.reasons} />
    </section>
    <section aria-label="Database assessment blockers">
      <h4>Assessment blockers</h4>
      {assessment.blockers.length ? <Reasons values={assessment.blockers} /> : <p>No assessment blockers were returned. Execution remains disabled.</p>}
    </section>
    <h4>Observed metric distributions</h4>
    <p className="form-note">Each row summarizes hourly source statistics. Average and Maximum are separate observations; these percentiles describe hourly statistics, not individual one-minute samples. Freeable memory in bytes is not memory utilization; an observed zero is distinct from unavailable data.</p>
    {assessment.metric_distributions.length ? <Table scrollLabel="Database metric distributions" headings={["Metric / native statistic", "Samples / hour coverage", "p50 of period statistic", "p95 of period statistic", "p99 of period statistic", "Maximum"]}>
      {assessment.metric_distributions.map((metric, index) => <tr key={`${metric.metric}:${metric.statistic}:${metric.member_id}:${index}`}>
        <th scope="row" style={{ whiteSpace: "normal", textTransform: "none", letterSpacing: "normal" }}>
          <div style={{ width: "18rem", maxWidth: "18rem", overflowWrap: "anywhere" }}>
            <strong style={{ display: "block" }}>{metric.metric}</strong>
            <small style={{ display: "block" }}>{metric.unit} · {metric.statistic}</small>
            {metric.member_id && <small className="evidence-id" style={{ display: "block" }}>Member {metric.member_id}</small>}
          </div>
        </th>
        <td>{metric.sample_count} / {metric.expected_sample_count ?? "Unavailable"} samples<small>{readable(metric.status)} · {metric.observed_hours} / {metric.expected_hours} hours</small><small>Native samples {decimal(metric.native_sample_count)} / {metric.expected_native_sample_count ?? "Unavailable"}</small></td>
        <td>{decimal(metric.p50_of_period_statistics)}</td><td>{decimal(metric.p95_of_period_statistics)}</td><td>{decimal(metric.p99_of_period_statistics)}</td><td>{decimal(metric.maximum)}</td>
      </tr>)}
    </Table> : <p>Metric distributions unavailable.</p>}
    <h4>Current and candidate economics</h4>
    <p className="form-note">Source basis: {readable(economics.basis)}. Values remain separated by source currency. Estimated opportunities are not verified savings.</p>
    <Table scrollLabel="Database assessment economics" headings={["Value", "Source amount"]}>
      {costs.map(([label, value]) => <tr key={label}><th scope="row">{label}</th><td>{amount(value, economics.currency)}</td></tr>)}
      <tr><th scope="row">Verified saving</th><td>Unavailable</td></tr>
    </Table>
    {assessment.model_assumptions && <section aria-label="Database model assumptions"><h4>Model assumptions</h4><Reasons values={assessment.model_assumptions} /></section>}
    {assessment.unsupported_opportunities && <section aria-label="Unsupported database changes"><h4>Unsupported database changes</h4><Reasons values={assessment.unsupported_opportunities} /></section>}
    {assessment.provider_comparison && <section aria-label="Compute Optimizer comparison">
      <h4>AWS Compute Optimizer comparison</h4>
      <p>Comparison: {readable(assessment.provider_comparison.difference)}</p>
      <p>{assessment.provider_comparison.reason_for_difference}</p>
      <p className="form-note">Provider recommendations retain their native evidence. Comparable options and prices must be established before a match or difference can be concluded.</p>
      <Projection label="Our read-only recommendation" value={assessment.provider_comparison.our_recommendation} />
      <details className="plan-operations"><summary>Native provider recommendations</summary>
        {assessment.provider_comparison.provider_recommendation === null ? <p>Unavailable</p>
          : <pre className="evidence-json">{JSON.stringify(assessment.provider_comparison.provider_recommendation, null, 2)}</pre>}
      </details>
    </section>}
    <Projection label="Current database configuration" value={assessment.current_configuration} />
    <Projection label="Candidate database configuration" value={assessment.candidate_configuration} />
    <details className="plan-operations"><summary>Evaluated database candidates ({assessment.candidates.length})</summary>
      {assessment.candidates.length ? assessment.candidates.map((candidate, index) => <pre className="evidence-json" key={index}>{JSON.stringify(candidate, null, 2)}</pre>) : <p>No candidate configuration was issued.</p>}
    </details>
    <details className="plan-operations"><summary>Immutable database source references ({assessment.source_refs.length})</summary>
      {assessment.source_refs.length ? assessment.source_refs.map((ref, index) => <pre className="evidence-json" key={index}>{JSON.stringify(ref, null, 2)}</pre>) : <p>Source references unavailable.</p>}
    </details>
  </div>;
}

function DatabaseAssessmentDetail({ id }: { id: string }) {
  const [revision, setRevision] = useState(0);
  const state = useRemote<Record>(`/database-assessments/${encode(id)}`, revision);
  return <section className="configuration-stack" aria-label="Selected database assessment">
    <h4>Database assessment {shortId(id)}</h4>
    {state.loading && <p role="status">Loading database assessment…</p>}
    {state.error && <p role="alert">Database assessment unavailable. {state.error}</p>}
    {state.value && <>
      <p>Requested {dateTime(state.value.created_at)} · resource {state.value.resource_id}</p>
      <Badge value={state.value.currentness?.status ?? state.value.status} /><RecommendationCurrentness value={state.value.currentness} historicalStatus={state.value.historical_status ?? state.value.status} />
      {state.value.current === false && <div role="alert" className="blocker-text"><p>The stored assessment no longer matches current source or configuration evidence. Request a new assessment before relying on its advice.</p><Reasons values={state.value.currentness_blockers ?? []} /></div>}
      {state.value.assessment ? <DatabaseAssessmentEvidence assessment={state.value.assessment} />
        : state.value.status === "QUEUED" || state.value.status === "RUNNING" ? <p role="status">Read-only assessment in progress. No result is available yet.</p>
          : <p role="alert">No assessment result is available. Review the source evidence before requesting a new assessment.</p>}
    </>}
    <Button secondary small disabled={state.loading} onClick={() => setRevision(value => value + 1)}>Refresh selected database assessment</Button>
  </section>;
}

export function DatabaseAssessmentDialog({ id, onClose }: { id: string; onClose: () => void }) {
  return <Modal title="Database assessment" subtitle={id} onClose={onClose}><DatabaseAssessmentDetail id={id} /></Modal>;
}

export function DatabaseResourceAssessment({ resource, run, busy }: { resource: Resource; run: RunMutation; busy: boolean }) {
  const [selected, setSelected] = useState("");
  return <>
    <Badge value="R3">Read-only · R3</Badge>
    <Button secondary small pending={busy} onClick={async () => {
      const body: S["DatabaseAssessmentRequest"] = { resource_id: resource.id };
      const result = await run({ path: "/database-assessments", body, version: 0, label: "Read-only database assessment requested" });
      if (result?.id) setSelected(result.id);
    }}>Assess database {resource.name || resource.provider_resource_id}</Button>
    {selected && <DatabaseAssessmentDialog id={selected} onClose={() => setSelected("")} />}
  </>;
}

export function DatabaseAssessmentHistory() {
  const [open, setOpen] = useState(false);
  const [revision, setRevision] = useState(0);
  const [selected, setSelected] = useState("");
  return <Panel title="Database assessments" eyebrow="RDS & AURORA · READ-ONLY">
    <p>Review persisted database evidence and R3 proposals. Database changes and savings verification are outside this assessment.</p>
    <details onToggle={event => setOpen(event.currentTarget.open)}><summary>Database assessment history</summary>
      {open && <div className="configuration-stack">
        <Button secondary small onClick={() => setRevision(value => value + 1)}>Refresh database assessment history</Button>
        <RemotePage<Record> key={revision} path="/database-assessments?limit=10" label="Database assessments" empty="Select an RDS instance or cluster in Cloud resources to request a read-only assessment.">
          {rows => <Table scrollLabel="Persisted database assessment history" headings={["Request / resource", "Status", "Evidence"]}>{rows.map(row => <tr key={row.id}>
            <td>{shortId(row.id)}<small>{row.resource_id}</small><small>{dateTime(row.created_at)}</small></td>
            <td><Badge value={row.status} /><small>{row.assessment ? readable(row.assessment.recommendation_kind) : "Result unavailable"}</small></td>
            <td><Button secondary small onClick={() => setSelected(row.id)}>Inspect database assessment {shortId(row.id)}</Button></td>
          </tr>)}</Table>}
        </RemotePage>
      </div>}
    </details>
    {selected && <DatabaseAssessmentDialog id={selected} onClose={() => setSelected("")} />}
  </Panel>;
}

export function DatabaseRecommendation({ item }: { item: Recommendation }) {
  const [open, setOpen] = useState(false);
  return <Panel className="recommendation-card">
    <div className="card-badges"><Badge value={item.currentness?.status ?? item.status} /><Badge value="R3">R3 · Database proposal</Badge></div>
    <h2>{item.title}</h2><RecommendationCurrentness value={item.currentness} historicalStatus={item.historical_status ?? item.status} />
    <p>Read-only database assessment. Execution and verified savings are unavailable.</p>
    {item.reason_code && <p className="blocker-text">{readable(item.reason_code)}</p>}
    <p>Estimated monthly opportunity: {amount(item.monthly_saving, item.currency ?? null)}</p>
    <Button secondary small disabled={!item.database_assessment_id} onClick={() => setOpen(true)}>Inspect database recommendation {shortId(item.id)}</Button>
    {open && item.database_assessment_id && <DatabaseAssessmentDialog id={item.database_assessment_id} onClose={() => setOpen(false)} />}
  </Panel>;
}

function CoverageContent() {
  const [revision, setRevision] = useState(0);
  const state = useRemote<S["AssessmentCoverage"]>("/coverage", revision);
  return <div className="configuration-stack">
    {state.loading && <p role="status">Loading assessment coverage…</p>}
    {state.error && <p role="alert">Assessment coverage unavailable. {state.error}</p>}
    {state.value && <>
      <p>{utcTime(state.value.period.start)} — {utcTime(state.value.period.end)} · UTC, end exclusive</p>
      <p className="form-note">Coverage uses all-AWS positive billed charges, separated by currency. Credits and net spend are shown separately. Unallocated and unowned amounts are attribution overlays, not additional spend. A null percentage is unknown, including when a denominator cannot establish coverage; it is not zero coverage or savings.</p>
      <Reasons values={state.value.blockers} />
      {state.value.groups.length ? <Table scrollLabel="All AWS assessment spend coverage" headings={["Currency / completeness", "Detected", "Analysed", "Observation only", "Blocked", "Unsupported", "Unallocated", "Unowned", "Credits", "Net", "Analysed %"]}>
        {state.value.groups.map((group, index) => <tr key={`${group.currency}:${index}`}>
          <th scope="row">{group.currency ?? "Currency unavailable"}<small>{group.complete ? "Complete billing window" : "Incomplete billing window"}</small><small>{group.basis}</small></th>
          {[group.detected_spend, group.analysed_spend, group.observation_only_spend, group.blocked_spend, group.unsupported_spend, group.unallocated_spend ?? null, group.unowned_spend ?? null, group.credits, group.net_spend].map((value, column) => <td key={column}>{amount(value, group.currency)}</td>)}
          <td>{group.analysed_percent === null ? "Unavailable" : `${group.analysed_percent}%`}</td>
        </tr>)}
      </Table> : <p>Spend coverage unavailable. No currency groups were returned.</p>}
      {state.value.service_groups && <section aria-label="AWS service spend coverage"><h4>Coverage by AWS service</h4><p className="form-note">These exclusive service partitions sum to the all-AWS source charges above. Unowned resources, missing identifiers, unsupported services and credits remain visible. ECS tasks and EKS nodes do not duplicate their underlying EC2 costs. Inventory is observation coverage; it does not establish analysed economics.</p>{state.value.service_groups.length ? <Table scrollLabel="AWS service spend partitions" headings={["Service / currency", "Detected", "Analysed", "Observation only", "Blocked", "Unsupported", "Credits", "Net", "Analysed %"]}>{state.value.service_groups.flatMap(service => service.groups.map((group, index) => <tr key={`${service.service}:${group.currency}:${index}`}><th scope="row">{service.service || "Unknown service"}<small>{group.currency ?? "Currency unavailable"} · {group.complete ? "Complete billing window" : "Incomplete billing window"}</small></th>{[group.detected_spend, group.analysed_spend, group.observation_only_spend, group.blocked_spend, group.unsupported_spend, group.credits, group.net_spend].map((value, column) => <td key={column}>{amount(value, group.currency)}</td>)}<td>{group.analysed_percent === null ? "Unavailable" : `${group.analysed_percent}%`}</td></tr>))}</Table> : <p>Service-level spend coverage unavailable.</p>}</section>}
      {state.value.object_storage_groups && <section aria-label="S3 object-storage spend coverage"><h4>S3 object-storage coverage</h4><p className="form-note">These S3 amounts are included in the all-AWS totals above. Unowned buckets, missing identifiers, unpriced access and unsupported storage remain in detected spend; a prefix assessment cannot establish complete bucket economics.</p>
        {state.value.object_storage_groups.length ? <Table scrollLabel="S3 assessment spend coverage" headings={["Currency / completeness", "Detected", "Analysed", "Observation only", "Blocked", "Unsupported", "Credits", "Net", "Analysed %"]}>{state.value.object_storage_groups.map((group, index) => <tr key={`${group.currency}:${index}`}><th scope="row">{group.currency ?? "Currency unavailable"}<small>{group.complete ? "Complete billing window" : "Incomplete billing window"}</small></th>{[group.detected_spend, group.analysed_spend, group.observation_only_spend, group.blocked_spend, group.unsupported_spend, group.credits, group.net_spend].map((value, column) => <td key={column}>{amount(value, group.currency)}</td>)}<td>{group.analysed_percent === null ? "Unavailable" : `${group.analysed_percent}%`}</td></tr>)}</Table> : <p>S3 spend coverage unavailable. No currency groups were returned.</p>}
      </section>}
      {state.value.lambda_groups && <section aria-label="Lambda spend coverage"><h4>Lambda coverage</h4><p className="form-note">All Lambda spend remains in the all-AWS denominator, including unsupported models, high-memory, arm64, low-invocation, unowned and unidentified charges. A qualifier assessment covers only its evidenced native billing components.</p>{state.value.lambda_groups.length ? <Table scrollLabel="Lambda assessment spend coverage" headings={["Currency / completeness", "Detected", "Analysed", "Observation only", "Blocked", "Unsupported", "Credits", "Net", "Analysed %"]}>{state.value.lambda_groups.map((group, index) => <tr key={String(group.currency) + ":" + index}><th scope="row">{group.currency ?? "Currency unavailable"}<small>{group.complete ? "Complete billing window" : "Incomplete billing window"}</small></th>{[group.detected_spend, group.analysed_spend, group.observation_only_spend, group.blocked_spend, group.unsupported_spend, group.credits, group.net_spend].map((value, column) => <td key={column}>{amount(value, group.currency)}</td>)}<td>{group.analysed_percent === null ? "Unavailable" : group.analysed_percent + "%"}</td></tr>)}</Table> : <p>Lambda spend coverage unavailable.</p>}</section>}
      {state.value.network_groups && <section aria-label="Network spend coverage"><h4>Network coverage</h4><p className="form-note">Network costs remain included in the all-AWS denominator. Unallocated transfer, NAT and public-IP charges remain detected spend. Analysed component economics require current topology, native billing and defensible traffic attribution; one cohort does not promote an entire network resource to analysed.</p>
        {state.value.network_groups.length ? <Table scrollLabel="Network assessment spend coverage" headings={["Currency / completeness", "Detected", "Analysed", "Observation only", "Blocked", "Unsupported", "Credits", "Net", "Analysed %"]}>{state.value.network_groups.map((group, index) => <tr key={`${group.currency}:${index}`}><th scope="row">{group.currency ?? "Currency unavailable"}<small>{group.complete ? "Complete billing window" : "Incomplete billing window"}</small></th>{[group.detected_spend, group.analysed_spend, group.observation_only_spend, group.blocked_spend, group.unsupported_spend, group.credits, group.net_spend].map((value, column) => <td key={column}>{amount(value, group.currency)}</td>)}<td>{group.analysed_percent === null ? "Unavailable" : `${group.analysed_percent}%`}</td></tr>)}</Table> : <p>Network spend coverage unavailable. No currency groups were returned.</p>}
      </section>}
      {state.value.network_component_groups?.length ? <section aria-label="Network component coverage"><h4>Network cost components</h4><p className="form-note">Component amounts partition network coverage above. Unsupported dimensions remain explicit, and credits preserve their signed values.</p><Table scrollLabel="Network component spend coverage" headings={["Component / currency", "Detected", "Analysed", "Observation only", "Blocked", "Unsupported", "Credits", "Net"]}>{state.value.network_component_groups.flatMap(component => component.groups.map((group, index) => <tr key={`${component.component}:${group.currency}:${index}`}><th scope="row">{readable(component.component)}<small>{group.currency ?? "Currency unavailable"}</small></th>{[group.detected_spend, group.analysed_spend, group.observation_only_spend, group.blocked_spend, group.unsupported_spend, group.credits, group.net_spend].map((value, column) => <td key={column}>{amount(value, group.currency)}</td>)}</tr>))}</Table></section> : null}
    </>}
    <Button secondary small disabled={state.loading} onClick={() => setRevision(value => value + 1)}>Refresh assessment coverage</Button>
  </div>;
}

export function DatabaseCoverage() {
  const [open, setOpen] = useState(false);
  return <Panel title="Assessment coverage" eyebrow="ALL AWS BILLED SPEND">
    <details onToggle={event => setOpen(event.currentTarget.open)}><summary>Inspect assessed and unsupported spend</summary>{open && <CoverageContent />}</details>
  </Panel>;
}
