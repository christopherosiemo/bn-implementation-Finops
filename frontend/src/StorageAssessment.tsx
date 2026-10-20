import { useState } from "react";
import type { components } from "./api.generated";
import type { Recommendation, Resource } from "./types";
import { RemotePage, useRemote } from "./RemoteData";
import { Badge, Button, Modal, Panel, Table, dateTime, readable, shortId, type RunMutation } from "./ui";

type S = components["schemas"];
type Assessment = S["StorageAssessment"];
type Record = S["StorageAssessmentRecord"];
const encode = encodeURIComponent;
const amount = (value: string | null, currency: string | null) => value === null || !currency ? "Unavailable" : `${value} ${currency}`;
const decimal = (value: string | null) => value === null ? "Unavailable" : value;
const utc = (value: string) => { const at = new Date(value); return Number.isNaN(at.getTime()) ? value : new Intl.DateTimeFormat("en-GB", { dateStyle: "medium", timeStyle: "short", timeZone: "UTC" }).format(at); };

export function isStorageResource(resource: Pick<Resource, "resource_type">) {
  return resource.resource_type === "EBS_VOLUME" || resource.resource_type === "EBS_SNAPSHOT";
}

function Reasons({ values }: { values: string[] }) {
  return values.length ? <ul>{values.map(value => <li key={value}>{readable(value)}</li>)}</ul> : null;
}

function Projection({ label, value }: { label: string; value: unknown }) {
  return <details className="plan-operations"><summary>{label}</summary>{value == null
    ? <p>Unavailable</p> : <pre className="evidence-json">{JSON.stringify(value, null, 2)}</pre>}</details>;
}

function Configuration({ label, value }: { label: string; value: S["StorageAssessmentObject"] | null }) {
  if (value == null) return <section><h4>{label}</h4><p>Unavailable</p></section>;
  const entries = Object.entries(value);
  return <section aria-label={label}><h4>{label}</h4>
    <Table scrollLabel={label} headings={["Property", "Observed or selected value"]}>
      {entries.filter(([, item]) => item === null || typeof item !== "object").map(([key, item]) => <tr key={key}><th scope="row">{readable(key)}</th><td style={{ whiteSpace: "normal", overflowWrap: "anywhere", maxWidth: "30rem" }}>{item === null ? "Unavailable" : typeof item === "boolean" ? item ? "Yes" : "No" : String(item)}</td></tr>)}
    </Table>
    {entries.filter(([, item]) => item !== null && typeof item === "object").map(([key, item]) => <Projection key={key} label={readable(key)} value={item} />)}
    {!entries.length && <p>Configuration fields unavailable.</p>}
  </section>;
}

export function StorageAssessmentEvidence({ assessment }: { assessment: Assessment }) {
  const economics = assessment.economics;
  const costs: [string, string | null][] = [
    ["Current hourly cost", economics.current_hourly_cost], ["Current monthly cost", economics.current_monthly_cost],
    ["Candidate hourly cost", economics.candidate_hourly_cost], ["Candidate monthly cost", economics.candidate_monthly_cost],
    ["Estimated monthly saving", economics.estimated_monthly_saving], ["Estimated annual saving", economics.estimated_annual_saving],
  ];
  return <div className="configuration-stack">
    <div className="row-actions"><Badge value={assessment.status} /><span>{readable(assessment.resource_kind)}</span><Badge value="R3">R3 · Read-only proposal</Badge></div>
    <p>{readable(assessment.recommendation_kind)}</p>
    <p className="form-note">This assessment cannot modify, detach, delete, archive or restore storage, create a change plan, or establish verified savings. An unattached volume is not proof that it is disposable. Snapshot dependencies must be resolved before any separate retention decision.</p>
    {assessment.evidence_window ? <><p>Evidence window: {utc(assessment.evidence_window.start)} — {utc(assessment.evidence_window.end)} · UTC, end exclusive</p><p>Observed {assessment.evidence_window.observed_utc_days} / {assessment.evidence_window.required_utc_days ?? "Unknown"} required UTC days · {assessment.evidence_window.observed_hours} / {assessment.evidence_window.expected_hours} hours. No gaps are interpolated.</p></> : <p>Evidence window unavailable.</p>}
    <section aria-label="Storage evidence quality"><h4>Evidence quality: {readable(assessment.confidence.status)}</h4><p className="form-note">An evidence-quality label is not a probability or future performance guarantee.</p><Reasons values={assessment.confidence.reasons} /></section>
    <section aria-label="Storage assessment blockers"><h4>Assessment blockers</h4>{assessment.blockers.length ? <Reasons values={assessment.blockers} /> : <p>No assessment blockers were returned. Storage execution remains disabled.</p>}</section>
    <h4>Observed storage demand</h4>
    <p className="form-note">Statistics retain their native source units and explicit aggregation. Rate percentiles summarize hourly maxima of native-period rates; latency summarizes maxima of native-period operation-weighted means. These are not raw-sample percentiles or a forecast. Missing data is unavailable, including when an observed zero is valid.</p>
    {assessment.metric_distributions.length ? <Table scrollLabel="Storage metric distributions" headings={["Metric / statistic", "Samples / hour coverage", "p50 of period statistic", "p95 of period statistic", "p99 of period statistic", "Maximum"]}>
      {assessment.metric_distributions.map((metric, index) => <tr key={`${metric.metric}:${metric.statistic}:${index}`}>
        <th scope="row" style={{ whiteSpace: "normal", textTransform: "none", letterSpacing: "normal" }}><div style={{ width: "18rem", overflowWrap: "anywhere" }}><strong style={{ display: "block" }}>{metric.metric}</strong><small style={{ display: "block" }}>{metric.unit} · {metric.statistic}</small></div></th>
        <td>{metric.sample_count} / {metric.expected_sample_count ?? "Unavailable"} samples<small>{readable(metric.status)} · {metric.observed_hours} / {metric.expected_hours} hours</small><small>Native samples {decimal(metric.native_sample_count)} / {metric.expected_native_sample_count ?? "Unavailable"}</small><small>Known zero-operation hours: {metric.zero_operation_hours}; undefined latency stays unavailable.</small></td>
        <td>{decimal(metric.p50_of_period_statistics)}</td><td>{decimal(metric.p95_of_period_statistics)}</td><td>{decimal(metric.p99_of_period_statistics)}</td><td>{decimal(metric.maximum)}</td>
      </tr>)}
    </Table> : <p>Metric distributions unavailable.</p>}
    <h4>Current customer costs and candidate estimates</h4>
    <p className="form-note">Source basis: {readable(economics.basis)} · {readable(economics.status)}. Source currencies remain separate. Candidate estimates and potential opportunities are not billed savings or verified savings.</p>
    <Table scrollLabel="Storage assessment economics" headings={["Value", "Source amount"]}>{costs.map(([label, value]) => <tr key={label}><th scope="row">{label}</th><td>{amount(value, economics.currency)}</td></tr>)}<tr><th scope="row">Verified saving</th><td>Unavailable</td></tr></Table>
    <h4>Storage component costs and continuing charges</h4>
    {economics.component_costs.length ? <Table scrollLabel="Storage cost components" headings={["Component / basis", "Actual billed period amount", "Current monthly", "Candidate monthly"]}>
      {economics.component_costs.map((component, index) => <tr key={`${component.component}:${index}`}><th scope="row">{readable(component.component)}<small>{component.unit} · {readable(component.basis)}</small><small>{component.continuing ? "Continuing charge retained" : "Customer effective component rate"}</small></th><td>{amount(component.actual_period_amount, component.currency)}</td><td>{amount(component.current_monthly_cost, component.currency)}</td><td>{amount(component.candidate_monthly_cost, component.currency)}</td></tr>)}
    </Table> : <p>Component prices unavailable. Public list prices have not been substituted.</p>}
    <section aria-label="Storage implementation boundary"><h4>Implementation and ownership</h4><p>Configuration authority: {readable(assessment.configuration_authority)}</p><p>Implementation method: {readable(assessment.implementation_method)}</p><p className="form-note">IaC-managed resources require declarative remediation. This screen does not create a Terraform pull request or execute a native storage modification. GiB reductions require a separate migration with validation, cutover and rollback; they are never an in-place shrink.</p></section>
    <Configuration label="Current storage configuration and attachments" value={assessment.current_configuration} />
    <Configuration label="Candidate storage configuration" value={assessment.candidate_configuration} />
    <section aria-label="Storage checks"><h4>Observed demand and safety checks</h4>{assessment.checks?.length ? <Table scrollLabel="Storage assessment checks" headings={["Dimension / basis", "Status", "Observed demand", "Required with reserve", "Available", "Planning limit"]}>{assessment.checks.map(check => <tr key={check.dimension}><th scope="row">{readable(check.dimension)}<small>{check.unit} · {readable(check.basis)}</small></th><td><Badge value={check.status} /></td><td>{decimal(check.observed_demand)}</td><td>{decimal(check.required_with_reserve)}</td><td>{decimal(check.available)}</td><td>{decimal(check.planning_limit)}</td></tr>)}</Table> : <p>No performance check result was issued for this review.</p>}</section>
    {assessment.unattached_review && <section aria-label="Unattached storage review"><h4>Owner and quarantine review</h4><p>Owner: {assessment.unattached_review.owner ?? "Unknown"} · age: {assessment.unattached_review.age_days === null ? "Unknown" : `${assessment.unattached_review.age_days} days`}</p><p>Prior attachment: {readable(assessment.unattached_review.prior_attachment_context)}</p><p>Backup observed: {assessment.unattached_review.backup_observed === null ? "Unknown" : assessment.unattached_review.backup_observed ? "Yes" : "No"} · quarantine requirement: {assessment.unattached_review.quarantine_days === null ? "Unknown" : `${assessment.unattached_review.quarantine_days} days`}</p><p>Next review: {readable(assessment.unattached_review.next_action)}</p><p>No deletion is recommended or authorized.</p></section>}
    <section aria-label="Snapshot retention review"><h4>Snapshot retention review</h4><p>Policy-required, AMI/restore-dependent and unknown dependencies remain distinct from potentially redundant snapshots. No deletion is authorized.</p>{assessment.snapshot_reviews.length ? <Table scrollLabel="Snapshot dependency and retention findings" headings={["Snapshot / source volume", "Classification / next review", "Age / carrying cost", "Dependencies / blockers"]}>{assessment.snapshot_reviews.map(snapshot => <tr key={snapshot.snapshot_id}><th scope="row">{snapshot.snapshot_id}<small>{snapshot.source_volume_id ?? "Source volume unknown"}</small></th><td><Badge value={snapshot.classification} /><small>{readable(snapshot.next_action)}</small></td><td>{snapshot.age_days === null ? "Age unknown" : `${snapshot.age_days} days`}<small>{amount(snapshot.monthly_carrying_cost, snapshot.currency)}</small></td><td>{snapshot.dependency_state === null ? "Dependency state unknown" : readable(snapshot.dependency_state)}<small>AMI references: {snapshot.ami_ids === null ? "Unknown" : snapshot.ami_ids.length ? snapshot.ami_ids.join(", ") : "None observed in selected evidence"}</small><small>Restore references: {snapshot.restore_references === null ? "Unknown" : snapshot.restore_references.length ? snapshot.restore_references.join(", ") : "None observed in selected evidence"}</small><Reasons values={snapshot.blockers} /></td></tr>)}</Table> : <p>No snapshot review evidence was returned. Absence does not prove that backups or dependencies are unnecessary.</p>}</section>
    {assessment.migration_requirements && <section aria-label="Separate storage migration requirements"><h4>Separate migration opportunity</h4><p>A smaller GiB target requires a new-volume migration. This is not an in-place storage change.</p><ol>{assessment.migration_requirements.map(step => <li key={step}>{readable(step)}</li>)}</ol></section>}
    <section aria-label="Storage model assumptions"><h4>Assessment assumptions</h4><Reasons values={assessment.model_assumptions} /></section>
    <section aria-label="Evaluated storage candidates"><h4>Evaluated candidates and rejections</h4>{assessment.candidates.length ? <Table scrollLabel="Storage candidate rationale" headings={["Candidate / kind", "Status / rationale", "Estimated monthly saving", "Details"]}>{assessment.candidates.map(candidate => <tr key={candidate.id}><th scope="row">{candidate.id}<small>{readable(candidate.recommendation_kind)}</small></th><td><Badge value={candidate.status} /><small>{readable(candidate.decision_code)}</small><Reasons values={candidate.blockers} /></td><td>{amount(candidate.economics.estimated_monthly_saving, candidate.economics.currency)}</td><td><Projection label={`Inspect candidate ${candidate.id}`} value={candidate} /></td></tr>)}</Table> : <p>No candidate was issued. Missing candidate evidence is not a rejected or approved change.</p>}</section>
    <Projection label={`Immutable storage source references (${assessment.source_refs.length})`} value={assessment.source_refs} />
  </div>;
}

function StorageAssessmentDetail({ id }: { id: string }) {
  const [revision, setRevision] = useState(0);
  const state = useRemote<Record>(`/storage-assessments/${encode(id)}`, revision);
  return <section className="configuration-stack" aria-label="Selected storage assessment"><h4>Storage assessment {shortId(id)}</h4>
    {state.loading && <p role="status">Loading storage assessment…</p>}{state.error && <p role="alert">Storage assessment unavailable. {state.error}</p>}
    {state.value && <><p>Requested {dateTime(state.value.created_at)} · resource {state.value.resource_id} · workload {state.value.workload_id ?? "Unowned / unknown"}</p><Badge value={state.value.status} />
      {state.value.current === false && <div role="alert" className="blocker-text"><p>The stored assessment no longer matches current source or configuration evidence. Request a new assessment before relying on its advice.</p><Reasons values={state.value.currentness_blockers ?? []} /></div>}
      {state.value.assessment ? <StorageAssessmentEvidence assessment={state.value.assessment} /> : state.value.status === "QUEUED" || state.value.status === "RUNNING" ? <p role="status">Read-only storage assessment in progress. No result is available yet.</p> : <p role="alert">No storage assessment result is available. Review the source evidence before requesting a new assessment.</p>}
    </>}
    <Button secondary small disabled={state.loading} onClick={() => setRevision(value => value + 1)}>Refresh selected storage assessment</Button>
  </section>;
}

export function StorageAssessmentDialog({ id, onClose }: { id: string; onClose: () => void }) {
  return <Modal title="Storage assessment" subtitle={id} onClose={onClose}><StorageAssessmentDetail id={id} /></Modal>;
}

export function StorageResourceAssessment({ resource, run, busy }: { resource: Resource; run: RunMutation; busy: boolean }) {
  const [selected, setSelected] = useState("");
  const [contextOpen, setContextOpen] = useState(false);
  return <><Badge value="R3">Read-only · R3</Badge><Button secondary small onClick={() => setContextOpen(true)}>Inspect storage {resource.name || resource.provider_resource_id}</Button>
    <Button secondary small pending={busy} onClick={async () => { const body: S["StorageAssessmentRequest"] = { resource_id: resource.id }; const result = await run({ path: "/storage-assessments", body, version: 0, label: "Read-only storage assessment requested" }); if (result?.id) setSelected(result.id); }}>Assess storage {resource.name || resource.provider_resource_id}</Button>
    {contextOpen && <Modal title="Storage resource" subtitle={resource.provider_resource_id} onClose={() => setContextOpen(false)}><p>{readable(resource.resource_type)} · workload {resource.workload_id || "Unowned / unknown"} · configuration authority {readable(resource.configuration_authority)}</p><p className="form-note">Native inventory observations are read-only. Missing attachment, ownership or backup evidence does not imply that storage can be removed.</p><Configuration label="Native storage inventory and attachments" value={resource.storage_configuration ?? null} /><Reasons values={resource.blockers} /></Modal>}
    {selected && <StorageAssessmentDialog id={selected} onClose={() => setSelected("")} />}
  </>;
}

export function StorageAssessmentHistory() {
  const [open, setOpen] = useState(false), [revision, setRevision] = useState(0), [selected, setSelected] = useState("");
  return <Panel title="Storage assessments" eyebrow="EBS VOLUMES & SNAPSHOTS · READ-ONLY"><p>Review persisted demand, customer costs, candidate rejections and retention evidence. Storage changes, deletion and savings verification remain outside this assessment.</p>
    <details onToggle={event => setOpen(event.currentTarget.open)}><summary>Storage assessment history</summary>{open && <div className="configuration-stack"><Button secondary small onClick={() => setRevision(value => value + 1)}>Refresh storage assessment history</Button>
      <RemotePage<Record> key={revision} path="/storage-assessments?limit=10" label="Storage assessments" empty="Select an EBS volume or snapshot in Cloud resources to request a read-only assessment.">{rows => <Table scrollLabel="Persisted storage assessment history" headings={["Request / resource", "Status", "Evidence"]}>{rows.map(row => <tr key={row.id}><td>{shortId(row.id)}<small>{row.resource_id}</small><small>{dateTime(row.created_at)}</small></td><td><Badge value={row.status} /><small>{row.assessment ? readable(row.assessment.recommendation_kind) : "Result unavailable"}</small></td><td><Button secondary small onClick={() => setSelected(row.id)}>Inspect storage assessment {shortId(row.id)}</Button></td></tr>)}</Table>}</RemotePage>
    </div>}</details>{selected && <StorageAssessmentDialog id={selected} onClose={() => setSelected("")} />}
  </Panel>;
}

export function StorageRecommendation({ item }: { item: Recommendation }) {
  const [open, setOpen] = useState(false);
  return <Panel className="recommendation-card"><div className="card-badges"><Badge value={item.status} /><Badge value="R3">R3 · Storage proposal</Badge></div><h2>{item.title}</h2><p>Read-only storage assessment. Storage actions and verified savings are unavailable.</p>{item.reason_code && <p className="blocker-text">{readable(item.reason_code)}</p>}<p>Estimated monthly opportunity: {amount(item.monthly_saving, item.currency ?? null)}</p><Button secondary small disabled={!item.storage_assessment_id} onClick={() => setOpen(true)}>Inspect storage recommendation {shortId(item.id)}</Button>{open && item.storage_assessment_id && <StorageAssessmentDialog id={item.storage_assessment_id} onClose={() => setOpen(false)} />}</Panel>;
}
