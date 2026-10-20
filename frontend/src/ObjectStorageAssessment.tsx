import { useState, type FormEvent } from "react";
import type { components } from "./api.generated";
import type { Recommendation, Resource } from "./types";
import { RemotePage, useRemote } from "./RemoteData";
import { Badge, Button, Modal, Panel, Table, dateTime, readable, shortId, type RunMutation } from "./ui";

type S = components["schemas"];
type Dataset = S["ObjectStorageDataset"];
type DatasetPolicy = S["ObjectStorageDatasetPolicy"];
type Assessment = S["ObjectStorageAssessment"];
type AssessmentRecord = S["ObjectStorageAssessmentRecord"];
const encode = encodeURIComponent;
const amount = (value: string | null | undefined, currency: string | null | undefined) => value == null || !currency ? "Unavailable" : `${value} ${currency}`;
const exact = (value: string | number | null | undefined) => value == null ? "Unavailable" : String(value);

export function isObjectStorageResource(resource: Pick<Resource, "resource_type">) {
  return resource.resource_type === "S3_BUCKET";
}

function Reasons({ values }: { values: string[] }) {
  return values.length ? <ul>{values.map(value => <li key={value}>{readable(value)}</li>)}</ul> : null;
}

function EvidenceProjection({ label, value }: { label: string; value: unknown }) {
  return <details className="plan-operations"><summary>{label}</summary>{value == null ? <p>Unavailable</p> : <pre className="evidence-json">{JSON.stringify(value, null, 2)}</pre>}</details>;
}

export function ObjectStorageConfiguration({ configuration }: { configuration: S["ObjectStorageConfiguration"] | null }) {
  if (!configuration) return <p>Native bucket configuration unavailable.</p>;
  return <section aria-label="S3 bucket configuration"><h4>Native bucket configuration</h4>
    <dl className="definition-list">
      <div><dt>Bucket</dt><dd>{configuration.name}</dd></div><div><dt>Account / region</dt><dd>{configuration.account_id} · {configuration.region}</dd></div>
      <div><dt>Observed</dt><dd>{dateTime(configuration.observed_at)}</dd></div><div><dt>Created</dt><dd>{configuration.created_at ? dateTime(configuration.created_at) : "Unavailable"}</dd></div>
    </dl>
    <p className="form-note">A denied or unsupported read remains unknown. An absent lifecycle or retention configuration is shown only when AWS supplied an authoritative absence response.</p>
    <Table scrollLabel="S3 native configuration read states" headings={["Configuration", "Read state", "Evidence"]}>
      {Object.entries(configuration.configurations).map(([name, observation]) => <tr key={name}>
        <th scope="row">{readable(name)}</th><td><Badge value={observation.status} />{observation.reason_code && <small>{readable(observation.reason_code)}</small>}</td>
        <td><EvidenceProjection label={`Inspect ${readable(name).toLowerCase()} evidence`} value={observation.value} /></td>
      </tr>)}
    </Table>
    <EvidenceProjection label="Bucket tags" value={configuration.tags ?? null} />
  </section>;
}

function DatasetForm({ resource, latest, run, busy, onClose, onSaved }: { resource: Resource; latest?: Dataset; run: RunMutation; busy: boolean; onClose: () => void; onSaved: () => void }) {
  const [name, setName] = useState(latest?.name ?? "");
  const [kind, setKind] = useState<S["ObjectStorageDatasetSelector"]["kind"]>(latest?.selector.kind ?? "BUCKET");
  const [prefix, setPrefix] = useState(latest?.selector.prefix ?? "");
  const [tags, setTags] = useState(Object.entries(latest?.selector.tags ?? {}).map(([key, value]) => `${key}=${value}`).join("\n"));
  const [workloadID, setWorkloadID] = useState(latest?.selector.workload_id ?? resource.workload_id ?? "");
  const [classes, setClasses] = useState((latest?.selector.storage_classes ?? []).join(", "));
  const [policy, setPolicy] = useState<DatasetPolicy>(latest?.policy ?? { criticality: resource.environment === "NON_PRODUCTION" ? "NON_PRODUCTION" : "TIER_3", high_seasonality: false, remaining_lifetime_days: null, rto_seconds: null, retention_known: false, compliance_clear: false, recovery_known: false, allow_onezone: null, dependencies_reviewed: null });
  const [error, setError] = useState("");
  const save = async (event: FormEvent) => {
    event.preventDefault(); setError("");
    const selector: S["ObjectStorageDatasetSelector"] = { kind };
    if (kind === "PREFIX") selector.prefix = prefix;
    if (kind === "WORKLOAD_DATASET") selector.workload_id = workloadID;
    if (kind === "STORAGE_POLICY") selector.storage_classes = classes.split(",").map(value => value.trim()).filter(Boolean);
    if (kind === "TAG_GROUP") {
      const entries = tags.split(/\r?\n/).filter(value => value.trim());
      if (!entries.length || entries.some(value => value.indexOf("=") < 1)) { setError("Enter at least one object tag as key=value, one per line."); return; }
      const parsed = entries.map(value => [value.slice(0, value.indexOf("=")).trim(), value.slice(value.indexOf("=") + 1)]);
      if (new Set(parsed.map(([key]) => key)).size !== parsed.length) { setError("Each object tag key must appear once."); return; }
      selector.tags = Object.fromEntries(parsed);
    }
    const body: S["ObjectStorageDatasetRequest"] = { resource_id: resource.id, name, selector, policy };
    const result = await run({ path: latest ? `/object-storage-datasets/${encode(latest.id)}/revisions` : "/object-storage-datasets", body, version: latest?.version ?? 0, label: "S3 dataset requirements saved; native evidence is still required" });
    if (result) onSaved(); else setError("The dataset was not saved. Review the API error and refresh before retrying a changed revision.");
  };
  return <Modal title={latest ? "Revise S3 dataset" : "Declare S3 dataset"} subtitle={resource.name || resource.provider_resource_id} onClose={onClose}>
    <form className="configuration-stack" onSubmit={save}>
      <p className="form-note">Declare the dataset and business requirements. The service selects native object, access and billing evidence independently. These declarations cannot establish coldness, remove legal retention, or authorize a storage change.</p>
      <div className="form-grid">
        <label className="field full-width"><span>Dataset name</span><input required maxLength={200} value={name} onChange={event => setName(event.target.value)} /></label>
        <label className="field"><span>Dataset selection</span><select value={kind} onChange={event => setKind(event.target.value as typeof kind)}>{(["BUCKET", "PREFIX", "TAG_GROUP", "WORKLOAD_DATASET", "STORAGE_POLICY"] as const).map(value => <option key={value} value={value}>{readable(value)}</option>)}</select></label>
        {kind === "PREFIX" && <label className="field full-width"><span>Object prefix</span><input required maxLength={1024} value={prefix} onChange={event => setPrefix(event.target.value)} placeholder="analytics/logs/" /></label>}
        {kind === "TAG_GROUP" && <label className="field full-width"><span>Object tags, one key=value per line</span><textarea required value={tags} onChange={event => setTags(event.target.value)} /></label>}
        {kind === "WORKLOAD_DATASET" && <label className="field full-width"><span>Workload identifier</span><input required value={workloadID} onChange={event => setWorkloadID(event.target.value)} /></label>}
        {kind === "STORAGE_POLICY" && <label className="field full-width"><span>Current storage classes, comma separated</span><input required value={classes} onChange={event => setClasses(event.target.value)} placeholder="STANDARD, STANDARD_IA" /></label>}
        <label className="field"><span>Workload criticality</span><select value={policy.criticality} onChange={event => setPolicy(value => ({ ...value, criticality: event.target.value as DatasetPolicy["criticality"] }))}>{(["NON_PRODUCTION", "TIER_0", "TIER_1", "TIER_2", "TIER_3"] as const).map(value => <option key={value} value={value}>{readable(value)}</option>)}</select></label>
        <label className="field"><span>Expected remaining lifetime (days)</span><input inputMode="decimal" pattern="[0-9]+(\.[0-9]+)?" value={policy.remaining_lifetime_days ?? ""} onChange={event => setPolicy(value => ({ ...value, remaining_lifetime_days: event.target.value || null }))} placeholder="Unknown" /></label>
        <label className="field"><span>Required recovery time (seconds)</span><input inputMode="decimal" pattern="[0-9]+(\.[0-9]+)?" value={policy.rto_seconds ?? ""} onChange={event => setPolicy(value => ({ ...value, rto_seconds: event.target.value || null }))} placeholder="Unknown" /></label>
        <label className="field"><span>Single-zone storage permitted</span><select value={policy.allow_onezone === null ? "UNKNOWN" : policy.allow_onezone ? "YES" : "NO"} onChange={event => setPolicy(value => ({ ...value, allow_onezone: event.target.value === "UNKNOWN" ? null : event.target.value === "YES" }))}><option value="UNKNOWN">Unknown</option><option value="NO">No</option><option value="YES">Yes, explicitly permitted</option></select></label>
      </div>
      <div className="configuration-stack">
        {([["high_seasonality", "Declared seasonal workload"], ["retention_known", "Customer retention requirements are known"], ["compliance_clear", "Customer compliance requirements have been reviewed"], ["recovery_known", "Workload recovery requirements are known"]] as const).map(([key, label]) => <label key={key}><input type="checkbox" checked={policy[key]} onChange={event => setPolicy(value => ({ ...value, [key]: event.target.checked }))} /> {label}</label>)}
        <label><input type="checkbox" checked={policy.dependencies_reviewed === true} onChange={event => setPolicy(value => ({ ...value, dependencies_reviewed: event.target.checked }))} /> Reviewed backup and external dataset dependencies</label>
      </div>
      {error && <p role="alert">{error}</p>}
      <div className="modal-actions"><Button secondary type="button" onClick={onClose}>Cancel</Button><Button type="submit" pending={busy}>Save dataset requirements</Button></div>
    </form>
  </Modal>;
}

function DatasetManager({ resource, busy, onAssess, onEdit }: { resource: Resource; busy: boolean; onAssess: (dataset: Dataset) => void; onEdit: (dataset: Dataset | "NEW") => void }) {
  const [revision, setRevision] = useState(0);
  return <section className="configuration-stack" aria-label="S3 dataset declarations"><h4>Datasets and business requirements</h4>
    <p className="form-note">Datasets group native object evidence into useful decisions. A declared prefix or tag does not prove that its object inventory, access history or costs are complete.</p>
    <div className="row-actions"><Button secondary small onClick={() => onEdit("NEW")}>Declare dataset</Button><Button secondary small onClick={() => setRevision(value => value + 1)}>Refresh datasets</Button></div>
    <RemotePage<Dataset> key={revision} path={`/object-storage-datasets?resource_id=${encode(resource.id)}&limit=10`} label="S3 datasets" empty="Declare a bucket, prefix, tag, workload or storage-policy dataset to record the requirements for its assessment.">{items => <Table scrollLabel="S3 dataset declarations" headings={["Dataset / revision", "Selection", "Requirements", "Actions"]}>
      {items.map(item => <tr key={item.id}><th scope="row">{item.name}<small>{shortId(item.id)} · revision {item.version}</small></th><td>{readable(item.selector.kind)}<small>{item.selector.prefix ?? item.selector.workload_id ?? item.selector.storage_classes?.join(", ") ?? "Selected object population"}</small></td><td>{readable(item.policy.criticality)}<small>Recovery: {item.policy.rto_seconds === null ? "Unknown" : `${item.policy.rto_seconds} seconds`}</small><small>Remaining lifetime: {item.policy.remaining_lifetime_days === null ? "Unknown" : `${item.policy.remaining_lifetime_days} days`}</small></td><td><div className="row-actions"><Button secondary small pending={busy} onClick={() => onAssess(item)}>Assess dataset {item.name}</Button><Button secondary small onClick={() => onEdit(item)}>Revise dataset {item.name}</Button></div><EvidenceProjection label={`Inspect dataset ${item.name}`} value={item} /></td></tr>)}
    </Table>}</RemotePage>
  </section>;
}

function CandidateEconomics({ economics }: { economics: S["ObjectStorageEconomics"] }) {
  const values: [string, string | null | undefined][] = [
    ["Current monthly cost", economics.current_monthly_cost], ["Candidate monthly cost", economics.candidate_monthly_cost],
    ["Transition cost", economics.transition_cost], ["Current-class minimum-duration obligation on transition", economics.current_minimum_duration_penalty],
    ["Unchanged-policy minimum-duration obligation", economics.baseline_minimum_duration_penalty],
    ["Candidate minimum-duration penalty", economics.candidate_minimum_duration_penalty], ["Intelligent-Tiering initialization cost", economics.tier_initialization_cost],
    ["Current lifetime cost", economics.current_horizon_cost], ["Candidate lifetime cost", economics.candidate_horizon_cost], ["Net lifetime saving", economics.net_horizon_saving],
    ["Estimated monthly saving including transition", economics.estimated_monthly_saving], ["Estimated annual saving", economics.estimated_annual_saving],
    ["Recurring monthly difference", economics.recurring_monthly_saving],
  ];
  return <section className="configuration-stack" aria-label="S3 candidate economics">
    <p>Economics: {readable(economics.status)} · pricing basis: {readable(economics.basis)} · currency: {economics.currency ?? "Unavailable"}</p>
    <p>Scenario horizon: {economics.horizon_days == null ? "Unavailable" : `${economics.horizon_days} days`}</p>
    <p className="form-note">Every candidate is an alternative for the same population. Candidate amounts are not additive portfolio savings. Annual estimates are unavailable when the evidenced remaining lifetime is too short. Signed negative outcomes remain visible.</p>
    <Table scrollLabel="S3 candidate economic comparison" headings={["Value", "Amount"]}>{values.map(([label, value]) => <tr key={label}><th scope="row">{label}</th><td>{amount(value, economics.currency)}</td></tr>)}<tr><th scope="row">Verified saving</th><td>Unavailable</td></tr></Table>
    {economics.component_costs.length ? <Table scrollLabel="S3 storage access and continuing cost components" headings={["Component", "Current monthly", "Candidate monthly"]}>
      {economics.component_costs.map(component => <tr key={component.component}><th scope="row">{readable(component.component)}</th><td>{amount(component.current_monthly_cost, economics.currency)}</td><td>{amount(component.candidate_monthly_cost, economics.currency)}</td></tr>)}
    </Table> : <p>Component economics unavailable. No zero cost has been inferred from a missing source.</p>}
    {economics.reference_scenario && <section aria-label="S3 reference price scenario"><h5>Reference pricing scenario</h5><p className="form-note">{readable(economics.reference_scenario.meaning)}. These reference amounts do not establish contracted customer costs or savings.</p><p>Current lifetime reference: {amount(economics.reference_scenario.current_horizon_cost, economics.reference_scenario.currency)} · candidate lifetime reference: {amount(economics.reference_scenario.candidate_horizon_cost, economics.reference_scenario.currency)}</p></section>}
  </section>;
}

export function ObjectStorageAssessmentEvidence({ assessment }: { assessment: Assessment }) {
  return <div className="configuration-stack">
    <div className="row-actions"><Badge value={assessment.status} /><Badge value="R3">R3 · Read-only S3 proposal</Badge></div>
    <p className="form-note">This assessment cannot change lifecycle rules, move or restore objects, delete data, enable automatic archival or create an execution plan. Estimates are separate from actual billed charges and verified savings.</p>
    <section aria-label="S3 assessment evidence quality"><h4>Evidence quality: {readable(assessment.confidence.status)}</h4><p className="form-note">{readable(assessment.confidence.meaning)}. Object age does not prove an infrequent access pattern.</p><Reasons values={assessment.confidence.reasons} /></section>
    <section aria-label="S3 assessment blockers"><h4>Blockers and unknowns</h4>{assessment.blockers.length ? <Reasons values={assessment.blockers} /> : <p>No assessment blockers were returned. Object and policy mutations remain disabled.</p>}</section>
    <h4>Dataset populations and storage classes</h4>
    {assessment.cohorts.length ? <Table scrollLabel="S3 dataset populations and access evidence" headings={["Dataset / storage class", "Population / size", "Age / access window", "Policy / quality", "Evidence"]}>
      {assessment.cohorts.map(cohort => <tr key={cohort.id}><th scope="row">{cohort.label}<small>{readable(cohort.source_class)} · {readable(cohort.state)}</small><small>{cohort.access_tier ? readable(cohort.access_tier) : "Access tier unavailable"}</small></th>
        <td>{exact(cohort.object_count)} objects<small>{exact(cohort.total_bytes)} bytes</small><EvidenceProjection label={`Size distribution for ${cohort.label}`} value={cohort.size_bands} /></td>
        <td>{exact(cohort.age_days_min)} — {exact(cohort.age_days_max)} days<small>{readable(cohort.access_state)}</small><small>{cohort.evidence_window.start ? dateTime(cohort.evidence_window.start) : "Window start unavailable"} — {cohort.evidence_window.end ? dateTime(cohort.evidence_window.end) : "Window end unavailable"}</small></td>
        <td>{readable(cohort.lifecycle_state)}<small>{cohort.inventory_complete ? "Complete selected inventory" : "Incomplete object inventory"}</small><Reasons values={cohort.blockers} /></td>
        <td><EvidenceProjection label={`Population proof for ${cohort.label}`} value={{ cohort_id: cohort.id, population_hash: cohort.population_hash, candidate_ids: cohort.candidate_ids }} /></td>
      </tr>)}
    </Table> : <p>Object population unavailable. Bucket aggregates cannot manufacture individual objects or prove prefix coverage.</p>}
    <section aria-label="S3 implementation and safety boundary"><h4>Implementation and recovery requirements</h4><p>Configuration authority: {readable(assessment.configuration_authority)}</p><p>Implementation method: {readable(assessment.implementation_method)}</p><p className="form-note">IaC-owned lifecycle and tiering changes require declarative review. Replicated data is retained for its evidenced reliability purpose; it is not classified as duplicate waste. Archive candidates must satisfy the declared recovery time, retention, compliance and retrieval economics. Unknown constraints remain blockers.</p></section>
    {assessment.declared_policy && <section aria-label="Frozen S3 dataset requirements"><h4>Frozen dataset requirements</h4><p>Criticality: {readable(assessment.declared_policy.criticality)} · seasonal workload: {assessment.declared_policy.high_seasonality ? "Yes" : "No"}</p><p>Required recovery time: {assessment.declared_policy.rto_seconds === null ? "Unknown" : `${assessment.declared_policy.rto_seconds} seconds`} · expected remaining lifetime: {assessment.declared_policy.remaining_lifetime_days === null ? "Unknown" : `${assessment.declared_policy.remaining_lifetime_days} days`}</p><p>Retention: {assessment.declared_policy.retention_known ? "Customer requirements declared known" : "Unknown"} · compliance: {assessment.declared_policy.compliance_clear ? "Customer review declared" : "Unknown"} · recovery requirements: {assessment.declared_policy.recovery_known ? "Declared known" : "Unknown"}</p><p>Backup and external dependencies: {assessment.declared_policy.dependencies_reviewed === true ? "Review declared" : assessment.declared_policy.dependencies_reviewed === false ? "Not reviewed" : "Unknown"} · single-zone storage: {assessment.declared_policy.allow_onezone === null ? "Unknown" : assessment.declared_policy.allow_onezone ? "Explicitly permitted" : "Not permitted"}</p><p className="form-note">These are the immutable customer declarations used for this assessment. Native retention and legal holds remain separate evidence and cannot be overridden by a declaration.</p><EvidenceProjection label="Frozen dataset policy reference" value={assessment.declared_policy_ref ?? null} /></section>}
    <h4>Candidate policies and economic trade-offs</h4>
    <p className="form-note">Storage class, request, retrieval, transition, monitoring, archive restore and minimum-duration costs are assessed together. A nominally cheaper per-GB class can cost more for small objects or frequent retrieval.</p>
    {assessment.candidates.length ? assessment.candidates.map(candidate => <section className="configuration-stack" key={candidate.id} aria-label={`S3 candidate ${candidate.id}`}>
      <h5>{readable(candidate.recommendation_kind)}</h5><div className="row-actions"><Badge value={candidate.status} /><span>{candidate.candidate_storage_class ? readable(candidate.candidate_storage_class) : "Target unavailable"}</span></div>
      <p>{readable(candidate.reason_code)} · cohort {shortId(candidate.cohort_id)}</p><Reasons values={candidate.blockers} />
      {candidate.recovery_requirement && <section aria-label="S3 candidate recovery requirements"><p>Required recovery time: {candidate.recovery_requirement.rto_seconds === null ? "Unknown" : `${candidate.recovery_requirement.rto_seconds} seconds`} · modelled retrieval/restore delay: {candidate.recovery_requirement.restore_latency_seconds === null ? "Unavailable" : `${candidate.recovery_requirement.restore_latency_seconds} seconds`}</p><p>Asynchronous restore: {candidate.recovery_requirement.requires_restore === null ? "Unknown" : candidate.recovery_requirement.requires_restore ? "Required" : "Not required by this class scenario"}. {readable(candidate.recovery_requirement.basis)}.</p><p className="form-note">Modelled class semantics do not guarantee provider response time, expedited retrieval capacity or the workload's recovery time.</p></section>}
      {candidate.policy_observations && <section aria-label="Intelligent-Tiering policy observations"><h5>Native tiering policy review</h5><p>Archive access: {candidate.policy_observations.archive_access_enabled === null ? "Unknown" : candidate.policy_observations.archive_access_enabled ? "Enabled" : "Disabled"} · deep archive access: {candidate.policy_observations.deep_archive_access_enabled === null ? "Unknown" : candidate.policy_observations.deep_archive_access_enabled ? "Enabled" : "Disabled"}</p><p>Monitored objects: {exact(candidate.policy_observations.monitored_object_count)} · unmonitored small objects: {exact(candidate.policy_observations.unmonitored_small_object_count)}</p><p>Required recovery time: {candidate.policy_observations.rto_seconds === null ? "Unknown" : `${candidate.policy_observations.rto_seconds} seconds`}</p><EvidenceProjection label="Current Intelligent-Tiering access tiers" value={candidate.policy_observations.current_tier_fractions} /></section>}
      <details className="plan-operations"><summary>Inspect economics for {candidate.candidate_storage_class ?? candidate.recommendation_kind} · {shortId(candidate.id)}</summary><CandidateEconomics economics={candidate.economics} /></details>
    </section>) : <p>No supported candidate policy was issued.</p>}
    <p className="form-note">No combined saving is shown because alternative and overlapping candidate policies must not be added together. Source currencies remain separate.</p>
    {assessment.economics.groups?.length ? <Table scrollLabel="S3 candidate currency groups" headings={["Currency", "Comparison basis", "Combined saving"]}>{assessment.economics.groups.map(group => <tr key={group.currency}><th scope="row">{group.currency}</th><td>{readable(group.status)}</td><td>Unavailable</td></tr>)}</Table> : null}
    <section aria-label="S3 assessment assumptions"><h4>Assumptions</h4><Reasons values={assessment.model_assumptions} /></section>
    <EvidenceProjection label={`Immutable S3 source references (${assessment.source_refs.length})`} value={assessment.source_refs} />
    <EvidenceProjection label="Bound S3 assessment identity" value={{ binding: assessment.binding, assessment_hash: assessment.assessment_hash, model_assessment_hash: assessment.model_assessment_hash, class_semantics_version: assessment.class_semantics_version ?? null, class_semantics_sha256: assessment.class_semantics_sha256 ?? null }} />
  </div>;
}

function ObjectStorageAssessmentDetail({ id }: { id: string }) {
  const [revision, setRevision] = useState(0);
  const state = useRemote<AssessmentRecord>(`/object-storage-assessments/${encode(id)}`, revision);
  return <section className="configuration-stack" aria-label="Selected S3 assessment">
    <h4>S3 assessment {shortId(id)}</h4>{state.loading && <p role="status">Loading S3 assessment…</p>}{state.error && <p role="alert">S3 assessment unavailable. {state.error}</p>}
    {state.value && <><p>Requested {dateTime(state.value.created_at)} · resource {state.value.resource_id} · dataset {state.value.dataset_id ?? "Bucket selection"}</p><Badge value={state.value.status} />
      {state.value.current === false && <div role="alert" className="blocker-text"><p>The stored S3 assessment no longer matches current source, configuration or dataset requirements. Request a new assessment before relying on its advice.</p><Reasons values={state.value.currentness_blockers ?? []} /></div>}
      {state.value.assessment ? <ObjectStorageAssessmentEvidence assessment={state.value.assessment} /> : state.value.status === "QUEUED" ? <p role="status">Read-only S3 assessment in progress. No result is available yet.</p> : <p role="alert">No S3 assessment result is available. Inspect its source and dataset evidence.</p>}
    </>}
    <Button secondary small disabled={state.loading} onClick={() => setRevision(value => value + 1)}>Refresh selected S3 assessment</Button>
  </section>;
}

export function ObjectStorageAssessmentDialog({ id, onClose }: { id: string; onClose: () => void }) {
  return <Modal title="S3 assessment" subtitle={id} onClose={onClose}><ObjectStorageAssessmentDetail id={id} /></Modal>;
}

export function ObjectStorageResourceAssessment({ resource, run, busy }: { resource: Resource; run: RunMutation; busy: boolean }) {
  const [selected, setSelected] = useState("");
  const [contextOpen, setContextOpen] = useState(false);
  const [editing, setEditing] = useState<Dataset | "NEW" | null>(null);
  const assess = async (dataset?: Dataset) => {
    const body: S["ObjectStorageAssessmentRequest"] = { resource_id: resource.id, ...(dataset ? { dataset_id: dataset.id } : {}) };
    const result = await run({ path: "/object-storage-assessments", body, version: 0, label: "Read-only S3 assessment requested" });
    if (result?.id) { setContextOpen(false); setSelected(result.id); }
  };
  return <><Badge value="R3">Read-only S3 · R3</Badge>
    <Button secondary small onClick={() => setContextOpen(true)}>Inspect S3 {resource.name || resource.provider_resource_id}</Button>
    <Button secondary small pending={busy} onClick={() => void assess()}>Assess S3 {resource.name || resource.provider_resource_id}</Button>
    {contextOpen && !editing && <Modal title="S3 bucket and datasets" subtitle={resource.provider_resource_id} onClose={() => setContextOpen(false)}>
      <div className="configuration-stack"><p>Workload: {resource.workload_id || "Unowned / unknown"} · configuration authority: {readable(resource.configuration_authority)}</p>
        <ObjectStorageConfiguration configuration={resource.object_storage_configuration ?? null} /><Reasons values={resource.blockers ?? []} />
        <DatasetManager resource={resource} busy={busy} onAssess={dataset => void assess(dataset)} onEdit={setEditing} />
      </div>
    </Modal>}
    {editing && <DatasetForm resource={resource} latest={editing === "NEW" ? undefined : editing} run={run} busy={busy} onClose={() => setEditing(null)} onSaved={() => setEditing(null)} />}
    {selected && <ObjectStorageAssessmentDialog id={selected} onClose={() => setSelected("")} />}
  </>;
}

export function ObjectStorageAssessmentHistory() {
  const [open, setOpen] = useState(false), [revision, setRevision] = useState(0), [selected, setSelected] = useState("");
  return <Panel title="S3 object-storage assessments" eyebrow="BUCKETS & DATASETS · READ-ONLY">
    <p>Inspect persisted storage-policy economics, access evidence, lifecycle state and blockers. Object and lifecycle mutations, deletion and automatic archival remain disabled.</p>
    <details onToggle={event => setOpen(event.currentTarget.open)}><summary>S3 assessment history</summary>{open && <div className="configuration-stack"><Button secondary small onClick={() => setRevision(value => value + 1)}>Refresh S3 assessment history</Button>
      <RemotePage<AssessmentRecord> key={revision} path="/object-storage-assessments?limit=10" label="S3 assessments" empty="Select a discovered S3 bucket in Cloud resources to request a read-only assessment.">{items => <Table scrollLabel="Persisted S3 assessment history" headings={["Request / dataset", "Status", "Evidence"]}>{items.map(item => <tr key={item.id}><th scope="row">{shortId(item.id)}<small>{item.resource_id}</small><small>{item.dataset_id ?? "Bucket selection"} · {dateTime(item.created_at)}</small></th><td><Badge value={item.status} /></td><td><Button secondary small onClick={() => setSelected(item.id)}>Inspect S3 assessment {shortId(item.id)}</Button></td></tr>)}</Table>}</RemotePage>
    </div>}</details>{selected && <ObjectStorageAssessmentDialog id={selected} onClose={() => setSelected("")} />}
  </Panel>;
}

export function ObjectStorageRecommendation({ item }: { item: Recommendation }) {
  const [open, setOpen] = useState(false);
  return <Panel className="recommendation-card"><div className="card-badges"><Badge value={item.status} /><Badge value="R3">R3 · S3 proposal</Badge></div>
    <h2>{item.title}</h2><p>Read-only S3 dataset and storage-policy assessment. Inspect each candidate's complete economics; alternatives are not additive savings.</p>
    {item.reason_code && <p className="blocker-text">{readable(item.reason_code)}</p>}
    <Button secondary small disabled={!item.object_storage_assessment_id} onClick={() => setOpen(true)}>Inspect S3 recommendation {shortId(item.id)}</Button>
    {open && item.object_storage_assessment_id && <ObjectStorageAssessmentDialog id={item.object_storage_assessment_id} onClose={() => setOpen(false)} />}
  </Panel>;
}
