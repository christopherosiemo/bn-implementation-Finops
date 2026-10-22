import { useState } from "react";
import type { components } from "./api.generated";
import { RemotePage, useRemote } from "./RemoteData";
import { Badge, Button, Modal, Panel, Table, dateTime, readable, shortId, type RunMutation } from "./ui";

type S = components["schemas"];
type Decision = S["CommitmentDecision"];
type Record = S["CommitmentDecisionRecord"];
type Ref = S["CommitmentPortfolioRef"];
type Choice = S["CommitmentDecisionInputChoice"];
type Props = { workloads: { id: string; name: string }[]; fixture: boolean; run: RunMutation; busy: boolean };
const encode = encodeURIComponent;
const inputKinds = [
  ["PORTFOLIO_ANALYSIS", "portfolio_analysis_request_id", "Portfolio analysis"],
  ["OFFER", "offer_receipt_id", "Native offer receipt"],
  ["POST_OPTIMIZATION_ASSESSMENT", "post_optimization_assessment_id", "Post-optimization assessment"],
  ["FORECAST", "forecast_id", "Issued forecast"],
] as const;

function Reasons({ values }: { values: string[] }) {
  return values.length ? <ul>{values.map(value => <li key={value}>{readable(value)}</li>)}</ul> : null;
}

function References({ refs }: { refs: Ref[] }) {
  const [open, setOpen] = useState(false);
  const [visible, setVisible] = useState(20);
  return <details onToggle={event => setOpen(event.currentTarget.open)}>
    <summary>Issued evidence references ({refs.length})</summary>
    {open && (refs.length ? <>
      <ul className="evidence-refs">{refs.slice(0, visible).map(ref => <li className="evidence-id" key={ref.kind + ":" + ref.id + ":" + ref.sha256}>
        {readable(ref.kind)} · {ref.id}<small>SHA256 {ref.sha256}</small>
      </li>)}</ul>
      {visible < refs.length && <Button type="button" small secondary onClick={() => setVisible(value => value + 20)}>Show more decision evidence references</Button>}
    </> : <p>Issued references unavailable.</p>)}
  </details>;
}

function Outcome({ status }: { status: Decision["status"] }) {
  return <Badge value={status} tone={status === "RECOMMEND_PURCHASE_PENDING_FINANCE" ? "amber" : status === "BLOCKED" ? "red" : "neutral"} />;
}

function MetricEvidence({ label, metric }: { label: string; metric: S["CommitmentDecisionMetric"] }) {
  return <tr>
    <th scope="row">{label}</th>
    <td>{metric.value === null ? "Unavailable" : metric.value}<small>{metric.unit}{metric.currency === null ? "" : " · " + metric.currency}</small></td>
    <td><Badge value={metric.status} /><small>{readable(metric.basis)}</small><small>{dateTime(metric.period.start)} — {dateTime(metric.period.end)} · end exclusive</small>
      <Reasons values={metric.reason_codes} /><References refs={metric.input_refs} />
    </td>
  </tr>;
}

export function CommitmentDecisionEvidence({ decision }: { decision: Decision }) {
  const scope = decision.scope;
  const confidence = decision.confidence;
  const metrics: [string, S["CommitmentDecisionMetric"]][] = [
    ["Observed coverage", decision.observed_coverage],
    ["Observed effective discount", decision.observed_effective_discount],
    ["Observed unused exposure", decision.observed_unused_exposure],
    ["Proposed hourly commitment", decision.proposed_hourly_commitment],
    ["Proposed term obligation", decision.proposed_term_obligation],
    ["Expected utilization", decision.expected_utilization],
    ["Break-even utilization", decision.break_even_utilization],
    ["Conditional expected savings", decision.expected_savings],
    ["Downside exposure", decision.downside_exposure],
    ["New cash requirement", decision.cash_requirement],
    ["Remaining contractual obligation", decision.remaining_contractual_obligation],
    ["Paid unamortized value", decision.paid_unamortized_value],
  ];
  return <div className="configuration-stack">
    <div className="row-actions"><Outcome status={decision.status} /><span>Observed {dateTime(decision.observed_at)}</span></div>
    <p className="form-note">{decision.status === "RECOMMEND_PURCHASE_PENDING_FINANCE"
      ? "The issued calculation supports a conditional recommendation pending independent Finance review. Review does not place an order or grant purchase authority."
      : decision.status === "DO_NOT_PURCHASE"
        ? "The issued calculation does not support this purchase. Its negative or zero values are retained."
        : "Required evidence or a supported calculation is unavailable. Unknown values do not mean zero."}</p>
    <p className="evidence-id">Decision {decision.id}<small>Request {decision.request_id}</small></p>
    <section aria-label="Commitment decision scope" className="configuration-stack">
      <h4>Exact calculation scope</h4>
      <p>Workload {scope.workload_id} · payer {scope.payer_account_id} · {readable(scope.class)} · {scope.currency}</p>
      <p className="evidence-id">Scope SHA256 {scope.sha256}<small>Configuration SHA256 {scope.configuration_sha256}</small></p>
      <p>History {dateTime(scope.history_period.start)} — {dateTime(scope.history_period.end)}; projection {dateTime(scope.projection_period.start)} — {dateTime(scope.projection_period.end)}. Both ends are exclusive.</p>
      <details><summary>Scoped accounts and resources</summary><p className="evidence-id">Usage accounts: {scope.usage_account_ids.join(", ") || "Unavailable"}</p><p className="evidence-id">Resources: {scope.resource_ids.join(", ") || "Unavailable"}</p><References refs={[scope.ownership_ref]} /></details>
    </section>
    <p className="form-note">Observed coverage, discount and unused spend describe the issued historical evidence. Expected utilization, savings and break-even values describe the stated projection and assumptions. Values are exact decimal strings with their own units, periods and evidence; currencies are never combined here.</p>
    <Table headings={["Metric", "Exact value / unit", "Status / basis / interval"]} scrollLabel="Commitment decision metrics">
      {metrics.map(([label, metric]) => <MetricEvidence key={label} label={label} metric={metric} />)}
    </Table>
    <section aria-label="Commitment decision price and risk assumptions" className="configuration-stack">
      <h4>Price change and downside</h4>
      <p>{readable(decision.forward_price_assumption)}</p>
      <p className="form-note">Holding a current observed native account net rate is a conditional assumption. It does not establish a forward PAYG contract or guaranteed savings.</p>
      <p>Computation policy: {readable(decision.computation_policy)}</p>
      <Badge value={decision.price_change_stress.status} />
      <p>{readable(decision.price_change_stress.assumption)}</p>
      <p>Break-even PAYG rate drop: {decision.price_change_stress.break_even_payg_rate_drop_fraction ?? "Unavailable"} (fraction).</p>
      <Table headings={["Metric", "Exact value / unit", "Status / basis / interval"]} scrollLabel="Commitment zero-usage downside">
        <MetricEvidence label="Zero-usage loss" metric={decision.price_change_stress.zero_usage_loss} />
      </Table>
      <Reasons values={decision.price_change_stress.reason_codes} />
    </section>
    <section aria-label="Commitment decision confidence" className="configuration-stack">
      <h4>Forecast confidence</h4><Badge value={confidence.status} />
      <dl className="definition-list">
        <div><dt>Expected savings lower bound</dt><dd>{confidence.lower_expected_savings ?? "Unavailable"}{confidence.lower_expected_savings === null || decision.expected_savings.currency === null ? "" : " " + decision.expected_savings.currency}</dd></div>
        <div><dt>Expected savings upper bound</dt><dd>{confidence.upper_expected_savings ?? "Unavailable"}{confidence.upper_expected_savings === null || decision.expected_savings.currency === null ? "" : " " + decision.expected_savings.currency}</dd></div>
        <div><dt>Empirical calibration coverage</dt><dd>{confidence.coverage === null ? "Unavailable" : confidence.coverage + " (fraction)"}</dd></div>
        <div><dt>Method</dt><dd>{confidence.method === null ? "Unavailable" : readable(confidence.method)}</dd></div>
      </dl>
      <p className="form-note">Confidence bounds share the expected-savings projection and currency above. Empirical rolling windows may overlap and are dependent observations; their coverage is not guaranteed confidence over a commitment term. Inspect the issued method, calibration and assumptions. Missing calibration remains unavailable.</p>
      {confidence.calibration_ref ? <References refs={[confidence.calibration_ref]} /> : <p>Calibration reference unavailable.</p>}
      <Reasons values={confidence.reason_codes} />
    </section>
    <section aria-label="Commitment decision optimization order" className="configuration-stack">
      <h4>Post-optimization prerequisites</h4>
      <ol>{decision.optimization_order.map(stage => <li key={stage.stage}>
        <strong>{readable(stage.stage)}</strong> · {readable(stage.disposition)}<small>Completed {dateTime(stage.completed_at)}</small>
        <p className="evidence-id">Scope SHA256 {stage.scope_sha256}</p><Reasons values={stage.reason_codes} /><References refs={[stage.decision_ref, stage.outcome_ref]} />
      </li>)}</ol>
      {!decision.optimization_order.length && <p>Issued optimization outcomes unavailable.</p>}
    </section>
    <Reasons values={decision.reason_codes} /><References refs={decision.input_refs} />
    <p className="form-note">Purchase and execution disabled. Verified saving unavailable. Finance review records consideration of this exact recommendation only.</p>
  </div>;
}

function InputChoices({ workloadID, kind, title, selected, onChange, busy }: {
  workloadID: string; kind: Choice["kind"]; title: string; selected: string; onChange: (id: string) => void; busy: boolean;
}) {
  return <fieldset className="configuration-stack" disabled={busy}>
    <legend>{title}</legend>
    <RemotePage<Choice> path={"/workloads/" + encode(workloadID) + "/commitment-decision-inputs?kind=" + kind + "&limit=10"}
      label={title + " choices"} empty={"No issued " + title.toLowerCase() + " is available for this workload."}>
      {items => items.map(choice => <label className="choice-card" key={choice.id}>
        <input type="radio" name={kind} checked={selected === choice.id} disabled={choice.status !== "CURRENT" || choice.kind !== kind} onChange={() => onChange(choice.id)} />
        <span><span className="evidence-id">{choice.id}</span><small>{choice.label} · {readable(choice.status)}</small>
          <small>{choice.period ? dateTime(choice.period.start) + " — " + dateTime(choice.period.end) + " · end exclusive" : "Issued interval unavailable"}</small>
          {choice.scope_sha256 && <small className="evidence-id">Scope SHA256 {choice.scope_sha256}</small>}
          <Reasons values={choice.reason_codes} />
        </span>
      </label>)}
    </RemotePage>
  </fieldset>;
}

function RequestDecision({ workloadID, run, busy, onClose, onSaved }: { workloadID: string; run: RunMutation; busy: boolean; onClose: () => void; onSaved: (id: string) => void }) {
  const empty: S["CommitmentDecisionSelection"] = { portfolio_analysis_request_id: "", offer_receipt_id: "", post_optimization_assessment_id: "", forecast_id: "" };
  const [selection, setSelection] = useState(empty);
  const [revision, setRevision] = useState(0);
  const [error, setError] = useState("");
  return <Modal title="Evaluate commitment decision" subtitle="Issued evidence · conditional purchasing analysis" onClose={onClose}>
    <p className="form-note">Select four server-issued IDs for this workload. The server resolves native offer rates, eligible account usage, completed optimization outcomes and forecast evidence. No amounts, forecast values or authority flags are uploaded.</p>
    <form className="configuration-stack" onSubmit={async event => {
      event.preventDefault(); setError("");
      if (Object.values(selection).some(value => !value)) return;
      const saved = await run({ path: "/workloads/" + encode(workloadID) + "/commitment-decisions", body: selection, version: 0, label: "Commitment decision queued." });
      if (saved) onSaved(saved.id);
      else setError("Request could not be confirmed. Inspect decision history and the API error before retrying this selection.");
    }}>
      {inputKinds.map(([kind, field, title]) => <InputChoices key={kind + ":" + revision} workloadID={workloadID} kind={kind} title={title} selected={selection[field]} busy={busy} onChange={id => setSelection(value => ({ ...value, [field]: id }))} />)}
      <Button type="button" secondary small disabled={busy} onClick={() => { setSelection(empty); setRevision(value => value + 1); }}>Refresh commitment decision inputs</Button>
      <p className="form-note">Only current choices are selectable. Selection does not establish matching scope, forecast calibration or economic benefit; the server checks those before publication.</p>
      {error && <p role="alert" className="blocker-text">{error}</p>}
      <Button type="submit" pending={busy} disabled={Object.values(selection).some(value => !value)}>Request commitment decision</Button>
    </form>
  </Modal>;
}

function FinanceReview({ record, run, busy, onClose, onSaved }: { record: Record; run: RunMutation; busy: boolean; onClose: () => void; onSaved: () => void }) {
  const [acknowledged, setAcknowledged] = useState(false);
  const [error, setError] = useState("");
  const eligible = record.can_finance_review && record.decision?.status === "RECOMMEND_PURCHASE_PENDING_FINANCE" && record.decision_sha256 !== null && record.input_sha256 !== null && record.finance_review === null;
  return <Modal title="Review commitment recommendation" subtitle="Independent Finance review · no purchase authority" onClose={onClose}>
    <p>This records Finance review of the exact immutable recommendation and its resolved inputs. It cannot place an order, authorize purchase or execute a change.</p>
    <p className="evidence-id">Request {record.id}<small>Record version {record.version}</small><small>Full decision SHA256 {record.decision_sha256 ?? "Unavailable"}</small><small>Input SHA256 {record.input_sha256 ?? "Unavailable"}</small></p>
    <Reasons values={record.review_reason_codes} />
    <form className="configuration-stack" onSubmit={async event => {
      event.preventDefault(); setError("");
      if (!acknowledged || !eligible || record.decision_sha256 === null) return;
      const body: S["CommitmentDecisionFinanceReviewRequest"] = { commitment_decision_id: record.id, decision_sha256: record.decision_sha256 };
      const saved = await run({ path: "/approvals", body, version: record.version, label: "Finance review recorded; purchase remains disabled." });
      if (saved) onSaved();
      else setError("Finance review could not be confirmed. Refresh the issued record before retrying. The server rechecks independent reviewer, current inputs and exact hash.");
    }}>
      <label className="choice-card"><input type="checkbox" checked={acknowledged} disabled={busy || !eligible} onChange={event => setAcknowledged(event.target.checked)} /><span>I reviewed the evidence and conditional assumptions. This approval does not authorize purchase or execution.</span></label>
      {error && <p role="alert" className="blocker-text">{error}</p>}
      <Button type="submit" pending={busy} disabled={!eligible || !acknowledged}>Record Finance review</Button>
    </form>
  </Modal>;
}

function PrepareInputs({ workloadID, run, busy, onClose, onSaved }: { workloadID: string; run: RunMutation; busy: boolean; onClose: () => void; onSaved: (id: string) => void }) {
  const [selection, setSelection] = useState<S["CommitmentDecisionPreparationSelection"]>({ portfolio_analysis_request_id: "", offer_receipt_id: "" });
  const [revision, setRevision] = useState(0);
  const [error, setError] = useState("");
  return <Modal title="Prepare commitment decision evidence" subtitle="Server-derived outcomes and forecast evidence" onClose={onClose}>
    <p className="form-note">Select an issued portfolio analysis and native offer. The existing analyst resolves optimization outcomes and forecast evidence for their scope. Missing outcomes or calibration remain explicit gaps; a returned ID does not establish a positive recommendation.</p>
    <form className="configuration-stack" onSubmit={async event => {
      event.preventDefault(); setError("");
      if (!selection.portfolio_analysis_request_id || !selection.offer_receipt_id) return;
      const saved = await run({ path: "/workloads/" + encode(workloadID) + "/commitment-decision-inputs", body: selection, version: 0, label: "Decision evidence preparation queued." });
      if (saved) onSaved(saved.id);
      else setError("Preparation could not be confirmed. Inspect its history and the API error before retrying the same selection.");
    }}>
      {[inputKinds[0], inputKinds[1]].map(([kind, field, title]) => <InputChoices key={kind + ":" + revision} workloadID={workloadID} kind={kind} title={title} selected={selection[field]} busy={busy} onChange={id => setSelection(value => ({ ...value, [field]: id }))} />)}
      <Button type="button" secondary small disabled={busy} onClick={() => { setSelection({ portfolio_analysis_request_id: "", offer_receipt_id: "" }); setRevision(value => value + 1); }}>Refresh preparation inputs</Button>
      {error && <p role="alert" className="blocker-text">{error}</p>}
      <Button type="submit" pending={busy} disabled={!selection.portfolio_analysis_request_id || !selection.offer_receipt_id}>Request evidence preparation</Button>
    </form>
  </Modal>;
}

function PreparationDetail({ id, workloadID }: { id: string; workloadID: string }) {
  const [revision, setRevision] = useState(0);
  const detail = useRemote<S["CommitmentDecisionPreparationRecord"]>("/commitment-decision-inputs/" + encode(id), revision);
  const record = detail.value;
  return <section className="configuration-stack" aria-label="Issued decision evidence preparation">
    <div className="row-actions"><h4>Issued decision evidence preparation</h4><Button type="button" secondary small onClick={() => setRevision(value => value + 1)}>Refresh issued evidence preparation</Button></div>
    {detail.loading && <p role="status">Loading evidence preparation…</p>}
    {detail.error && <p role="alert">Evidence preparation unavailable. {detail.error}</p>}
    {record && (record.id !== id || record.workload_id !== workloadID ? <p role="alert">The API returned a different preparation scope.</p> : <>
      <p className="evidence-id">{record.id} · version {record.version}<small>Creator {record.creator_id} · {dateTime(record.created_at)}</small></p><Badge value={record.status} />
      {record.status === "QUEUED" && <p>Awaiting the dedicated analyst. Refresh reads persisted state.</p>}
      <Table headings={["Issued input", "Identifier"]} scrollLabel="Prepared commitment decision input IDs">
        <tr><th scope="row">Portfolio analysis</th><td className="evidence-id">{record.selection.portfolio_analysis_request_id}</td></tr>
        <tr><th scope="row">Native offer</th><td className="evidence-id">{record.selection.offer_receipt_id}</td></tr>
        <tr><th scope="row">Post-optimization assessment</th><td className="evidence-id">{record.post_optimization_assessment_id ?? "Unavailable"}</td></tr>
        <tr><th scope="row">Issued forecast</th><td className="evidence-id">{record.forecast_id ?? "Unavailable"}</td></tr>
      </Table>
      <Reasons values={record.reason_codes} /><References refs={record.input_refs} />
      <p className="form-note">Issued IDs may describe blocked outcomes or unavailable forecast evidence. Evaluate the four current IDs to obtain the decision; preparation does not authorize purchase or assert economic benefit.</p>
    </>)}
  </section>;
}

function PreparationHistory({ workloadID, run, busy }: { workloadID: string; run: RunMutation; busy: boolean }) {
  const [open, setOpen] = useState(false);
  const [revision, setRevision] = useState(0);
  const [selected, setSelected] = useState<string | null>(null);
  const [form, setForm] = useState(false);
  return <section className="configuration-stack" aria-label="Commitment evidence preparation">
    <div className="row-actions"><Button type="button" secondary small disabled={busy} onClick={() => setForm(true)}>Prepare commitment decision evidence</Button></div>
    <details open={open} onToggle={event => setOpen(event.currentTarget.open)}><summary>Evidence preparation history</summary>
      {open && <>
        <Button type="button" secondary small onClick={() => setRevision(value => value + 1)}>Refresh evidence preparations</Button>
        <RemotePage<S["CommitmentDecisionPreparationRecord"]> key={revision} path={"/workloads/" + encode(workloadID) + "/commitment-decision-inputs?limit=10"} label="Evidence preparations" empty="Prepare server-derived optimization and forecast evidence from an issued portfolio and native offer.">
          {items => <Table headings={["Request / created", "Preparation status", "Evidence"]} scrollLabel="Commitment evidence preparation history">
            {items.map(record => <tr key={record.id}><td className="evidence-id">{shortId(record.id)}<small>{dateTime(record.created_at)}</small></td><td><Badge value={record.status} /><small>Economic readiness not inferred</small></td><td><Button type="button" secondary small onClick={() => setSelected(record.id)}>Inspect evidence preparation {shortId(record.id)}</Button></td></tr>)}
          </Table>}
        </RemotePage>
      </>}
    </details>
    {selected && <PreparationDetail key={selected} id={selected} workloadID={workloadID} />}
    {form && <PrepareInputs workloadID={workloadID} run={run} busy={busy} onClose={() => setForm(false)} onSaved={id => { setForm(false); setOpen(true); setSelected(id); setRevision(value => value + 1); }} />}
  </section>;
}

function DecisionDetail({ id, workloadID, run, busy, onChanged }: { id: string; workloadID: string; run: RunMutation; busy: boolean; onChanged: () => void }) {
  const [revision, setRevision] = useState(0);
  const [review, setReview] = useState(false);
  const detail = useRemote<Record>("/commitment-decisions/" + encode(id), revision);
  const record = detail.value;
  return <section className="configuration-stack" aria-label="Issued commitment decision">
    <div className="row-actions"><h3>Issued commitment decision</h3><Button type="button" secondary small onClick={() => { setReview(false); setRevision(value => value + 1); }}>Refresh issued commitment decision</Button></div>
    {detail.loading && <p role="status">Loading issued commitment decision…</p>}
    {detail.error && <p role="alert">Commitment decision unavailable. {detail.error}</p>}
    {record && (record.id !== id || record.workload_id !== workloadID ? <p role="alert">The API returned a different decision scope. Refresh before continuing.</p> : <>
      <p className="evidence-id">Request {record.id} · version {record.version}<small>Created {dateTime(record.created_at)} · creator {record.creator_id}</small></p><Badge value={record.status} />
      {record.status === "QUEUED" && <p>Awaiting the dedicated analyst. Refresh reads persisted state; it does not renew evidence or approve a purchase.</p>}
      {record.refusal && <p role="status">{readable(record.refusal.reason_code)} · {dateTime(record.refusal.observed_at)}</p>}
      {record.decision && <CommitmentDecisionEvidence decision={record.decision} />}
      <p className="evidence-id">Full decision SHA256 {record.decision_sha256 ?? "Unavailable"}<small>Input SHA256 {record.input_sha256 ?? "Unavailable"}</small></p>
      <References refs={record.input_refs} />
      {record.finance_review ? <section aria-label="Recorded Finance review"><h4>Finance review recorded</h4><p className="evidence-id">{record.finance_review.id}<small>Reviewer {record.finance_review.actor_id} · {dateTime(record.finance_review.approved_at)}</small><small>Decision SHA256 {record.finance_review.decision_sha256}</small><small>Input SHA256 {record.finance_review.input_sha256}</small></p><p>{readable(record.finance_review.approval_scope)}. Purchase and execution remain disabled.</p></section> : <>
        <Reasons values={record.review_reason_codes} />
        {record.can_finance_review && record.decision?.status === "RECOMMEND_PURCHASE_PENDING_FINANCE" && record.decision_sha256 !== null && record.input_sha256 !== null && <Button type="button" secondary disabled={busy} onClick={() => setReview(true)}>Review commitment recommendation</Button>}
      </>}
      {review && <FinanceReview key={record.id + ":" + record.version} record={record} run={run} busy={busy} onClose={() => setReview(false)} onSaved={() => { setReview(false); setRevision(value => value + 1); onChanged(); }} />}
    </>)}
  </section>;
}

function WorkloadDecisions({ workloadID, run, busy }: { workloadID: string; run: RunMutation; busy: boolean }) {
  const [revision, setRevision] = useState(0);
  const [selected, setSelected] = useState<string | null>(null);
  const [form, setForm] = useState(false);
  return <div className="configuration-stack">
    <PreparationHistory workloadID={workloadID} run={run} busy={busy} />
    <div className="row-actions"><Button type="button" small secondary disabled={busy} onClick={() => setForm(true)}>Evaluate commitment decision</Button><Button type="button" small secondary onClick={() => setRevision(value => value + 1)}>Refresh commitment decisions</Button></div>
    <RemotePage<S["CommitmentDecisionPageRow"]> key={revision} path={"/workloads/" + encode(workloadID) + "/commitment-decisions?limit=10"} label="Commitment decisions" empty="Request a calculation from issued portfolio, native offer, post-optimization and forecast evidence.">
      {items => <Table headings={["Request / created", "Issued outcome", "Evidence"]} scrollLabel="Commitment decision history">
        {items.map(record => <tr key={record.id}><td className="evidence-id">{shortId(record.id)}<small>{dateTime(record.created_at)}</small></td><td><Badge value={record.status} />{record.decision_summary && <><Outcome status={record.decision_summary.status} /><small>Proposed hourly commitment: {record.decision_summary.proposed_hourly_commitment === null ? "Unavailable" : record.decision_summary.proposed_hourly_commitment + " " + record.decision_summary.currency + "/hour"}</small><small>Conditional expected savings: {record.decision_summary.expected_savings === null ? "Unavailable" : record.decision_summary.expected_savings + " " + record.decision_summary.currency}</small><small>Finance: {readable(record.decision_summary.finance_status)}</small></>}<small>Purchase disabled</small></td><td><Button type="button" secondary small onClick={() => setSelected(record.id)}>Inspect commitment decision {shortId(record.id)}</Button></td></tr>)}
      </Table>}
    </RemotePage>
    {selected && <DecisionDetail key={selected} id={selected} workloadID={workloadID} run={run} busy={busy} onChanged={() => setRevision(value => value + 1)} />}
    {form && <RequestDecision workloadID={workloadID} run={run} busy={busy} onClose={() => setForm(false)} onSaved={id => { setForm(false); setSelected(id); setRevision(value => value + 1); }} />}
  </div>;
}

function DecisionContent({ workloads, run, busy }: Props) {
  const [workloadID, setWorkloadID] = useState("");
  return <div className="configuration-stack">
    <label className="field"><span>Commitment decision workload</span><select value={workloadID} onChange={event => setWorkloadID(event.target.value)}><option value="">Select workload</option>{workloads.map(workload => <option key={workload.id} value={workload.id}>{workload.name}</option>)}</select></label>
    {workloadID && <WorkloadDecisions key={workloadID} workloadID={workloadID} run={run} busy={busy} />}
  </div>;
}

export function CommitmentDecision(props: Props) {
  const [open, setOpen] = useState(false);
  return <Panel title="Commitment purchasing decisions" eyebrow="CONDITIONAL ECONOMICS · INDEPENDENT FINANCE REVIEW">
    {props.fixture && <p className="form-note">Local fixture evidence. Provider history and source transports are simulated.</p>}
    <p className="form-note">Evaluate authentic stored offers against scoped account usage after optimization. A recommendation and its independent Finance review grant no purchase or execution authority.</p>
    <details onToggle={event => setOpen(event.currentTarget.open)}><summary>Commitment decision evidence</summary>{open && <DecisionContent {...props} />}</details>
  </Panel>;
}
