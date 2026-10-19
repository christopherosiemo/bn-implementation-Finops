import { useState } from "react";
import type { components } from "./api.generated";
import { RemotePage, useRemote } from "./RemoteData";
import { Badge, Button, Modal, Table, dateTime, readable, shortId, type RunMutation } from "./ui";

type Decision = components["schemas"]["FleetJointDecision"];
type Record = components["schemas"]["FleetJointDecisionRecord"];
type PageRow = components["schemas"]["FleetJointDecisionPageRow"];
type Member = components["schemas"]["FleetJointDecisionMember"];
type Scenario = components["schemas"]["FleetNativeHourlyScenario"];
type Choice = { id: string; status: "QUEUED" | "ASSESSED"; created_at: string };
type Props = { workload: string; fixture: boolean; run: RunMutation; busy: boolean };
const query = encodeURIComponent;
const hourly = (amount: string | null, currency: string | null) =>
  amount !== null && currency !== null ? `${amount} ${currency}/hour` : "Unavailable";

function IssuedChoice({ workload, kind, selected, onSelect }: {
  workload: string; kind: "assessment" | "capacity"; selected: Choice | null; onSelect: (row: Choice) => void;
}) {
  const label = kind === "assessment" ? "Issued native assessments" : "Issued capacity batches";
  const route = kind === "assessment" ? "fleet-native-assessments" : "fleet-native-capacity-batches";
  return <fieldset className="configuration-stack">
    <legend>{kind === "assessment" ? "Observed compute assessment" : "Member capacity batch"}</legend>
    <RemotePage<Choice> key={`${workload}:${kind}`} path={`/workloads/${query(workload)}/${route}?limit=10`} label={label} empty="Complete the corresponding analysis before requesting a joint decision.">
      {(items) => items.map((row) => <label className="choice-card" key={row.id}>
        <input type="radio" name={`joint-${kind}`} checked={selected?.id === row.id} disabled={row.status !== "ASSESSED"} onChange={() => onSelect(row)} />
        <span><span className="evidence-id">{row.id}</span><small>{dateTime(row.created_at)} · {readable(row.status)}{row.status !== "ASSESSED" ? " · result unavailable" : ""}</small></span>
      </label>)}
    </RemotePage>
  </fieldset>;
}

function DecisionForm({ workload, run, busy, onClose, onSaved }: Props & { onClose: () => void; onSaved: (id: string) => void }) {
  const [revision, setRevision] = useState(0);
  const profile = useRemote<components["schemas"]["WorkloadSafetyPage"]>(`/workloads/${query(workload)}/safety-profiles?limit=1`, revision);
  const [assessment, setAssessment] = useState<Choice | null>(null);
  const [capacity, setCapacity] = useState<Choice | null>(null);
  const [failed, setFailed] = useState(false);
  const latest = profile.value?.latest;
  return <Modal title="Combine fleet analysis" subtitle="Read-only · issued evidence only" onClose={onClose}>
    <p className="form-note">Select completed analyses for the same original and candidate groups. The server checks their exact source, membership and safety-profile bindings. A conditional compute difference does not establish avoidable cost or execution readiness.</p>
    {profile.loading && <p role="status">Loading current safety profile…</p>}
    {profile.error && <p role="alert">Safety profile unavailable. {profile.error}</p>}
    {!profile.loading && !profile.error && !latest && <p className="blocker-text">Record a workload safety profile before requesting joint analysis.</p>}
    {latest && <p>Safety profile revision {latest.version}.</p>}
    <Button type="button" secondary small disabled={profile.loading || busy} onClick={() => setRevision((value) => value + 1)}>Refresh safety profile</Button>
    {failed && <p role="alert">Request could not be confirmed. Review the error and joint decision history before retrying.</p>}
    <form className="configuration-stack" onSubmit={async (event) => {
      event.preventDefault();
      if (!latest || !assessment || !capacity) return;
      setFailed(false);
      const body: components["schemas"]["FleetJointDecisionRequest"] = { assessment_request_id: assessment.id, capacity_batch_request_id: capacity.id };
      const saved = await run({ path: `/workloads/${query(workload)}/fleet-joint-decisions`, version: latest.version, body, label: "Read-only joint analysis queued." });
      if (saved) onSaved(saved.id); else setFailed(true);
    }}>
      <IssuedChoice workload={workload} kind="assessment" selected={assessment} onSelect={setAssessment} />
      <IssuedChoice workload={workload} kind="capacity" selected={capacity} onSelect={setCapacity} />
      <Button type="submit" pending={busy} disabled={!latest || !assessment || !capacity}>Request joint fleet analysis</Button>
    </form>
  </Modal>;
}

function ScenarioEvidence({ scenario }: { scenario: Scenario }) {
  return <div className="configuration-stack">
    <h4>Conditional hourly compute scenario</h4>
    <p className="form-note">Historical account rates applied to the observed member count. A zero or negative difference is retained. These amounts are not contracted avoidable cost or savings.</p>
    <Table scrollLabel="Joint conditional hourly scenario" headings={["Measure", "Observed amount"]}>
      <tr><td>Original rate per member</td><td>{hourly(scenario.old_hourly_rate, scenario.currency)}</td></tr>
      <tr><td>Candidate rate per member</td><td>{hourly(scenario.candidate_hourly_rate, scenario.currency)}</td></tr>
      <tr><td>Like-for-like member count</td><td>{scenario.status === "OBSERVED_CONDITIONAL" ? scenario.member_count : "Unavailable"}</td></tr>
      <tr><td>Original hourly compute</td><td>{hourly(scenario.old_hourly_compute, scenario.currency)}</td></tr>
      <tr><td>Candidate hourly compute</td><td>{hourly(scenario.candidate_hourly_compute, scenario.currency)}</td></tr>
      <tr><td>Conditional hourly compute difference</td><td>{hourly(scenario.hourly_compute_difference, scenario.currency)}</td></tr>
      <tr><td>Contracted avoidable cost</td><td>Unavailable</td></tr>
      <tr><td>Estimated savings</td><td>Unavailable</td></tr>
      <tr><td>Verified savings</td><td>Unavailable</td></tr>
    </Table>
    <p className="form-note">Rate basis: {readable(scenario.rate_basis)}. Excluded costs: {scenario.excluded_costs.map(readable).join(", ")}.</p>
  </div>;
}

function MemberEvidence({ member }: { member: Member }) {
  const [open, setOpen] = useState(false);
  return <details onToggle={(event) => setOpen(event.currentTarget.open)}>
    <summary>{member.instance_id} · physical checks {member.status}</summary>
    {open && <div className="configuration-stack">
      <p className="evidence-id">Member result {member.result.id}<small>SHA256 {member.result.sha256}</small></p>
      <Table scrollLabel={`Physical dimensions for ${member.instance_id}`} headings={["Dimension", "Observation", "Candidate capacity", "Required with reserve", "Gaps / reasons"]}>
        {member.dimensions.map((dimension) => <tr key={dimension.name}>
          <td>{readable(dimension.name)}<small>{dimension.unit}</small></td>
          <td>{dimension.status}</td>
          <td>{dimension.candidate_capacity ?? "Unavailable"}</td>
          <td>{dimension.required_with_reserve ?? "Unavailable"}</td>
          <td>{dimension.reason_codes.length ? dimension.reason_codes.map(readable).join(", ") : "No recorded gap"}</td>
        </tr>)}
      </Table>
    </div>}
  </details>;
}

export function FleetJointDecisionEvidence({ decision }: { decision: Decision }) {
  return <div className="configuration-stack">
    <div className="row-actions"><Badge value={decision.status} /><span>Physical observations: {decision.physical_status}</span></div>
    <p className="form-note">Observed {dateTime(decision.observed_at)}. PASS, FAIL and UNKNOWN describe the recorded physical checks only. Fleet capacity authority, business-work preservation and execution remain unestablished. Refreshing history does not renew evidence.</p>
    <ScenarioEvidence scenario={decision.scenario} />
    <h4>Per-member physical checks</h4>
    <p className="form-note">Each member retains CPU, memory, network, storage IOPS and storage throughput observations. UNKNOWN is missing evidence, never zero demand or a passed check.</p>
    {decision.members.map((member) => <MemberEvidence key={member.instance_id} member={member} />)}
    <p className="blocker-text">Execution disabled. No change plan is authorized.</p>
    <ul>{decision.reason_codes.map((reason) => <li key={reason}>{readable(reason)}</li>)}</ul>
    <details><summary>Exact issued input references</summary><ul className="evidence-refs">{decision.inputs.map((ref) => <li key={ref.id}><span className="evidence-id">{ref.id}<small>SHA256 {ref.sha256}</small></span></li>)}</ul></details>
  </div>;
}

function DecisionDetail({ id }: { id: string }) {
  const [revision, setRevision] = useState(0);
  const state = useRemote<Record>(`/fleet-joint-decisions/${query(id)}`, revision);
  return <section className="configuration-stack" aria-label="Selected joint fleet decision">
    {state.loading && <p role="status">Loading joint fleet decision…</p>}
    {state.error && <p role="alert">Joint decision unavailable. {state.error}</p>}
    {state.value && <>
      <h4>Joint decision {shortId(state.value.id)}</h4>
      <p className="evidence-id">Assessment request {state.value.assessment_request_id}<small>Capacity batch request {state.value.capacity_batch_request_id}</small></p>
      {state.value.decision ? <FleetJointDecisionEvidence decision={state.value.decision} /> : state.value.status === "REFUSED" ? <div role="alert" className="blocker-text">
        <p>Joint analysis refused. No joint result or execution authority was created.</p>
        {state.value.refusal ? <><p>Observed {dateTime(state.value.refusal.observed_at)}.</p><ul>{state.value.refusal.reason_codes.map(reason => <li key={reason}>{readable(reason)}</li>)}</ul></> : <p>Refusal details unavailable.</p>}
        <p>Select freshly issued matching analyses before making another request.</p>
      </div> : <p role="status">Queued for the analysis worker. No joint result is available yet.</p>}
    </>}
    <Button type="button" secondary small disabled={state.loading} onClick={() => setRevision((value) => value + 1)}>Refresh selected joint decision</Button>
  </section>;
}

function DecisionContent(props: Props) {
  const [form, setForm] = useState(false);
  const [revision, setRevision] = useState(0);
  const [selected, setSelected] = useState("");
  return <div className="configuration-stack">
    <div className="row-actions">
      <Button type="button" secondary small disabled={props.busy} onClick={() => setForm(true)}>Combine fleet analysis</Button>
      <Button type="button" secondary small onClick={() => setRevision((value) => value + 1)}>Refresh joint decisions</Button>
    </div>
    <RemotePage<PageRow> key={`${props.workload}:${revision}`} path={`/workloads/${query(props.workload)}/fleet-joint-decisions?limit=10`} label="Joint fleet decisions" empty="Select completed native compute and member-capacity analyses to view their combined evidence.">
      {(items) => <Table scrollLabel="Joint fleet decision history" headings={["Request", "Analysis", "Evidence"]}>{items.map((item) => <tr key={item.id}>
        <td className="evidence-id">{shortId(item.id)}<small>{dateTime(item.created_at)}</small></td>
        <td><Badge value={item.status} /><small>Physical observations: {item.decision_summary?.physical_status ?? "Unavailable"}</small><small>Execution disabled</small></td>
        <td><Button type="button" secondary small onClick={() => setSelected(item.id)}>Inspect joint decision {shortId(item.id)}</Button></td>
      </tr>)}</Table>}
    </RemotePage>
    {selected && <DecisionDetail key={selected} id={selected} />}
    {form && <DecisionForm {...props} onClose={() => setForm(false)} onSaved={(id) => { setForm(false); setSelected(id); setRevision((value) => value + 1); }} />}
  </div>;
}

export function FleetJointDecision(props: Props) {
  const [open, setOpen] = useState(false);
  return <details className="native-section" onToggle={(event) => setOpen(event.currentTarget.open)}>
    <summary className="native-subheading">Joint fleet evidence</summary>
    {props.fixture && <p className="form-note">Local fixture evidence. Provider transports and historical workloads are simulated.</p>}
    <p className="form-note">Combine issued compute-rate and member-capacity analyses without authorizing a fleet change.</p>
    {open && <DecisionContent {...props} />}
  </details>;
}
