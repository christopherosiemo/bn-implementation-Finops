import { RecommendationCurrentness } from "./RecommendationCurrentness";
import { useState } from "react";
import type { components } from "./api.generated";
import { RemotePage, useRemote } from "./RemoteData";
import { GroupChoice } from "./FleetProposalChoice";
import {
  Badge,
  Button,
  Modal,
  Table,
  dateTime,
  readable,
  shortId,
  type RunMutation,
} from "./ui";

type Record = components["schemas"]["FleetNativeAssessmentRecord"];
type Assessment = components["schemas"]["FleetNativeAssessment"];
type Request = components["schemas"]["FleetNativeAssessmentRequest"];
type Proposal = components["schemas"]["FleetConfigurationProposal"];
type ProfilePage = components["schemas"]["WorkloadSafetyPage"];
type Props = {
  workload: string;
  fixture: boolean;
  run: RunMutation;
  busy: boolean;
};
const query = encodeURIComponent;

// Keep DECIMAL(38,12) strings intact, including negative results and explicit zero.
function hourly(value: string | null, currency: string | null) {
  return value !== null && currency !== null
    ? `${value} ${currency}/hour`
    : "Unavailable";
}

function AssessmentForm({
  workload,
  run,
  busy,
  onClose,
  onSaved,
}: Props & {
  onClose: () => void;
  onSaved: (id: string) => void;
}) {
  const profile = useRemote<ProfilePage>(
    `/workloads/${query(workload)}/safety-profiles?limit=1`,
  );
  const [old, setOld] = useState<Proposal | null>(null);
  const [candidate, setCandidate] = useState<Proposal | null>(null);
  const [error, setError] = useState("");
  const latest = profile.value?.latest;
  return (
    <Modal
      title="Compare observed fleet compute rates"
      subtitle="Read-only assessment · existing evidence"
      onClose={onClose}
    >
      <p className="form-note">
        Select two captured group configurations. The assessment reads stored
        provider evidence and the current safety profile. It does not authorize
        a fleet change.
      </p>
      {profile.loading && <p role="status">Loading current safety profile…</p>}
      {profile.error && (
        <p role="alert">Safety profile unavailable. {profile.error}</p>
      )}
      {!profile.loading && !profile.error && !latest && (
        <p className="blocker-text">
          Record a workload safety profile before requesting an assessment.
        </p>
      )}
      {latest && (
        <p className="form-note">
          Safety profile revision {latest.version}. A concurrent profile change
          requires a new request.
        </p>
      )}
      <form
        className="configuration-stack"
        onSubmit={async (event) => {
          event.preventDefault();
          setError("");
          if (!old || !candidate || !latest) {
            setError("Select both proposals and a current safety profile.");
            return;
          }
          if (old.id === candidate.id) {
            setError("Select distinct original and candidate group proposals.");
            return;
          }
          const body: Request = {
            old_configuration_proposal_id: old.id,
            candidate_configuration_proposal_id: candidate.id,
          };
          const saved = await run({
            path: `/workloads/${query(workload)}/fleet-native-assessments`,
            version: latest.version,
            body,
            label: "Read-only fleet assessment queued.",
          });
          if (saved) onSaved(saved.id);
        }}
      >
        <GroupChoice
          workload={workload}
          side="Original"
          selected={old}
          onSelect={setOld}
        />
        <GroupChoice
          workload={workload}
          side="Candidate"
          selected={candidate}
          onSelect={setCandidate}
        />
        {error && <p role="alert">{error}</p>}
        <Button
          type="submit"
          pending={busy}
          disabled={!latest || !old || !candidate || old.id === candidate.id}
        >
          Request native fleet assessment
        </Button>
      </form>
    </Modal>
  );
}

export function FleetNativeAssessmentEvidence({
  assessment,
}: {
  assessment: Assessment;
}) {
  const scenario = assessment.scenario;
  return (
    <div className="configuration-stack">
      <div className="row-actions">
        <Badge value={assessment.status} />
        <Badge value="OBSERVATIONAL">Read-only evidence</Badge>
      </div>
      <p className="form-note">
        Observed {dateTime(assessment.observed_at)}. This compares historical
        account rates at the member count observed at capture. It does not
        establish safe capacity, avoidable expenditure or preserved business
        work.
      </p>
      {scenario.status === "OBSERVED_CONDITIONAL" && (
        <p className="form-note">
          Rate evidence was valid until{" "}
          {dateTime(assessment.native_rates.valid_until)} at publication.
          Historical results remain visible; refreshing this view does not renew
          evidence or establish current readiness.
        </p>
      )}
      <Table
        scrollLabel="Conditional fleet hourly compute comparison"
        headings={["Measure", "Observed amount"]}
      >
        <tr>
          <td>Original rate per member</td>
          <td>{hourly(scenario.old_hourly_rate, scenario.currency)}</td>
        </tr>
        <tr>
          <td>Candidate rate per member</td>
          <td>{hourly(scenario.candidate_hourly_rate, scenario.currency)}</td>
        </tr>
        <tr>
          <td>Like-for-like member count</td>
          <td>
            {scenario.status === "OBSERVED_CONDITIONAL"
              ? scenario.member_count
              : "Unavailable"}
          </td>
        </tr>
        <tr>
          <td>Original hourly compute</td>
          <td>{hourly(scenario.old_hourly_compute, scenario.currency)}</td>
        </tr>
        <tr>
          <td>Candidate hourly compute</td>
          <td>
            {hourly(scenario.candidate_hourly_compute, scenario.currency)}
          </td>
        </tr>
        <tr>
          <td>Conditional hourly compute difference</td>
          <td>
            {hourly(scenario.hourly_compute_difference, scenario.currency)}
          </td>
        </tr>
        <tr>
          <td>Contracted avoidable cost</td>
          <td>Unavailable</td>
        </tr>
        <tr>
          <td>Estimated savings</td>
          <td>Unavailable</td>
        </tr>
        <tr>
          <td>Verified savings</td>
          <td>Unavailable</td>
        </tr>
      </Table>
      <p className="form-note">
        Pricing basis: {readable(scenario.rate_basis)}. A negative difference is
        retained. Excluded costs:{" "}
        {scenario.excluded_costs.map(readable).join(", ")}.
      </p>
      <h4>Capacity evidence</h4>
      <p>
        {readable(assessment.capacity.status)} · historical membership:{" "}
        {readable(assessment.capacity.historical_membership)}
      </p>
      {assessment.capacity.members.length > 0 && (
        <Table
          scrollLabel="Per-member capacity evidence"
          headings={["Instance / resource", "Assessment", "Demand meaning"]}
        >
          {assessment.capacity.members.map((member) => (
            <tr key={member.instance_id}>
              <td>
                {member.instance_id}
                <small>{member.resource_id}</small>
              </td>
              <td>
                {readable(member.status)}
                <small className="evidence-id">{member.result_id}</small>
              </td>
              <td>{readable(member.demand_meaning)}</td>
            </tr>
          ))}
        </Table>
      )}
      {assessment.capacity.missing_instance_ids.length > 0 && (
        <p className="blocker-text">
          Missing member assessments:{" "}
          {assessment.capacity.missing_instance_ids.join(", ")}.
        </p>
      )}
      <p>
        Completed business work preserved: unavailable. Group capacity approval:
        unavailable. Execution disabled.
      </p>
      <h4>Readiness blockers</h4>
      <ul className="blocker-list">
        {[
          ...new Set([
            ...assessment.reason_codes,
            ...assessment.native_rates.reason_codes,
          ]),
        ].map((reason) => (
          <li key={reason}>{readable(reason)}</li>
        ))}
      </ul>
      <details>
        <summary>Immutable source references</summary>
        <p className="evidence-id">Assessment {assessment.id}</p>
        <p className="evidence-id">
          Snapshot {assessment.native_rates.snapshot_sha256}
        </p>
        <p className="evidence-id">
          Economic scope {assessment.native_rates.economic_scope_sha256}
        </p>
        {scenario.status === "OBSERVED_CONDITIONAL" ? (
          <p>
            Billing window {dateTime(assessment.native_rates.baseline.start)} —{" "}
            {dateTime(assessment.native_rates.baseline.end)}
          </p>
        ) : (
          <p>Billing window unavailable</p>
        )}
        <ul className="evidence-refs">
          {assessment.native_rates.source_pins.map((pin) => (
            <li key={pin.receipt_id}>
              <div style={{ display: "grid", rowGap: 4, marginBlock: 4 }}>
                <span className="evidence-id">
                  Receipt {pin.receipt_id} · revision {pin.revision_id}
                </span>
                <small>
                  Receipt object version {pin.receipt_version_id}; revision
                  object version {pin.revision_version_id}
                </small>
                <small className="evidence-id">Raw {pin.raw_sha256}</small>
              </div>
            </li>
          ))}
        </ul>
      </details>
    </div>
  );
}

function AssessmentDetail({ id }: { id: string }) {
  const [revision, setRevision] = useState(0);
  const state = useRemote<Record>(
    `/fleet-native-assessments/${query(id)}`,
    revision,
  );
  return (
    <section
      aria-label="Selected native fleet assessment"
      className="native-evaluation"
    >
      <h4>Assessment {shortId(id)}</h4>
      {state.loading && <p role="status">Loading fleet assessment…</p>}
      {state.error && <p role="alert">Assessment unavailable. {state.error}</p>}
      {state.value && (
        <>
          <Badge value={state.value.status} /><RecommendationCurrentness value={state.value.currentness} historicalStatus={state.value.historical_status ?? state.value.status} />
          {state.value.assessment ? (
            <FleetNativeAssessmentEvidence
              assessment={state.value.assessment}
            />
          ) : (
            <p className="form-note">
              Queued for the evidence worker. No analytical result is available
              yet.
            </p>
          )}
          <p className="evidence-id">
            Requested {dateTime(state.value.created_at)} · safety profile
            revision {state.value.selection.safety_profile.version}
          </p>
        </>
      )}
      <Button
        secondary
        small
        disabled={state.loading}
        onClick={() => setRevision((value) => value + 1)}
      >
        Refresh selected assessment
      </Button>
    </section>
  );
}

function AssessmentContent(props: Props) {
  const [form, setForm] = useState(false);
  const [selected, setSelected] = useState("");
  const [revision, setRevision] = useState(0);
  return (
    <div className="configuration-stack">
      <div className="row-actions">
        <Button
          secondary
          small
          disabled={props.busy}
          onClick={() => setForm(true)}
        >
          Compare fleet compute rates
        </Button>
        <Button
          secondary
          small
          onClick={() => setRevision((value) => value + 1)}
        >
          Refresh native assessments
        </Button>
      </div>
      <RemotePage<Record>
        key={`${props.workload}:${revision}`}
        path={`/workloads/${query(props.workload)}/fleet-native-assessments?limit=10`}
        label="Native fleet assessments"
        empty="Select existing group proposals to request a read-only evidence comparison."
      >
        {(items) => (
          <Table
            scrollLabel="Native fleet assessment history"
            headings={["Request", "Status", "Evidence"]}
          >
            {items.map((item) => (
              <tr key={item.id}>
                <td className="evidence-id">
                  {shortId(item.id)}
                  <small>{dateTime(item.created_at)}</small>
                </td>
                <td>
                  <Badge value={item.status} />
                  <small>Verified savings: unavailable</small>
                </td>
                <td>
                  <Button secondary small onClick={() => setSelected(item.id)}>
                    Inspect native assessment {shortId(item.id)}
                  </Button>
                </td>
              </tr>
            ))}
          </Table>
        )}
      </RemotePage>
      {selected && <AssessmentDetail key={selected} id={selected} />}
      {form && (
        <AssessmentForm
          {...props}
          onClose={() => setForm(false)}
          onSaved={(id) => {
            setForm(false);
            setSelected(id);
            setRevision((value) => value + 1);
          }}
        />
      )}
    </div>
  );
}

export function FleetNativeAssessment(props: Props) {
  const [open, setOpen] = useState(false);
  return (
    <details
      className="native-section"
      onToggle={(event) => setOpen(event.currentTarget.open)}
    >
      <summary className="native-subheading">
        Native fleet assessment & observed compute rates
      </summary>
      {props.fixture && (
        <p className="form-note">
          Local fixture evidence. Provider transports are simulated.
        </p>
      )}
      <p className="form-note">
        Persisted, read-only comparisons retain missing evidence and financial
        uncertainty. Verified savings and execution remain unavailable.
      </p>
      {open && <AssessmentContent {...props} />}
    </details>
  );
}
