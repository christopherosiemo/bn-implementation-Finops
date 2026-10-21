import { RecommendationCurrentness } from "./RecommendationCurrentness";
import { useState } from "react";
import type { components } from "./api.generated";
import { GroupChoice } from "./FleetProposalChoice";
import { ModelEvidence } from "./NativeCapacityResults";
import { RemotePage, useRemote } from "./RemoteData";
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

type Record = components["schemas"]["FleetNativeCapacityBatchRecord"];
type Member = components["schemas"]["FleetNativeCapacityMemberRecord"];
type Summary = components["schemas"]["FleetNativeCapacityMemberSummary"];
type Proposal = components["schemas"]["FleetConfigurationProposal"];
type ProfilePage = components["schemas"]["WorkloadSafetyPage"];
type Props = {
  workload: string;
  fixture: boolean;
  run: RunMutation;
  busy: boolean;
};
const query = encodeURIComponent;

function CapacityForm({
  workload,
  run,
  busy,
  onClose,
  onSaved,
}: Props & {
  onClose: () => void;
  onSaved: (id: string) => void;
}) {
  const [profileRevision, setProfileRevision] = useState(0);
  const [requestFailed, setRequestFailed] = useState(false);
  const profile = useRemote<ProfilePage>(
    `/workloads/${query(workload)}/safety-profiles?limit=1`,
    profileRevision,
  );
  const [old, setOld] = useState<Proposal | null>(null);
  const [candidate, setCandidate] = useState<Proposal | null>(null);
  const latest = profile.value?.latest;
  return (
    <Modal
      title="Evaluate fleet member capacity"
      subtitle="Read-only · server-selected native evidence"
      onClose={onClose}
    >
      <p className="form-note">
        Choose existing original and candidate group configurations. The worker
        freezes the observed original membership and evaluates each member
        against the exact captured candidate launch template. Missing members
        and observations remain visible.
      </p>
      {profile.loading && <p role="status">Loading current safety profile…</p>}
      {profile.error && (
        <p role="alert">Safety profile unavailable. {profile.error}</p>
      )}
      {!profile.loading && !profile.error && !latest && (
        <p className="blocker-text">
          Record a workload safety profile before requesting member evaluation.
        </p>
      )}
      {latest && (
        <p className="form-note">
          Safety profile revision {latest.version}. A concurrent change requires
          a new request.
        </p>
      )}
      <Button
        type="button"
        secondary
        small
        disabled={profile.loading || busy}
        onClick={() => setProfileRevision((value) => value + 1)}
      >
        Refresh safety profile
      </Button>
      {requestFailed && (
        <p role="alert">
          Request could not be confirmed. Review the error and batch history
          before retrying.
        </p>
      )}
      <form
        className="configuration-stack"
        onSubmit={async (event) => {
          event.preventDefault();
          if (!old || !candidate || !latest || old.id === candidate.id) return;
          setRequestFailed(false);
          const body: components["schemas"]["FleetNativeCapacityBatchRequest"] =
            {
              old_configuration_proposal_id: old.id,
              candidate_configuration_proposal_id: candidate.id,
            };
          const saved = await run({
            path: `/workloads/${query(workload)}/fleet-native-capacity-batches`,
            version: latest.version,
            body,
            label: "Read-only fleet member evaluation queued.",
          });
          if (saved) onSaved(saved.id);
          else setRequestFailed(true);
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
        {old && candidate && old.id === candidate.id && (
          <p role="alert">
            Select distinct original and candidate group proposals.
          </p>
        )}
        <Button
          type="submit"
          pending={busy}
          disabled={
            profile.loading ||
            !latest ||
            !old ||
            !candidate ||
            old.id === candidate.id
          }
        >
          Request fleet member evaluation
        </Button>
      </form>
    </Modal>
  );
}

function MemberDetail({ id }: { id: string }) {
  const state = useRemote<Member>(
    `/fleet-native-capacity-members/${query(id)}`,
  );
  const member = state.value?.member;
  return (
    <section
      className="native-evaluation"
      aria-label="Selected fleet member capacity evidence"
    >
      {state.loading && <p role="status">Loading member capacity evidence…</p>}
      {state.error && (
        <p role="alert">Member evidence unavailable. {state.error}</p>
      )}
      {member && (
        <>
          <h4>{member.instance_id}</h4>
          <p className="form-note">
            Member result captured {dateTime(member.observed_at)}. Historical
            telemetry retains its own measurement window.
          </p>
          <Badge value={member.status} />
          <p className="form-note">
            Model {member.model_evaluated ? "evaluated" : "unavailable"}.
            Complete candidate suitability:{" "}
            {member.capacity_suitable === null
              ? "unavailable"
              : member.capacity_suitable
                ? "recorded by the model"
                : "not established"}
            . Individual physical checks do not authorize a group change.
          </p>
          <p>
            Demand meaning: {readable(member.demand_meaning)}. Completed
            business work preserved: unavailable.
          </p>
          <ul className="blocker-list">
            {member.reason_codes.map((reason) => (
              <li key={reason}>{readable(reason)}</li>
            ))}
          </ul>
          {member.model_evaluated && member.model_evaluation ? (
            <details>
              <summary>
                Inspect member observations, forecasts & physical checks
              </summary>
              <ModelEvidence model={member.model_evaluation} />
            </details>
          ) : (
            <p className="blocker-text">
              No calculated physical result is available. Missing inputs cannot
              establish capacity suitability.
            </p>
          )}
          <p>
            Contracted avoidable cost, estimated savings and verified savings:
            unavailable. Execution disabled.
          </p>
          <details>
            <summary>
              Member source references & candidate configuration
            </summary>
            <p className="evidence-id">
              Result {state.value!.id} · SHA-256 {state.value!.sha256}
            </p>
            <p className="evidence-id">
              Frozen scope {member.scope.snapshot_sha256}
            </p>
            {member.binding && (
              <p>
                {member.binding.provider_resource_id} ·{" "}
                {member.binding.account_id} · {member.binding.region}
              </p>
            )}
            {member.candidate_template ? (
              <>
                <p>
                  Candidate {member.candidate_template.instance_type} · image{" "}
                  {member.candidate_template.image_id}
                </p>
                <p className="evidence-id">
                  Launch template {member.candidate_template.id}, version{" "}
                  {member.candidate_template.version}
                </p>
                <p className="evidence-id">
                  Definition {member.candidate_template.definition_sha256}
                </p>
              </>
            ) : (
              <p>Candidate configuration unavailable.</p>
            )}
            {member.hardware ? (
              <>
                <p className="evidence-id">
                  Hardware receipt {member.hardware.receipt_id} · revision{" "}
                  {member.hardware.revision_id}
                </p>
                <p className="evidence-id">Raw {member.hardware.raw_sha256}</p>
              </>
            ) : (
              <p>Native hardware evidence unavailable.</p>
            )}
            {member.telemetry ? (
              <>
                <p className="evidence-id">
                  Telemetry connection {member.telemetry.connection_id} revision{" "}
                  {member.telemetry.connection_version}
                </p>
                <p className="evidence-id">
                  Population {member.telemetry.population_hash}
                </p>
                <p>
                  {member.telemetry.receipt_ids.length} pinned native receipts.
                </p>
              </>
            ) : (
              <p>Native telemetry evidence unavailable.</p>
            )}
          </details>
        </>
      )}
    </section>
  );
}

function BatchDetail({ id }: { id: string }) {
  const [revision, setRevision] = useState(0);
  const [selected, setSelected] = useState("");
  const state = useRemote<Record>(
    `/fleet-native-capacity-batches/${query(id)}`,
    revision,
  );
  const record = state.value;
  const scope = record?.scope?.scope;
  const observed = scope?.population_status === "OBSERVED_POINT";
  return (
    <section
      className="native-evaluation"
      aria-label="Selected fleet capacity batch"
    >
      <h4>Member evaluation {shortId(id)}</h4>
      {state.loading && <p role="status">Loading fleet member evaluation…</p>}
      {state.error && <p role="alert">Evaluation unavailable. {state.error}</p>}
      {record && (
        <>
          <Badge value={record.currentness?.status ?? record.status} /><RecommendationCurrentness value={record.currentness} historicalStatus={record.historical_status ?? record.status} />
          <p className="form-note">
            Requested {dateTime(record.created_at)} · safety profile revision{" "}
            {record.selection.safety_profile.version}. Historical results retain
            their original evidence; refreshing does not renew authority.
          </p>
          {record.batch ? (
            <>
              <p>Member-result coverage: {readable(record.batch.coverage)}.</p>
              <p>
                Original membership:{" "}
                {observed
                  ? `${scope.current_member_ids.length} members observed at ${dateTime(scope.observed_at)}`
                  : "unavailable"}
                . A membership point does not establish historical interval
                ownership.
              </p>
              <ul className="blocker-list">
                {[
                  ...new Set([
                    ...(record.scope?.reason_codes ?? []),
                    ...record.batch.reason_codes,
                  ]),
                ].map((reason) => (
                  <li key={reason}>{readable(reason)}</li>
                ))}
              </ul>
              <p>
                Group capacity approval: unavailable. Completed business work
                preserved: unavailable. Estimated and verified savings:
                unavailable. Execution disabled.
              </p>
              <RemotePage<Summary>
                key={`${id}:${revision}`}
                path={`/fleet-native-capacity-batches/${query(id)}/members?limit=10`}
                label="Fleet capacity members"
                empty="No member results were published. Missing membership remains unavailable; an observed empty point contains zero members."
              >
                {(items) => (
                  <Table
                    scrollLabel="Fleet member capacity summaries"
                    headings={["Instance", "Model / suitability", "Evidence"]}
                  >
                    {items.map((item) => (
                      <tr key={item.id}>
                        <td>
                          {item.instance_id}
                          <small>
                            <Badge value={item.status} />
                          </small>
                        </td>
                        <td>
                          {item.model_evaluated ? "Evaluated" : "Unavailable"}
                          <small>
                            Complete suitability:{" "}
                            {item.capacity_suitable === null
                              ? "unavailable"
                              : item.capacity_suitable
                                ? "recorded"
                                : "not established"}
                          </small>
                        </td>
                        <td>
                          <Button
                            type="button"
                            secondary
                            small
                            onClick={() => setSelected(item.id)}
                          >
                            Inspect member {item.instance_id}
                          </Button>
                        </td>
                      </tr>
                    ))}
                  </Table>
                )}
              </RemotePage>
              <details>
                <summary>Frozen group references</summary>
                <p className="evidence-id">
                  Snapshot {scope?.snapshot_sha256 || "Unavailable"}
                </p>
                <p className="evidence-id">
                  Original proposal{" "}
                  {record.selection.groups.old_configuration_proposal.id}
                </p>
                <p className="evidence-id">
                  Candidate proposal{" "}
                  {record.selection.groups.candidate_configuration_proposal.id}
                </p>
                <ul className="evidence-refs">
                  {record.scope?.source_pins.map((pin) => (
                    <li key={pin.receipt_id}>
                      <span className="evidence-id">
                        Receipt {pin.receipt_id} · revision {pin.revision_id}
                      </span>
                      <small>
                        Object versions {pin.receipt_version_id} /{" "}
                        {pin.revision_version_id}
                      </small>
                      <small className="evidence-id">
                        Raw {pin.raw_sha256}
                      </small>
                    </li>
                  ))}
                </ul>
              </details>
            </>
          ) : (
            <p className="form-note">
              Queued for the capacity worker. No analytical result is available
              yet.
            </p>
          )}
        </>
      )}
      <Button
        type="button"
        secondary
        small
        disabled={state.loading}
        onClick={() => setRevision((value) => value + 1)}
      >
        Refresh selected capacity batch
      </Button>
      {selected && <MemberDetail key={selected} id={selected} />}
    </section>
  );
}

function CapacityContent(props: Props) {
  const [form, setForm] = useState(false);
  const [selected, setSelected] = useState("");
  const [revision, setRevision] = useState(0);
  return (
    <div className="configuration-stack">
      <div className="row-actions">
        <Button
          type="button"
          secondary
          small
          disabled={props.busy}
          onClick={() => setForm(true)}
        >
          Evaluate fleet member capacity
        </Button>
        <Button
          type="button"
          secondary
          small
          onClick={() => setRevision((value) => value + 1)}
        >
          Refresh capacity batches
        </Button>
      </div>
      <RemotePage<Record>
        key={`${props.workload}:${revision}`}
        path={`/workloads/${query(props.workload)}/fleet-native-capacity-batches?limit=10`}
        label="Fleet capacity batches"
        empty="Select captured group proposals to evaluate native physical capacity for the observed members."
      >
        {(items) => (
          <Table
            scrollLabel="Fleet capacity batch history"
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
                  <small>Execution disabled</small>
                </td>
                <td>
                  <Button
                    type="button"
                    secondary
                    small
                    onClick={() => setSelected(item.id)}
                  >
                    Inspect capacity batch {shortId(item.id)}
                  </Button>
                </td>
              </tr>
            ))}
          </Table>
        )}
      </RemotePage>
      {selected && <BatchDetail key={selected} id={selected} />}
      {form && (
        <CapacityForm
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

export function FleetNativeCapacity(props: Props) {
  const [open, setOpen] = useState(false);
  return (
    <details
      className="native-section"
      onToggle={(event) => setOpen(event.currentTarget.open)}
    >
      <summary className="native-subheading">
        Native fleet member capacity
      </summary>
      {props.fixture && (
        <p className="form-note">
          Local fixture evidence. Provider transports and historical workloads
          are simulated.
        </p>
      )}
      <p className="form-note">
        Per-member CPU, memory, network and storage checks use native evidence
        and the physical capacity model. Financial proof, fleet safety and
        execution approval remain independent gates.
      </p>
      {open && <CapacityContent {...props} />}
    </details>
  );
}
