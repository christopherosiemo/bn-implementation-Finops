import { useState } from "react";
import type { components } from "./api.generated";
import type { FleetHistoryRegistration } from "./types";
import { RemotePage, useRemote } from "./RemoteData";
import { FleetGroupAuthorization } from "./FleetGroupAuthorization";
import { FleetFixtureRuns } from "./FleetFixtureRuns";
import {
  Badge,
  Button,
  Empty,
  Modal,
  Table,
  dateTime,
  readable,
  shortId,
  type RunMutation,
} from "./ui";

type Record = components["schemas"]["FleetFixtureProposalRecord"];
type Selection = components["schemas"]["FleetFixtureSelection"];
type Configuration = components["schemas"]["FleetConfigurationProposal"];
type Prepared = components["schemas"]["FleetFixturePreparedProgram"];
type Profile = components["schemas"]["FleetFixtureProfile"];
type Props = { workload: string; run: RunMutation; busy: boolean };
const query = encodeURIComponent;

function Reasons({ values }: { values: string[] }) {
  return (
    <ul className="blocker-list">
      {values.map((value) => (
        <li key={value}>{readable(value)}</li>
      ))}
    </ul>
  );
}

function GroupSelection({
  workload,
  side,
  selected,
  onSelect,
}: {
  workload: string;
  side: "Original" | "Candidate";
  selected: Configuration | null;
  onSelect: (value: Configuration | null) => void;
}) {
  const [registration, setRegistration] =
    useState<FleetHistoryRegistration | null>(null);
  return (
    <fieldset className="configuration-stack">
      <legend>{side} registered group</legend>
      <RemotePage<FleetHistoryRegistration>
        key={`${workload}:${side}`}
        path={`/fleet-history-registrations?workload_id=${query(workload)}&limit=10`}
        label={`${side} group choices`}
        empty="Register a real fleet observation target and record its declared configuration and sealed history scope first."
      >
        {(items) => (
          <Table
            scrollLabel={`${side} group identity choices`}
            headings={["Registered group", "Account / region", "Selection"]}
          >
            {items.map((row) => (
              <tr key={row.id}>
                <td>
                  {row.registration.fleet_id}
                  <small className="evidence-id">
                    {row.registration.asg_arn}
                  </small>
                </td>
                <td>
                  {row.registration.binding.account_id}
                  <small>{row.registration.binding.region}</small>
                </td>
                <td>
                  <Button
                    secondary
                    small
                    aria-pressed={registration?.id === row.id}
                    onClick={() => {
                      setRegistration(row);
                      onSelect(null);
                    }}
                  >
                    Use {side.toLowerCase()} group {row.registration.fleet_id}
                  </Button>
                </td>
              </tr>
            ))}
          </Table>
        )}
      </RemotePage>
      {registration && (
        <RemotePage<Configuration>
          key={`${side}:${registration.id}:${registration.version}`}
          path={`/fleet-history-registrations/${query(registration.id)}/configuration-proposals?limit=10`}
          label={`${side} configuration proposals`}
          empty="Record a declared configuration and select a sealed scope for this group. The customer evidence remains blocked."
        >
          {(items) => (
            <Table
              scrollLabel={`${side} existing configuration proposals`}
              headings={["Captured proposal", "Customer evidence", "Selection"]}
            >
              {items.map((row) => (
                <tr key={row.id}>
                  <td>
                    {shortId(row.id)}
                    <small>Captured {dateTime(row.as_of)}</small>
                    <small>
                      Registration revision {row.registration_version}
                    </small>
                  </td>
                  <td>
                    <Badge value={row.status} />
                    <small>{readable(row.membership_status)}</small>
                  </td>
                  <td>
                    <Button
                      secondary
                      small
                      aria-pressed={selected?.id === row.id}
                      onClick={() => onSelect(row)}
                    >
                      Select {side.toLowerCase()} proposal {shortId(row.id)}
                    </Button>
                  </td>
                </tr>
              ))}
            </Table>
          )}
        </RemotePage>
      )}
    </fieldset>
  );
}

function ProposalForm({
  workload,
  run,
  busy,
  onSaved,
  onClose,
}: Props & { onSaved: (id: string) => void; onClose: () => void }) {
  const [profile, setProfile] = useState<Profile | null>(null);
  const [old, setOld] = useState<Configuration | null>(null);
  const [candidate, setCandidate] = useState<Configuration | null>(null);
  const [error, setError] = useState("");
  return (
    <Modal
      title="Propose an isolated group fixture"
      subtitle="Two real group selections · private fixture model"
      onClose={onClose}
    >
      <p className="form-note">
        This selects existing group records for an isolated Terraform model.
        Their declared configuration, incomplete history and customer blockers
        are preserved. No AWS action, customer execution or savings is approved.
      </p>
      <RemotePage<Profile>
        path="/fleet-fixture-profiles?limit=10"
        label="Installed fixture generations"
        empty="The private fixture producer is not installed. An operator must commission a real pinned local toolchain generation. The browser cannot upload images, artifacts, authority proofs or installation settings."
      >
        {(profiles) => (
          <>
            <label className="field">
              <span>Installed fixture generation</span>
              <select
                value={profile?.id ?? ""}
                onChange={(event) =>
                  setProfile(
                    profiles.find((row) => row.id === event.target.value) ??
                      null,
                  )
                }
              >
                <option value="">Select an installed generation</option>
                {profiles.map((row) => (
                  <option key={row.id} value={row.id}>
                    {row.name} · {shortId(row.generation)}
                  </option>
                ))}
              </select>
            </label>
            {profile && (
              <dl className="evidence-grid">
                <div>
                  <dt>Fixture model</dt>
                  <dd>
                    {profile.model.budget.baseline_count} baseline members /{" "}
                    {profile.model.budget.max_in_flight} in flight
                    <small>
                      Fixture values only; actual group capacity is unproven.
                    </small>
                  </dd>
                </div>
                <div>
                  <dt>Pinned toolchain</dt>
                  <dd>
                    Terraform {profile.installation.terraform_version}
                    <small className="evidence-id">
                      {profile.installation.toolchain_image_sha256}
                    </small>
                  </dd>
                </div>
                <div>
                  <dt>Generation</dt>
                  <dd className="evidence-id">
                    {profile.generation}
                    <small>{profile.model_sha256}</small>
                  </dd>
                </div>
              </dl>
            )}
            <GroupSelection
              workload={workload}
              side="Original"
              selected={old}
              onSelect={setOld}
            />
            <GroupSelection
              workload={workload}
              side="Candidate"
              selected={candidate}
              onSelect={setCandidate}
            />
            {error && (
              <p role="alert" className="blocker-text">
                {error}
              </p>
            )}
            <Button
              pending={busy}
              onClick={async () => {
                setError("");
                if (!profile || !old || !candidate) {
                  setError(
                    "Select an installed generation and both existing group proposals.",
                  );
                  return;
                }
                if (
                  old.registration_id === candidate.registration_id ||
                  old.asg_arn === candidate.asg_arn
                ) {
                  setError(
                    "The original and candidate must be different registered Auto Scaling groups.",
                  );
                  return;
                }
                const body: Selection = {
                  old_configuration_proposal_id: old.id,
                  candidate_configuration_proposal_id: candidate.id,
                  fixture_profile_id: profile.id,
                };
                const saved = await run({
                  path: "/fleet-fixture-proposals",
                  version: 0,
                  body,
                  label:
                    "Fixture selection recorded. Private program preparation and independent approval are still required.",
                });
                if (saved) onSaved(saved.id);
              }}
            >
              Record isolated fixture proposal
            </Button>
          </>
        )}
      </RemotePage>
    </Modal>
  );
}

function ProgramReview({ prepared }: { prepared: Prepared }) {
  const program = prepared.program,
    review = prepared.journal_review;
  return (
    <section
      className="configuration-stack"
      aria-label="Exact prepared fixture program"
    >
      <h4>Exact program & Git manifest</h4>
      <p className="form-note">
        A privately issued built-in Terraform fixture program. Model costs and
        evidence do not attest to customer AWS capacity, history, service health
        or savings. A future exact journal authorization must be independently
        approved before any command.
      </p>
      <dl className="evidence-grid">
        <div>
          <dt>Program hash</dt>
          <dd className="evidence-id">{prepared.program_hash}</dd>
        </div>
        <div>
          <dt>Manifest hash</dt>
          <dd className="evidence-id">{prepared.manifest_hash}</dd>
        </div>
        <div>
          <dt>Expiry</dt>
          <dd>{dateTime(program.expires_at)}</dd>
        </div>
        <div>
          <dt>Controlled Git ref</dt>
          <dd className="evidence-id">
            {program.manifest.ref}
            <small>{program.manifest.base.commit}</small>
          </dd>
        </div>
        <div>
          <dt>Declared address mapping</dt>
          <dd className="evidence-id">
            {program.artifact_context.mapping.old_declared_asg}
            <small>
              {program.artifact_context.mapping.candidate_declared_asg}
            </small>
            <small>
              {program.artifact_context.mapping.declared_listener_rule}
            </small>
          </dd>
        </div>
        <div>
          <dt>Installed toolchain</dt>
          <dd>
            Terraform {program.artifact_context.terraform_version}
            <small className="evidence-id">
              {program.artifact_context.toolchain_image_sha256}
            </small>
          </dd>
        </div>
        <div>
          <dt>Fixture model budget</dt>
          <dd>
            {program.budget.maximum_model_cost} {program.budget.currency}
            <small>
              {readable(program.budget.cost_basis)} · no native contracted rate
              or customer money claim
            </small>
          </dd>
        </div>
      </dl>
      <Table
        scrollLabel="Complete prepared fixture Git manifest"
        headings={[
          "Step / stage",
          "Exact Git revision",
          "Model effect",
          "Required observation",
        ]}
      >
        {program.manifest.entries.map((entry) => (
          <tr key={entry.sequence}>
            <td>
              {entry.sequence} · {readable(entry.stage_id)}
            </td>
            <td className="evidence-id">
              {entry.revision.commit}
              <small>{entry.revision.desired_sha256}</small>
            </td>
            <td>
              Original {entry.before.old_count} → {entry.after.old_count}
              <small>
                Candidate {entry.before.candidate_count} →{" "}
                {entry.after.candidate_count}
              </small>
              <small>
                Candidate traffic {entry.before.candidate_traffic_percent}% →{" "}
                {entry.after.candidate_traffic_percent}%
              </small>
            </td>
            <td>
              {entry.minimum_observation_seconds}s
              <small>Real elapsed evidence remains required.</small>
            </td>
          </tr>
        ))}
      </Table>
      <h4>Journal review scope</h4>
      <dl className="evidence-grid">
        <div>
          <dt>Review hash</dt>
          <dd className="evidence-id">{prepared.journal_review_hash}</dd>
        </div>
        <div>
          <dt>Policy</dt>
          <dd>
            {review.policy.id} · revision {review.policy.version}
            <small className="evidence-id">{review.policy.sha256}</small>
          </dd>
        </div>
        <div>
          <dt>Pipeline / limits</dt>
          <dd>
            {review.pipeline_id}
            <small>
              {review.max_effects} effects / {review.max_records} records
            </small>
          </dd>
        </div>
        <div>
          <dt>Pipeline key pin</dt>
          <dd className="evidence-id">{review.pipeline_key_sha256}</dd>
        </div>
        <div>
          <dt>Ledger key pin</dt>
          <dd className="evidence-id">{review.ledger_key_sha256}</dd>
        </div>
        <div>
          <dt>Initial state</dt>
          <dd className="evidence-id">
            {review.base.state_lineage}
            <small>
              Serial {review.base.state_serial} · {review.base.state_sha256}
            </small>
          </dd>
        </div>
      </dl>
    </section>
  );
}

function ProposalDetails({
  id,
  run,
  busy,
  onClose,
}: {
  id: string;
  run: RunMutation;
  busy: boolean;
  onClose: () => void;
}) {
  const [refresh, setRefresh] = useState(0),
    [reviewed, setReviewed] = useState(false);
  const record = useRemote<Record>(
    `/fleet-fixture-proposals/${query(id)}`,
    refresh,
  );
  const prepared = useRemote<Prepared>(
    record.value?.prepared_program
      ? `/fleet-fixture-proposals/${query(id)}/prepared-program`
      : null,
    refresh,
  );
  const row = record.value;
  return (
    <Modal
      title="Isolated group fixture proposal"
      subtitle={shortId(id)}
      onClose={onClose}
    >
      {record.loading ? (
        <p role="status">Loading persisted fixture proposal…</p>
      ) : record.error ? (
        <p role="alert" className="blocker-text">
          Fixture proposal unavailable. {record.error}
        </p>
      ) : (
        row && (
          <div className="configuration-stack">
            <Badge value={row.status} />
            <p className="form-note">
              Customer execution remains disabled. Estimated saving:
              unavailable. Verified saving: unavailable.
            </p>
            <dl className="evidence-grid">
              <div>
                <dt>Original registered group</dt>
                <dd className="evidence-id">
                  {row.proposal.binding.old.target.asg_arn}
                  <small>{row.proposal.old_configuration_proposal.id}</small>
                </dd>
              </div>
              <div>
                <dt>Candidate registered group</dt>
                <dd className="evidence-id">
                  {row.proposal.binding.candidate.target.asg_arn}
                  <small>
                    {row.proposal.candidate_configuration_proposal.id}
                  </small>
                </dd>
              </div>
              <div>
                <dt>Captured selection</dt>
                <dd>
                  Revision {row.version}
                  <small className="evidence-id">{row.hash}</small>
                </dd>
              </div>
              <div>
                <dt>Fixture realm</dt>
                <dd>
                  {row.proposal.realm.kind}
                  <small className="evidence-id">
                    {row.proposal.realm.fixture_id}
                    <br />
                    {row.proposal.realm.generation}
                  </small>
                </dd>
              </div>
            </dl>
            <details>
              <summary>Preserved customer evidence blockers</summary>
              <h4>Original group</h4>
              <Reasons
                values={
                  row.proposal.old_configuration_proposal.customer_reasons
                }
              />
              <h4>Candidate group</h4>
              <Reasons
                values={
                  row.proposal.candidate_configuration_proposal.customer_reasons
                }
              />
              <p className="form-note">
                Captured publication-time evidence. A fixture proposal or
                signature does not turn point observations into historical
                ownership or declared metadata into native authority.
              </p>
            </details>
            <section aria-label="Fixture runtime readiness">
              <h4>Runtime readiness</h4>
              <Badge value={row.readiness.status} />
              <Reasons values={row.readiness.reason_codes} />
              <p className="form-note">
                Private runtime gates govern commands and restoration. Inspect
                persisted execution and recovery duties below when available.
              </p>
            </section>
            {!row.prepared_program ? (
              <Empty
                title="Waiting for private program preparation"
                text="Approval is unavailable until the private producer has persisted the exact program, complete committed Git manifest and readable journal review. Selecting group IDs does not approve an unknown future program."
              />
            ) : prepared.loading ? (
              <p role="status">Loading exact prepared program…</p>
            ) : prepared.error ? (
              <p role="alert" className="blocker-text">
                Exact program review unavailable. {prepared.error}
              </p>
            ) : (
              prepared.value && (
                <>
                  <ProgramReview prepared={prepared.value} />
                  {row.approval ? (
                    <section>
                      <h4>Independent program approval</h4>
                      <p>
                        Approved by {row.approval.actor_id} on{" "}
                        {dateTime(row.approval.created_at)}.
                      </p>
                      <p className="evidence-id">{row.approval.program_hash}</p>
                      <p className="form-note">
                        Exact prepared program and journal review only. Exact
                        journal and recovery authorization reviews follow below;
                        durable runtime gates still apply.
                      </p>
                      <FleetGroupAuthorization proposalId={id} />
                      <FleetFixtureRuns proposalId={id} />
                    </section>
                  ) : (
                    <>
                      <label className="checkbox-field">
                        <input
                          type="checkbox"
                          checked={reviewed}
                          onChange={(event) =>
                            setReviewed(event.target.checked)
                          }
                        />
                        I reviewed this exact fixture program, complete
                        manifest, expiry and journal key/policy scope.
                      </label>
                      <p className="form-note">
                        An APPROVER must be a different authenticated person
                        from creator {row.proposal.creator_id}. The server
                        checks identity, current source bindings and the
                        displayed revision.
                      </p>
                      <Button
                        pending={busy}
                        disabled={!reviewed}
                        onClick={async () => {
                          const saved = await run({
                            path: `/fleet-fixture-proposals/${query(id)}/approvals`,
                            version: row.version,
                            body: {},
                            label:
                              "Exact fixture program independently approved. Runtime and exact journal authorization are still required.",
                          });
                          if (saved) {
                            setReviewed(false);
                            setRefresh((n) => n + 1);
                          }
                        }}
                      >
                        Approve exact fixture program
                      </Button>
                    </>
                  )}
                </>
              )
            )}
            <Button
              secondary
              small
              onClick={() => {
                setReviewed(false);
                setRefresh((n) => n + 1);
              }}
            >
              Refresh fixture proposal
            </Button>
          </div>
        )
      )}
    </Modal>
  );
}

export function FleetFixture({ workload, run, busy }: Props) {
  const [dialog, setDialog] = useState<"create" | string | null>(null),
    [refresh, setRefresh] = useState(0);
  return (
    <section
      className="configuration-stack"
      aria-label="Isolated group fixture proposals"
    >
      <h3>Isolated group fixture proposals</h3>
      <p className="form-note">
        Connect two actual registered group selections to a privately installed
        local Terraform fixture. Customer evidence remains blocked and money
        unavailable. Program preparation, independent approval and runtime
        readiness are separate gates.
      </p>
      <div className="row-actions">
        <Button secondary small onClick={() => setDialog("create")}>
          Propose isolated group fixture
        </Button>
        <Button secondary small onClick={() => setRefresh((n) => n + 1)}>
          Refresh fixture proposals
        </Button>
      </div>
      <RemotePage<Record>
        key={`${workload}:${refresh}`}
        path={`/fleet-fixture-proposals?workload_id=${query(workload)}&limit=10`}
        label="Fixture proposals"
        empty="No isolated fixture proposal has been selected for this workload."
      >
        {(items) => (
          <Table
            scrollLabel="Persisted isolated fixture proposals"
            headings={[
              "Group pair",
              "Fixture program",
              "Runtime / customer authority",
              "Inspect",
            ]}
          >
            {items.map((row) => (
              <tr key={row.id}>
                <td>
                  {row.proposal.binding.old.target.fleet_id} →{" "}
                  {row.proposal.binding.candidate.target.fleet_id}
                  <small>Captured {dateTime(row.created_at)}</small>
                </td>
                <td>
                  <Badge value={row.status} />
                  <small>Revision {row.version}</small>
                </td>
                <td>
                  <Badge value={row.readiness.status} />
                  <small>
                    Runtime unavailable · customer execution disabled
                  </small>
                  <small>Savings unavailable</small>
                </td>
                <td>
                  <Button secondary small onClick={() => setDialog(row.id)}>
                    Inspect fixture proposal {shortId(row.id)}
                  </Button>
                </td>
              </tr>
            ))}
          </Table>
        )}
      </RemotePage>
      {dialog === "create" ? (
        <ProposalForm
          workload={workload}
          run={run}
          busy={busy}
          onClose={() => setDialog(null)}
          onSaved={(id) => {
            setRefresh((n) => n + 1);
            setDialog(id);
          }}
        />
      ) : (
        dialog && (
          <ProposalDetails
            key={dialog}
            id={dialog}
            run={run}
            busy={busy}
            onClose={() => {
              setDialog(null);
              setRefresh((n) => n + 1);
            }}
          />
        )
      )}
    </section>
  );
}
