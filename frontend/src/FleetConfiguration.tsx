import { useState, type InputHTMLAttributes } from "react";
import type { components } from "./api.generated";
import type { FleetHistoryRegistration, FleetHistoryScope } from "./types";
import { RemotePage, useRemote } from "./RemoteData";
import {
  Badge,
  Button,
  Empty,
  Table,
  dateTime,
  readable,
  shortId,
  type RunMutation,
} from "./ui";

type Declaration = components["schemas"]["FleetConfigurationDeclaration"];
type DeclarationInput = components["schemas"]["FleetDeclarationInput"];
type DeclarationPage = components["schemas"]["FleetConfigurationPage"];
type Proposal = components["schemas"]["FleetConfigurationProposal"];
type ProposalSelection = components["schemas"]["FleetProposalSelection"];
type Props = {
  registration: FleetHistoryRegistration;
  run: RunMutation;
  busy: boolean;
  refresh: number;
};
const query = encodeURIComponent;

function TextField({
  label,
  value,
  onChange,
  ...props
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
} & Omit<InputHTMLAttributes<HTMLInputElement>, "value" | "onChange">) {
  return (
    <label className="field">
      <span>{label}</span>
      <input
        required
        maxLength={512}
        {...props}
        value={value}
        onChange={(event) => onChange(event.target.value)}
      />
    </label>
  );
}

function Reasons({ values }: { values: string[] }) {
  return (
    <ul className="blocker-list">
      {values.map((reason) => (
        <li key={reason}>{readable(reason)}</li>
      ))}
    </ul>
  );
}

function DeclarationForm({
  registration,
  latest,
  version,
  run,
  busy,
  onCancel,
  onSaved,
}: {
  registration: FleetHistoryRegistration;
  latest: Declaration | null;
  version: number;
  run: RunMutation;
  busy: boolean;
  onCancel: () => void;
  onSaved: () => void;
}) {
  const [repository, setRepository] = useState<DeclarationInput["repository"]>(
    latest?.metadata.repository ?? { url: "", ref: "", directory: "." },
  );
  const [pipeline, setPipeline] = useState<DeclarationInput["pipeline"]>(
    latest?.metadata.pipeline ?? {
      system: "GITHUB_ACTIONS",
      identity: {
        issuer: "",
        audience: "finops-deployment-observer",
        subject: "",
        pipeline_id: "",
      },
    },
  );
  const [terraform, setTerraform] = useState(
    latest?.metadata.terraform ?? {
      workspace: "",
      state_lineage: "",
      asg_address: "",
      launch_template_address: "",
    },
  );
  const [traffic, setTraffic] = useState(
    Boolean(latest?.metadata.terraform.traffic),
  );
  const [listener, setListener] = useState(
    latest?.metadata.terraform.traffic?.listener_rule_address ?? "",
  );
  const [targets, setTargets] = useState<[string, string]>([
    latest?.metadata.terraform.traffic?.target_group_addresses[0] ?? "",
    latest?.metadata.terraform.traffic?.target_group_addresses[1] ?? "",
  ]);
  const [error, setError] = useState("");
  return (
    <form
      className="configuration-stack"
      aria-label="Fleet Terraform declaration"
      onSubmit={async (event) => {
        event.preventDefault();
        setError("");
        if (traffic && targets[0] === targets[1]) {
          setError("Declare two distinct target-group resource addresses.");
          return;
        }
        const body: DeclarationInput = {
          schema_version: "1",
          authority: "TERRAFORM",
          repository,
          pipeline,
          terraform: {
            workspace: terraform.workspace,
            state_lineage: terraform.state_lineage,
            asg_address: terraform.asg_address,
            launch_template_address: terraform.launch_template_address,
            ...(traffic
              ? {
                  traffic: {
                    listener_rule_address: listener,
                    target_group_addresses: targets,
                  },
                }
              : {}),
          },
        };
        const saved = await run({
          path: `/fleet-history-registrations/${query(registration.id)}/configuration-authorities`,
          version,
          body,
          label:
            "Fleet configuration metadata declared; mapping and pipeline remain unattested.",
        });
        if (saved) onSaved();
        else
          setError(
            "Declaration was not saved. Review the API error and refresh the selected fleet before retrying a changed revision.",
          );
      }}
    >
      <h4>Declare fleet Terraform metadata · revision {version + 1}</h4>
      <p className="form-note">
        Bound to this registered ASG by the server. Repository and pipeline
        details are operator metadata only. Provide no credentials, state
        payloads, artifacts or observed commit assertions.
      </p>
      <fieldset className="days-fieldset">
        <legend>Repository declaration</legend>
        <TextField
          label="Fleet repository HTTPS URL"
          type="url"
          pattern="https://.+"
          maxLength={2048}
          value={repository.url}
          onChange={(url) => setRepository({ ...repository, url })}
        />
        <TextField
          label="Fleet declared Git branch or tag"
          maxLength={255}
          value={repository.ref}
          onChange={(ref) => setRepository({ ...repository, ref })}
        />
        <TextField
          label="Fleet repository relative directory"
          value={repository.directory}
          onChange={(directory) => setRepository({ ...repository, directory })}
        />
        <p className="form-note">
          A branch or tag is not an observed commit. Use a dot for the
          repository root; no repository is fetched from this form.
        </p>
      </fieldset>
      <fieldset className="days-fieldset">
        <legend>Dedicated deployment pipeline declaration</legend>
        <label className="field">
          <span>Fleet pipeline system</span>
          <select
            value={pipeline.system}
            onChange={(event) =>
              setPipeline({
                ...pipeline,
                system: event.target.value as typeof pipeline.system,
              })
            }
          >
            <option value="GITHUB_ACTIONS">GitHub Actions</option>
            <option value="GITLAB_CI">GitLab CI</option>
            <option value="BITBUCKET_PIPELINES">Bitbucket Pipelines</option>
            <option value="OTHER">Other</option>
          </select>
        </label>
        <TextField
          label="Fleet pipeline issuer HTTPS URL"
          type="url"
          pattern="https://.+"
          maxLength={2048}
          value={pipeline.identity.issuer}
          onChange={(issuer) =>
            setPipeline({
              ...pipeline,
              identity: { ...pipeline.identity, issuer },
            })
          }
        />
        <label className="field">
          <span>Fleet dedicated pipeline audience</span>
          <input readOnly value={pipeline.identity.audience} />
        </label>
        <TextField
          label="Fleet exact pipeline machine subject"
          value={pipeline.identity.subject}
          onChange={(subject) =>
            setPipeline({
              ...pipeline,
              identity: { ...pipeline.identity, subject },
            })
          }
        />
        <TextField
          label="Fleet stable pipeline identifier"
          maxLength={256}
          value={pipeline.identity.pipeline_id}
          onChange={(pipeline_id) =>
            setPipeline({
              ...pipeline,
              identity: { ...pipeline.identity, pipeline_id },
            })
          }
        />
        <p className="form-note">
          Saving metadata does not enroll or authenticate this identity in the
          deployment observer.
        </p>
      </fieldset>
      <fieldset className="days-fieldset">
        <legend>Declared group configuration mapping</legend>
        <TextField
          label="Fleet Terraform workspace"
          maxLength={128}
          pattern="[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}"
          value={terraform.workspace}
          onChange={(workspace) => setTerraform({ ...terraform, workspace })}
        />
        <TextField
          label="Fleet declared state lineage UUID"
          maxLength={36}
          pattern="[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
          value={terraform.state_lineage}
          onChange={(state_lineage) =>
            setTerraform({ ...terraform, state_lineage })
          }
        />
        <TextField
          label="Fleet ASG Terraform resource address"
          value={terraform.asg_address}
          onChange={(asg_address) =>
            setTerraform({ ...terraform, asg_address })
          }
          placeholder="module.api.aws_autoscaling_group.api"
        />
        <TextField
          label="Fleet launch-template Terraform resource address"
          value={terraform.launch_template_address}
          onChange={(launch_template_address) =>
            setTerraform({ ...terraform, launch_template_address })
          }
          placeholder="module.api.aws_launch_template.api"
        />
        <p className="form-note">
          These configuration addresses are declared mappings. They do not prove
          native launch-template versions, membership, hardware or surviving
          capacity.
        </p>
      </fieldset>
      <label className="checkbox-field">
        <input
          type="checkbox"
          checked={traffic}
          onChange={(event) => setTraffic(event.target.checked)}
        />
        <span>
          Declare an optional listener rule and two target-group mappings
        </span>
      </label>
      {traffic && (
        <fieldset className="days-fieldset">
          <legend>Optional traffic configuration mapping</legend>
          <TextField
            label="Fleet listener-rule Terraform resource address"
            value={listener}
            onChange={setListener}
          />
          <TextField
            label="Fleet first target-group Terraform resource address"
            value={targets[0]}
            onChange={(value) => setTargets([value, targets[1]])}
          />
          <TextField
            label="Fleet second target-group Terraform resource address"
            value={targets[1]}
            onChange={(value) => setTargets([targets[0], value])}
          />
        </fieldset>
      )}
      <label className="checkbox-field">
        <input type="checkbox" required />
        <span>
          I acknowledge that this declaration is unattested and grants no
          execution, deployment, approval or savings authority.
        </span>
      </label>
      {error && (
        <p role="alert" className="blocker-text">
          {error}
        </p>
      )}
      <div className="modal-actions">
        <Button secondary type="button" onClick={onCancel}>
          Cancel fleet declaration
        </Button>
        <Button type="submit" pending={busy}>
          Save fleet declaration
        </Button>
      </div>
    </form>
  );
}

function DeclarationEvidence({ value }: { value: Declaration }) {
  const metadata = value.metadata;
  return (
    <div className="configuration-stack">
      <div className="readiness-summary">
        <Badge value="BLOCKED">Declared, unattested</Badge>
        <span>
          Declaration revision {value.version} · {dateTime(value.created_at)}
        </span>
      </div>
      <dl className="definition-list">
        <div>
          <dt>Captured group binding</dt>
          <dd className="evidence-id">
            {value.asg_arn}
            <small>
              Registration {value.registration_id} · revision{" "}
              {value.registration_version}
            </small>
            <small>{value.registration_hash}</small>
          </dd>
        </div>
        <div>
          <dt>Captured source configuration</dt>
          <dd className="evidence-id">
            {value.source_id} · revision {value.source_registration_version}
            <small>{value.source_config_hash}</small>
          </dd>
        </div>
        <div>
          <dt>Declared repository</dt>
          <dd className="evidence-id">
            {metadata.repository.url}
            <small>
              {metadata.repository.ref} · {metadata.repository.directory}
            </small>
          </dd>
        </div>
        <div>
          <dt>Declared pipeline</dt>
          <dd className="evidence-id">
            {metadata.pipeline.identity.subject}
            <small>{metadata.pipeline.identity.issuer}</small>
            <small>
              {metadata.pipeline.identity.audience} ·{" "}
              {metadata.pipeline.identity.pipeline_id}
            </small>
          </dd>
        </div>
        <div>
          <dt>Declared Terraform mapping</dt>
          <dd className="evidence-id">
            {metadata.terraform.workspace}
            <small>Lineage {metadata.terraform.state_lineage}</small>
            <small>ASG {metadata.terraform.asg_address}</small>
            <small>
              Launch template {metadata.terraform.launch_template_address}
            </small>
            {metadata.terraform.traffic && (
              <>
                <small>
                  Listener rule{" "}
                  {metadata.terraform.traffic.listener_rule_address}
                </small>
                {metadata.terraform.traffic.target_group_addresses.map(
                  (address) => (
                    <small key={address}>Target group {address}</small>
                  ),
                )}
              </>
            )}
          </dd>
        </div>
        <div>
          <dt>Observed commit / state / native mapping</dt>
          <dd>Unavailable · independent attestation required</dd>
        </div>
        <div>
          <dt>Immutable declaration</dt>
          <dd className="evidence-id">
            {value.id}
            <small>{value.hash}</small>
            <small>Declared by {value.declared_by}</small>
          </dd>
        </div>
      </dl>
      <Reasons values={value.reason_codes} />
    </div>
  );
}

function ProposalForm({
  registration,
  declaration,
  run,
  busy,
  onCancel,
  onSaved,
}: {
  registration: FleetHistoryRegistration;
  declaration: Declaration;
  run: RunMutation;
  busy: boolean;
  onCancel: () => void;
  onSaved: (id: string) => void;
}) {
  const [scope, setScope] = useState<FleetHistoryScope | null>(null);
  const [error, setError] = useState("");
  return (
    <form
      className="configuration-stack"
      aria-label="Blocked fleet configuration proposal"
      onSubmit={async (event) => {
        event.preventDefault();
        setError("");
        if (!scope) return;
        const body: ProposalSelection = {
          declaration_id: declaration.id,
          scope_id: scope.id,
        };
        const saved = await run({
          path: `/fleet-history-registrations/${query(registration.id)}/configuration-proposals`,
          version: declaration.version,
          body,
          label:
            "Blocked fleet proposal recorded with immutable declaration and history references.",
        });
        if (saved) onSaved(saved.id);
        else
          setError(
            "Proposal was not recorded. Review the API error; registration, declaration or source bindings may have changed. Refresh before selecting evidence again.",
          );
      }}
    >
      <h4>Select evidence for a blocked fleet proposal</h4>
      <p className="form-note">
        Declaration revision {declaration.version} · {shortId(declaration.id)}.
        The request sends only this declaration ID and one stored scope ID. The
        server rechecks bindings and source state. An individual-resource
        capacity assessment cannot establish fleet capacity.
      </p>
      <RemotePage<FleetHistoryScope>
        path={`/fleet-history-scopes?registration_id=${query(registration.id)}&limit=10`}
        label="Fleet proposal scope options"
        empty="Capture a history scope for this registered fleet before recording a blocked proposal."
      >
        {(items) => (
          <Table
            scrollLabel="Fleet history scope selection for blocked proposal"
            headings={[
              "Select",
              "Captured period / scope",
              "Recorded observations",
              "Binding",
            ]}
          >
            {items.map((item) => {
              const matches =
                item.registration_id === registration.id &&
                item.registration_version === registration.version &&
                item.registration_hash === registration.hash;
              return (
                <tr key={item.id}>
                  <td>
                    <input
                      type="radio"
                      name="fleet-proposal-scope"
                      aria-label={`Select fleet proposal scope ${item.id}`}
                      disabled={!matches}
                      checked={scope?.id === item.id}
                      onChange={() => setScope(item)}
                    />
                  </td>
                  <td>
                    <time dateTime={item.start}>{item.start}</time> —{" "}
                    <time dateTime={item.end}>{item.end}</time>
                    <small>UTC · end exclusive</small>
                    <small className="evidence-id">{item.id}</small>
                  </td>
                  <td>
                    {item.selected_observation_count} selected native points
                    <small>
                      {item.demand_receipt_count} guarded Completed-field
                      receipts
                    </small>
                    <small>
                      Complete-window total:{" "}
                      {item.demand.window_units ?? "Unavailable"}{" "}
                      {item.demand.unit}
                    </small>
                  </td>
                  <td>
                    <Badge value={item.status} />
                    <small>
                      {matches
                        ? "Matches selected registration revision"
                        : "Historical or different registration; refresh evidence"}
                    </small>
                  </td>
                </tr>
              );
            })}
          </Table>
        )}
      </RemotePage>
      <p className="form-note">
        A blocked scope may be selected to retain its blockers. Selection does
        not prove work preservation, historical membership, native capacity,
        price or execution readiness.
      </p>
      {error && (
        <p role="alert" className="blocker-text">
          {error}
        </p>
      )}
      <div className="modal-actions">
        <Button secondary type="button" onClick={onCancel}>
          Cancel fleet proposal
        </Button>
        <Button type="submit" pending={busy} disabled={!scope}>
          Record blocked fleet proposal
        </Button>
      </div>
    </form>
  );
}

function ProposalEvidence({
  registrationID,
  id,
}: {
  registrationID: string;
  id: string;
}) {
  const state = useRemote<Proposal>(
    `/fleet-history-registrations/${query(registrationID)}/configuration-proposals/${query(id)}`,
  );
  if (state.loading)
    return <p role="status">Loading immutable fleet proposal…</p>;
  if (state.error)
    return (
      <p role="alert" className="blocker-text">
        Fleet proposal unavailable. {state.error}
      </p>
    );
  if (!state.value) return null;
  const value = state.value;
  return (
    <section
      className="configuration-stack"
      aria-label={`Immutable fleet configuration proposal ${value.id}`}
    >
      <h4>Immutable fleet proposal evidence</h4>
      <div className="readiness-summary">
        <Badge value={value.status} />
        <span>Captured {dateTime(value.as_of)} · execution disabled</span>
      </div>
      <p className="form-note">
        This is the publication-time snapshot. Reading it does not revalidate
        current source state or attest a Terraform mapping. No executable plan
        or savings claim was created.
      </p>
      <dl className="definition-list">
        <div>
          <dt>Group</dt>
          <dd className="evidence-id">
            {value.asg_arn}
            <small>
              {value.binding.account_id} · {value.binding.region}
            </small>
            <small>
              Registration {value.registration_id} · revision{" "}
              {value.registration_version}
            </small>
            <small>{value.registration_hash}</small>
          </dd>
        </div>
        <div>
          <dt>Declaration</dt>
          <dd className="evidence-id">
            {value.declaration_id} · revision {value.declaration_version}
            <small>{value.declaration_hash}</small>
          </dd>
        </div>
        <div>
          <dt>History scope</dt>
          <dd className="evidence-id">
            {value.scope_id}
            <small>{value.scope_hash}</small>
            <small>Reference root {value.scope_reference_root}</small>
          </dd>
        </div>
        <div>
          <dt>Independent definition</dt>
          <dd className="evidence-id">
            {value.definition_id} · revision {value.definition_version}
            <small>{value.definition_hash}</small>
          </dd>
        </div>
        <div>
          <dt>Recorded historical period</dt>
          <dd>
            <time dateTime={value.history_start}>{value.history_start}</time> —{" "}
            <time dateTime={value.history_end}>{value.history_end}</time>
            <small>UTC · end exclusive</small>
            <small>
              {value.selected_observation_count} selected /{" "}
              {value.observation_count} recorded points
            </small>
            <small>{readable(value.membership_status)}</small>
          </dd>
        </div>
        <div>
          <dt>Estimated / verified savings</dt>
          <dd>
            Unavailable / unavailable
            <small>No financial or execution authority</small>
          </dd>
        </div>
        <div>
          <dt>Proposal receipt</dt>
          <dd className="evidence-id">
            {value.id}
            <small>{value.hash}</small>
            <small>Proposed by {value.proposed_by}</small>
          </dd>
        </div>
      </dl>
      <details>
        <summary>Source state captured for this proposal</summary>
        <Table
          scrollLabel="Captured fleet proposal source states"
          headings={["Source", "Captured state", "Configuration / checked at"]}
        >
          {value.source_states.map((source) => (
            <tr key={`${source.source_system}:${source.source_id}`}>
              <td className="evidence-id">
                {source.source_id}
                <small>{source.source_system}</small>
              </td>
              <td>
                {readable(source.status)}
                <small>
                  {source.source_registration_version == null
                    ? source.source_system === "ACTIVITY_SOURCE"
                      ? "Guarded activity has no registry version"
                      : "Source revision unavailable"
                    : `Source revision ${source.source_registration_version}`}
                </small>
              </td>
              <td className="evidence-id">
                {source.config_hash}
                <small>{dateTime(source.checked_at)}</small>
              </td>
            </tr>
          ))}
        </Table>
      </details>
      <Reasons values={value.reason_codes} />
    </section>
  );
}

function ConfigurationContent({ registration, run, busy, refresh }: Props) {
  const [revision, setRevision] = useState(0);
  const [form, setForm] = useState<"declaration" | "proposal" | null>(null);
  const [proposalID, setProposalID] = useState("");
  const base = `/fleet-history-registrations/${query(registration.id)}`;
  const declarations = useRemote<DeclarationPage>(
    `${base}/configuration-authorities?limit=10`,
    refresh + revision,
  );
  const saved = () => {
    setRevision((value) => value + 1);
    setForm(null);
  };
  if (declarations.loading)
    return <p role="status">Loading fleet configuration declarations…</p>;
  if (declarations.error)
    return (
      <div className="configuration-stack">
        <p role="alert" className="blocker-text">
          Fleet configuration unavailable. {declarations.error}
        </p>
        <Button
          secondary
          small
          onClick={() => setRevision((value) => value + 1)}
        >
          Retry fleet configuration
        </Button>
      </div>
    );
  const page = declarations.value;
  if (
    !page ||
    !Array.isArray(page.items) ||
    !Number.isInteger(page.version) ||
    !(page.latest === null || page.latest?.id)
  )
    return (
      <p role="alert" className="blocker-text">
        Fleet configuration unavailable. The API returned an incomplete revision
        page.
      </p>
    );
  const latest = page.latest;
  const matches = Boolean(
    latest &&
    latest.registration_id === registration.id &&
    latest.registration_version === registration.version &&
    latest.registration_hash === registration.hash,
  );
  return (
    <div className="configuration-stack">
      <p className="form-note">
        Selected registration revision {registration.version} ·{" "}
        {registration.registration.fleet_id}. The server resolves exact group
        bindings for each write. These declarations remain separate from native
        attestation and individual-resource capacity.
      </p>
      {latest ? (
        <DeclarationEvidence value={latest} />
      ) : (
        <Empty
          title="No fleet configuration declaration"
          text="Declare Terraform group metadata against this registered ASG. Independent Git, state, address-mapping and pipeline attestations remain required."
        />
      )}
      {latest && !matches && (
        <p className="blocker-text">
          The latest declaration was captured against a different registration
          revision. Its immutable history remains readable. Save a new
          declaration for the selected registration before proposing a review.
        </p>
      )}
      <div className="row-actions">
        <Button
          secondary
          small
          disabled={busy}
          onClick={() => setForm("declaration")}
        >
          {latest
            ? "Revise fleet declaration"
            : "Declare fleet Terraform metadata"}
        </Button>
        <Button
          secondary
          small
          disabled={busy || !matches}
          onClick={() => setForm("proposal")}
        >
          Review fleet proposal evidence
        </Button>
        <Button
          secondary
          small
          disabled={busy}
          onClick={() => setRevision((value) => value + 1)}
        >
          Refresh fleet configuration
        </Button>
      </div>
      {form === "declaration" && (
        <DeclarationForm
          key={`declaration:${page.version}`}
          registration={registration}
          latest={latest}
          version={page.version}
          run={run}
          busy={busy}
          onCancel={() => setForm(null)}
          onSaved={saved}
        />
      )}
      {form === "proposal" && latest && matches && (
        <ProposalForm
          key={`proposal:${latest.id}`}
          registration={registration}
          declaration={latest}
          run={run}
          busy={busy}
          onCancel={() => setForm(null)}
          onSaved={(id) => {
            saved();
            setProposalID(id);
          }}
        />
      )}
      <details>
        <summary>Immutable fleet declaration history</summary>
        <RemotePage<Declaration>
          key={`declarations:${refresh}:${revision}`}
          path={`${base}/configuration-authorities?limit=10`}
          label="Fleet declaration revisions"
          empty="No fleet metadata revisions are recorded."
        >
          {(items) => (
            <Table
              scrollLabel="Immutable fleet declaration revisions"
              headings={["Revision / capture", "Declared mapping", "State"]}
            >
              {items.map((item) => (
                <tr key={item.id}>
                  <td>
                    Revision {item.version}
                    <small>{dateTime(item.created_at)}</small>
                    <small className="evidence-id">{item.id}</small>
                  </td>
                  <td className="evidence-id">
                    {item.metadata.terraform.asg_address}
                    <small>
                      {item.metadata.repository.ref} ·{" "}
                      {item.metadata.terraform.workspace}
                    </small>
                    <small>
                      Registration revision {item.registration_version}
                    </small>
                    <small>{item.hash}</small>
                  </td>
                  <td>
                    <Badge value="BLOCKED">Declared, unattested</Badge>
                  </td>
                </tr>
              ))}
            </Table>
          )}
        </RemotePage>
      </details>
      <h4>Blocked fleet configuration proposals</h4>
      <RemotePage<Proposal>
        key={`proposals:${refresh}:${revision}`}
        path={`${base}/configuration-proposals?limit=10`}
        label="Blocked fleet configuration proposals"
        empty="No blocked proposal has been recorded for this fleet. Select a declaration and a stored history scope to retain their blockers."
      >
        {(items) => (
          <Table
            scrollLabel="Blocked fleet configuration proposal history"
            headings={[
              "Proposal / captured at",
              "Immutable inputs",
              "Status / financial result",
            ]}
          >
            {items.map((item) => (
              <tr key={item.id}>
                <td className="evidence-id">
                  {shortId(item.id)}
                  <small>{dateTime(item.as_of)}</small>
                  <Button
                    secondary
                    small
                    onClick={() => setProposalID(item.id)}
                  >
                    Inspect fleet proposal {shortId(item.id)}
                  </Button>
                </td>
                <td className="evidence-id">
                  Declaration {shortId(item.declaration_id)} · v
                  {item.declaration_version}
                  <small>Scope {shortId(item.scope_id)}</small>
                  <small>Registration v{item.registration_version}</small>
                </td>
                <td>
                  <Badge value={item.status} />
                  <small>Estimated savings: unavailable</small>
                  <small>Verified savings: unavailable</small>
                  <small>Execution disabled</small>
                </td>
              </tr>
            ))}
          </Table>
        )}
      </RemotePage>
      {proposalID && (
        <ProposalEvidence
          key={proposalID}
          registrationID={registration.id}
          id={proposalID}
        />
      )}
    </div>
  );
}

export function FleetConfiguration(props: Props) {
  const [open, setOpen] = useState(false);
  return (
    <details
      className="native-section"
      onToggle={(event) => setOpen(event.currentTarget.open)}
    >
      <summary className="native-subheading">
        Fleet configuration declarations & blocked proposals
      </summary>
      <p className="form-note">
        Operator metadata only. A declaration does not attest the group,
        register machine authority, authorize execution or verify savings.
      </p>
      {open && <ConfigurationContent {...props} />}
    </details>
  );
}
