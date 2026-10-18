import { useState } from "react";
import type { components } from "./api.generated";
import type {
  ConfigurationAuthority as Authority,
  ConfigurationAuthorityRequest,
  ConfigurationProposal,
  Dashboard,
  Resource,
  WorkloadSafetyProfile,
} from "./types";
import { RemotePage, useRemote } from "./RemoteData";
import {
  Badge,
  Button,
  Empty,
  Modal,
  Panel,
  Table,
  dateTime,
  readable,
  shortId,
  type RunMutation,
} from "./ui";

type Props = { data: Dashboard; run: RunMutation; busy: boolean };
type AuthorityPage = components["schemas"]["ConfigurationAuthorityPage"];
type Assessment = components["schemas"]["CapacityAssessment"];

function DeclarationForm({
  resource,
  latest,
  version,
  run,
  busy,
  onClose,
  onSaved,
}: {
  resource: Resource;
  latest: Authority | null;
  version: number;
  run: RunMutation;
  busy: boolean;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [repository, setRepository] = useState(
    latest?.repository ?? { url: "", ref: "", directory: "." },
  );
  const [pipeline, setPipeline] = useState<
    ConfigurationAuthorityRequest["pipeline"]
  >(
    latest?.pipeline ?? {
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
    latest?.terraform ?? {
      workspace: "",
      state_lineage: "",
      addresses: [] as string[],
    },
  );
  const [addresses, setAddresses] = useState(terraform.addresses.join("\n"));
  const [error, setError] = useState("");
  const input = (
    label: string,
    value: string,
    update: (v: string) => void,
    options: {
      maxLength?: number;
      pattern?: string;
      type?: string;
      placeholder?: string;
    } = {},
  ) => (
    <label className="field">
      <span>{label}</span>
      <input
        required
        maxLength={options.maxLength ?? 512}
        value={value}
        onChange={(event) => update(event.target.value)}
        {...options}
      />
    </label>
  );
  return (
    <Modal
      title="Declare Terraform configuration authority"
      subtitle={`${resource.name} · revision ${version + 1}`}
      onClose={onClose}
    >
      <form
        className="configuration-stack"
        onSubmit={async (event) => {
          event.preventDefault();
          setError("");
          const selected = addresses
            .split(/\r?\n/)
            .map((address) => address.trim())
            .filter(Boolean);
          if (
            selected.length < 1 ||
            selected.length > 32 ||
            new Set(selected).size !== selected.length
          ) {
            setError(
              "Provide between 1 and 32 unique managed-resource addresses, one per line.",
            );
            return;
          }
          const body: ConfigurationAuthorityRequest = {
            schema_version: "1",
            authority: "TERRAFORM",
            repository,
            pipeline,
            terraform: { ...terraform, addresses: selected },
          };
          const result = await run({
            path: `/resources/${resource.id}/configuration-authorities`,
            version,
            body,
            label:
              "Configuration ownership declared; machine attestation is still required.",
          });
          if (result) onSaved();
          else
            setError(
              "Declaration was not saved. Review the API error and refresh before retrying a changed revision.",
            );
        }}
      >
        <p className="form-note">
          This immutable revision records operator metadata bound to the current
          resource. Repository URLs are metadata only. Provide no tokens,
          passwords, state contents or other secrets.
        </p>
        <fieldset className="days-fieldset">
          <legend>Repository declaration</legend>
          {input(
            "Repository HTTPS URL",
            repository.url,
            (url) => setRepository({ ...repository, url }),
            {
              type: "url",
              maxLength: 2048,
              placeholder: "https://github.com/organisation/infrastructure",
            },
          )}
          {input(
            "Declared Git branch or tag",
            repository.ref,
            (ref) => setRepository({ ...repository, ref }),
            { maxLength: 255 },
          )}
          {input(
            "Repository relative directory",
            repository.directory,
            (directory) => setRepository({ ...repository, directory }),
          )}
          <p className="form-note">
            The declared branch or tag does not attest a commit. Use a dot for
            the repository root.
          </p>
        </fieldset>
        <fieldset className="days-fieldset">
          <legend>Dedicated deployment pipeline identity</legend>
          <label className="field">
            <span>Pipeline system</span>
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
          {input(
            "Pipeline issuer HTTPS URL",
            pipeline.identity.issuer,
            (issuer) =>
              setPipeline({
                ...pipeline,
                identity: { ...pipeline.identity, issuer },
              }),
            { type: "url", maxLength: 2048 },
          )}
          <label className="field">
            <span>Dedicated pipeline audience</span>
            <input readOnly value="finops-deployment-observer" />
          </label>
          {input(
            "Exact pipeline machine subject",
            pipeline.identity.subject,
            (subject) =>
              setPipeline({
                ...pipeline,
                identity: { ...pipeline.identity, subject },
              }),
          )}
          {input(
            "Stable pipeline identifier",
            pipeline.identity.pipeline_id,
            (pipeline_id) =>
              setPipeline({
                ...pipeline,
                identity: { ...pipeline.identity, pipeline_id },
              }),
            { maxLength: 256 },
          )}
          <p className="form-note">
            Identity is a declaration awaiting separate authenticated machine
            observation. Console, activity and telemetry credentials cannot
            attest deployment authority.
          </p>
        </fieldset>
        <fieldset className="days-fieldset">
          <legend>Declared Terraform state mapping</legend>
          {input(
            "Terraform workspace",
            terraform.workspace,
            (workspace) => setTerraform({ ...terraform, workspace }),
            { maxLength: 128, pattern: "[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}" },
          )}
          {input(
            "Declared Terraform state lineage UUID",
            terraform.state_lineage,
            (state_lineage) => setTerraform({ ...terraform, state_lineage }),
            {
              maxLength: 36,
              pattern:
                "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            },
          )}
          <label className="field">
            <span>Managed Terraform resource addresses</span>
            <textarea
              aria-label="Managed Terraform resource addresses"
              required
              maxLength={16416}
              rows={4}
              value={addresses}
              onChange={(event) => setAddresses(event.target.value)}
              placeholder={'module.api["dev"].aws_instance.api[0]'}
            />
          </label>
          <p className="form-note">
            One exact address per line, up to 32. Indexed module paths are
            supported. Data sources and wildcard mappings are rejected. Lineage
            and state serial require independent observation before trust.
          </p>
        </fieldset>
        <label className="checkbox-field">
          <input required type="checkbox" />
          <span>
            I acknowledge that this declaration remains unattested and grants no
            execution or merge permission.
          </span>
        </label>
        {error && (
          <p role="alert" className="blocker-text">
            {error}
          </p>
        )}
        <div className="modal-actions">
          <Button secondary type="button" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" pending={busy}>
            Save ownership declaration
          </Button>
        </div>
      </form>
    </Modal>
  );
}

function AuthorityEvidence({ authority }: { authority: Authority }) {
  return (
    <div className="configuration-stack">
      <div className="readiness-summary">
        <Badge value="BLOCKED">Declared, unattested</Badge>
        <span>
          Revision {authority.version} · {dateTime(authority.created_at)}
        </span>
      </div>
      <p className="form-note">
        Operator declaration is a manual trust boundary. Separate machine
        observations of the pipeline, repository commit and Terraform state are
        required. Execution remains disabled.
      </p>
      <Table
        scrollLabel="Scrollable configuration authority binding"
        headings={["Declared configuration", "Exact value"]}
      >
        <tr>
          <td>Provider resource</td>
          <td className="evidence-id">
            {authority.binding.provider_resource_id}
            <small>
              {authority.binding.provider} · {authority.binding.account_id} ·{" "}
              {authority.binding.region}
            </small>
          </td>
        </tr>
        <tr>
          <td>Resource revision</td>
          <td>
            {authority.binding.resource_version}
            <small className="evidence-id">
              {authority.binding.resource_snapshot_hash}
            </small>
          </td>
        </tr>
        <tr>
          <td>Repository / declared ref</td>
          <td className="evidence-id">
            {authority.repository.url}
            <small>
              {authority.repository.ref} · {authority.repository.directory}
            </small>
          </td>
        </tr>
        <tr>
          <td>Pipeline identity</td>
          <td className="evidence-id">
            {authority.pipeline.identity.subject}
            <small>{authority.pipeline.identity.issuer}</small>
            <small>
              {authority.pipeline.identity.audience} ·{" "}
              {authority.pipeline.identity.pipeline_id}
            </small>
          </td>
        </tr>
        <tr>
          <td>Terraform state declaration</td>
          <td>
            {authority.terraform.workspace}
            <small className="evidence-id">
              {authority.terraform.state_lineage}
            </small>
            {authority.terraform.addresses.map((address) => (
              <small className="evidence-id" key={address}>
                {address}
              </small>
            ))}
          </td>
        </tr>
        <tr>
          <td>Observed commit / state serial</td>
          <td>Unavailable — independent machine observation required</td>
        </tr>
        <tr>
          <td>Revision evidence</td>
          <td className="evidence-id">
            {authority.id}
            <small>{authority.hash}</small>
            <small>Declared by {authority.declared_by}</small>
          </td>
        </tr>
      </Table>
      <ul className="blocker-list">
        {authority.reason_codes.map((reason) => (
          <li key={reason}>{readable(reason)}</li>
        ))}
      </ul>
    </div>
  );
}

function ProposalForm({
  resource,
  authority,
  run,
  busy,
  onClose,
  onSaved,
}: {
  resource: Resource;
  authority: Authority;
  run: RunMutation;
  busy: boolean;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [assessmentID, setAssessmentID] = useState("");
  const [error, setError] = useState("");
  const profile = useRemote<{ latest: WorkloadSafetyProfile | null }>(
    `/workloads/${resource.workload_id}/safety-profiles?limit=1`,
  );
  return (
    <Modal
      title="Record a blocked configuration proposal"
      subtitle={resource.name}
      onClose={onClose}
    >
      <form
        className="configuration-stack"
        onSubmit={async (event) => {
          event.preventDefault();
          setError("");
          if (!assessmentID) {
            setError(
              "Select an existing capacity assessment for this resource and the current safety requirements.",
            );
            return;
          }
          const result = await run({
            path: `/workloads/${resource.workload_id}/configuration-proposals`,
            version: authority.version,
            body: {
              authority_id: authority.id,
              capacity_assessment_id: assessmentID,
            },
            label:
              "Blocked configuration proposal recorded with immutable evidence references.",
          });
          if (result) onSaved();
          else
            setError(
              "Proposal was not recorded. Refresh if the resource, declaration, requirements or source has changed.",
            );
        }}
      >
        <p className="form-note">
          The server selects evidence from existing records and rechecks current
          bindings. This increment records blockers for review; it creates no
          patch, executable plan or savings claim.
        </p>
        {profile.loading ? (
          <p role="status">Loading current safety requirements…</p>
        ) : profile.error ? (
          <p role="alert" className="blocker-text">
            Current requirements unavailable. {profile.error}
          </p>
        ) : !profile.value?.latest ? (
          <p className="blocker-text">
            Declare workload safety requirements before selecting a capacity
            assessment.
          </p>
        ) : (
          <>
            <p className="form-note">
              Current safety profile revision {profile.value.latest.version} ·{" "}
              {shortId(profile.value.latest.id)}
            </p>
            <RemotePage<Assessment>
              path={`/workloads/${resource.workload_id}/capacity-assessments?limit=20`}
              label="Capacity assessments for proposal"
              empty="Assess native capacity evidence from a registered source before recording a configuration proposal."
            >
              {(assessments) => (
                <Table
                  scrollLabel="Scrollable capacity assessment selection"
                  headings={[
                    "Select",
                    "Assessment / resource",
                    "Safety profile",
                    "Status",
                  ]}
                >
                  {assessments.map((assessment) => {
                    const matches =
                      assessment.resource_id === resource.id &&
                      assessment.safety_profile_id ===
                        profile.value?.latest?.id &&
                      assessment.safety_profile_hash ===
                        profile.value?.latest?.hash;
                    return (
                      <tr key={assessment.id}>
                        <td>
                          <input
                            type="radio"
                            name="capacity-assessment"
                            aria-label={`Select capacity assessment ${assessment.id}`}
                            disabled={!matches}
                            checked={assessmentID === assessment.id}
                            onChange={() => setAssessmentID(assessment.id)}
                          />
                        </td>
                        <td className="evidence-id">
                          {assessment.id}
                          <small>{assessment.resource_id}</small>
                        </td>
                        <td>
                          Revision {assessment.safety_profile_version}
                          <small>
                            {matches
                              ? "Resource and requirements match"
                              : "Different resource or historical requirements"}
                          </small>
                        </td>
                        <td>
                          <Badge value={assessment.status} />{" "}
                          <small>Money unavailable</small>
                        </td>
                      </tr>
                    );
                  })}
                </Table>
              )}
            </RemotePage>
          </>
        )}
        {error && (
          <p role="alert" className="blocker-text">
            {error}
          </p>
        )}
        <div className="modal-actions">
          <Button secondary type="button" onClick={onClose}>
            Cancel
          </Button>
          <Button
            type="submit"
            pending={busy}
            disabled={!assessmentID || !profile.value?.latest}
          >
            Record blocked proposal
          </Button>
        </div>
      </form>
    </Modal>
  );
}

function ResourceAuthority({
  resource,
  run,
  busy,
}: {
  resource: Resource;
  run: RunMutation;
  busy: boolean;
}) {
  const [refresh, setRefresh] = useState(0);
  const [form, setForm] = useState<"declaration" | "proposal" | null>(null);
  const path = `/resources/${resource.id}/configuration-authorities?limit=20`;
  const authority = useRemote<AuthorityPage>(path, refresh);
  const saved = () => {
    setRefresh((value) => value + 1);
    setForm(null);
  };
  return (
    <div className="configuration-stack">
      <p className="form-note">
        Inventory reports {readable(resource.configuration_authority)}.
        Declarations below are stored separately and do not change runtime
        stop/start delegation.
      </p>
      {authority.loading ? (
        <p role="status">Loading configuration declarations…</p>
      ) : authority.error ? (
        <p role="alert" className="blocker-text">
          Configuration authority unavailable. {authority.error}
        </p>
      ) : !authority.value ||
        !Array.isArray(authority.value.items) ||
        !Number.isInteger(authority.value.version) ||
        !(authority.value.latest === null || authority.value.latest?.id) ? (
        <p role="alert" className="blocker-text">
          Configuration authority unavailable. The API returned an incomplete
          revision page.
        </p>
      ) : (
        <>
          {authority.value.latest ? (
            <AuthorityEvidence authority={authority.value.latest} />
          ) : (
            <Empty
              title="Configuration ownership is unobserved"
              text="An operator may declare Terraform ownership metadata. Independent pipeline and state observations remain required before any configuration execution."
            />
          )}
          <div className="configuration-actions">
            <Button
              secondary
              disabled={busy}
              onClick={() => setForm("declaration")}
            >
              {authority.value.latest
                ? "Revise ownership declaration"
                : "Declare Terraform ownership"}
            </Button>
            {authority.value.latest && (
              <Button
                secondary
                disabled={busy}
                onClick={() => setForm("proposal")}
              >
                Review proposal evidence
              </Button>
            )}
          </div>
          <details>
            <summary className="native-subheading">
              Immutable ownership declaration history
            </summary>
            <RemotePage<Authority>
              key={`authority-${refresh}`}
              path={path}
              label="Ownership declarations"
              empty="No ownership declarations have been recorded."
            >
              {(rows) => (
                <Table
                  scrollLabel="Scrollable ownership declaration history"
                  headings={["Revision", "Declaration", "Status"]}
                >
                  {rows.map((row) => (
                    <tr key={row.id}>
                      <td>
                        {row.version}
                        <small>{dateTime(row.created_at)}</small>
                      </td>
                      <td className="evidence-id">
                        {row.id}
                        <small>
                          {row.repository.ref} · {row.terraform.workspace}
                        </small>
                        <small>{row.hash}</small>
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
          {form === "declaration" && (
            <DeclarationForm
              resource={resource}
              latest={authority.value.latest}
              version={authority.value.version}
              run={run}
              busy={busy}
              onClose={() => setForm(null)}
              onSaved={saved}
            />
          )}
          {form === "proposal" && authority.value.latest && (
            <ProposalForm
              resource={resource}
              authority={authority.value.latest}
              run={run}
              busy={busy}
              onClose={() => setForm(null)}
              onSaved={saved}
            />
          )}
        </>
      )}
      <h3 className="native-subheading">Blocked configuration proposals</h3>
      <RemotePage<ConfigurationProposal>
        key={`proposals-${refresh}`}
        path={`/workloads/${resource.workload_id}/configuration-proposals?limit=20`}
        label="Configuration proposals"
        empty="No blocked proposals have been recorded for this workload."
      >
        {(rows) => (
          <Table
            scrollLabel="Scrollable configuration proposals"
            headings={[
              "Proposal / resource",
              "Immutable evidence",
              "Status / money",
            ]}
          >
            {rows.map((row) => (
              <tr key={row.id}>
                <td className="evidence-id">
                  {row.id}
                  <small>{row.resource_id}</small>
                  <small>{dateTime(row.created_at)}</small>
                </td>
                <td>
                  <small className="evidence-id">
                    Authority {row.authority_id} · v{row.authority_version}
                  </small>
                  <small className="evidence-id">
                    Assessment {row.capacity_assessment_id}
                  </small>
                  <small className="evidence-id">
                    Profile {row.safety_profile_id} · v
                    {row.safety_profile_version}
                  </small>
                  <details>
                    <summary>Evidence bindings and blockers</summary>
                    <p className="evidence-id">
                      Authority {row.authority_hash}
                      <br />
                      Assessment {row.capacity_assessment_hash}
                      <br />
                      Population {row.population_hash}
                      <br />
                      Native configuration {row.config_hash}
                      <br />
                      Proposal {row.hash}
                    </p>
                    <ul className="blocker-list">
                      {row.reason_codes.map((reason) => (
                        <li key={reason}>{readable(reason)}</li>
                      ))}
                    </ul>
                  </details>
                </td>
                <td>
                  <Badge value={row.status} />
                  <small>Estimated savings: unavailable</small>
                  <small>Verified savings: unavailable</small>
                  <small>Execution disabled</small>
                </td>
              </tr>
            ))}
          </Table>
        )}
      </RemotePage>
    </div>
  );
}

export function ConfigurationAuthority({ data, run, busy }: Props) {
  const [workloadID, setWorkloadID] = useState(data.workloads[0]?.id ?? "");
  const workload = data.workloads.find((item) => item.id === workloadID);
  const resources = data.resources.filter(
    (item) => item.workload_id === workload?.id,
  );
  const [resourceID, setResourceID] = useState("");
  const resource =
    resources.find((item) => item.id === resourceID) ?? resources[0];
  return (
    <Panel
      title="Configuration ownership & proposal evidence"
      className="configuration-authority"
    >
      <p className="form-note">
        Declare Terraform ownership and retain blocked evidence reviews while
        independent deployment attestation remains unavailable.
      </p>
      {!data.workloads.length ? (
        <Empty
          title="No workloads available"
          text="Discover resources and map their ownership before declaring configuration authority."
        />
      ) : (
        <div className="configuration-stack">
          <label className="field">
            <span>Configuration authority workload</span>
            <select
              value={workload?.id ?? ""}
              onChange={(event) => {
                setWorkloadID(event.target.value);
                setResourceID("");
              }}
            >
              {data.workloads.map((item) => (
                <option key={item.id} value={item.id}>
                  {item.name}
                </option>
              ))}
            </select>
          </label>
          {!resource ? (
            <Empty
              title="No resources in this workload"
              text="A declaration requires an exact discovered provider resource, account and region binding."
            />
          ) : (
            <>
              <label className="field">
                <span>Configuration authority resource</span>
                <select
                  value={resource.id}
                  onChange={(event) => setResourceID(event.target.value)}
                >
                  {resources.map((item) => (
                    <option key={item.id} value={item.id}>
                      {item.name || item.provider_resource_id}
                    </option>
                  ))}
                </select>
              </label>
              <ResourceAuthority
                key={`${workload?.id}:${resource.id}`}
                resource={resource}
                run={run}
                busy={busy}
              />
            </>
          )}
        </div>
      )}
    </Panel>
  );
}
