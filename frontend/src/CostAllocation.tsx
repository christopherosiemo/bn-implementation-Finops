import { useState } from "react";
import type { components } from "./api.generated";
import type { Dashboard } from "./types";
import { RemotePage, useRemote } from "./RemoteData";
import {
  Badge,
  Button,
  Empty,
  Modal,
  Panel,
  Table,
  dateTime,
  matches,
  readable,
  shortId,
  type RunMutation,
} from "./ui";

type Policy = components["schemas"]["AllocationPolicy"];
type Definition = components["schemas"]["AllocationPolicyDefinition"];
type Report = components["schemas"]["AllocationReport"];
type ImportSource = components["schemas"]["AllocationImportSource"];
type Props = {
  data: Dashboard;
  run: RunMutation;
  busy: boolean;
  query: string;
};

// Preserve all supplied DECIMAL(38,12) digits, including the smallest allocated
// residual. Converting to Number would lose cents on large observed amounts.
function amount(value: string | null, currency: string) {
  if (value === null) return "Unavailable";
  const match = /^(-?)(\d+)(?:\.(\d{1,12}))?$/.exec(value);
  if (!match) return "Unavailable";
  const fraction = (match[3] || "").replace(/0+$/, "").padEnd(2, "0");
  return `${currency} ${match[1]}${match[2].replace(/\B(?=(\d{3})+(?!\d))/g, ",")}.${fraction}`;
}

function PolicyEditor({
  data,
  latest,
  version,
  run,
  busy,
  onClose,
  onSaved,
}: Props & {
  latest: Policy | null;
  version: number;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [name, setName] = useState(
    latest?.definition.name || "Current ownership allocation",
  );
  const [rules, setRules] = useState<Definition["rules"]>(() =>
    latest ? structuredClone(latest.definition.rules) : [],
  );
  const [error, setError] = useState("");
  const update = (index: number, patch: Partial<Definition["rules"][number]>) =>
    setRules((current) =>
      current.map((rule, at) => (at === index ? { ...rule, ...patch } : rule)),
    );
  return (
    <Modal
      title="Save allocation policy revision"
      subtitle={`Current version ${version} · immutable analytical mapping`}
      onClose={onClose}
    >
      <form
        className="allocation-form"
        onSubmit={async (event) => {
          event.preventDefault();
          setError("");
          const selected = new Set<string>();
          for (const rule of rules) {
            if (
              !rule.resource_ids.length ||
              !rule.recipients.length ||
              rule.resource_ids.some((id) => selected.has(id))
            ) {
              setError(
                "Select resources once across the policy, with at least one recipient per rule.",
              );
              return;
            }
            rule.resource_ids.forEach((id) => selected.add(id));
            if (
              new Set(rule.recipients.map((target) => target.workload_id))
                .size !== rule.recipients.length ||
              rule.recipients.some(
                (target) =>
                  !target.workload_id ||
                  !Number.isInteger(target.weight_ppm) ||
                  target.weight_ppm < 1 ||
                  target.weight_ppm > 1_000_000,
              ) ||
              rule.recipients.reduce(
                (sum, target) => sum + target.weight_ppm,
                0,
              ) !== 1_000_000
            ) {
              setError(
                "Each rule needs distinct workloads with positive integer shares totaling exactly 1,000,000 ppm.",
              );
              return;
            }
          }
          const definition: Definition = {
            schema_version: "1",
            name: name.trim(),
            rules,
          };
          if (
            await run({
              path: "/allocation-policies",
              version,
              body: definition,
              label: "Immutable allocation policy revision saved.",
            })
          )
            onSaved();
          else
            setError(
              "Policy was not saved. Check financial permissions and refresh if the current revision changed.",
            );
        }}
      >
        <p className="form-note">
          Without fixed shares, a matched resource uses its current inventory
          workload. Missing ownership stays unallocated. This policy makes no
          historical ownership or savings claim.
        </p>
        <label className="field">
          <span>Allocation policy name</span>
          <input
            required
            maxLength={80}
            value={name}
            onChange={(event) => setName(event.target.value)}
          />
        </label>
        {rules.map((rule, index) => (
          <fieldset className="allocation-rule" key={index}>
            <legend>Fixed share rule {index + 1}</legend>
            <label className="field">
              <span>Resources for rule {index + 1}</span>
              <select
                required
                multiple
                size={Math.min(4, Math.max(2, data.resources.length))}
                value={rule.resource_ids}
                onChange={(event) =>
                  update(index, {
                    resource_ids: Array.from(
                      event.target.selectedOptions,
                      (option) => option.value,
                    ),
                  })
                }
              >
                {data.resources.map((resource) => (
                  <option key={resource.id} value={resource.id}>
                    {resource.name} · {resource.provider_resource_id}
                  </option>
                ))}
              </select>
            </label>
            <p className="form-note">
              Select one or more resources. Each resource can appear in one
              rule.
            </p>
            {rule.recipients.map((target, recipientIndex) => (
              <div className="allocation-recipient" key={recipientIndex}>
                <label className="field">
                  <span>{`Rule ${index + 1} recipient ${recipientIndex + 1}`}</span>
                  <select
                    required
                    value={target.workload_id}
                    onChange={(event) =>
                      update(index, {
                        recipients: rule.recipients.map((recipient, at) =>
                          at === recipientIndex
                            ? { ...recipient, workload_id: event.target.value }
                            : recipient,
                        ),
                      })
                    }
                  >
                    <option value="">Select workload</option>
                    {data.workloads.map((workload) => (
                      <option key={workload.id} value={workload.id}>
                        {workload.name}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="field">
                  <span>{`Rule ${index + 1} share ${recipientIndex + 1} (ppm)`}</span>
                  <input
                    type="number"
                    required
                    min={1}
                    max={1_000_000}
                    step={1}
                    value={target.weight_ppm}
                    onChange={(event) =>
                      update(index, {
                        recipients: rule.recipients.map((recipient, at) =>
                          at === recipientIndex
                            ? {
                                ...recipient,
                                weight_ppm: Number(event.target.value),
                              }
                            : recipient,
                        ),
                      })
                    }
                  />
                </label>
                <Button
                  type="button"
                  secondary
                  small
                  aria-label={`Remove rule ${index + 1} recipient ${recipientIndex + 1}`}
                  onClick={() =>
                    update(index, {
                      recipients: rule.recipients.filter(
                        (_, at) => at !== recipientIndex,
                      ),
                    })
                  }
                >
                  Remove
                </Button>
              </div>
            ))}
            <div className="configuration-actions">
              <Button
                type="button"
                small
                secondary
                disabled={rule.recipients.length >= 100}
                onClick={() =>
                  update(index, {
                    recipients: [
                      ...rule.recipients,
                      { workload_id: "", weight_ppm: 1_000_000 },
                    ],
                  })
                }
              >
                Add recipient to rule {index + 1}
              </Button>
              <Button
                type="button"
                secondary
                small
                onClick={() =>
                  setRules((current) => current.filter((_, at) => at !== index))
                }
              >
                Remove rule {index + 1}
              </Button>
            </div>
          </fieldset>
        ))}
        <Button
          type="button"
          secondary
          small
          disabled={
            !data.resources.length ||
            !data.workloads.length ||
            rules.length >= 100
          }
          onClick={() =>
            setRules((current) => [
              ...current,
              {
                resource_ids: [],
                recipients: [{ workload_id: "", weight_ppm: 1_000_000 }],
              },
            ])
          }
        >
          Add fixed share rule
        </Button>
        {error && (
          <p role="alert" className="blocker-text">
            {error}
          </p>
        )}
        <div className="form-footer">
          <span>1,000,000 ppm = 100% · finance scope required</span>
          <Button pending={busy}>Save policy revision</Button>
        </div>
      </form>
    </Modal>
  );
}

function ReportCreator({
  data,
  policy,
  run,
  busy,
  onClose,
  onSaved,
}: Omit<Props, "query"> & {
  policy: Policy;
  onClose: () => void;
  onSaved: (id: string) => void;
}) {
  const [kind, setKind] = useState<"CUSTOMER_IMPORT" | "AWS_CUR2_CONNECTION">(
    "CUSTOMER_IMPORT",
  );
  const [job, setJob] = useState("");
  const [connection, setConnection] = useState("");
  const [month, setMonth] = useState("");
  const [sourceRevision, setSourceRevision] = useState(0);
  const [error, setError] = useState("");
  return (
    <Modal
      title="Create allocation report"
      subtitle={`Policy revision ${policy.version} · current ownership view`}
      onClose={onClose}
    >
      <form
        className="allocation-form"
        onSubmit={async (event) => {
          event.preventDefault();
          setError("");
          if (
            (kind === "CUSTOMER_IMPORT" && !job) ||
            (kind === "AWS_CUR2_CONNECTION" &&
              (!connection || !/^\d{4}-\d{2}$/.test(month)))
          ) {
            setError(
              "Select an available persisted import, or a native connection and exact billing month.",
            );
            return;
          }
          const body: components["schemas"]["AllocationReportRequest"] = {
            policy_id: policy.id,
            source:
              kind === "CUSTOMER_IMPORT"
                ? { kind, ingestion_job_id: job }
                : {
                    kind,
                    source_connection_id: connection,
                    billing_period_start: `${month}-01T00:00:00Z`,
                  },
          };
          const result = await run({
            path: "/allocation-reports",
            version: policy.version,
            body,
            label:
              "Current-ownership allocation snapshot sealed. It is provisional billing analysis.",
          });
          if (result) onSaved(result.id);
          else
            setError(
              "No report was created. Check source availability, financial permissions and the current policy revision.",
            );
        }}
      >
        <p className="form-note">
          The server selects persisted canonical billing facts, inventory
          ownership and source references. Imports and fixtures have unknown
          coverage. Native exports remain provisional; invoice finality and
          verified savings are separate.
        </p>
        <label className="field">
          <span>Allocation billing source</span>
          <select
            value={kind}
            onChange={(event) => setKind(event.target.value as typeof kind)}
          >
            <option value="CUSTOMER_IMPORT">
              Persisted customer import / fixture
            </option>
            <option value="AWS_CUR2_CONNECTION">
              Authenticated AWS CUR 2.0 month
            </option>
          </select>
        </label>
        {kind === "CUSTOMER_IMPORT" ? (
          <>
            <RemotePage<ImportSource>
              key={sourceRevision}
              path="/allocation-sources?limit=20"
              label="Allocation import sources"
              empty="No persisted customer imports or deterministic fixtures are available. Complete billing ingestion first."
            >
              {(items) => (
                <label className="field">
                  <span>Persisted allocation import</span>
                  <select
                    required
                    value={job}
                    onChange={(event) => setJob(event.target.value)}
                  >
                    <option value="">Select persisted source</option>
                    {items.map((source) => (
                      <option
                        key={source.id}
                        value={source.id}
                        disabled={source.status !== "PERSISTED"}
                      >
                        {source.provenance === "DETERMINISTIC_FIXTURE"
                          ? "FIXTURE"
                          : "CUSTOMER IMPORT"}{" "}
                        · {source.source_id} · {source.source_version} ·{" "}
                        {source.status} · {shortId(source.id)}
                      </option>
                    ))}
                  </select>
                </label>
              )}
            </RemotePage>
            <Button
              type="button"
              secondary
              small
              onClick={() => {
                setJob("");
                setSourceRevision((current) => current + 1);
              }}
            >
              Refresh available imports
            </Button>
          </>
        ) : (
          <>
            <label className="field">
              <span>Allocation native billing connection</span>
              <select
                required
                value={connection}
                onChange={(event) => setConnection(event.target.value)}
              >
                <option value="">Select registered CUR 2.0 source</option>
                {data.source_connections?.map((source) => (
                  <option
                    key={source.id}
                    value={source.id}
                    disabled={source.enabled === false}
                  >
                    {source.id} · {source.payer_account_id} · {source.region}
                  </option>
                ))}
              </select>
            </label>
            {!data.source_connections?.length && (
              <p className="form-note">
                Register and synchronize a trusted billing connection in
                Connections & quality first.
              </p>
            )}
            <label className="field">
              <span>Allocation billing month (UTC)</span>
              <input
                required
                type="month"
                value={month}
                onChange={(event) => setMonth(event.target.value)}
              />
            </label>
          </>
        )}
        {error && (
          <p role="alert" className="blocker-text">
            {error}
          </p>
        )}
        <div className="form-footer">
          <span>IDs only · amounts selected by the server</span>
          <Button pending={busy}>Seal allocation report</Button>
        </div>
      </form>
    </Modal>
  );
}

function ReportEvidence({
  id,
  data,
  onClose,
}: {
  id: string;
  data: Dashboard;
  onClose: () => void;
}) {
  const report = useRemote<Report>(
    `/allocation-reports/${encodeURIComponent(id)}`,
  );
  const boundPolicy = useRemote<Policy>(
    report.value
      ? `/allocation-policies/${encodeURIComponent(report.value.policy_id)}`
      : null,
  );
  const resourceName = (resourceID: string | null) =>
    resourceID
      ? data.resources.find((resource) => resource.id === resourceID)?.name ||
        resourceID
      : "Unmatched resource";
  const workloadName = (workloadID: string | null) =>
    workloadID
      ? data.workloads.find((workload) => workload.id === workloadID)?.name ||
        workloadID
      : "Unallocated";
  const value = report.value;
  return (
    <Modal
      title="Allocation report evidence"
      subtitle="Immutable current-ownership snapshot · no verified savings"
      onClose={onClose}
    >
      <div className="allocation-evidence">
        {report.loading ? (
          <p role="status">Loading allocation report…</p>
        ) : report.error ? (
          <p className="blocker-text" role="alert">
            Report unavailable. {report.error}
          </p>
        ) : (
          value && (
            <>
              <div className="configuration-actions">
                <Badge tone="neutral" value={value.status} />
                <Badge tone="neutral" value={value.source.kind}>
                  {value.source.kind === "DETERMINISTIC_FIXTURE"
                    ? "FIXTURE DATA"
                    : readable(value.source.kind)}
                </Badge>
                <span className="form-note">CURRENT_OWNERSHIP_VIEW</span>
              </div>
              <p className="form-note">
                Allocation follows inventory ownership as of{" "}
                {dateTime(value.mapping_as_of)}. Unknown ownership stays
                unallocated. These signed billing amounts do not establish
                historical ownership, invoice finality or savings.
              </p>
              <Table
                scrollLabel="Scrollable allocation currency totals"
                headings={[
                  "Currency",
                  "Observed billed total",
                  "Known subtotal",
                  "Allocated",
                  "Unallocated",
                  "Unknown records",
                ]}
              >
                {value.totals.map((total) => (
                  <tr key={total.currency}>
                    <th scope="row">{total.currency}</th>
                    <td className="money-cell">
                      {amount(total.observed_billed_total, total.currency)}
                    </td>
                    <td className="money-cell">
                      {amount(total.known_billed_subtotal, total.currency)}
                    </td>
                    <td className="money-cell">
                      {amount(total.allocated_subtotal, total.currency)}
                    </td>
                    <td className="money-cell">
                      {amount(total.unallocated_subtotal, total.currency)}
                    </td>
                    <td>{total.unknown_record_count}</td>
                  </tr>
                ))}
              </Table>
              {!value.totals.length && (
                <p className="form-note">
                  No billing observations. No currency total is available.
                </p>
              )}
              <dl className="definition-list allocation-provenance">
                <div>
                  <dt>Report / policy</dt>
                  <dd className="evidence-id">
                    {value.id}
                    <small>{value.policy_id}</small>
                    <small>
                      {boundPolicy.loading
                        ? "Loading bound policy revision…"
                        : boundPolicy.error
                          ? "Bound policy details unavailable"
                          : boundPolicy.value
                            ? `Policy revision ${boundPolicy.value.version} · ${boundPolicy.value.definition.name}`
                            : "Policy revision unavailable"}
                    </small>
                  </dd>
                </div>
                <div>
                  <dt>Source provenance</dt>
                  <dd>
                    {readable(value.source.provenance)}
                    <small>
                      Coverage: {readable(value.source.coverage)} · finality:{" "}
                      {readable(value.source.finality)}
                    </small>
                  </dd>
                </div>
                <div>
                  <dt>Source / version</dt>
                  <dd className="evidence-id">
                    {value.source.source_id}
                    <small>{value.source.source_version}</small>
                  </dd>
                </div>
                <div>
                  <dt>Observation / entry count</dt>
                  <dd>
                    {value.record_count} observations · {value.line_count}{" "}
                    derived entries
                  </dd>
                </div>
                <div>
                  <dt>Mapping as of</dt>
                  <dd>
                    {dateTime(value.mapping_as_of)}
                    <small className="evidence-id">{value.mapping_hash}</small>
                  </dd>
                </div>
                <div>
                  <dt>Source references</dt>
                  <dd className="evidence-id">
                    Job {value.source.ingestion_job_id}
                    {value.source.source_receipt_id && (
                      <small>Receipt {value.source.source_receipt_id}</small>
                    )}
                    {value.source.source_revision_id && (
                      <small>Revision {value.source.source_revision_id}</small>
                    )}
                    {value.source.source_connection_id && (
                      <small>
                        Connection {value.source.source_connection_id}
                      </small>
                    )}
                    {value.source.billing_period_start && (
                      <small>
                        Billing month{" "}
                        {dateTime(value.source.billing_period_start)}
                      </small>
                    )}
                  </dd>
                </div>
              </dl>
              <details className="allocation-hashes">
                <summary>Immutable hashes and qualifications</summary>
                <dl className="definition-list">
                  {Object.entries({
                    "Input hash": value.input_hash,
                    "Result hash": value.result_hash,
                    "Raw source hash": value.source.raw_hash,
                    "Canonical source hash": value.source.canonical_hash,
                    ...(value.source.source_proof_hash
                      ? {
                          "Native source proof hash":
                            value.source.source_proof_hash,
                        }
                      : {}),
                  }).map(([label, hash]) => (
                    <div key={label}>
                      <dt>{label}</dt>
                      <dd className="evidence-id">{hash}</dd>
                    </div>
                  ))}
                </dl>
                <ul className="form-note">
                  {[...value.reason_codes, value.source.reason_code].map(
                    (reason, at) => (
                      <li key={`${reason}-${at}`}>{readable(reason)}</li>
                    ),
                  )}
                </ul>
              </details>
              <section
                className="allocation-collection"
                aria-label="Derived allocation entries"
              >
                <h3>Derived allocation entries</h3>
                <p className="form-note">
                  Shares conserve each known observed amount, including credits.
                  A source charge appears once in observations and may have
                  several derived entries.
                </p>
                <RemotePage<components["schemas"]["AllocationLine"]>
                  path={`/allocation-reports/${encodeURIComponent(id)}/lines?limit=20`}
                  label="Allocation entries"
                  empty="This immutable report has no derived entries."
                >
                  {(items) => (
                    <Table
                      scrollLabel="Scrollable derived allocation entries"
                      headings={[
                        "Source record",
                        "Resource",
                        "Snapshot recipient",
                        "Allocated billed cost",
                        "Mapping",
                      ]}
                    >
                      {items.map((line) => (
                        <tr key={line.id}>
                          <td>
                            <span className="evidence-id">
                              {line.record_id}
                            </span>
                            <small>{shortId(line.source_version)}</small>
                          </td>
                          <td>
                            {resourceName(line.resource_id)}
                            <small>
                              {line.provider_resource_id ||
                                "No native resource ID"}
                            </small>
                          </td>
                          <td>
                            {workloadName(line.workload_id)}
                            {line.workload_id && (
                              <small className="evidence-id">
                                {line.workload_id}
                              </small>
                            )}
                          </td>
                          <td className="money-cell">
                            {amount(line.allocated_billed_cost, line.currency)}
                          </td>
                          <td>
                            {readable(line.method)}
                            <small>{readable(line.reason_code)}</small>
                          </td>
                        </tr>
                      ))}
                    </Table>
                  )}
                </RemotePage>
              </section>
              <section
                className="allocation-collection"
                aria-label="Original billing observations"
              >
                <h3>Original billing observations</h3>
                <p className="form-note">
                  One row per canonical source record. Observation totals and
                  allocation entries are separate views of the same spend.
                </p>
                <RemotePage<components["schemas"]["AllocationObservation"]>
                  path={`/allocation-reports/${encodeURIComponent(id)}/observations?limit=20`}
                  label="Billing observations"
                  empty="This immutable report has no source observations."
                >
                  {(items) => (
                    <Table
                      scrollLabel="Scrollable original billing observations"
                      headings={[
                        "Source record",
                        "Native resource",
                        "Account / region",
                        "Observed billed cost",
                      ]}
                    >
                      {items.map((row) => (
                        <tr key={row.id}>
                          <td className="evidence-id">
                            {row.record_id}
                            <small>{shortId(row.source_version)}</small>
                          </td>
                          <td>
                            {row.provider_resource_id || "Unmatched"}
                            <small>{row.provider}</small>
                          </td>
                          <td>
                            {row.account_id}
                            <small>{row.region || "Region unavailable"}</small>
                          </td>
                          <td className="money-cell">
                            {amount(row.observed_billed_cost, row.currency)}
                          </td>
                        </tr>
                      ))}
                    </Table>
                  )}
                </RemotePage>
              </section>
            </>
          )
        )}
      </div>
    </Modal>
  );
}

export function CostAllocation(props: Props) {
  const [revision, setRevision] = useState(0);
  const [editor, setEditor] = useState(false);
  const [creator, setCreator] = useState(false);
  const [reportID, setReportID] = useState("");
  const policy = useRemote<components["schemas"]["AllocationPolicyPage"]>(
    "/allocation-policies?limit=1",
    revision,
  );
  const refresh = () => setRevision((current) => current + 1);
  return (
    <>
      <div className="page-heading">
        <div>
          <div className="eyebrow">Financial visibility</div>
          <h1>
            Give observed spend an owner<span className="title-dot">.</span>
          </h1>
          <p>
            Currency-separated billing analysis with explicit ownership gaps and
            immutable source evidence.
          </p>
        </div>
        <Button secondary onClick={refresh}>
          Refresh allocation
        </Button>
      </div>
      <div className="allocation-boundary">
        <strong>Current ownership view</strong>
        <p>
          Provisional observed BilledCost · ownership mapped at report creation
          · unknown costs remain unavailable. Reports are separate snapshots; do
          not add revisions together. Verified savings stays in Savings
          evidence.
        </p>
      </div>
      {policy.loading ? (
        <p role="status">Loading financial scope and current policy…</p>
      ) : policy.error ? (
        <Panel title="Financial scope unavailable">
          <p className="blocker-text" role="alert">
            Allocation policies could not be read. {policy.error}
          </p>
          <p className="form-note">
            Organization finance access requires FINANCE, FINOPS_ADMIN or
            AUDITOR. Auditors have read access; policy and report creation
            require financial write permissions.
          </p>
        </Panel>
      ) : (
        policy.value && (
          <>
            <Panel
              title="Allocation policy"
              eyebrow="Immutable revisions"
              action={
                <Button
                  secondary
                  small
                  pending={props.busy}
                  onClick={() => setEditor(true)}
                >
                  {policy.value.latest
                    ? "Revise allocation policy"
                    : "Create allocation policy"}
                </Button>
              }
            >
              <p className="native-intro">
                {policy.value.latest
                  ? `Current revision ${policy.value.version} · ${policy.value.latest.definition.name}.`
                  : "No allocation policy exists yet. Create a current-ownership policy, with optional fixed shares."}{" "}
                Explicit shares use integer ppm totaling 1,000,000. Other
                matched resources keep their current workload; missing ownership
                remains unallocated.
              </p>
              <RemotePage<Policy>
                key={`policies-${revision}`}
                path="/allocation-policies?limit=10"
                label="Allocation policy revisions"
                empty="Save the first immutable policy revision to begin."
              >
                {(items) => (
                  <Table
                    scrollLabel="Scrollable allocation policy revisions"
                    headings={[
                      "Revision",
                      "Policy",
                      "Mapping rules",
                      "Created",
                      "Evidence",
                    ]}
                  >
                    {items
                      .filter((row) =>
                        matches(
                          props.query,
                          row.id,
                          row.definition.name,
                          row.version,
                        ),
                      )
                      .map((row) => (
                        <tr key={row.id}>
                          <td>v{row.version}</td>
                          <td>
                            {row.definition.name}
                            <small>{row.created_by}</small>
                          </td>
                          <td>
                            {row.definition.rules.length ? (
                              <details>
                                <summary>
                                  {row.definition.rules.length} fixed share
                                  rules
                                </summary>
                                {row.definition.rules.map((rule, at) => (
                                  <p key={at} className="form-note">
                                    {rule.resource_ids.join(", ")} →{" "}
                                    {rule.recipients
                                      .map(
                                        (target) =>
                                          `${target.workload_id}: ${target.weight_ppm} ppm`,
                                      )
                                      .join("; ")}
                                  </p>
                                ))}
                              </details>
                            ) : (
                              "Current resource ownership"
                            )}
                          </td>
                          <td>{dateTime(row.created_at)}</td>
                          <td className="evidence-id">
                            {shortId(row.id)}
                            <small title={row.hash}>{shortId(row.hash)}</small>
                          </td>
                        </tr>
                      ))}
                  </Table>
                )}
              </RemotePage>
            </Panel>
            <Panel
              title="Allocation reports"
              eyebrow="Independent source snapshots"
              action={
                <Button
                  small
                  disabled={!policy.value.latest}
                  pending={props.busy}
                  onClick={() => setCreator(true)}
                >
                  Create allocation report
                </Button>
              }
            >
              <p className="native-intro">
                Inspect one report at a time. Observations, derived entries and
                report history paginate independently. Search filters loaded
                summaries only.
              </p>
              <RemotePage<Report>
                key={`reports-${revision}`}
                path="/allocation-reports?limit=10"
                label="Allocation reports"
                empty="Select a persisted billing source and the current policy to create an observed-spend snapshot."
              >
                {(items) => (
                  <Table
                    scrollLabel="Scrollable allocation report summaries"
                    headings={[
                      "Report / source",
                      "Mapping as of",
                      "Currencies",
                      "Population",
                      "Status",
                      "Evidence",
                    ]}
                  >
                    {items
                      .filter((row) =>
                        matches(
                          props.query,
                          row.id,
                          row.status,
                          row.source.source_id,
                          row.source.kind,
                        ),
                      )
                      .map((row) => (
                        <tr key={row.id}>
                          <td>
                            <span className="evidence-id">
                              {shortId(row.id)}
                            </span>
                            <small>{readable(row.source.kind)}</small>
                          </td>
                          <td>{dateTime(row.mapping_as_of)}</td>
                          <td>
                            {row.totals
                              .map((total) => total.currency)
                              .join(" · ") || "Unavailable"}
                          </td>
                          <td>
                            {row.record_count} observations
                            <small>{row.line_count} entries</small>
                          </td>
                          <td>
                            <Badge value={row.status} tone="neutral" />
                          </td>
                          <td>
                            <Button
                              small
                              secondary
                              aria-label={`Inspect allocation report ${row.id}`}
                              onClick={() => setReportID(row.id)}
                            >
                              Inspect report
                            </Button>
                          </td>
                        </tr>
                      ))}
                  </Table>
                )}
              </RemotePage>
            </Panel>
          </>
        )
      )}
      {!policy.loading && !policy.error && !policy.value && (
        <Empty
          title="Allocation policy unavailable"
          text="The API returned no policy metadata. Refresh before creating a report."
        />
      )}
      {editor && policy.value && (
        <PolicyEditor
          {...props}
          latest={policy.value.latest}
          version={policy.value.version}
          onClose={() => setEditor(false)}
          onSaved={() => {
            setEditor(false);
            refresh();
          }}
        />
      )}
      {creator && policy.value?.latest && (
        <ReportCreator
          {...props}
          policy={policy.value.latest}
          onClose={() => setCreator(false)}
          onSaved={(id) => {
            setCreator(false);
            refresh();
            setReportID(id);
          }}
        />
      )}
      {reportID && (
        <ReportEvidence
          key={reportID}
          id={reportID}
          data={props.data}
          onClose={() => setReportID("")}
        />
      )}
    </>
  );
}
