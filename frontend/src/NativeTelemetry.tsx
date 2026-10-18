import { useEffect, useState } from "react";
import type { components } from "./api.generated";
import type {
  Dashboard,
  TelemetryConnection,
  TelemetryConnectionRequest,
  TelemetryDefinition,
  TelemetryEvaluationRecord,
  Workload,
} from "./types";
import { useRemote, RemotePage } from "./RemoteData";
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

const metrics = {
  cpu_utilization: ["GAUGE", "ratio"],
  memory_utilization: ["GAUGE", "ratio"],
  gpu_utilization: ["GAUGE", "ratio"],
  network_in: ["SUM", "bytes"],
  network_out: ["SUM", "bytes"],
  disk_read_bytes: ["SUM", "bytes"],
  disk_write_bytes: ["SUM", "bytes"],
  disk_read_operations: ["SUM", "count"],
  disk_write_operations: ["SUM", "count"],
  request_count: ["SUM", "count"],
  error_count: ["SUM", "count"],
  disk_queue: ["GAUGE", "count"],
  latency: ["HISTOGRAM", "milliseconds"],
} as const;
const decimalText = (value: string | null | undefined) =>
  value == null ? "Unavailable" : value;
const coverage = (value: number) => `${(value / 10_000).toLocaleString()}%`;

function Selectors({
  title,
  values,
  onChange,
}: {
  title: string;
  values: Record<string, string>;
  onChange: (values: Record<string, string>) => void;
}) {
  const [rows, setRows] = useState(() =>
    Object.entries(values).map(([key, value]) => ({
      id: crypto.randomUUID(),
      key,
      value,
    })),
  );
  const update = (next: typeof rows) => {
    setRows(next);
    onChange(
      Object.fromEntries(
        next.filter((row) => row.key).map((row) => [row.key, row.value]),
      ),
    );
  };
  return (
    <fieldset className="days-fieldset">
      <legend>{title}</legend>
      {rows.map((row, index) => (
        <div className="selector-row" key={row.id}>
          <label className="field">
            <span>
              {title} key {index + 1}
            </span>
            <input
              ref={(element) => {
                element?.setCustomValidity(
                  rows.some(
                    (item) => item.id !== row.id && item.key === row.key,
                  )
                    ? "Attribute keys must be unique."
                    : "",
                );
              }}
              required
              value={row.key}
              onChange={(event) =>
                update(
                  rows.map((item) =>
                    item.id === row.id
                      ? { ...item, key: event.target.value }
                      : item,
                  ),
                )
              }
            />
          </label>
          <label className="field">
            <span>
              {title} value {index + 1}
            </span>
            <input
              value={row.value}
              onChange={(event) =>
                update(
                  rows.map((item) =>
                    item.id === row.id
                      ? { ...item, value: event.target.value }
                      : item,
                  ),
                )
              }
            />
          </label>
          <Button
            secondary
            small
            type="button"
            aria-label={`Remove ${title.toLowerCase()} ${index + 1}`}
            onClick={() => update(rows.filter((item) => item.id !== row.id))}
          >
            Remove
          </Button>
        </div>
      ))}
      <Button
        secondary
        small
        type="button"
        disabled={rows.length >= 32}
        onClick={() =>
          update([...rows, { id: crypto.randomUUID(), key: "", value: "" }])
        }
      >
        Add {title.toLowerCase()}
      </Button>
    </fieldset>
  );
}

function ConnectionForm({
  data,
  workload,
  connection,
  run,
  busy,
  onClose,
  saved,
}: {
  data: Dashboard;
  workload: Workload;
  connection?: TelemetryConnection;
  run: RunMutation;
  busy: boolean;
  onClose: () => void;
  saved: () => void;
}) {
  const [base] = useState(connection);
  const [resource, setResource] = useState(
    connection?.binding.resource_id ?? "",
  );
  const [kind, setKind] = useState<TelemetryConnectionRequest["kind"]>(
    connection?.kind ?? "PROMETHEUS",
  );
  const [identity, setIdentity] = useState(
    connection?.read_binding_id ?? connection?.subject ?? "",
  );
  const [definitions, setDefinitions] = useState(
    () =>
      connection?.definitions.map((definition) => ({
        key: crypto.randomUUID(),
        ...definition,
      })) ?? [],
  );
  const [error, setError] = useState("");
  const update = (key: string, patch: Partial<TelemetryDefinition>) =>
    setDefinitions((current) =>
      current.map((definition) =>
        definition.key === key ? { ...definition, ...patch } : definition,
      ),
    );
  return (
    <Modal
      title={
        base
          ? "Revise native telemetry connection"
          : "Register native telemetry connection"
      }
      subtitle={`${workload.name} · platform administrator${base ? ` · revision ${base.version}` : ""}`}
      onClose={onClose}
    >
      <form
        onSubmit={async (event) => {
          event.preventDefault();
          setError("");
          if (
            !definitions.length ||
            new Set(definitions.map((definition) => definition.id)).size !==
              definitions.length ||
            new Set(definitions.map((definition) => definition.metric)).size !==
              definitions.length ||
            definitions.some(
              (definition) =>
                definition.max_gap_seconds < definition.cadence_seconds,
            )
          ) {
            setError(
              "Add unique metric definitions with maximum gaps at least as long as their cadence.",
            );
            return;
          }
          const body: TelemetryConnectionRequest = {
            resource_id: resource,
            kind,
            definitions: definitions.map(
              ({ key: _key, ...definition }) => definition,
            ),
            ...(kind === "PROMETHEUS"
              ? { read_binding_id: identity.trim() }
              : { subject: identity.trim() }),
          };
          if (
            await run({
              path: base
                ? `/telemetry-connections/${base.id}/revisions`
                : "/telemetry-connections",
              version: base?.version,
              body,
              label:
                "Native telemetry configuration recorded. Independent collection and persisted evidence are still required.",
            })
          ) {
            saved();
            onClose();
          } else
            setError(
              "Configuration not saved. Check the request error and refresh before retrying a changed revision.",
            );
        }}
      >
        <p className="form-note">
          Configure metric identity and collection expectations. This form
          cannot upload observations, supply source URLs or credentials, or
          grant execution authority. Instruments must emit the server-required
          resource labels or OTLP attributes; registration does not invent
          received points.
        </p>
        <div className="form-grid">
          <label className="field">
            <span>Telemetry resource</span>
            <select
              required
              value={resource}
              disabled={Boolean(base)}
              onChange={(event) => setResource(event.target.value)}
            >
              <option value="">Choose a resource</option>
              {data.resources
                .filter((item) => item.workload_id === workload.id)
                .map((item) => (
                  <option key={item.id} value={item.id}>
                    {item.name} · {item.provider_resource_id}
                  </option>
                ))}
            </select>
          </label>
          <label className="field">
            <span>Native protocol</span>
            <select
              value={kind}
              onChange={(event) => {
                setKind(event.target.value as typeof kind);
                setIdentity("");
              }}
            >
              <option value="PROMETHEUS">Prometheus read binding</option>
              <option value="OTLP">OTLP machine ingestion</option>
            </select>
          </label>
          <label className="field full-width">
            <span>
              {kind === "PROMETHEUS"
                ? "Approved Prometheus read binding ID"
                : "Exact OTLP machine subject"}
            </span>
            <input
              required
              autoComplete="off"
              value={identity}
              onChange={(event) => setIdentity(event.target.value)}
            />
          </label>
        </div>
        {definitions.map((definition, index) => (
          <fieldset className="days-fieldset" key={definition.key}>
            <legend>Metric definition {index + 1}</legend>
            <div className="form-grid">
              <label className="field">
                <span>Canonical metric {index + 1}</span>
                <select
                  value={definition.metric}
                  onChange={(event) => {
                    const metric = event.target.value as keyof typeof metrics;
                    const [type] = metrics[metric];
                    update(definition.key, {
                      metric,
                      type,
                      unit: "",
                      monotonic: type === "SUM",
                    });
                  }}
                >
                  {Object.keys(metrics).map((name) => (
                    <option key={name} value={name}>
                      {readable(name)}
                    </option>
                  ))}
                </select>
              </label>
              <label className="field">
                <span>Native metric name {index + 1}</span>
                <input
                  required
                  value={definition.name}
                  onChange={(event) =>
                    update(definition.key, { name: event.target.value })
                  }
                />
              </label>
              <label className="field">
                <span>Definition ID {index + 1}</span>
                <input
                  required
                  value={definition.id}
                  onChange={(event) =>
                    update(definition.key, { id: event.target.value })
                  }
                />
              </label>
              <label className="field">
                <span>Definition version {index + 1}</span>
                <input
                  required
                  value={definition.version}
                  onChange={(event) =>
                    update(definition.key, { version: event.target.value })
                  }
                />
              </label>
              <label className="field">
                <span>Metric unit {index + 1}</span>
                <input
                  required
                  maxLength={128}
                  list={`native-units-${definition.key}`}
                  value={definition.unit}
                  onChange={(event) =>
                    update(definition.key, { unit: event.target.value })
                  }
                />
                <datalist id={`native-units-${definition.key}`}>
                  {(definition.metric === "latency"
                    ? ["ms", "s", "milliseconds", "seconds"]
                    : [
                        metrics[
                          definition.metric as keyof typeof metrics
                        ]?.[1] ?? definition.unit,
                        "requests",
                        "1",
                        "vCPU",
                      ]
                  ).map((unit) => (
                    <option key={unit} value={unit}>
                      {unit}
                    </option>
                  ))}
                </datalist>
                <small className="binding-caption">
                  Exact native unit, including UCUM spelling. Suggestions do not
                  convert source observations.
                </small>
              </label>
              <label className="field">
                <span>Expected cadence {index + 1} (seconds)</span>
                <input
                  required
                  type="number"
                  min={1}
                  max={300}
                  step={1}
                  value={definition.cadence_seconds}
                  onChange={(event) =>
                    update(definition.key, {
                      cadence_seconds: Number(event.target.value),
                    })
                  }
                />
              </label>
              <label className="field">
                <span>Maximum gap {index + 1} (seconds)</span>
                <input
                  required
                  type="number"
                  min={definition.cadence_seconds}
                  max={600}
                  step={1}
                  value={definition.max_gap_seconds}
                  onChange={(event) =>
                    update(definition.key, {
                      max_gap_seconds: Number(event.target.value),
                    })
                  }
                />
              </label>
              {definition.type === "SUM" && kind === "PROMETHEUS" && (
                <label className="field">
                  <span>Counter epoch metric {index + 1}</span>
                  <input
                    value={definition.epoch_metric ?? ""}
                    onChange={(event) =>
                      update(definition.key, {
                        epoch_metric: event.target.value,
                      })
                    }
                  />
                </label>
              )}
            </div>
            <p className="binding-caption">
              {definition.type} ·{" "}
              {definition.monotonic
                ? "monotonic native counter"
                : "native observations"}
              . Ratio means 0–1; source units and actual time bounds are
              preserved. Counter resets and missing epochs remain visible.
            </p>
            <Selectors
              title={`Metric ${index + 1} attributes`}
              values={definition.attributes}
              onChange={(attributes) => update(definition.key, { attributes })}
            />
            <Selectors
              title={`Metric ${index + 1} resource attributes`}
              values={definition.resource_attributes}
              onChange={(resource_attributes) =>
                update(definition.key, { resource_attributes })
              }
            />
            {definition.type === "SUM" && kind === "PROMETHEUS" && (
              <Selectors
                title={`Metric ${index + 1} epoch attributes`}
                values={definition.epoch_attributes ?? {}}
                onChange={(epoch_attributes) =>
                  update(definition.key, { epoch_attributes })
                }
              />
            )}
            <Button
              type="button"
              secondary
              small
              onClick={() =>
                setDefinitions((current) =>
                  current.filter((item) => item.key !== definition.key),
                )
              }
            >
              Remove metric definition {index + 1}
            </Button>
          </fieldset>
        ))}
        <Button
          type="button"
          secondary
          small
          disabled={definitions.length >= 32}
          onClick={() =>
            setDefinitions((current) => [
              ...current,
              {
                key: crypto.randomUUID(),
                id: "",
                version: "",
                metric: "cpu_utilization",
                name: "",
                unit: "",
                type: "GAUGE",
                monotonic: false,
                cadence_seconds: 60,
                max_gap_seconds: 120,
                attributes: {},
                resource_attributes: {},
              },
            ])
          }
        >
          Add metric definition
        </Button>
        {error && (
          <p role="alert" className="blocker-text">
            {error}
          </p>
        )}
        <div className="modal-actions">
          <Button secondary type="button" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" pending={busy} disabled={!definitions.length}>
            Save telemetry configuration
          </Button>
        </div>
      </form>
    </Modal>
  );
}

function EvaluationView({ record }: { record: TelemetryEvaluationRecord }) {
  const result = record.evaluation;
  return (
    <section
      className="native-evaluation"
      aria-label={`Native evaluation ${record.id}`}
    >
      <div className="policy-row">
        <span>
          <strong>
            {result.history_days
              ? `${result.history_days}-day history`
              : "Current observation window"}
          </strong>
          <small>
            {dateTime(result.start)} — {dateTime(result.end)} ·{" "}
            {result.timezone || "UTC"}
          </small>
        </span>
        <Badge value={result.status} />
      </div>
      {!!result.reason_codes.length && (
        <p className="blocker-text">
          {result.reason_codes.map(readable).join(" · ")}
        </p>
      )}
      <Table
        scrollLabel={`Scrollable metrics for ${record.id}`}
        headings={[
          "Metric / native statistic",
          "Coverage / samples",
          "Observed p50 / p90",
          "Observed p95 / p99",
          "Observed p99.9",
          "Maximum / total",
        ]}
      >
        {result.metrics.map((metric) => (
          <tr key={metric.definition_id}>
            <td>
              <strong>{readable(metric.metric)}</strong>
              <small>
                {metric.unit} · {metric.statistic}
              </small>
              <Badge value={metric.status} />
              <small className="blocker-text">
                {metric.reason_codes.map(readable).join(" · ")}
              </small>
            </td>
            <td>
              {coverage(metric.coverage_ppm)}
              <small>
                {metric.observed_samples} observed / {metric.expected_samples}{" "}
                expected
              </small>
              <small>
                {dateTime(metric.start)} — {dateTime(metric.end)}
              </small>
            </td>
            <td>
              {decimalText(metric.p50)} / {decimalText(metric.p90)}
            </td>
            <td>
              {decimalText(metric.p95)} / {decimalText(metric.p99)}
            </td>
            <td>{decimalText(metric.p999)}</td>
            <td>
              {decimalText(metric.maximum)}
              <small>Total: {decimalText(metric.total)}</small>
            </td>
          </tr>
        ))}
      </Table>
      <p className="form-note">
        Quantiles describe the registered observed sample distribution or
        histogram bucket bounds in the displayed units. They do not establish an
        unseen burst distribution. Hourly Maximum is not p95; missing
        observations remain unavailable.
      </p>
      <details>
        <summary>Evaluation and source references</summary>
        <dl className="definition-list">
          <div>
            <dt>Evaluation hash</dt>
            <dd className="evidence-id">{record.hash || result.hash}</dd>
          </div>
          <div>
            <dt>Configuration hash</dt>
            <dd className="evidence-id">{record.config_hash}</dd>
          </div>
          {result.metrics.map((metric) => (
            <div key={metric.definition_id}>
              <dt>{readable(metric.metric)} segments</dt>
              <dd>
                {metric.segment_count} total ·{" "}
                {metric.segment_ids_truncated
                  ? "truncated preview"
                  : "complete preview"}
                <small className="evidence-id">{metric.segment_hash}</small>
                <small className="evidence-id">
                  {metric.segment_ids.join(", ") || "No segment IDs"}
                </small>
                {metric.histogram && (
                  <small className="evidence-id">
                    Histogram count {metric.histogram.count}; bounds [
                    {metric.histogram.bounds.join(", ")}]; disjoint buckets [
                    {metric.histogram.bucket_counts.join(", ")}]
                  </small>
                )}
              </dd>
            </div>
          ))}
        </dl>
        <p className="form-note">
          The bounded segment preview is not the complete source population.
          Receipt references retain the pinned raw and canonical evidence.
        </p>
        <ul className="evidence-refs">
          {record.receipt_ids.map((id) => (
            <li key={id}>{id}</li>
          ))}
        </ul>
      </details>
    </section>
  );
}

function SyncStatus({
  connectionId,
  id,
}: {
  connectionId: string;
  id: string;
}) {
  const [refresh, setRefresh] = useState(0);
  const job = useRemote<components["schemas"]["TelemetrySyncJob"]>(
    `/telemetry-connections/${connectionId}/sync/${id}`,
    refresh,
  );
  const status = job.value?.status;
  useEffect(() => {
    if (!status || status === "COMPLETED" || status === "BLOCKED") return;
    const timer = window.setTimeout(
      () => setRefresh((value) => value + 1),
      4000,
    );
    return () => window.clearTimeout(timer);
  }, [status, refresh]);
  return (
    <section
      className="native-section"
      aria-label="Durable native synchronization"
    >
      <h3>Durable synchronization</h3>
      {job.loading && <p role="status">Reading synchronization state…</p>}
      {job.error && (
        <p role="alert">Synchronization status unavailable. {job.error}</p>
      )}
      {job.value && (
        <>
          <Badge value={job.value.status} />
          <p className="form-note">
            {job.value.history_days} days requested · attempt{" "}
            {job.value.attempts}. Completed means query evidence was published;
            observed coverage is evaluated separately.
          </p>
          <p className="binding-caption">
            {dateTime(job.value.start)} — {dateTime(job.value.end)}
          </p>
          {job.value.reason_code && (
            <p className="blocker-text">{readable(job.value.reason_code)}</p>
          )}
          <ul className="evidence-refs">
            {job.value.receipt_ids.map((receipt) => (
              <li key={receipt}>{receipt}</li>
            ))}
          </ul>
        </>
      )}
      <Button secondary small onClick={() => setRefresh((value) => value + 1)}>
        Refresh synchronization status
      </Button>
    </section>
  );
}

function CapacityEvidence({
  connection,
  run,
  busy,
}: {
  connection: TelemetryConnection;
  run: RunMutation;
  busy: boolean;
}) {
  const [refresh, setRefresh] = useState(0);
  const workload = connection.binding.workload_id;
  const requirements = useRemote<components["schemas"]["WorkloadSafetyPage"]>(
    `/workloads/${workload}/safety-profiles?limit=1`,
    refresh,
  );
  const version = requirements.value?.version;
  return (
    <section
      className="native-section"
      aria-label="Native capacity evidence assessment"
    >
      <h3>Capacity evidence assessment</h3>
      <p className="form-note">
        The server selects the current source configuration, immutable
        observations and safety profile. Historical quantiles and forecasts need
        physical capacity denominators; source registration cannot supply a
        provider hardware catalog or contracted price. This assessment never
        approves or executes a change.
      </p>
      {requirements.loading && (
        <p role="status">Reading the current requirements version…</p>
      )}
      {requirements.error && (
        <p role="alert">Requirements unavailable. {requirements.error}</p>
      )}
      {version === 0 && (
        <p className="blocker-text">
          Declare a workload safety profile before requesting an assessment.
        </p>
      )}
      <div className="row-actions">
        <Button
          secondary
          small
          disabled={
            busy ||
            connection.revoked ||
            !Number.isSafeInteger(version) ||
            !version
          }
          onClick={async () => {
            if (
              await run({
                path: `/workloads/${workload}/capacity-assessments`,
                version,
                body: { connection_id: connection.id },
                label:
                  "Immutable capacity evidence assessment recorded; execution and savings authority remain separate.",
              })
            )
              setRefresh((value) => value + 1);
          }}
        >
          Assess capacity evidence
        </Button>
        <Button
          secondary
          small
          onClick={() => setRefresh((value) => value + 1)}
        >
          Refresh capacity assessments
        </Button>
      </div>
      <RemotePage<components["schemas"]["CapacityAssessment"]>
        key={refresh}
        path={`/workloads/${workload}/capacity-assessments?limit=20`}
        label="Capacity assessments"
        empty="No capacity assessment is recorded. Missing hardware, memory observations or price evidence cannot establish a safe resize."
      >
        {(records) =>
          records.map((record) => (
            <section
              className="native-evaluation"
              key={record.id}
              aria-label={`Capacity assessment ${record.id}`}
            >
              <div className="policy-row">
                <span>
                  <strong>{record.history.days}-day source population</strong>
                  <small>
                    {dateTime(record.created_at)} · {record.resource_id}
                  </small>
                </span>
                <Badge value={record.status} />
              </div>
              <ul className="evidence-refs">
                {record.reason_codes.map((reason) => (
                  <li key={reason}>{readable(reason)}</li>
                ))}
              </ul>
              <dl className="definition-list">
                <div>
                  <dt>Native observation coverage</dt>
                  <dd>
                    <Badge value={record.native_evaluation.status} />
                    <small>
                      Coverage does not establish physical suitability
                    </small>
                  </dd>
                </div>
                <div>
                  <dt>Provider hardware catalog / contracted price</dt>
                  <dd>
                    {readable(record.hardware_catalog_status)} /{" "}
                    {readable(record.native_price_status)}
                  </dd>
                </div>
                <div>
                  <dt>Estimated / verified savings</dt>
                  <dd>
                    {record.estimated_saving == null
                      ? "Unavailable"
                      : "Currency unavailable"}{" "}
                    /{" "}
                    {record.verified_saving == null
                      ? "Unavailable"
                      : "Currency unavailable"}
                  </dd>
                </div>
                <div>
                  <dt>Execution authority</dt>
                  <dd>Not authorized by this assessment</dd>
                </div>
              </dl>
              <details>
                <summary>Frozen source and requirements references</summary>
                <dl className="definition-list">
                  <div>
                    <dt>Safety profile</dt>
                    <dd>
                      {record.safety_profile_id} · revision{" "}
                      {record.safety_profile_version}
                      <small className="evidence-id">
                        {record.safety_profile_hash}
                      </small>
                    </dd>
                  </div>
                  <div>
                    <dt>Connection configuration</dt>
                    <dd>
                      {record.connection_id} · revision{" "}
                      {record.connection_version}
                      <small className="evidence-id">
                        {record.config_hash}
                      </small>
                      {record.connection_id === connection.id &&
                        record.config_hash !== connection.config_hash && (
                          <small>
                            Historical configuration; inspect current source
                            before reassessing
                          </small>
                        )}
                    </dd>
                  </div>
                  <div>
                    <dt>Observation population hash</dt>
                    <dd className="evidence-id">{record.population_hash}</dd>
                  </div>
                  <div>
                    <dt>Local calendar window</dt>
                    <dd>
                      {dateTime(record.history.start)} —{" "}
                      {dateTime(record.history.end)}
                      <small>
                        {record.history.timezone} ·{" "}
                        {readable(record.history.environment)}
                      </small>
                    </dd>
                  </div>
                </dl>
                <p className="form-note">
                  {record.receipt_ids.length} source receipts; bounded preview
                  below. Complete pinned evidence remains available through the
                  source receipt history.
                </p>
                <ul className="evidence-refs">
                  {record.receipt_ids.slice(0, 16).map((id) => (
                    <li key={id}>{id}</li>
                  ))}
                </ul>
              </details>
            </section>
          ))
        }
      </RemotePage>
    </section>
  );
}

function ConnectionDetails({
  data,
  workload,
  connection,
  run,
  busy,
  onClose,
  changed,
}: {
  data: Dashboard;
  workload: Workload;
  connection: TelemetryConnection;
  run: RunMutation;
  busy: boolean;
  onClose: () => void;
  changed: () => void;
}) {
  const [refresh, setRefresh] = useState(0);
  const [editing, setEditing] = useState(false);
  const [revoking, setRevoking] = useState(false);
  const [reason, setReason] = useState("");
  const [notice, setNotice] = useState("");
  const [syncId, setSyncId] = useState<string | null>(null);
  const [capacityOpen, setCapacityOpen] = useState(false);
  const source = useRemote<TelemetryConnection>(
    `/telemetry-connections/${connection.id}`,
    refresh,
  );
  const definitions = useRemote<
    components["schemas"]["TelemetryDefinitionPage"]
  >(
    `/metric-definitions?connection_id=${encodeURIComponent(connection.id)}`,
    refresh,
  );
  const current = source.value;
  const mutate = async (action: string, body: object, label: string) => {
    if (!current) return;
    const result = await run({
      path: `/telemetry-connections/${current.id}/${action}`,
      version: current.version,
      body,
      label,
    });
    if (result) {
      if (action === "sync" && typeof result.id === "string")
        setSyncId(result.id);
      setNotice(label);
      setRefresh((value) => value + 1);
      changed();
    }
    return result;
  };
  if (editing && current)
    return (
      <ConnectionForm
        data={data}
        workload={workload}
        connection={current}
        run={run}
        busy={busy}
        onClose={() => setEditing(false)}
        saved={() => {
          setRefresh((value) => value + 1);
          changed();
        }}
      />
    );
  return (
    <Modal
      title="Native telemetry evidence"
      subtitle={`${connection.kind} · ${shortId(connection.id)}`}
      onClose={onClose}
    >
      {source.loading && <p role="status">Loading current source metadata…</p>}
      {source.error && (
        <p role="alert" className="blocker-text">
          Current source metadata unavailable. {source.error}
        </p>
      )}
      {current && (
        <>
          <div className="policy-row">
            <span>
              <strong>Configuration revision {current.version}</strong>
              <small>
                {current.binding.provider_resource_id} ·{" "}
                {current.binding.region}
              </small>
            </span>
            <Badge value={current.revoked ? "BLOCKED" : "CONNECTED"}>
              {current.revoked ? "Revoked" : "Registered"}
            </Badge>
          </div>
          <p className="form-note">
            Registration is not evidence coverage or execution approval. OTLP
            instrumentation must emit finops.resource.id and finops.tenant.id;
            Prometheus must emit the labels selected by the approved server
            binding.
          </p>
          <div className="row-actions">
            <Button
              secondary
              small
              disabled={
                busy || current.revoked || current.kind !== "PROMETHEUS"
              }
              onClick={() =>
                void mutate(
                  "sync",
                  {},
                  "Native source synchronization requested; collection length is selected from workload requirements.",
                )
              }
            >
              Synchronize history
            </Button>
            <Button
              secondary
              small
              disabled={busy || current.revoked}
              onClick={() =>
                void mutate(
                  "evaluate",
                  { mode: "history" },
                  "Historical telemetry evaluation recorded",
                )
              }
            >
              Evaluate history
            </Button>
            <Button
              secondary
              small
              disabled={busy || current.revoked}
              onClick={() =>
                void mutate(
                  "evaluate",
                  { mode: "window" },
                  "Current telemetry evaluation recorded",
                )
              }
            >
              Evaluate current window
            </Button>
            <Button
              secondary
              small
              disabled={busy}
              onClick={() => setEditing(true)}
            >
              Revise configuration
            </Button>
            <Button
              secondary
              small
              disabled={busy || current.revoked}
              onClick={() => setRevoking(true)}
            >
              Revoke source
            </Button>
          </div>
          {revoking && (
            <form
              className="source-revoke"
              onSubmit={async (event) => {
                event.preventDefault();
                if (
                  await mutate(
                    "revoke",
                    { reason: reason.trim() },
                    "Telemetry source revoked; evidence history and owned recovery remain preserved",
                  )
                )
                  setRevoking(false);
              }}
            >
              <label className="field">
                <span>Reason for revoking this telemetry source</span>
                <input
                  required
                  value={reason}
                  onChange={(event) => setReason(event.target.value)}
                />
              </label>
              <div className="row-actions">
                <Button
                  secondary
                  small
                  type="button"
                  onClick={() => setRevoking(false)}
                >
                  Cancel revocation
                </Button>
                <Button
                  small
                  type="submit"
                  pending={busy}
                  disabled={!reason.trim()}
                >
                  Confirm source revocation
                </Button>
              </div>
            </form>
          )}
          {notice && (
            <p role="status" className="form-note">
              {notice}
            </p>
          )}
          <h3 className="native-subheading">Registered metric definitions</h3>
          {definitions.loading && <p role="status">Loading definitions…</p>}
          {definitions.error && (
            <p role="alert">Definitions unavailable. {definitions.error}</p>
          )}
          {definitions.value && (
            <Table
              scrollLabel="Scrollable registered metric definitions"
              headings={[
                "Metric",
                "Definition / native name",
                "Semantics",
                "Cadence / maximum gap",
              ]}
            >
              {definitions.value.items.map((definition) => (
                <tr key={definition.id}>
                  <td>{readable(definition.metric)}</td>
                  <td>
                    {definition.id} · v{definition.version}
                    <small>{definition.name}</small>
                  </td>
                  <td>
                    {definition.type} · {definition.unit}
                    <small>
                      {definition.monotonic ? "Monotonic" : "Observed samples"}
                    </small>
                  </td>
                  <td>
                    {definition.cadence_seconds}s / {definition.max_gap_seconds}
                    s
                  </td>
                </tr>
              ))}
            </Table>
          )}
          {syncId && <SyncStatus connectionId={current.id} id={syncId} />}
          <details
            onToggle={(event) => setCapacityOpen(event.currentTarget.open)}
          >
            <summary className="native-subheading">
              Assess historical capacity evidence
            </summary>
            {capacityOpen && (
              <CapacityEvidence connection={current} run={run} busy={busy} />
            )}
          </details>
          <h3 className="native-subheading">Immutable source receipts</h3>
          <RemotePage<components["schemas"]["TelemetryReceipt"]>
            key={`receipts-${refresh}`}
            path={`/telemetry-connections/${current.id}/receipts?limit=20`}
            label="Telemetry receipts"
            empty="No persisted native source evidence is available. Registration does not fill missing observations."
          >
            {(receipts) => (
              <Table
                scrollLabel="Scrollable native source receipts"
                headings={[
                  "Receipt / actual source time",
                  "Samples / rejected",
                  "Authority / hashes",
                ]}
              >
                {receipts.map((receipt) => (
                  <tr key={receipt.id}>
                    <td className="evidence-id">
                      {receipt.id}
                      <small>
                        {dateTime(receipt.start ?? undefined)} —{" "}
                        {dateTime(receipt.end ?? undefined)}
                      </small>
                      <small>Collected {dateTime(receipt.collected_at)}</small>
                    </td>
                    <td>
                      {receipt.sample_count} / {receipt.rejection_count}
                      <small>{receipt.warning_count} warnings</small>
                    </td>
                    <td>
                      <Badge
                        value={receipt.active_source ? "READY" : "BLOCKED"}
                      >
                        {receipt.active_source
                          ? "Current source"
                          : "Historical source"}
                      </Badge>
                      <small className="evidence-id">
                        Raw {receipt.raw_sha256}
                      </small>
                      <small className="evidence-id">
                        Canonical {receipt.canonical_hash}
                      </small>
                    </td>
                  </tr>
                ))}
              </Table>
            )}
          </RemotePage>
          <h3 className="native-subheading">Immutable evaluations</h3>
          <RemotePage<TelemetryEvaluationRecord>
            key={`evaluations-${refresh}`}
            path={`/telemetry-connections/${current.id}/evaluations?limit=20`}
            label="Telemetry evaluations"
            empty="Request a server-selected evaluation after independent observations are persisted."
          >
            {(evaluations) =>
              evaluations.map((record) => (
                <EvaluationView key={record.id} record={record} />
              ))
            }
          </RemotePage>
        </>
      )}
    </Modal>
  );
}

function WorkloadTelemetry({
  data,
  workload,
  run,
  busy,
}: {
  data: Dashboard;
  workload: Workload;
  run: RunMutation;
  busy: boolean;
}) {
  const [refresh, setRefresh] = useState(0);
  const [creating, setCreating] = useState(false);
  const [selected, setSelected] = useState<TelemetryConnection | null>(null);
  const path = `/telemetry-connections?workload_id=${encodeURIComponent(workload.id)}&limit=20`;
  return (
    <>
      <div className="policy-row">
        <span>
          <strong>{workload.name}</strong>
          <small>
            Sources are queried within this workload's authorized scope.
          </small>
        </span>
        <div className="row-actions">
          <Button
            secondary
            small
            disabled={busy}
            onClick={() => setRefresh((value) => value + 1)}
          >
            Refresh native sources
          </Button>
          <Button
            secondary
            small
            disabled={busy}
            onClick={() => setCreating(true)}
          >
            Register native source
          </Button>
        </div>
      </div>
      <RemotePage<TelemetryConnection>
        key={`${path}-${refresh}`}
        path={path}
        label="Native telemetry connections"
        empty="Register a Prometheus read binding or OTLP machine source. Missing native observations stay unknown."
      >
        {(sources) => (
          <Table
            scrollLabel="Scrollable native telemetry sources"
            headings={[
              "Source / resource",
              "Protocol / identity",
              "Configuration",
              "Action",
            ]}
          >
            {sources.map((source) => (
              <tr key={source.id}>
                <td>
                  {data.resources.find(
                    (resource) => resource.id === source.binding.resource_id,
                  )?.name || source.binding.provider_resource_id}
                  <small>{source.binding.region}</small>
                </td>
                <td>
                  {source.kind}
                  <small>
                    {source.subject ||
                      source.read_binding_id ||
                      "Identity unavailable"}
                  </small>
                </td>
                <td>
                  Revision {source.version}
                  <small className="evidence-id">
                    {shortId(source.config_hash)}
                  </small>
                  <Badge
                    value={
                      source.revoked || !source.enabled
                        ? "BLOCKED"
                        : "CONNECTED"
                    }
                  >
                    {source.revoked
                      ? "Revoked"
                      : source.enabled
                        ? "Registered"
                        : "Disabled"}
                  </Badge>
                </td>
                <td>
                  <Button
                    secondary
                    small
                    aria-label={`Inspect native telemetry ${source.id}`}
                    onClick={() => setSelected(source)}
                  >
                    Inspect evidence
                  </Button>
                </td>
              </tr>
            ))}
          </Table>
        )}
      </RemotePage>
      {creating && (
        <ConnectionForm
          data={data}
          workload={workload}
          run={run}
          busy={busy}
          onClose={() => setCreating(false)}
          saved={() => setRefresh((value) => value + 1)}
        />
      )}
      {selected && (
        <ConnectionDetails
          data={data}
          workload={workload}
          connection={selected}
          run={run}
          busy={busy}
          onClose={() => setSelected(null)}
          changed={() => setRefresh((value) => value + 1)}
        />
      )}
    </>
  );
}

export function NativeTelemetry({
  data,
  run,
  busy,
}: {
  data: Dashboard;
  run: RunMutation;
  busy: boolean;
}) {
  const [workloadId, setWorkloadId] = useState(data.workloads[0]?.id ?? "");
  const workload =
    data.workloads.find((item) => item.id === workloadId) ?? data.workloads[0];
  return (
    <Panel
      title="Native application & capacity telemetry"
      eyebrow="PROMETHEUS & OPENTELEMETRY"
    >
      <p className="native-intro">
        Native observations retain their actual timestamps, units, counter
        epochs and histogram populations. An empty source is not zero
        utilization. Historical capacity planning and live execution authority
        are separate assessments.
      </p>
      {workload ? (
        <>
          <label className="field native-workload-picker">
            <span>Native telemetry workload</span>
            <select
              value={workload.id}
              onChange={(event) => setWorkloadId(event.target.value)}
            >
              {data.workloads.map((item) => (
                <option key={item.id} value={item.id}>
                  {item.name}
                </option>
              ))}
            </select>
          </label>
          <WorkloadTelemetry
            key={workload.id}
            data={data}
            workload={workload}
            run={run}
            busy={busy}
          />
        </>
      ) : (
        <Empty
          title="No authorized workloads"
          text="Discover and map a workload before registering native telemetry."
        />
      )}
    </Panel>
  );
}
