import { useState } from "react";
import { ShieldCheck } from "lucide-react";
import type { components } from "./api.generated";
import type {
  Dashboard,
  Resource,
  SloEvaluation,
  SloEvaluationSnapshot,
  SloObjective,
  SloObjectiveRequest,
  Workload,
} from "./types";
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

const days = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const limitFields = [
  ["max_p95_latency_ms", "Hard maximum p95 latency (ms)", 1, 86_400_000],
  ["max_p99_latency_ms", "Hard maximum p99 latency (ms)", 1, 86_400_000],
  ["max_error_rate_ppm", "Hard maximum error rate (ppm)", 0, 1_000_000],
  ["min_availability_ppm", "Hard minimum availability (ppm)", 0, 1_000_000],
  ["min_latency_samples", "Minimum latency samples", 1, 1_000_000_000_000],
] as const;
const ppm = (value: number | null | undefined) =>
  value == null ? "Unavailable" : `${(value / 10_000).toLocaleString()}%`;
const count = (value?: number) =>
  value == null ? "Unavailable" : value.toLocaleString();
const latency = (
  upper: number | null | undefined,
  lower: number | null | undefined,
) =>
  upper == null
    ? "Unavailable"
    : lower == null
      ? `${upper.toLocaleString()} ms upper bound`
      : `${lower.toLocaleString()}–${upper.toLocaleString()} ms (bucket bounds)`;
const latestObjective = (data: Dashboard, workloadId: string) =>
  data.slo_objectives
    ?.filter((item) => item.workload_id === workloadId)
    .sort((a, b) => b.version - a.version)[0];

function Reasons({ reasons }: { reasons?: string[] }) {
  return reasons?.length ? (
    <ul className="evidence-refs">
      {reasons.map((reason) => (
        <li key={reason}>{readable(reason)}</li>
      ))}
    </ul>
  ) : null;
}

function ObjectiveForm({
  workload,
  objective,
  run,
  busy,
  onClose,
}: {
  workload: Workload;
  objective?: SloObjective;
  run: RunMutation;
  busy: boolean;
  onClose: () => void;
}) {
  // A background refresh must not silently rebase an operator's policy edit.
  const [baseVersion] = useState(objective?.version ?? 0);
  const [limits, setLimits] = useState(() =>
    Object.fromEntries(
      limitFields.map(([key]) => [
        key,
        objective?.limits[key]?.toString() ?? "",
      ]),
    ),
  );
  const [minutes, setMinutes] = useState(
    objective?.evaluation_minutes.toString() ?? "",
  );
  const [mode, setMode] = useState<"ALWAYS" | "WINDOWS">(
    objective?.availability.mode ?? "ALWAYS",
  );
  const [timezone, setTimezone] = useState(
    objective?.availability.timezone ?? workload.timezone,
  );
  const [windows, setWindows] = useState(
    () =>
      objective?.availability.windows.map((window) => ({
        ...window,
        key: crypto.randomUUID(),
      })) ?? [],
  );
  const [regression, setRegression] = useState(
    objective?.regression.enabled ?? false,
  );
  const [percent, setPercent] = useState(
    objective?.regression.max_percent.toString() ?? "",
  );
  const [error, setError] = useState("");
  const updateWindow = (
    key: string,
    patch: Partial<(typeof windows)[number]>,
  ) =>
    setWindows((current) =>
      current.map((window) =>
        window.key === key ? { ...window, ...patch } : window,
      ),
    );
  return (
    <Modal
      title="Configure service objectives"
      subtitle={`${workload.name} · objective revision ${baseVersion} · platform administrator`}
      onClose={onClose}
    >
      <form
        onSubmit={async (event) => {
          event.preventDefault();
          setError("");
          const values = Object.fromEntries(
            limitFields.map(([key]) => [key, Number(limits[key])]),
          ) as SloObjectiveRequest["limits"];
          if (
            limitFields.some(
              ([key, , min, max]) =>
                limits[key] === "" ||
                !Number.isSafeInteger(values[key]) ||
                values[key] < min ||
                (max !== undefined && values[key] > max),
            ) ||
            values.max_p99_latency_ms < values.max_p95_latency_ms
          ) {
            setError(
              "Use integer limits and a p99 maximum at least as large as the p95 maximum.",
            );
            return;
          }
          if (
            !Number.isInteger(Number(minutes)) ||
            Number(minutes) < 2 ||
            Number(minutes) > 60
          ) {
            setError(
              "Choose an evaluation window from 2 to 60 complete minutes.",
            );
            return;
          }
          try {
            new Intl.DateTimeFormat("en", { timeZone: timezone }).format();
          } catch {
            setError("Enter a valid IANA timezone.");
            return;
          }
          if (
            mode === "WINDOWS" &&
            (!windows.length ||
              windows.some(
                (window) =>
                  !window.days.length || window.start_time >= window.end_time,
              ))
          ) {
            setError(
              "Add at least one same-day availability window with selected days and an end after its start.",
            );
            return;
          }
          if (
            regression &&
            (!Number.isInteger(Number(percent)) ||
              percent === "" ||
              Number(percent) < 0 ||
              Number(percent) > 1000)
          ) {
            setError(
              "Choose an independent regression allowance from 0 to 1000 percent.",
            );
            return;
          }
          const body: SloObjectiveRequest = {
            schema_version: "1",
            limits: values,
            evaluation_minutes: Number(minutes),
            availability: {
              mode,
              timezone,
              windows:
                mode === "ALWAYS"
                  ? []
                  : windows.map(({ days, start_time, end_time }) => ({
                      days: [...days].sort((a, b) => a - b),
                      start_time,
                      end_time,
                    })),
            },
            regression: {
              enabled: regression,
              max_percent: regression ? Number(percent) : 0,
            },
          };
          if (
            await run({
              path: `/workloads/${workload.id}/slo-objectives`,
              version: baseVersion,
              body,
              label:
                "Objective revision recorded. Refresh readiness before creating a new plan; no plan was approved or executed.",
            })
          )
            onClose();
          else
            setError(
              "Objective not saved. Check the request error and refresh before retrying if the objective version changed.",
            );
        }}
      >
        <p className="form-note">
          Hard limits and baseline regression are independent constraints.
          Either breach blocks automation. Saving a policy does not create
          trusted observations or approve a change.
        </p>
        <fieldset className="days-fieldset">
          <legend>Absolute hard limits</legend>
          <div className="form-grid">
            {limitFields.map(([key, label, min, max]) => (
              <label className="field" key={key}>
                <span>{label}</span>
                <input
                  required
                  type="number"
                  min={min}
                  max={max}
                  step={1}
                  value={limits[key]}
                  onChange={(event) =>
                    setLimits((current) => ({
                      ...current,
                      [key]: event.target.value,
                    }))
                  }
                />
              </label>
            ))}
            <label className="field">
              <span>Evaluation window (minutes)</span>
              <input
                required
                type="number"
                min={2}
                max={60}
                step={1}
                value={minutes}
                onChange={(event) => setMinutes(event.target.value)}
              />
            </label>
          </div>
          <p className="form-note">
            Rates use integer parts per million: 10,000 ppm = 1%; 1,000,000 ppm
            = 100%. Latency limits use integer milliseconds.
          </p>
        </fieldset>
        <fieldset className="days-fieldset">
          <legend>Availability obligation</legend>
          <div className="form-grid">
            <label className="field">
              <span>Required availability</span>
              <select
                value={mode}
                onChange={(event) => setMode(event.target.value as typeof mode)}
              >
                <option value="ALWAYS">Always, every day</option>
                <option value="WINDOWS">Explicit weekly windows</option>
              </select>
            </label>
            <label className="field">
              <span>Availability timezone</span>
              <input
                required
                value={timezone}
                onChange={(event) => setTimezone(event.target.value)}
                autoComplete="off"
                placeholder="Europe/London"
              />
            </label>
          </div>
          <p className="form-note">
            {mode === "ALWAYS"
              ? "Always-on availability blocks stopping a standalone instance. A low error rate or zero demand cannot waive this obligation."
              : "The complete stop-to-required-readiness interval must be outside these availability windows. Windows cannot cross midnight."}
          </p>
          {mode === "WINDOWS" && (
            <>
              {windows.map((window, index) => (
                <fieldset className="days-fieldset" key={window.key}>
                  <legend>Availability window {index + 1}</legend>
                  <div className="slo-day-options">
                    {days.map((day, dayIndex) => (
                      <label key={day}>
                        <input
                          type="checkbox"
                          checked={window.days.includes(dayIndex)}
                          onChange={(event) =>
                            updateWindow(window.key, {
                              days: event.target.checked
                                ? [...window.days, dayIndex]
                                : window.days.filter(
                                    (value) => value !== dayIndex,
                                  ),
                            })
                          }
                        />
                        <span>{day}</span>
                      </label>
                    ))}
                  </div>
                  <div className="form-grid">
                    <label className="field">
                      <span>Window {index + 1} starts</span>
                      <input
                        type="time"
                        required
                        value={window.start_time}
                        onChange={(event) =>
                          updateWindow(window.key, {
                            start_time: event.target.value,
                          })
                        }
                      />
                    </label>
                    <label className="field">
                      <span>Window {index + 1} ends</span>
                      <input
                        type="time"
                        required
                        value={window.end_time}
                        onChange={(event) =>
                          updateWindow(window.key, {
                            end_time: event.target.value,
                          })
                        }
                      />
                    </label>
                  </div>
                  <Button
                    type="button"
                    secondary
                    small
                    onClick={() =>
                      setWindows((current) =>
                        current.filter((item) => item.key !== window.key),
                      )
                    }
                  >
                    Remove availability window {index + 1}
                  </Button>
                </fieldset>
              ))}
              <Button
                type="button"
                secondary
                small
                disabled={windows.length >= 32}
                onClick={() =>
                  setWindows((current) => [
                    ...current,
                    {
                      key: crypto.randomUUID(),
                      days: [],
                      start_time: "",
                      end_time: "",
                    },
                  ])
                }
              >
                Add availability window
              </Button>
            </>
          )}
        </fieldset>
        <fieldset className="days-fieldset">
          <legend>Independent baseline regression guard</legend>
          <label className="checkbox-field">
            <input
              type="checkbox"
              checked={regression}
              onChange={(event) => setRegression(event.target.checked)}
            />
            <span>Require a frozen, measurable pre-plan latency baseline</span>
          </label>
          {regression && (
            <label className="field">
              <span>Maximum latency regression (%)</span>
              <input
                type="number"
                required
                min={0}
                max={1000}
                step={1}
                value={percent}
                onChange={(event) => setPercent(event.target.value)}
              />
            </label>
          )}
          <p className="form-note">
            This allowance never relaxes a hard limit. Enabling it requires
            sufficient trusted baseline samples; missing baseline latency blocks
            new stops.
          </p>
        </fieldset>
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
            Save objective revision
          </Button>
        </div>
      </form>
    </Modal>
  );
}

function SourceForm({
  data,
  run,
  busy,
  onClose,
}: {
  data: Dashboard;
  run: RunMutation;
  busy: boolean;
  onClose: () => void;
}) {
  const [resourceId, setResourceId] = useState("");
  const [objective, setObjective] = useState<SloObjective>();
  const [subject, setSubject] = useState("");
  const [failed, setFailed] = useState(false);
  return (
    <Modal
      title="Register independent SLO collector"
      subtitle="Exact machine identity · no observation upload"
      onClose={onClose}
    >
      <form
        onSubmit={async (event) => {
          event.preventDefault();
          if (!objective) return;
          const body: components["schemas"]["SloSourceRequest"] = {
            objective_id: objective.id,
            resource_id: resourceId,
            subject: subject.trim(),
          };
          if (
            await run({
              path: "/slo-sources",
              body,
              label:
                "SLO collector registered. Trusted interval coverage is still required; no execution authority granted.",
            })
          )
            onClose();
          else setFailed(true);
        }}
      >
        <p className="form-note">
          The server binds the resource, account, region, issuer, and exact
          dedicated machine subject. The collector must remain reachable while
          the instance is stopped. Console credentials cannot submit SLO
          observations.
        </p>
        <label className="field">
          <span>SLO collector resource</span>
          <select
            required
            value={resourceId}
            onChange={(event) => {
              const selected = data.resources.find(
                (item) => item.id === event.target.value,
              );
              setResourceId(event.target.value);
              setObjective(
                selected
                  ? latestObjective(data, selected.workload_id)
                  : undefined,
              );
            }}
          >
            <option value="">Choose a resource with an objective</option>
            {data.resources
              .filter((item) => latestObjective(data, item.workload_id))
              .map((item) => (
                <option key={item.id} value={item.id}>
                  {item.name} · {item.provider_resource_id}
                </option>
              ))}
          </select>
        </label>
        {objective && (
          <p className="binding-caption">
            Objective revision {objective.version} · <code>{objective.id}</code>
          </p>
        )}
        <label className="field">
          <span>Exact machine subject</span>
          <input
            required
            autoComplete="off"
            value={subject}
            onChange={(event) => setSubject(event.target.value)}
          />
        </label>
        {failed && (
          <p role="alert" className="blocker-text">
            Collector not registered. Check the request error and refresh the
            objective before retrying.
          </p>
        )}
        <div className="modal-actions">
          <Button secondary type="button" onClick={onClose}>
            Cancel
          </Button>
          <Button
            type="submit"
            pending={busy}
            disabled={!objective || !subject.trim()}
          >
            Register SLO collector
          </Button>
        </div>
      </form>
    </Modal>
  );
}

function Checks({
  checks,
  label,
}: {
  checks: NonNullable<SloEvaluation["hard_checks"]>;
  label: string;
}) {
  return (
    <section aria-label={label}>
      {checks.length ? (
        <Table
          scrollLabel={`Scrollable ${label.toLowerCase()}`}
          headings={["Constraint", "Result", "Reason"]}
        >
          {checks.map((check) => (
            <tr key={check.name}>
              <td>{readable(check.name)}</td>
              <td>
                <Badge
                  value={check.status}
                  tone={
                    check.status === "PASS"
                      ? "green"
                      : check.status === "FAIL"
                        ? "red"
                        : "neutral"
                  }
                />
              </td>
              <td>{readable(check.reason_code)}</td>
            </tr>
          ))}
        </Table>
      ) : (
        <p className="form-note">
          No evaluated constraints supplied. An empty result is not a passing
          assessment.
        </p>
      )}
    </section>
  );
}

function Evaluation({
  resource,
  snapshot,
}: {
  resource: Resource;
  snapshot?: SloEvaluationSnapshot;
}) {
  if (!snapshot)
    return (
      <section
        className="slo-resource"
        aria-label={`SLO evaluation for ${resource.name}`}
      >
        <h3>{resource.name}</h3>
        <Empty
          title="SLO assessment unavailable"
          text="Configure objectives and an independent collector. Missing evidence does not authorize a stop."
        />
      </section>
    );
  const { evaluation: result, objective, source } = snapshot;
  const complete = result.coverage_ppm === 1_000_000;
  return (
    <section
      className="slo-resource"
      aria-label={`SLO evaluation for ${resource.name}`}
    >
      <div className="policy-row">
        <span>
          <strong>{resource.name}</strong>
          <small>
            Current SLO evaluation · objective revision{" "}
            {result.objective_version || "unavailable"}
          </small>
        </span>
        <Badge value={result.status} />
      </div>
      <Reasons reasons={result.reason_codes} />
      <dl className="definition-list slo-observations">
        <div>
          <dt>Observation window</dt>
          <dd>
            {dateTime(result.window_start)} — {dateTime(result.window_end)}
          </dd>
        </div>
        <div>
          <dt>Trusted interval coverage</dt>
          <dd>
            {ppm(result.coverage_ppm)} · {count(result.observed_intervals)}/
            {count(result.expected_intervals)} intervals
          </dd>
        </div>
        <div>
          <dt>Requests / errors</dt>
          <dd>
            {complete
              ? `${count(result.request_count)} / ${count(result.error_count)}`
              : "Unavailable · incomplete coverage"}
          </dd>
        </div>
        <div>
          <dt>Latency samples</dt>
          <dd>
            {complete
              ? `${count(result.latency_samples)} · ${readable(result.latency_status || "UNKNOWN")}`
              : "Unavailable · incomplete coverage"}
          </dd>
        </div>
        <div>
          <dt>p95 latency</dt>
          <dd>
            {complete
              ? latency(result.p95_latency_ms, result.p95_lower_ms)
              : "Unavailable"}
          </dd>
        </div>
        <div>
          <dt>p99 latency</dt>
          <dd>
            {complete
              ? latency(result.p99_latency_ms, result.p99_lower_ms)
              : "Unavailable"}
          </dd>
        </div>
        <div>
          <dt>Error rate</dt>
          <dd>{ppm(complete ? result.error_rate_ppm : undefined)}</dd>
        </div>
        <div>
          <dt>Availability</dt>
          <dd>
            {ppm(complete ? result.availability_ppm : undefined)}
            {complete && (
              <small>
                {count(result.availability_good_seconds)}/
                {count(result.availability_total_seconds)} eligible seconds
              </small>
            )}
          </dd>
        </div>
        <div>
          <dt>Evidence received</dt>
          <dd>{dateTime(result.received_at)}</dd>
        </div>
        <div>
          <dt>Independent source</dt>
          <dd className="evidence-id">
            {source?.subject || result.source_id || "Unavailable"}
            <small>{source?.issuer || "Issuer unavailable"}</small>
          </dd>
        </div>
      </dl>
      <p className="form-note">
        Latency comes from trusted histogram bucket bounds. Zero demand or
        insufficient samples leave latency unavailable. CloudWatch hourly maxima
        are not latency quantiles.
      </p>
      <div className="slo-guards">
        <div>
          <h3>Absolute hard limits</h3>
          {objective ? (
            <dl className="definition-list">
              <div>
                <dt>Maximum p95 / p99</dt>
                <dd>
                  {objective.limits.max_p95_latency_ms} /{" "}
                  {objective.limits.max_p99_latency_ms} ms
                </dd>
              </div>
              <div>
                <dt>Maximum error rate</dt>
                <dd>{ppm(objective.limits.max_error_rate_ppm)}</dd>
              </div>
              <div>
                <dt>Minimum availability</dt>
                <dd>{ppm(objective.limits.min_availability_ppm)}</dd>
              </div>
              <div>
                <dt>Minimum latency samples</dt>
                <dd>{objective.limits.min_latency_samples}</dd>
              </div>
            </dl>
          ) : (
            <p className="form-note">Objective limits unavailable.</p>
          )}
          <Checks
            checks={result.hard_checks || []}
            label={`Hard-limit results for ${resource.name}`}
          />
        </div>
        <div>
          <h3>Independent regression guard</h3>
          <p className="form-note">
            {!objective
              ? "Regression policy unavailable."
              : objective.regression.enabled
                ? `Maximum latency regression: ${objective.regression.max_percent}%. A hard-limit pass cannot waive this guard.`
                : "Regression guard is not enabled in the supplied objective. Hard limits remain enforced."}
          </p>
          <p className="binding-caption">
            Frozen baseline:{" "}
            <code>{result.baseline_evaluation_id || "Unavailable"}</code>
          </p>
          <Checks
            checks={result.regression_checks || []}
            label={`Regression results for ${resource.name}`}
          />
        </div>
      </div>
      <details className="slo-receipts">
        <summary>Trusted evidence and snapshot references</summary>
        <dl className="definition-list">
          <div>
            <dt>Objective hash</dt>
            <dd className="evidence-id">
              {result.objective_hash || "Unavailable"}
            </dd>
          </div>
          <div>
            <dt>Source hash</dt>
            <dd className="evidence-id">
              {result.source_hash || "Unavailable"}
            </dd>
          </div>
          <div>
            <dt>Sealed evaluation</dt>
            <dd className="evidence-id">
              {snapshot.snapshot_id || "Not sealed"}
              <small>
                {snapshot.snapshot_hash ||
                  "Refresh readiness to bind an immutable evaluation."}
              </small>
            </dd>
          </div>
          <div>
            <dt>Baseline evaluation hash</dt>
            <dd className="evidence-id">
              {result.baseline_evaluation_hash || "Unavailable"}
            </dd>
          </div>
        </dl>
        {result.receipt_ids?.length ? (
          <ul className="evidence-refs" aria-label="Trusted SLO receipts">
            {result.receipt_ids.map((id) => (
              <li key={id}>{id}</li>
            ))}
          </ul>
        ) : (
          <p className="form-note">No trusted receipt references supplied.</p>
        )}
      </details>
    </section>
  );
}

export function SloSafety({
  data,
  run,
  busy,
}: {
  data: Dashboard;
  run: RunMutation;
  busy: boolean;
}) {
  const [editing, setEditing] = useState<Workload | null>(null);
  const [registering, setRegistering] = useState(false);
  return (
    <>
      <Panel
        title="Service objectives & trusted evidence"
        eyebrow="HARD LIMITS & INDEPENDENT REGRESSION"
        action={
          <Button
            secondary
            small
            disabled={busy || !data.slo_objectives?.length}
            onClick={() => setRegistering(true)}
          >
            Register SLO collector
          </Button>
        }
      >
        <div className="policy-note">
          <ShieldCheck size={19} aria-hidden="true" />
          <div>
            <strong>Hard limits and regression guards are independent.</strong>
            <p>
              Either breach blocks new stops. Trusted SLO evidence supplements
              workload activity, dependency review, and restoration health
              checks. This scheduling view does not establish fleet canary or
              production headroom acceptance.
            </p>
          </div>
        </div>
        <section aria-label="Workload SLO objectives">
          {data.workloads.length ? (
            <Table
              scrollLabel="Scrollable workload objectives"
              headings={[
                "Workload",
                "Objective revision",
                "Availability obligation",
                "Action",
              ]}
            >
              {data.workloads.map((workload) => {
                const objective = latestObjective(data, workload.id);
                return (
                  <tr key={workload.id}>
                    <td>
                      <strong>{workload.name}</strong>
                      <small>{workload.owner || "Owner unknown"}</small>
                    </td>
                    <td>
                      {objective ? (
                        <>
                          <strong>Revision {objective.version}</strong>
                          <small className="evidence-id" title={objective.hash}>
                            {shortId(objective.hash)}
                          </small>
                        </>
                      ) : (
                        "Not configured"
                      )}
                    </td>
                    <td>
                      {objective ? (
                        <>
                          <strong>
                            {objective.availability.mode === "ALWAYS"
                              ? "Always available · singleton stop blocked"
                              : "Explicit weekly windows"}
                          </strong>
                          <small>
                            {objective.availability.timezone} ·{" "}
                            {objective.evaluation_minutes}-minute evaluation
                          </small>
                          {objective.availability.windows.map(
                            (window, index) => (
                              <small key={index}>
                                {window.days.map((day) => days[day]).join(", ")}{" "}
                                · {window.start_time}–{window.end_time}
                              </small>
                            ),
                          )}
                        </>
                      ) : (
                        "Unknown availability obligation"
                      )}
                    </td>
                    <td>
                      <Button
                        secondary
                        small
                        disabled={busy}
                        aria-label={`Configure SLO objectives for ${workload.name}`}
                        onClick={() => setEditing(workload)}
                      >
                        Configure objectives
                      </Button>
                    </td>
                  </tr>
                );
              })}
            </Table>
          ) : (
            <Empty
              title="No workload objectives available"
              text="Discover and classify a workload before configuring its service objectives."
            />
          )}
        </section>
        {data.resources.map((resource) => (
          <Evaluation
            key={resource.id}
            resource={resource}
            snapshot={data.slo_evaluations?.find(
              (item) => item.resource_id === resource.id,
            )}
          />
        ))}
        {!!data.slo_sources?.length && (
          <section aria-label="Registered SLO collectors">
            <h3>Independent collector identities</h3>
            <Table
              scrollLabel="Scrollable SLO collectors"
              headings={[
                "Resource",
                "Machine subject",
                "Provider binding",
                "Registration",
              ]}
            >
              {data.slo_sources.map((source) => (
                <tr key={source.id}>
                  <td>
                    {data.resources.find(
                      (resource) => resource.id === source.resource_id,
                    )?.name || source.resource_id}
                    <small>Objective {source.objective_id}</small>
                  </td>
                  <td className="evidence-id">
                    {source.subject}
                    <small>{source.issuer}</small>
                  </td>
                  <td>
                    {source.provider_resource_id}
                    <small>
                      {source.account_id} · {source.region}
                    </small>
                  </td>
                  <td>
                    <Badge value={source.enabled ? "CONNECTED" : "BLOCKED"}>
                      {source.enabled ? "Registered" : "Disabled"}
                    </Badge>
                    <small>Registration does not prove coverage</small>
                  </td>
                </tr>
              ))}
            </Table>
          </section>
        )}
      </Panel>
      {editing && (
        <ObjectiveForm
          workload={editing}
          objective={latestObjective(data, editing.id)}
          run={run}
          busy={busy}
          onClose={() => setEditing(null)}
        />
      )}
      {registering && (
        <SourceForm
          data={data}
          run={run}
          busy={busy}
          onClose={() => setRegistering(false)}
        />
      )}
    </>
  );
}
