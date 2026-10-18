import { useState } from "react";
import { SourceTrust } from "./SourceTrust";
import {
  Activity,
  ArrowDownRight,
  ArrowRight,
  ArrowUpRight,
  Check,
  CheckCircle2,
  CircleAlert,
  Cloud,
  Code2,
  Download,
  Eye,
  FileCheck2,
  Fingerprint,
  Link2,
  Pause,
  Play,
  Plus,
  ShieldCheck,
  SkipForward,
  Sparkles,
  Timer,
} from "lucide-react";
import {
  Badge,
  Button,
  Empty,
  Evidence,
  EvidenceSummary,
  ExecutionReadiness,
  Metric,
  Modal,
  Panel,
  Table,
  TextLink,
  currentSavings,
  hasBoundMeasurement,
  isTrustedPlan,
  isMoneyKnown,
  dateTime,
  matches,
  money,
  preExecutionReady,
  resourceReadiness,
  readable,
  shortId,
  sumMoney,
  type RunMutation,
} from "./ui";
import type {
  ChangePlan,
  Dashboard,
  Document,
  Page,
  Recommendation,
  Workload,
} from "./types";

type PageProps = {
  data: Dashboard;
  run: RunMutation;
  busy: boolean;
  query: string;
};
const weekdayNames = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
const titleFor = (data: Dashboard, id: string) =>
  data.workloads.find((item) => item.id === id)?.name || shortId(id);
const resourceFor = (data: Dashboard, id: string) =>
  data.resources.find((item) => item.id === id)?.name || shortId(id);
function Heading({
  eyebrow,
  title,
  description,
  children,
}: {
  eyebrow: string;
  title: string;
  description: string;
  children?: React.ReactNode;
}) {
  return (
    <div className="page-heading">
      <div>
        <div className="eyebrow">{eyebrow}</div>
        <h1>
          {title}
          <span className="title-dot">.</span>
        </h1>
        <p>{description}</p>
      </div>
      {children}
    </div>
  );
}
function RecordButton({
  item,
  inspect,
}: {
  item: Document;
  inspect: (item: Document) => void;
}) {
  return (
    <button
      className="icon-button"
      title="Inspect evidence"
      aria-label={`Inspect ${item.id}`}
      onClick={() => inspect(item)}
    >
      <Eye size={17} />
    </button>
  );
}
function NoMatches() {
  return <div className="no-matches">No records match this search.</div>;
}
function ReadinessCell({
  data,
  resourceId,
  run,
  busy,
}: {
  data: Dashboard;
  resourceId: string;
  run: RunMutation;
  busy: boolean;
}) {
  const readiness = resourceReadiness(data, resourceId);
  return (
    <div className="resource-readiness">
      <ExecutionReadiness record={readiness} />
      <small className="blocker-text">
        {readiness?.reason_code
          ? readable(readiness.reason_code)
          : "Fresh baseline assessment required"}
      </small>
      <Button
        secondary
        small
        pending={busy}
        onClick={() =>
          void run({
            path: `/resources/${resourceId}/readiness/refresh`,
            label:
              "Readiness refreshed. Generate recommendations to bind a new change plan.",
          })
        }
      >
        Refresh assessment
      </Button>
    </div>
  );
}

function SignalForm({
  workload,
  run,
  busy,
  onClose,
}: {
  workload: Workload;
  run: RunMutation;
  busy: boolean;
  onClose: () => void;
}) {
  const [signals, setSignals] = useState({
    incident: workload.incident || "UNKNOWN",
    deployment: workload.deployment || "UNKNOWN",
    job: workload.job || "UNKNOWN",
  });
  return (
    <Modal
      title="Update workload signals"
      subtitle={workload.name}
      onClose={onClose}
    >
      <form
        onSubmit={async (event) => {
          event.preventDefault();
          const result = await run({
            path: `/workloads/${workload.id}/signals`,
            body: signals,
            version: workload.version,
            label: "Workload signals updated",
          });
          if (result) onClose();
        }}
      >
        <p className="form-note">
          Signals are timestamped when received. Stops require fresh, clear
          evidence for every safety input.
        </p>
        <div className="form-grid">
          {(["incident", "deployment", "job"] as const).map((key) => (
            <label className="field" key={key}>
              <span>{readable(key)}</span>
              <select
                aria-label={readable(key)}
                value={signals[key]}
                onChange={(event) =>
                  setSignals((current) => ({
                    ...current,
                    [key]: event.target.value,
                  }))
                }
              >
                <option value="CLEAR">Clear</option>
                <option value="ACTIVE">Active</option>
                <option value="UNKNOWN">Unknown</option>
              </select>
            </label>
          ))}
        </div>
        <div className="modal-actions">
          <Button secondary type="button" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" pending={busy}>
            Publish signals
            <ArrowRight size={15} />
          </Button>
        </div>
      </form>
    </Modal>
  );
}

export function WorkloadsPage({ data, run, busy, query }: PageProps) {
  const [inspect, setInspect] = useState<Document | null>(null);
  const [signalWorkload, setSignalWorkload] = useState<Workload | null>(null);
  const resources = data.resources.filter((item) =>
    matches(
      query,
      item.name,
      item.provider_resource_id,
      item.environment,
      item.state,
      titleFor(data, item.workload_id),
    ),
  );
  const workloads = data.workloads.filter((item) =>
    matches(query, item.name, item.owner, item.environment),
  );
  return (
    <>
      <Heading
        eyebrow="INVENTORY & OWNERSHIP"
        title="Know what you run"
        description="Workload context and fresh safety evidence make automation possible."
      />
      <div className="workload-grid">
        {workloads.map((item) => (
          <Panel key={item.id} className="workload-card">
            <div className="workload-card-top">
              <span className="workload-symbol">
                <Code2 size={21} />
              </span>
              <Badge
                value={item.environment}
                tone={
                  item.environment?.toLowerCase().includes("prod") &&
                  !item.environment?.toLowerCase().includes("non")
                    ? "red"
                    : "neutral"
                }
              />
            </div>
            <h2>{item.name}</h2>
            <p className="card-owner">{item.owner || "Owner unknown"}</p>
            <div className="workload-signals">
              {(["incident", "deployment", "job"] as const).map((key) => (
                <div key={key}>
                  <span>{readable(key)}</span>
                  <Badge value={item[key]} />
                </div>
              ))}
            </div>
            <div className="workload-card-footer">
              <small>Signals: {dateTime(item.signals_at)}</small>
              <TextLink onClick={() => setSignalWorkload(item)}>
                Update signals
              </TextLink>
            </div>
          </Panel>
        ))}
      </div>
      {!workloads.length && (
        <Panel>
          <Empty
            title={query ? "No matching workloads" : "No workloads discovered"}
            text="Connected AWS inventory is grouped into workloads using ownership and environment evidence."
          />
        </Panel>
      )}
      <Panel
        title="Cloud resources"
        action={
          <span className="count-pill">{resources.length} resources</span>
        }
      >
        {resources.length ? (
          <Table
            headings={[
              "Resource",
              "Workload / environment",
              "State",
              "Eligibility",
              "Execution readiness",
              "Monthly compute",
              "",
            ]}
          >
            {resources.map((item) => (
              <tr key={item.id}>
                <td>
                  <div className="resource-name">
                    <span className="aws-icon">ec2</span>
                    <div>
                      <strong>{item.name || item.provider_resource_id}</strong>
                      <small className="mono">
                        {item.provider_resource_id}
                      </small>
                    </div>
                  </div>
                </td>
                <td>
                  <strong>{titleFor(data, item.workload_id)}</strong>
                  <small>
                    {readable(item.environment)} ·{" "}
                    {readable(item.configuration_authority)}
                  </small>
                </td>
                <td>
                  <Badge value={item.state} />
                </td>
                <td>
                  <Badge
                    value={
                      typeof item.eligibility === "boolean"
                        ? item.eligibility
                          ? "ELIGIBLE"
                          : "BLOCKED"
                        : item.eligibility
                    }
                  />
                  <small className="blocker-text">
                    {(item.blockers || []).map(readable).join(" · ")}
                  </small>
                </td>
                <td className="numeric">
                  <ReadinessCell
                    data={data}
                    resourceId={item.id}
                    run={run}
                    busy={busy}
                  />
                </td>
                <td className="numeric">
                  {money(item.monthly_effective_cost, item.currency)}
                  <small>
                    {!isMoneyKnown(item.monthly_effective_cost) ||
                    !item.currency
                      ? "No evidenced compute price"
                      : "Source currency · compute"}
                  </small>
                </td>
                <td>
                  <RecordButton item={item} inspect={setInspect} />
                </td>
              </tr>
            ))}
          </Table>
        ) : query ? (
          <NoMatches />
        ) : (
          <Empty
            title="Inventory will appear here"
            text="Connect an AWS account to discover eligible and excluded EC2 resources."
          />
        )}
      </Panel>
      {inspect && (
        <Evidence record={inspect} onClose={() => setInspect(null)} />
      )}
      {signalWorkload && (
        <SignalForm
          workload={signalWorkload}
          run={run}
          busy={busy}
          onClose={() => setSignalWorkload(null)}
        />
      )}
    </>
  );
}

function PlanForm({
  recommendation,
  data,
  run,
  busy,
  onClose,
  onCreated,
}: {
  recommendation: Recommendation;
  data: Dashboard;
  run: RunMutation;
  busy: boolean;
  onClose: () => void;
  onCreated: () => void;
}) {
  const schedules = data.schedules.filter(
    (item) => item.workload_id === recommendation.workload_id,
  );
  const [scheduleId, setScheduleId] = useState(schedules[0]?.id || "");
  const [acknowledged, setAcknowledged] = useState(false);
  return (
    <Modal
      title="Create immutable change plan"
      subtitle={recommendation.title}
      onClose={onClose}
    >
      <form
        onSubmit={async (event) => {
          event.preventDefault();
          const result = await run({
            path: "/change-plans",
            body: {
              recommendation_id: recommendation.id,
              ...(scheduleId ? { schedule_id: scheduleId } : {}),
              memory_state_acknowledged: true,
              public_ip_change_acknowledged: true,
            },
            label:
              "Immutable change plan created. Review and approve it in Schedules.",
          });
          if (result) onCreated();
        }}
      >
        <div className="plan-summary">
          <ShieldCheck size={23} />
          <div>
            <strong>Approve the exact action you intend</strong>
            <p>
              A signed plan binds the resource, schedule and policy versions,
              permitted operations, expiry, and nonce.
            </p>
          </div>
        </div>
        <label className="field">
          <span>Schedule</span>
          <select
            value={scheduleId}
            onChange={(event) => setScheduleId(event.target.value)}
            required={schedules.length > 0}
          >
            {!schedules.length && (
              <option value="">Use recommendation occurrence</option>
            )}
            {schedules.map((item) => (
              <option key={item.id} value={item.id}>
                {item.stop_time} → {item.ready_time} · {item.timezone}
              </option>
            ))}
          </select>
        </label>
        <dl className="definition-list">
          <div>
            <dt>Workload</dt>
            <dd>{titleFor(data, recommendation.workload_id)}</dd>
          </div>
          <div>
            <dt>Risk class</dt>
            <dd>{recommendation.risk_class} · Non-production scheduling</dd>
          </div>
          <div>
            <dt>Estimated monthly opportunity</dt>
            <dd>
              {money(recommendation.monthly_saving, recommendation.currency)}
            </dd>
          </div>
        </dl>
        <EvidenceSummary record={recommendation} />
        {preExecutionReady(recommendation) &&
          recommendation.verification_status === "MEASURING" && (
            <p className="form-note">
              The baseline is ready for execution. Savings remain measuring
              until the post-activation window and financial evidence are
              complete. Creating the plan reserves its measurement reference.
            </p>
          )}
        <label className="checkbox-field">
          <input
            type="checkbox"
            checked={acknowledged}
            onChange={(event) => setAcknowledged(event.target.checked)}
            required
          />
          <span>
            I acknowledge that stopping loses in-memory state and may change an
            automatically assigned public IPv4 address. This workload can safely
            stop and restart.
          </span>
        </label>
        <div className="modal-actions">
          <Button secondary type="button" onClick={onClose}>
            Cancel
          </Button>
          <Button
            type="submit"
            pending={busy}
            disabled={!acknowledged || !preExecutionReady(recommendation)}
          >
            <Fingerprint size={16} />
            Create signed plan
          </Button>
        </div>
      </form>
    </Modal>
  );
}

export function RecommendationsPage({
  data,
  run,
  busy,
  query,
  navigate,
}: PageProps & { navigate: (page: Page) => void }) {
  const [inspect, setInspect] = useState<Document | null>(null);
  const [planFor, setPlanFor] = useState<Recommendation | null>(null);
  const items = data.recommendations.filter((item) =>
    matches(
      query,
      item.title,
      item.status,
      titleFor(data, item.workload_id),
      item.reason_code,
    ),
  );
  return (
    <>
      <Heading
        eyebrow="OPPORTUNITIES WITH EVIDENCE"
        title="Make idle time count"
        description="Recommendations pair observed idle windows with workload and billing evidence."
      >
        <Button
          pending={busy}
          onClick={() =>
            void run({
              path: "/recommendations",
              label: "Recommendations refreshed from available evidence",
            })
          }
        >
          <Sparkles size={16} />
          Generate recommendations
        </Button>
      </Heading>
      <div className="info-strip">
        <ShieldCheck size={19} />
        <div>
          <strong>Only avoidable, uncovered compute spend qualifies.</strong>
          <span>
            Production, unknown authority, unresolved dependencies, and missing
            commitment evidence block execution.
          </span>
        </div>
      </div>
      {items.length ? (
        <div className="recommendation-list">
          {items.map((item) => (
            <Panel key={item.id} className="recommendation-card">
              <div className="recommendation-body">
                <span className="recommendation-symbol">
                  <Timer size={25} />
                </span>
                <div className="recommendation-main">
                  <div className="card-badges">
                    <Badge value={item.status} />
                    <span className="risk-label">
                      {item.risk_class} · SCHEDULING
                    </span>
                  </div>
                  <div className="readiness-summary">
                    <span>
                      Execution <ExecutionReadiness record={item} />
                    </span>
                    <span>
                      Savings verification{" "}
                      <Badge value={item.verification_status || "UNVERIFIED"} />
                    </span>
                  </div>
                  <h2>{item.title}</h2>
                  <p>
                    {titleFor(data, item.workload_id)}{" "}
                    <span className="middot">·</span> {readable(item.category)}
                  </p>
                  <div className="recommendation-evidence">
                    <span>
                      <Activity size={14} />
                      {item.baseline_id
                        ? "Frozen baseline bound"
                        : "Complete baseline required"}
                    </span>
                    <span>
                      <ShieldCheck size={14} />
                      {typeof item.confidence === "number"
                        ? `${Math.round(item.confidence <= 1 ? item.confidence * 100 : item.confidence)}%`
                        : readable(item.confidence)}{" "}
                      confidence
                    </span>
                  </div>
                  {item.reason_code && (
                    <div className="reason-line">
                      {readable(item.reason_code)}
                    </div>
                  )}
                  {item.baseline_id && (
                    <div className="binding-caption">
                      Baseline{" "}
                      <span className="mono" title={item.baseline_id}>
                        {shortId(item.baseline_id)}
                      </span>
                    </div>
                  )}
                </div>
                <div className="recommendation-value">
                  <small>Estimated monthly opportunity</small>
                  <strong>{money(item.monthly_saving, item.currency)}</strong>
                  <span>
                    {money(item.annual_saving, item.currency)} annual run-rate
                  </span>
                </div>
              </div>
              <div className="recommendation-footer">
                <TextLink onClick={() => setInspect(item)}>
                  Inspect supporting evidence
                </TextLink>
                <Button
                  small
                  pending={busy}
                  disabled={
                    item.status !== "VALIDATED" || !preExecutionReady(item)
                  }
                  title={
                    item.status !== "VALIDATED" || !preExecutionReady(item)
                      ? readable(item.reason_code || item.status)
                      : "Create an immutable signed occurrence plan"
                  }
                  onClick={() => setPlanFor(item)}
                >
                  Create change plan
                  <ArrowUpRight size={15} />
                </Button>
              </div>
            </Panel>
          ))}
        </div>
      ) : (
        <Panel>
          <Empty
            title={
              query ? "No matching recommendations" : "No recommendations yet"
            }
            text="Connect an account and supply complete workload and cost history, then generate recommendations."
          />
        </Panel>
      )}
      {inspect && (
        <Evidence record={inspect} onClose={() => setInspect(null)} />
      )}
      {planFor && (
        <PlanForm
          recommendation={planFor}
          data={data}
          run={run}
          busy={busy}
          onClose={() => setPlanFor(null)}
          onCreated={() => {
            setPlanFor(null);
            navigate("schedules");
          }}
        />
      )}
    </>
  );
}

function ScheduleForm({
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
  const [values, setValues] = useState({
    workload_id: data.workloads[0]?.id || "",
    stop_time: "20:00",
    ready_time: "07:00",
    timezone: data.workloads[0]?.timezone || "Europe/London",
    mode: "ASSISTED_EXECUTION",
  });
  const [days, setDays] = useState([1, 2, 3, 4, 5]);
  const [acknowledged, setAcknowledged] = useState(false);
  const autopilotAllowed = data.policies.some(
    (policy) =>
      Array.isArray(policy.workload_autopilot_ids) &&
      policy.workload_autopilot_ids.includes(values.workload_id),
  );
  return (
    <Modal
      title="Create a workload schedule"
      subtitle="Local time windows with durable restoration"
      onClose={onClose}
    >
      <form
        onSubmit={async (event) => {
          event.preventDefault();
          const result = await run({
            path: "/schedules",
            body: {
              ...values,
              days,
              memory_state_acknowledged: true,
              public_ip_change_acknowledged: true,
              autopilot_opt_in: values.mode === "AUTOPILOT",
            },
            label: "Schedule created",
          });
          if (result) onClose();
        }}
      >
        <div className="form-grid">
          <label className="field full-width">
            <span>Workload</span>
            <select
              required
              value={values.workload_id}
              onChange={(event) =>
                setValues((current) => ({
                  ...current,
                  workload_id: event.target.value,
                }))
              }
            >
              {data.workloads.map((item) => (
                <option key={item.id} value={item.id}>
                  {item.name} · {item.environment}
                </option>
              ))}
            </select>
          </label>
          <label className="field">
            <span>Stop at</span>
            <input
              type="time"
              value={values.stop_time}
              required
              onChange={(event) =>
                setValues((current) => ({
                  ...current,
                  stop_time: event.target.value,
                }))
              }
            />
          </label>
          <label className="field">
            <span>Required availability</span>
            <input
              type="time"
              value={values.ready_time}
              required
              onChange={(event) =>
                setValues((current) => ({
                  ...current,
                  ready_time: event.target.value,
                }))
              }
            />
          </label>
          <label className="field full-width">
            <span>IANA timezone</span>
            <input
              value={values.timezone}
              required
              placeholder="Europe/London"
              onChange={(event) =>
                setValues((current) => ({
                  ...current,
                  timezone: event.target.value,
                }))
              }
            />
          </label>
          <label className="field full-width">
            <span>Scheduling mode</span>
            <select
              value={values.mode}
              onChange={(event) =>
                setValues((current) => ({
                  ...current,
                  mode: event.target.value,
                }))
              }
            >
              <option value="OBSERVE">Observe</option>
              <option value="RECOMMEND">Recommend</option>
              <option value="ASSISTED_EXECUTION">
                Assisted · approve each occurrence
              </option>
              <option value="AUTOPILOT">
                Autopilot · expiring scoped policy
              </option>
              <option value="FROZEN">Frozen</option>
            </select>
          </label>
        </div>
        <fieldset className="days-fieldset">
          <legend>Stop days</legend>
          <div className="day-options">
            {weekdayNames.map((name, index) => (
              <label
                className={days.includes(index + 1) ? "selected" : ""}
                key={name}
              >
                <input
                  type="checkbox"
                  checked={days.includes(index + 1)}
                  onChange={(event) =>
                    setDays((current) =>
                      event.target.checked
                        ? [...current, index + 1].sort()
                        : current.filter((day) => day !== index + 1),
                    )
                  }
                />
                {name}
              </label>
            ))}
          </div>
        </fieldset>
        <p className="form-note">
          <Timer size={16} />
          Restoration begins 15 minutes before required availability. Pausing a
          schedule never cancels owned restoration.
        </p>
        {values.mode === "AUTOPILOT" && (
          <p className="form-note">
            Autopilot requires platform-admin approval of this workload in the
            scoped policy. Schedules expire after 30 days.{" "}
            {autopilotAllowed
              ? "This workload is within the approved policy scope."
              : "Update the scoped policy below before creating an Autopilot schedule."}
          </p>
        )}
        <label className="checkbox-field">
          <input
            type="checkbox"
            checked={acknowledged}
            onChange={(event) => setAcknowledged(event.target.checked)}
            required
          />
          <span>
            I acknowledge loss of in-memory state and possible changes to an
            automatically assigned public IPv4 address. This workload can safely
            stop and restart.
          </span>
        </label>
        <div className="modal-actions">
          <Button secondary type="button" onClick={onClose}>
            Cancel
          </Button>
          <Button
            type="submit"
            pending={busy}
            disabled={
              !values.workload_id ||
              !days.length ||
              !acknowledged ||
              (values.mode === "AUTOPILOT" && !autopilotAllowed)
            }
          >
            Create schedule
            <ArrowRight size={15} />
          </Button>
        </div>
      </form>
    </Modal>
  );
}

function PlanReview({
  plan,
  data,
  run,
  busy,
  onClose,
}: {
  plan: ChangePlan;
  data: Dashboard;
  run: RunMutation;
  busy: boolean;
  onClose: () => void;
}) {
  const [acknowledged, setAcknowledged] = useState(false);
  const schedule = data.schedules.find((item) => item.id === plan.schedule_id);
  const recommendation = data.recommendations.find(
    (item) => item.id === plan.recommendation_id,
  );
  return (
    <Modal
      title="Review & approve change plan"
      subtitle={shortId(plan.id)}
      onClose={onClose}
    >
      <div className="plan-summary">
        <Fingerprint size={23} />
        <div>
          <strong>Immutable scope. Explicit authorization.</strong>
          <p>
            Approval authorizes this signed occurrence. The execution service
            rechecks every safety gate before stopping.
          </p>
        </div>
      </div>
      <dl className="definition-list">
        <div>
          <dt>Recommendation</dt>
          <dd>{recommendation?.title || plan.recommendation_id}</dd>
        </div>
        <div>
          <dt>Risk</dt>
          <dd>{plan.risk_class}</dd>
        </div>
        <div>
          <dt>Schedule</dt>
          <dd>
            {schedule
              ? `${schedule.stop_time} → ${schedule.ready_time} · ${schedule.timezone}`
              : "Plan-defined occurrence"}
          </dd>
        </div>
        <div>
          <dt>Expires</dt>
          <dd>{dateTime(plan.expires_at)}</dd>
        </div>
        <div>
          <dt>Version</dt>
          <dd>{plan.version}</dd>
        </div>
      </dl>
      <EvidenceSummary record={plan} />
      <details className="plan-operations" open>
        <summary>Bound operations & restoration</summary>
        <pre>{JSON.stringify(plan.operations, null, 2)}</pre>
      </details>
      <label className="checkbox-field">
        <input
          type="checkbox"
          checked={acknowledged}
          onChange={(event) => setAcknowledged(event.target.checked)}
        />
        <span>
          I reviewed this plan and authorize its stop and restoration operations
          for the stated scope.
        </span>
      </label>
      <div className="modal-actions">
        <Button secondary onClick={onClose}>
          Cancel
        </Button>
        <Button
          pending={busy}
          disabled={!acknowledged || !isTrustedPlan(plan)}
          onClick={async () => {
            const result = await run({
              path: "/approvals",
              body: { change_plan_id: plan.id },
              version: plan.version,
              label: "Change plan approved",
            });
            if (result) onClose();
          }}
        >
          <Check size={16} />
          Approve plan
        </Button>
      </div>
    </Modal>
  );
}

function PolicyForm({
  policy,
  data,
  run,
  busy,
  onClose,
}: {
  policy: Document;
  data: Dashboard;
  run: RunMutation;
  busy: boolean;
  onClose: () => void;
}) {
  const [workloadIds, setWorkloadIds] = useState<string[]>(
    Array.isArray(policy.workload_autopilot_ids)
      ? policy.workload_autopilot_ids.map(String)
      : [],
  );
  const [acknowledged, setAcknowledged] = useState(false);
  return (
    <Modal
      title="Approve scoped Autopilot policy"
      subtitle={String(policy.name || policy.id)}
      onClose={onClose}
    >
      <form
        onSubmit={async (event) => {
          event.preventDefault();
          const result = await run({
            path: `/policies/${policy.id}`,
            version: policy.version,
            body: { workload_autopilot_ids: workloadIds },
            label: "Scoped policy updated. Autopilot grants expire in 30 days.",
          });
          if (result) onClose();
        }}
      >
        <div className="plan-summary">
          <ShieldCheck size={23} />
          <div>
            <strong>Explicit authority for named workloads</strong>
            <p>
              Only selected non-production workloads may create Autopilot
              schedules. This grant expires in 30 days; safety gates and signed
              occurrence plans remain required.
            </p>
          </div>
        </div>
        <div className="policy-workloads">
          {data.workloads
            .filter((workload) => workload.environment === "NON_PRODUCTION")
            .map((workload) => (
              <label className="checkbox-field" key={workload.id}>
                <input
                  type="checkbox"
                  checked={workloadIds.includes(workload.id)}
                  onChange={(event) =>
                    setWorkloadIds((current) =>
                      event.target.checked
                        ? [...current, workload.id]
                        : current.filter((id) => id !== workload.id),
                    )
                  }
                />
                <span>
                  <strong>{workload.name}</strong>
                  <br />
                  {workload.owner}
                </span>
              </label>
            ))}
        </div>
        <label className="checkbox-field">
          <input
            required
            type="checkbox"
            checked={acknowledged}
            onChange={(event) => setAcknowledged(event.target.checked)}
          />
          <span>
            I authorize scheduling Autopilot only for the selected workloads
            within the existing non-production guardrails.
          </span>
        </label>
        <div className="modal-actions">
          <Button secondary type="button" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" pending={busy} disabled={!acknowledged}>
            <Fingerprint size={16} />
            Approve workload scope
          </Button>
        </div>
      </form>
    </Modal>
  );
}

export function SchedulesPage({
  data,
  run,
  busy,
  query,
  navigate,
}: PageProps & { navigate: (page: Page) => void }) {
  const [creating, setCreating] = useState(false);
  const [inspect, setInspect] = useState<Document | null>(null);
  const [review, setReview] = useState<ChangePlan | null>(null);
  const [editPolicy, setEditPolicy] = useState<Document | null>(null);
  const schedules = data.schedules.filter((item) =>
    matches(query, titleFor(data, item.workload_id), item.timezone, item.mode),
  );
  const plans = data.change_plans.filter((item) =>
    matches(
      query,
      item.id,
      item.status,
      data.recommendations.find((rec) => rec.id === item.recommendation_id)
        ?.title,
    ),
  );
  return (
    <>
      <Heading
        eyebrow="POLICY-GOVERNED AUTOMATION"
        title="Set the right rhythm"
        description="Explicit timezones, scoped approvals, and restoration that survives a pause."
      >
        <Button
          onClick={() => setCreating(true)}
          disabled={!data.workloads.length}
        >
          <Plus size={16} />
          Create schedule
        </Button>
      </Heading>
      <Panel
        title="Workload schedules"
        action={
          <span className="count-pill">{schedules.length} schedules</span>
        }
      >
        {schedules.length ? (
          <div className="schedule-list">
            {schedules.map((item) => (
              <div className="schedule-row" key={item.id}>
                <span className="schedule-symbol">
                  <Timer size={23} />
                </span>
                <div className="schedule-info">
                  <strong>{titleFor(data, item.workload_id)}</strong>
                  <span>
                    {item.timezone} <span className="middot">·</span>{" "}
                    {(item.days || [])
                      .map((day) => weekdayNames[day - 1])
                      .join(", ")}
                  </span>
                  <div className="schedule-badges">
                    <Badge value={item.mode} />
                    {item.paused && <Badge value="FROZEN">Paused</Badge>}
                    {item.skip_next_stop && (
                      <Badge value="PENDING">Next stop skipped</Badge>
                    )}
                  </div>
                </div>
                <div className="schedule-window">
                  <span>STOP</span>
                  <strong>{item.stop_time}</strong>
                </div>
                <ArrowRight className="schedule-window-arrow" size={18} />
                <div className="schedule-window">
                  <span>READY BY</span>
                  <strong>{item.ready_time}</strong>
                  <small>Start 15m earlier</small>
                </div>
                <div className="row-actions">
                  <Button
                    small
                    secondary
                    pending={busy}
                    onClick={() =>
                      void run({
                        path: `/schedules/${item.id}/skip-next-stop`,
                        version: item.version,
                        label: "The next scheduled stop will be skipped",
                      })
                    }
                  >
                    <SkipForward size={14} />
                    Skip next
                  </Button>
                  <Button
                    small
                    secondary
                    pending={busy}
                    onClick={() =>
                      void run({
                        path: `/schedules/${item.id}/pause`,
                        body: { paused: !item.paused },
                        version: item.version,
                        label: item.paused
                          ? "Schedule resumed"
                          : "Schedule paused. Restoration remains authorized.",
                      })
                    }
                  >
                    {item.paused ? <Play size={14} /> : <Pause size={14} />}
                    {item.paused ? "Resume" : "Pause"}
                  </Button>
                  <RecordButton item={item} inspect={setInspect} />
                </div>
              </div>
            ))}
          </div>
        ) : query ? (
          <NoMatches />
        ) : (
          <Empty
            title="Choose your first idle window"
            text="Schedules define when a non-production workload may stop and when it must be ready."
            action={
              <Button
                onClick={() => setCreating(true)}
                disabled={!data.workloads.length}
              >
                Create schedule
              </Button>
            }
          />
        )}
      </Panel>
      <Panel
        title="Immutable change plans"
        eyebrow="APPROVAL & EXECUTION"
        action={
          <TextLink onClick={() => navigate("recommendations")}>
            Create from recommendation
          </TextLink>
        }
      >
        {plans.length ? (
          <Table
            headings={[
              "Plan / recommendation",
              "Risk",
              "Status",
              "Expires",
              "Actions",
            ]}
          >
            {plans.map((item) => {
              const executed = data.executions.some(
                (execution) => execution.change_plan_id === item.id,
              );
              const bound = isTrustedPlan(item);
              const ready = preExecutionReady(
                resourceReadiness(data, item.resource_id),
              );
              return (
                <tr key={item.id}>
                  <td>
                    <strong>
                      {data.recommendations.find(
                        (rec) => rec.id === item.recommendation_id,
                      )?.title || shortId(item.recommendation_id)}
                    </strong>
                    <small className="mono">
                      {shortId(item.id)} · v{item.version}
                    </small>
                    <small>
                      {bound
                        ? `Baseline ${shortId(item.baseline_id!)} · Measurement ${shortId(item.measurement_id!)}`
                        : "Historical plan · fresh bound evidence required"}
                    </small>
                  </td>
                  <td>
                    <span className="risk-label">{item.risk_class}</span>
                  </td>
                  <td>
                    <Badge value={item.status} />
                  </td>
                  <td>{dateTime(item.expires_at)}</td>
                  <td>
                    <div className="row-actions">
                      {item.status === "APPROVED" && !executed ? (
                        <Button
                          small
                          pending={busy}
                          disabled={!bound || !ready}
                          title={
                            !bound
                              ? "Create a fresh plan bound to current baseline and measurement evidence"
                              : !ready
                                ? "Refresh execution readiness before dispatch"
                                : undefined
                          }
                          onClick={async () => {
                            const result = await run({
                              path: "/executions",
                              body: { change_plan_id: item.id },
                              version: item.version,
                              label: "Durable execution started",
                            });
                            if (result) navigate("executions");
                          }}
                        >
                          <Play size={14} />
                          Execute approved plan
                        </Button>
                      ) : !/APPROVED|EXECUTED|COMPLETED|REJECTED|EXPIRED|CANCELLED/.test(
                          item.status,
                        ) ? (
                        <Button
                          small
                          pending={busy}
                          disabled={!bound}
                          title={
                            !bound
                              ? "Historical plan is read-only; create a fresh evidence-bound plan"
                              : undefined
                          }
                          onClick={() => setReview(item)}
                        >
                          <Fingerprint size={14} />
                          Review & approve
                        </Button>
                      ) : executed ? (
                        <TextLink onClick={() => navigate("executions")}>
                          View execution
                        </TextLink>
                      ) : null}
                      <RecordButton item={item} inspect={setInspect} />
                    </div>
                  </td>
                </tr>
              );
            })}
          </Table>
        ) : query ? (
          <NoMatches />
        ) : (
          <Empty
            title="No change plans yet"
            text="Create a plan from a recommendation. Every occurrence binds its own target, operations, expiry, and signature."
          />
        )}
      </Panel>
      <Panel
        title="Scoped autonomy policies"
        action={<ShieldCheck size={18} className="teal" />}
      >
        {data.policies.length ? (
          <div className="policy-list">
            {data.policies
              .filter((item) => matches(query, JSON.stringify(item)))
              .map((item) => (
                <div className="policy-row" key={item.id}>
                  <span>
                    <strong>
                      {String(item.name || item.action_class || item.id)}
                    </strong>
                    <small>
                      Version {item.version} · expires{" "}
                      {dateTime(
                        String(
                          item.autopilot_expires_at || item.expires_at || "",
                        ),
                      )}
                    </small>
                  </span>
                  <Badge value={item.mode || item.status} />
                  <Button secondary small onClick={() => setEditPolicy(item)}>
                    Manage scope
                  </Button>
                  <RecordButton item={item} inspect={setInspect} />
                </div>
              ))}
          </div>
        ) : (
          <div className="policy-note">
            <ShieldCheck size={24} />
            <div>
              <strong>Assisted execution is the pilot default</strong>
              <p>
                Each occurrence requires explicit approval. Autopilot schedules
                require a separately approved, expiring workload policy.
              </p>
            </div>
          </div>
        )}
      </Panel>
      {creating && (
        <ScheduleForm
          data={data}
          run={run}
          busy={busy}
          onClose={() => setCreating(false)}
        />
      )}
      {review && (
        <PlanReview
          plan={review}
          data={data}
          run={run}
          busy={busy}
          onClose={() => setReview(null)}
        />
      )}
      {editPolicy && (
        <PolicyForm
          policy={editPolicy}
          data={data}
          run={run}
          busy={busy}
          onClose={() => setEditPolicy(null)}
        />
      )}
      {inspect && (
        <Evidence record={inspect} onClose={() => setInspect(null)} />
      )}
    </>
  );
}

const stages = ["Preflight", "Stop", "Observe", "Restore", "Verify health"];
function stageIndex(stage: string, status: string): number {
  const value = `${stage} ${status}`.toUpperCase();
  if (/COMPLET|HEALTHY|READINESS|VERIFY/.test(value)) return 4;
  if (/RESTOR|START/.test(value)) return 3;
  if (/OBSERV|STOPPED|WAIT/.test(value)) return 2;
  if (/STOP|DISPATCH/.test(value)) return 1;
  return 0;
}
export function ExecutionsPage({ data, run, busy, query }: PageProps) {
  const [inspect, setInspect] = useState<Document | null>(null);
  const items = data.executions
    .filter((item) =>
      matches(
        query,
        item.id,
        item.stage,
        item.status,
        resourceFor(data, item.resource_id),
      ),
    )
    .slice()
    .reverse();
  return (
    <>
      <Heading
        eyebrow="DURABLE ACTIONS & RESTORATION"
        title="Every change, in view"
        description="Follow the execution, ownership, and readiness of each approved occurrence."
      />
      <div className="info-strip">
        <Activity size={19} />
        <div>
          <strong>
            Restoration persists through pauses and approval expiry.
          </strong>
          <span>
            Only resources stopped by an occurrence are restored. Manual stops
            are left untouched.
          </span>
        </div>
      </div>
      {items.length ? (
        <div className="execution-list">
          {items.map((item) => {
            const index = stageIndex(item.stage, item.status);
            const done = /COMPLETED|SUCCEEDED/.test(item.status);
            return (
              <Panel className="execution-card" key={item.id}>
                <div className="execution-card-head">
                  <div>
                    <div className="card-badges">
                      <Badge value={item.status} />
                      {item.restoration_owned && (
                        <span className="ownership-badge">
                          <ShieldCheck size={13} />
                          Restoration owned
                        </span>
                      )}
                    </div>
                    <h2>{resourceFor(data, item.resource_id)}</h2>
                    <small className="mono">
                      {shortId(item.id)} <span className="middot">·</span>{" "}
                      Started {dateTime(item.started_at)}
                    </small>
                  </div>
                  <div className="row-actions">
                    {item.restoration_owned && (
                      <Button
                        secondary
                        small
                        pending={busy}
                        onClick={() =>
                          void run({
                            path: `/executions/${item.id}/start-now`,
                            version: item.version,
                            label: "Immediate restoration requested",
                          })
                        }
                      >
                        <Play size={14} />
                        Start now
                      </Button>
                    )}
                    <RecordButton item={item} inspect={setInspect} />
                  </div>
                </div>
                <div className="execution-progress">
                  {stages.map((name, position) => (
                    <div
                      className={`execution-step ${position < index || done ? "complete" : ""} ${position === index && !done ? "current" : ""}`}
                      key={name}
                    >
                      <span>
                        {position < index || done ? (
                          <Check size={15} />
                        ) : (
                          position + 1
                        )}
                      </span>
                      <strong>{name}</strong>
                    </div>
                  ))}
                </div>
                <div className="execution-card-footer">
                  <span>
                    <span className={done ? "live-dot" : "pulse-dot"} />
                    {readable(item.stage || item.status)}
                  </span>
                  <span>
                    {done
                      ? "Execution completed · evidence retained"
                      : "Durable workflow · refreshed every 4 seconds"}
                  </span>
                </div>
                {item.error && (
                  <div className="execution-error">
                    <CircleAlert size={16} />
                    <span>{item.error}</span>
                  </div>
                )}
              </Panel>
            );
          })}
        </div>
      ) : (
        <Panel>
          <Empty
            title={query ? "No matching executions" : "Ready when you are"}
            text="Approve an immutable change plan, then execute it from Schedules & policies. The fixture workflow uses logical time and completes in seconds."
          />
        </Panel>
      )}
      {inspect && (
        <Evidence record={inspect} onClose={() => setInspect(null)} />
      )}
    </>
  );
}

function CurrencySummary({ data }: { data: Dashboard }) {
  const currencies = [...new Set(data.savings.map((item) => item.currency))];
  if (!currencies.length)
    return (
      <div className="metrics-grid three">
        <Metric
          label="Verified period savings"
          value="Unavailable"
          detail="No verified measurement periods"
          icon={<ShieldCheck size={17} />}
          accent
        />
        <Metric
          label="Measurement records"
          value="0"
          detail="Run financial verification after execution"
          icon={<FileCheck2 size={17} />}
        />
        <Metric
          label="Reconciliation gate"
          value="99.5%"
          detail="Minimum required for verified status"
          icon={<CheckCircle2 size={17} />}
        />
      </div>
    );
  return (
    <div className="currency-summaries">
      {currencies.map((currency) => {
        const records = currentSavings(data.savings).filter(
          (item) => item.currency === currency,
        );
        const verified = records.filter(
          (item) => item.status === "VERIFIED" && hasBoundMeasurement(item),
        );
        const provisional = records.filter(
          (item) => item.status !== "VERIFIED" && hasBoundMeasurement(item),
        );
        return (
          <div className="metrics-grid three" key={currency}>
            <Metric
              label={`Verified period savings · ${currency}`}
              value={money(
                sumMoney(verified.map((item) => item.verified_saving)),
                currency,
              )}
              detail={`${verified.length} bound final measurement records · legacy history excluded`}
              icon={<ShieldCheck size={17} />}
              accent
            />
            <Metric
              label={`Provisional / unverified · ${currency}`}
              value={provisional.length}
              detail="Excluded from verified savings totals"
              icon={<FileCheck2 size={17} />}
            />
            <Metric
              label="Reconciliation gate"
              value="99.5%"
              detail="Invoice and source finality also required"
              icon={<CheckCircle2 size={17} />}
            />
          </div>
        );
      })}
    </div>
  );
}
export function SavingsPage({ data, run, busy, query }: PageProps) {
  const [inspect, setInspect] = useState<Document | null>(null);
  const items = data.savings.filter((item) =>
    matches(query, item.id, item.currency, item.status, item.reason_code),
  );
  const eligible = data.executions.some((item) =>
    /COMPLETED|SUCCEEDED/.test(item.status),
  );
  const currentIds = new Set(
    currentSavings(data.savings).map((item) => item.id),
  );
  return (
    <>
      <Heading
        eyebrow="MEASURED, RECONCILED, VERIFIED"
        title="Savings you can stand behind"
        description="Frozen baselines and preserved workload demand turn estimates into financial evidence."
      >
        <Button
          pending={busy}
          disabled={!eligible}
          onClick={() =>
            void run({
              path: "/savings/verify",
              label:
                "Savings evidence refreshed. Measurement windows and finality gates determine verification.",
            })
          }
        >
          <FileCheck2 size={16} />
          Verify savings
        </Button>
      </Heading>
      <CurrencySummary data={data} />
      {data.fixture && (
        <div className="fixture-notice">
          <Timer size={21} />
          <div>
            <strong>Fixture financial clock · logical time</strong>
            <p>
              Financial windows simulate fourteen complete days. Provider
              stop/start receipts belong to the actual fixture cycle; the
              resulting savings are deterministic test evidence.
            </p>
          </div>
          <span className="fixture-badge">
            <span />
            FIXTURE MODE
          </span>
        </div>
      )}
      <div className="savings-method">
        <span className="method-icon">
          <Fingerprint size={24} />
        </span>
        <div>
          <strong>A claim is only as strong as its evidence.</strong>
          <p>
            14 complete days before and after activation, matched weekday/time
            windows, preserved work, final invoices, and at least 99.5%
            reconciliation. Continuing EBS and retained-IP costs receive no
            savings claim.
          </p>
        </div>
        <Badge value="VERIFIED" tone="neutral">
          Append-only ledger
        </Badge>
      </div>
      <Panel
        title="Measurement ledger"
        action={<span className="count-pill">{items.length} records</span>}
      >
        {items.length ? (
          <Table
            headings={[
              "Measurement",
              "Status",
              "Baseline / actual",
              "Period savings",
              "Evidence",
            ]}
          >
            {items.map((item) => (
              <tr key={item.id}>
                <td>
                  <strong>{shortId(item.id)}</strong>
                  <small>Execution {shortId(item.execution_id)}</small>
                </td>
                <td>
                  {hasBoundMeasurement(item) ? (
                    <Badge
                      value={
                        currentIds.has(item.id) ? item.status : "SUPERSEDED"
                      }
                    />
                  ) : (
                    <Badge value="LEGACY">Legacy / unbound history</Badge>
                  )}
                  {item.reason_code && (
                    <small className="blocker-text">
                      {readable(item.reason_code)}
                    </small>
                  )}
                </td>
                <td>
                  <div className="cost-comparison">
                    <span>
                      {money(item.expected_baseline_cost, item.currency)}
                    </span>
                    <ArrowRight size={13} />
                    <strong>{money(item.actual_cost, item.currency)}</strong>
                  </div>
                  <small>Baseline → actual · {item.currency}</small>
                </td>
                <td
                  className={`saving-amount ${Number(item.verified_saving) < 0 ? "negative" : ""}`}
                >
                  {money(item.verified_saving, item.currency)}
                  <small>
                    {!hasBoundMeasurement(item)
                      ? "Legacy / unbound history · excluded from verified totals"
                      : !currentIds.has(item.id)
                        ? "Superseded · retained history"
                        : item.status === "VERIFIED"
                          ? "Verified measurement period"
                          : "Not a verified savings claim"}
                  </small>
                </td>
                <td>
                  <RecordButton item={item} inspect={setInspect} />
                </td>
              </tr>
            ))}
          </Table>
        ) : query ? (
          <NoMatches />
        ) : (
          <Empty
            title="Build the evidence, then verify"
            text="Complete a scheduling execution and run verification. Provisional or incomplete evidence cannot become a verified savings claim."
          />
        )}
      </Panel>
      <div className="two-column">
        <Panel title="How verification works">
          <ol className="method-steps">
            <li>
              <span>01</span>
              <div>
                <strong>Freeze the counterfactual</strong>
                <p>
                  Match historical runtime to comparable weekday and time
                  windows.
                </p>
              </div>
            </li>
            <li>
              <span>02</span>
              <div>
                <strong>Confirm work was preserved</strong>
                <p>
                  Demand observations are required. Zero demand is valid
                  evidence.
                </p>
              </div>
            </li>
            <li>
              <span>03</span>
              <div>
                <strong>Reconcile every attributable cost</strong>
                <p>
                  Include startup and incremental costs; retain negative
                  outcomes.
                </p>
              </div>
            </li>
            <li>
              <span>04</span>
              <div>
                <strong>Preserve the financial history</strong>
                <p>
                  Corrections append superseding entries. Overlapping claims are
                  excluded.
                </p>
              </div>
            </li>
          </ol>
        </Panel>
        <Panel title="Annual run-rate is an estimate">
          <div className="annual-note">
            <ArrowDownRight size={32} />
            <h3>
              Period evidence first.
              <br />
              Forecasts separately.
            </h3>
            <p>
              Recommendations show estimated annual run-rate. The ledger above
              reports the measured savings period in its source currency.
            </p>
            <p>
              Source currencies stay separate. Foreign exchange conversion is
              outside this pilot.
            </p>
          </div>
        </Panel>
      </div>
      {inspect && (
        <Evidence record={inspect} onClose={() => setInspect(null)} />
      )}
    </>
  );
}

function AccountForm({
  run,
  busy,
  fixture,
  onClose,
}: {
  run: RunMutation;
  busy: boolean;
  fixture: boolean;
  onClose: () => void;
}) {
  const [values, setValues] = useState({
    provider: "AWS",
    name: "",
    account_id: "",
    region: "eu-west-1",
  });
  return (
    <Modal
      title="Connect an AWS account"
      subtitle={
        fixture
          ? "Deterministic fixture adapter · no AWS calls"
          : "Cross-account discovery"
      }
      onClose={onClose}
    >
      <form
        onSubmit={async (event) => {
          event.preventDefault();
          const result = await run({
            path: "/cloud-accounts",
            body: values,
            label: "AWS account connected and inventory discovered",
          });
          if (result) onClose();
        }}
      >
        <div className="plan-summary">
          <Cloud size={24} />
          <div>
            <strong>Start with read-only discovery</strong>
            <p>
              {fixture
                ? "This workspace uses deterministic AWS fixtures. The account remains visibly labelled as fixture data."
                : "Discovery uses an external-ID-bound role and short-lived credentials. Stop/start requires separately delegated execution authority."}
            </p>
          </div>
        </div>
        <div className="form-grid">
          <label className="field full-width">
            <span>Connection name</span>
            <input
              required
              autoComplete="off"
              placeholder="Engineering non-production"
              value={values.name}
              onChange={(event) =>
                setValues((current) => ({
                  ...current,
                  name: event.target.value,
                }))
              }
            />
          </label>
          <label className="field">
            <span>AWS account ID</span>
            <input
              required
              pattern="[0-9]{12}"
              inputMode="numeric"
              title="Enter a 12-digit AWS account ID"
              placeholder="123456789012"
              value={values.account_id}
              onChange={(event) =>
                setValues((current) => ({
                  ...current,
                  account_id: event.target.value,
                }))
              }
            />
          </label>
          <label className="field">
            <span>Region</span>
            <select
              value={values.region}
              onChange={(event) =>
                setValues((current) => ({
                  ...current,
                  region: event.target.value,
                }))
              }
            >
              <option value="eu-west-1">eu-west-1 · Ireland</option>
            </select>
          </label>
        </div>
        <div className="modal-actions">
          <Button secondary type="button" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" pending={busy}>
            <Link2 size={16} />
            Connect & discover
          </Button>
        </div>
      </form>
    </Modal>
  );
}

export function ConnectionsPage({ data, run, busy, query }: PageProps) {
  const [creating, setCreating] = useState(false);
  const [inspect, setInspect] = useState<Document | null>(null);
  const accounts = data.cloud_accounts.filter((item) =>
    matches(query, item.name, item.account_id, item.provider, item.status),
  );
  const quality = data.data_quality.filter((item) =>
    matches(query, JSON.stringify(item)),
  );
  return (
    <>
      <Heading
        eyebrow="SOURCES & DATA QUALITY"
        title="Trust starts at the source"
        description="Connect discovery, workload telemetry, and billing without granting execution authority."
      >
        <Button onClick={() => setCreating(true)}>
          <Plus size={16} />
          Connect AWS account
        </Button>
      </Heading>
      {data.fixture && (
        <div className="fixture-notice">
          <Cloud size={21} />
          <div>
            <strong>Fixture adapter is active</strong>
            <p>
              Inventory, telemetry, billing, and transitions are deterministic
              test evidence. This workspace does not represent a live AWS
              account.
            </p>
          </div>
          <span className="fixture-badge">
            <span />
            FIXTURE MODE
          </span>
        </div>
      )}
      <Panel
        title="Cloud account connections"
        action={<span className="count-pill">{accounts.length} connected</span>}
      >
        {accounts.length ? (
          <Table
            headings={[
              "Connection",
              "Account ID",
              "Region",
              "Status",
              "Evidence",
            ]}
          >
            {accounts.map((item) => (
              <tr key={item.id}>
                <td>
                  <div className="resource-name">
                    <span className="aws-icon">aws</span>
                    <div>
                      <strong>{item.name}</strong>
                      <small>
                        {item.provider} ·{" "}
                        {data.fixture
                          ? "Fixture adapter"
                          : "Cross-account role"}
                      </small>
                    </div>
                  </div>
                </td>
                <td className="mono">{item.account_id}</td>
                <td>{item.region}</td>
                <td>
                  <Badge value={item.status || "CONNECTED"} />
                </td>
                <td>
                  <RecordButton item={item} inspect={setInspect} />
                </td>
              </tr>
            ))}
          </Table>
        ) : query ? (
          <NoMatches />
        ) : (
          <Empty
            title="Connect your first account"
            text="AWS discovery populates resources, cost evidence, and workload relationships."
            action={
              <Button onClick={() => setCreating(true)}>
                Connect AWS account
              </Button>
            }
          />
        )}
      </Panel>
      <Panel
        title="Data quality gates"
        eyebrow="INCOMPLETE EVIDENCE STAYS VISIBLE"
        action={<ShieldCheck className="teal" size={19} />}
      >
        {quality.length ? (
          <div className="quality-grid">
            {quality.map((item) => (
              <button
                className="quality-card"
                key={item.id}
                onClick={() => setInspect(item)}
              >
                <span className="quality-card-top">
                  <span className="quality-icon">
                    <FileCheck2 size={20} />
                  </span>
                  <Badge value={item.status || item.state || "UNKNOWN"} />
                </span>
                <strong>
                  {String(
                    item.name ||
                      item.label ||
                      item.check ||
                      item.source ||
                      item.id,
                  )}
                </strong>
                <p>
                  {String(
                    item.description ||
                      item.reason_code ||
                      item.message ||
                      "Inspect the source record for detailed evidence.",
                  ).replace(/_/g, " ")}
                </p>
                {item.coverage !== undefined && (
                  <span className="quality-coverage">
                    Coverage: {String(item.coverage)}
                  </span>
                )}
                <span className="quality-inspect">
                  Inspect source evidence
                  <ArrowUpRight size={14} />
                </span>
              </button>
            ))}
          </div>
        ) : (
          <Empty
            title="No quality observations yet"
            text="Ingested inventory, cost, and workload signals publish their quality evidence here."
          />
        )}
      </Panel>
      <SourceTrust data={data} run={run} busy={busy} />
      <div className="two-column">
        <Panel title="Read, approve, execute">
          <div className="boundary-list">
            <div>
              <span>01</span>
              <strong>Ingestion identity</strong>
              <p>Reads billing, telemetry, and inventory.</p>
            </div>
            <div>
              <span>02</span>
              <strong>Approval & signing identity</strong>
              <p>Signs exact, immutable change plans.</p>
            </div>
            <div>
              <span>03</span>
              <strong>Execution identity</strong>
              <p>Performs only delegated stop/start operations.</p>
            </div>
          </div>
        </Panel>
        <Panel title="Regional data residency">
          <div className="residency-card">
            <span className="residency-map">EU</span>
            <div>
              <h3>Ireland · eu-west-1</h3>
              <p>
                EU storage and processing for the first hosted cell. Raw
                evidence remains versioned and auditable.
              </p>
              <span className="subtle-label">
                <span className="live-dot" />
                Regional cell configured
              </span>
            </div>
          </div>
        </Panel>
      </div>
      {creating && (
        <AccountForm
          run={run}
          busy={busy}
          fixture={data.fixture}
          onClose={() => setCreating(false)}
        />
      )}
      {inspect && (
        <Evidence record={inspect} onClose={() => setInspect(null)} />
      )}
    </>
  );
}

export function AuditPage({ data, query }: PageProps) {
  const [inspect, setInspect] = useState<Document | null>(null);
  const items = data.audit
    .filter((item) =>
      matches(query, item.action, item.actor, item.resource, item.timestamp),
    )
    .slice()
    .sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp));
  const exportAudit = () => {
    const blob = new Blob([JSON.stringify(items, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `finops-audit-${new Date().toISOString().slice(0, 10)}.json`;
    anchor.click();
    URL.revokeObjectURL(url);
  };
  return (
    <>
      <Heading
        eyebrow="ACCOUNTABLE BY DESIGN"
        title="An unbroken trail"
        description="Who acted, what changed, and the evidence behind every decision."
      >
        <Button secondary onClick={exportAudit} disabled={!items.length}>
          <Download size={16} />
          Export visible records
        </Button>
      </Heading>
      <div className="info-strip">
        <Fingerprint size={19} />
        <div>
          <strong>Append-only audit evidence</strong>
          <span>
            Records bind tenant, actor, action, and source resource. Hosted
            evidence storage uses S3 Object Lock.
          </span>
        </div>
      </div>
      <Panel
        title="Audit events"
        action={<span className="count-pill">{items.length} events</span>}
      >
        {items.length ? (
          <Table
            headings={["Timestamp", "Action", "Actor", "Resource", "Record"]}
          >
            {items.map((item) => (
              <tr key={item.id}>
                <td className="nowrap">{dateTime(item.timestamp)}</td>
                <td>
                  <span className="audit-action">
                    <CheckCircle2 size={15} />
                    {readable(item.action)}
                  </span>
                </td>
                <td>{item.actor}</td>
                <td className="mono">
                  {shortId(
                    typeof item.resource === "string"
                      ? item.resource
                      : JSON.stringify(item.resource),
                  )}
                </td>
                <td>
                  <RecordButton item={item} inspect={setInspect} />
                </td>
              </tr>
            ))}
          </Table>
        ) : query ? (
          <NoMatches />
        ) : (
          <Empty
            title="Your audit history starts here"
            text="Account connections, recommendations, approvals, executions, and verification all create evidence."
          />
        )}
      </Panel>
      {inspect && (
        <Evidence record={inspect} onClose={() => setInspect(null)} />
      )}
    </>
  );
}
