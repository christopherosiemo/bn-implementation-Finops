import { lazy, Suspense, useState } from "react";
import type { components } from "./api.generated";
import type {
  Dashboard,
  FleetDemandDefinition,
  FleetHistoryRegistration,
  FleetHistoryScope,
} from "./types";
import { RemotePage, useRemote } from "./RemoteData";
import { FleetConfiguration } from "./FleetConfiguration";
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
type Observation = components["schemas"]["FleetHistoryObservationRecord"];
type Reference = components["schemas"]["FleetHistoryScopeReference"];
const FleetFixture = lazy(() =>
  import("./FleetFixture").then((module) => ({ default: module.FleetFixture })),
);
const FleetNativeAssessment = lazy(() =>
  import("./FleetNativeAssessment").then((module) => ({
    default: module.FleetNativeAssessment,
  })),
);
const FleetNativeCapacity = lazy(() =>
  import("./FleetNativeCapacity").then((module) => ({
    default: module.FleetNativeCapacity,
  })),
);
type RegistrationRequest =
  components["schemas"]["FleetHistoryRegistrationRequest"];
type DefinitionRequest = components["schemas"]["FleetDemandDefinitionRequest"];
type ActivityChoice = {
  id: string;
  workload: string;
  account: string;
  region: string;
  metric: string;
  version: string;
  unit: string;
};
const unknown = (value: string | null | undefined) =>
  value == null ? "Unavailable" : value;
const query = encodeURIComponent;
const kinds = [
  "SOURCE_STATE",
  "REGISTRATION",
  "DEFINITION",
  "OBSERVATION",
  "DEMAND_RECEIPT",
] as const;

function activityChoices(
  data: Dashboard,
  registration: FleetHistoryRegistration,
): ActivityChoice[] {
  return (data.activity_sources ?? []).flatMap((source) => {
    const metric = source.metric_definition as
      | Record<string, unknown>
      | undefined;
    if (
      source.enabled !== true ||
      source.workload_id !== registration.registration.binding.workload_id ||
      source.account_id !== registration.registration.binding.account_id ||
      source.region !== registration.registration.binding.region ||
      !metric ||
      typeof metric.id !== "string" ||
      typeof metric.version !== "string" ||
      typeof metric.unit !== "string"
    )
      return [];
    return [
      {
        id: source.id,
        workload: String(source.workload_id),
        account: String(source.account_id),
        region: String(source.region),
        metric: metric.id,
        version: metric.version,
        unit: metric.unit,
      },
    ];
  });
}

function RegistrationForm({
  data,
  workload,
  latest,
  run,
  busy,
  onClose,
  onSaved,
}: Props & {
  workload: string;
  latest?: FleetHistoryRegistration;
  onClose: () => void;
  onSaved: (id: string) => void;
}) {
  const previous = latest?.registration;
  const sources = (data.source_connections ?? []).filter(
    (item) =>
      item.kind === "AWS_CUR2" &&
      item.enabled === true &&
      item.revoked !== true,
  );
  const [fleet, setFleet] = useState(previous?.fleet_id ?? "");
  const [arn, setARN] = useState(previous?.asg_arn ?? "");
  const [source, setSource] = useState(previous?.source_id ?? "");
  const [cadence, setCadence] = useState(previous?.cadence_seconds ?? 60);
  const [gap, setGap] = useState(previous?.max_gap_seconds ?? 120);
  const [error, setError] = useState("");
  return (
    <Modal
      title={
        latest ? "Revise fleet history registration" : "Register fleet history"
      }
      subtitle={`Observation configuration · revision ${(latest?.version ?? 0) + 1}`}
      onClose={onClose}
    >
      <form
        className="configuration-stack"
        onSubmit={async (event) => {
          event.preventDefault();
          setError("");
          if (gap < cadence) {
            setError(
              "The maximum gap must be at least the observation cadence.",
            );
            return;
          }
          const body: RegistrationRequest = {
            workload_id: workload,
            fleet_id: fleet.trim(),
            asg_arn: arn.trim(),
            source_connection_id: source,
            cadence_seconds: cadence,
            max_gap_seconds: gap,
          };
          const saved = await run({
            path: latest
              ? `/fleet-history-registrations/${query(latest.id)}/revisions`
              : "/fleet-history-registrations",
            version: latest?.version ?? 0,
            body,
            label:
              "Fleet observation configuration recorded; historical ownership remains unproven.",
          });
          if (saved) onSaved(saved.id);
        }}
      >
        <p className="form-note">
          This registers a read-only observation target. The server binds the
          tenant, account, Ireland region and current approved source. It
          creates no fleet change or execution permission.
        </p>
        <label className="field">
          <span>Fleet identifier</span>
          <input
            required
            maxLength={256}
            readOnly={Boolean(latest)}
            value={fleet}
            onChange={(e) => setFleet(e.target.value)}
          />
        </label>
        <label className="field">
          <span>Exact ASG ARN</span>
          <input
            required
            maxLength={512}
            readOnly={Boolean(latest)}
            value={arn}
            onChange={(e) => setARN(e.target.value)}
            placeholder="arn:aws:autoscaling:eu-west-1:…:autoScalingGroup:…:autoScalingGroupName/…"
          />
        </label>
        {latest && (
          <p className="form-note">
            Workload, fleet identity and exact ASG ARN are immutable. Register a
            separate fleet when identity changes.
          </p>
        )}
        <label className="field">
          <span>Approved AWS source connection</span>
          <select
            required
            value={source}
            onChange={(e) => setSource(e.target.value)}
          >
            <option value="">Select a registered AWS source</option>
            {sources.map((item) => (
              <option key={item.id} value={item.id}>
                {item.payer_account_id} · {item.id} ·{" "}
                {readable(item.status || "UNKNOWN")}
              </option>
            ))}
          </select>
        </label>
        {!sources.length && (
          <p className="blocker-text">
            No enabled AWS source is available. Register an approved read source
            in Connections & quality first.
          </p>
        )}
        <div className="form-grid">
          <label className="field">
            <span>Observation cadence (seconds)</span>
            <input
              required
              type="number"
              min={15}
              max={600}
              step={1}
              value={cadence}
              onChange={(e) => setCadence(Number(e.target.value))}
            />
          </label>
          <label className="field">
            <span>Maximum point gap (seconds)</span>
            <input
              required
              type="number"
              min={cadence}
              max={600}
              step={1}
              value={gap}
              onChange={(e) => setGap(Number(e.target.value))}
            />
          </label>
        </div>
        {error && <p role="alert">{error}</p>}
        <Button type="submit" pending={busy} disabled={!source}>
          {latest ? "Save registration revision" : "Save fleet registration"}
        </Button>
      </form>
    </Modal>
  );
}

function DefinitionForm({
  data,
  registration,
  latest,
  run,
  busy,
  onClose,
  onSaved,
}: Props & {
  registration: FleetHistoryRegistration;
  latest?: FleetDemandDefinition;
  onClose: () => void;
  onSaved: () => void;
}) {
  const choices = activityChoices(data, registration);
  const [source, setSource] = useState(latest?.definition.source_id ?? "");
  const [operation, setOperation] = useState(
    latest?.definition.business_operation ?? "",
  );
  const [contract, setContract] = useState(
    latest?.definition.semantic_contract_id ?? "",
  );
  const [hash, setHash] = useState(
    latest?.definition.semantic_contract_hash ?? "",
  );
  const selected = choices.find((item) => item.id === source);
  return (
    <Modal
      title={
        latest
          ? "Revise completed-work definition"
          : "Declare completed-work definition"
      }
      subtitle={`${registration.registration.fleet_id} · semantic declaration`}
      onClose={onClose}
    >
      <form
        className="configuration-stack"
        onSubmit={async (event) => {
          event.preventDefault();
          const body: DefinitionRequest = {
            registration_id: registration.id,
            activity_source_id: source,
            business_operation: operation.trim(),
            semantic_contract_id: contract.trim(),
            semantic_contract_hash: hash.trim(),
          };
          if (
            await run({
              path: latest
                ? `/fleet-demand-definitions/${query(latest.id)}/revisions`
                : "/fleet-demand-definitions",
              version: latest?.version ?? 0,
              body,
              label:
                "Independent completed-work semantics declared; authenticity and work preservation remain unproven.",
            })
          )
            onSaved();
        }}
      >
        <p className="form-note">
          Declare what the independently collected Completed field means.
          Requests, accepted work and CPU are not completed business work. This
          declaration does not authenticate its meaning or prove that work was
          preserved.
        </p>
        <label className="field">
          <span>Independent completed-work source</span>
          <select
            required
            value={source}
            onChange={(e) => setSource(e.target.value)}
          >
            <option value="">Select a registered independent collector</option>
            {choices.map((item) => (
              <option key={item.id} value={item.id}>
                {item.id} · {item.metric} v{item.version} · {item.unit}
              </option>
            ))}
          </select>
        </label>
        {selected ? (
          <p className="form-note">
            The server selects activity.Completed · DELTA · {selected.metric}{" "}
            revision {selected.version} · {selected.unit}. Original guarded
            receipt times and values are retained.
          </p>
        ) : (
          <p className="blocker-text">
            An enabled collector must match this workload, account and region.
            No counts or source evidence can be entered here.
          </p>
        )}
        <label className="field">
          <span>Completed business operation</span>
          <input
            required
            maxLength={512}
            value={operation}
            onChange={(e) => setOperation(e.target.value)}
          />
        </label>
        <label className="field">
          <span>Semantic contract ID</span>
          <input
            required
            maxLength={256}
            value={contract}
            onChange={(e) => setContract(e.target.value)}
          />
        </label>
        <label className="field">
          <span>Declared semantic contract SHA-256</span>
          <input
            required
            pattern="[a-f0-9]{64}"
            maxLength={64}
            value={hash}
            onChange={(e) => setHash(e.target.value)}
          />
        </label>
        <Button type="submit" pending={busy} disabled={!selected}>
          {latest
            ? "Save definition revision"
            : "Save completed-work definition"}
        </Button>
      </form>
    </Modal>
  );
}

function PointEvidence({ record }: { record: Observation }) {
  const point = record.observation;
  return (
    <details className="native-evaluation">
      <summary>
        Native point {shortId(record.id)} · {dateTime(point.observed_at)} ·{" "}
        {point.members.length} members
      </summary>
      <p className="form-note">
        Observed at {dateTime(point.observed_at)}; original receipt received{" "}
        {dateTime(point.received_at)}. A point does not prove membership between
        observations.
      </p>
      {point.corrects_id && (
        <p>
          Explicit correction of {point.corrects_id}; prior history remains
          immutable.
        </p>
      )}
      <p className="evidence-id">
        Receipt {point.source.receipt_id} · object version{" "}
        {point.source.archive.version_id}
      </p>
      <p className="evidence-id">
        Raw {point.source.raw_sha256} · canonical {point.source.canonical_hash}
      </p>
      <Table
        scrollLabel={`Fleet member point ${record.id}`}
        headings={[
          "Native instance / inventory",
          "Launch incarnation",
          "Launch template",
          "Hardware evidence",
        ]}
      >
        {point.members.map((member) => (
          <tr key={member.instance_id}>
            <td>
              {member.instance_id}
              <small>
                {member.resource_id ||
                  "Individual inventory mapping unavailable"}
              </small>
            </td>
            <td>
              {member.launch_time
                ? dateTime(member.launch_time)
                : "Unknown launch incarnation"}
            </td>
            <td>
              {member.launch_template_id}
              <small>Version {member.launch_template_version}</small>
            </td>
            <td>
              {member.hardware
                ? member.hardware.receipt_id
                : "Hardware unavailable"}
            </td>
          </tr>
        ))}
      </Table>
      {!point.members.length && (
        <p>No members were present at this observed instant.</p>
      )}
    </details>
  );
}

function ReferenceEvidence({ reference }: { reference: Reference }) {
  const value = reference.reference;
  return (
    <li>
      <div style={{ display: "grid", rowGap: 4, marginBlock: 4 }}>
        <strong>
          {readable(reference.kind)} · {reference.id}
        </strong>
        {"source_system" in value ? (
          <>
            <small>
              {value.source_system} · {value.source_id} ·{" "}
              {readable(value.status)}
            </small>
            <small>
              Checked at capture {dateTime(value.checked_at)}
              {value.source_registration_version == null
                ? " · No registry version exists for guarded activity"
                : ` · source revision ${value.source_registration_version}`}
            </small>
            <small className="evidence-id">{value.config_hash}</small>
          </>
        ) : "body_sha256" in value ? (
          <>
            <small>Original guarded receipt · {value.source_id}</small>
            <small className="evidence-id">Body {value.body_sha256}</small>
            <small className="evidence-id">
              Canonical {value.canonical_hash}
            </small>
          </>
        ) : (
          <>
            <small>
              {"version" in value
                ? `Immutable revision ${value.version}`
                : "Immutable native point"}
            </small>
            <small className="evidence-id">{value.hash}</small>
          </>
        )}
        <small className="evidence-id">Reference hash {reference.hash}</small>
      </div>
    </li>
  );
}

function GapEvidence({
  label,
  value,
}: {
  label: string;
  value: components["schemas"]["FleetHistoryGapPreview"];
}) {
  return (
    <details>
      <summary>
        {label} · {value.count} recorded ranges
      </summary>
      <ul className="evidence-refs">
        {value.preview.map((gap, index) => (
          <li key={`${gap.start}-${gap.end}-${index}`}>
            {dateTime(gap.start)} — {dateTime(gap.end)}
            <small>{readable(gap.reason_code)}</small>
          </li>
        ))}
      </ul>
      {value.truncated && (
        <p className="form-note">
          Bounded preview; full population is pinned by the immutable hash.
        </p>
      )}
      <p className="evidence-id">{value.hash}</p>
    </details>
  );
}

function ScopeEvidence({ id }: { id: string }) {
  const state = useRemote<FleetHistoryScope>(
    `/fleet-history-scopes/${query(id)}`,
  );
  const [kind, setKind] = useState<(typeof kinds)[number]>("SOURCE_STATE");
  if (state.loading)
    return <p role="status">Loading selected immutable history scope…</p>;
  if (state.error)
    return <p role="alert">History scope unavailable. {state.error}</p>;
  if (!state.value) return null;
  const scope = state.value;
  return (
    <section
      className="native-section"
      aria-label={`Immutable fleet history scope ${scope.id}`}
    >
      <div className="policy-row">
        <strong>
          Fourteen complete UTC days · captured {dateTime(scope.as_of)}
        </strong>
        <Badge value={scope.status} />
      </div>
      <p className="blocker-text">
        Historical membership interval ownership is unproven. This snapshot
        authorizes no execution and claims no verified savings or business-work
        preservation.
      </p>
      <dl className="definition-list">
        <div>
          <dt>Server-selected period</dt>
          <dd>
            <time dateTime={scope.start}>{scope.start}</time> —{" "}
            <time dateTime={scope.end}>{scope.end}</time>
            <small>UTC · end exclusive</small>
          </dd>
        </div>
        <div>
          <dt>Point evidence</dt>
          <dd>
            {scope.selected_observation_count} selected /{" "}
            {scope.observation_count} recorded
            <small>
              {scope.demand_receipt_count} guarded Completed-field receipts
            </small>
          </dd>
        </div>
        <div>
          <dt>Observed subtotal</dt>
          <dd>
            {unknown(scope.demand.observed_units)} {scope.demand.unit}
            <small>Partial observed intervals only</small>
          </dd>
        </div>
        <div>
          <dt>Complete-window total</dt>
          <dd>
            {unknown(scope.demand.window_units)} {scope.demand.unit}
            <small>
              {readable(scope.demand.status)} ·{" "}
              {readable(scope.demand.meaning_basis)}
            </small>
          </dd>
        </div>
      </dl>
      <ul className="evidence-refs">
        {scope.reason_codes.map((reason) => (
          <li key={reason}>{readable(reason)}</li>
        ))}
      </ul>
      <GapEvidence
        label="Unproven membership intervals"
        value={scope.membership_gaps}
      />
      <GapEvidence
        label="Missing point cadence"
        value={scope.observation_gaps}
      />
      <GapEvidence
        label="Missing completed-work intervals"
        value={scope.demand.gaps}
      />
      <details>
        <summary>
          Observed completed-work intervals · {scope.demand.segments.count}
        </summary>
        <Table
          scrollLabel="Completed-work interval preview"
          headings={["Native interval", "Observation", "Exact completed count"]}
        >
          {scope.demand.segments.preview.map((segment, index) => (
            <tr key={`${segment.start}-${index}`}>
              <td>
                {dateTime(segment.start)} — {dateTime(segment.end)}
              </td>
              <td>
                {readable(segment.status)}
                <small>{readable(segment.reason_code)}</small>
              </td>
              <td>{unknown(segment.units)}</td>
            </tr>
          ))}
        </Table>
        {scope.demand.segments.truncated && (
          <p>Bounded preview; full population remains hash-bound.</p>
        )}
      </details>
      <details>
        <summary>Correction and source issues · {scope.issues.count}</summary>
        <ul className="evidence-refs">
          {scope.issues.preview.map((issue, index) => (
            <li key={`${issue.record_id}-${index}`}>
              {issue.record_id}
              <small>{readable(issue.reason_code)}</small>
            </li>
          ))}
        </ul>
        <p>{scope.superseded_ids.count} immutable predecessors superseded.</p>
      </details>
      <p className="form-note">
        Source lifecycle below is frozen at capture time. Reading this snapshot
        does not refresh currentness. Registration, definitions, native
        observations and guarded receipts remain separate immutable evidence.
      </p>
      <label className="field">
        <span>History reference kind</span>
        <select
          value={kind}
          onChange={(e) => setKind(e.target.value as (typeof kinds)[number])}
        >
          {kinds.map((item) => (
            <option key={item} value={item}>
              {readable(item)}
            </option>
          ))}
        </select>
      </label>
      <RemotePage<Reference>
        key={`${scope.id}:${kind}`}
        path={`/fleet-history-scopes/${query(scope.id)}/references?kind=${kind}&limit=10`}
        label="Fleet history references"
        empty="No references of this kind are recorded for this immutable scope."
      >
        {(items) => (
          <ul className="evidence-refs">
            {items.map((ref) => (
              <ReferenceEvidence
                key={`${ref.kind}:${ref.ordinal}`}
                reference={ref}
              />
            ))}
          </ul>
        )}
      </RemotePage>
      <p className="evidence-id">
        Reference root {scope.reference_root} · {scope.reference_count}{" "}
        references
      </p>
      <p className="evidence-id">Analysis {scope.analysis_hash}</p>
      <p className="evidence-id">Input {scope.input_hash}</p>
    </section>
  );
}

function RegistrationEvidence({
  id,
  run,
  busy,
  refresh,
  onRefresh,
  onClose,
  onEdit,
  onDefine,
}: {
  id: string;
  run: RunMutation;
  busy: boolean;
  refresh: number;
  onRefresh: () => void;
  onClose: () => void;
  onEdit: (row: FleetHistoryRegistration) => void;
  onDefine: (
    registration: FleetHistoryRegistration,
    definition?: FleetDemandDefinition,
  ) => void;
}) {
  const state = useRemote<FleetHistoryRegistration>(
    `/fleet-history-registrations/${query(id)}`,
    refresh,
  );
  const [scope, setScope] = useState("");
  return (
    <Modal
      title="Fleet history evidence"
      subtitle="Native points, declared work semantics and immutable blocked scopes"
      onClose={onClose}
    >
      {state.loading && (
        <p role="status">Reading current fleet registration…</p>
      )}
      {state.error && (
        <p role="alert">Fleet registration unavailable. {state.error}</p>
      )}
      {state.value && (
        <>
          <h3>
            {state.value.registration.fleet_id} · revision {state.value.version}
          </h3>
          <p className="evidence-id">{state.value.registration.asg_arn}</p>
          <p className="form-note">
            {state.value.registration.binding.account_id} ·{" "}
            {state.value.registration.binding.region} · AWS source{" "}
            {state.value.registration.source_id}. An ASG is not represented as a
            shared EC2 resource.
          </p>
          <div className="row-actions">
            <Button secondary small onClick={() => onEdit(state.value!)}>
              Revise observation configuration
            </Button>
            <Button secondary small onClick={onRefresh}>
              Refresh fleet history
            </Button>
          </div>
          <h3>Independent completed-work definitions</h3>
          <p className="form-note">
            A request-throughput proxy cannot stand in for independently defined
            completed work. Semantic declarations remain unverified.
          </p>
          <Button secondary small onClick={() => onDefine(state.value!)}>
            Declare completed-work definition
          </Button>
          <RemotePage<FleetDemandDefinition>
            key={`definitions:${id}:${refresh}`}
            path={`/fleet-demand-definitions?registration_id=${query(id)}&limit=10`}
            label="Fleet completed-work definitions"
            empty="Declare an independently collected Completed field before capturing a history scope."
          >
            {(items) => (
              <Table
                scrollLabel="Declared independent completed-work definitions"
                headings={[
                  "Business operation / semantic contract",
                  "Native field / unit",
                  "Revision / capture",
                ]}
              >
                {items.map((item) => (
                  <tr key={item.id}>
                    <td>
                      {item.definition.business_operation}
                      <small>{item.definition.semantic_contract_id}</small>
                      <small className="evidence-id">
                        {item.definition.semantic_contract_hash}
                      </small>
                    </td>
                    <td>
                      {item.definition.metric} · {item.definition.temporality}
                      <small>
                        {item.definition.unit} ·{" "}
                        {item.definition.metric_definition_id} v
                        {item.definition.metric_definition_version}
                      </small>
                      <small>Source {item.definition.source_id}</small>
                    </td>
                    <td>
                      Definition revision {item.version}
                      <small>
                        Registration revision {item.registration_version}
                      </small>
                      <div className="row-actions">
                        <Button
                          secondary
                          small
                          onClick={() => onDefine(state.value!, item)}
                        >
                          Revise definition {shortId(item.id)}
                        </Button>
                        <Button
                          small
                          pending={busy}
                          disabled={
                            item.registration_version !== state.value!.version
                          }
                          onClick={async () => {
                            const saved = await run({
                              path: "/fleet-history-scopes",
                              version: state.value!.version,
                              body: {
                                registration_id: id,
                                definition_id: item.id,
                                definition_version: item.version,
                              },
                              label:
                                "Immutable read-only history scope recorded; historical membership remains unproven.",
                            });
                            if (saved) {
                              setScope(saved.id);
                              onRefresh();
                            }
                          }}
                        >
                          Capture scope for {item.definition.business_operation}
                        </Button>
                      </div>
                      {item.registration_version !== state.value!.version && (
                        <small>
                          Revise this definition for the current registration
                          before capture.
                        </small>
                      )}
                    </td>
                  </tr>
                ))}
              </Table>
            )}
          </RemotePage>
          <h3>Native point observations</h3>
          <p className="form-note">
            Published only by the independent ingestion identity. Missing
            incarnation and hardware evidence remain explicit; there is no
            observation upload control.
          </p>
          <RemotePage<Observation>
            key={`observations:${id}:${refresh}`}
            path={`/fleet-history-registrations/${query(id)}/observations?limit=20`}
            label="Fleet native point observations"
            empty="No native membership point has been published for this registration. Registration alone is not evidence."
          >
            {(items) =>
              items.map((item) => <PointEvidence key={item.id} record={item} />)
            }
          </RemotePage>
          <h3>Immutable history scopes</h3>
          <RemotePage<FleetHistoryScope>
            key={`scopes:${id}:${refresh}`}
            path={`/fleet-history-scopes?registration_id=${query(id)}&limit=10`}
            label="Fleet history scopes"
            empty="No scope is recorded. Capture selects genuine stored evidence for fourteen complete UTC days."
          >
            {(items) => (
              <Table
                scrollLabel="Immutable blocked fleet history scopes"
                headings={[
                  "Capture / period",
                  "Evidence / work observations",
                  "State",
                ]}
              >
                {items.map((item) => (
                  <tr key={item.id}>
                    <td>
                      {dateTime(item.as_of)}
                      <small>
                        {dateTime(item.start)} — {dateTime(item.end)}
                      </small>
                    </td>
                    <td>
                      {item.observation_count} native points ·{" "}
                      {item.demand_receipt_count} receipts
                      <small>
                        Complete-window total:{" "}
                        {unknown(item.demand.window_units)} {item.demand.unit}
                      </small>
                    </td>
                    <td>
                      <Badge value={item.status} />
                      <Button secondary small onClick={() => setScope(item.id)}>
                        Inspect history scope {shortId(item.id)}
                      </Button>
                    </td>
                  </tr>
                ))}
              </Table>
            )}
          </RemotePage>
          {scope && <ScopeEvidence key={scope} id={scope} />}
          <FleetConfiguration
            key={`configuration:${id}:${state.value.version}`}
            registration={state.value}
            run={run}
            busy={busy}
            refresh={refresh}
          />
        </>
      )}
    </Modal>
  );
}

type Dialog =
  | { kind: "register"; record?: FleetHistoryRegistration }
  | { kind: "inspect"; id: string }
  | {
      kind: "define";
      registration: FleetHistoryRegistration;
      definition?: FleetDemandDefinition;
    };
export function FleetHistory({ data, run, busy }: Props) {
  const [workloadID, setWorkloadID] = useState("");
  const [refresh, setRefresh] = useState(0);
  const [dialog, setDialog] = useState<Dialog | null>(null);
  const workload =
    data.workloads.find((item) => item.id === workloadID) ?? data.workloads[0];
  const saved = (id: string) => {
    setRefresh((n) => n + 1);
    setDialog({ kind: "inspect", id });
  };
  return (
    <Panel
      title="Fleet history & completed-work scope"
      eyebrow="AWS Ireland · observational evidence only"
    >
      <p className="form-note">
        Inspect exact native fleet points and independent completed-work
        declarations. Point captures do not establish historical membership
        intervals. No execution, verified savings or business-work preservation
        is authorized here.
      </p>
      {!workload ? (
        <Empty
          title="No workload for fleet history"
          text="Discover and assign an owned workload before registering a fleet observation target."
        />
      ) : (
        <>
          <label className="field">
            <span>Fleet history workload</span>
            <select
              value={workload.id}
              onChange={(e) => {
                setWorkloadID(e.target.value);
                setDialog(null);
              }}
            >
              {data.workloads.map((item) => (
                <option key={item.id} value={item.id}>
                  {item.name}
                </option>
              ))}
            </select>
          </label>
          <div className="row-actions">
            <Button
              secondary
              small
              onClick={() => setDialog({ kind: "register" })}
            >
              Register fleet history
            </Button>
            <Button secondary small onClick={() => setRefresh((n) => n + 1)}>
              Refresh fleet registrations
            </Button>
          </div>
          <RemotePage<FleetHistoryRegistration>
            key={`${workload.id}:${refresh}`}
            path={`/fleet-history-registrations?workload_id=${query(workload.id)}&limit=10`}
            label="Fleet history registrations"
            empty="No fleet observation target is registered for this workload. Empty results do not prove there are no external dependencies or consumers."
          >
            {(items) => (
              <Table
                scrollLabel="Registered fleet history targets"
                headings={[
                  "Fleet / native identity",
                  "Owner / environment",
                  "Source / observation cadence",
                  "History",
                ]}
              >
                {items.map((item) => (
                  <tr key={item.id}>
                    <td>
                      {item.registration.fleet_id}
                      <small className="evidence-id">
                        {item.registration.asg_arn}
                      </small>
                      <small>
                        {item.registration.binding.account_id} ·{" "}
                        {item.registration.binding.region}
                      </small>
                    </td>
                    <td>
                      {workload.owner || "Owner unavailable"}
                      <small>{readable(workload.environment)}</small>
                    </td>
                    <td>
                      {item.registration.source_id}
                      <small>
                        {item.registration.cadence_seconds}s cadence /{" "}
                        {item.registration.max_gap_seconds}s maximum gap
                      </small>
                      <small>Revision {item.version}</small>
                    </td>
                    <td>
                      <Badge value="OBSERVATIONAL" />
                      <Button
                        secondary
                        small
                        onClick={() =>
                          setDialog({ kind: "inspect", id: item.id })
                        }
                      >
                        Inspect fleet history {item.registration.fleet_id}
                      </Button>
                    </td>
                  </tr>
                ))}
              </Table>
            )}
          </RemotePage>
          <Suspense
            fallback={<p role="status">Loading native fleet assessment…</p>}
          >
            <FleetNativeAssessment
              key={workload.id}
              workload={workload.id}
              fixture={data.fixture}
              run={run}
              busy={busy}
            />
          </Suspense>
          <Suspense
            fallback={<p role="status">Loading fleet member capacity…</p>}
          >
            <FleetNativeCapacity
              key={workload.id}
              workload={workload.id}
              fixture={data.fixture}
              run={run}
              busy={busy}
            />
          </Suspense>
          <Suspense
            fallback={<p role="status">Loading isolated fixture review…</p>}
          >
            <FleetFixture
              key={workload.id}
              workload={workload.id}
              run={run}
              busy={busy}
            />
          </Suspense>
        </>
      )}
      {dialog?.kind === "register" && workload && (
        <RegistrationForm
          key={dialog.record?.id ?? workload.id}
          data={data}
          workload={workload.id}
          latest={dialog.record}
          run={run}
          busy={busy}
          onClose={() => setDialog(null)}
          onSaved={saved}
        />
      )}
      {dialog?.kind === "inspect" && (
        <RegistrationEvidence
          key={dialog.id}
          id={dialog.id}
          run={run}
          busy={busy}
          refresh={refresh}
          onRefresh={() => setRefresh((n) => n + 1)}
          onClose={() => setDialog(null)}
          onEdit={(record) => setDialog({ kind: "register", record })}
          onDefine={(registration, definition) =>
            setDialog({ kind: "define", registration, definition })
          }
        />
      )}
      {dialog?.kind === "define" && (
        <DefinitionForm
          key={dialog.definition?.id ?? dialog.registration.id}
          data={data}
          registration={dialog.registration}
          latest={dialog.definition}
          run={run}
          busy={busy}
          onClose={() =>
            setDialog({ kind: "inspect", id: dialog.registration.id })
          }
          onSaved={() => saved(dialog.registration.id)}
        />
      )}
    </Panel>
  );
}
