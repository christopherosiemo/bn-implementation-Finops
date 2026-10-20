import { useState } from "react";
import { api } from "./api";
import type { components } from "./api.generated";
import type {
  Dashboard,
  Workload,
  WorkloadSafetyProfile,
  WorkloadSafetyRequest,
} from "./types";
import { useRemote } from "./RemoteData";
import {
  Badge,
  Button,
  Empty,
  Modal,
  Panel,
  Table,
  readable,
  shortId,
  type RunMutation,
} from "./ui";

type Window = components["schemas"]["SafetyWeeklyWindow"];
type StorageLimits = components["schemas"]["StorageLimits"];
const storageDecimals = [
  ["iops_max_fraction", "Maximum IOPS capacity fraction"],
  ["throughput_max_fraction", "Maximum throughput capacity fraction"],
  ["max_read_latency_seconds", "Maximum read latency (seconds)"],
  ["max_write_latency_seconds", "Maximum write latency (seconds)"],
  ["max_disk_queue_depth", "Maximum disk queue depth"],
  ["min_burst_balance_percent", "Minimum burst balance (percent)"],
] as const;
const storageDays = [["snapshot_retention_days", "Snapshot retention requirement (days)"], ["quarantine_days", "Unattached-volume quarantine requirement (days)"]] as const;
const storageBooleans = [
  ["backup_required", "Backup required"],
  ["allow_durability_reduction", "Durability reduction allowed"],
  ["require_multi_attach", "Multi-Attach required"],
  ["filesystem_review_required", "Filesystem review required"],
] as const;
const days = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const fields = [
  ["min_replicas", "Minimum healthy replicas", 1, 1000000],
  ["min_zones", "Minimum healthy zones", 1, 100],
  ["cpu_free_ppm", "CPU unused capacity (ppm)", 1, 999999],
  ["memory_free_ppm", "Memory unused capacity (ppm)", 1, 999999],
  ["reserve_above_forecast_ppm", "Reserve above forecast (ppm)", 0, 10000000],
  ["cpu_p99_ppm", "CPU p99 rollback ceiling (ppm)", 1, 1000000],
  ["memory_p99_ppm", "Memory p99 rollback ceiling (ppm)", 1, 1000000],
  ["rto_seconds", "Recovery time target (seconds)", 1, 604800],
  [
    "max_simultaneous_change_ppm",
    "Maximum simultaneous disruptive change (ppm)",
    1,
    1000000,
  ],
  ["vm_cooldown_seconds", "VM change cooldown (seconds)", 0, 31536000],
] as const;
const utcInput = (value: string) =>
  value ? new Date(value).toISOString().slice(0, 16) : "";
const utcStamp = (value: string) => new Date(`${value}Z`).toISOString();

function WeeklyWindows({
  label,
  windows,
  onChange,
}: {
  label: string;
  windows: (Window & { key: string })[];
  onChange: (windows: (Window & { key: string })[]) => void;
}) {
  const update = (key: string, patch: Partial<Window>) =>
    onChange(
      windows.map((window) =>
        window.key === key ? { ...window, ...patch } : window,
      ),
    );
  return (
    <fieldset className="days-fieldset">
      <legend>{label}</legend>
      <p className="form-note">
        Local IANA timezone. An end before the start continues into the next
        local day; repeated DST hours remain covered.
      </p>
      {windows.map((window, index) => (
        <fieldset className="days-fieldset" key={window.key}>
          <legend>
            {label} {index + 1}
          </legend>
          <div className="slo-day-options">
            {days.map((day, number) => (
              <label key={day}>
                <input
                  type="checkbox"
                  checked={window.days.includes(number)}
                  onChange={(event) =>
                    update(window.key, {
                      days: event.target.checked
                        ? [...window.days, number]
                        : window.days.filter((value) => value !== number),
                    })
                  }
                />
                <span>{day}</span>
              </label>
            ))}
          </div>
          <div className="form-grid">
            <label className="field">
              <span>
                {label} {index + 1} start
              </span>
              <input
                required
                type="time"
                value={window.start_time}
                onChange={(event) =>
                  update(window.key, { start_time: event.target.value })
                }
              />
            </label>
            <label className="field">
              <span>
                {label} {index + 1} end
              </span>
              <input
                required
                type="text"
                pattern="([01][0-9]|2[0-3]):[0-5][0-9]|24:00"
                title="HH:MM, with 24:00 allowed for the end of a local day"
                placeholder="HH:MM or 24:00"
                value={window.end_time}
                onChange={(event) =>
                  update(window.key, { end_time: event.target.value })
                }
              />
            </label>
          </div>
          <Button
            secondary
            small
            type="button"
            onClick={() =>
              onChange(windows.filter((item) => item.key !== window.key))
            }
          >
            Remove {label.toLowerCase()} {index + 1}
          </Button>
        </fieldset>
      ))}
      <Button
        secondary
        small
        type="button"
        disabled={windows.length >= 64}
        onClick={() =>
          onChange([
            ...windows,
            {
              key: crypto.randomUUID(),
              days: [],
              start_time: "",
              end_time: "",
            },
          ])
        }
      >
        Add {label.toLowerCase()}
      </Button>
    </fieldset>
  );
}

const calendarCollections = [
  "maintenance",
  "recurring_blackouts",
  "blackouts",
  "demand_events",
] as const;
const availableItems = <T,>(value: T[] | null | undefined): T[] =>
  Array.isArray(value) ? value : [];

function SafetyForm({
  workload,
  profile,
  version,
  run,
  busy,
  saved,
  onClose,
}: {
  workload: Workload;
  profile: WorkloadSafetyProfile | null;
  version: number;
  run: RunMutation;
  busy: boolean;
  saved: () => void;
  onClose: () => void;
}) {
  const unavailableCollections = profile
    ? calendarCollections.filter((key) => !Array.isArray(profile[key]))
    : [];
  const [baseVersion] = useState(version);
  const [criticality, setCriticality] = useState(profile?.criticality ?? "");
  const [statefulness, setStatefulness] = useState(
    profile?.statefulness ?? "UNKNOWN",
  );
  const [timezone, setTimezone] = useState(
    profile?.timezone ?? workload.timezone,
  );
  const [seasonal, setSeasonal] = useState(profile?.high_seasonality ?? false);
  const [values, setValues] = useState(() =>
    Object.fromEntries(
      fields.map(([key]) => [
        key,
        profile
          ? String(
              key in profile.headroom
                ? profile.headroom[key as keyof typeof profile.headroom]
                : key in profile.saturation
                  ? profile.saturation[key as keyof typeof profile.saturation]
                  : profile[key as keyof WorkloadSafetyProfile],
            )
          : "",
      ]),
    ),
  );
  const [rpoKnown, setRpoKnown] = useState(profile?.rpo_seconds != null);
  const [rpo, setRpo] = useState(profile?.rpo_seconds?.toString() ?? "");
  const [storageEnabled, setStorageEnabled] = useState(!!profile?.storage);
  const [storageValues, setStorageValues] = useState<Record<string, string>>(() => Object.fromEntries(
    [...storageDecimals, ...storageDays].map(([key]) => [key, profile?.storage?.[key]?.toString() ?? ""]),
  ));
  const [storageFlags, setStorageFlags] = useState<Record<string, string>>(() => Object.fromEntries(
    storageBooleans.map(([key]) => [key, profile?.storage?.[key] == null ? "" : String(profile.storage[key])]),
  ));
  const [maintenance, setMaintenance] = useState<(Window & { key: string })[]>(
    () =>
      availableItems(profile?.maintenance).map((window) => ({
        ...window,
        key: crypto.randomUUID(),
      })),
  );
  const [recurring, setRecurring] = useState<(Window & { key: string })[]>(
    () =>
      availableItems(profile?.recurring_blackouts).map((window) => ({
        ...window,
        key: crypto.randomUUID(),
      })),
  );
  const [blackouts, setBlackouts] = useState(
    () =>
      availableItems(profile?.blackouts).map((item) => ({
        ...item,
        start: utcInput(item.start),
        end: utcInput(item.end),
      })),
  );
  const [events, setEvents] = useState(
    () =>
      availableItems(profile?.demand_events).map((item) => ({
        ...item,
        start: utcInput(item.start),
        end: utcInput(item.end),
      })),
  );
  const [error, setError] = useState("");
  return (
    <Modal
      title="Configure workload safety requirements"
      subtitle={`${workload.name} · profile revision ${baseVersion} · platform administrator`}
      onClose={onClose}
    >
      <form
        onSubmit={async (event) => {
          event.preventDefault();
          setError("");
          if (unavailableCollections.length) {
            setError(
              "Unavailable stored collections cannot be saved as empty declarations.",
            );
            return;
          }
          if (
            fields.some(
              ([key, , min, max]) =>
                values[key] === "" ||
                !Number.isSafeInteger(Number(values[key])) ||
                Number(values[key]) < min ||
                Number(values[key]) > max,
            ) ||
            Number(values.min_zones) > Number(values.min_replicas)
          ) {
            setError(
              "Provide explicit integer requirements; zone minimum cannot exceed replica minimum.",
            );
            return;
          }
          if (
            [...maintenance, ...recurring].some(
              (window) =>
                !window.days.length || window.start_time === window.end_time,
            )
          ) {
            setError(
              "Select days and unequal start/end times for every weekly window.",
            );
            return;
          }
          if (
            rpoKnown &&
            (rpo === "" ||
              !Number.isInteger(Number(rpo)) ||
              Number(rpo) < 0 ||
              Number(rpo) > 604800)
          ) {
            setError(
              "Declare an RPO target from 0 to 604800 seconds, or leave it explicitly unknown.",
            );
            return;
          }
          if (storageEnabled && (
            storageDecimals.some(([key]) => !/^(?:0|[1-9]\d*)(?:\.\d{1,12})?$/.test(storageValues[key])) ||
            ["iops_max_fraction", "throughput_max_fraction"].some(key => Number(storageValues[key]) <= 0 || Number(storageValues[key]) > 1) ||
            Number(storageValues.min_burst_balance_percent) > 100 ||
            storageDays.some(([key]) => storageValues[key] === "" || !Number.isSafeInteger(Number(storageValues[key])) || Number(storageValues[key]) < 1 || Number(storageValues[key]) > 36500)
          )) {
            setError("Provide storage fractions above zero and at most one, non-negative decimal limits (up to 12 decimal places), burst balance at most 100%, and retention/quarantine days from 1 to 36500. Unknown booleans remain unknown.");
            return;
          }
          try {
            new Intl.DateTimeFormat("en", { timeZone: timezone }).format();
          } catch {
            setError("Enter a valid IANA timezone.");
            return;
          }
          if (
            [...blackouts, ...events].some(
              (item) =>
                !item.start ||
                !item.end ||
                item.start >= item.end ||
                !item.reason.trim(),
            )
          ) {
            setError("Dated windows need a reason and an end after the start.");
            return;
          }
          if (
            events.some(
              (item) =>
                !Number.isSafeInteger(item.demand_multiplier_ppm) ||
                item.demand_multiplier_ppm < 1000000 ||
                item.demand_multiplier_ppm > 1000000000,
            )
          ) {
            setError(
              "Demand-event multipliers use integer ppm from 1,000,000 (1×) to 1,000,000,000 (1000×).",
            );
            return;
          }
          const windows = (items: typeof maintenance) =>
            items.map(({ days, start_time, end_time }) => ({
              days: [...days].sort((a, b) => a - b),
              start_time,
              end_time,
            }));
          const body: WorkloadSafetyRequest = {
            ...(profile?.database ? { database: profile.database } : {}),
            ...(storageEnabled ? { storage: {
              iops_max_fraction: storageValues.iops_max_fraction,
              throughput_max_fraction: storageValues.throughput_max_fraction,
              max_read_latency_seconds: storageValues.max_read_latency_seconds,
              max_write_latency_seconds: storageValues.max_write_latency_seconds,
              max_disk_queue_depth: storageValues.max_disk_queue_depth,
              min_burst_balance_percent: storageValues.min_burst_balance_percent,
              snapshot_retention_days: Number(storageValues.snapshot_retention_days),
              quarantine_days: Number(storageValues.quarantine_days),
              backup_required: storageFlags.backup_required === "" ? null : storageFlags.backup_required === "true",
              allow_durability_reduction: storageFlags.allow_durability_reduction === "" ? null : storageFlags.allow_durability_reduction === "true",
              require_multi_attach: storageFlags.require_multi_attach === "" ? null : storageFlags.require_multi_attach === "true",
              filesystem_review_required: storageFlags.filesystem_review_required === "" ? null : storageFlags.filesystem_review_required === "true",
            } satisfies StorageLimits } : {}),
            schema_version: "1",
            criticality: criticality as WorkloadSafetyRequest["criticality"],
            statefulness: statefulness as WorkloadSafetyRequest["statefulness"],
            high_seasonality: seasonal,
            timezone,
            min_replicas: Number(values.min_replicas),
            min_zones: Number(values.min_zones),
            headroom: {
              cpu_free_ppm: Number(values.cpu_free_ppm),
              memory_free_ppm: Number(values.memory_free_ppm),
              reserve_above_forecast_ppm: Number(
                values.reserve_above_forecast_ppm,
              ),
            },
            saturation: {
              cpu_p99_ppm: Number(values.cpu_p99_ppm),
              memory_p99_ppm: Number(values.memory_p99_ppm),
            },
            rto_seconds: Number(values.rto_seconds),
            rpo_seconds: rpoKnown ? Number(rpo) : null,
            maintenance: windows(maintenance),
            recurring_blackouts: windows(recurring),
            blackouts: blackouts.map((item) => ({
              ...item,
              reason: item.reason.trim(),
              start: utcStamp(item.start),
              end: utcStamp(item.end),
            })),
            demand_events: events.map((item) => ({
              ...item,
              reason: item.reason.trim(),
              start: utcStamp(item.start),
              end: utcStamp(item.end),
            })),
            max_simultaneous_change_ppm: Number(
              values.max_simultaneous_change_ppm,
            ),
            vm_cooldown_seconds: Number(values.vm_cooldown_seconds),
          };
          if (
            await run({
              path: `/workloads/${workload.id}/safety-profiles`,
              version: baseVersion,
              body,
              label:
                "Workload requirements revision recorded; observed recovery and capacity evidence are still required.",
            })
          ) {
            saved();
            onClose();
          } else
            setError(
              "Requirements not saved. Check the request error and refresh before retrying a changed revision.",
            );
        }}
      >
        {unavailableCollections.length > 0 && (
          <p role="alert" className="blocker-text">
            Stored collections unavailable:{" "}
            {unavailableCollections.map(readable).join(", ")}.
            This form cannot save a revision from incomplete stored requirements.
            Missing collections have not been declared empty.
          </p>
        )}
        <p className="form-note">
          These are policy requirements, not proof of achieved recovery, healthy
          replicas, safe capacity or execution approval. Unknown RPO is
          submitted as null. Saving never creates a change plan.
        </p>
        <div className="form-grid">
          <label className="field">
            <span>Workload criticality</span>
            <select
              required
              value={criticality}
              onChange={(event) =>
                setCriticality(event.target.value as typeof criticality)
              }
            >
              <option value="">Choose explicit criticality</option>
              {["TIER_0", "TIER_1", "TIER_2", "TIER_3", "NON_PRODUCTION"].map(
                (value) => (
                  <option key={value} value={value}>
                    {readable(value)}
                  </option>
                ),
              )}
            </select>
          </label>
          <label className="field">
            <span>Workload statefulness</span>
            <select
              value={statefulness}
              onChange={(event) =>
                setStatefulness(event.target.value as typeof statefulness)
              }
            >
              {["UNKNOWN", "STATELESS", "STATEFUL"].map((value) => (
                <option key={value} value={value}>
                  {readable(value)}
                </option>
              ))}
            </select>
          </label>
          <label className="field full-width">
            <span>Safety policy timezone</span>
            <input
              required
              value={timezone}
              onChange={(event) => setTimezone(event.target.value)}
            />
          </label>
        </div>
        <label className="checkbox-field">
          <input
            type="checkbox"
            checked={seasonal}
            onChange={(event) => setSeasonal(event.target.checked)}
          />
          <span>High seasonality requires at least 90 complete days</span>
        </label>
        <fieldset className="days-fieldset">
          <legend>Capacity, recovery and disruption requirements</legend>
          <p className="form-note">
            PPM is parts per million. CPU unused capacity of 300,000 means
            utilization at most 70%; reserve above forecast of 300,000
            independently requires capacity ≥ forecast × 1.30. Planning targets
            and p99 rollback ceilings remain separate.
          </p>
          <div className="form-grid">
            {fields.map(([key, label, min, max]) => (
              <label className="field" key={key}>
                <span>{label}</span>
                <input
                  required
                  type="number"
                  min={min}
                  max={max}
                  step={1}
                  value={values[key]}
                  onChange={(event) =>
                    setValues((current) => ({
                      ...current,
                      [key]: event.target.value,
                    }))
                  }
                />
              </label>
            ))}
          </div>
          <label className="checkbox-field">
            <input
              type="checkbox"
              checked={rpoKnown}
              onChange={(event) => setRpoKnown(event.target.checked)}
            />
            <span>Declare a specific RPO requirement</span>
          </label>
          {rpoKnown ? (
            <label className="field">
              <span>Recovery point target (seconds)</span>
              <input
                type="number"
                required
                min={0}
                max={604800}
                step={1}
                value={rpo}
                onChange={(event) => setRpo(event.target.value)}
              />
            </label>
          ) : (
            <p className="form-note">
              RPO requirement: Unknown (null). No zero-data-loss claim is
              inferred.
            </p>
          )}
        </fieldset>
        <fieldset className="days-fieldset">
          <legend>Optional storage requirements</legend>
          <label className="checkbox-field"><input type="checkbox" checked={storageEnabled} onChange={event => setStorageEnabled(event.target.checked)} /><span>Declare storage requirements for this workload</span></label>
          <p className="form-note">Customer requirements only. These values do not prove demand, safe modification, successful backup or permission to delete storage. The existing reserve above forecast and demand-event requirements also apply. Disabling this section omits storage requirements from the new revision.</p>
          {storageEnabled && <div className="form-grid">
            {storageDecimals.map(([key, label]) => <label className="field" key={key}><span>{label}</span><input required inputMode="decimal" pattern="(?:0|[1-9][0-9]*)(?:\.[0-9]{1,12})?" value={storageValues[key]} onChange={event => setStorageValues(current => ({ ...current, [key]: event.target.value }))} /></label>)}
            {storageDays.map(([key, label]) => <label className="field" key={key}><span>{label}</span><input required type="number" min={1} max={36500} step={1} value={storageValues[key]} onChange={event => setStorageValues(current => ({ ...current, [key]: event.target.value }))} /></label>)}
            {storageBooleans.map(([key, label]) => <label className="field" key={key}><span>{label}</span><select value={storageFlags[key]} onChange={event => setStorageFlags(current => ({ ...current, [key]: event.target.value }))}><option value="">Unknown</option><option value="true">Yes</option><option value="false">No</option></select></label>)}
          </div>}
        </fieldset>
        <WeeklyWindows
          label="Maintenance windows"
          windows={maintenance}
          onChange={setMaintenance}
        />
        <WeeklyWindows
          label="Recurring blackouts"
          windows={recurring}
          onChange={setRecurring}
        />
        <fieldset className="days-fieldset">
          <legend>Dated blackouts</legend>
          {blackouts.map((item, index) => (
            <fieldset className="days-fieldset" key={item.id}>
              <legend>Blackout {index + 1}</legend>
              <label className="field">
                <span>Blackout {index + 1} reason</span>
                <input
                  required
                  value={item.reason}
                  onChange={(event) =>
                    setBlackouts((current) =>
                      current.map((entry) =>
                        entry.id === item.id
                          ? { ...entry, reason: event.target.value }
                          : entry,
                      ),
                    )
                  }
                />
              </label>
              <div className="form-grid">
                {(["start", "end"] as const).map((field) => (
                  <label className="field" key={field}>
                    <span>
                      Blackout {index + 1} {field} (UTC)
                    </span>
                    <input
                      required
                      type="datetime-local"
                      value={item[field]}
                      onChange={(event) =>
                        setBlackouts((current) =>
                          current.map((entry) =>
                            entry.id === item.id
                              ? { ...entry, [field]: event.target.value }
                              : entry,
                          ),
                        )
                      }
                    />
                  </label>
                ))}
              </div>
              <Button
                secondary
                small
                type="button"
                onClick={() =>
                  setBlackouts((current) =>
                    current.filter((entry) => entry.id !== item.id),
                  )
                }
              >
                Remove blackout {index + 1}
              </Button>
            </fieldset>
          ))}
          <Button
            secondary
            small
            type="button"
            disabled={blackouts.length >= 256}
            onClick={() =>
              setBlackouts((current) => [
                ...current,
                { id: crypto.randomUUID(), reason: "", start: "", end: "" },
              ])
            }
          >
            Add dated blackout
          </Button>
        </fieldset>
        <fieldset className="days-fieldset">
          <legend>Known demand events</legend>
          {events.map((item, index) => (
            <fieldset className="days-fieldset" key={item.id}>
              <legend>Demand event {index + 1}</legend>
              <label className="field">
                <span>Demand event {index + 1} reason</span>
                <input
                  required
                  value={item.reason}
                  onChange={(event) =>
                    setEvents((current) =>
                      current.map((entry) =>
                        entry.id === item.id
                          ? { ...entry, reason: event.target.value }
                          : entry,
                      ),
                    )
                  }
                />
              </label>
              <div className="form-grid">
                {(["start", "end"] as const).map((field) => (
                  <label className="field" key={field}>
                    <span>
                      Demand event {index + 1} {field} (UTC)
                    </span>
                    <input
                      required
                      type="datetime-local"
                      value={item[field]}
                      onChange={(event) =>
                        setEvents((current) =>
                          current.map((entry) =>
                            entry.id === item.id
                              ? { ...entry, [field]: event.target.value }
                              : entry,
                          ),
                        )
                      }
                    />
                  </label>
                ))}
                <label className="field full-width">
                  <span>Demand event {index + 1} multiplier (ppm)</span>
                  <input
                    type="number"
                    required
                    min={1000000}
                    max={1000000000}
                    step={1}
                    value={item.demand_multiplier_ppm}
                    onChange={(event) =>
                      setEvents((current) =>
                        current.map((entry) =>
                          entry.id === item.id
                            ? {
                                ...entry,
                                demand_multiplier_ppm: Number(
                                  event.target.value,
                                ),
                              }
                            : entry,
                        ),
                      )
                    }
                  />
                </label>
              </div>
              <Button
                secondary
                small
                type="button"
                onClick={() =>
                  setEvents((current) =>
                    current.filter((entry) => entry.id !== item.id),
                  )
                }
              >
                Remove demand event {index + 1}
              </Button>
            </fieldset>
          ))}
          <Button
            secondary
            small
            type="button"
            disabled={events.length >= 256}
            onClick={() =>
              setEvents((current) => [
                ...current,
                {
                  id: crypto.randomUUID(),
                  reason: "",
                  start: "",
                  end: "",
                  demand_multiplier_ppm: 1000000,
                },
              ])
            }
          >
            Add demand event
          </Button>
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
          <Button
            type="submit"
            pending={busy}
            disabled={unavailableCollections.length > 0}
          >
            Save safety requirements
          </Button>
        </div>
      </form>
    </Modal>
  );
}

function SafetyDetails({
  workload,
  run,
  busy,
}: {
  workload: Workload;
  run: RunMutation;
  busy: boolean;
}) {
  const [refresh, setRefresh] = useState(0);
  const [editing, setEditing] = useState(false);
  const [more, setMore] = useState<
    components["schemas"]["WorkloadSafetyPage"][]
  >([]);
  const [pageError, setPageError] = useState("");
  const [loadingMore, setLoadingMore] = useState(false);
  const path = `/workloads/${workload.id}/safety-profiles?limit=20`;
  const profiles = useRemote<components["schemas"]["WorkloadSafetyPage"]>(
    path,
    refresh,
  );
  const evaluation = useRemote<
    components["schemas"]["WorkloadSafetyEvaluation"]
  >(`/workloads/${workload.id}/safety-evaluation`, refresh);
  const reload = () => {
    setMore([]);
    setPageError("");
    setRefresh((value) => value + 1);
  };
  const pageData =
    profiles.value &&
    Number.isSafeInteger(profiles.value.version) &&
    profiles.value.version >= 0 &&
    Array.isArray(profiles.value.items) &&
    (profiles.value.next_cursor === null ||
      typeof profiles.value.next_cursor === "string")
      ? profiles.value
      : undefined;
  const profile = pageData?.latest;
  const history = [
    ...(pageData?.items ?? []),
    ...more.flatMap((page) => page.items),
  ];
  const cursor =
    more.at(-1)?.next_cursor ?? (more.length ? null : pageData?.next_cursor);
  return (
    <>
      <div className="policy-row">
        <span>
          <strong>{workload.name}</strong>
          <small>
            {profile
              ? `Current requirements revision ${profile.version}`
              : "No current requirements supplied"}
          </small>
        </span>
        <div className="row-actions">
          <Button secondary small onClick={reload}>
            Refresh safety requirements
          </Button>
          <Button
            secondary
            small
            disabled={busy || !pageData}
            onClick={() => setEditing(true)}
          >
            Configure safety requirements
          </Button>
        </div>
      </div>
      {profiles.loading && <p role="status">Loading workload requirements…</p>}
      {profiles.error && (
        <p role="alert" className="blocker-text">
          Safety requirements unavailable. {profiles.error}
        </p>
      )}
      {profiles.value && !pageData && (
        <p role="alert" className="blocker-text">
          Safety requirements unavailable. The API returned an incomplete page.
        </p>
      )}
      <section
        className="native-section"
        aria-label={`Safety assessment for ${workload.name}`}
      >
        <h3>Requirements and observed proof</h3>
        <div className="readiness-summary">
          <span>
            Execution authority{" "}
            <Badge value="BLOCKED">Not authorized by this view</Badge>
          </span>
          <span>
            Recovery evidence{" "}
            <Badge value="UNKNOWN">
              {evaluation.value?.recovery_evidence_status || "Unavailable"}
            </Badge>
          </span>
        </div>
        <p className="form-note">
          Declared headroom, replica/zone minima and RTO/RPO targets are
          requirements. They do not prove current capacity, surviving healthy
          members or achieved recovery.
        </p>
        {evaluation.loading && (
          <p role="status">Loading current policy assessment…</p>
        )}
        {evaluation.error && (
          <p role="alert" className="blocker-text">
            Safety assessment unavailable. {evaluation.error}
          </p>
        )}
        {evaluation.value && (
          <>
            <Badge value={evaluation.value.status} />
            <ul className="evidence-refs">
              {evaluation.value.reason_codes.map((reason) => (
                <li key={reason}>{readable(reason)}</li>
              ))}
            </ul>
          </>
        )}
        {profile && (
          <dl className="definition-list">
            <div>
              <dt>Criticality / statefulness</dt>
              <dd>
                {readable(profile.criticality)} /{" "}
                {readable(profile.statefulness)}
              </dd>
            </div>
            <div>
              <dt>History requirement</dt>
              <dd>
                {profile.high_seasonality
                  ? "90 days · high seasonality"
                  : profile.criticality === "NON_PRODUCTION"
                    ? "14 complete days"
                    : "30 complete days by default"}
              </dd>
            </div>
            <div>
              <dt>Minimum healthy replicas / zones</dt>
              <dd>
                {profile.min_replicas} / {profile.min_zones}
              </dd>
            </div>
            <div>
              <dt>CPU / memory unused capacity</dt>
              <dd>
                {profile.headroom.cpu_free_ppm} /{" "}
                {profile.headroom.memory_free_ppm} ppm
              </dd>
            </div>
            <div>
              <dt>Additive reserve above forecast</dt>
              <dd>{profile.headroom.reserve_above_forecast_ppm} ppm</dd>
            </div>
            <div>
              <dt>CPU / memory p99 rollback ceiling</dt>
              <dd>
                {profile.saturation.cpu_p99_ppm} /{" "}
                {profile.saturation.memory_p99_ppm} ppm
              </dd>
            </div>
            <div>
              <dt>Declared RTO / RPO target</dt>
              <dd>
                {profile.rto_seconds}s /{" "}
                {profile.rpo_seconds == null
                  ? "Unknown"
                  : `${profile.rpo_seconds}s`}
                <small>Recovery evidence remains unavailable</small>
              </dd>
            </div>
            <div>
              <dt>Disruption budget / VM cooldown</dt>
              <dd>
                {profile.max_simultaneous_change_ppm} ppm /{" "}
                {profile.vm_cooldown_seconds}s
              </dd>
            </div>
            <div>
              <dt>Requirements hash</dt>
              <dd className="evidence-id">{profile.hash}</dd>
            </div>
          </dl>
        )}
        {!profile && pageData && !profiles.loading && !profiles.error && (
          <Empty
            title="No safety profile recorded"
            text="Declare explicit requirements before capacity or fleet planning. An absent profile does not mean zero recovery targets or unlimited disruption."
          />
        )}
      </section>
      {!!history.length && (
        <section aria-label="Immutable safety requirement history">
          <h3>Immutable requirement history</h3>
          <Table
            scrollLabel="Scrollable workload safety revision history"
            headings={[
              "Revision",
              "Policy",
              "Recovery targets",
              "Calendar / events",
            ]}
          >
            {history.map((item) => (
              <tr key={item.id}>
                <td>
                  Revision {item.version}
                  <small className="evidence-id">{shortId(item.hash)}</small>
                </td>
                <td>
                  {readable(item.criticality)}
                  <small>{readable(item.statefulness)}</small>
                </td>
                <td>
                  RTO {item.rto_seconds}s
                  <small>
                    RPO{" "}
                    {item.rpo_seconds == null
                      ? "Unknown"
                      : `${item.rpo_seconds}s`}
                  </small>
                </td>
                <td>
                  {item.timezone}
                  <small>
                    {Array.isArray(item.maintenance)
                      ? `${item.maintenance.length} maintenance`
                      : "Maintenance unavailable"}{" "}
                    ·{" "}
                    {Array.isArray(item.recurring_blackouts) &&
                    Array.isArray(item.blackouts)
                      ? `${item.recurring_blackouts.length + item.blackouts.length} blackouts`
                      : "Blackouts unavailable"}{" "}
                    ·{" "}
                    {Array.isArray(item.demand_events)
                      ? `${item.demand_events.length} demand events`
                      : "Demand events unavailable"}
                  </small>
                </td>
              </tr>
            ))}
          </Table>
          {pageError && <p role="alert">{pageError}</p>}
          {cursor && (
            <div className="remote-page-actions">
              <Button
                secondary
                small
                pending={loadingMore}
                onClick={async () => {
                  setLoadingMore(true);
                  setPageError("");
                  try {
                    const page = await api.get<
                      components["schemas"]["WorkloadSafetyPage"]
                    >(`${path}&cursor=${encodeURIComponent(cursor)}`);
                    if (
                      !Array.isArray(page.items) ||
                      page.version !== pageData?.version ||
                      !(
                        page.next_cursor === null ||
                        typeof page.next_cursor === "string"
                      ) ||
                      page.next_cursor === cursor ||
                      page.items.some((item) =>
                        history.some((old) => old.id === item.id),
                      )
                    )
                      throw new Error(
                        "Safety history changed or repeated. Refresh before continuing.",
                      );
                    setMore((current) => [...current, page]);
                  } catch (error) {
                    setPageError(
                      error instanceof Error
                        ? error.message
                        : "Safety history could not be read.",
                    );
                  } finally {
                    setLoadingMore(false);
                  }
                }}
              >
                Load more safety history
              </Button>
            </div>
          )}
        </section>
      )}
      {editing && pageData && (
        <SafetyForm
          workload={workload}
          profile={profile ?? null}
          version={pageData.version}
          run={run}
          busy={busy}
          saved={reload}
          onClose={() => setEditing(false)}
        />
      )}
    </>
  );
}

export function WorkloadSafety({
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
      title="Workload capacity & recovery requirements"
      eyebrow="VERSIONED REQUIREMENTS · INDEPENDENT OBSERVED PROOF"
    >
      <p className="native-intro">
        Set explicit headroom, replica/AZ minima, maintenance and blackout
        rules, demand events, recovery targets and change budgets. Unknown
        evidence stays visible and blocks authority.
      </p>
      {workload ? (
        <>
          <label className="field native-workload-picker">
            <span>Safety requirements workload</span>
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
          <SafetyDetails
            key={workload.id}
            workload={workload}
            run={run}
            busy={busy}
          />
        </>
      ) : (
        <Empty
          title="No authorized workloads"
          text="Discover a workload before recording safety requirements."
        />
      )}
    </Panel>
  );
}
