import { useState } from "react";
import type { components } from "./api.generated";
import type { Dashboard } from "./types";
import { useRemote } from "./RemoteData";
import { Badge, Button, Empty, Modal, Panel, Table, dateTime, readable, type RunMutation } from "./ui";

type S = components["schemas"];
type Request = S["NetworkSourceConnectionRequest"];
const fields = [
  ["account_id", "Source AWS account ID"], ["region", "Source AWS region"],
  ["flow_log_id", "Existing Flow Log ID"], ["read_role_binding_id", "Approved network read-role binding ID"],
  ["report_bucket", "Versioned Flow Log delivery bucket"], ["report_owner", "Delivery bucket owner account ID"],
  ["report_region", "Delivery bucket region"], ["prefix", "Registered delivery prefix"],
] as const;
function SourceForm({ run, busy, onClose }: { run: RunMutation; busy: boolean; onClose: () => void }) {
  const [values, setValues] = useState<Record<string, string>>({ region: "eu-west-1", report_region: "eu-west-1" });
  const [resources, setResources] = useState(""), [format, setFormat] = useState(""), [traffic, setTraffic] = useState<Request["traffic_type"]>("ALL"), [period, setPeriod] = useState<60 | 600>(60), [error, setError] = useState("");
  return <Modal title="Register network Flow Logs" subtitle="Existing commissioned evidence · read-only" onClose={onClose}>
    <form className="configuration-stack" onSubmit={async event => {
      event.preventDefault(); setError("");
      const body: Request = { kind: "AWS_VPC_FLOW_LOGS", account_id: values.account_id, region: values.region, read_role_binding_id: values.read_role_binding_id, flow_log_id: values.flow_log_id, resource_ids: resources.split(/[,\s]+/).filter(Boolean), report_bucket: values.report_bucket, report_owner: values.report_owner, report_region: values.report_region, prefix: values.prefix ?? "", fields: format.split(/[,\s]+/).filter(Boolean).map(value => value.replace(/^\$\{(.+)\}$/, "$1")), traffic_type: traffic, max_aggregation_seconds: period };
      if (await run({ path: "/source-connections", body, version: 0, label: "Existing Flow Logs registered; synchronize to validate delivery and traffic scope" })) onClose();
      else setError("Registration was refused. Check the native Flow Log scope, delivery destination and approved read binding.");
    }}>
      <p className="form-note">Select existing VPC Flow Logs. Registration creates no logging, endpoint, route or other customer resource. Native configuration and versioned delivery evidence determine scope; missing or partial traffic remains unknown.</p>
      <div className="form-grid">{fields.map(([key, label]) => <label className="field full-width" key={key}><span>{label}</span><input required={key !== "prefix"} autoComplete="off" value={values[key] ?? ""} onChange={event => setValues(previous => ({ ...previous, [key]: event.target.value }))} /></label>)}</div>
      <label className="field"><span>Native VPC, subnet or interface IDs, comma separated</span><input required value={resources} onChange={event => setResources(event.target.value)} /></label>
      <label className="field"><span>Native log-format fields, in order</span><textarea required value={format} onChange={event => setFormat(event.target.value)} placeholder="version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status …" /></label>
      <div className="form-grid"><label className="field"><span>Commissioned traffic scope</span><select value={traffic} onChange={event => setTraffic(event.target.value as Request["traffic_type"])}>{(["ALL", "ACCEPT", "REJECT"] as const).map(value => <option key={value}>{value}</option>)}</select></label><label className="field"><span>Native maximum aggregation interval</span><select value={period} onChange={event => setPeriod(Number(event.target.value) as 60 | 600)}><option value={60}>60 seconds</option><option value={600}>600 seconds</option></select></label></div>
      {error && <p role="alert">{error}</p>}<div className="modal-actions"><Button secondary type="button" onClick={onClose}>Cancel</Button><Button type="submit" pending={busy}>Register commissioned Flow Logs</Button></div>
    </form>
  </Modal>;
}
function SourceInspection({ id }: { id: string }) {
  const [revision, setRevision] = useState(0), state = useRemote<S["SourceConnection"]>(`/source-connections/${encodeURIComponent(id)}`, revision);
  return <div className="configuration-stack">{state.loading && <p role="status">Loading network source health…</p>}{state.error && <p role="alert">Network source unavailable. {state.error}</p>}{state.value && <><Badge value={state.value.status ?? "UNKNOWN"} /><p>{readable(state.value.reason_code ?? "NETWORK_SOURCE_SYNC_REQUIRED")}</p><p>Last synchronization: {dateTime(state.value.last_sync_at)}</p><p className="form-note">A successful native delivery is scoped evidence. Flow Logs are best effort; skipped records, incomplete destination classification and unavailable intervals prevent complete traffic or zero-use claims.</p><pre className="evidence-json">{JSON.stringify(state.value, null, 2)}</pre></>}<Button secondary small disabled={state.loading} onClick={() => setRevision(value => value + 1)}>Refresh network source health</Button></div>;
}
export function NetworkSources({ data, run, busy }: { data: Dashboard; run: RunMutation; busy: boolean }) {
  const [creating, setCreating] = useState(false), [selected, setSelected] = useState("");
  const sources = (data.source_connections ?? []).filter(source => source.kind === "AWS_VPC_FLOW_LOGS");
  return <Panel title="Network traffic evidence" eyebrow="COMMISSIONED FLOW LOGS · READ-ONLY" action={<Button secondary small onClick={() => setCreating(true)}>Register network Flow Logs</Button>}>
    <p>Read-only network discovery and NAT telemetry remain useful without Flow Logs. Destination-dependent recommendations require independently validated traffic paths, source scope and customer economics. Logging remains customer commissioned.</p>
    {sources.length ? <Table scrollLabel="Network source health" headings={["Native source / account", "Health", "Last synchronization", "Actions"]}>{sources.map(source => <tr key={source.id}><th scope="row">{source.flow_log_id}<small>{source.account_id} · {source.region}</small></th><td><Badge value={source.status ?? "UNKNOWN"} /><small>{readable(source.reason_code ?? "NETWORK_SOURCE_SYNC_REQUIRED")}</small></td><td>{dateTime(source.last_sync_at)}</td><td><div className="row-actions"><Button secondary small disabled={busy || !source.enabled} onClick={() => void run({ path: `/source-connections/${encodeURIComponent(source.id)}/sync`, version: source.version, label: "Network source synchronization queued" })}>Synchronize network source {source.flow_log_id}</Button><Button secondary small onClick={() => setSelected(source.id)}>Inspect network source {source.flow_log_id}</Button></div></td></tr>)}</Table> : <Empty title="No commissioned network traffic source" text="Missing Flow Logs remain unknown. Register an existing source to assess destination-specific alternatives; no paid logging is enabled by this product." />}
    {creating && <SourceForm run={run} busy={busy} onClose={() => setCreating(false)} />}{selected && <Modal title="Network source health" subtitle={selected} onClose={() => setSelected("")}><SourceInspection id={selected} /></Modal>}
  </Panel>;
}
