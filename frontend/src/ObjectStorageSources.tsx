import { useState } from "react";
import type { components } from "./api.generated";
import type { Dashboard } from "./types";
import { RemotePage, useRemote } from "./RemoteData";
import { Badge, Button, Empty, Modal, Panel, Table, dateTime, readable, type RunMutation } from "./ui";

type S = components["schemas"];
type SourceRequest = S["ObjectStorageSourceConnectionRequest"];
const fields = [
  ["account_id", "Source AWS account ID"], ["bucket", "Source bucket"],
  ["report_bucket", "Existing report delivery bucket"], ["report_owner", "Report bucket owner account ID"],
  ["prefix", "Report delivery prefix"], ["read_role_binding_id", "Approved read-role binding ID"],
] as const;

function SourceForm({ run, busy, onClose }: { run: RunMutation; busy: boolean; onClose: () => void }) {
  const [kind, setKind] = useState<SourceRequest["kind"]>("AWS_S3_INVENTORY");
  const [reportType, setReportType] = useState<NonNullable<SourceRequest["report_type"]>>("S3_STORAGE_CLASS_ANALYSIS");
  const [values, setValues] = useState<Record<string, string>>({});
  const [error, setError] = useState("");
  return <Modal title="Register S3 evidence source" subtitle="Existing commissioned native reports · Ireland" onClose={onClose}>
    <form className="configuration-stack" onSubmit={async event => {
      event.preventDefault(); setError("");
      const body: SourceRequest = { kind, account_id: values.account_id, region: "eu-west-1", bucket: values.bucket, report_bucket: values.report_bucket, report_owner: values.report_owner, prefix: values.prefix ?? "", read_role_binding_id: values.read_role_binding_id, dataset_ids: (values.dataset_ids ?? "").split(",").map(value => value.trim()).filter(Boolean), ...(kind === "AWS_S3_INVENTORY" ? { inventory_id: values.inventory_id } : { report_type: reportType }), ...(values.report_region ? { report_region: values.report_region } : {}) };
      const result = await run({ path: "/source-connections", body, label: "S3 source registered; synchronize to validate native evidence" });
      if (result) onClose(); else setError("The source was not registered. Review the API error and approved read binding before retrying.");
    }}>
      <p className="form-note">Connect an existing S3 Inventory or Storage Class Analysis report using a server-approved read binding. Registration does not create reports or logging, modify lifecycle rules, move objects or authorize deletion. Delivery owner, versions and manifests are validated before evidence can support advice.</p>
      <label className="field"><span>Native evidence kind</span><select value={kind} onChange={event => setKind(event.target.value as SourceRequest["kind"])}><option value="AWS_S3_INVENTORY">S3 Inventory</option><option value="AWS_S3_ANALYTICS">Commissioned access reports</option></select></label>
      {kind === "AWS_S3_ANALYTICS" && <label className="field"><span>Native access report format</span><select value={reportType} onChange={event => setReportType(event.target.value as typeof reportType)}><option value="S3_STORAGE_CLASS_ANALYSIS">S3 Storage Class Analysis</option><option value="S3_STORAGE_LENS">S3 Storage Lens</option><option value="APP_ACCESS">Independent application access archive</option></select></label>}
      <div className="form-grid">{fields.map(([key, label]) => <label className="field full-width" key={key}><span>{label}</span><input required={key !== "prefix"} autoComplete="off" value={values[key] ?? ""} onChange={event => setValues(current => ({ ...current, [key]: event.target.value }))} /></label>)}
        {kind === "AWS_S3_INVENTORY" && <label className="field full-width"><span>Inventory configuration ID</span><input required autoComplete="off" value={values.inventory_id ?? ""} onChange={event => setValues(current => ({ ...current, inventory_id: event.target.value }))} /></label>}
        <label className="field full-width"><span>Issued dataset identifiers, comma separated</span><input autoComplete="off" value={values.dataset_ids ?? ""} onChange={event => setValues(current => ({ ...current, dataset_ids: event.target.value }))} placeholder="Leave blank for the bucket population" /></label>
        <label className="field full-width"><span>Report delivery region</span><input autoComplete="off" value={values.report_region ?? ""} onChange={event => setValues(current => ({ ...current, report_region: event.target.value }))} placeholder="Source bucket region when omitted" /></label>
      </div>
      <p className="form-note">Declare dataset selectors in the bucket's inventory detail first. The server resolves their current versions and hashes; this form cannot upload object observations or authoritative costs.</p>
      {error && <p role="alert">{error}</p>}
      <div className="modal-actions"><Button secondary type="button" onClick={onClose}>Cancel</Button><Button type="submit" pending={busy}>Register S3 source</Button></div>
    </form>
  </Modal>;
}

function SourceInspection({ id }: { id: string }) {
  const [revision, setRevision] = useState(0);
  const state = useRemote<S["SourceConnection"]>(`/source-connections/${encodeURIComponent(id)}`, revision);
  return <div className="configuration-stack">{state.loading && <p role="status">Loading S3 source health…</p>}{state.error && <p role="alert">S3 source unavailable. {state.error}</p>}
    {state.value && <><div className="row-actions"><Badge value={state.value.status ?? "UNKNOWN"} /><span>{readable(state.value.kind)}</span></div><p>{readable(state.value.reason_code ?? "SOURCE_SYNC_REQUIRED")}</p><p>Last synchronization: {dateTime(state.value.last_sync_at)}</p><p className="form-note">Source registration and receipt presence do not prove complete access history or native customer economics. Missing report files, versions, ownership and coverage remain blockers.</p><pre className="evidence-json">{JSON.stringify(state.value, null, 2)}</pre></>}
    <Button secondary small disabled={state.loading} onClick={() => setRevision(value => value + 1)}>Refresh S3 source health</Button>
  </div>;
}

function CollectorForm({ resourceID, run, busy, onClose, onSaved }: { resourceID: string; run: RunMutation; busy: boolean; onClose: () => void; onSaved: () => void }) {
  const [dataset, setDataset] = useState(""), [subject, setSubject] = useState(""), [definition, setDefinition] = useState(""), [version, setVersion] = useState("1"), [covers, setCovers] = useState(false), [error, setError] = useState("");
  return <Modal title="Register S3 access collector" subtitle="Independent machine identity · no historical backfill" onClose={onClose}>
    <form className="configuration-stack" onSubmit={async event => {
      event.preventDefault(); setError("");
      const body: S["ObjectStorageAccessSourceRequest"] = { resource_id: resourceID, dataset_id: dataset, subject, metric_definition: { id: definition, version, unit: "s3-get-requests-and-bytes" }, authoritative_access_scope: covers };
      const result = await run({ path: "/object-storage-access-sources", body, version: 0, label: "S3 machine collector registered; observation history remains independently required" });
      if (result) onSaved(); else setError("Collector registration was refused. Review platform administration, dataset binding and configured machine issuer.");
    }}>
      <p className="form-note">The collector must use the dedicated activity-ingress OIDC audience and the exact registered subject. Console tokens cannot submit observations. Complete one-minute counts and bytes are accepted only near receipt time; registration cannot create past activity or prove that all bucket reads were captured.</p>
      <div className="form-grid">
        {([["Issued dataset identifier", dataset, setDataset], ["Machine OIDC subject", subject, setSubject], ["Metric definition identifier", definition, setDefinition], ["Metric definition version", version, setVersion]] as const).map(([label, value, update]) => <label className="field full-width" key={label}><span>{label}</span><input required autoComplete="off" value={value} onChange={event => update(event.target.value)} /></label>)}
      </div>
      <label><input type="checkbox" checked={covers} onChange={event => setCovers(event.target.checked)} /> Customer declares this collector covers the selected dataset's reads</label>
      {error && <p role="alert">{error}</p>}
      <div className="modal-actions"><Button secondary type="button" onClick={onClose}>Cancel</Button><Button type="submit" pending={busy}>Register independent S3 collector</Button></div>
    </form>
  </Modal>;
}

function AccessCollectors({ data, run, busy }: { data: Dashboard; run: RunMutation; busy: boolean }) {
  const [resourceID, setResourceID] = useState(""), [creating, setCreating] = useState(false), [revision, setRevision] = useState(0), [selected, setSelected] = useState<S["ObjectStorageAccessSource"] | null>(null);
  const resources = data.resources.filter(resource => resource.resource_type === "S3_BUCKET");
  return <section className="configuration-stack" aria-label="Independent S3 access collectors"><h4>Independent access collectors</h4>
    <p className="form-note">Observed GET requests and retrieved bytes are distinct from object age. Explicit zero activity is valid; missing intervals, changed definitions and stale heartbeats remain unknown.</p>
    <label className="field"><span>S3 bucket for access collectors</span><select value={resourceID} onChange={event => { setResourceID(event.target.value); setRevision(value => value + 1); }}><option value="">Select a discovered bucket</option>{resources.map(resource => <option key={resource.id} value={resource.id}>{resource.name || resource.provider_resource_id}</option>)}</select></label>
    {resourceID && <><div className="row-actions"><Button secondary small onClick={() => setCreating(true)}>Register independent S3 collector</Button><Button secondary small onClick={() => setRevision(value => value + 1)}>Refresh S3 collectors</Button></div>
      <RemotePage<S["ObjectStorageAccessSource"]> key={`${resourceID}:${revision}`} path={`/object-storage-access-sources?resource_id=${encodeURIComponent(resourceID)}&limit=10`} label="S3 access collectors" empty="No independent access collector is registered for this bucket. Historical access remains unknown.">{items => <Table scrollLabel="S3 independent collector registrations" headings={["Dataset / subject", "Metric definition", "Authority / state", "Actions"]}>{items.map(item => <tr key={item.id}><th scope="row">{item.dataset_id}<small>{item.subject}</small></th><td>{item.metric_definition.id}<small>Version {item.metric_definition.version} · {item.metric_definition.unit}</small></td><td><Badge value={item.enabled ? "ENABLED" : "REVOKED"} /><small>{item.authoritative_access_scope ? "Declared dataset scope" : "Access scope incomplete"}</small><small>Registration does not establish observed coverage</small></td><td><div className="row-actions"><Button secondary small onClick={() => setSelected(item)}>Inspect S3 collector {item.id}</Button><Button secondary small disabled={busy || !item.enabled} onClick={async () => { if (await run({ path: `/object-storage-access-sources/${encodeURIComponent(item.id)}/revoke`, version: item.version, label: "S3 collector revoked; historical receipts retained" })) setRevision(value => value + 1); }}>Revoke S3 collector {item.id}</Button></div></td></tr>)}</Table>}</RemotePage>
    </>}
    {creating && <CollectorForm resourceID={resourceID} run={run} busy={busy} onClose={() => setCreating(false)} onSaved={() => { setCreating(false); setRevision(value => value + 1); }} />}
    {selected && <Modal title="Independent S3 collector" subtitle={selected.id} onClose={() => setSelected(null)}><p className="form-note">The issuer, subject and metric definition authenticate new observations. This record cannot manufacture historical intervals or establish complete native bucket access.</p><pre className="evidence-json">{JSON.stringify(selected, null, 2)}</pre></Modal>}
  </section>;
}

export function ObjectStorageSources({ data, run, busy }: { data: Dashboard; run: RunMutation; busy: boolean }) {
  const [creating, setCreating] = useState(false), [selected, setSelected] = useState("");
  const sources = (data.source_connections ?? []).filter(source => source.kind === "AWS_S3_INVENTORY" || source.kind === "AWS_S3_ANALYTICS");
  return <Panel title="S3 object-storage evidence" eyebrow="READ-ONLY NATIVE REPORTS" action={<Button secondary small onClick={() => setCreating(true)}>Register S3 evidence source</Button>}>
    <p className="form-note">S3 Inventory is the scalable object catalogue. Access-pattern evidence is independently commissioned; object age alone cannot establish coldness. Bucket-only observations remain visible when object or access reports are unavailable.</p>
    {sources.length ? <Table scrollLabel="S3 evidence source health" headings={["Source / native report", "Health", "Last synchronization", "Actions"]}>{sources.map(source => <tr key={source.id}>
      <th scope="row">{source.bucket}<small>{readable(source.kind)} · {source.region}</small><small>{"account_id" in source ? source.account_id : "Account unavailable"}</small></th>
      <td><Badge value={source.status ?? "UNKNOWN"} /><small>{readable(source.reason_code ?? "SOURCE_SYNC_REQUIRED")}</small></td><td>{dateTime(source.last_sync_at)}</td>
      <td><div className="row-actions"><Button secondary small disabled={busy || !source.enabled} onClick={() => void run({ path: `/source-connections/${encodeURIComponent(source.id)}/sync`, version: source.version, label: "S3 source synchronization queued" })}>Synchronize S3 source {source.bucket}</Button><Button secondary small onClick={() => setSelected(source.id)}>Inspect S3 source {source.bucket}</Button></div></td>
    </tr>)}</Table> : <Empty title="No commissioned S3 source" text="Read-only bucket discovery works without an Inventory or access report. Register existing native reports to support object-scale policy and economics assessment; missing evidence remains unknown." />}
    {creating && <SourceForm run={run} busy={busy} onClose={() => setCreating(false)} />}
    {selected && <Modal title="S3 evidence source health" subtitle={selected} onClose={() => setSelected("")}><SourceInspection id={selected} /></Modal>}
    <AccessCollectors data={data} run={run} busy={busy} />
  </Panel>;
}
