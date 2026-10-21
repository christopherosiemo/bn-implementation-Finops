import { useState } from "react";
import type { components } from "./api.generated";
import type { Dashboard, Resource, Workload } from "./types";
import { RemotePage, useRemote } from "./RemoteData";
import { Badge, Button, Empty, Modal, Panel, Table, dateTime, readable, type RunMutation } from "./ui";

type S = components["schemas"];
type Source = S["EKSSourceConnectionRequest"] & { id: string; version: number; enabled?: boolean; status?: string; reason_code?: string; last_sync_at?: string };
function Reasons({ values }: { values?: string[] }) {
  return values?.length ? <ul>{values.map(value => <li key={value}>{readable(value)}</li>)}</ul> : null;
}

export function EksAssociation({ resourceID, workloadID }: { resourceID: string; workloadID?: string }) {
  const [revision, setRevision] = useState(0);
  const state = useRemote<S["EKSKubernetesAssociation"]>(`/resources/${encodeURIComponent(resourceID)}/eks-association`, revision);
  const result = state.value;
  const workloads = result?.workloads.filter(item => !workloadID || item.workload_id === workloadID) ?? [];
  return <section className="configuration-stack" aria-label="EKS Kubernetes identity association">
    <h4>Observed Kubernetes association</h4>
    <p className="form-note">Native endpoint and CA, observed kube-system UID, node identity and independently read AWS membership bind this point observation. Names and declarations alone do not establish placement. Relationships add no spend or execution authority.</p>
    {state.loading ? <p role="status">Loading EKS association…</p> : null}
    {state.error ? <p role="alert">EKS association unavailable. {state.error}</p> : null}
    {result ? <>
      <div className="row-actions"><Badge value={result.status} /><Badge value={result.current ? "CURRENT" : "NOT_CURRENT"} /></div>
      <Reasons values={result.reason_codes} /><Reasons values={result.currentness_blockers} />
      <dl className="definition-list"><div><dt>Observed cluster UID</dt><dd>{result.cluster?.kube_system_uid || "Unavailable"}</dd></div><div><dt>Observed at</dt><dd>{dateTime(result.observed_at)}</dd></div><div><dt>Source revisions</dt><dd>{result.source_version ?? "Unavailable"} · native {result.native_source_version ?? "Unavailable"}</dd></div></dl>
      {result.nodes.length ? <Table scrollLabel="EKS observed node identities" headings={["Kubernetes node", "Native identity", "Association"]}>{result.nodes.map(node => <tr key={node.kubernetes_node_uid}><th scope="row">{node.kubernetes_node_name}<small>{node.kubernetes_node_uid}</small><small>{node.provider_id || "Provider ID unavailable"}</small></th><td>{node.ec2_instance_id || node.fargate_profile_name || "Unproven placement"}<small>{node.nodegroup_resource_id || node.fargate_profile_resource_id || "No exact managed group / profile association"}</small></td><td><Badge value={node.status} /><Reasons values={node.reason_codes} /></td></tr>)}</Table> : <p>No node placement has been independently established.</p>}
      {workloads.length ? <Table scrollLabel="EKS observed workload placement" headings={["Workload / immutable identities", "Placement", "Association"]}>{workloads.map(workload => <tr key={workload.workload_id}><th scope="row">{workload.workload_id}<small>Namespace UID: {workload.namespace_uid || "Unavailable"}</small><small>Deployment UID: {workload.deployment_uid || "Unavailable"}</small></th><td>{workload.pod_uids.length} observed pods · {new Set(workload.node_uids).size} observed nodes</td><td><Badge value={workload.status} /><Reasons values={workload.reason_codes} /></td></tr>)}</Table> : <p>No authorised workload placement has been established for this selection.</p>}
      <details className="plan-operations"><summary>Inspect immutable identity proof references</summary><pre className="evidence-json">{JSON.stringify({ endpoint_sha256: result.cluster?.endpoint_sha256, ca_sha256: result.cluster?.ca_sha256, content_hash: result.content_hash, archive: result.archive, source_refs: result.source_refs }, null, 2)}</pre></details>
    </> : null}
    <Button secondary small disabled={state.loading} onClick={() => setRevision(value => value + 1)}>Refresh EKS association</Button>
  </section>;
}

function RegistrationForm({ data, run, busy, onClose }: { data: Dashboard; run: RunMutation; busy: boolean; onClose: () => void }) {
  const bindings = useRemote<S["EKSApprovedBindingList"]>("/eks-kubernetes-bindings");
  const [bindingID, setBindingID] = useState(""), [sourceID, setSourceID] = useState("");
  const [values, setValues] = useState({ name: "", workload_id: "", namespace: "", namespace_uid: "", deployment: "", deployment_uid: "" });
  const [error, setError] = useState("");
  const selected = bindings.value?.items.find(binding => binding.id === bindingID);
  const nativeSources = (data.source_connections ?? []).filter(source => source.kind === "AWS_SERVICE_NATIVE_V1" && source.enabled && source.account_id === selected?.account_id && source.region === selected?.region && source.service_families?.includes("EKS") && (source.scope_mode === "ACCOUNT" || source.root_resource_arns?.includes(selected?.cluster_arn ?? ""))) as (S["AWSServiceSourceConnectionRequest"] & { id: string })[];
  const source = nativeSources.find(item => item.id === sourceID);
  return <Modal title="Register EKS identity association" subtitle="Existing operator-approved read bindings only" onClose={onClose}><form className="configuration-stack" onSubmit={async event => {
    event.preventDefault(); setError("");
    if (!selected || !source) { setError("Select a commissioned Kubernetes binding and matching native EKS source."); return; }
    const body: S["EKSSourceConnectionRequest"] = { kind: "AWS_EKS_KUBERNETES_V1", name: values.name, account_id: selected.account_id, region: selected.region, cluster_arn: selected.cluster_arn, read_role_binding_id: source.read_role_binding_id, kubernetes_read_binding_id: selected.id, workload_bindings: values.workload_id ? [{ workload_id: values.workload_id, namespace: values.namespace, namespace_uid: values.namespace_uid, deployment: values.deployment, deployment_uid: values.deployment_uid }] : [] };
    if (await run({ path: "/source-connections", body, version: 0, label: "EKS identity source registered; synchronize to observe placement" })) onClose();
    else setError("Registration was refused. Review approved scope, unique native source and workload access.");
  }}>
    <p>Operator-managed credentials stay outside the console. Registration applies no RBAC or customer changes. Namespace and deployment declarations are checked against actual UIDs and owner references.</p>
    {bindings.loading ? <p role="status">Loading approved Kubernetes bindings…</p> : null}
    {bindings.error ? <p role="alert">Approved bindings unavailable. {bindings.error}</p> : null}
    {!bindings.loading && bindings.value?.items.length === 0 ? <p>No operator-approved Kubernetes binding is commissioned for this tenant.</p> : null}
    <label className="field"><span>EKS association source name</span><input required maxLength={200} value={values.name} onChange={event => setValues(previous => ({ ...previous, name: event.target.value }))} /></label>
    <label className="field"><span>Approved Kubernetes read binding</span><select required value={bindingID} onChange={event => { setBindingID(event.target.value); setSourceID(""); }}><option value="">Select an existing approved binding</option>{bindings.value?.items.map(binding => <option key={binding.id} value={binding.id}>{binding.id} · {binding.cluster_arn}</option>)}</select></label>
    <label className="field"><span>Matching native EKS source</span><select required value={sourceID} onChange={event => setSourceID(event.target.value)}><option value="">Select a registered EKS source</option>{nativeSources.map(item => <option key={item.id} value={item.id}>{item.name || item.id} · {item.read_role_binding_id}</option>)}</select></label>
    <label className="field"><span>Optional workload identity scope</span><select value={values.workload_id} onChange={event => setValues(previous => ({ ...previous, workload_id: event.target.value }))}><option value="">Observe cluster nodes only</option>{data.workloads.map(workload => <option key={workload.id} value={workload.id}>{workload.name}</option>)}</select></label>
    {values.workload_id ? <div className="form-grid">{([["namespace", "Kubernetes namespace"], ["namespace_uid", "Expected namespace UID"], ["deployment", "Kubernetes deployment"], ["deployment_uid", "Expected deployment UID"]] as const).map(([key, label]) => <label className="field" key={key}><span>{label}</span><input required autoComplete="off" maxLength={128} value={values[key]} onChange={event => setValues(previous => ({ ...previous, [key]: event.target.value }))} /></label>)}</div> : null}
    {error ? <p role="alert">{error}</p> : null}<div className="modal-actions"><Button secondary type="button" onClick={onClose}>Cancel</Button><Button type="submit" pending={busy} disabled={!source || !selected}>Register existing EKS identity source</Button></div>
  </form></Modal>;
}

export function EksAssociationSources({ data, run, busy }: { data: Dashboard; run: RunMutation; busy: boolean }) {
  const [creating, setCreating] = useState(false);
  const sources = (data.source_connections ?? []).filter(source => source.kind === "AWS_EKS_KUBERNETES_V1") as Source[];
  return <Panel title="EKS Kubernetes identity connections" eyebrow="OBSERVED PLACEMENT · READ ONLY" action={<Button secondary small onClick={() => setCreating(true)}>Register EKS identity association</Button>}><p>Connect observed Kubernetes identity to native EKS infrastructure through existing approved read bindings. Missing or denied reads remain blockers; association does not duplicate EC2 or Fargate costs.</p>{sources.length ? <Table scrollLabel="EKS Kubernetes source health" headings={["Source / cluster", "Scope", "Health", "Actions"]}>{sources.map(source => <tr key={source.id}><th scope="row">{source.name || source.id}<small>{source.cluster_arn}</small></th><td>{source.account_id} · {source.region}<small>{source.workload_bindings?.length ?? 0} declared workload scopes</small></td><td><Badge value={source.status || "REGISTERED"} /><small>{readable(source.reason_code || "EKS_ASSOCIATION_SYNC_REQUIRED")}</small><small>{dateTime(source.last_sync_at)}</small></td><td><Button secondary small disabled={busy || !source.enabled} onClick={() => void run({ path: `/source-connections/${encodeURIComponent(source.id)}/sync`, version: source.version, label: "EKS identity synchronization queued" })}>Synchronize EKS identity {source.name || source.id}</Button></td></tr>)}</Table> : <Empty title="No commissioned EKS identity source" text="An operator must approve the existing cluster read binding. The console selects its identifier without receiving credentials." />}{creating ? <RegistrationForm data={data} run={run} busy={busy} onClose={() => setCreating(false)} /> : null}</Panel>;
}

export function EksWorkloadAssociations({ workloads }: { workloads: Workload[] }) {
  const [open, setOpen] = useState(false), [selected, setSelected] = useState<Resource | null>(null), [workloadID, setWorkloadID] = useState("");
  return <Panel title="EKS workload placement" eyebrow="NATIVE EKS ↔ OBSERVED KUBERNETES"><details onToggle={event => setOpen(event.currentTarget.open)}><summary>Inspect observed EKS workload association</summary>{open ? <div className="configuration-stack"><label className="field"><span>EKS placement workload</span><select value={workloadID} onChange={event => setWorkloadID(event.target.value)}><option value="">All authorised workload scopes</option>{workloads.map(workload => <option key={workload.id} value={workload.id}>{workload.name}</option>)}</select></label><RemotePage<Resource> path="/resources?service_family=EKS&resource_type=EKS_CLUSTER&limit=10" label="EKS clusters" empty="No EKS clusters were discovered in your authorised scope.">{items => <Table scrollLabel="EKS cluster association selection" headings={["Cluster", "Placement evidence"]}>{items.map(resource => <tr key={resource.id}><th scope="row">{resource.name || resource.provider_resource_id}<small>{resource.provider_resource_id}</small></th><td><Button secondary small onClick={() => setSelected(resource)}>Inspect EKS placement {resource.name || resource.id}</Button></td></tr>)}</Table>}</RemotePage></div> : null}</details>{selected ? <Modal title="EKS workload placement" subtitle={selected.provider_resource_id} onClose={() => setSelected(null)}><EksAssociation resourceID={selected.id} workloadID={workloadID || undefined} /></Modal> : null}</Panel>;
}
