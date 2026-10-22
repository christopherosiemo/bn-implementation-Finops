import { useState } from "react";
import type { components } from "./api.generated";
import type { Resource } from "./types";
import { RemotePage } from "./RemoteData";
import { Badge, Button, Modal, Table, readable, shortId, type RunMutation } from "./ui";

type S = components["schemas"];
type Policy = S["NetworkPolicy"];
type Definition = S["NetworkPolicyDefinition"];
const booleanFields = [
  ["security_reviewed", "Security impact reviewed"], ["network_policy_known", "Network access policy known"],
  ["dependencies_known", "Dependencies known"], ["recovery_known", "Recovery requirements known"],
  ["resilience_known", "Resilience purpose known"], ["allow_topology_change", "Topology changes permitted for review"],
  ["ha_required", "High availability required"], ["on_premises_required", "On-premises access required"],
  ["cross_vpc_required", "Cross-VPC access required"], ["dns_change_approved", "DNS behaviour change reviewed"],
  ["public_access_required", "Public connectivity required"], ["endpoint_policy_reviewed", "Endpoint and service policy reviewed"],
  ["seasonal", "Declared seasonal workload"],
] as const;

export function NetworkPolicyForm({ resource, latest, run, busy, onClose, onSaved }: { resource: Resource; latest?: Policy; run: RunMutation; busy: boolean; onClose: () => void; onSaved: () => void }) {
  const [name, setName] = useState(latest?.name ?? ""), [policy, setPolicy] = useState<Definition>(latest?.policy ?? { owner: "", configuration_authority: "UNKNOWN", criticality: resource.environment === "NON_PRODUCTION" ? "NON_PRODUCTION" : "PRODUCTION" }), [error, setError] = useState("");
  return <Modal title={latest ? "Revise network requirements" : "Declare network requirements"} subtitle={resource.name || resource.provider_resource_id} onClose={onClose}>
    <form className="configuration-stack" onSubmit={async event => {
      event.preventDefault(); setError(""); const body: S["NetworkPolicyRequest"] = { resource_id: resource.id, name, policy };
      if (await run({ path: latest ? `/network-policies/${encodeURIComponent(latest.id)}/revisions` : "/network-policies", body, version: latest?.version ?? 0, label: "Network requirements saved; native topology, traffic and economics remain independently required" })) onSaved();
      else setError("Requirements were not saved. Refresh the current policy revision and inspect the API error before retrying.");
    }}>
      <p className="form-note">Record customer requirements for read-only advice. Unknown declarations remain unknown. These fields supply no traffic, topology, customer prices or permission to modify AWS. Declarative ownership is checked against the existing configuration-authority evidence.</p>
      <div className="form-grid">
        <label className="field full-width"><span>Network policy name</span><input required maxLength={200} value={name} onChange={event => setName(event.target.value)} /></label>
        <label className="field"><span>Network owner</span><input value={policy.owner ?? ""} onChange={event => setPolicy(value => ({ ...value, owner: event.target.value }))} placeholder="Unknown" /></label>
        <label className="field"><span>Configuration authority</span><select value={policy.configuration_authority ?? "UNKNOWN"} onChange={event => setPolicy(value => ({ ...value, configuration_authority: event.target.value as Definition["configuration_authority"] }))}>{(["UNKNOWN", "TERRAFORM", "CLOUDFORMATION", "MANUAL"] as const).map(value => <option key={value}>{value}</option>)}</select></label>
        <label className="field"><span>Workload criticality</span><select value={policy.criticality ?? "PRODUCTION"} onChange={event => setPolicy(value => ({ ...value, criticality: event.target.value as Definition["criticality"] }))}><option value="PRODUCTION">Production</option><option value="NON_PRODUCTION">Non-production</option></select></label>
        <label className="field"><span>Minimum Availability Zones</span><input type="number" min={1} max={16} step={1} value={policy.required_azs ?? ""} onChange={event => setPolicy(value => ({ ...value, required_azs: event.target.value === "" ? null : Number(event.target.value) }))} placeholder="Unknown" /></label>
        <label className="field full-width"><span>Traffic purpose and resilience requirements</span><textarea value={policy.traffic_purpose ?? ""} onChange={event => setPolicy(value => ({ ...value, traffic_purpose: event.target.value }))} placeholder="Unknown; include replication, DR, customer geography and access requirements when known" /></label>
        {booleanFields.map(([key, label]) => <label className="field" key={key}><span>{label}</span><select value={policy[key] == null ? "UNKNOWN" : policy[key] ? "YES" : "NO"} onChange={event => setPolicy(value => ({ ...value, [key]: event.target.value === "UNKNOWN" ? null : event.target.value === "YES" }))}><option value="UNKNOWN">Unknown</option><option value="NO">No</option><option value="YES">Yes</option></select></label>)}
      </div>
      {error && <p role="alert">{error}</p>}<div className="modal-actions"><Button secondary type="button" onClick={onClose}>Cancel</Button><Button type="submit" pending={busy}>Save network requirements</Button></div>
    </form>
  </Modal>;
}

export function NetworkPolicies({ resource, busy, onAssess, onEdit }: { resource: Resource; busy: boolean; onAssess: (policy: Policy) => void; onEdit: (policy: Policy | "NEW") => void }) {
  const [revision, setRevision] = useState(0);
  return <section className="configuration-stack" aria-label="Network requirements"><h4>Customer network requirements</h4><p>Assessment binds to an immutable policy revision. Changing ownership, access, recovery, resilience or security requirements invalidates current advice.</p><div className="row-actions"><Button secondary small onClick={() => onEdit("NEW")}>Declare network requirements</Button><Button secondary small onClick={() => setRevision(value => value + 1)}>Refresh network requirements</Button></div>
    <RemotePage<Policy> key={revision} path={`/network-policies?resource_id=${encodeURIComponent(resource.id)}&limit=10`} label="Network policies" empty="No customer network requirements are registered. Material unknown requirements block validated alternatives.">{items => <Table scrollLabel="Registered network requirements" headings={["Policy / revision", "Owner / authority", "Access / resilience", "Actions"]}>{items.map(item => <tr key={item.id}><th scope="row">{item.name}<small>{shortId(item.id)} · revision {item.version}</small></th><td>{item.policy.owner || "Unknown owner"}<small>{readable(item.policy.configuration_authority ?? "UNKNOWN")}</small></td><td>{item.policy.required_azs == null ? "AZ requirement unknown" : `${item.policy.required_azs} AZ minimum`}<small>{item.policy.traffic_purpose || "Traffic purpose unknown"}</small><Badge value={item.policy.security_reviewed === true ? "REVIEWED" : "UNKNOWN"}>Security review {item.policy.security_reviewed === true ? "declared" : "unavailable"}</Badge></td><td><div className="row-actions"><Button secondary small pending={busy} onClick={() => onAssess(item)}>Assess with policy {item.name}</Button><Button secondary small onClick={() => onEdit(item)}>Revise network policy {item.name}</Button></div></td></tr>)}</Table>}</RemotePage>
  </section>;
}
