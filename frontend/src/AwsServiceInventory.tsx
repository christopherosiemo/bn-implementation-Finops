import { useState } from "react";
import type { components } from "./api.generated";
import type { Resource, Workload } from "./types";
import { RemotePage, useRemote } from "./RemoteData";
import { EksAssociation } from "./EksAssociation";
import { AwsServiceAssessmentDialog, AwsServiceResourceAssessment } from "./AwsServiceAssessment";
import { Badge, Button, Modal, Panel, Table, dateTime, readable, type RunMutation } from "./ui";

export const awsServiceFamilies = ["ECS", "EKS", "ELASTICACHE", "DYNAMODB", "ELB"] as const;
export type AwsServiceFamily = components["schemas"]["AWSServiceFamily"];
const families: Record<AwsServiceFamily, { name: string; types: readonly string[] }> = {
  ECS: { name: "ECS / Fargate", types: ["ECS_SERVICE", "ECS_CLUSTER", "ECS_TASK_DEFINITION", "ECS_TASK", "ECS_CAPACITY_PROVIDER", "ECS_CONTAINER_INSTANCE"] },
  EKS: { name: "EKS infrastructure", types: ["EKS_CLUSTER", "EKS_NODE_GROUP", "EKS_FARGATE_PROFILE", "EKS_ADDON"] },
  ELASTICACHE: { name: "ElastiCache", types: ["ELASTICACHE_REPLICATION_GROUP", "ELASTICACHE_CLUSTER", "ELASTICACHE_SERVERLESS_CACHE"] },
  DYNAMODB: { name: "DynamoDB", types: ["DYNAMODB_TABLE", "DYNAMODB_GSI"] },
  ELB: { name: "Load balancing", types: ["LOAD_BALANCER", "ELB_LISTENER", "ELB_TARGET_GROUP"] },
};
type NativeResource = Resource & {
  service_family?: AwsServiceFamily;
  aws_service_configuration?: components["schemas"]["AWSServiceConfiguration"];
  provider_relationships?: unknown[];
  spend_coverage?: string;
  cost_status?: string;
};
const kinds = new Set(Object.values(families).flatMap(family => family.types));
export function isAwsServiceResource(resource: Resource) {
  const value = resource as NativeResource;
  return kinds.has(resource.resource_type) && (resource.resource_type !== "LOAD_BALANCER" || Boolean(value.aws_service_configuration));
}
const object = (value: unknown): Record<string, unknown> => value !== null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
const text = (value: unknown): string => value === null || value === undefined || value === "" ? "Unknown" : typeof value === "boolean" ? value ? "Yes" : "No" : typeof value === "string" || typeof value === "number" ? String(value) : Array.isArray(value) ? value.map(item => typeof item === "object" ? "Structured native observation" : String(item)).join(", ") || "Observed empty list" : "Structured native observation";
const amount = (resource: Resource) => (resource as NativeResource).cost_status === "UNAVAILABLE" || resource.monthly_effective_cost == null || !resource.currency ? "Unavailable" : `${resource.monthly_effective_cost} ${resource.currency}`;
const facts = [
  ["Placement / capacity", ["launch_type", "launchType", "capacity_type", "capacityType", "capacity_provider", "capacityProviderName", "type"]],
  ["Desired / running / pending", ["desired_count", "desiredCount", "running_count", "runningCount", "pending_count", "pendingCount"]],
  ["CPU / memory", ["cpu", "memory", "node_type", "CacheNodeType", "instance_types", "instanceTypes"]],
  ["Engine / version", ["engine", "Engine", "engine_version", "EngineVersion", "version"]],
  ["Capacity / billing mode", ["billing_mode", "BillingModeSummary", "provisioned_throughput", "ProvisionedThroughput", "scaling_config", "scalingConfig"]],
  ["Availability / failover", ["multi_az", "MultiAZ", "AutomaticFailover", "availability_zones", "AvailabilityZones", "zones"]],
  ["Network / topology", ["cluster_arn", "clusterArn", "cluster_name", "clusterName", "replication_group_id", "ReplicationGroupId", "vpc_id", "VpcId", "scheme", "Scheme"]],
] as const;
function Configuration({ resource }: { resource: NativeResource }) {
  const config = object(resource.aws_service_configuration);
  const native = { ...config, ...object(config.configuration), ...object(config.native) };
  return <section className="configuration-stack" aria-label="AWS service native configuration">
    <h4>Native configuration and topology</h4>
    <dl className="definition-list"><div><dt>Service / resource type</dt><dd>{resource.service_family ? families[resource.service_family]?.name : "AWS service"} · {readable(resource.resource_type)}</dd></div><div><dt>Account / region</dt><dd>{text(resource.account_id)} · {text(resource.region)}</dd></div><div><dt>Owner / authority</dt><dd>{text(resource.owner)} · {readable(resource.configuration_authority || "UNKNOWN")}</dd></div><div><dt>Workload</dt><dd>{resource.workload_id || "Unowned / unknown"}</dd></div><div><dt>Last observed</dt><dd>{dateTime(resource.last_seen_at as string | undefined)}</dd></div><div><dt>Monthly source cost</dt><dd>{amount(resource)} · {readable(resource.cost_status || "COST_EVIDENCE_UNAVAILABLE")}</dd></div></dl>
    {facts.map(([label, keys]) => { const values = keys.filter(key => native[key] !== null && native[key] !== undefined); return values.length ? <div key={label}><h5>{label}</h5>{values.map(key => <p key={key}>{readable(key)}: {text(native[key])}</p>)}</div> : null; })}
    <p className="form-note">Task and Kubernetes placement are analytical relationships. EC2-backed task or node costs are not added to the same underlying EC2 charge. Missing ownership, denied reads and unresolved allocation remain explicit.</p>
    {resource.blockers?.length ? <ul>{resource.blockers.map(reason => <li key={reason}>{readable(reason)}</li>)}</ul> : <p>Detailed read coverage is retained with the native evidence.</p>}
    <details className="plan-operations"><summary>Inspect retained configuration fields</summary>{Object.keys(config).length ? <pre className="evidence-json">{JSON.stringify(config, null, 2)}</pre> : <p>Native configuration unavailable.</p>}</details>
    <details className="plan-operations"><summary>Inspect evidenced service relationships</summary><pre className="evidence-json">{JSON.stringify(resource.provider_relationships ?? [], null, 2)}</pre></details>
  </section>;
}
function NativeEvidence({ resourceID }: { resourceID: string }) {
  const [revision, setRevision] = useState(0), state = useRemote<components["schemas"]["AWSServiceEvidence"]>(`/resources/${encodeURIComponent(resourceID)}/aws-service-evidence`, revision);
  return <section className="configuration-stack" aria-label="AWS service immutable evidence"><h4>Collection coverage and provenance</h4>{state.loading && <p role="status">Loading native service evidence…</p>}{state.error && <p role="alert">Native evidence unavailable. {state.error}</p>}{state.value !== undefined && <details className="plan-operations"><summary>Inspect source versions, collection gaps and relationships</summary><pre className="evidence-json">{JSON.stringify(state.value, null, 2)}</pre></details>}<Button secondary small disabled={state.loading} onClick={() => setRevision(value => value + 1)}>Refresh native service evidence</Button></section>;
}
export function AwsServiceResourceDetails({ resource, run, busy }: { resource: Resource; run: RunMutation; busy: boolean }) {
  const [open, setOpen] = useState(false), [assessment, setAssessment] = useState("");
  const native = resource as NativeResource;
  return <><Badge value={native.spend_coverage || "OBSERVATION_ONLY"} /><Button secondary small onClick={() => setOpen(true)}>Inspect AWS service {resource.name || resource.provider_resource_id}</Button>{open && <Modal title="AWS service resource" subtitle={resource.provider_resource_id} onClose={() => setOpen(false)}><Configuration resource={native} /><NativeEvidence resourceID={resource.id} />{resource.resource_type === "EKS_CLUSTER" ? <EksAssociation resourceID={resource.id} /> : null}<AwsServiceResourceAssessment resource={resource} run={run} busy={busy} onRequested={id => { setOpen(false); setAssessment(id); }} /><p className="form-note">Read-only inventory and advice. This view grants no deployment, scaling, deletion or execution authority.</p></Modal>}{assessment && <AwsServiceAssessmentDialog id={assessment} onClose={() => setAssessment("")} />}</>;
}
export function AwsServiceInventory({ workloads, run, busy }: { workloads: Workload[]; run: RunMutation; busy: boolean }) {
  const [open, setOpen] = useState(false), [family, setFamily] = useState<AwsServiceFamily>("ECS"), [kind, setKind] = useState("ECS_SERVICE"), [workload, setWorkload] = useState(""), [revision, setRevision] = useState(0);
  const path = `/resources?service_family=${family}&resource_type=${encodeURIComponent(kind)}&limit=10${workload ? `&workload_id=${encodeURIComponent(workload)}` : ""}`;
  return <Panel title="AWS service inventory" eyebrow="ECS / FARGATE · EKS · CACHE · DYNAMODB · LOAD BALANCING"><p>Inspect services, infrastructure and topology with scoped pagination. Unknown costs and unowned resources remain visible. Service inventory does not establish an optimisation or a savings claim.</p><details onToggle={event => setOpen(event.currentTarget.open)}><summary>Inspect AWS service inventory</summary>{open && <div className="configuration-stack"><div className="form-grid"><label className="field"><span>AWS service family</span><select aria-label="AWS service family" value={family} onChange={event => { const selected = event.target.value as AwsServiceFamily; setFamily(selected); setKind(families[selected].types[0]); }}>{awsServiceFamilies.map(value => <option key={value} value={value}>{families[value].name}</option>)}</select></label><label className="field"><span>AWS service resource type</span><select aria-label="AWS service resource type" value={kind} onChange={event => setKind(event.target.value)}>{families[family].types.map(value => <option key={value} value={value}>{readable(value)}</option>)}</select></label><label className="field"><span>AWS service workload</span><select aria-label="AWS service workload" value={workload} onChange={event => setWorkload(event.target.value)}><option value="">All authorised workloads and unowned resources</option>{workloads.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}</select></label></div><Button secondary small onClick={() => setRevision(value => value + 1)}>Refresh AWS service inventory</Button><RemotePage<Resource> key={`${path}:${revision}`} path={path} label="AWS service resources" empty="No resources of this type were discovered in your authorised scope. Inspect source health for missing or denied native reads.">{items => <Table scrollLabel="Scoped AWS service inventory" headings={["Resource / placement", "Workload / owner", "Configuration authority", "Monthly source cost", "Coverage / details"]}>{items.map(resource => { const native = resource as NativeResource, config = object(native.aws_service_configuration); return <tr key={resource.id}><th scope="row">{resource.name || resource.provider_resource_id}<small>{resource.provider_resource_id}</small><small>{readable(resource.resource_type)} · {text(config.launch_type ?? config.launchType ?? config.subtype)}</small><Badge value={resource.state || "UNKNOWN"} /></th><td>{workloads.find(item => item.id === resource.workload_id)?.name || resource.workload_id || "Unowned / unknown"}<small>{text(resource.owner)}</small></td><td>{readable(resource.configuration_authority || "UNKNOWN")}</td><td>{amount(resource)}<small>{readable(native.cost_status || "COST_EVIDENCE_UNAVAILABLE")}</small></td><td><AwsServiceResourceDetails resource={resource} run={run} busy={busy} /></td></tr>; })}</Table>}</RemotePage></div>}</details></Panel>;
}
