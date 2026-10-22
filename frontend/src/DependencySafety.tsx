import { useState } from "react";
import { ShieldCheck } from "lucide-react";
import type { components } from "./api.generated";
import type {
  Dashboard,
  DependencyEdgeInput,
  DependencyEdgeType,
  DependencyNode,
  Resource,
  ResourceGraph,
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
  resourceReadiness,
  shortId,
  type RunMutation,
} from "./ui";

const edgeTypes: DependencyEdgeType[] = [
  "RUNS_ON",
  "ATTACHED_TO",
  "ROUTES_TO",
  "DEPENDS_ON",
  "BACKED_BY",
  "MEMBER_OF",
  "MANAGED_BY",
  "SCALES_WITH",
  "PROTECTED_BY",
  "CONFIGURED_BY",
  "PAID_BY_COMMITMENT",
];
const nodeName = (node?: DependencyNode, fallback = "Unknown node") =>
  node?.name || node?.id || fallback;

function Reasons({ reasons, label }: { reasons?: string[]; label: string }) {
  return reasons?.length ? (
    <ul className="evidence-refs" aria-label={label}>
      {reasons.map((reason) => (
        <li key={reason}>{readable(reason)}</li>
      ))}
    </ul>
  ) : null;
}

function GraphForm({
  graph,
  run,
  busy,
  onClose,
}: {
  graph: ResourceGraph;
  run: RunMutation;
  busy: boolean;
  onClose: () => void;
}) {
  // Keep the reviewed revision fixed while editing. A background refresh must
  // never attach stale declarations to a newer If-Match version silently.
  const [base] = useState(graph);
  const [edges, setEdges] = useState(() =>
    graph.edges
      .filter((edge) => edge.source === "OPERATOR_DECLARED")
      .map(({ from, to, type }) => ({
        key: crypto.randomUUID(),
        from,
        to,
        type,
      })),
  );
  const [reason, setReason] = useState("");
  const [error, setError] = useState("");
  const update = (
    key: string,
    field: keyof DependencyEdgeInput,
    value: string,
  ) =>
    setEdges((current) =>
      current.map((edge) =>
        edge.key === key ? { ...edge, [field]: value } : edge,
      ),
    );
  return (
    <Modal
      title="Declare dependency graph"
      subtitle={`Graph revision ${base.version} · platform administrator`}
      onClose={onClose}
    >
      <form
        onSubmit={async (event) => {
          event.preventDefault();
          setError("");
          const declared = edges.map(({ from, to, type }) => ({
            from,
            to,
            type,
          }));
          if (declared.some((edge) => edge.from === edge.to)) {
            setError(
              "Choose different source and destination nodes for every dependency.",
            );
            return;
          }
          if (
            new Set(declared.map((edge) => JSON.stringify(edge))).size !==
            declared.length
          ) {
            setError("Remove duplicate dependency declarations before saving.");
            return;
          }
          const body: components["schemas"]["ResourceGraphRequest"] = {
            edges: declared,
            reason: reason.trim(),
          };
          if (
            await run({
              path: "/resource-graph",
              version: base.version,
              body,
              label:
                "Dependency graph revision recorded; resource reviews must be renewed",
            })
          )
            onClose();
          else
            setError(
              "Graph not saved. Check the request error and refresh before retrying if the graph or inventory changed.",
            );
        }}
      >
        <p className="form-note">
          Save the complete declared edge set. Inventory-derived mappings remain
          server-managed. Every declared edge is a hard dependency; removing one
          requires an auditable reason.
        </p>
        {edges.map((edge, index) => (
          <fieldset className="days-fieldset" key={edge.key}>
            <legend>Declared dependency {index + 1}</legend>
            <div className="form-grid">
              {(["from", "to"] as const).map((field) => (
                <label className="field" key={field}>
                  <span>
                    {field === "from" ? "Source node" : "Destination node"}{" "}
                    {index + 1}
                  </span>
                  <select
                    required
                    value={edge[field]}
                    onChange={(event) =>
                      update(edge.key, field, event.target.value)
                    }
                  >
                    <option value="">Choose an inventory node</option>
                    {base.nodes.map((node) => (
                      <option key={node.id} value={node.id}>
                        {nodeName(node)} · {readable(node.kind)}
                      </option>
                    ))}
                  </select>
                </label>
              ))}
              <label className="field full-width">
                <span>Dependency type {index + 1}</span>
                <select
                  value={edge.type}
                  onChange={(event) =>
                    update(edge.key, "type", event.target.value)
                  }
                >
                  {edgeTypes.map((type) => (
                    <option key={type} value={type}>
                      {readable(type)}
                    </option>
                  ))}
                </select>
              </label>
            </div>
            <Button
              secondary
              small
              type="button"
              onClick={() =>
                setEdges((current) =>
                  current.filter((item) => item.key !== edge.key),
                )
              }
            >
              Remove declared dependency {index + 1}
            </Button>
          </fieldset>
        ))}
        {!edges.length && (
          <p className="form-note">
            No operator-declared edges. Discovered mappings alone do not
            establish that stopping is safe.
          </p>
        )}
        <Button
          secondary
          small
          type="button"
          onClick={() =>
            setEdges((current) => [
              ...current,
              {
                key: crypto.randomUUID(),
                from: "",
                to: "",
                type: "DEPENDS_ON",
              },
            ])
          }
        >
          Add declared dependency
        </Button>
        <label className="field full-width">
          <span>Reason for this graph revision</span>
          <input
            required
            minLength={10}
            maxLength={2000}
            autoComplete="off"
            value={reason}
            onChange={(event) => setReason(event.target.value)}
          />
        </label>
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
            disabled={reason.trim().length < 10}
          >
            Save graph revision
          </Button>
        </div>
      </form>
    </Modal>
  );
}

function ReviewForm({
  resource,
  graph,
  run,
  busy,
  onClose,
}: {
  resource: Resource;
  graph: ResourceGraph;
  run: RunMutation;
  busy: boolean;
  onClose: () => void;
}) {
  const [graphVersion] = useState(graph.version);
  const [hours, setHours] = useState(4);
  const [note, setNote] = useState("");
  const [acknowledged, setAcknowledged] = useState(false);
  const [failed, setFailed] = useState(false);
  const validDuration = Number.isInteger(hours) && hours >= 1 && hours <= 24;
  return (
    <Modal
      title="Review resource dependencies"
      subtitle={`${resource.name} · graph revision ${graphVersion}`}
      onClose={onClose}
    >
      <form
        onSubmit={async (event) => {
          event.preventDefault();
          if (!acknowledged || !validDuration || note.trim().length < 10)
            return;
          setFailed(false);
          const body: components["schemas"]["DependencyReviewRequest"] = {
            graph_version: graphVersion,
            valid_until: new Date(Date.now() + hours * 3_600_000).toISOString(),
            acknowledgement: "REVIEWED_DISCOVERED_AND_EXTERNAL_DEPENDENCIES",
            note: note.trim(),
          };
          if (
            await run({
              path: `/resources/${resource.id}/dependency-reviews`,
              version: resource.version,
              body,
              label:
                "Dependency review recorded. Blocking dependencies remain enforced; no change plan was approved or executed.",
            })
          )
            onClose();
          else setFailed(true);
        }}
      >
        <p className="form-note">
          This is an explicit operator review, not automatic dependency
          discovery. Check downstream consumers and external systems as well as
          the visible graph. Hard dependencies can keep the result blocked even
          after a review is recorded.
        </p>
        <div className="form-grid">
          <label className="field full-width">
            <span>Review validity in hours</span>
            <input
              type="number"
              min={1}
              max={24}
              step={1}
              required
              value={hours}
              onChange={(event) => setHours(Number(event.target.value))}
            />
            <small>
              Expires at a UTC timestamp; maximum 24 hours. Inventory or graph
              changes require a new review.
            </small>
          </label>
          <label className="field full-width">
            <span>Dependency review note</span>
            <input
              required
              minLength={10}
              maxLength={2000}
              autoComplete="off"
              value={note}
              onChange={(event) => setNote(event.target.value)}
            />
          </label>
        </div>
        <label className="checkbox-field">
          <input
            type="checkbox"
            required
            checked={acknowledged}
            onChange={(event) => setAcknowledged(event.target.checked)}
          />
          <span>
            I reviewed discovered mappings, declared dependencies, and external
            consumers for this resource.
          </span>
        </label>
        {failed && (
          <p role="alert" className="blocker-text">
            Review not recorded. Check the request error; refresh before
            retrying if the resource or graph changed.
          </p>
        )}
        <div className="modal-actions">
          <Button secondary type="button" onClick={onClose}>
            Cancel
          </Button>
          <Button
            type="submit"
            pending={busy}
            disabled={
              !acknowledged || !validDuration || note.trim().length < 10
            }
          >
            Record dependency review
          </Button>
        </div>
      </form>
    </Modal>
  );
}

export function DependencySafety({
  data,
  run,
  busy,
}: {
  data: Dashboard;
  run: RunMutation;
  busy: boolean;
}) {
  const [editing, setEditing] = useState(false);
  const [reviewing, setReviewing] = useState<Resource | null>(null);
  const graph = data.dependency_graph;
  if (!graph)
    return (
      <Panel title="Dependency safety">
        <Empty
          title="Dependency graph unavailable"
          text="Current dependency evidence has not been supplied. An empty or unavailable graph does not establish that a resource has no dependencies."
        />
      </Panel>
    );
  const nodes = new Map(graph.nodes.map((node) => [node.id, node]));
  return (
    <>
      <Panel
        title="Dependency safety"
        eyebrow="INVENTORY MAPPINGS & OPERATOR REVIEW"
        action={
          <Button
            secondary
            small
            disabled={busy || !graph.nodes.length}
            onClick={() => setEditing(true)}
          >
            Declare dependencies
          </Button>
        }
      >
        <div className="policy-note">
          <ShieldCheck size={19} aria-hidden="true" />
          <div>
            <strong>Manual review is a trust boundary.</strong>
            <p>
              Discovered mappings describe known inventory relationships.
              Operator declarations and expiring reviews must account for
              external consumers. This view does not claim complete automatic
              dependency discovery.
            </p>
          </div>
        </div>
        <div className="policy-row">
          <span>
            <strong>Graph revision {graph.version}</strong>
            <small>
              Declared graphs remain subject to resource-specific blocking
              checks.
            </small>
          </span>
          <Badge value={graph.status} />
        </div>
        <Reasons reasons={graph.reasons} label="Graph blocking reasons" />
        {graph.version === 0 && (
          <div className="policy-note">
            Declare and inspect the current graph before recording a resource
            review.
          </div>
        )}
        <section aria-label="Dependency graph nodes">
          {graph.nodes.length ? (
            <Table
              scrollLabel="Scrollable graph inventory"
              headings={[
                "Inventory node",
                "Owner / environment",
                "Provider binding",
                "Configuration authority",
              ]}
            >
              {graph.nodes.map((node) => (
                <tr key={node.id}>
                  <td>
                    <strong>{nodeName(node)}</strong>
                    <small>
                      {readable(node.kind)} · {node.id}
                    </small>
                  </td>
                  <td>
                    {node.owner || "Owner unknown"}
                    <small>{readable(node.environment || "UNKNOWN")}</small>
                  </td>
                  <td>
                    {node.provider_resource_id || "Workload mapping"}
                    <small>
                      {[node.provider, node.account_id, node.region]
                        .filter(Boolean)
                        .join(" · ") || "Provider binding unavailable"}
                    </small>
                  </td>
                  <td>{readable(node.configuration_authority)}</td>
                </tr>
              ))}
            </Table>
          ) : (
            <Empty
              title="No visible graph nodes"
              text="Inventory may be unavailable or outside your authorized scope. Dependency safety remains unknown."
            />
          )}
        </section>
        <section aria-label="Dependency graph edges">
          {graph.edges.length ? (
            <Table
              scrollLabel="Scrollable dependency relationships"
              headings={[
                "Source",
                "Relationship",
                "Destination",
                "Evidence source",
              ]}
            >
              {graph.edges.map((edge) => (
                <tr key={`${edge.source}:${edge.from}:${edge.type}:${edge.to}`}>
                  <td>{nodeName(nodes.get(edge.from), edge.from)}</td>
                  <td>
                    {edge.type}
                    <small>Hard dependency</small>
                  </td>
                  <td>{nodeName(nodes.get(edge.to), edge.to)}</td>
                  <td>
                    <Badge tone="neutral" value={edge.source}>
                      {edge.source === "DISCOVERED_MAPPING"
                        ? "Discovered mapping"
                        : "Operator declared"}
                    </Badge>
                  </td>
                </tr>
              ))}
            </Table>
          ) : (
            <Empty
              title="No visible dependency edges"
              text="No visible edges does not prove there are no external dependencies. Explicit resource review and current safety evidence are still required."
            />
          )}
        </section>
        <div className="policy-row">
          <span>
            <strong>Immutable graph binding</strong>
            <small>
              Inventory{" "}
              <code title={graph.inventory_hash}>
                {shortId(graph.inventory_hash)}
              </code>{" "}
              · Graph{" "}
              <code title={graph.graph_hash}>{shortId(graph.graph_hash)}</code>
            </small>
          </span>
        </div>
      </Panel>
      <Panel title="Resource dependency reviews">
        <section aria-label="Dependency review status">
          {data.resources.length ? (
            <Table
              scrollLabel="Scrollable resource dependency reviews"
              headings={[
                "Resource",
                "Latest dependency assessment",
                "Latest recorded review",
                "Action",
              ]}
            >
              {data.resources.map((resource) => {
                const readiness = resourceReadiness(data, resource.id);
                const latest = graph.reviews
                  .filter((review) => review.resource_id === resource.id)
                  .sort(
                    (a, b) =>
                      Date.parse(b.reviewed_at) - Date.parse(a.reviewed_at),
                  )[0];
                return (
                  <tr key={resource.id}>
                    <td>
                      <strong>
                        {resource.name || resource.provider_resource_id}
                      </strong>
                      <small>Resource version {resource.version}</small>
                    </td>
                    <td>
                      <Badge
                        value={readiness?.dependency_status || "UNKNOWN"}
                      />
                      <Reasons
                        reasons={readiness?.dependency_reasons}
                        label={`${resource.name} dependency blockers`}
                      />
                      {!readiness?.dependency_status && (
                        <small>Current dependency assessment required</small>
                      )}
                      {readiness?.dependency_status && (
                        <small>Assessed {dateTime(readiness.checked_at)}</small>
                      )}
                      {readiness?.dependency_review_id && (
                        <small>
                          Review{" "}
                          <code title={readiness.dependency_review_id}>
                            {shortId(readiness.dependency_review_id)}
                          </code>
                        </small>
                      )}
                    </td>
                    <td>
                      {latest ? (
                        <>
                          <strong>
                            Recorded result: {readable(latest.status)}
                          </strong>
                          <small>
                            {latest.reviewed_by} · revision{" "}
                            {latest.graph_version}
                          </small>
                          <small>Expires {dateTime(latest.expires_at)}</small>
                          <Reasons
                            reasons={latest.reasons}
                            label={`${resource.name} recorded review reasons`}
                          />
                          <details>
                            <summary>Review evidence</summary>
                            <dl className="definition-list">
                              <div>
                                <dt>Review</dt>
                                <dd className="evidence-id">{latest.id}</dd>
                              </div>
                              <div>
                                <dt>Graph hash</dt>
                                <dd className="evidence-id">
                                  {latest.graph_hash}
                                </dd>
                              </div>
                              <div>
                                <dt>Inventory hash</dt>
                                <dd className="evidence-id">
                                  {latest.inventory_hash}
                                </dd>
                              </div>
                              <div>
                                <dt>Note</dt>
                                <dd>{latest.note}</dd>
                              </div>
                            </dl>
                          </details>
                        </>
                      ) : (
                        <span>No recorded dependency review</span>
                      )}
                    </td>
                    <td>
                      <Button
                        secondary
                        small
                        pending={busy}
                        disabled={
                          graph.version === 0 ||
                          graph.status !== "DECLARED" ||
                          !graph.nodes.some(
                            (node) =>
                              node.resource_id === resource.id ||
                              node.id === `resource:${resource.id}`,
                          )
                        }
                        onClick={() => setReviewing(resource)}
                        aria-label={`Review dependencies for ${resource.name || resource.provider_resource_id}`}
                      >
                        Review dependencies
                      </Button>
                    </td>
                  </tr>
                );
              })}
            </Table>
          ) : (
            <Empty
              title="No resources available for review"
              text="Discover and classify a resource before reviewing its dependency safety."
            />
          )}
        </section>
      </Panel>
      {editing && (
        <GraphForm
          graph={graph}
          run={run}
          busy={busy}
          onClose={() => setEditing(false)}
        />
      )}
      {reviewing && (
        <ReviewForm
          resource={reviewing}
          graph={graph}
          run={run}
          busy={busy}
          onClose={() => setReviewing(null)}
        />
      )}
    </>
  );
}
