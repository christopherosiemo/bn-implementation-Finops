import { useState } from "react";
import type { components } from "./api.generated";
import { RemotePage } from "./RemoteData";
import { Badge, Button, Table, dateTime, readable, shortId } from "./ui";

type Run = components["schemas"]["FleetFixtureRun"];

export function FleetFixtureRuns({ proposalId }: { proposalId: string }) {
  const [revision, setRevision] = useState(0);
  return (
    <section className="configuration-stack" aria-label="Persisted fixture execution and recovery">
      <h4>Execution & owned recovery</h4>
      <p className="form-note">
        These records come from the private durable journal. They describe isolated
        fixture effects and outstanding restoration duties. Health acceptance and
        customer savings require their own evidence.
      </p>
      <Button secondary small onClick={() => setRevision((value) => value + 1)}>
        Refresh persisted fixture runs
      </Button>
      <RemotePage<Run>
        key={`${proposalId}:${revision}`}
        path={`/fleet-fixture-proposals/${encodeURIComponent(proposalId)}/runs?limit=10`}
        label="Persisted fixture runs"
        empty="The private runtime has not issued a journal for this proposal. Customer execution is disabled."
      >
        {(runs) => (
          <Table
            scrollLabel="Persisted fixture execution and restoration duties"
            headings={["Journal", "Current duty", "Evidence", "Financial disposition"]}
          >
            {runs.map((run) => (
              <tr key={run.id}>
                <td>
                  {shortId(run.id)}
                  <small>{dateTime(run.created_at)}</small>
                  <small className="evidence-id">{run.realm.generation}</small>
                </td>
                <td>
                  <Badge value={run.status} />
                  <small>{run.owned_effect_count} owned effects</small>
                  <small>{run.pending_phase ? readable(run.pending_phase) : "No pending command"}</small>
                  <small>{run.obligation_released ? "Native duties resolved" : "Restoration ownership retained"}</small>
                </td>
                <td>
                  Segment {run.segment} · {run.global_count} recorded events
                  <small className="evidence-id">{run.head_sha256}</small>
                  {run.reason_codes.map((reason) => <small key={reason}>{readable(reason)}</small>)}
                </td>
                <td>
                  <Badge value={run.financial_disposition} />
                  <small>Verified savings: unavailable</small>
                  {(run.forward_aborted || run.recovery_only) && (
                    <small>Forward progress is permanently aborted. This run cannot establish positive verified savings.</small>
                  )}
                </td>
              </tr>
            ))}
          </Table>
        )}
      </RemotePage>
    </section>
  );
}
