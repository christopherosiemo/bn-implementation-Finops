import { useState } from "react";
import type { components } from "./api.generated";
import type { FleetHistoryRegistration } from "./types";
import { RemotePage } from "./RemoteData";
import { Badge, Button, Table, dateTime, readable, shortId } from "./ui";

type Proposal = components["schemas"]["FleetConfigurationProposal"];
const query = encodeURIComponent;

export function GroupChoice({
  workload,
  side,
  selected,
  onSelect,
}: {
  workload: string;
  side: "Original" | "Candidate";
  selected: Proposal | null;
  onSelect: (proposal: Proposal | null) => void;
}) {
  const [registration, setRegistration] =
    useState<FleetHistoryRegistration | null>(null);
  return (
    <fieldset className="configuration-stack">
      <legend>{side} group for assessment</legend>
      <RemotePage<FleetHistoryRegistration>
        path={`/fleet-history-registrations?workload_id=${query(workload)}&limit=10`}
        label={`${side} assessment groups`}
        empty="Register the fleet and capture a configuration proposal before comparing it."
      >
        {(items) => (
          <Table
            scrollLabel={`${side} assessment group choices`}
            headings={["Fleet", "Account / region", "Selection"]}
          >
            {items.map((item) => (
              <tr key={item.id}>
                <td>
                  {item.registration.fleet_id}
                  <small className="evidence-id">
                    {item.registration.asg_arn}
                  </small>
                </td>
                <td>
                  {item.registration.binding.account_id}
                  <small>{item.registration.binding.region}</small>
                </td>
                <td>
                  <Button
                    type="button"
                    secondary
                    small
                    aria-pressed={registration?.id === item.id}
                    onClick={() => {
                      setRegistration(item);
                      onSelect(null);
                    }}
                  >
                    Assess {side.toLowerCase()} group{" "}
                    {item.registration.fleet_id}
                  </Button>
                </td>
              </tr>
            ))}
          </Table>
        )}
      </RemotePage>
      {registration && (
        <RemotePage<Proposal>
          key={`${side}:${registration.id}:${registration.version}`}
          path={`/fleet-history-registrations/${query(registration.id)}/configuration-proposals?limit=10`}
          label={`${side} assessment proposals`}
          empty="A captured configuration proposal is required for this fleet."
        >
          {(items) => (
            <Table
              scrollLabel={`${side} assessment proposal choices`}
              headings={["Captured proposal", "Evidence status", "Selection"]}
            >
              {items.map((item) => (
                <tr key={item.id}>
                  <td className="evidence-id">
                    {shortId(item.id)}
                    <small>{dateTime(item.as_of)}</small>
                  </td>
                  <td>
                    <Badge value={item.status} />
                    <small>{readable(item.membership_status)}</small>
                  </td>
                  <td>
                    <Button
                      type="button"
                      secondary
                      small
                      aria-pressed={selected?.id === item.id}
                      onClick={() => onSelect(item)}
                    >
                      Compare {side.toLowerCase()} proposal {shortId(item.id)}
                    </Button>
                  </td>
                </tr>
              ))}
            </Table>
          )}
        </RemotePage>
      )}
    </fieldset>
  );
}
