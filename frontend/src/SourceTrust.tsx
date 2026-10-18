import { useState } from "react";
import {
  Badge,
  Button,
  Empty,
  Evidence,
  Modal,
  Panel,
  Table,
  dateTime,
  readable,
  type RunMutation,
} from "./ui";
import type { Dashboard, Document } from "./types";
import type { components } from "./api.generated";

const fields = [
  ["payer_account_id", "Payer account ID"],
  ["usage_accounts", "Usage account IDs (comma separated)"],
  ["export_arn", "CUR 2.0 export ARN"],
  ["read_role_binding_id", "Approved read binding ID"],
  ["bucket", "Versioned delivery bucket"],
  ["bucket_owner", "Bucket owner account ID"],
  ["prefix", "Delivery prefix"],
] as const;

function SourceForm({
  run,
  busy,
  onClose,
}: {
  run: RunMutation;
  busy: boolean;
  onClose: () => void;
}) {
  const [values, setValues] = useState<Record<string, string>>({});
  return (
    <Modal
      title="Register trusted billing source"
      subtitle="Hourly CUR 2.0 · Ireland"
      onClose={onClose}
    >
      <form
        onSubmit={async (event) => {
          event.preventDefault();
          const body: components["schemas"]["SourceConnectionRequest"] = {
            kind: "AWS_CUR2",
            region: "eu-west-1",
            payer_account_id: values.payer_account_id,
            usage_account_ids: values.usage_accounts
              .split(",")
              .map((value) => value.trim())
              .filter(Boolean),
            export_arn: values.export_arn,
            read_role_binding_id: values.read_role_binding_id,
            bucket: values.bucket,
            bucket_owner: values.bucket_owner,
            prefix: values.prefix,
          };
          if (
            await run({
              path: "/source-connections",
              body,
              label:
                "Billing source registered; synchronize to validate its evidence",
            })
          )
            onClose();
        }}
      >
        <p className="form-note">
          Use a server-approved read binding and a delivery prefix restricted to
          AWS Data Exports. Registration grants no execution authority.
        </p>
        <div className="form-grid">
          {fields.map(([key, label]) => (
            <label className="field full-width" key={key}>
              <span>{label}</span>
              <input
                required
                autoComplete="off"
                value={values[key] || ""}
                onChange={(event) =>
                  setValues((previous) => ({
                    ...previous,
                    [key]: event.target.value,
                  }))
                }
              />
            </label>
          ))}
        </div>
        <div className="modal-actions">
          <Button secondary type="button" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" pending={busy}>
            Register source
          </Button>
        </div>
      </form>
    </Modal>
  );
}

export function SourceTrust({
  data,
  run,
  busy,
}: {
  data: Dashboard;
  run: RunMutation;
  busy: boolean;
}) {
  const [creating, setCreating] = useState(false);
  const [inspect, setInspect] = useState<Document | null>(null);
  const sources = data.source_connections || [];
  return (
    <>
      <Panel
        title="Trusted billing sources"
        action={
          <Button secondary small onClick={() => setCreating(true)}>
            Register billing source
          </Button>
        }
      >
        {sources.length ? (
          <Table
            headings={[
              "Source",
              "Coverage & status",
              "Last synchronization",
              "Actions",
            ]}
          >
            {sources.map((source) => (
              <tr key={source.id}>
                <td>
                  <strong>{source.bucket}</strong>
                  <small>
                    {source.payer_account_id} · {source.region}
                  </small>
                </td>
                <td>
                  <Badge value={source.status || "UNKNOWN"} />
                  <p>
                    {readable(source.reason_code || "SOURCE_SYNC_REQUIRED")}
                  </p>
                </td>
                <td>{dateTime(source.last_sync_at)}</td>
                <td>
                  <div className="row-actions">
                    <Button
                      small
                      secondary
                      disabled={busy || !source.enabled}
                      onClick={() =>
                        void run({
                          path: `/source-connections/${source.id}/sync`,
                          version: source.version,
                          label: "Source synchronization queued",
                        })
                      }
                    >
                      Synchronize
                    </Button>
                    <Button small secondary onClick={() => setInspect(source)}>
                      Inspect source
                    </Button>
                  </div>
                </td>
              </tr>
            ))}
          </Table>
        ) : (
          <Empty
            title="No authenticated billing source"
            text="Customer imports remain provisional. Trusted exports must pass query, policy, version and file-set checks before they can justify a stop."
          />
        )}
      </Panel>
      <Panel title="Independent workload collectors">
        {data.activity_sources?.length ? (
          <Table
            headings={[
              "Resource",
              "Collector subject",
              "Latest observation",
              "Signal state",
            ]}
          >
            {data.activity_sources.map((source) => (
              <tr key={source.id}>
                <td>{readable(source.resource_id)}</td>
                <td>{readable(source.subject)}</td>
                <td>
                  {dateTime(
                    typeof source.last_received_at === "string"
                      ? source.last_received_at
                      : undefined,
                  )}
                </td>
                <td>
                  {readable(
                    source.reason_code || "ACTIVITY_OBSERVATIONS_REQUIRED",
                  )}
                </td>
              </tr>
            ))}
          </Table>
        ) : (
          <Empty
            title="No independent collector"
            text="A machine-authenticated collector must remain reachable while EC2 is stopped. Explicit zero demand is valid; missing minutes block readiness."
          />
        )}
      </Panel>
      {(data.readiness || []).length > 0 ? (
        <Panel title="Evidence readiness details">
          <Table
            headings={[
              "Resource",
              "Pricing & coverage",
              "Invoice reconciliation",
              "Readiness",
            ]}
          >
            {(data.readiness || []).map((report) => (
              <tr key={report.id || report.resource_id}>
                <td>
                  {report.resource_id}
                  <small>
                    {report.activity_signal
                      ? `${readable(report.activity_signal.reason_code)} · ${dateTime(report.activity_signal.received_at)}`
                      : "Independent collector evidence unavailable"}
                  </small>
                </td>
                <td>
                  {report.source_proof ? (
                    <>
                      <strong>
                        {readable(report.pricing_basis?.join(", "))}
                      </strong>
                      <small>
                        {readable(report.source_proof.state)} ·{" "}
                        {report.source_proof.verified_object_count}/
                        {report.source_proof.object_count} files
                      </small>
                      <small>
                        {dateTime(report.source_proof.period_start)} –{" "}
                        {dateTime(report.source_proof.period_end)}
                      </small>
                    </>
                  ) : (
                    "Trusted source unavailable"
                  )}
                </td>
                <td>
                  {readable(report.verification_status)}
                  <small>
                    {report.commitment_scope?.complete
                      ? "Payer commitment scope complete"
                      : "Commitment scope unavailable"}
                  </small>
                </td>
                <td>
                  <Badge value={report.status} />
                  <p>{readable(report.reason_code)}</p>
                  <p>{report.blockers?.map(readable).join(" · ")}</p>
                </td>
              </tr>
            ))}
          </Table>
        </Panel>
      ) : null}
      {creating ? (
        <SourceForm run={run} busy={busy} onClose={() => setCreating(false)} />
      ) : null}
      {inspect ? (
        <Evidence record={inspect} onClose={() => setInspect(null)} />
      ) : null}
    </>
  );
}
