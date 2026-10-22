import { useEffect, useState } from "react";
import type { components } from "./api.generated";
import type { Account } from "./types";
import { api } from "./api";
import { useRemote } from "./RemoteData";
import { Badge, Button, Panel, Table, dateTime, readable, type RunMutation } from "./ui";

type S = components["schemas"];
type Report = S["AWSCommissioningReport"];
const exactMoney = (value: string | null | undefined, currency: string | null | undefined) => value != null && currency ? `${value} ${currency}` : "Unavailable";
const percent = (value: string | null | undefined) => value == null ? "Unavailable" : `${value}%`;

function CurrentnessSummary({ value }: { value: S["RecommendationCurrentnessSummary"] | undefined }) {
  if (!value) return null;
  return <section aria-label="Commissioning recommendation currentness">
    <h4>Recommendation evidence currentness</h4>
    <p>{value.evaluated_contexts} latest captured contexts evaluated · {value.complete ? "Bounded context selection complete" : "Incomplete selection"}. Family-specific evidence checks still determine usable advice and analysed spend. Older reports retain their original as-of results.</p>
    <Table scrollLabel="Commissioning recommendation status counts" headings={["Assumptions", "Count"]}>{(["CURRENT", "STALE", "BLOCKED", "EXPIRED"] as const).map(status => <tr key={status}><th scope="row">{readable(status)}</th><td>{value.assumption_context_counts[status]}</td></tr>)}</Table>
    {Object.keys(value.reason_counts).length > 0 && <ul>{Object.entries(value.reason_counts).map(([reason, count]) => <li key={reason}>{count}: {readable(reason)}</li>)}</ul>}
  </section>;
}

function ReportView({ report, path }: { report: Report; path: string }) {
  const [error, setError] = useState("");
  const [exporting, setExporting] = useState(false);
  async function download() {
    setError(""); setExporting(true);
    try {
      const sealed = await api.get<Report>(`${path}/report`);
      if (sealed.id !== report.id || sealed.content_hash !== report.content_hash) throw new Error("Report identity changed; refresh before exporting.");
      const url = URL.createObjectURL(new Blob([JSON.stringify(sealed, null, 2) + "\n"], { type: "application/json" }));
      const link = document.createElement("a");
      link.href = url; link.download = `aws-readiness-${report.id}.json`; link.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Commissioning export unavailable."); }
    finally { setExporting(false); }
  }
  return <section aria-label="AWS commissioning report" className="configuration-stack">
    <div className="row-actions"><Badge value={report.summary_state} /><Badge value={report.provider_mode} /><Button secondary small pending={exporting} onClick={() => void download()}>Export commissioning JSON</Button></div>
    <p>Immutable result as of {dateTime(report.observed_at)}. Run another preflight after changing a binding or evidence source. This report grants no execution authority.</p>
    {report.fixture ? <p className="fixture-notice">Synthetic provider-shaped evidence · no customer AWS account was contacted.</p> : null}
    <dl className="definition-list"><div><dt>Account / region</dt><dd>{report.account_id} · {report.region}</dd></div><div><dt>Approved read binding</dt><dd>{report.read_role_binding_id}</dd></div><div><dt>Execution credentials</dt><dd>{readable(report.execution_credentials.status)} · {readable(report.execution_credentials.reason_code)}</dd></div><div><dt>Report hash</dt><dd className="mono">{report.content_hash}</dd></div></dl>
    {error ? <p role="alert">{error}</p> : null}
    <CurrentnessSummary value={report.coverage.recommendation_currentness} />
    <h4>Readiness dimensions</h4>
    <Table scrollLabel="AWS commissioning readiness dimensions" headings={["Dimension", "State", "Evidence gaps and next action", "Affected spend"]}>{report.dimensions.map(item => <tr key={item.key}><th scope="row">{readable(item.key)}</th><td><Badge value={item.status} /></td><td>{item.reason_codes.length ? <ul>{item.reason_codes.map(code => <li key={code}>{readable(code)}</li>)}</ul> : <span>No reported blocker</span>}{item.remediation.map((action, index) => <p key={`${index}-${action}`}>{action}</p>)}<details><summary>Inspect dimension evidence</summary><pre className="evidence-json">{JSON.stringify(item.details, null, 2)}</pre></details></td><td>{item.affected_spend?.length ? item.affected_spend.map((entry, index) => <p key={index}>{typeof entry.amount === "string" && typeof entry.currency === "string" ? `${entry.amount} ${entry.currency}` : "Unavailable"}</p>) : "Unavailable"}</td></tr>)}</Table>
    <h4>Inventory access by category</h4>
    <p>Successful bounded probes establish access to the listed operations. They do not establish complete inventory. Denied reads remain distinct from absent resources.</p>
    <Table scrollLabel="AWS inventory read access" headings={["Category", "Access state", "Checked operations / limitations"]}>{report.inventory.map(item => <tr key={item.category}><th scope="row">{readable(item.category)}</th><td><Badge value={item.status} /><small>{readable(item.reason_code)}</small></td><td>{item.operations.map(operation => <p key={operation.name}>{operation.name} · {readable(operation.status)} · {readable(operation.reason_code)}</p>)}{item.limitations.map((limit, index) => <small key={index}>{limit}</small>)}</td></tr>)}</Table>
    <h4>Spend coverage</h4>
    <p>All AWS services and global charges in the account remain in scope. Four exclusive partitions sum to detected positive spend. Unallocated spend overlaps those partitions; credits are separate. Unknown or incomplete billing has no percentage.</p>
    {report.coverage.reason_codes.map(code => <p key={code}>{readable(code)}</p>)}
    {report.coverage.currencies.length ? report.coverage.currencies.map((row, index) => <div key={`${row.currency}-${index}`}>
      <h5>{row.currency || "Currency unavailable"} · {row.denominator_complete ? "Complete denominator" : "Incomplete denominator"}</h5>
      <Table scrollLabel={`Commissioning coverage ${row.currency || "unknown"}`} headings={["Coverage", "Amount", "Share of detected positive spend"]}>
        <tr><th scope="row">Detected spend</th><td>{exactMoney(row.detected_spend, row.currency)}</td><td>{row.denominator_complete && row.detected_spend != null && !/^0(?:\.0+)?$/.test(row.detected_spend) ? "100%" : "Unavailable"}</td></tr>
        {([["Analysed", row.analysed_spend, row.percentages.analysed], ["Observation only", row.observation_only_spend, row.percentages.observation_only], ["Blocked", row.blocked_spend, row.percentages.blocked], ["Unsupported", row.unsupported_spend, row.percentages.unsupported], ["Unallocated attribution overlay", row.unallocated_spend, row.percentages.unallocated]] as const).map(([label, amount, share]) => <tr key={label}><th scope="row">{label}</th><td>{exactMoney(amount, row.currency)}</td><td>{percent(share)}</td></tr>)}
        <tr><th scope="row">Credits (separate)</th><td>{exactMoney(row.credits, row.currency)}</td><td>Not a positive-spend partition</td></tr>
      </Table>
    </div>) : <p>Spend and coverage percentages unavailable until a scoped authoritative financial source is persisted.</p>}
    <details><summary>Identity, billing, telemetry and authority evidence</summary><pre className="evidence-json">{JSON.stringify({ identity: report.identity, billing: report.billing, telemetry: report.telemetry, ownership: report.ownership, configuration_authority: report.configuration_authority, commitments: report.commitments, coverage_scope: report.coverage_scope, evidence_refs: report.evidence_refs }, null, 2)}</pre></details>
  </section>;
}

function AccountPreflights({ account, run, busy }: { account: Account; run: RunMutation; busy: boolean }) {
  const base = `/cloud-accounts/${encodeURIComponent(account.id)}/preflights`;
  const [revision, setRevision] = useState(0), [selectedID, setSelectedID] = useState("");
  const history = useRemote<S["AWSAccountPreflightPage"]>(`${base}?limit=20`, revision);
  const selected = selectedID || history.value?.items[0]?.id;
  const detail = useRemote<S["AWSAccountPreflight"]>(selected ? `${base}/${encodeURIComponent(selected)}` : null, revision);
  const pending = detail.value?.status === "QUEUED" || detail.value?.status === "RUNNING";
  useEffect(() => { if (!pending) return; const timer = setInterval(() => setRevision(value => value + 1), 3000); return () => clearInterval(timer); }, [pending]);
  return <div className="configuration-stack">
    <div className="row-actions"><Button disabled={busy || pending} pending={busy} onClick={async () => {
      const result = await run({ path: base, body: {}, version: account.version, label: "Read-only account preflight queued" });
      if (result) { setSelectedID(result.id); setRevision(value => value + 1); }
    }}>Run read-only preflight</Button><Button secondary small disabled={history.loading || detail.loading} onClick={() => setRevision(value => value + 1)}>Refresh commissioning</Button></div>
    {history.error || detail.error ? <p role="alert">Commissioning unavailable. {history.error || detail.error}</p> : null}
    {history.loading && !history.value ? <p role="status">Loading commissioning history…</p> : null}
    {history.value?.items.length ? <label className="field"><span>Immutable preflight history</span><select value={selected || ""} onChange={event => setSelectedID(event.target.value)}>{history.value.items.map(item => <option key={item.id} value={item.id}>{dateTime(item.created_at)} · {item.status} · {item.id}</option>)}</select></label> : <p>No commissioning result yet. Run a preflight to inspect access and persisted evidence.</p>}
    {detail.value ? <><p role="status">Preflight {readable(detail.value.status)}{detail.value.reason_code ? ` · ${readable(detail.value.reason_code)}` : ""}</p>{detail.value.binding_current === false ? <p role="alert">The approved account binding changed or was revoked. This historical report cannot establish current readiness.</p> : null}{detail.value.currentness_reason_codes?.map(code => <p key={code}>{readable(code)}</p>)}{detail.value.report ? <ReportView key={detail.value.report.id} report={detail.value.report} path={`${base}/${encodeURIComponent(detail.value.id)}`} /> : <p>Evidence checks are asynchronous. A pending request establishes no readiness.</p>}</> : null}
    {history.value?.next_cursor ? <p>Older history is available through the scoped paginated preflight API.</p> : null}
  </div>;
}

export function AccountCommissioning({ accounts, run, busy }: { accounts: Account[]; run: RunMutation; busy: boolean }) {
  const [selectedID, setSelectedID] = useState("");
  const selected = accounts.find(account => account.id === selectedID) || accounts[0];
  return <Panel title="AWS read-only commissioning"><p>Prove identity, read access and evidence readiness before trusting a recommendation. Inspect each dimension; a readable account can still lack financial or workload evidence.</p>{selected ? <>
    <label className="field"><span>Commissioning account</span><select value={selected.id} onChange={event => setSelectedID(event.target.value)}>{accounts.map(account => <option key={account.id} value={account.id}>{account.name} · {account.account_id} · {account.region}</option>)}</select></label>
    <AccountPreflights key={selected.id} account={selected} run={run} busy={busy} />
  </> : <p>Register an AWS account with an approved read binding to begin.</p>}</Panel>;
}
