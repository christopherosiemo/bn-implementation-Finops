import { useState } from "react";
import type { components } from "./api.generated";
import { RemotePage, useRemote } from "./RemoteData";
import { Badge, Button, Modal, Panel, Table, dateTime, readable, shortId, type RunMutation } from "./ui";

type Schemas = components["schemas"];
type Source = Schemas["CommitmentPortfolioSource"];
type Receipt = Schemas["CommitmentPortfolioReceipt"];
type Analysis = Schemas["CommitmentPortfolioAnalysis"];
type Position = Schemas["CommitmentPortfolioPositionAnalysis"];
type Partition = Schemas["CommitmentPortfolioPartition"];
type Ref = Schemas["CommitmentPortfolioRef"];
type Props = { fixture: boolean; run: RunMutation; busy: boolean };
const query = encodeURIComponent;
const exactMoney = (value: string | null, currency: string | null) =>
  value !== null && currency !== null ? value + " " + currency : "Unavailable";
const exactRatio = (value: string | null) => value === null ? "Unavailable" : value + " (fraction)";

function References({ refs }: { refs: Ref[] }) {
  return refs.length ? <ul className="evidence-refs">{refs.map((ref) => <li key={ref.kind + ":" + ref.id}>
    <span className="evidence-id">{readable(ref.kind)} · {ref.id}<small>SHA256 {ref.sha256}</small></span>
  </li>)}</ul> : <p>Issued references unavailable.</p>;
}

function ReceiptChoices({ sourceID, kind, selected, onChange, busy }: {
  sourceID: string; kind: "AWS_COMMITMENT" | "AWS_CUR2"; selected: string[];
  onChange: (ids: string[]) => void; busy: boolean;
}) {
  const native = kind === "AWS_COMMITMENT";
  const label = native ? "Native commitment receipts" : "Canonical billing receipts";
  return <fieldset className="configuration-stack" disabled={busy}>
    <legend>{native ? "Native commitment point" : "Observed billing windows"}</legend>
    <RemotePage<Receipt> key={sourceID + ":" + kind}
      path={"/commitment-portfolio-sources/" + query(sourceID) + "/receipts?kind=" + kind + "&limit=10"}
      label={label} empty={native ? "No issued commitment point is available for this source." : "No issued billing window is available. Analysis will retain billing metrics as unavailable."}>
      {(items) => items.map((row) => {
        const matches = row.source_id === sourceID && row.kind === kind && row.current;
        return <label className="choice-card" key={row.id}>
          <input type={native ? "radio" : "checkbox"} name={native ? "commitment-receipt" : undefined}
            checked={selected.includes(row.id)}
            disabled={!matches || (!native && selected.length >= 24 && !selected.includes(row.id))}
            onChange={(event) => onChange(native ? [row.id] : event.target.checked ? [...selected, row.id] : selected.filter(id => id !== row.id))} />
          <span><span className="evidence-id">{row.id}</span>
            <small>{dateTime(row.observed_at)} · {readable(row.proof_state)} · {matches ? "Current issued receipt" : "Historical or different source"}</small>
            <small>{row.period ? dateTime(row.period.start) + " — " + dateTime(row.period.end) + " · UTC, end exclusive" : "Historical interval coverage unavailable"}</small>
          </span>
        </label>;
      })}
    </RemotePage>
    {!native && <p className="form-note">{selected.length} of at most 24 billing receipt IDs selected. Empty billing selection does not mean zero cost.</p>}
  </fieldset>;
}

function RequestForm({ run, busy, onClose, onSaved }: Props & { onClose: () => void; onSaved: (id: string) => void }) {
  const [source, setSource] = useState<Source | null>(null);
  const [commitment, setCommitment] = useState<string[]>([]);
  const [billing, setBilling] = useState<string[]>([]);
  const [start, setStart] = useState("");
  const [end, setEnd] = useState("");
  const [revision, setRevision] = useState(0);
  const [error, setError] = useState("");
  return <Modal title="Analyze commitment portfolio" subtitle="Read-only · issued native evidence" onClose={onClose}>
    <p className="form-note">Select an authenticated source, one issued commitment point and optional issued CUR windows. The server rechecks their scope and exact stored evidence. No observations, prices, credentials or optimization approvals are uploaded.</p>
    <form className="configuration-stack" onSubmit={async (event) => {
      event.preventDefault();
      setError("");
      if (!source || commitment.length !== 1) return;
      const first = Date.parse(start + "T00:00:00Z"), last = Date.parse(end + "T00:00:00Z");
      if (!Number.isFinite(first) || !Number.isFinite(last) || new Date(first).toISOString().slice(0, 10) !== start || new Date(last).toISOString().slice(0, 10) !== end || last <= first || last - first > 31 * 86400000) {
        setError("Select between one and 31 complete UTC days; the end date is excluded.");
        return;
      }
      const body: Schemas["CommitmentPortfolioRequest"] = {
        source_id: source.id, commitment_receipt_id: commitment[0], billing_receipt_ids: billing,
        period: { start: start + "T00:00:00Z", end: end + "T00:00:00Z" },
      };
      const saved = await run({ path: "/commitment-portfolio-analyses", body, version: 0, label: "Read-only commitment analysis queued." });
      if (saved) onSaved(saved.id);
      else setError("Request could not be confirmed. Review the API error and analysis history before retrying the same selection.");
    }}>
      <fieldset className="configuration-stack" disabled={busy}>
        <legend>Authenticated billing source</legend>
        <RemotePage<Source> key={revision} path="/commitment-portfolio-sources?limit=10" label="Commitment portfolio sources" empty="Register and ingest an authenticated native billing source before requesting this analysis.">
          {(items) => items.map((row) => <label className="choice-card" key={row.id}>
            <input type="radio" name="portfolio-source" checked={source?.id === row.id} onChange={() => { setSource(row); setCommitment([]); setBilling([]); }} />
            <span><span className="evidence-id">{row.id}</span><small>{row.payer_account_id} · {row.region} · revision {row.version} · {readable(row.status)}</small><small>{row.usage_account_count} scoped usage accounts</small></span>
          </label>)}
        </RemotePage>
      </fieldset>
      <Button type="button" secondary small disabled={busy} onClick={() => { setSource(null); setCommitment([]); setBilling([]); setRevision(value => value + 1); }}>Refresh portfolio source choices</Button>
      {source && <>
        <ReceiptChoices key={source.id + ":commitment"} sourceID={source.id} kind="AWS_COMMITMENT" selected={commitment} onChange={setCommitment} busy={busy} />
        <ReceiptChoices key={source.id + ":billing"} sourceID={source.id} kind="AWS_CUR2" selected={billing} onChange={setBilling} busy={busy} />
      </>}
      <fieldset className="form-grid" disabled={busy}>
        <legend>Observed analysis interval · UTC</legend>
        <label className="field"><span>Portfolio interval start</span><input type="date" required value={start} onChange={event => setStart(event.target.value)} /></label>
        <label className="field"><span>Portfolio interval end (exclusive)</span><input type="date" required value={end} onChange={event => setEnd(event.target.value)} /></label>
      </fieldset>
      <p className="form-note">Requested dates do not assert complete billing or utilization coverage. A point-in-time inventory cannot establish historical interval ownership.</p>
      {error && <p role="alert" className="blocker-text">{error}</p>}
      <Button type="submit" pending={busy} disabled={!source || commitment.length !== 1}>Request commitment analysis</Button>
    </form>
  </Modal>;
}

function UnmatchedBillingEvidence({ rows }: { rows: Schemas["CommitmentPortfolioUnmatchedBilling"][] }) {
  const [visible, setVisible] = useState(25);
  return <section className="configuration-stack" aria-label="Unmatched commitment billing">
    <h4>Billing commitments absent from the selected native point</h4>
    <p className="form-note">These issued billing rows may describe retired or otherwise unobserved commitments. They retain observed billed cost by account and currency. Native terms, utilization, expiry and future exposure remain unavailable; no position is invented.</p>
    {rows.length ? <Table scrollLabel="Unmatched observed commitment costs" headings={["Commitment / account", "Currency", "Observed billed cost", "Contributing rows"]}>
      {rows.slice(0, visible).map(row => <tr key={row.account_id + ":" + row.currency + ":" + row.commitment_id}>
        <td className="evidence-id">{row.commitment_id}<small>{row.account_id}</small></td><td>{row.currency}</td>
        <td>{exactMoney(row.observed_billed_cost, row.currency)}</td><td><BillingLineReferences ids={row.line_ids} /></td>
      </tr>)}
    </Table> : <p>No unmatched commitment-linked rows are present in this selected evidence. This does not establish payer-wide billing coverage.</p>}
    {rows.length > visible && <Button type="button" secondary small onClick={() => setVisible(value => value + 25)}>Show more unmatched billing commitments</Button>}
  </section>;
}

function BillingLineReferences({ ids }: { ids: string[] }) {
  const [open, setOpen] = useState(false);
  const [visible, setVisible] = useState(25);
  return <details onToggle={event => setOpen(event.currentTarget.open)}>
    <summary>View issued billing line IDs ({ids.length})</summary>
    {open && <>
      <ul className="evidence-refs">{ids.slice(0, visible).map(id => <li key={id} className="evidence-id">{id}</li>)}</ul>
      {ids.length > visible && <Button type="button" secondary small onClick={() => setVisible(value => value + 25)}>Show more billing line IDs</Button>}
    </>}
  </details>;
}

function PartitionEvidence({ value }: { value: Partition }) {
  const [open, setOpen] = useState(false);
  const key = [value.account_id, value.class, value.currency ?? "currency unavailable", value.region ?? "region unavailable", value.instance_family ?? "family unavailable"].join(" · ");
  return <details onToggle={event => setOpen(event.currentTarget.open)}>
    <summary>Partition observations · {readable(key)}</summary>
    {open && <div className="configuration-stack">
      <p>{value.position_count} observed positions. Metrics cover only this account, class, currency, region and family partition.</p>
      <Table scrollLabel={"Commitment partition metrics " + key} headings={["Metric", "Observed value"]}>
        {([
          ["Billed cost", value.observed_billed_cost], ["Committed cost", value.observed_committed_cost],
          ["Used commitment", value.observed_used_commitment], ["Unused commitment", value.observed_unused_commitment],
        ] as [string, string | null][]).map(([label, amount]) => <tr key={label}><td>{label}</td><td>{exactMoney(amount, value.currency)}</td></tr>)}
        <tr><td>Utilization</td><td>{exactRatio(value.utilization)}</td></tr>
        <tr><td>Native hourly commitment rate</td><td>{value.hourly_commitment_rate !== null && value.currency !== null ? exactMoney(value.hourly_commitment_rate, value.currency) + "/hour" : "Unavailable"}</td></tr>
      </Table>
      <p className="form-note">Unused commitment is observed spend exposure in the selected billing window. It is not avoidable cost or a savings forecast. Native hourly rate shares describe concentration within this partition; they do not establish future usage.</p>
      <Table scrollLabel={"Native commitment concentration " + key} headings={["Position", "Share of native hourly commitment rate"]}>
        {value.position_shares.map(share => <tr key={share.position_id}><td className="evidence-id">{share.position_id}</td><td>{exactRatio(share.share)}</td></tr>)}
      </Table>
      {!value.position_shares.length && <p>Native commitment concentration unavailable.</p>}
      <p>Positions expiring within 30 days of the issued observation:</p>
      {value.expiring_position_ids.length ? <ul>{value.expiring_position_ids.map(id => <li className="evidence-id" key={id}>{id}</li>)}</ul> : <p>No known expiry in this window; inspect unavailable expiry terms separately.</p>}
    </div>}
  </details>;
}

function PositionEvidence({ value }: { value: Position }) {
  const [open, setOpen] = useState(false);
  const position = value.position;
  const riTerms = position.reserved_instance_terms;
  const amountRows: [string, string | null][] = [
    ["Observed billed cost", value.observed_billed_cost],
    ["Observed allocated cost", value.observed_allocated_cost],
    ["Observed committed cost", value.observed_committed_cost],
    ["Observed used commitment", value.observed_used_commitment],
    ["Observed unused commitment", value.observed_unused_commitment],
    ["Zero-usage downside in the observed window", value.downside_if_zero_usage_observed_window],
    ["Remaining value", value.remaining_value], ["New cash requirement", value.cash_requirement],
  ];
  return <details onToggle={event => setOpen(event.currentTarget.open)}>
    <summary className="evidence-id">{position.id} · {readable(position.class)} · {readable(value.status)}</summary>
    {open && <div className="configuration-stack">
      <p>Account {position.account_id} · {position.region ?? "Region unavailable"} · {position.instance_family ?? "Instance family unavailable"} · {readable(position.state)}</p>
      <p className="form-note">These are observations from the selected evidence window, not a purchase recommendation or forecast. Missing RI terms and monetary values remain unavailable.</p>
      <Table scrollLabel={"Commitment expiry " + position.id} headings={["Expiry observation", "Value"]}>
        <tr><td>State at observation</td><td>{readable(value.expiry.status)}</td></tr>
        <tr><td>Remaining duration (seconds)</td><td>{value.expiry.remaining_seconds ?? "Unavailable"}</td></tr>
        <tr><td>Expires within 30 days</td><td>{value.expiry.expires_within_window === null ? "Unavailable" : value.expiry.expires_within_window ? "Yes" : "No"}</td></tr>
      </Table>
      <Table scrollLabel={"Observed commitment metrics " + position.id} headings={["Metric", "Observed value"]}>
        {amountRows.map(([label, value]) => <tr key={label}><td>{label}</td><td>{exactMoney(value, position.currency)}</td></tr>)}
        {([
          ["Utilization", value.utilization], ["Coverage", value.coverage], ["Effective discount", value.effective_discount],
          ["Break-even utilization", value.break_even_utilization], ["Expected utilization", value.expected_utilization],
        ] as [string, string | null][]).map(([label, value]) => <tr key={label}><td>{label}</td><td>{exactRatio(value)}</td></tr>)}
        <tr><td>Confidence interval</td><td>{value.confidence_interval ?? "Unavailable"}</td></tr>
        <tr><td>Allocated cost basis</td><td>{value.allocated_cost_basis === null ? "Unavailable" : readable(value.allocated_cost_basis)}</td></tr>
        <tr><td>Commitment cost basis</td><td>{readable(value.commitment_cost_basis)}</td></tr>
      </Table>
      <details><summary>Observed native terms</summary>
        <Table scrollLabel={"Native commitment terms " + position.id} headings={["Term", "Native value"]}>
          <tr><td>Start</td><td>{position.start === null ? "Unavailable" : dateTime(position.start)}</td></tr>
          <tr><td>End</td><td>{position.end === null ? "Unavailable" : dateTime(position.end)}</td></tr>
          <tr><td>Term duration (seconds)</td><td>{position.term_seconds ?? "Unavailable"}</td></tr>
          <tr><td>Hourly commitment</td><td>{position.hourly_commitment !== null && position.currency !== null ? exactMoney(position.hourly_commitment, position.currency) + "/hour" : "Unavailable"}</td></tr>
          <tr><td>Observed upfront payment</td><td>{exactMoney(position.upfront_amount, position.currency)}<small>Historical paid amount; not a new cash requirement</small></td></tr>
          <tr><td>Recurring amount</td><td>{exactMoney(position.recurring_amount, position.currency)}<small>{readable(position.recurring_amount_unit)}</small></td></tr>
          <tr><td>Payment option</td><td>{position.payment_option === null ? "Unavailable" : readable(position.payment_option)}</td></tr>
        </Table>
        {riTerms !== null && <>
          <h5>Issued Reserved Instance terms</h5>
          <p className="form-note">Native offering terms are separate from observed usage allocation. A fixed or usage price does not establish a new cash requirement, utilization or a Savings Plan commitment rate.</p>
          <Table scrollLabel={"Native Reserved Instance terms " + position.id} headings={["Native term", "Observed value"]}>
            {([
              ["Offering class", riTerms.offering_class], ["Offering type", riTerms.offering_type],
              ["Scope", riTerms.scope], ["Instance count", riTerms.instance_count],
              ["Instance type", riTerms.instance_type], ["Tenancy", riTerms.instance_tenancy],
              ["Product description", riTerms.product_description], ["Availability Zone", riTerms.availability_zone],
              ["Availability Zone ID", riTerms.availability_zone_id],
            ] as [string, string | null][]).map(([label, term]) => <tr key={label}><td>{label}</td><td>{term ?? "Unavailable"}</td></tr>)}
            <tr><td>Native fixed price</td><td>{exactMoney(riTerms.fixed_price, riTerms.currency_code)}</td></tr>
            <tr><td>Native usage price</td><td>{exactMoney(riTerms.usage_price, riTerms.currency_code)}</td></tr>
          </Table>
          {riTerms.recurring_charges === null ? <p>Native recurring-charge collection unavailable.</p> :
            riTerms.recurring_charges.length ? <Table scrollLabel={"Native RI recurring charges " + position.id} headings={["Amount", "Native frequency"]}>
              {riTerms.recurring_charges.map((charge, index) => <tr key={index}><td>{exactMoney(charge.amount, riTerms.currency_code)}</td><td>{charge.frequency ?? "Unavailable"}</td></tr>)}
            </Table> : <p>No recurring charges were reported in the issued native collection.</p>}
        </>}
        <References refs={[position.native_ref]} />
      </details>
      <ul>{[...new Set([...position.reason_codes, ...value.reason_codes])].map(reason => <li key={reason}>{readable(reason)}</li>)}</ul>
    </div>}
  </details>;
}

export function CommitmentPortfolioEvidence({ analysis }: { analysis: Analysis }) {
  const [search, setSearch] = useState("");
  const [visible, setVisible] = useState(25);
  const [partitionCount, setPartitionCount] = useState(25);
  const matching = analysis.positions.filter(({ position }) =>
    [position.id, position.account_id, position.class, position.currency ?? ""].some(value => value.toLowerCase().includes(search.toLowerCase())));
  return <div className="configuration-stack">
    <div className="row-actions"><Badge value={analysis.recommendation_status} /><span>Inventory: {readable(analysis.inventory_status)}</span><span>Billing: {readable(analysis.billing_status)}</span></div>
    <p className="form-note">Observed {dateTime(analysis.observed_at)}. Point-in-time commitment inventory and billing-window coverage are separate. Refreshing this immutable record does not renew its evidence.</p>
    <p className="evidence-id">Analysis {analysis.id}<small>Request {analysis.request_id}</small></p>
    <section className="configuration-stack" aria-label="Commitment account and currency partitions">
      <h4>Account, class and currency partitions</h4>
      <p className="form-note">Amounts are never summed across currencies, commitment classes or accounts. A complete inventory point does not establish complete utilization.</p>
      {analysis.partitions.length ? <Table scrollLabel="Observed commitment partitions" headings={["Account / native class", "Region / family", "Currency", "Positions", "Observed billed / unused commitment", "Utilization"]}>
        {analysis.partitions.slice(0, partitionCount).map((partition, index) => <tr key={index}>
          <td>{partition.account_id}<small>{readable(partition.class)}</small></td>
          <td>{partition.region ?? "Unavailable"}<small>{partition.instance_family ?? "Unavailable"}</small></td>
          <td>{partition.currency ?? "Unavailable"}</td><td>{partition.position_count}</td><td>{exactMoney(partition.observed_billed_cost, partition.currency)}<small>Unused: {exactMoney(partition.observed_unused_commitment, partition.currency)}</small></td><td>{exactRatio(partition.utilization)}</td>
        </tr>)}
      </Table> : <p>Partition observations unavailable.</p>}
      {analysis.partitions.slice(0, partitionCount).map((partition, index) => <PartitionEvidence key={index} value={partition} />)}
      {analysis.partitions.length > partitionCount && <Button type="button" secondary small onClick={() => setPartitionCount(value => value + 25)}>Show more observed partitions</Button>}
    </section>
    <section className="configuration-stack" aria-label="Observed commitment positions">
      <h4>Observed positions</h4>
      <p>{analysis.inventory_status === "UNAVAILABLE" ? "Position population unavailable. An empty result does not establish that there are no commitments." :
        analysis.positions.length === 0 && analysis.inventory_status === "PARTIAL" ? "No usable positions were observed; the complete population remains unknown." :
        analysis.positions.length + " positions observed in this issued record."} Sparse Reserved Instance terms remain unclassified rather than borrowing Savings Plan terms.</p>
      <label className="field"><span>Find observed commitment</span><input value={search} onChange={event => { setSearch(event.target.value); setVisible(25); }} placeholder="Position ID, account, class or currency" /></label>
      <p className="form-note">{matching.length} matching positions. Evidence details load into the view only when opened.</p>
      {matching.slice(0, visible).map(position => <PositionEvidence key={position.position.account_id + ":" + position.position.id} value={position} />)}
      {!matching.length && <p>No matching position is present in this issued record.</p>}
      {matching.length > visible && <Button type="button" secondary small onClick={() => setVisible(value => value + 25)}>Show more observed positions</Button>}
    </section>
    <UnmatchedBillingEvidence rows={analysis.unmatched_billing} />
    <section className="configuration-stack" aria-label="Commitment optimization prerequisites">
      <h4>Optimization order and missing prerequisites</h4>
      <p className="form-note">Remove idle use, schedule, rightsize, autoscale, then recalculate stable demand. A named stage is not evidence that the action occurred; exact decision and outcome references are required.</p>
      <ol>{analysis.optimization_order.map(stage => <li key={stage.stage}>
        <strong>{readable(stage.stage)} · {readable(stage.status)}</strong>
        <p>{stage.reason_codes.map(readable).join(", ") || "Supporting proof unavailable"}</p>
        <p>Scope {stage.scope_sha256 ?? "Unavailable"}</p>
        <References refs={[stage.decision_ref, stage.outcome_ref].filter((value): value is Ref => value !== null)} />
      </li>)}</ol>
    </section>
    <Table scrollLabel="Commitment financial claims" headings={["Claim", "Value"]}>
      <tr><td>Expected savings</td><td>Unavailable</td></tr><tr><td>Estimated savings</td><td>Unavailable</td></tr><tr><td>Verified savings</td><td>Unavailable</td></tr>
    </Table>
    <p className="blocker-text">Recommendation, purchase and execution disabled. No commitment change or savings claim is authorized.</p>
    <ul>{analysis.reason_codes.map(reason => <li key={reason}>{readable(reason)}</li>)}</ul>
    <details><summary>Exact issued input references</summary><References refs={analysis.input_refs} /></details>
  </div>;
}

function AnalysisDetail({ id }: { id: string }) {
  const [revision, setRevision] = useState(0);
  const result = useRemote<Schemas["CommitmentPortfolioRecord"]>("/commitment-portfolio-analyses/" + query(id), revision);
  return <section className="configuration-stack" aria-label="Selected commitment portfolio analysis">
    {result.loading && <p role="status">Loading commitment analysis…</p>}
    {result.error && <p role="alert">Commitment analysis unavailable. {result.error}</p>}
    {result.value && <>
      <h4>Commitment analysis {shortId(result.value.id)}</h4>
      <p>{dateTime(result.value.selection.period.start)} — {dateTime(result.value.selection.period.end)} · UTC, end exclusive</p>
      {result.value.analysis ? <CommitmentPortfolioEvidence key={result.value.analysis.id} analysis={result.value.analysis} /> :
        result.value.status === "REFUSED" ? <div role="alert" className="blocker-text">
          <p>Analysis refused. No portfolio result or authority was created.</p>
          <p>{result.value.refusal ? readable(result.value.refusal.reason_code) + " · " + dateTime(result.value.refusal.observed_at) : "Refusal details unavailable"}</p>
          <p>Review current source and issued receipts before making another request.</p>
        </div> : <p role="status">Queued for the read-only analysis worker. No portfolio result is available yet.</p>}
    </>}
    <Button type="button" secondary small disabled={result.loading} onClick={() => setRevision(value => value + 1)}>Refresh selected commitment analysis</Button>
  </section>;
}

function PortfolioContent(props: Props) {
  const [form, setForm] = useState(false);
  const [revision, setRevision] = useState(0);
  const [selected, setSelected] = useState("");
  return <div className="configuration-stack">
    <div className="row-actions">
      <Button type="button" secondary small disabled={props.busy} onClick={() => setForm(true)}>Analyze commitment portfolio</Button>
      <Button type="button" secondary small onClick={() => setRevision(value => value + 1)}>Refresh commitment analyses</Button>
    </div>
    <RemotePage<Schemas["CommitmentPortfolioPageRow"]> key={revision} path="/commitment-portfolio-analyses?limit=10" label="Commitment portfolio analyses" empty="Select native issued commitment and billing receipts to request read-only analysis.">
      {(items) => <Table scrollLabel="Commitment portfolio analysis history" headings={["Request / interval", "Observed coverage", "Evidence"]}>
        {items.map(row => <tr key={row.id}>
          <td className="evidence-id">{shortId(row.id)}<small>{dateTime(row.created_at)}</small><small>{dateTime(row.selection.period.start)} — {dateTime(row.selection.period.end)}</small></td>
          <td><Badge value={row.status} /><small>Inventory: {row.analysis_summary ? readable(row.analysis_summary.inventory_status) : "Unavailable"}</small><small>Billing: {row.analysis_summary ? readable(row.analysis_summary.billing_status) : "Unavailable"}</small><small>{row.analysis_summary && row.analysis_summary.inventory_status !== "UNAVAILABLE" && (row.analysis_summary.position_count !== 0 || row.analysis_summary.inventory_status === "COMPLETE_POINT_IN_TIME") ? row.analysis_summary.position_count + " observed positions" : "Position count unavailable"}</small><small>Purchase disabled</small></td>
          <td><Button type="button" secondary small onClick={() => setSelected(row.id)}>Inspect commitment analysis {shortId(row.id)}</Button></td>
        </tr>)}
      </Table>}
    </RemotePage>
    {selected && <AnalysisDetail key={selected} id={selected} />}
    {form && <RequestForm {...props} onClose={() => setForm(false)} onSaved={id => { setForm(false); setSelected(id); setRevision(value => value + 1); }} />}
  </div>;
}

export function CommitmentPortfolio(props: Props) {
  const [open, setOpen] = useState(false);
  return <Panel title="AWS commitment portfolio" eyebrow="OBSERVED TERMS · READ-ONLY ANALYSIS">
    {props.fixture && <p className="form-note">Local fixture evidence. Provider transports and historical billing are simulated.</p>}
    <p className="form-note">Inspect issued native commitments and billing metrics by account, class and currency. Unavailable observations remain unknown; this view cannot recommend or purchase commitments.</p>
    <details onToggle={event => setOpen(event.currentTarget.open)}>
      <summary>Commitment portfolio evidence</summary>
      {open && <PortfolioContent {...props} />}
    </details>
  </Panel>;
}
