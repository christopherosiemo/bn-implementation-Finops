import type { components } from "./api.generated";
import { RemotePage } from "./RemoteData";
import { Badge, Table, dateTime, readable, shortId } from "./ui";
import "./NativeCapacityResults.css";

type Result = components["schemas"]["NativeCapacityResult"];
type Model = components["schemas"]["CapacityModelResult"];
const decimal = (value: string | null | undefined) =>
  value == null ? "Unavailable" : value.replace(/(\.\d*?[1-9])0+$|\.0+$/, "$1");
const percent = (value: number | null | undefined) =>
  value == null ? "Unavailable" : `${(value / 10_000).toLocaleString()}%`;

type ProxyMetadata = {
  semantic_role?: string;
  source_metric?: string;
  source_unit?: string;
  unit?: string;
};
function proxyLabel(model: Model, name: string, metric: ProxyMetadata) {
  if (name !== "demand") return readable(name);
  if (model.model_version === "capacity-weekday-block-v1")
    return "Legacy demand · unproven proxy";
  return model.model_version === "capacity-weekday-block-v2" &&
    metric.semantic_role === "REQUEST_THROUGHPUT_PROXY" &&
    metric.source_metric === "request_count" &&
    (metric.source_unit === "count" || metric.source_unit === "requests") &&
    metric.unit === `${metric.source_unit}/second`
    ? "Request throughput proxy"
    : "Demand semantics unavailable";
}

function ModelEvidence({ model }: { model: Model }) {
  return (
    <>
      <h4>Observed capacity & request proxy</h4>
      <p className="form-note">
        Quantiles describe measured samples or actual counter-interval rates. A
        source maximum is never relabelled as a percentile. Missing observations
        remain unknown.
      </p>
      <p className="form-note">
        Request throughput is a proxy. Requests do not prove completed business
        work or work preservation. Legacy generic work units retain their
        original recorded units; their semantics are unproven.
      </p>
      <p className="evidence-id">Model semantics: {model.model_version}</p>
      <Table
        scrollLabel="Observed native capacity and request proxy"
        headings={[
          "Metric / units",
          "Coverage / missing",
          "Observed p95",
          "Observed p99",
          "Physical denominator",
        ]}
      >
        {model.metrics.map((metric) => (
          <tr key={metric.name}>
            <td>
              {proxyLabel(model, metric.name, metric)}
              <small>
                {metric.unit} · {readable(metric.statistic)}
              </small>
              {metric.name === "demand" &&
              proxyLabel(model, metric.name, metric) ===
                "Request throughput proxy" ? (
                <small>
                  {metric.semantic_role} · source {metric.source_metric} (
                  {metric.source_unit})
                </small>
              ) : null}
            </td>
            <td>
              {percent(metric.coverage_ppm)}
              <small>
                {metric.observed_intervals} / {metric.expected_intervals}{" "}
                intervals · {metric.missing_intervals} missing
              </small>
              <small>{decimal(metric.unknown_seconds)} unknown seconds</small>
            </td>
            <td>
              {decimal(metric.observed_quantiles.p95.upper)}
              <small>{readable(metric.quantile_method)}</small>
            </td>
            <td>{decimal(metric.observed_quantiles.p99.upper)}</td>
            <td>
              {decimal(metric.denominator?.value)}
              <small>
                {metric.denominator?.unit ?? "No physical denominator applies"}
              </small>
            </td>
          </tr>
        ))}
      </Table>
      <h4>Forecast evidence</h4>
      <p className="form-note">
        Weekday/hour medians and rolling-origin residual blocks support these
        projections. A calibrated backtest is not a calibrated future breach
        probability. Future probability remains unavailable, including when no
        historical breaches occurred.
      </p>
      <Table
        scrollLabel="Capacity forecast horizons and calibration"
        headings={[
          "Horizon / metric",
          "Projection p99 / peak",
          "Prediction interval",
          "Backtest evidence",
        ]}
      >
        {model.forecasts.flatMap((forecast) =>
          Object.entries(forecast.metrics).map(([name, metric]) => (
            <tr key={`${forecast.horizon}-${name}`}>
              <td>
                {readable(forecast.horizon)} · {proxyLabel(model, name, metric)}
                <small>{readable(metric.status)}</small>
                {name === "demand" ? (
                  <small>
                    {metric.unit ??
                      model.metrics.find((item) => item.name === name)?.unit ??
                      "Units unavailable"}
                  </small>
                ) : null}
              </td>
              <td>
                {decimal(metric.point_p99)} / {decimal(metric.point_peak)}
                <small>
                  Demand event multiplier{" "}
                  {decimal(metric.event_multiplier_peak)}
                </small>
              </td>
              <td>
                {metric.prediction_interval
                  ? `${decimal(metric.prediction_interval.lower)} – ${decimal(metric.prediction_interval.upper)}`
                  : "Unavailable"}
                <small>
                  {metric.prediction_interval
                    ? `${percent(metric.prediction_interval.nominal_coverage_ppm)} nominal coverage`
                    : "Insufficient calibration evidence"}
                </small>
              </td>
              <td>
                {metric.backtest.nonoverlapping_block_count} independent{" "}
                {metric.backtest.block_days}-day blocks
                <small>
                  {metric.reason_codes.map(readable).join(" · ") ||
                    readable(metric.backtest.method)}
                </small>
              </td>
            </tr>
          )),
        )}
      </Table>
      {model.candidates.map((candidate) => (
        <details key={candidate.id} className="native-evaluation">
          <summary>
            {candidate.id} × {candidate.count} · {readable(candidate.status)}
          </summary>
          <p className="form-note">
            Individual passing physical checks do not establish complete
            suitability. Price, commitment compatibility and execution safety
            remain independent gates.
          </p>
          <ul className="evidence-refs">
            {candidate.reason_codes.map((reason) => (
              <li key={reason}>{readable(reason)}</li>
            ))}
          </ul>
          <Table
            scrollLabel={`Physical planning checks for ${candidate.id}`}
            headings={[
              "Dimension / capacity",
              "Required with reserve",
              "p95 planning",
              "p99 rollback",
              "Result",
            ]}
          >
            {candidate.checks.map((check) => (
              <tr key={check.dimension}>
                <td>
                  {readable(check.dimension)}
                  <small>
                    {decimal(check.candidate_capacity)} {check.unit}
                  </small>
                </td>
                <td>
                  {decimal(check.required_with_reserve)}
                  <small>
                    {percent(check.reserve_above_forecast_ppm)} reserve above
                    forecast · {percent(check.unused_capacity_ppm)}{" "}
                    unused-capacity fraction
                  </small>
                </td>
                <td>
                  {percent(check.observed_p95_utilization_ppm)}
                  <small>Limit {percent(check.p95_planning_limit_ppm)}</small>
                </td>
                <td>
                  {percent(check.projected_p99_utilization_ppm)}
                  <small>Limit {percent(check.p99_rollback_limit_ppm)}</small>
                </td>
                <td>
                  <Badge value={check.status} />
                  <small>
                    Observed breach frequency{" "}
                    {percent(check.observed_capacity_breach_ppm)}
                  </small>
                </td>
              </tr>
            ))}
          </Table>
          <p className="blocker-text">
            Contracted candidate cost and savings: unavailable. Future breach
            probability: unavailable ({readable(candidate.future_risk.status)}).
            Execution is not authorized.
          </p>
        </details>
      ))}
      <details>
        <summary>Model assumptions and immutable references</summary>
        <ul className="evidence-refs">
          {model.model_assumptions.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
        <ul className="evidence-refs">
          {model.evidence_refs.map((ref) => (
            <li key={`${ref.id}-${ref.sha256}`}>
              {ref.receipt_id}
              <small className="evidence-id">{ref.sha256}</small>
            </li>
          ))}
        </ul>
        <p className="evidence-id">Model result {model.assessment_hash}</p>
      </details>
    </>
  );
}

function ResultEvidence({ record }: { record: Result }) {
  const current = record.hardware_mapping.current;
  return (
    <section
      className="native-evaluation native-capacity-result"
      aria-label={`Native physical capacity result ${record.id}`}
    >
      <div className="policy-row">
        <span>
          <strong>Native hardware & capacity model</strong>
          <small>
            {dateTime(record.created_at)} · {record.resource_id}
          </small>
        </span>
        <Badge value={record.status} />
      </div>
      <p className="form-note">
        Server-selected provider hardware and pinned native observations. This
        immutable analysis creates no execution plan and claims no savings.
      </p>
      <ul className="evidence-refs">
        {record.reason_codes.map((reason) => (
          <li key={reason}>{readable(reason)}</li>
        ))}
      </ul>
      <dl className="definition-list">
        <div>
          <dt>Current configured hardware</dt>
          <dd>
            {current.id || "Unavailable"}
            <small>
              {decimal(current.capacity.cpu)} vCPU ·{" "}
              {decimal(current.capacity.memory)} bytes memory
            </small>
            <small>
              Sustained network {decimal(current.capacity.network)} bytes/second
            </small>
            <small>
              Retained EBS bottleneck {decimal(current.capacity.storage_iops)}{" "}
              operations/second · {decimal(current.capacity.storage_throughput)}{" "}
              bytes/second
            </small>
          </dd>
        </div>
        <div>
          <dt>Model / contracted price / execution</dt>
          <dd>
            {record.model_evaluated ? "Calculated" : "Unavailable"} /
            Unavailable / Not authorized
            <small>Estimated and verified savings: unavailable</small>
          </dd>
        </div>
        <div>
          <dt>Hardware receipt</dt>
          <dd>
            {record.hardware_receipt_id}
            <small className="evidence-id">{record.hardware_raw_sha256}</small>
          </dd>
        </div>
        <div>
          <dt>Frozen scope & requirements</dt>
          <dd>
            {record.binding.provider_resource_id} · {record.binding.account_id}{" "}
            · {record.binding.region}
            <small>
              {record.safety_profile_id} revision{" "}
              {record.safety_profile_version}
            </small>
            <small className="evidence-id">{record.safety_profile_hash}</small>
          </dd>
        </div>
      </dl>
      {Object.entries(record.hardware_mapping.candidate_reasons).map(
        ([id, reasons]) =>
          reasons.length ? (
            <p className="blocker-text" key={id}>
              {id}: {reasons.map(readable).join(" · ")}
            </p>
          ) : null,
      )}
      {record.model_evaluated && record.model_evaluation ? (
        <details>
          <summary>Inspect observations, forecasts & candidate checks</summary>
          <ModelEvidence model={record.model_evaluation} />
        </details>
      ) : (
        <p className="blocker-text">
          The physical model was not evaluated. Missing hardware dimensions,
          historical denominators or native evidence must be resolved first.
        </p>
      )}
      <details>
        <summary>
          Frozen population references · {shortId(record.population_hash)}
        </summary>
        <p>
          {record.history.days} complete local days · {record.history.timezone}{" "}
          · {dateTime(record.history.start)} — {dateTime(record.history.end)}
        </p>
        <p className="evidence-id">{record.population_hash}</p>
        <ul className="evidence-refs">
          {record.receipt_ids.slice(0, 16).map((id) => (
            <li key={id}>{id}</li>
          ))}
        </ul>
        <p className="form-note">
          {record.receipt_ids.length} pinned native receipts; bounded preview
          above. Full populations remain in versioned source evidence.
        </p>
      </details>
    </section>
  );
}

export function NativeCapacityResults({
  workloadId,
  refresh,
}: {
  workloadId: string;
  refresh: number;
}) {
  return (
    <RemotePage<Result>
      key={`${workloadId}-${refresh}`}
      path={`/workloads/${encodeURIComponent(workloadId)}/native-capacity-results?limit=10`}
      label="Native physical capacity results"
      empty="No independently sourced hardware/model result is recorded. Assessments without current native hardware remain in the unavailable-catalogue history below."
    >
      {(records) =>
        records.map((record) => (
          <ResultEvidence key={record.id} record={record} />
        ))
      }
    </RemotePage>
  );
}
