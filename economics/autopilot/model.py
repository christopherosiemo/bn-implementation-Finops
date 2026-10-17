"""Conservative calendar-matched savings, never runtime-as-workload normalization."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation, localcontext
import hashlib
import json
import re

ZERO = Decimal("0")
SCALE = Decimal("0.000000000001")


class EvidenceError(ValueError):
    pass


def decimal(value: object, name: str = "amount") -> Decimal:
    # JSON numbers would already have been rounded through a float by many clients.
    if not isinstance(value, str) or not re.fullmatch(r"-?\d+(?:\.\d{1,12})?", value):
        raise EvidenceError(f"{name} must be a decimal string with at most 12 fractional digits")
    try:
        result = Decimal(value)
    except InvalidOperation as exc:
        raise EvidenceError(f"invalid {name}") from exc
    if len(result.as_tuple().digits) + max(result.as_tuple().exponent, 0) > 38:
        raise EvidenceError(f"{name} exceeds DECIMAL(38,12)")
    if abs(result) >= Decimal("1e26"):
        raise EvidenceError(f"{name} exceeds DECIMAL(38,12)")
    return result


def money(value: Decimal) -> str:
    with localcontext() as ctx:
        ctx.prec = 60
        return format(value.quantize(SCALE), "f")


def instant(value: object) -> datetime:
    if not isinstance(value, str):
        raise EvidenceError("interval timestamps must be ISO 8601 strings")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise EvidenceError("invalid interval timestamp") from exc
    if parsed.tzinfo is None:
        raise EvidenceError("interval timestamps need a UTC offset")
    return parsed.astimezone(timezone.utc)


def _integer(data: dict, name: str, default: int = 0) -> int:
    value = data.get(name, default)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise EvidenceError(f"{name} must be a non-negative integer")
    return value


def evaluate(data: dict) -> dict:
    if not isinstance(data, dict):
        raise EvidenceError("request must be an object")
    currency = data.get("currency")
    if not isinstance(currency, str) or not re.fullmatch("[A-Z]{3}", currency):
        raise EvidenceError("one explicit ISO currency is required; do not aggregate currencies")
    if not data.get("resource_id") or not data.get("source_version"):
        raise EvidenceError("resource_id and source_version are required")
    baseline_days = _integer(data, "baseline_days")
    verification_days = _integer(data, "verification_days")
    intervals = data.get("intervals")
    if not isinstance(intervals, list) or not intervals or len(intervals) > 100000:
        raise EvidenceError("one to 100000 evidence intervals are required")
    expected = actual = incremental = ZERO
    seen_ids: set[str] = set()
    ranges: list[tuple[datetime, datetime]] = []
    workload_complete = data.get("workload_evidence_complete") is True
    non_idle = False
    with localcontext() as ctx:
        ctx.prec = 60
        for row in intervals:
            if not isinstance(row, dict):
                raise EvidenceError("interval must be an object")
            source_id = row.get("source_record_id")
            if not isinstance(source_id, str) or not source_id or source_id in seen_ids:
                raise EvidenceError("duplicate or absent source_record_id")
            seen_ids.add(source_id)
            start, end = instant(row.get("start")), instant(row.get("end"))
            if end <= start:
                raise EvidenceError("interval end must be after start")
            ranges.append((start, end))
            if row.get("currency", currency) != currency:
                raise EvidenceError("mixed currencies are not supported")
            # These are matched *idle* windows. Runtime reduction is not a demand metric.
            for name in ("baseline_units", "actual_units"):
                if row.get(name) is None:
                    workload_complete = False
                else:
                    units = decimal(row[name], name)
                    if units < ZERO:
                        raise EvidenceError("workload units must be non-negative")
                    non_idle |= units != ZERO
            baseline = decimal(row.get("baseline_compute_cost"), "baseline_compute_cost")
            charge = decimal(row.get("actual_compute_cost"), "actual_compute_cost")
            extra = decimal(row.get("incremental_cost", "0"), "incremental_cost")
            expected += baseline
            actual += charge
            incremental += extra
        ranges.sort()
        for previous, current in zip(ranges, ranges[1:]):
            if current[0] < previous[1]:
                raise EvidenceError("overlapping resource/time claims are forbidden")
        saving = expected - actual - incremental
        # Completed distinct local dates are supplied by ingestion; timestamps still
        # bound the maximum observation span so a single hour cannot claim 14 days.
        if verification_days >= 14 and ranges[-1][1] - ranges[0][0] < timedelta(days=13):
            raise EvidenceError("verification evidence does not span 14 complete days")
        status, reason = "VERIFIED", "BILLING_AND_WORKLOAD_EVIDENCE_VERIFIED"
        if data.get("commitment_known") is not True:
            status, reason = "BLOCKED", "COMMITMENT_UNKNOWN"
        elif data.get("uncovered_on_demand") is not True:
            status, reason = "BLOCKED", "COMMITMENT_PORTFOLIO_MODEL_REQUIRED"
        elif baseline_days < 14 or data.get("baseline_complete") is not True:
            status, reason = "MEASURING", "INSUFFICIENT_OBSERVATION"
        elif not workload_complete:
            status, reason = "MEASURING", "WORKLOAD_EVIDENCE_MISSING"
        elif data.get("confounded") is True:
            status, reason = "CONFOUNDED", "CONCURRENT_CHANGE"
        elif data.get("work_preserved") is not True or non_idle:
            status, reason = "CONFOUNDED", "WORKLOAD_ADJUSTMENT_REQUIRED"
        elif verification_days < 14:
            status, reason = "MEASURING", "VERIFICATION_WINDOW_INCOMPLETE"
        elif data.get("invoice_final") is not True:
            status, reason = "MEASURING", "BILLING_PROVISIONAL"
        else:
            reconciliation = decimal(data.get("reconciliation_ratio", "0"), "reconciliation_ratio")
            if reconciliation < ZERO or reconciliation > Decimal("1"):
                raise EvidenceError("reconciliation_ratio must be between 0 and 1")
            if reconciliation < Decimal("0.995"):
                status, reason = "MEASURING", "RECONCILIATION_BELOW_THRESHOLD"
        canonical = json.dumps(data, sort_keys=True, separators=(",", ":"), allow_nan=False)
        coverage = [{"start": start.isoformat(), "end": end.isoformat()} for start, end in ranges]
        claim_identity = json.dumps({"resource_id": data["resource_id"], "currency": currency, "coverage": coverage}, sort_keys=True, separators=(",", ":"))
        return {
            "status": status, "reason_code": reason, "currency": currency,
            "resource_id": data["resource_id"], "source_version": data["source_version"],
            "expected_baseline_cost": money(expected), "actual_cost": money(actual),
            "incremental_cost": money(incremental), "observed_saving": money(saving),
            "verified_saving": money(saving) if status == "VERIFIED" else None,
            "confidence": "HIGH" if status == "VERIFIED" else "LOW",
            "fingerprint": hashlib.sha256(canonical.encode()).hexdigest(),
            "claim_key": hashlib.sha256(claim_identity.encode()).hexdigest(),
            "coverage_intervals": coverage,
            "baseline_days": baseline_days, "verification_days": verification_days,
            "interval_count": len(intervals), "normalization_unit": "workload_activity",
            "baseline_model": "calendar_matched_idle_windows",
            "annualised_estimate": money(saving * Decimal(365) / Decimal(verification_days)) if verification_days else None,
            "explanation": "Matched historical idle-window compute cost minus actual compute and incremental cloud charges. Continuing EBS/IP charges are not claimed. Annualisation is an estimate, separate from the verified period amount.",
        }
