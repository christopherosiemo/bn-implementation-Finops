"""Source-bound, calendar-matched pilot economics.

Only the control plane supplies these snapshots, after persisting their source
jobs. There is deliberately no fixture-mode exception in this validator.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal, localcontext
import hashlib
import json
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .model import EvidenceError, decimal, instant, money
from .normalize import normalize

ZERO = Decimal("0")
IDENTITY = ("tenant_id", "resource_id", "provider_resource_id", "account_id", "region", "currency")


def _period(data, name):
    if not isinstance(data, dict):
        raise EvidenceError(f"{name} must be an object")
    start, end = instant(data.get("start")), instant(data.get("end"))
    if end <= start:
        raise EvidenceError(f"{name} end must follow start")
    return start, end


def _midnight(value, zone):
    local = value.astimezone(zone)
    return local.hour == local.minute == local.second == local.microsecond == 0


def _calendar_days(start, end, zone):
    if not _midnight(start, zone) or not _midnight(end, zone):
        raise EvidenceError("measurement periods require complete local calendar days")
    return (end.astimezone(zone).date() - start.astimezone(zone).date()).days


def _coverage(ranges, start, end):
    cursor = start
    for left, right in sorted(ranges):
        if right <= cursor or left >= end:
            continue
        if left > cursor:
            return False
        cursor = max(cursor, right)
        if cursor >= end:
            return True
    return cursor >= end


def _overlap(left, right, start, end):
    return max(timedelta(0), min(right, end) - max(left, start))


def _seconds(delta):
    return Decimal(delta.days * 86400 + delta.seconds) + Decimal(delta.microseconds) / Decimal(1000000)


def _unique_ranges(items, name):
    ordered = sorted(items, key=lambda item: (item[0], item[1]))
    for previous, current in zip(ordered, ordered[1:]):
        if current[0] < previous[1]:
            raise EvidenceError(f"overlapping {name} records")
    return ordered


def _samples(data, binding, start, end):
    rows = data.get("workload_samples")
    if not isinstance(rows, list) or len(rows) > 100000:
        raise EvidenceError("workload_samples must be an array")
    samples, ids = [], set()
    for row in rows:
        if not isinstance(row, dict):
            raise EvidenceError("workload sample must be an object")
        for key in ("resource_id", "provider_resource_id", "account_id", "region"):
            if row.get(key) != binding[key]:
                raise EvidenceError(f"workload sample {key} mismatch")
        if row.get("tenant_id", binding["tenant_id"]) != binding["tenant_id"]:
            raise EvidenceError("workload sample tenant mismatch")
        identifier = row.get("source_record_id")
        if not identifier or identifier in ids:
            raise EvidenceError("missing or duplicate workload source record")
        ids.add(identifier)
        left, right = _period(row, "workload sample")
        if left < start or right > end:
            raise EvidenceError("workload sample outside its declared period")
        units = None if row.get("units") is None else decimal(row["units"], "workload units")
        if units is not None and units < ZERO:
            raise EvidenceError("negative workload units")
        samples.append((left, right, units, identifier))
    return _unique_ranges(samples, "workload")


def _rows(data, binding, start, end):
    rows = data.get("billing_records")
    if not isinstance(rows, list) or len(rows) > 100000:
        raise EvidenceError("billing_records must be an array")
    if not data.get("source_id") or not data.get("source_version"):
        raise EvidenceError("immutable source identity is required")
    if any(not isinstance(row, dict) or not isinstance(row.get("x_ProviderFields"), dict) for row in rows):
        raise EvidenceError("canonical rows require their immutable provider source records")
    derived = normalize({"records": [row["x_ProviderFields"] for row in rows], "source_id": data["source_id"], "source_version": data["source_version"]})["records"]
    result, ids = [], set()
    for row, mapped in zip(rows, derived):
        if not isinstance(row, dict):
            raise EvidenceError("canonical billing row must be an object")
        for column, key in (("SubAccountId", "account_id"), ("ResourceId", "provider_resource_id"), ("RegionId", "region"), ("BillingCurrency", "currency")):
            if row.get(column) != binding[key]:
                raise EvidenceError(f"canonical billing {column} mismatch")
        if row.get("x_SourceId") != data["source_id"] or row.get("x_SourceVersion") != data["source_version"]:
            raise EvidenceError("canonical billing source version mismatch")
        if row.get("x_TenantId", binding["tenant_id"]) != binding["tenant_id"]:
            raise EvidenceError("canonical billing tenant mismatch")
        for column in ("BilledCost", "EffectiveCost", "ContractedCost", "SubAccountId", "ResourceId", "RegionId", "BillingCurrency", "ChargePeriodStart", "ChargePeriodEnd", "ServiceName", "x_SourceRecordId"):
            if row.get(column) != mapped.get(column):
                raise EvidenceError(f"canonical {column} differs from immutable source record")
        identifier = row.get("x_SourceRecordId")
        if not identifier or identifier in ids:
            raise EvidenceError("missing or duplicate canonical source record")
        ids.add(identifier)
        left, right = instant(row.get("ChargePeriodStart")), instant(row.get("ChargePeriodEnd"))
        if right <= left or left < start or right > end:
            raise EvidenceError("billing row outside its declared period")
        raw = row.get("x_ProviderFields") or {}
        family = str(raw.get("product_product_family", raw.get("product/productFamily", ""))).lower().replace(" ", "")
        usage = str(raw.get("line_item_usage_type", raw.get("lineItem/UsageType", "")))
        operation = raw.get("line_item_operation", raw.get("lineItem/Operation", ""))
        compute = row.get("ServiceName") == "AmazonEC2" and (family == "computeinstance" or "BoxUsage:" in usage or str(operation).startswith("RunInstances"))
        kind = raw.get("line_item_line_item_type", raw.get("lineItem/LineItemType", "Usage"))
        term = raw.get("pricing_term", raw.get("pricing/term", ""))
        uncovered = compute and kind == "Usage" and term == "OnDemand" and not any(raw.get(name) for name in ("reservation_reservation_a_r_n", "reservation/ReservationARN", "savings_plan_savings_plan_a_r_n", "savingsPlan/SavingsPlanARN"))
        billed = decimal(row.get("BilledCost"), "BilledCost")
        effective = None if row.get("EffectiveCost") is None else decimal(row["EffectiveCost"], "EffectiveCost")
        contracted = None if row.get("ContractedCost") is None else decimal(row["ContractedCost"], "ContractedCost")
        result.append({"start": left, "end": right, "id": identifier, "compute": compute, "uncovered": uncovered, "effective": effective, "contracted": contracted, "billed": billed, "row": row})
    _unique_ranges([(r["start"], r["end"]) for r in result if r["compute"]], "compute billing")
    return result


def _clock(value):
    if not isinstance(value, str) or len(value) != 5 or value[2] != ":":
        raise EvidenceError("schedule requires HH:MM local times")
    try:
        hours, minutes = map(int, value.split(":"))
    except ValueError as exc:
        raise EvidenceError("invalid local schedule time") from exc
    if not 0 <= hours <= 23 or not 0 <= minutes <= 59:
        raise EvidenceError("invalid local schedule time")
    return hours, minutes


def _windows(start, end, schedule, zone):
    stop_hour, stop_minute = _clock(schedule.get("stop_time"))
    ready_hour, ready_minute = _clock(schedule.get("ready_time"))
    days = schedule.get("days")
    if not isinstance(days, list) or not days or any(type(day) is not int or day not in range(1, 8) for day in days):
        raise EvidenceError("schedule days must use ISO weekdays 1 to 7")
    lead = schedule.get("start_lead_minutes", 15)
    if type(lead) is not int or not 0 <= lead <= 120:
        raise EvidenceError("invalid restoration lead time")
    date = start.astimezone(zone).date() - timedelta(days=1)
    last = end.astimezone(zone).date()
    windows = []
    while date <= last:
        if date.isoweekday() in days:
            local_stop = datetime(date.year, date.month, date.day, stop_hour, stop_minute, tzinfo=zone)
            # A missing DST stop has no occurrence. A repeated local time occurs once.
            stop = local_stop.astimezone(timezone.utc)
            if stop.astimezone(zone).replace(tzinfo=None) != local_stop.replace(tzinfo=None):
                date += timedelta(days=1)
                continue
            ready_date = date + timedelta(days=int((ready_hour, ready_minute) <= (stop_hour, stop_minute)))
            # Include the startup lead in the financial window. Compute incurred
            # between running and readiness must reduce the claimed saving.
            ready = datetime(ready_date.year, ready_date.month, ready_date.day, ready_hour, ready_minute, tzinfo=zone).astimezone(timezone.utc)
            left, right = max(start, stop), min(end, ready)
            while right > left:
                next_date = left.astimezone(zone).date() + timedelta(days=1)
                midnight = datetime(next_date.year, next_date.month, next_date.day, tzinfo=zone).astimezone(timezone.utc)
                edge = min(right, midnight)
                windows.append((left, edge))
                left = edge
        date += timedelta(days=1)
    return windows


def _idle(samples, windows):
    return all(_coverage([(left, right) for left, right, units, _ in samples if units is not None], start, end) and all(units == ZERO for left, right, units, _ in samples if _overlap(left, right, start, end) > timedelta(0)) for start, end in windows)


def _compute_cost(rows, start, end, baseline=False):
    amount = ZERO
    for row in rows:
        overlap = _overlap(row["start"], row["end"], start, end)
        if not row["compute"] or not overlap:
            continue
        cost = row["effective"]
        if cost is None:
            raise EvidenceError("effective compute cost is unknown")
        if baseline:
            if row["contracted"] is None:
                raise EvidenceError("contracted compute cost is unknown")
            cost = min(cost, row["contracted"])
        amount += cost * _seconds(overlap) / _seconds(row["end"] - row["start"])
    return amount


def _work_preserved(baseline_samples, base_start, base_end, samples, start, end, zone):
    def days(values, left, right):
        totals = []
        day = left.astimezone(zone).date()
        while day < right.astimezone(zone).date():
            a = datetime(day.year, day.month, day.day, tzinfo=zone).astimezone(timezone.utc)
            next_day = day + timedelta(days=1)
            b = datetime(next_day.year, next_day.month, next_day.day, tzinfo=zone).astimezone(timezone.utc)
            total = sum((units * _seconds(_overlap(x, y, a, b)) / _seconds(y - x) for x, y, units, _ in values if units is not None and _overlap(x, y, a, b)), ZERO)
            totals.append((day.isoweekday(), total))
            day = next_day
        return totals
    historical = dict(days(baseline_samples, base_start, base_end))
    return all(weekday in historical and abs(units - historical[weekday]) <= Decimal("0.000000000001") for weekday, units in days(samples, start, end))


def evaluate_v2(data: dict) -> dict:
    if not isinstance(data, dict) or str(data.get("schema_version")) != "2":
        raise EvidenceError("schema_version 2 is required")
    binding = data.get("binding")
    if not isinstance(binding, dict) or any(not isinstance(binding.get(key), str) or not binding[key] for key in IDENTITY):
        raise EvidenceError("complete tenant and provider resource binding is required")
    if binding["region"] != "eu-west-1" or len(binding["account_id"]) != 12 or not binding["account_id"].isdigit():
        raise EvidenceError("sandbox account/region binding is invalid")
    if len(binding["currency"]) != 3 or not binding["currency"].isupper():
        raise EvidenceError("native source currency is required")
    if not data.get("baseline_id"):
        raise EvidenceError("immutable baseline_id is required")
    phase = data.get("phase")
    if phase not in ("BASELINE", "MEASUREMENT"):
        raise EvidenceError("phase must be BASELINE or MEASUREMENT")
    baseline = data.get("baseline")
    base_start, base_end = _period(baseline, "baseline")
    schedule = baseline.get("schedule") or {}
    try:
        zone = ZoneInfo(schedule["timezone"])
    except (KeyError, TypeError, ZoneInfoNotFoundError) as exc:
        raise EvidenceError("explicit IANA schedule timezone is required") from exc
    as_of, activation = instant(data.get("as_of")), instant(data.get("activation_at"))
    if base_end > activation or base_end > as_of:
        raise EvidenceError("baseline must be complete before activation")
    if activation > as_of:
        raise EvidenceError("activation cannot be in the future")
    if base_end.astimezone(zone).date() != activation.astimezone(zone).date():
        raise EvidenceError("baseline must end at the latest complete local day before activation")
    baseline_days = _calendar_days(base_start, base_end, zone)
    if baseline_days > 31:
        raise EvidenceError("pilot baseline must contain at most 31 days")
    base_rows = _rows(baseline, binding, base_start, base_end)
    base_samples = _samples(baseline, binding, base_start, base_end)
    base_windows = _windows(base_start, base_end, schedule, zone)
    complete_samples = _coverage([(left, right) for left, right, units, _ in base_samples if units is not None], base_start, base_end)
    complete_billing = _coverage([(r["start"], r["end"]) for r in base_rows if r["compute"]], base_start, base_end)
    known_compute = [r for r in base_rows if r["compute"]]
    commitment_known = bool(known_compute) and all(r["uncovered"] and r["effective"] is not None and r["effective"] >= ZERO and r["contracted"] is not None and r["contracted"] >= ZERO for r in known_compute)
    pre_ready, status, reason = True, "MEASURING", "VERIFICATION_WINDOW_INCOMPLETE"
    if baseline_days < 14 or not complete_billing:
        pre_ready, reason = False, "INSUFFICIENT_OBSERVATION"
    elif not complete_samples:
        pre_ready, reason = False, "WORKLOAD_EVIDENCE_MISSING"
    elif not commitment_known:
        pre_ready, status, reason = False, "BLOCKED", "COMMITMENT_UNKNOWN_OR_COVERED"
    elif not base_windows or not _idle(base_samples, base_windows):
        pre_ready, status, reason = False, "BLOCKED", "BASELINE_WORKLOAD_ACTIVE"
    baseline_status, baseline_reason = status, reason
    expected = actual = incremental = ZERO
    coverage, verification_days, calculated = [], 0, False
    measurement = data.get("measurement")
    with localcontext() as ctx:
        ctx.prec = 60
        if phase == "MEASUREMENT":
            if not data.get("measurement_id"):
                raise EvidenceError("measurement_id is required")
            start, end = _period(measurement, "measurement")
            if start < activation:
                raise EvidenceError("measurement precedes activation")
            verification_days = _calendar_days(start, end, zone)
            if verification_days > 31:
                raise EvidenceError("pilot measurement must contain at most 31 days")
            rows = _rows(measurement, binding, start, end)
            samples = _samples(measurement, binding, start, end)
            windows = _windows(start, end, schedule, zone)
            owned, seen_executions = [], set()
            for interval in measurement.get("owned_intervals", []):
                execution = interval.get("execution_id")
                if not execution or execution in seen_executions:
                    raise EvidenceError("missing or duplicate owned execution")
                seen_executions.add(execution)
                left, right = instant(interval.get("stopped_at")), instant(interval.get("running_at"))
                if left < activation or left < start or right > end or right <= left:
                    raise EvidenceError("owned execution interval outside measurement")
                if not _coverage(windows, left, right):
                    raise EvidenceError("owned execution is outside the approved schedule")
                owned.append((left, right))
            _unique_ranges(owned, "owned execution")
            # The correction identity is the measured resource/time scope even
            # when new evidence invalidates an older claim. Amounts stay unknown
            # until the calculation gates pass.
            coverage = [{"start": left.isoformat(), "end": right.isoformat()} for left, right in windows]
            if end > as_of or verification_days < 14:
                status, reason = "MEASURING", "VERIFICATION_WINDOW_INCOMPLETE"
            elif not _coverage([(a, b) for a, b, units, _ in samples if units is not None], start, end):
                status, reason = "MEASURING", "WORKLOAD_EVIDENCE_MISSING"
            elif not _idle(samples, windows) or not _work_preserved(base_samples, base_start, base_end, samples, start, end, zone):
                status, reason = "CONFOUNDED", "WORKLOAD_ADJUSTMENT_REQUIRED"
            elif not _coverage([(r["start"], r["end"]) for r in rows if r["compute"]], start, end):
                status, reason = "MEASURING", "BILLING_EVIDENCE_MISSING"
            elif not all(r["uncovered"] and r["effective"] is not None for r in rows if r["compute"]):
                status, reason = "BLOCKED", "COMMITMENT_UNKNOWN_OR_COVERED"
            elif not owned:
                status, reason = "BLOCKED", "OWNED_EXECUTION_REQUIRED"
            elif pre_ready:
                calculated = True
                for left, right in windows:
                    # Select the latest matching weekday/local-time baseline window.
                    candidates = [(a, b) for a, b in base_windows if a.astimezone(zone).isoweekday() == left.astimezone(zone).isoweekday() and a.astimezone(zone).time().replace(tzinfo=None) == left.astimezone(zone).time().replace(tzinfo=None) and _seconds(b - a) == _seconds(right - left)]
                    if not candidates:
                        raise EvidenceError("no calendar-matched baseline window")
                    a, b = candidates[-1]
                    baseline_cost = _compute_cost(base_rows, a, b, True)
                    actual_cost = _compute_cost(rows, left, right)
                    owned_parts = [(max(left, x), min(right, y)) for x, y in owned if _overlap(left, right, x, y)]
                    attributed = sum((_seconds(y - x) for x, y in owned_parts), ZERO)
                    # A reduction beyond actual owned downtime is an unrelated change.
                    max_avoidable = baseline_cost * attributed / _seconds(right - left)
                    if baseline_cost - actual_cost > max_avoidable + Decimal("0.000000000001"):
                        status, reason = "CONFOUNDED", "UNOWNED_RUNTIME_CHANGE"
                    expected += baseline_cost
                    actual += actual_cost
                extra_ids = measurement.get("incremental_billing_record_ids", [])
                if not isinstance(extra_ids, list) or len(extra_ids) != len(set(extra_ids)):
                    raise EvidenceError("invalid incremental billing references")
                by_id = {r["id"]: r for r in rows}
                for identifier in extra_ids:
                    if identifier not in by_id or by_id[identifier]["compute"]:
                        raise EvidenceError("missing or duplicate-counted incremental billing reference")
                    row = by_id[identifier]
                    raw = row["row"].get("x_ProviderFields") or {}
                    usage = str(raw.get("line_item_usage_type", raw.get("lineItem/UsageType", ""))).lower()
                    family = str(raw.get("product_product_family", raw.get("product/productFamily", ""))).lower()
                    if "ebs" in usage or "volume" in family or "storage" in family or "ip" in family or "ipv4" in usage or "elasticip" in usage:
                        raise EvidenceError("continuing storage and retained-IP charges cannot be attributed as savings")
                    if raw.get("finops_incremental_execution_id") not in seen_executions:
                        raise EvidenceError("incremental charge lacks owned execution attribution")
                    if row["effective"] is None:
                        raise EvidenceError("incremental charge cost is unknown")
                    incremental += row["effective"]
                invoice = measurement.get("invoice") or {}
                if status not in ("CONFOUNDED", "BLOCKED"):
                    if not invoice.get("invoice_id") or invoice.get("final") is not True:
                        status, reason = "MEASURING", "BILLING_PROVISIONAL"
                    else:
                        issued = instant(invoice.get("issued_at"))
                        if issued < end or issued > as_of:
                            raise EvidenceError("invoice issuance does not cover measurement")
                        invoice_total = decimal(invoice.get("total"), "invoice total")
                        canonical_total = decimal(invoice.get("reconciled_billed_total"), "canonical billed total")
                        ratio = max(ZERO, Decimal(1) - abs(canonical_total - invoice_total) / abs(invoice_total)) if invoice_total else (Decimal(1) if not canonical_total else ZERO)
                        if ratio < Decimal("0.995"):
                            status, reason = "MEASURING", "RECONCILIATION_BELOW_THRESHOLD"
                        else:
                            status, reason = "VERIFIED", "BILLING_AND_WORKLOAD_EVIDENCE_VERIFIED"
        if not pre_ready:
            # Later billing cannot override an invalid frozen baseline.
            status, reason = baseline_status, baseline_reason
        saving = expected - actual - incremental
        canonical = json.dumps(data, sort_keys=True, separators=(",", ":"), allow_nan=False)
        # A new reservation or execution cannot create a second claim for the
        # same resource/time. Corrections share this key and append a revision.
        claim = json.dumps({"binding": binding, "coverage": coverage}, sort_keys=True, separators=(",", ":"))
        return {"schema_version": "2", "status": status, "reason_code": reason, "pre_execution_ready": pre_ready,
                "readiness": {"baseline_ready": pre_ready, "baseline_days": baseline_days, "workload_complete": complete_samples, "commitment_known": commitment_known},
                "binding": binding, "resource_id": binding["resource_id"], "currency": binding["currency"], "baseline_id": data["baseline_id"], "measurement_id": data.get("measurement_id"),
                "expected_baseline_cost": money(expected) if calculated else None, "actual_cost": money(actual) if calculated else None, "incremental_cost": money(incremental) if calculated else None, "observed_saving": money(saving) if calculated else None,
                "verified_saving": money(saving) if status == "VERIFIED" else None,
                "annualised_estimate": money(saving * Decimal(365) / Decimal(verification_days)) if pre_ready and verification_days and calculated and status not in ("CONFOUNDED", "BLOCKED") else None,
                "confidence": "HIGH" if pre_ready else "LOW", "baseline_days": baseline_days, "verification_days": verification_days,
                "coverage_intervals": coverage, "interval_count": len(coverage), "source_version": (measurement or baseline).get("source_version"),
                "fingerprint": hashlib.sha256(canonical.encode()).hexdigest(), "claim_key": hashlib.sha256(claim.encode()).hexdigest(),
                "normalization_unit": "workload_activity", "baseline_model": "source_bound_calendar_idle_windows_v2",
                "explanation": "Frozen source-bound baseline; verified amounts require complete post-activation observations, owned downtime and final reconciled invoices. Retained storage/IP charges are excluded; native compute charges include startup."}
