"""Receipt-bound native billing and activity model.

The control plane resolves trusted receipts. This private worker verifies their
scope and consistency; an identifier alone is not proof of source authenticity.
"""
from datetime import datetime, timedelta, timezone
from decimal import Decimal, localcontext
import hashlib
import json
import re
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .model import EvidenceError, decimal, instant, money
from .native import normalize_v3, native_cost
from .v2 import (_period, _calendar_days, _coverage, _overlap, _seconds,
                 _unique_ranges, _windows)

ZERO = Decimal("0")
IDENTITY = ("tenant_id", "resource_id", "provider_resource_id", "account_id", "region", "currency", "payer_account_id", "invoice_entity")
COUNTERS = ("accepted", "completed", "rejected", "backlog", "inflight")


class ExportIncomplete(EvidenceError):
    """An authentic revision is pending/partial, rather than a forged binding."""


def _required(value, message):
    if not value:
        raise EvidenceError(message)


def _count(value, name):
    if type(value) is not int or value < 0:
        raise EvidenceError(f"{name} must be an explicit nonnegative integer")
    return value


def validate_source_proof(proof, binding, start, end, final=False):
    _required(isinstance(proof, dict), "trusted source proof required")
    for key in ("receipt_id", "revision_id", "manifest_hash"):
        _required(isinstance(proof.get(key), str) and proof[key], f"source {key} required")
    _required(re.fullmatch(r"[a-fA-F0-9]{64}", proof["manifest_hash"]), "source manifest hash invalid")
    for key, target in (("payer_account_id", "payer_account_id"), ("usage_account_id", "account_id"), ("region", "region"), ("currency", "currency"), ("invoice_entity", "invoice_entity")):
        _required(proof.get(key) == binding[target], f"source {key} mismatch")
    left, right = instant(proof.get("period_start")), instant(proof.get("period_end"))
    _required(left <= start < end <= right, "source proof does not cover the period")
    objects = _count(proof.get("object_count"), "object_count")
    rows = _count(proof.get("row_count"), "row_count")
    verified_objects = _count(proof.get("verified_object_count"), "verified_object_count")
    verified_rows = _count(proof.get("verified_row_count"), "verified_row_count")
    if proof.get("state") not in (("FINAL",) if final else ("COMPLETE", "FINAL")) or objects == 0 or objects != verified_objects or rows != verified_rows:
        raise ExportIncomplete("export is not complete/finalized")
    return proof


def _proofs(snapshot):
    values = snapshot.get("source_proofs")
    if values is None:
        values = [snapshot.get("source_proof")]
    _required(isinstance(values, list) and values and all(isinstance(value, dict) for value in values), "source receipts required")
    _required(len({value.get("receipt_id") for value in values}) == len(values), "duplicate source receipt")
    return values


def _proof_coverage(snapshot, binding, start, end, final=False, allow_incomplete=False):
    ranges = []
    complete = True
    for proof in _proofs(snapshot):
        left, right = instant(proof.get("period_start")), instant(proof.get("period_end"))
        try:
            validate_source_proof(proof, binding, left, right, final=final)
        except ExportIncomplete:
            if not allow_incomplete: raise
            complete = False
        ranges.append((left, right))
    if not _coverage(ranges, start, end):
        if not allow_incomplete: raise EvidenceError("source receipts do not cover period")
        complete = False
    return complete


def _canonical(snapshot, rows):
    pairs = {(proof.get("source_id"), proof.get("source_version")) for proof in _proofs(snapshot)}
    # Old single-revision service callers can pin the identity on the snapshot.
    if len(pairs) == 1 and (None, None) in pairs:
        pairs = {(snapshot.get("source_id"), snapshot.get("source_version"))}
    result = []
    for row in rows:
        pair = row.get("x_SourceId"), row.get("x_SourceVersion")
        _required(all(pair) and pair in pairs, "billing row not bound to an authorized source revision")
        result.append(normalize_v3({"source_id": pair[0], "source_version": pair[1], "records": [row.get("x_ProviderFields")]})["records"][0])
    return result


def validate_commitments(proof, binding):
    _required(isinstance(proof, dict) and proof.get("receipt_id"), "commitment receipt required")
    _required(proof.get("payer_account_id") == binding["payer_account_id"], "commitment payer mismatch")
    _required(proof.get("scope") == "PAYER_ALL_LINKED_ACCOUNTS_ALL_REGIONS" and proof.get("complete") is True, "full commitment scope required")
    accounts = proof.get("usage_account_ids")
    _required(isinstance(accounts, list) and binding["account_id"] in accounts and len(accounts) == len(set(accounts)), "commitment usage-account scope missing")
    return _count(proof.get("reserved_instance_count"), "reserved_instance_count") == 0 and _count(proof.get("savings_plan_count"), "savings_plan_count") == 0


def _activity(snapshot, binding, start, end):
    rows = snapshot.get("workload_samples")
    _required(isinstance(rows, list) and 0 < len(rows) <= 100000, "independent activity samples required")
    samples, ids, definition = [], set(), None
    for row in rows:
        _required(isinstance(row, dict), "activity sample must be an object")
        current_binding = row.get("binding") or row
        for key in ("tenant_id", "resource_id", "provider_resource_id", "account_id", "region"):
            _required(current_binding.get(key) == binding[key], f"activity {key} mismatch")
        _required(row.get("source_provenance") == "INDEPENDENT_ACTIVITY" and row.get("source_id") and row.get("receipt_id"), "independent activity receipt required")
        _required(re.fullmatch(r"[a-fA-F0-9]{64}", str(row.get("body_sha256", ""))), "activity body hash required")
        _required(row.get("heartbeat") is True, "missing activity heartbeat")
        metric = row.get("metric_definition") or {}
        _required(all(metric.get(key) is not None and str(metric[key]) for key in ("id", "version", "unit")), "immutable metric definition required")
        current_definition = tuple(str(metric[key]) for key in ("id", "version", "unit"))
        if definition is None:
            definition = current_definition
        _required(definition == current_definition, "metric definition changed during observation")
        identifier = row.get("source_record_id") or row["receipt_id"]
        _required(identifier not in ids, "duplicate activity receipt")
        ids.add(identifier)
        left, right = _period(row, "activity")
        _required(start <= left < right <= end, "activity outside observation period")
        values = {key: decimal(row.get(key), key) for key in COUNTERS}
        _required(all(value >= ZERO for value in values.values()), "negative activity counter")
        _required(decimal(row.get("units"), "units") == values["accepted"], "units must preserve accepted demand")
        _required(all(row.get(key) == "CLEAR" for key in ("incident", "deployment", "job")), "activity safety signal not CLEAR")
        samples.append((left, right, values, identifier))
    _unique_ranges(samples, "activity")
    return samples, definition


def _billing(snapshot, binding, start, end):
    rows = snapshot.get("billing_records")
    _required(isinstance(rows, list) and len(rows) <= 100000, "canonical billing records required")
    _required(snapshot.get("source_id") and snapshot.get("source_version"), "immutable source identity required")
    _required(all(isinstance(row, dict) and isinstance(row.get("x_ProviderFields"), dict) for row in rows), "original provider fields required")
    derived = _canonical(snapshot, rows)
    result, ids = [], set()
    for row, mapped in zip(rows, derived):
        for column, key in (("SubAccountId", "account_id"), ("ResourceId", "provider_resource_id"), ("RegionId", "region"), ("BillingCurrency", "currency"), ("BillingAccountId", "payer_account_id"), ("InvoiceIssuerName", "invoice_entity")):
            _required(row.get(column) == binding[key], f"native billing {column} mismatch")
        for column in ("BilledCost", "SubAccountId", "ResourceId", "RegionId", "BillingCurrency", "BillingAccountId", "InvoiceIssuerName", "ChargePeriodStart", "ChargePeriodEnd", "ServiceName", "x_SourceRecordId", "x_PricingBasis", "x_NativeComputeCost"):
            _required(row.get(column) == mapped.get(column), f"native canonical {column} tampered")
        identifier = (row.get("x_SourceId"), row.get("x_SourceVersion"), row.get("x_SourceRecordId"))
        _required(identifier and identifier not in ids, "duplicate billing source record")
        ids.add(identifier)
        left, right = instant(row.get("ChargePeriodStart")), instant(row.get("ChargePeriodEnd"))
        _required(start <= left < right <= end, "billing row outside observation period")
        raw = row["x_ProviderFields"]
        family = str(raw.get("product_product_family", raw.get("product/productFamily", ""))).lower().replace(" ", "")
        usage = str(raw.get("line_item_usage_type", raw.get("lineItem/UsageType", "")))
        operation = str(raw.get("line_item_operation", raw.get("lineItem/Operation", "")))
        compute = row.get("ServiceName") == "AmazonEC2" and (family == "computeinstance" or "BoxUsage:" in usage or operation.startswith("RunInstances"))
        kind = raw.get("line_item_line_item_type", raw.get("lineItem/LineItemType", ""))
        term = raw.get("pricing_term", raw.get("pricing/term", ""))
        uncovered = kind == "Usage" and term == "OnDemand" and not any(raw.get(name) for name in ("reservation_reservation_a_r_n", "reservation/ReservationARN", "savings_plan_savings_plan_a_r_n", "savingsPlan/SavingsPlanARN"))
        basis, amount = native_cost(raw)
        result.append({"start": left, "end": right, "id": row.get("x_SourceRecordId"), "identity": identifier, "compute": compute, "uncovered": uncovered, "cost": amount, "basis": basis, "row": row})
    _unique_ranges([(row["start"], row["end"]) for row in result if row["compute"]], "compute billing")
    return result


def _owned(snapshot, start, end, activation, windows):
    result, ids = [], set()
    for interval in snapshot.get("owned_intervals", []):
        identifier = interval.get("execution_id")
        _required(identifier and identifier not in ids, "duplicate or absent owned execution")
        ids.add(identifier)
        left, right = instant(interval.get("stopped_at")), instant(interval.get("running_at"))
        _required(max(start, activation) <= left < right <= end and _coverage(windows, left, right), "owned downtime outside approved period/windows")
        result.append((left, right))
    return _unique_ranges(result, "owned downtime"), ids


def _observations(snapshot, rows, binding, start, end, owned, baseline=False):
    observations = snapshot.get("billing_observations")
    if observations is None:
        observations = [{"start": row["start"].isoformat(), "end": row["end"].isoformat(), "state": "OBSERVED", "source_record_ids": [row["id"]]} for row in rows if row["compute"]]
    _required(isinstance(observations, list) and len(observations) <= 100000, "billing observations must be an array")
    result, known = [], []
    by_id = {}
    for row in rows:
        if row["compute"]: by_id.setdefault(row["id"], []).append(row)
    for observation in observations:
        left, right = _period(observation, "billing observation")
        _required(start <= left < right <= end, "billing observation outside period")
        state = observation.get("state")
        _required(state in ("OBSERVED", "ABSENT_FINAL_EXPORT", "UNKNOWN"), "unknown observation state")
        if state == "OBSERVED":
            ids = observation.get("source_record_ids")
            _required(isinstance(ids, list) and ids and len(ids) == len(set(ids)) and all(identifier in by_id for identifier in ids), "observed interval requires native source records")
            # Native line IDs may repeat across billing months/revisions. All
            # candidates are authorized and compute intervals cannot overlap;
            # timestamp coverage resolves the observation without losing its
            # full source/version/record identity in financial calculation.
            _required(_coverage([(row["start"], row["end"]) for identifier in ids for row in by_id[identifier]], left, right), "observed source records do not cover interval")
            known.append((left, right))
        elif state == "ABSENT_FINAL_EXPORT":
            _required(not baseline, "baseline must contain actual observed compute coverage")
            _required(not any(key in observation for key in ("cost", "amount", "actual_cost", "BilledCost")), "absence must not manufacture a zero-cost record")
            proof = next((proof for proof in _proofs(snapshot) if proof.get("receipt_id") == observation.get("source_receipt_id")), None)
            finalized = True
            try:
                validate_source_proof(proof, binding, left, right, final=True)
            except ExportIncomplete:
                finalized = False
            _required(_coverage(owned, left, right), "absence is not entirely owned downtime")
            _required(not any(_overlap(row["start"], row["end"], left, right) for row in rows if row["compute"]), "absent interval contradicts observed compute")
            if finalized: known.append((left, right))
            else: state = "UNKNOWN"
        result.append((left, right, state))
    _unique_ranges(result, "billing observation")
    return _coverage(known, start, end), {state: sum(_seconds(right - left) for left, right, current in result if current == state) for state in ("OBSERVED", "ABSENT_FINAL_EXPORT", "UNKNOWN")}


def _idle(samples, windows):
    return all(_coverage([(left, right) for left, right, _, _ in samples], start, end) and all(all(value == ZERO for value in values.values()) for left, right, values, _ in samples if _overlap(left, right, start, end)) for start, end in windows)


def _daily(samples, start, end, zone):
    result = []
    day = start.astimezone(zone).date()
    while day < end.astimezone(zone).date():
        left = datetime(day.year, day.month, day.day, tzinfo=zone).astimezone(timezone.utc)
        next_day = day + timedelta(days=1)
        right = datetime(next_day.year, next_day.month, next_day.day, tzinfo=zone).astimezone(timezone.utc)
        totals = {key: ZERO for key in COUNTERS}
        for a, b, values, _ in samples:
            overlap = _overlap(a, b, left, right)
            if overlap:
                for key in COUNTERS:
                    if key in ("backlog", "inflight"):
                        totals[key] = max(totals[key], values[key])
                    else:
                        totals[key] += values[key] * _seconds(overlap) / _seconds(b - a)
        result.append((day.isoweekday(), totals))
        day = next_day
    return result


def _work_preserved(base, base_start, base_end, samples, start, end, zone):
    historical = {}
    for weekday, values in _daily(base, base_start, base_end, zone):
        historical.setdefault(weekday, []).append(values)
    for weekday, values in _daily(samples, start, end, zone):
        matches = historical.get(weekday, [])
        if not matches:
            return False
        # Compare with the observed weekday mean across the full baseline.
        reference = {key: sum((entry[key] for entry in matches), ZERO) / Decimal(len(matches)) for key in COUNTERS}
        if any(abs(values[key] - reference[key]) > Decimal("0.000000000001") for key in ("accepted", "completed")):
            return False
        if any(values[key] > reference[key] + Decimal("0.000000000001") for key in ("rejected", "backlog", "inflight")):
            return False
    return True


def _cost(rows, start, end):
    return sum((row["cost"] * _seconds(_overlap(row["start"], row["end"], start, end)) / _seconds(row["end"] - row["start"]) for row in rows if row["compute"] and row["cost"] is not None and _overlap(row["start"], row["end"], start, end)), ZERO)


def _retained_key(row):
    raw = row["row"]["x_ProviderFields"]
    family = str(raw.get("product_product_family", raw.get("product/productFamily", ""))).lower()
    usage = str(raw.get("line_item_usage_type", raw.get("lineItem/UsageType", ""))).lower()
    operation = str(raw.get("line_item_operation", raw.get("lineItem/Operation", "")))
    retained = any(word in family for word in ("storage", "volume", "ip")) or any(word in usage for word in ("ebs", "ipv4", "elasticip"))
    return (row["row"].get("ResourceId"), row["row"].get("ServiceName"), family, usage, operation, row["basis"]) if retained else None


def _scope_retained(snapshot, binding, start, end, target_rows, require_complete=True):
    """Conservatively include unallocated volumes/IP from the complete source."""
    scope = snapshot.get("source_scope_records", snapshot.get("invoice_scope_records"))
    _required(isinstance(scope, list) and scope, "full source-scope canonical records required")
    mapped = _canonical(snapshot, scope)
    counts = {}
    for row in mapped:
        pair = row.get("x_SourceId"), row.get("x_SourceVersion")
        counts[pair] = counts.get(pair, 0) + 1
    for proof in _proofs(snapshot):
        pair = proof.get("source_id", snapshot.get("source_id")), proof.get("source_version", snapshot.get("source_version"))
        if require_complete:
            _required(counts.get(pair, 0) == proof.get("verified_row_count"), "full source-scope records do not match receipt row count")
    known = {row["identity"] for row in target_rows}
    result = []
    seen = set()
    for row in mapped:
        identity = row.get("x_SourceId"), row.get("x_SourceVersion"), row.get("x_SourceRecordId")
        _required(identity not in seen, "duplicate full source-scope record")
        seen.add(identity)
        if identity in known or row.get("SubAccountId") != binding["account_id"] or row.get("RegionId") != binding["region"] or row.get("ServiceName") != "AmazonEC2":
            continue
        left, right = instant(row.get("ChargePeriodStart")), instant(row.get("ChargePeriodEnd"))
        _required(left < right, "source-scope record period invalid")
        overlap = _overlap(left, right, start, end)
        if not overlap: continue
        basis, amount = native_cost(row["x_ProviderFields"])
        with localcontext() as context:
            context.prec = 60
            prorated = amount * _seconds(overlap) / _seconds(right - left) if amount is not None else None
        current = {"compute": False, "cost": prorated, "basis": basis, "row": row}
        if _retained_key(current):
            if row.get("BillingAccountId") != binding["payer_account_id"] or row.get("InvoiceIssuerName") != binding["invoice_entity"] or row.get("BillingCurrency") != binding["currency"]:
                current["cost"] = None  # Allocation across invoice scopes/FX is unsupported.
            result.append(current)
    return result


def _unallocated_increase(base_rows, rows, base_start, base_end, start, end):
    historical, current = {}, {}
    for row in base_rows:
        key = _retained_key(row)
        if row["cost"] is None: return True
        historical[key] = historical.get(key, ZERO) + row["cost"]
    for row in rows:
        key = _retained_key(row)
        if row["cost"] is None: return True
        current[key] = current.get(key, ZERO) + row["cost"]
    return any(amount > historical.get(key, ZERO) * _seconds(end - start) / _seconds(base_end - base_start) + Decimal("0.000000000001") for key, amount in current.items())


def _native_scope_risk(snapshot, binding, start, end):
    """Current zero inventories cannot erase historical portfolio economics."""
    adjustment = False
    for row in snapshot.get("source_scope_records", snapshot.get("invoice_scope_records", [])):
        raw = row["x_ProviderFields"]
        payer = raw.get("bill_payer_account_id", raw.get("bill/PayerAccountId", row.get("BillingAccountId")))
        if payer != binding["payer_account_id"]: continue
        kind = str(raw.get("line_item_line_item_type", raw.get("lineItem/LineItemType", "")))
        term = str(raw.get("pricing_term", raw.get("pricing/term", "")))
        commitment = kind in ("DiscountedUsage", "RIFee", "SavingsPlanCoveredUsage", "SavingsPlanNegation", "SavingsPlanRecurringFee", "SavingsPlanUpfrontFee") or term in ("Reserved", "SavingsPlan") or any(raw.get(name) for name in ("reservation_reservation_a_r_n", "reservation_reservation_arn", "reservation/ReservationARN", "savings_plan_savings_plan_a_r_n", "savings_plan_savings_plan_arn", "savingsPlan/SavingsPlanARN"))
        _, amount = native_cost(raw)
        financial_adjustment = kind in ("Credit", "Refund", "Discount", "BundledDiscount", "EdpDiscount", "PrivateRateDiscount") or (amount is not None and amount < ZERO)
        if not commitment and not financial_adjustment: continue
        left = row.get("ChargePeriodStart") or row.get("BillingPeriodStart")
        right = row.get("ChargePeriodEnd") or row.get("BillingPeriodEnd")
        # An undated adjustment cannot be established as disjoint. Its presence
        # is not permission to allocate a payer-wide discount to this instance.
        if left and right:
            a, b = instant(left), instant(right)
            _required(a < b, "native portfolio adjustment period invalid")
            if not _overlap(a, b, start, end): continue
        if commitment: return "HISTORICAL_COMMITMENT_EXPOSURE"
        adjustment = True
    return "UNALLOCATED_FINANCIAL_ADJUSTMENT" if adjustment else None


def _incremental(base_rows, rows, base_start, base_end, start, end, executions):
    """Retained storage/IP never yields savings. New native costs need attribution."""
    baseline, retained, extra = {}, {}, ZERO
    for row in base_rows:
        key = _retained_key(row)
        if key and row["cost"] is not None:
            baseline[key] = baseline.get(key, ZERO) + row["cost"]
    for row in rows:
        if row["compute"]: continue
        key = _retained_key(row)
        if key:
            retained.setdefault(key, []).append(row)
        elif row["cost"] is None or row["row"]["x_ProviderFields"].get("finops_incremental_execution_id") not in executions:
            return None
        else:
            extra += row["cost"]
    for key, current in retained.items():
        if any(row["cost"] is None for row in current): return None
        reference = baseline.get(key, ZERO) * _seconds(end - start) / _seconds(base_end - base_start)
        increase = sum((row["cost"] for row in current), ZERO) - reference
        if increase > Decimal("0.000000000001"):
            # Native source-backed rows must identify the owned execution. A
            # caller cannot declare that every EBS/IP increase was unavoidable.
            if not all(row["row"]["x_ProviderFields"].get("finops_incremental_execution_id") in executions for row in current):
                return None
            extra += increase
    return extra


def _invoices(snapshot, binding, start, end, as_of):
    wrappers = snapshot.get("invoices")
    if not isinstance(wrappers, list) or not wrappers:
        return False, "BILLING_PROVISIONAL"
    scope = snapshot.get("invoice_scope_records")
    _required(isinstance(scope, list) and scope, "full invoice-scope canonical records required")
    rows = _canonical(snapshot, scope)
    identities = [(row.get("x_SourceId"), row.get("x_SourceVersion"), row.get("x_SourceRecordId")) for row in rows]
    _required(len(identities) == len(set(identities)), "duplicate invoice source row")
    _required(all(all(row.get(key) == mapped.get(key) for key in ("BilledCost", "BillingAccountId", "InvoiceIssuerName", "BillingCurrency", "x_SourceRecordId")) for row, mapped in zip(scope, rows)), "invoice scope canonical amount/identity tampered")
    full = _canonical(snapshot, snapshot.get("source_scope_records", scope))
    full_by_id = {(row.get("x_SourceId"), row.get("x_SourceVersion"), row.get("x_SourceRecordId")): row for row in full}
    for identity, row in zip(identities, rows):
        _required(identity in full_by_id and row["x_ProviderFields"] == full_by_id[identity]["x_ProviderFields"], "invoice scope record not in authorized full source")
    selected_identities = set(identities)
    _required(all((row.get("x_SourceId"), row.get("x_SourceVersion"), row.get("x_SourceRecordId")) in selected_identities for row in full if row.get("BillingAccountId") == binding["payer_account_id"] and row.get("InvoiceIssuerName") == binding["invoice_entity"] and row.get("BillingCurrency") == binding["currency"]), "invoice scope omits matching native source records")
    seen, periods = set(), []
    for wrapper in wrappers:
        _required(isinstance(wrapper, dict) and wrapper.get("receipt_id"), "native invoice receipt required")
        invoice = wrapper.get("native") or {}
        identifier = invoice.get("InvoiceId")
        _required(identifier and identifier not in seen, "native invoice identity absent/duplicate")
        seen.add(identifier)
        if invoice.get("TaxAuthorityStatus") == "CANCELLED":
            return False, "INVOICE_CANCELLED"
        _required(invoice.get("AccountId") == binding["payer_account_id"] and (invoice.get("Entity") or {}).get("InvoicingEntity") == binding["invoice_entity"], "native invoice payer/entity mismatch")
        amount = invoice.get("BaseCurrencyAmount") or {}
        _required(amount.get("CurrencyCode") == binding["currency"], "native invoice currency mismatch; FX is not supported")
        period = invoice.get("BillingPeriod") or {}
        year, month = period.get("Year"), period.get("Month")
        _required(type(year) is int and type(month) is int and 1 <= month <= 12, "native invoice billing period required")
        left = datetime(year, month, 1, tzinfo=timezone.utc)
        right = datetime(year + (month == 12), 1 if month == 12 else month + 1, 1, tzinfo=timezone.utc)
        if not _proof_coverage(snapshot, binding, left, right, final=True, allow_incomplete=True):
            return False, "BILLING_EXPORT_NOT_FINAL"
        if invoice.get("InvoiceType") != "INVOICE" or invoice.get("TaxAuthorityStatus") != "ISSUED":
            return False, "NATIVE_INVOICE_NOT_ISSUED"
        issued = instant(invoice.get("IssuedDate"))
        _required(issued >= right and issued <= as_of, "invoice issued date does not cover finalized billing period")
        selected = []
        for row in rows:
            raw = row["x_ProviderFields"]
            invoice_id = raw.get("bill_invoice_id", raw.get("bill/InvoiceId"))
            _required(row.get("BillingAccountId") == binding["payer_account_id"] and row.get("InvoiceIssuerName") == binding["invoice_entity"] and row.get("BillingCurrency") == binding["currency"], "invoice scope mixes payer/entity/currency")
            if invoice_id == identifier:
                charge_start, charge_end = instant(row.get("ChargePeriodStart")), instant(row.get("ChargePeriodEnd"))
                _required(left <= charge_start < charge_end <= right, "invoice row outside native billing period")
                selected.append(row)
        if not selected: return False, "NATIVE_INVOICE_SOURCE_UNAVAILABLE"
        total = sum((decimal(row["BilledCost"]) for row in selected), ZERO)
        native_total = decimal(amount.get("TotalAmount"), "native invoice total")
        ratio = max(ZERO, Decimal(1) - abs(total - native_total) / abs(native_total)) if native_total else (Decimal(1) if total == ZERO else ZERO)
        if ratio < Decimal("0.995"):
            return False, "RECONCILIATION_BELOW_THRESHOLD"
        periods.append((left, right))
    if not _coverage(periods, start, end): return False, "INVOICE_PERIOD_INCOMPLETE"
    if not all(row["x_ProviderFields"].get("bill_invoice_id", row["x_ProviderFields"].get("bill/InvoiceId")) in seen for row in rows):
        return False, "NATIVE_INVOICE_SOURCE_UNAVAILABLE"
    scoped = {identity: row for identity, row in zip(identities, rows)}
    for row in snapshot.get("billing_records", []):
        identity = row.get("x_SourceId"), row.get("x_SourceVersion"), row.get("x_SourceRecordId")
        _required(identity in scoped and row.get("x_ProviderFields") == scoped[identity].get("x_ProviderFields"), "target billing differs from reconciled invoice source")
    return True, "NATIVE_INVOICES_RECONCILED"


def evaluate_v3(data):
    _required(isinstance(data, dict) and str(data.get("schema_version")) == "3", "schema_version 3 required")
    binding = data.get("binding")
    _required(isinstance(binding, dict) and all(isinstance(binding.get(key), str) and binding[key] for key in IDENTITY), "complete native billing binding required")
    _required(binding["region"] == "eu-west-1" and re.fullmatch(r"\d{12}", binding["account_id"]) and re.fullmatch(r"\d{12}", binding["payer_account_id"]) and re.fullmatch(r"[A-Z]{3}", binding["currency"]), "invalid native account/region/currency binding")
    _required(data.get("proof_set_id") and data.get("baseline_id"), "immutable proof set and baseline required")
    _required(data.get("phase") in ("BASELINE", "MEASUREMENT"), "invalid evidence phase")
    baseline = data.get("baseline")
    base_start, base_end = _period(baseline, "baseline")
    try:
        zone = ZoneInfo(baseline["schedule"]["timezone"])
    except (KeyError, TypeError, ZoneInfoNotFoundError) as exc:
        raise EvidenceError("explicit IANA timezone required") from exc
    activation, as_of = instant(data.get("activation_at")), instant(data.get("as_of"))
    _required(base_end <= activation <= as_of and activation - base_end <= timedelta(hours=48), "latest complete baseline billing day must be within 48 hours of activation")
    base_days = _calendar_days(base_start, base_end, zone)
    _required(base_days == 14, "fourteen complete baseline calendar days required")
    _proof_coverage(baseline, binding, base_start, base_end)
    commitments = validate_commitments(baseline.get("commitment_scope"), binding)
    base_rows = _billing(baseline, binding, base_start, base_end)
    base_unallocated = _scope_retained(baseline, binding, base_start, base_end, base_rows)
    base_risk = _native_scope_risk(baseline, binding, base_start, base_end)
    base_samples, definition = _activity(baseline, binding, base_start, base_end)
    base_windows = _windows(base_start, base_end, baseline["schedule"], zone)
    complete_base, base_states = _observations(baseline, base_rows, binding, base_start, base_end, [], baseline=True)
    activity_complete = _coverage([(a, b) for a, b, _, _ in base_samples], base_start, base_end)
    native_compute = [row for row in base_rows if row["compute"]]
    commitments = commitments and bool(native_compute) and all(row["uncovered"] and row["cost"] is not None and row["cost"] >= ZERO for row in native_compute)
    pre_ready = complete_base and activity_complete and commitments and not base_risk and bool(base_windows) and _idle(base_samples, base_windows)
    reason = "VERIFICATION_WINDOW_INCOMPLETE"
    if not complete_base: reason = "BASELINE_BILLING_UNKNOWN"
    elif not activity_complete: reason = "WORKLOAD_EVIDENCE_MISSING"
    elif base_risk: reason = base_risk
    elif not commitments: reason = "COMMITMENT_UNKNOWN_OR_COVERED"
    elif not base_windows or not _idle(base_samples, base_windows): reason = "BASELINE_WORKLOAD_ACTIVE"
    status = "MEASURING" if pre_ready else "BLOCKED"
    expected = actual = incremental = ZERO
    coverage, states, verification_days, actual_known, calculated = [], {}, 0, False, False
    measurement = data.get("measurement")
    with localcontext() as context:
        context.prec = 60
        if data["phase"] == "MEASUREMENT":
            _required(data.get("measurement_id"), "measurement reservation required")
            start, end = _period(measurement, "measurement")
            _required(start >= activation, "measurement precedes activation")
            verification_days = _calendar_days(start, end, zone)
            _required(0 < verification_days <= 31, "measurement period outside pilot bounds")
            post_complete = _proof_coverage(measurement, binding, start, end, allow_incomplete=True)
            post_commitments = validate_commitments(measurement.get("commitment_scope"), binding)
            rows = _billing(measurement, binding, start, end)
            unallocated = _scope_retained(measurement, binding, start, end, rows, require_complete=post_complete)
            post_risk = _native_scope_risk(measurement, binding, start, end)
            samples, post_definition = _activity(measurement, binding, start, end)
            _required(definition == post_definition, "measurement changed activity metric definition")
            windows = _windows(start, end, baseline["schedule"], zone)
            coverage = [{"start": left.isoformat(), "end": right.isoformat()} for left, right in windows]
            owned, executions = _owned(measurement, start, end, activation, windows)
            actual_known, states = _observations(measurement, rows, binding, start, end, owned)
            actual_known = actual_known and post_complete
            if not pre_ready: pass
            elif end > as_of or verification_days < 14: reason = "VERIFICATION_WINDOW_INCOMPLETE"
            elif not post_commitments or not all(row["uncovered"] and row["cost"] is not None for row in rows if row["compute"]): status, reason = "BLOCKED", "COMMITMENT_UNKNOWN_OR_COVERED"
            elif post_risk: status, reason = "BLOCKED", post_risk
            elif not post_complete: reason = "BILLING_EXPORT_INCOMPLETE"
            elif not actual_known: reason = "BILLING_OBSERVATION_UNKNOWN"
            elif not _coverage([(a, b) for a, b, _, _ in samples], start, end): reason = "WORKLOAD_EVIDENCE_MISSING"
            elif not _idle(samples, windows) or not _work_preserved(base_samples, base_start, base_end, samples, start, end, zone): status, reason = "CONFOUNDED", "WORKLOAD_ADJUSTMENT_REQUIRED"
            elif not owned: status, reason = "BLOCKED", "OWNED_EXECUTION_REQUIRED"
            elif _unallocated_increase(base_unallocated, unallocated, base_start, base_end, start, end): status, reason = "BLOCKED", "ALLOCATION_SCOPE_REQUIRED"
            else:
                for left, right in windows:
                    matches = [(a, b) for a, b in base_windows if a.astimezone(zone).isoweekday() == left.astimezone(zone).isoweekday() and a.astimezone(zone).time().replace(tzinfo=None) == left.astimezone(zone).time().replace(tzinfo=None) and b - a == right - left]
                    _required(matches, "no calendar-matched baseline window")
                    reference = sum((_cost(base_rows, a, b) for a, b in matches), ZERO) / Decimal(len(matches))
                    charge = _cost(rows, left, right)
                    stopped = sum((_seconds(_overlap(a, b, left, right)) for a, b in owned), ZERO)
                    if reference - charge > reference * stopped / _seconds(right - left) + Decimal("0.000000000001"):
                        status, reason = "CONFOUNDED", "UNOWNED_RUNTIME_CHANGE"
                    expected += reference; actual += charge
                calculated = True
                attributed = _incremental(base_rows, rows, base_start, base_end, start, end, executions)
                if attributed is None:
                    status, reason = "BLOCKED", "INCREMENTAL_COST_ATTRIBUTION_UNKNOWN"
                else:
                    incremental = attributed
                if status not in ("BLOCKED", "CONFOUNDED"):
                    final, reason = _invoices(measurement, binding, start, end, as_of)
                    status = "VERIFIED" if final else "MEASURING"
        saving = expected - actual - incremental
        canonical = json.dumps(data, sort_keys=True, separators=(",", ":"), allow_nan=False)
        claim = json.dumps({"binding": binding, "coverage": coverage}, sort_keys=True, separators=(",", ":"))
        return {"schema_version": "3", "status": status, "reason_code": reason, "pre_execution_ready": pre_ready,
                "binding": binding, "resource_id": binding["resource_id"], "currency": binding["currency"], "proof_set_id": data["proof_set_id"], "baseline_id": data["baseline_id"], "measurement_id": data.get("measurement_id"),
                "readiness": {"baseline_ready": pre_ready, "baseline_days": base_days, "workload_complete": activity_complete, "commitment_known": commitments},
                "pricing_basis": sorted({row["basis"] for row in base_rows if row["compute"]}), "billing_observations": {"baseline": {key: str(value) for key, value in base_states.items()}, "measurement": {key: str(value) for key, value in states.items()}},
                "expected_baseline_cost": money(expected) if calculated else None, "actual_cost": money(actual) if actual_known and calculated else None, "incremental_cost": money(incremental) if actual_known and calculated else None,
                "observed_saving": money(saving) if actual_known and calculated else None, "verified_saving": money(saving) if status == "VERIFIED" else None,
                "annualised_estimate": money(saving * Decimal(365) / Decimal(verification_days)) if status == "VERIFIED" else None,
                "confidence": "HIGH" if status == "VERIFIED" else "MEDIUM" if pre_ready else "LOW", "baseline_days": base_days, "verification_days": verification_days,
                "coverage_intervals": coverage, "fingerprint": hashlib.sha256(canonical.encode()).hexdigest(), "claim_key": hashlib.sha256(claim.encode()).hexdigest(),
                "baseline_model": "source_bound_native_calendar_idle_windows_v3", "normalization_unit": definition[2]}
