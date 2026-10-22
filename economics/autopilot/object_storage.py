"""Read-only S3 cohort decisions from server-selected immutable evidence.

Receipt authentication/currentness and population streaming belong to the Go
ingester. This pure boundary checks typed quantities, population arithmetic,
class semantics and cost assumptions; it never turns object age into access.
No result authorises lifecycle, object, deletion, restore or network actions.
"""
from datetime import timedelta
from decimal import Decimal, ROUND_HALF_EVEN, localcontext
import hashlib
import json
import re

from .model import EvidenceError, decimal, instant

SCHEMA_VERSION = "1"
MODEL_VERSION = "object-storage-v1"
MODEL_KIND = "OBJECT_STORAGE_ASSESSMENT_V1"
ROUTE = "/v9/object-storage-assessment"
CLASS_SEMANTICS_VERSION = "aws-s3-general-purpose-2026-10-20"
# Versioned selected public capability facts, never a native API response or a
# customer price. Their hash is independent of all financial source revisions.
CLASS_SEMANTICS = {
    "version": CLASS_SEMANTICS_VERSION,
    "sources": ["https://aws.amazon.com/s3/pricing/",
                "https://docs.aws.amazon.com/AmazonS3/latest/userguide/intelligent-tiering-overview.html",
                "https://docs.aws.amazon.com/AmazonS3/latest/userguide/lifecycle-transition-general-considerations.html"],
    "minimum_billable_bytes": {"STANDARD_IA": "131072", "ONEZONE_IA": "131072", "GLACIER_INSTANT_RETRIEVAL": "131072"},
    "minimum_storage_days": {"STANDARD_IA": "30", "ONEZONE_IA": "30", "GLACIER_INSTANT_RETRIEVAL": "90", "GLACIER_FLEXIBLE_RETRIEVAL": "90", "DEEP_ARCHIVE": "180"},
    "archive_metadata_bytes": {"STANDARD": "8192", "ARCHIVE": "32768"},
    "it_auto_tiering_minimum_bytes": "131072", "it_monitoring_for_smaller_objects": False,
    "it_no_access_days": {"INFREQUENT": "30", "ARCHIVE_INSTANT": "90", "ARCHIVE": "90", "DEEP_ARCHIVE": "180"},
    "current_lifecycle_default_minimum_bytes": "131072", "legacy_lifecycle_default_requires_observation": True,
    "standard_restore_scenario_seconds": {"GLACIER_FLEXIBLE_RETRIEVAL": "18000", "DEEP_ARCHIVE": "43200"},
    "restore_latency_is_guaranteed": False,
}
GIB = Decimal(1073741824)
KIB = Decimal(1024)
# A storage month is explicitly the held730-hour scenario; arithmetic is done
# inside the evaluator's80-digit context, not rounded at module import.
MONTH_HOURS = Decimal(730)
CLASSES = ("STANDARD", "INTELLIGENT_TIERING", "STANDARD_IA", "ONEZONE_IA",
           "GLACIER_INSTANT_RETRIEVAL", "GLACIER_FLEXIBLE_RETRIEVAL", "DEEP_ARCHIVE")
ALIASES = {"GLACIER_IR": "GLACIER_INSTANT_RETRIEVAL", "GLACIER": "GLACIER_FLEXIBLE_RETRIEVAL"}
TIERS = ("FREQUENT", "INFREQUENT", "ARCHIVE_INSTANT", "ARCHIVE", "DEEP_ARCHIVE")
MIN_DAYS = {"STANDARD_IA": Decimal(30), "ONEZONE_IA": Decimal(30),
            "GLACIER_INSTANT_RETRIEVAL": Decimal(90), "GLACIER_FLEXIBLE_RETRIEVAL": Decimal(90),
            "DEEP_ARCHIVE": Decimal(180)}
RESTORE_SECONDS = {"GLACIER_INSTANT_RETRIEVAL": Decimal(0),
                   "GLACIER_FLEXIBLE_RETRIEVAL": Decimal(18000), "DEEP_ARCHIVE": Decimal(43200)}
KINDS = ("S3_STANDARD_TO_INTELLIGENT_TIERING", "S3_STANDARD_TO_STANDARD_IA", "S3_ARCHIVE_CLASS_REVIEW",
         "S3_INTELLIGENT_TIERING_POLICY", "S3_NONCURRENT_VERSION_REVIEW", "S3_MULTIPART_UPLOAD_REVIEW",
         "S3_SMALL_OBJECT_ECONOMICS")
BINDING = ("tenant_id", "resource_id", "account_id", "region", "provider", "provider_resource_id", "workload_id")
COMPONENTS = {"storage": "GiB-Mo", "request": "Request", "retrieval": "GiB", "transition": "Request",
              "monitoring": "Object-Mo", "restore_request": "Request", "restore_storage": "GiB-Mo"}


def _obj(value, allowed=None):
    if not isinstance(value, dict) or allowed is not None and set(value) - set(allowed):
        raise EvidenceError("unsupported object-storage object fields")
    return value


def _text(value):
    if not isinstance(value, str) or not value or len(value) > 2048 or any(ord(c) < 32 for c in value):
        raise EvidenceError("object-storage identity required")
    return value


def _n(value, *, optional=False, integral=False):
    if value is None and optional:
        return None
    result = decimal(value, "object-storage quantity")
    if result < 0 or integral and result != result.to_integral_value():
        raise EvidenceError("invalid object-storage nonnegative quantity")
    return result


def _bool(value, reasons, reason):
    if value is not None and type(value) is not bool:
        raise EvidenceError("object-storage boolean required")
    if value is not True:
        reasons.add(reason)
    return value


def _money(value):
    with localcontext() as context:
        context.prec = 80
        result = value.quantize(Decimal("0.000000000001"), rounding=ROUND_HALF_EVEN)
    if abs(result) >= Decimal("1e26"):
        raise EvidenceError("object-storage result exceeds DECIMAL(38,12)")
    return format(result, "f")


def _month_days():
    return MONTH_HOURS / Decimal(24)


def _hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def _ref(value, refs, reasons, label):
    if value is None:
        reasons.add("S3_IMMUTABLE_REFERENCE_REQUIRED:" + label)
        return False
    _obj(value, ("kind", "id", "version", "sha256"))
    for key in ("kind", "id", "version"):
        _text(value.get(key))
    if not isinstance(value.get("sha256"), str) or not re.fullmatch("[a-f0-9]{64}", value["sha256"]):
        raise EvidenceError("object-storage immutable hash required")
    key = (value["kind"], value["id"], value["version"])
    if key in refs and refs[key] != value:
        raise EvidenceError("conflicting object-storage immutable reference")
    refs[key] = value
    return True


def _stamp(value):
    if not isinstance(value, str) or not (value.endswith("Z") or value.endswith("+00:00")):
        raise EvidenceError("object-storage UTC timestamp required")
    return instant(value)


def _class(value):
    value = ALIASES.get(value, value)
    return _text(value)


def _population(cohort, reasons):
    count, size = _n(cohort.get("object_count"), integral=True), _n(cohort.get("total_bytes"), integral=True)
    bands = cohort.get("size_bands")
    if not isinstance(bands, list) or not 1 <= len(bands) <= 128:
        raise EvidenceError("object-storage exact size bands required")
    totals = [Decimal(0), Decimal(0), Decimal(0), Decimal(0), Decimal(0)]
    for band in bands:
        _obj(band, ("count", "total_bytes", "min_bytes", "max_bytes"))
        n, b, low, high = (_n(band.get(k), integral=True) for k in ("count", "total_bytes", "min_bytes", "max_bytes"))
        if low > high or b < n * low or b > n * high or n == 0 and b != 0:
            raise EvidenceError("object-storage band arithmetic mismatch")
        totals[0] += n
        totals[1] += b
        if high < 128 * KIB:
            totals[2] += n * 128 * KIB
            totals[3] += n
            totals[4] += b
        elif low >= 128 * KIB:
            totals[2] += b
        else:
            reasons.add("S3_SIZE_BAND_CROSSES_BILLABLE_MINIMUM")
    if totals[0] != count or totals[1] != size:
        raise EvidenceError("object-storage population total mismatch")
    if not isinstance(cohort.get("population_hash"), str) or not re.fullmatch("[a-f0-9]{64}", cohort["population_hash"]):
        raise EvidenceError("object-storage exact population hash required")
    return {"count": count, "bytes": size, "minimum_bytes": totals[2], "small_count": totals[3], "small_bytes": totals[4]}


def _access(cohort, policy, now, refs, reasons):
    raw = _obj(cohort.get("access") or {}, ("state", "start", "end", "complete", "requests", "retrieved_bytes",
                                                  "eligible_cold_bytes_fraction", "it_tier_fractions", "source_ref"))
    state = raw.get("state", "ACCESS_UNKNOWN")
    if state not in ("ACCESS_PATTERN_OBSERVED", "AGE_OBSERVED", "ACCESS_UNKNOWN"):
        raise EvidenceError("object-storage access state unsupported")
    result = {"state": state, "days": None, "requests": None, "retrieved_bytes": None,
              "cold_fraction": None, "tiers": None, "complete": False, "start": raw.get("start"), "end": raw.get("end")}
    if state != "ACCESS_PATTERN_OBSERVED":
        reasons.add("S3_ACCESS_PATTERN_UNKNOWN")
        return result
    if not _ref(raw.get("source_ref"), refs, reasons, "ACCESS"):
        return result
    start, end = _stamp(raw.get("start")), _stamp(raw.get("end"))
    if end <= start or end > now or any((x.hour, x.minute, x.second, x.microsecond) != (0, 0, 0, 0) for x in (start, end)):
        raise EvidenceError("object-storage complete-day access window invalid")
    days = Decimal((end - start).days)
    required = 90 if policy.get("high_seasonality") is True else 14 if policy.get("criticality") == "NON_PRODUCTION" else 30
    if days < required:
        reasons.add("S3_ACCESS_HISTORY_INSUFFICIENT")
    if now - end > timedelta(hours=48):
        reasons.add("S3_ACCESS_HISTORY_STALE")
    _bool(raw.get("complete"), reasons, "S3_ACCESS_COVERAGE_INCOMPLETE")
    result.update(days=days, requests=_n(raw.get("requests"), optional=True, integral=True),
                  retrieved_bytes=_n(raw.get("retrieved_bytes"), optional=True, integral=True),
                  cold_fraction=_n(raw.get("eligible_cold_bytes_fraction"), optional=True))
    if result["requests"] is None or result["retrieved_bytes"] is None:
        reasons.add("S3_ACCESS_REQUEST_OR_RETRIEVAL_UNKNOWN")
    if result["cold_fraction"] is not None and result["cold_fraction"] > 1:
        raise EvidenceError("object-storage cold fraction outside bounds")
    tiers = raw.get("it_tier_fractions")
    if tiers is not None:
        _obj(tiers, TIERS)
        if set(tiers) != set(TIERS):
            raise EvidenceError("all object-storage tier fractions required")
        result["tiers"] = {key: _n(value) for key, value in tiers.items()}
        if sum(result["tiers"].values()) != 1:
            raise EvidenceError("object-storage tier fractions do not conserve population")
        if result["tiers"]["INFREQUENT"] > 0 and days < 30 or result["tiers"]["ARCHIVE_INSTANT"] > 0 and days < 90:
            reasons.add("S3_TIER_RESIDENCE_HISTORY_INSUFFICIENT")
        if result["tiers"]["ARCHIVE"] > 0 and days < 90 or result["tiers"]["DEEP_ARCHIVE"] > 0 and days < 180:
            reasons.add("S3_TIER_RESIDENCE_HISTORY_INSUFFICIENT")
    result["complete"] = raw.get("complete") is True and days >= required and now - end <= timedelta(hours=48)
    return result


def _prices(cohort, refs, reasons):
    raw = _obj(cohort.get("pricing") or {}, ("basis", "currency", "components", "continuing_monthly_cost", "source_ref"))
    basis, currency = raw.get("basis", "UNAVAILABLE"), raw.get("currency")
    if basis not in ("AWS_CUR_NET_USAGE", "REFERENCE_ONLY", "UNAVAILABLE"):
        raise EvidenceError("object-storage pricing basis unsupported")
    if currency is not None and not re.fullmatch("[A-Z]{3}", currency):
        raise EvidenceError("object-storage source currency invalid")
    if basis != "AWS_CUR_NET_USAGE" or currency is None:
        reasons.add("S3_CUSTOMER_ECONOMICS_UNAVAILABLE")
    _ref(raw.get("source_ref"), refs, reasons, "PRICING")
    components = raw.get("components", [])
    if not isinstance(components, list) or len(components) > 512:
        raise EvidenceError("object-storage pricing component bound")
    rates = {}
    for part in components:
        _obj(part, ("class", "component", "unit", "rate", "source_ref"))
        kind, name = _class(part.get("class")), part.get("component")
        if name not in COMPONENTS or part.get("unit") != COMPONENTS[name]:
            raise EvidenceError("object-storage pricing component unit mismatch")
        rate = _n(part.get("rate"))
        _ref(part.get("source_ref"), refs, reasons, "PRICE_COMPONENT")
        key = kind, name
        if key in rates:
            raise EvidenceError("ambiguous object-storage price tier/component")
        rates[key] = rate
    # Native credits remain signed and continue unchanged in both scenarios.
    # They are not a new saving and cannot reduce the coverage denominator.
    continuing = decimal(raw["continuing_monthly_cost"], "signed continuing charges") if raw.get("continuing_monthly_cost") is not None else None
    if continuing is None:
        reasons.add("S3_CONTINUING_CHARGES_UNKNOWN")
    return {"basis": basis, "currency": currency, "rates": rates, "continuing": continuing}


def _component(rates, cls, name, quantity, reasons):
    if quantity == 0:
        return Decimal(0)
    rate = rates.get((cls, name))
    if rate is None:
        reasons.add("S3_CUSTOMER_RATE_UNAVAILABLE:" + cls + ":" + name)
        return None
    return quantity * rate


def _add(values):
    return None if any(value is None for value in values) else sum(values, Decimal(0))


def _monthly(cls, population, access, pricing, reasons, tiers=None):
    rates = pricing["rates"]
    n, size = population["count"], population["bytes"]
    req = retrieved = None
    if access["requests"] is not None and access["days"]:
        req = access["requests"] * _month_days() / access["days"]
    if access["retrieved_bytes"] is not None and access["days"]:
        retrieved = access["retrieved_bytes"] / GIB * _month_days() / access["days"]
    if req is None or retrieved is None:
        reasons.add("S3_ACCESS_REQUEST_OR_RETRIEVAL_UNKNOWN")
    if cls == "INTELLIGENT_TIERING":
        if tiers is None:
            reasons.add("S3_IT_TIER_DISTRIBUTION_UNKNOWN")
            storage = None
        else:
            eligible = size - population["small_bytes"]
            storage = _component(rates, "IT_FREQUENT", "storage", population["small_bytes"] / GIB, reasons)
            amounts = [storage]
            for tier in TIERS:
                amounts.append(_component(rates, "IT_" + tier, "storage", eligible / GIB * tiers[tier], reasons))
            # Native cohorts are normally split by actual access tier. A
            # homogeneous archive cohort establishes its exact object count;
            # mixed byte fractions cannot manufacture that object count.
            if tiers["ARCHIVE"] > 0 or tiers["DEEP_ARCHIVE"] > 0:
                archived = "ARCHIVE" if tiers["ARCHIVE"] == 1 else "DEEP_ARCHIVE" if tiers["DEEP_ARCHIVE"] == 1 else None
                if archived is None or population["small_count"] > 0:
                    reasons.add("S3_IT_ARCHIVE_OBJECT_COUNT_UNAVAILABLE")
                    amounts.append(None)
                else:
                    amounts.append(_component(rates, "STANDARD", "storage", n * 8 * KIB / GIB, reasons))
                    amounts.append(_component(rates, "IT_" + archived, "storage", n * 32 * KIB / GIB, reasons))
            storage = _add(amounts)
        monitoring = _component(rates, cls, "monitoring", n - population["small_count"], reasons)
    else:
        billable = population["minimum_bytes"] if cls in ("STANDARD_IA", "ONEZONE_IA", "GLACIER_INSTANT_RETRIEVAL") else size
        storage = _component(rates, cls, "storage", billable / GIB, reasons)
        if cls in ("GLACIER_FLEXIBLE_RETRIEVAL", "DEEP_ARCHIVE"):
            storage = _add([storage, _component(rates, "STANDARD", "storage", n * 8 * KIB / GIB, reasons),
                            _component(rates, cls, "storage", n * 32 * KIB / GIB, reasons)])
        monitoring = Decimal(0)
    request = _component(rates, cls, "request", req, reasons) if req is not None else None
    retrieval = Decimal(0) if cls in ("STANDARD", "INTELLIGENT_TIERING") else _component(rates, cls, "retrieval", retrieved, reasons) if retrieved is not None else None
    restore_request = restore_storage = Decimal(0)
    if cls in ("GLACIER_FLEXIBLE_RETRIEVAL", "DEEP_ARCHIVE"):
        # Every access may require restoration. Use an explicit conservative
        # one-day restored copy per retrieved byte; no free restore assumption.
        restore_request = _component(rates, cls, "restore_request", req, reasons) if req is not None else None
        restore_storage = _component(rates, cls, "restore_storage", retrieved / _month_days(), reasons) if retrieved is not None else None
    components = {"storage": storage, "requests": request, "retrieval": retrieval, "monitoring": monitoring,
                  "restore_requests": restore_request, "restore_storage": restore_storage, "continuing": pricing["continuing"]}
    return _add(list(components.values())), components


def _economics(cohort, current, target, population, access, pricing, horizon, reasons, tiers=None):
    cost_reasons = set()
    before, before_parts = _monthly(current, population, access, pricing, cost_reasons,
                                    access["tiers"] if current == "INTELLIGENT_TIERING" else None)
    after, after_parts = _monthly(target, population, access, pricing, cost_reasons, tiers)
    transition = _component(pricing["rates"], target, "transition", population["count"], cost_reasons)
    remaining = _n(cohort.get("minimum_duration_remaining_days"), optional=True)
    exit_penalty = Decimal(0)
    baseline_penalty = Decimal(0)
    if current in MIN_DAYS:
        if remaining is None:
            cost_reasons.add("S3_CURRENT_MINIMUM_DURATION_REMAINING_UNKNOWN")
            exit_penalty = None
            baseline_penalty = None
        else:
            if remaining > MIN_DAYS[current]:
                raise EvidenceError("object-storage remaining minimum duration exceeds native class minimum")
            # Only the storage obligation continues; requests/continuing costs
            # are not multiplied into minimum-duration charges.
            exit_penalty = before_parts["storage"] * remaining / _month_days() if before_parts["storage"] is not None else None
            # Leaving the current policy unchanged also incurs its remaining
            # native duration obligation when the evidenced lifetime ends.
            baseline_penalty = before_parts["storage"] * max(remaining - horizon, Decimal(0)) / _month_days() if before_parts["storage"] is not None and horizon is not None else None
    candidate_penalty = None
    if horizon is not None:
        unmet = max(Decimal(0), MIN_DAYS.get(target, Decimal(0)) - horizon)
        candidate_penalty = after_parts["storage"] * unmet / _month_days() if after_parts["storage"] is not None else None
    else:
        cost_reasons.add("S3_REMAINING_LIFETIME_UNKNOWN")
    initialization = Decimal(0)
    if target == "INTELLIGENT_TIERING" and tiers is not None and horizon is not None:
        # Existing object age never backdates the new native access timer.
        # Even the evidenced cold population begins in Frequent Access.
        size = (population["bytes"] - population["small_bytes"]) / GIB
        steady = _add([_component(pricing["rates"], "IT_" + tier, "storage", size * tiers[tier], cost_reasons) for tier in TIERS])
        first = _component(pricing["rates"], "IT_FREQUENT", "storage", size, cost_reasons)
        second = _add([_component(pricing["rates"], "IT_FREQUENT", "storage", size * tiers["FREQUENT"], cost_reasons),
                       _component(pricing["rates"], "IT_INFREQUENT", "storage", size * (tiers["INFREQUENT"] + tiers["ARCHIVE_INSTANT"]), cost_reasons)])
        initialization = _add([(first - steady) * min(horizon, Decimal(30)) / _month_days() if first is not None and steady is not None else None,
                               (second - steady) * min(max(horizon - 30, Decimal(0)), Decimal(60)) / _month_days() if second is not None and steady is not None else None])
    total_before = _add([before * horizon / _month_days() if before is not None and horizon is not None else None, baseline_penalty])
    total_after = _add([after * horizon / _month_days() if after is not None and horizon is not None else None,
                        transition, exit_penalty, candidate_penalty, initialization])
    saving = total_before - total_after if total_before is not None and total_after is not None else None
    # A reference scenario is not a native customer saving, even if all public
    # list-price components happen to be present.
    native = pricing["basis"] == "AWS_CUR_NET_USAGE" and not cost_reasons and not reasons
    out = {"status": "AVAILABLE" if native else "UNAVAILABLE", "basis": pricing["basis"], "currency": pricing["currency"],
           "current_monthly_cost": _money(before) if before is not None and native else None,
           "candidate_monthly_cost": _money(after) if after is not None and native else None,
           "transition_cost": _money(transition) if transition is not None and native else None,
           "current_minimum_duration_penalty": _money(exit_penalty) if exit_penalty is not None and native else None,
           "baseline_minimum_duration_penalty": _money(baseline_penalty) if baseline_penalty is not None and native else None,
           "candidate_minimum_duration_penalty": _money(candidate_penalty) if candidate_penalty is not None and native else None,
           "tier_initialization_cost": _money(initialization) if initialization is not None and native else None,
           "horizon_days": _money(horizon) if horizon is not None else None,
           "current_horizon_cost": _money(total_before) if total_before is not None and native else None,
           "candidate_horizon_cost": _money(total_after) if total_after is not None and native else None,
           "net_horizon_saving": _money(saving) if saving is not None and native else None,
           "estimated_monthly_saving": _money(saving * _month_days() / horizon) if saving is not None and horizon is not None and horizon > 0 and native else None,
           "estimated_annual_saving": _money(saving * Decimal(365) / horizon) if saving is not None and horizon is not None and horizon >= 365 and native else None,
           "recurring_monthly_saving": _money(before - after) if before is not None and after is not None and native else None,
           "component_costs": [{"component": key, "current_monthly_cost": _money(before_parts[key]) if before_parts[key] is not None and native else None,
                                "candidate_monthly_cost": _money(after_parts[key]) if after_parts[key] is not None and native else None} for key in before_parts],
           "reference_scenario": None, "verified_saving": None}
    if pricing["basis"] == "REFERENCE_ONLY":
        out["reference_scenario"] = {"currency": pricing["currency"], "current_horizon_cost": _money(total_before) if total_before is not None else None,
                                     "candidate_horizon_cost": _money(total_after) if total_after is not None else None,
                                     "meaning": "PUBLIC_REFERENCE_ONLY_NOT_CUSTOMER_SAVINGS"}
    reasons.update(cost_reasons)
    return out


def _empty_economics(pricing=None):
    return {"status": "UNAVAILABLE", "basis": pricing["basis"] if pricing else "UNAVAILABLE", "currency": pricing["currency"] if pricing else None,
            "current_monthly_cost": None, "candidate_monthly_cost": None, "estimated_monthly_saving": None,
            "estimated_annual_saving": None, "verified_saving": None, "component_costs": []}


def _candidate(kind, cohort, target, reasons, economics=None, review=False, already=False):
    economics = economics or _empty_economics()
    positive = economics.get("net_horizon_saving") is not None and decimal(economics["net_horizon_saving"]) > 0
    status = "NO_CHANGE" if already else "OBSERVATION_ONLY" if review else "BLOCKED" if reasons else "RECOMMENDED" if positive else "NO_CHANGE"
    if not reasons and not review and not already and not positive:
        reasons.add("S3_TOTAL_ECONOMICS_DO_NOT_JUSTIFY_TRANSITION")
    if already:
        reasons.add("S3_CURRENT_LIFECYCLE_ALREADY_IMPLEMENTS_POLICY")
        # An existing scheduled transition belongs to the current-policy
        # counterfactual. It is not a new incremental recommendation saving.
        for key in ("estimated_monthly_saving", "estimated_annual_saving", "recurring_monthly_saving", "net_horizon_saving"):
            if key in economics:
                economics[key] = None
    return {"id": _hash({"cohort_id": cohort["id"], "kind": kind, "target": target})[:32], "cohort_id": cohort["id"],
            "recommendation_kind": kind, "candidate_storage_class": target, "status": status,
            "reason_code": "S3_REVIEW_REQUIRED" if review else "S3_ALREADY_IMPLEMENTED" if already else "S3_ECONOMICALLY_SUPPORTED" if status == "RECOMMENDED" else "S3_EVIDENCE_BLOCKED" if status == "BLOCKED" else "S3_DO_NOT_TRANSITION",
            "blockers": sorted(reasons), "economics": economics, "risk_class": "R3", "executable": False,
            "execution_authorized": False, "verified_saving": None}


def _evaluate(data):
    _obj(data, ("schema_version", "model_version", "binding", "as_of", "configuration", "cohorts", "policy", "source_refs"))
    if data.get("schema_version") != SCHEMA_VERSION or data.get("model_version") != MODEL_VERSION:
        raise EvidenceError("unsupported object-storage schema/model")
    binding = _obj(data.get("binding"), BINDING)
    if set(binding) != set(BINDING):
        raise EvidenceError("object-storage binding incomplete")
    for key in BINDING:
        if key != "workload_id" or binding[key] is not None:
            _text(binding[key])
    if binding["provider"] != "AWS" or not re.fullmatch("[0-9]{12}", binding["account_id"]) or not binding["provider_resource_id"].startswith("arn:aws:s3:::"):
        raise EvidenceError("object-storage native binding invalid")
    now, refs, base = _stamp(data.get("as_of")), {}, set()
    config = _obj(data.get("configuration") or {}, ("owner", "configuration_authority", "versioning", "lifecycle_state", "replication_state", "object_lock_state", "source_ref"))
    _ref(config.get("source_ref"), refs, base, "CONFIGURATION")
    if not config.get("owner") or not binding["workload_id"]:
        base.add("S3_WORKLOAD_OWNERSHIP_UNKNOWN")
    authority = config.get("configuration_authority", "UNKNOWN")
    if authority not in ("TERRAFORM", "CLOUDFORMATION", "MANUAL", "UNKNOWN"):
        raise EvidenceError("object-storage configuration authority unsupported")
    if authority == "UNKNOWN":
        base.add("S3_CONFIGURATION_AUTHORITY_UNKNOWN")
    if config.get("lifecycle_state") != "KNOWN":
        base.add("S3_LIFECYCLE_CONFIGURATION_UNKNOWN")
    if config.get("replication_state") not in ("NONE", "KNOWN"):
        base.add("S3_REPLICATION_CONFIGURATION_UNKNOWN")
    if config.get("object_lock_state") not in ("DISABLED", "KNOWN"):
        base.add("S3_OBJECT_LOCK_CONFIGURATION_UNKNOWN")
    if config.get("versioning") not in ("ENABLED", "SUSPENDED", "DISABLED"):
        base.add("S3_VERSIONING_UNKNOWN")
    policy = _obj(data.get("policy") or {}, ("criticality", "high_seasonality", "remaining_lifetime_days", "rto_seconds", "retention_known", "compliance_clear", "recovery_known", "allow_onezone", "source_ref"))
    _ref(policy.get("source_ref"), refs, base, "POLICY")
    if policy.get("criticality") not in ("NON_PRODUCTION", "TIER_0", "TIER_1", "TIER_2", "TIER_3") or type(policy.get("high_seasonality")) is not bool:
        base.add("S3_WORKLOAD_SAFETY_PROFILE_UNKNOWN")
    for field in ("retention_known", "compliance_clear", "recovery_known"):
        _bool(policy.get(field), base, "S3_" + field.upper())
    horizon, rto = _n(policy.get("remaining_lifetime_days"), optional=True), _n(policy.get("rto_seconds"), optional=True)
    if horizon is not None and (horizon <= 0 or horizon > 36500):
        raise EvidenceError("object-storage lifetime horizon outside bound")
    if rto is None:
        base.add("S3_RECOVERY_RTO_UNKNOWN")
    if policy.get("allow_onezone") is not None and type(policy["allow_onezone"]) is not bool:
        raise EvidenceError("object-storage one-zone policy boolean required")
    for ref in data.get("source_refs", []):
        _ref(ref, refs, base, "SOURCE")
    cohorts = data.get("cohorts")
    if not isinstance(cohorts, list) or not 1 <= len(cohorts) <= 1000:
        raise EvidenceError("object-storage transactional cohort bound")
    output, candidates, seen = [], [], set()
    currencies, all_blockers = set(), set(base)
    for cohort in cohorts:
        _obj(cohort, ("id", "label", "source_class", "access_tier", "state", "object_count", "total_bytes", "size_bands", "age_days_min", "age_days_max", "minimum_duration_remaining_days", "inventory_complete", "population_hash", "source_ref", "access", "lifecycle", "retention", "pricing"))
        ident = _text(cohort.get("id"))
        if ident in seen:
            raise EvidenceError("object-storage duplicate cohort identity")
        seen.add(ident)
        _text(cohort.get("label"))
        reasons, access_reasons = set(base), set()
        _ref(cohort.get("source_ref"), refs, reasons, "POPULATION")
        pop = _population(cohort, reasons)
        _bool(cohort.get("inventory_complete"), reasons, "S3_OBJECT_INVENTORY_INCOMPLETE")
        low, high = _n(cohort.get("age_days_min")), _n(cohort.get("age_days_max"))
        if low > high:
            raise EvidenceError("object-storage age distribution mismatch")
        cls, state = _class(cohort.get("source_class")), cohort.get("state")
        if state not in ("CURRENT", "NONCURRENT", "MULTIPART"):
            raise EvidenceError("object-storage population state unsupported")
        if cls not in CLASSES:
            reasons.add("S3_STORAGE_CLASS_UNSUPPORTED")
        access = _access(cohort, policy, now, refs, access_reasons)
        pricing_reasons = set()
        prices = _prices(cohort, refs, pricing_reasons)
        if prices["currency"]:
            currencies.add(prices["currency"])
        lifecycle = _obj(cohort.get("lifecycle") or {}, ("state", "already_targets", "conflicts", "archive_access_enabled", "deep_archive_access_enabled", "small_object_transition_allowed"))
        if lifecycle.get("state") not in ("NONE", "KNOWN"):
            reasons.add("S3_LIFECYCLE_CONFIGURATION_UNKNOWN")
        if lifecycle.get("conflicts") is not False:
            reasons.add("S3_LIFECYCLE_RETENTION_CONFLICT_OR_UNKNOWN")
        already = lifecycle.get("already_targets", [])
        if not isinstance(already, list) or len(already) > 100 or any(not isinstance(value, str) for value in already):
            raise EvidenceError("object-storage lifecycle target list invalid")
        retention = _obj(cohort.get("retention") or {}, ("known", "legal_hold", "retained", "replication_pending", "dependencies_known"))
        for key in ("known", "dependencies_known"):
            _bool(retention.get(key), reasons, "S3_RETENTION_" + key.upper())
        if retention.get("legal_hold") is not False or retention.get("retained") is not False:
            reasons.add("S3_RETENTION_OR_LEGAL_HOLD_REQUIRES_REVIEW")
        if retention.get("replication_pending") is not False:
            reasons.add("S3_REPLICATION_PENDING_OR_UNKNOWN")
        mine = []
        if state in ("NONCURRENT", "MULTIPART"):
            kind, target = (KINDS[4], "NONCURRENT_POLICY_REVIEW") if state == "NONCURRENT" else (KINDS[5], "MULTIPART_POLICY_REVIEW")
            review_reasons = reasons | pricing_reasons
            if state == "NONCURRENT" and config.get("versioning") not in ("ENABLED", "SUSPENDED"):
                review_reasons.add("S3_VERSIONED_POPULATION_CONFIGURATION_MISMATCH")
            burden_reasons = set()
            burden, parts = _monthly(cls, pop, {**access, "requests": Decimal(0), "retrieved_bytes": Decimal(0), "days": Decimal(1)}, prices, burden_reasons,
                                     access["tiers"] if cls == "INTELLIGENT_TIERING" else None)
            econ = _empty_economics(prices)
            if prices["basis"] == "AWS_CUR_NET_USAGE" and burden is not None and not burden_reasons:
                econ["current_monthly_cost"] = _money(burden)
                econ["status"] = "BURDEN_ONLY"
            review_reasons.update(burden_reasons)
            if retention.get("legal_hold") is True or retention.get("retained") is True:
                review_reasons.add("S3_DELETION_PROHIBITED_BY_RETENTION")
            mine.append(_candidate(kind, cohort, target, review_reasons, econ, review=True, already=target in already))
        elif cls == "INTELLIGENT_TIERING":
            review_reasons = reasons | pricing_reasons | access_reasons
            if lifecycle.get("archive_access_enabled") is None or lifecycle.get("deep_archive_access_enabled") is None:
                review_reasons.add("S3_IT_ARCHIVE_POLICY_UNKNOWN")
            if rto is not None and rto < RESTORE_SECONDS["GLACIER_FLEXIBLE_RETRIEVAL"]:
                review_reasons.add("S3_RTO_BLOCKS_ASYNCHRONOUS_ARCHIVE")
            # Show the actual evidenced current tier/monitoring burden without
            # claiming an invented future archive population or micromanaging
            # native automatic object movement.
            burden_reasons = set()
            burden, parts = _monthly(cls, pop, access, prices, burden_reasons, access["tiers"])
            econ = _empty_economics(prices)
            if prices["basis"] == "AWS_CUR_NET_USAGE" and burden is not None and not burden_reasons and not pricing_reasons:
                econ["current_monthly_cost"] = _money(burden)
                econ["status"] = "BURDEN_ONLY"
                econ["component_costs"] = [{"component": key, "current_monthly_cost": _money(value), "candidate_monthly_cost": None}
                                           for key, value in parts.items()]
            review_reasons.update(burden_reasons)
            item = _candidate(KINDS[3], cohort, "INTELLIGENT_TIERING_POLICY_REVIEW", review_reasons, econ, review=True,
                              already="INTELLIGENT_TIERING_POLICY_REVIEW" in already)
            item["policy_observations"] = {"archive_access_enabled": lifecycle.get("archive_access_enabled"),
                                           "deep_archive_access_enabled": lifecycle.get("deep_archive_access_enabled"),
                                           "monitored_object_count": _money(pop["count"] - pop["small_count"]),
                                           "unmonitored_small_object_count": _money(pop["small_count"]),
                                           "current_tier_fractions": cohort["access"].get("it_tier_fractions"),
                                           "rto_seconds": policy.get("rto_seconds"),
                                           "decision": "REVIEW_OPTIONAL_ARCHIVE_POLICY" if not lifecycle.get("archive_access_enabled") and not lifecycle.get("deep_archive_access_enabled") else "REVIEW_EXISTING_ARCHIVE_POLICY"}
            mine.append(item)
        elif cls in ("STANDARD", "STANDARD_IA", "ONEZONE_IA"):
            targets = [(KINDS[0], "INTELLIGENT_TIERING"), (KINDS[1], "STANDARD_IA")] if cls == "STANDARD" else []
            if cls == "STANDARD" and policy.get("allow_onezone") is True:
                targets.append((KINDS[1], "ONEZONE_IA"))
            targets += [(KINDS[2], c) for c in ("GLACIER_INSTANT_RETRIEVAL", "GLACIER_FLEXIBLE_RETRIEVAL", "DEEP_ARCHIVE")]
            for kind, target in targets:
                cr = reasons | pricing_reasons | access_reasons
                if target not in already and any(_class(value) in CLASSES for value in already):
                    cr.add("S3_EXISTING_LIFECYCLE_COUNTERFACTUAL_REQUIRED")
                if target != "INTELLIGENT_TIERING":
                    if access["cold_fraction"] is None:
                        cr.add("S3_INFREQUENT_ACCESS_SUPPORT_UNKNOWN")
                    elif access["cold_fraction"] < 1:
                        cr.add("S3_RECENT_OR_FREQUENT_ACCESS_BLOCKS_COLD_COHORT")
                if target in ("STANDARD_IA", "ONEZONE_IA") and low < 30:
                    cr.add("S3_LIFECYCLE_IA_OBJECT_AGE_BELOW_30_DAYS")
                if pop["small_count"] > 0 and lifecycle.get("small_object_transition_allowed") is not True:
                    cr.add("S3_SMALL_OBJECT_LIFECYCLE_FILTER_REQUIRED")
                if target in RESTORE_SECONDS and (rto is None or rto < RESTORE_SECONDS[target]):
                    cr.add("S3_RTO_BLOCKS_ARCHIVE_CLASS")
                tiers = access["tiers"] if target == "INTELLIGENT_TIERING" else None
                if target == "INTELLIGENT_TIERING" and tiers and (tiers["ARCHIVE"] > 0 or tiers["DEEP_ARCHIVE"] > 0):
                    cr.add("S3_OPTIONAL_IT_ARCHIVE_REQUIRES_SEPARATE_POLICY_REVIEW")
                econ = _economics(cohort, cls, target, pop, access, prices, horizon, cr, tiers)
                mine.append(_candidate(kind, cohort, target, cr, econ, already=target in already))
        if pop["small_count"] > 0:
            small_reasons = reasons | pricing_reasons | access_reasons
            small_reasons.add("S3_PER_OBJECT_MINIMA_AND_REQUEST_COSTS_REQUIRE_FILTERED_POLICY")
            mine.append(_candidate(KINDS[6], cohort, "SMALL_OBJECT_POLICY_REVIEW", small_reasons, review=True))
        if not mine:
            mine.append(_candidate("S3_UNSUPPORTED_CONFIGURATION", cohort, None, reasons | {"S3_NO_SUPPORTED_TRANSITION"}))
        for item in mine:
            target = item["candidate_storage_class"]
            latency = RESTORE_SECONDS.get(target)
            if target in ("STANDARD", "STANDARD_IA", "ONEZONE_IA", "INTELLIGENT_TIERING"):
                latency = Decimal(0)
            if target == "INTELLIGENT_TIERING_POLICY_REVIEW":
                if lifecycle.get("deep_archive_access_enabled") is True:
                    latency = RESTORE_SECONDS["DEEP_ARCHIVE"]
                elif lifecycle.get("archive_access_enabled") is True:
                    latency = RESTORE_SECONDS["GLACIER_FLEXIBLE_RETRIEVAL"]
                elif lifecycle.get("archive_access_enabled") is False and lifecycle.get("deep_archive_access_enabled") is False:
                    latency = Decimal(0)
            item["recovery_requirement"] = {"rto_seconds": policy.get("rto_seconds"),
                                            "restore_latency_seconds": _money(latency) if latency is not None else None,
                                            "requires_restore": latency > 0 if latency is not None else None,
                                            "basis": "STANDARD_RESTORE_SCENARIO_NO_EXPEDITED_GUARANTEE" if latency is not None and latency > 0 else "NO_ASYNCHRONOUS_RESTORE_REQUIRED" if latency == 0 else "REVIEW_ONLY_NO_CANDIDATE_RESTORE_ASSUMPTION"}
        candidates.extend(mine)
        for item in mine:
            all_blockers.update(item["blockers"])
        output.append({"id": ident, "label": cohort["label"], "source_class": cls, "access_tier": cohort.get("access_tier"), "state": state,
                       "object_count": cohort["object_count"], "total_bytes": cohort["total_bytes"], "size_bands": cohort["size_bands"],
                       "age_days_min": cohort["age_days_min"], "age_days_max": cohort["age_days_max"], "population_hash": cohort["population_hash"],
                       "access_state": access["state"], "evidence_window": {"start": access["start"], "end": access["end"]},
                       "lifecycle_state": lifecycle.get("state", "UNKNOWN"), "candidate_ids": [item["id"] for item in mine],
                       "blockers": sorted(reasons | pricing_reasons | access_reasons), "inventory_complete": cohort.get("inventory_complete") is True})
    if len(currencies) > 1:
        # No cross-currency total exists. Individual candidate amounts remain
        # scoped to their own currency, as do the explicit currency groups.
        all_blockers.add("S3_CURRENCIES_REPORTED_SEPARATELY")
    recommended = [c for c in candidates if c["status"] == "RECOMMENDED"]
    review = [c for c in candidates if c["status"] == "OBSERVATION_ONLY"]
    status = "RECOMMENDED" if recommended else "OBSERVATION_ONLY" if review else "NO_CHANGE" if all(c["status"] == "NO_CHANGE" for c in candidates) else "BLOCKED"
    economics = _empty_economics()
    # Alternative candidates and overlapping policies are never summed into a
    # purported portfolio saving. Each candidate is an independent comparison.
    economics["groups"] = [{"currency": c, "status": "CANDIDATE_COMPARISONS_ONLY", "estimated_monthly_saving": None,
                            "estimated_annual_saving": None} for c in sorted(currencies)]
    result = {"schema_version": SCHEMA_VERSION, "model_version": MODEL_VERSION, "model_kind": MODEL_KIND,
              "class_semantics_version": CLASS_SEMANTICS_VERSION, "class_semantics_sha256": _hash(CLASS_SEMANTICS),
              "binding": binding.copy(), "status": status, "reason_code": "S3_COHORT_ASSESSMENT_COMPLETED", "blockers": sorted(all_blockers),
              "cohorts": output, "candidates": candidates, "economics": economics,
              "confidence": {"status": "EVIDENCED" if recommended else "LIMITED" if review else "UNAVAILABLE",
                             "meaning": "EVIDENCE_COVERAGE_NOT_A_CALIBRATED_PROBABILITY", "reasons": sorted(all_blockers)},
              "configuration_authority": authority,
              "declared_policy": {key: value for key, value in policy.items() if key != "source_ref"},
              "implementation_method": "DECLARATIVE_REMEDIATION_REVIEW" if authority in ("TERRAFORM", "CLOUDFORMATION") else "REVIEW_ONLY",
              "proposal": {"risk_class": "R3", "executable": False, "execution_authorized": False},
              "pre_execution_ready": False, "execution_authorized": False, "verified_saving": None,
              "source_refs": [refs[key] for key in sorted(refs)],
              "model_assumptions": ["Native customer component rates held constant only over the declared remaining-lifetime scenario.",
                                    "Exact cohort population; alternative candidates are not additive savings.",
                                    "Access age is not coldness; missing intervals are unknown.",
                                    "Archive costs include conservative standard restore with one-day restored copies; no expedited capacity guarantee.",
                                    "Annual amounts are unavailable when the declared remaining lifetime is less than365days.",
                                    "No object, lifecycle, deletion, restore, or network operation is authorised."]}
    result["assessment_hash"] = _hash(result)
    return result


def evaluate_object_storage(data):
    with localcontext() as context:
        context.prec = 80
        context.rounding = ROUND_HALF_EVEN
        return _evaluate(data)
