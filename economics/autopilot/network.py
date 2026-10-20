"""Versioned read-only network comparisons from server-selected native evidence.

The control plane authenticates receipts, registered scopes and currentness.
This pure boundary checks decimal arithmetic, exclusive cohort allocation and
the distinction between historical cost, marginal cost and architectural review.
No receipt-shaped Python dictionary authenticates a provider or permits mutation.
"""
from datetime import timedelta
from decimal import Decimal, ROUND_HALF_EVEN, localcontext
from fractions import Fraction
import hashlib
import json
import re

from .model import EvidenceError, decimal, instant

SCHEMA_VERSION = "1"
MODEL_VERSION = "network-v1"
MODEL_KIND = "NETWORK_ASSESSMENT_V1"
ROUTE = "/v10/network-assessment"
SEMANTICS_VERSION = "aws-network-2026-10-20"
SEMANTICS = {
    "version": SEMANTICS_VERSION,
    "gateway_services": ["s3", "dynamodb"],
    "gateway_endpoint_additional_charge": "0",
    "nat_byte_basis": "BYTES_IN_FROM_SOURCE_PLUS_BYTES_IN_FROM_DESTINATION",
    "regional_nat_hourly_basis": "PER_CONFIGURED_AVAILABILITY_ZONE",
    "regional_nat_private_connectivity": False,
    "sources": ["https://docs.aws.amazon.com/vpc/latest/privatelink/gateway-endpoints.html",
                "https://docs.aws.amazon.com/vpc/latest/userguide/nat-gateways-regional.html",
                "https://docs.aws.amazon.com/vpc/latest/userguide/nat-gateway-pricing.html",
                "https://docs.aws.amazon.com/vpc/latest/userguide/metrics-dimensions-nat-gateway.html"],
}
FAMILIES = {
    "A": "GATEWAY_ENDPOINT_REVIEW", "B": "INTERFACE_ENDPOINT_REVIEW",
    "C": "NAT_TOPOLOGY_REVIEW", "D": "IDLE_NAT_REVIEW",
    "E": "PUBLIC_IPV4_REVIEW", "F": "CROSS_AZ_TRAFFIC_REVIEW",
    "G": "CROSS_REGION_TRAFFIC_REVIEW", "H": "INTERNET_EGRESS_REVIEW",
}
CATEGORIES = ("NAT_HOURLY", "NAT_PROCESSING", "PUBLIC_IPV4", "CROSS_AZ_TRANSFER", "CROSS_REGION_TRANSFER",
              "INTERNET_EGRESS", "ENDPOINT_HOURLY", "ENDPOINT_PROCESSING", "TRANSIT_GATEWAY", "PRIVATELINK",
              "LOAD_BALANCER_PROCESSING", "CONTINUING", "CREDIT")
BINDING = ("tenant_id", "account_id", "region", "resource_id", "provider", "provider_resource_id", "workload_id")
MONTH_HOURS = Decimal(730)


def _object(value, allowed):
    if not isinstance(value, dict) or set(value) - set(allowed):
        raise EvidenceError("unsupported network evidence fields")
    return value


def _text(value, optional=False):
    if value is None and optional:
        return None
    if not isinstance(value, str) or not value or len(value) > 2048 or any(ord(c) < 32 for c in value):
        raise EvidenceError("network identity required")
    return value


def _number(value, optional=False, signed=False, integral=False):
    if value is None and optional:
        return None
    number = decimal(value, "network quantity")
    if not signed and number < 0 or integral and number != number.to_integral_value():
        raise EvidenceError("invalid network quantity")
    return number


def _boolean(value):
    if value is not None and type(value) is not bool:
        raise EvidenceError("network boolean required")
    return value


def _money(value):
    if value is None:
        return None
    number = value.quantize(Decimal("0.000000000001"), rounding=ROUND_HALF_EVEN)
    if abs(number) >= Decimal("1e26"):
        raise EvidenceError("network result exceeds DECIMAL(38,12)")
    return format(number, "f")


def _hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def _stamp(value):
    if not isinstance(value, str) or not (value.endswith("Z") or value.endswith("+00:00")):
        raise EvidenceError("network UTC timestamp required")
    return instant(value)


def _ref(value, refs, reasons, name, binding):
    if value is None:
        reasons.add("NETWORK_IMMUTABLE_REFERENCE_REQUIRED:" + name)
        return
    _object(value, ("kind", "id", "version", "sha256", "binding"))
    for key in ("kind", "id", "version"):
        _text(value.get(key))
    if not isinstance(value.get("sha256"), str) or not re.fullmatch("[a-f0-9]{64}", value["sha256"]):
        raise EvidenceError("network immutable hash required")
    if "binding" in value:
        scope = _object(value["binding"], BINDING)
        if any(scope.get(k) != binding.get(k) for k in scope):
            raise EvidenceError("network evidence binding mismatch")
    key = (value["kind"], value["id"], value["version"])
    if key in refs and refs[key] != value:
        raise EvidenceError("conflicting immutable network reference")
    refs[key] = value


def _unit_bytes(unit, item):
    if unit == "Byte":
        return Decimal(1)
    if unit == "GiB":
        return Decimal(1073741824)
    if unit == "GB":
        # AWS financial products need not use the same GB convention. The
        # authoritative native dimension mapper must retain the conversion.
        value = _number(item.get("bytes_per_unit"), optional=True, integral=True)
        if value is None or value <= 0:
            return None
        return value
    return None


def _paths(value):
    if not isinstance(value, list) or not 1 <= len(value) <= 32:
        raise EvidenceError("bounded network path required")
    return [_text(item) for item in value]


def _economics_empty(currency):
    return {"status": "ECONOMICS_UNAVAILABLE", "currency": currency,
            "observed_allocated_cost": None, "current_window_cost": None,
            "candidate_window_cost": None, "estimated_window_saving": None,
            "estimated_monthly_saving": None, "estimated_annual_saving": None,
            "component_costs": [], "nat_hourly_retained": True,
            "pricing_basis": "NATIVE_CUSTOMER_NET_ONLY", "allocation_basis": "EXCLUSIVE_COHORT_ALLOCATION"}


def _evaluate(data):
    _object(data, ("schema_version", "model_version", "binding", "as_of", "topology", "policy", "observation", "billing", "rates", "cohorts"))
    if data.get("schema_version") != SCHEMA_VERSION or data.get("model_version") != MODEL_VERSION:
        raise EvidenceError("unsupported network model version")
    binding = _object(data.get("binding"), BINDING)
    for key in BINDING:
        _text(binding.get(key), optional=key == "workload_id")
    if binding.get("provider") != "AWS" or not re.fullmatch("[0-9]{12}", binding["account_id"]):
        raise EvidenceError("invalid AWS network binding")
    as_of = _stamp(data.get("as_of"))
    refs, reasons = {}, set()
    top = _object(data.get("topology"), ("revision", "hash", "mode", "vpc_id", "source_az", "nat_az", "route_table_ids", "route_current", "route_certain", "source_ref"))
    _text(top.get("revision"))
    # An unassociated address has no evidenced VPC. Do not invent one merely
    # to admit its carrying-cost review into the same assessment boundary.
    _text(top.get("vpc_id"), optional=True)
    if not isinstance(top.get("hash"), str) or not re.fullmatch("[a-f0-9]{64}", top["hash"]):
        raise EvidenceError("network topology hash required")
    mode = top.get("mode")
    if mode not in ("ZONAL", "REGIONAL", "UNKNOWN"):
        raise EvidenceError("unknown native NAT availability mode")
    if mode == "UNKNOWN":
        reasons.add("NETWORK_NAT_TOPOLOGY_MODE_UNKNOWN")
    if mode == "ZONAL" and top.get("nat_az") is None:
        reasons.add("NETWORK_ZONAL_NAT_AZ_UNKNOWN")
    for key in ("source_az", "nat_az"):
        _text(top.get(key), optional=True)
    routes = top.get("route_table_ids")
    if not isinstance(routes, list) or len(routes) > 256 or len(routes) != len(set(routes)):
        raise EvidenceError("invalid bounded route table scope")
    for route in routes:
        _text(route)
    for key, code in (("route_current", "NETWORK_TOPOLOGY_STALE"), ("route_certain", "NETWORK_ROUTE_PATH_UNKNOWN")):
        if _boolean(top.get(key)) is not True:
            reasons.add(code)
    _ref(top.get("source_ref"), refs, reasons, "topology", binding)

    policy = _object(data.get("policy"), ("owner", "configuration_authority", "criticality", "seasonal", "security_reviewed", "network_policy_known", "dependencies_known", "recovery_known", "resilience_known", "allow_topology_change", "required_azs", "ha_required", "on_premises_required", "cross_vpc_required", "dns_change_approved", "public_access_required", "traffic_purpose", "endpoint_policy_reviewed", "source_ref"))
    if not _text(policy.get("owner"), optional=True):
        reasons.add("NETWORK_OWNERSHIP_UNKNOWN")
    authority = policy.get("configuration_authority")
    if authority not in (None, "UNKNOWN", "TERRAFORM", "CLOUDFORMATION", "MANUAL", "OTHER_DECLARATIVE"):
        raise EvidenceError("invalid configuration authority")
    if authority in (None, "UNKNOWN"):
        reasons.add("NETWORK_CONFIGURATION_AUTHORITY_UNKNOWN")
    if policy.get("criticality") not in ("NON_PRODUCTION", "PRODUCTION"):
        reasons.add("NETWORK_CRITICALITY_UNKNOWN")
    for key in ("security_reviewed", "network_policy_known", "dependencies_known", "recovery_known", "resilience_known"):
        if _boolean(policy.get(key)) is not True:
            reasons.add("NETWORK_" + key.upper() + "_REQUIRED")
    for key in ("seasonal", "allow_topology_change", "ha_required", "on_premises_required", "cross_vpc_required", "dns_change_approved", "public_access_required", "endpoint_policy_reviewed"):
        _boolean(policy.get(key))
    required_azs = policy.get("required_azs")
    if required_azs is not None and (type(required_azs) is not int or not 1 <= required_azs <= 16):
        raise EvidenceError("network required AZ count outside bounds")
    _ref(policy.get("source_ref"), refs, reasons, "policy", binding)

    obs = _object(data.get("observation"), ("start", "end", "telemetry_complete", "flow_complete", "processed_bytes", "byte_basis", "maximum_active_connections", "source_ref"))
    start, end = _stamp(obs.get("start")), _stamp(obs.get("end"))
    if end <= start or end > as_of or start.hour or start.minute or start.second or start.microsecond or end.hour or end.minute or end.second or end.microsecond:
        raise EvidenceError("network complete UTC evidence days required")
    duration = end - start
    days = Decimal(str(duration.total_seconds())) / Decimal(86400)
    hours = days * 24
    minimum_days = 90 if policy.get("seasonal") is True else 30 if policy.get("criticality") == "PRODUCTION" else 14
    if days < minimum_days:
        reasons.add("NETWORK_INSUFFICIENT_HISTORY")
    if as_of - end > timedelta(hours=48):
        reasons.add("NETWORK_OBSERVATION_STALE")
    if _boolean(obs.get("telemetry_complete")) is not True:
        reasons.add("NETWORK_TELEMETRY_INCOMPLETE")
    _boolean(obs.get("flow_complete"))
    total_bytes = _number(obs.get("processed_bytes"), optional=True, integral=True)
    active_connections = _number(obs.get("maximum_active_connections"), optional=True, integral=True)
    byte_basis = obs.get("byte_basis")
    if total_bytes is None or byte_basis != SEMANTICS["nat_byte_basis"]:
        reasons.add("NETWORK_PROCESSED_BYTE_DENOMINATOR_UNKNOWN")
    _ref(obs.get("source_ref"), refs, reasons, "observations", binding)

    bill = _object(data.get("billing"), ("currency", "basis", "complete", "scope_complete", "marginal_pricing_known", "start", "end", "source_ref", "components"))
    currency = bill.get("currency")
    if not isinstance(currency, str) or not re.fullmatch("[A-Z]{3}", currency):
        raise EvidenceError("one explicit network source currency required")
    financial_reasons = set()
    if bill.get("basis") != "AWS_CUR_NET_USAGE":
        financial_reasons.add("NETWORK_NATIVE_NET_ECONOMICS_REQUIRED")
    for key in ("complete", "scope_complete", "marginal_pricing_known"):
        if _boolean(bill.get(key)) is not True:
            financial_reasons.add("NETWORK_BILLING_" + key.upper() + "_REQUIRED")
    if _stamp(bill.get("start")) != start or _stamp(bill.get("end")) != end:
        financial_reasons.add("NETWORK_BILLING_OBSERVATION_WINDOW_MISMATCH")
    _ref(bill.get("source_ref"), refs, financial_reasons, "billing", binding)
    rows = bill.get("components")
    if not isinstance(rows, list) or len(rows) > 256:
        raise EvidenceError("bounded network billing components required")
    charges, native_bytes, native_byte_quantity_known = {}, Decimal(0), True
    native_byte_records = False
    for row in rows:
        _object(row, ("id", "category", "amount", "quantity", "unit", "bytes_per_unit", "source_ref"))
        ident, category = _text(row.get("id")), row.get("category")
        if ident in charges or category not in CATEGORIES:
            raise EvidenceError("duplicate or unsupported network charge")
        amount = _number(row.get("amount"), signed=True)
        quantity = _number(row.get("quantity"), optional=True)
        _text(row.get("unit"))
        _ref(row.get("source_ref"), refs, financial_reasons, "charge:" + ident, binding)
        divisor = _unit_bytes(row["unit"], row)
        if category == "NAT_PROCESSING":
            native_byte_records = True
            if quantity is None or divisor is None:
                native_byte_quantity_known = False
                financial_reasons.add("NETWORK_NATIVE_BILLED_BYTE_QUANTITY_UNKNOWN")
            else:
                native_bytes += quantity * divisor
        charges[ident] = {"category": category, "amount": amount, "quantity": quantity}
    if not rows:
        financial_reasons.add("NETWORK_BILLING_RECORDS_MISSING")
    if any(c["category"] == "NAT_PROCESSING" for c in charges.values()) and total_bytes is not None and native_bytes != total_bytes:
        financial_reasons.add("NETWORK_BILLED_TELEMETRY_BYTE_QUANTITY_MISMATCH")

    rate_rows = data.get("rates", [])
    if not isinstance(rate_rows, list) or len(rate_rows) > 128:
        raise EvidenceError("bounded network native rates required")
    rates = {}
    for rate in rate_rows:
        _object(rate, ("id", "component", "rate", "unit", "bytes_per_unit", "currency", "payer_account_id", "usage_account_id", "region", "service", "pricing_bracket", "pricing_bracket_resolved", "marginal_pricing_known", "source_ref"))
        ident = _text(rate.get("id"))
        if ident in rates or rate.get("currency") != currency or rate.get("usage_account_id") != binding["account_id"] or rate.get("region") != binding["region"]:
            raise EvidenceError("network native rate scope or currency mismatch")
        if not isinstance(rate.get("payer_account_id"), str) or not re.fullmatch("[0-9]{12}", rate["payer_account_id"]):
            raise EvidenceError("network rate payer scope required")
        for key in ("component", "service", "unit", "pricing_bracket"):
            _text(rate.get(key))
        rate_reasons = set()
        for key in ("pricing_bracket_resolved", "marginal_pricing_known"):
            if _boolean(rate.get(key)) is not True:
                rate_reasons.add("NETWORK_NATIVE_RATE_" + key.upper() + "_REQUIRED")
        _ref(rate.get("source_ref"), refs, rate_reasons, "rate:" + ident, binding)
        rates[ident] = {"row": rate, "amount": _number(rate.get("rate")), "reasons": rate_reasons}

    cohorts = data.get("cohorts")
    if not isinstance(cohorts, list) or not 1 <= len(cohorts) <= 128:
        raise EvidenceError("bounded exclusive network cohorts required")
    allocations, seen, summed_bytes, candidates, summaries = {}, set(), Decimal(0), [], []
    for cohort in cohorts:
        _object(cohort, ("id", "family", "bytes", "traffic_complete", "attribution_complete", "destination_service", "destination_region", "traffic_source", "current_path", "target_path", "billing_allocations", "technical", "candidate_costs", "source_ref"))
        ident, family = _text(cohort.get("id")), cohort.get("family")
        if ident in seen or family not in FAMILIES:
            raise EvidenceError("duplicate cohort or unsupported network family")
        seen.add(ident)
        cr = set(reasons)
        cohort_bytes = _number(cohort.get("bytes"), optional=True, integral=True)
        if cohort_bytes is not None:
            summed_bytes += cohort_bytes
        current_path, target_path = _paths(cohort.get("current_path")), _paths(cohort.get("target_path"))
        for key in ("traffic_complete", "attribution_complete"):
            if _boolean(cohort.get(key)) is not True:
                cr.add("NETWORK_" + key.upper() + "_REQUIRED")
        if family in ("A", "B", "C", "F", "G", "H"):
            if obs.get("flow_complete") is not True or cohort.get("traffic_source") != "FLOW_LOGS" or cohort_bytes is None:
                cr.add("NETWORK_FLOW_ATTRIBUTION_INCOMPLETE")
        _ref(cohort.get("source_ref"), refs, cr, "cohort:" + ident, binding)
        technical = _object(cohort.get("technical"), ("endpoint_available", "endpoint_scope_compatible", "current_endpoint", "dns_compatible", "on_premises_compatible", "cross_vpc_compatible", "security_compatible", "resilience_preserved", "rto_compatible", "topology_footprint_known", "target_az_count", "nat_hourly_avoidable", "idle_threshold_bytes", "public_ipv4_kind", "association_state", "purpose"))
        for key in ("endpoint_available", "endpoint_scope_compatible", "current_endpoint", "dns_compatible", "on_premises_compatible", "cross_vpc_compatible", "security_compatible", "resilience_preserved", "rto_compatible", "topology_footprint_known", "nat_hourly_avoidable"):
            _boolean(technical.get(key))
        az_count = technical.get("target_az_count")
        if az_count is not None and (type(az_count) is not int or not 1 <= az_count <= 16):
            raise EvidenceError("network target AZ count outside bounds")
        if family in ("A", "B", "C"):
            if top.get("vpc_id") is None:
                cr.add("NETWORK_VPC_BINDING_UNKNOWN")
            for key in ("security_compatible", "resilience_preserved", "rto_compatible"):
                if technical.get(key) is not True:
                    cr.add("NETWORK_" + key.upper() + "_REQUIRED")
        if family in ("A", "B"):
            for key in ("endpoint_available", "endpoint_scope_compatible", "dns_compatible", "on_premises_compatible", "cross_vpc_compatible"):
                if technical.get(key) is not True:
                    cr.add("NETWORK_" + key.upper() + "_REQUIRED")
            if policy.get("endpoint_policy_reviewed") is not True:
                cr.add("NETWORK_ENDPOINT_POLICY_REVIEW_REQUIRED")
            for key in ("on_premises_required", "cross_vpc_required"):
                if policy.get(key) is None:
                    cr.add("NETWORK_" + key.upper() + "_UNKNOWN")
        if family == "A" and (cohort.get("destination_service") not in SEMANTICS["gateway_services"] or cohort.get("destination_region") != binding["region"]):
            cr.add("NETWORK_GATEWAY_SERVICE_OR_REGION_UNSUPPORTED")
        if family == "A" and (policy.get("on_premises_required") is True or policy.get("cross_vpc_required") is True):
            cr.add("NETWORK_GATEWAY_LOCAL_VPC_ACCESS_SCOPE_REQUIRED")
        if family == "B":
            if policy.get("dns_change_approved") is not True:
                cr.add("NETWORK_ENDPOINT_DNS_CHANGE_APPROVAL_REQUIRED")
            if policy.get("ha_required") is None:
                cr.add("NETWORK_HA_REQUIREMENT_UNKNOWN")
            if az_count is None or required_azs is None or technical.get("topology_footprint_known") is not True:
                cr.add("NETWORK_ENDPOINT_AZ_FOOTPRINT_UNKNOWN")
            elif az_count < required_azs:
                cr.add("NETWORK_ENDPOINT_HA_FOOTPRINT_INSUFFICIENT")
        if family == "C":
            if policy.get("allow_topology_change") is not True:
                cr.add("NETWORK_TOPOLOGY_CHANGE_POLICY_BLOCKED")
            if mode == "REGIONAL" and technical.get("topology_footprint_known") is not True:
                cr.add("NETWORK_REGIONAL_NAT_AZ_FOOTPRINT_UNKNOWN")
            if mode == "REGIONAL" and top.get("source_az") == top.get("nat_az"):
                cr.add("NETWORK_REGIONAL_PATH_REQUIRES_PROVIDER_ZONAL_AFFINITY_EVIDENCE")

        component_costs, current, economic_reasons = {}, Decimal(0), set(financial_reasons)
        cohort_allocations = cohort.get("billing_allocations")
        if not isinstance(cohort_allocations, list) or len(cohort_allocations) > 256:
            raise EvidenceError("network charge allocation references required")
        if not cohort_allocations:
            economic_reasons.add("NETWORK_ATTRIBUTABLE_BILLING_MISSING")
        allocated_ids = set()
        for allocation in cohort_allocations:
            _object(allocation, ("component_id", "fraction", "numerator", "denominator"))
            charge_id = _text(allocation.get("component_id"))
            if charge_id not in charges or charge_id in allocated_ids:
                raise EvidenceError("missing or duplicated native network billing record")
            allocated_ids.add(charge_id)
            if "numerator" in allocation or "denominator" in allocation:
                if "fraction" in allocation:
                    raise EvidenceError("ambiguous network allocation representation")
                numerator = _number(allocation.get("numerator"), integral=True)
                denominator = _number(allocation.get("denominator"), integral=True)
                if denominator == 0:
                    raise EvidenceError("zero network allocation denominator")
                fraction = Fraction(numerator) / Fraction(denominator)
            else:
                fraction = Fraction(_number(allocation.get("fraction")))
            if fraction > 1:
                raise EvidenceError("network charge allocation exceeds one")
            allocations[charge_id] = allocations.get(charge_id, Fraction(0)) + fraction
            if allocations[charge_id] > 1:
                raise EvidenceError("overlapping network cohorts double count charges")
            charge = charges[charge_id]
            if charge["category"] == "NAT_PROCESSING":
                if total_bytes is None or total_bytes == 0 and (cohort_bytes != 0 or fraction != 0):
                    economic_reasons.add("NETWORK_NAT_ALLOCATION_DENOMINATOR_UNKNOWN")
                elif total_bytes > 0 and (cohort_bytes is None or fraction * Fraction(total_bytes) != Fraction(cohort_bytes)):
                    raise EvidenceError("NAT processing allocation differs from exclusive byte cohort")
            # Exact integer ratios validate population and cost conservation.
            # DECIMAL12 rounding is only presentation/persistence of money,
            # never authoritative rounding of a traffic-allocation fraction.
            amount = charge["amount"] * Decimal(fraction.numerator) / Decimal(fraction.denominator)
            current += amount
            component_costs[charge["category"]] = component_costs.get(charge["category"], Decimal(0)) + amount
        econ = _economics_empty(currency)
        econ["observed_allocated_cost"] = _money(current) if cohort_allocations else None
        # All endpoint comparisons retain NAT hourly obligations. Allocating a
        # shared hourly bill to a cohort never proves that bill can be removed.
        avoided_categories = {"NAT_PROCESSING", "CROSS_AZ_TRANSFER"} if family in ("A", "B") else set()
        candidate_parts = {category: Decimal(0) if category in avoided_categories else amount for category, amount in component_costs.items()}
        candidate_inputs = cohort.get("candidate_costs", [])
        if not isinstance(candidate_inputs, list) or len(candidate_inputs) > 32:
            raise EvidenceError("bounded candidate component references required")
        input_seen = set()
        for cost in candidate_inputs:
            _object(cost, ("component", "rate_id", "quantity"))
            component, rate_id = _text(cost.get("component")), _text(cost.get("rate_id"))
            if component in input_seen or rate_id not in rates:
                raise EvidenceError("duplicate or missing native candidate rate")
            input_seen.add(component)
            rate, rate_reasons = rates[rate_id]["row"], rates[rate_id]["reasons"]
            economic_reasons.update(rate_reasons)
            if component != rate["component"] or rate["service"] != cohort.get("destination_service"):
                raise EvidenceError("candidate network rate technical dimensions mismatch")
            quantity = _number(cost.get("quantity"), optional=True)
            if component == "ENDPOINT_HOURLY":
                expected_quantity = hours * az_count if az_count is not None else None
                if rate["unit"] != "Hour":
                    raise EvidenceError("endpoint hourly rate unit mismatch")
                if quantity is not None and quantity != expected_quantity:
                    raise EvidenceError("endpoint hourly quantity does not cover all AZs")
                quantity = expected_quantity
            elif component == "ENDPOINT_PROCESSING":
                divisor = _unit_bytes(rate["unit"], rate)
                expected_quantity = cohort_bytes / divisor if cohort_bytes is not None and divisor else None
                if quantity is not None and quantity != expected_quantity:
                    raise EvidenceError("endpoint processing quantity differs from observed bytes")
                quantity = expected_quantity
            if quantity is None:
                economic_reasons.add("NETWORK_CANDIDATE_COMPONENT_QUANTITY_UNKNOWN")
            else:
                candidate_parts[component] = candidate_parts.get(component, Decimal(0)) + quantity * rates[rate_id]["amount"]
        if family == "A" and candidate_inputs:
            raise EvidenceError("gateway endpoint additional charge must use versioned no-charge semantics")
        if family == "B" and not {"ENDPOINT_HOURLY", "ENDPOINT_PROCESSING"}.issubset(input_seen):
            economic_reasons.add("NETWORK_ENDPOINT_NATIVE_CUSTOMER_RATES_MISSING")
        if family not in ("A", "B") and candidate_inputs:
            economic_reasons.add("NETWORK_ARCHITECTURE_COUNTERFACTUAL_NOT_VALIDATED")
        if not any(category in component_costs for category in avoided_categories) and family in ("A", "B"):
            economic_reasons.add("NETWORK_AVOIDABLE_NATIVE_COMPONENT_MISSING")

        status, decision = "OBSERVATION_ONLY", FAMILIES[family]
        classification = None
        if family == "D":
            threshold = _number(technical.get("idle_threshold_bytes"), optional=True, integral=True)
            complete = obs.get("telemetry_complete") is True and cohort.get("traffic_complete") is True and total_bytes is not None and byte_basis == SEMANTICS["nat_byte_basis"]
            if mode == "REGIONAL":
                # V1 carries a current candidate AZ footprint, not an
                # authenticated historical expansion/contraction timeline.
                # Even a complete current-AZ counter series cannot prove idle
                # traffic across previously configured regional NAT zones.
                complete = False
                cr.add("NETWORK_REGIONAL_NAT_HISTORICAL_AZ_FOOTPRINT_UNKNOWN")
            classification = "UNKNOWN" if not complete else "APPARENTLY_IDLE" if total_bytes == 0 and active_connections == 0 else "LOW_UTILISATION" if threshold is not None and 0 < total_bytes <= threshold else "ACTIVE"
            if complete and total_bytes == 0 and active_connections is None:
                classification = "UNKNOWN"
                cr.add("NETWORK_ACTIVE_CONNECTION_EVIDENCE_UNKNOWN")
            decision = "REVIEW_IDLE_NAT_DEPENDENCIES" if classification == "APPARENTLY_IDLE" else "NO_CHANGE" if classification == "ACTIVE" else "REVIEW_NAT_UTILISATION" if classification == "LOW_UTILISATION" else "NAT_ACTIVITY_UNKNOWN"
            if classification == "ACTIVE":
                status = "NO_CHANGE"
        elif family == "E":
            ip_kind, association = technical.get("public_ipv4_kind"), technical.get("association_state")
            if ip_kind not in ("ELASTIC_IP", "EC2_PUBLIC_IPV4", "SERVICE_MANAGED_PUBLIC_IPV4", "BYOIP", "UNKNOWN", None) or association not in ("ASSOCIATED", "UNASSOCIATED", "UNKNOWN", None):
                raise EvidenceError("unknown public IPv4 classification")
            classification = ip_kind
            decision = "REVIEW_UNASSOCIATED_EIP" if ip_kind == "ELASTIC_IP" and association == "UNASSOCIATED" else "NO_CHANGE" if ip_kind == "BYOIP" else "REVIEW_PUBLIC_IPV4_ACCESS_ARCHITECTURE"
            if ip_kind == "BYOIP":
                status = "NO_CHANGE"
            if association in (None, "UNKNOWN"):
                cr.add("NETWORK_PUBLIC_IPV4_ASSOCIATION_UNKNOWN")
            if policy.get("public_access_required") is None:
                cr.add("NETWORK_PUBLIC_ACCESS_REQUIREMENT_UNKNOWN")
        elif family in ("F", "G", "H"):
            purpose = technical.get("purpose") or policy.get("traffic_purpose")
            if purpose in (None, "UNKNOWN"):
                cr.add("NETWORK_TRAFFIC_PURPOSE_UNKNOWN")
            if family == "G" and purpose in ("DR", "REPLICATION", "REGULATORY", "ACTIVE_ACTIVE", "CUSTOMER_GEOGRAPHY"):
                cr.add("NETWORK_CROSS_REGION_PURPOSE_MUST_BE_PRESERVED")
            if family == "F" and purpose in ("HA", "REPLICATION", "ACTIVE_ACTIVE"):
                cr.add("NETWORK_CROSS_AZ_RESILIENCE_MUST_BE_PRESERVED")
        if family in ("A", "B"):
            cr.update(economic_reasons)
            if technical.get("current_endpoint") is True:
                status, decision = "NO_CHANGE", "ALREADY_IMPLEMENTED"
            elif technical.get("current_endpoint") is None:
                cr.add("NETWORK_CURRENT_ENDPOINT_CONFIGURATION_UNKNOWN")
            if not cr and decision != "ALREADY_IMPLEMENTED":
                candidate = sum(candidate_parts.values(), Decimal(0))
                saving = current - candidate
                econ.update({"status": "MODELLED_NATIVE_CUSTOMER_ECONOMICS", "current_window_cost": _money(current), "candidate_window_cost": _money(candidate),
                             "estimated_window_saving": _money(saving), "estimated_monthly_saving": _money(saving * MONTH_HOURS / hours)})
                status, decision = ("RECOMMENDED", FAMILIES[family]) if saving > 0 else ("NO_CHANGE", "DO_NOT_CREATE_ENDPOINT" if family == "B" else "NO_ECONOMIC_BENEFIT")
            elif decision != "ALREADY_IMPLEMENTED":
                status = "BLOCKED"
        else:
            # Reviews show the observed carrying burden but do not manufacture
            # a removal, co-location, CDN or replication counterfactual saving.
            cr.update(economic_reasons)
            if not economic_reasons:
                econ["status"] = "OBSERVED_BURDEN_ONLY"
                econ["current_window_cost"] = _money(current)
            if cr:
                status = "OBSERVATION_ONLY"
        for category in sorted(set(component_costs) | set(candidate_parts)):
            before, after = component_costs.get(category, Decimal(0)), candidate_parts.get(category, Decimal(0))
            modeled = econ["status"] == "MODELLED_NATIVE_CUSTOMER_ECONOMICS"
            econ["component_costs"].append({"component": category, "current_window_cost": _money(before),
                                           "candidate_window_cost": _money(after) if modeled else None,
                                           "avoided_window_cost": _money(before - after) if modeled else None,
                                           "attribution_basis": "MODELLED_EXCLUSIVE_ALLOCATION_OF_NATIVE_BILLING"})
        impacts = ["NETWORK_POLICY_AND_ACCESS_REVIEW_REQUIRED"]
        if family == "A":
            impacts += ["AWS_SERVICE_GATEWAY_PATH", "ENDPOINT_AND_SERVICE_POLICY_IMPACT", "ROUTE_TABLE_SCOPE_CHANGES", "CROSS_ACCOUNT_AND_ON_PREMISES_ACCESS_DIFFERENCE"]
        elif family == "B":
            impacts += ["PRIVATE_SERVICE_PATH", "DNS_BEHAVIOUR_CHANGES", "ENDPOINT_SECURITY_GROUP_IMPACT", "CROSS_ACCOUNT_AND_ON_PREMISES_ACCESS_DIFFERENCE"]
        elif family in ("C", "F", "G"):
            impacts += ["FAULT_DOMAIN_AND_RECOVERY_REVIEW", "TRAFFIC_PATH_CHANGES"]
        elif family == "E":
            impacts += ["PUBLIC_CONNECTIVITY_AND_ALLOWLIST_IMPACT"]
        else:
            impacts += ["DEPENDENCY_AND_ACCESS_PATH_REVIEW"]
        confidence_reasons = sorted(cr)
        confidence = "HIGH" if not cr and obs.get("flow_complete") is True and cohort.get("attribution_complete") is True else "LIMITED" if cohort_allocations else "UNAVAILABLE"
        candidate = {"id": _hash({"cohort": cohort, "topology": top, "observation": obs, "billing": bill, "policy": policy, "rates": rate_rows, "model": MODEL_VERSION}),
                     "cohort_id": ident, "family": family, "kind": FAMILIES[family], "decision": decision, "status": status,
                     "reason_code": "NETWORK_NATIVE_ECONOMICS_SUPPORTED" if status == "RECOMMENDED" else "NETWORK_" + decision,
                     "blockers": sorted(cr), "classification": classification, "current_path": current_path, "target_path": target_path,
                     "route_table_ids": routes, "economics": econ, "confidence": {"status": confidence, "reasons": confidence_reasons, "meaning": "EVIDENCE_COVERAGE_NOT_A_CALIBRATED_PROBABILITY"},
                     "security_impact": {"classification": "REVIEW_REQUIRED", "effects": impacts, "reviewed": policy.get("security_reviewed") is True},
                     "configuration_authority": authority, "implementation_method": "DECLARATIVE_REMEDIATION_REVIEW" if authority in ("TERRAFORM", "CLOUDFORMATION", "OTHER_DECLARATIVE") else "REVIEW_ONLY",
                     "read_only": True, "pre_execution_ready": False, "execution_authorized": False, "verified_saving": None}
        candidates.append(candidate)
        summaries.append({"id": ident, "family": family, "bytes": _money(cohort_bytes), "destination_service": cohort.get("destination_service"),
                          "destination_region": cohort.get("destination_region"), "attribution_complete": cohort.get("attribution_complete") is True,
                          "traffic_complete": cohort.get("traffic_complete") is True, "current_path": current_path, "target_path": target_path,
                          "candidate_id": candidate["id"], "blockers": sorted(cr)})
    if total_bytes is not None and summed_bytes > total_bytes:
        raise EvidenceError("exclusive traffic cohort bytes exceed network population")
    if total_bytes is None or summed_bytes != total_bytes:
        # A trustworthy per-cohort comparison need not explain every other byte,
        # but a partially attributed NAT population never earns HIGH confidence.
        for candidate in candidates:
            if candidate["confidence"]["status"] == "HIGH":
                candidate["confidence"]["status"] = "LIMITED"
            candidate["confidence"]["reasons"] = sorted(set(candidate["confidence"]["reasons"]) | {"NETWORK_POPULATION_ATTRIBUTION_PARTIAL"})
    all_blockers = sorted(set().union(*(set(c["blockers"]) for c in candidates)))
    status = "RECOMMENDED" if any(c["status"] == "RECOMMENDED" for c in candidates) else "NO_CHANGE" if all(c["status"] == "NO_CHANGE" for c in candidates) else "OBSERVATION_ONLY" if any(c["status"] == "OBSERVATION_ONLY" for c in candidates) else "BLOCKED"
    result = {"schema_version": SCHEMA_VERSION, "contract_version": 1, "model_version": MODEL_VERSION, "model_kind": MODEL_KIND,
              "semantics_version": SEMANTICS_VERSION, "semantics_sha256": _hash(SEMANTICS), "binding": binding.copy(),
              "status": status, "reason_code": "NETWORK_ASSESSMENT_COMPLETED", "blockers": all_blockers,
              "window_start": obs["start"], "window_end": obs["end"], "history_days": _money(days), "topology_hash": top["hash"],
              "cohorts": summaries, "candidates": candidates, "configuration_authority": authority,
              "economics": {"currency": currency, "detected_native_cost": _money(sum((c["amount"] for c in charges.values()), Decimal(0))) if rows else None,
                            "estimated_monthly_saving": None, "estimated_annual_saving": None, "status": "INDEPENDENT_CANDIDATES_NEVER_SUMMED"},
              "denominators": {"native_processed_bytes": _money(native_bytes) if native_byte_records and native_byte_quantity_known else None, "observed_processed_bytes": _money(total_bytes),
                               "attributed_cohort_bytes": _money(summed_bytes), "unattributed_bytes": _money(total_bytes - summed_bytes) if total_bytes is not None else None,
                               "observation_complete": obs.get("telemetry_complete") is True, "flow_complete": obs.get("flow_complete") is True,
                               "billing_complete": bill.get("complete") is True, "billing_scope_complete": bill.get("scope_complete") is True},
              "read_only": True, "pre_execution_ready": False, "execution_authorized": False, "verified_saving": None,
              "proposal": {"risk_class": "R3", "executable": False, "execution_authorized": False},
              "evidence_refs": [refs[key] for key in sorted(refs)], "source_refs": [refs[key] for key in sorted(refs)],
              "model_assumptions": ["Only server-selected native customer NET economics; no public price substitution.",
                                    "NAT hourly obligations continue in gateway and interface endpoint comparisons.",
                                    "Endpoint candidates are alternatives; overlapping architectural opportunities are never portfolio savings.",
                                    "Monthly estimates hold the observed traffic rate and evidenced marginal prices for730hours; annual estimates unavailable.",
                                    "Inbound source plus inbound destination counters count both traffic directions once; output byte counters are diagnostics.",
                                    "Regional NAT is not a single-subnet zonal NAT and requires its actual per-AZ footprint.",
                                    "Idle, IPv4, cross-AZ, cross-region and egress reviews do not assume deletion or removed resilience."]}
    result["assessment_hash"] = _hash(result)
    return result


def evaluate_network(data):
    with localcontext() as context:
        context.prec = 80
        context.rounding = ROUND_HALF_EVEN
        return _evaluate(data)
