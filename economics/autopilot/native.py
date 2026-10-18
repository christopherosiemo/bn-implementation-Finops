"""Additive native CUR pricing; no synthetic ContractedCost for AWS evidence."""
from .normalize import normalize, pick
from .model import decimal, money


def native_cost(raw):
    for basis, names in (
        ("NET_UNBLENDED", ("line_item_net_unblended_cost", "lineItem/NetUnblendedCost")),
        ("UNBLENDED", ("line_item_unblended_cost", "lineItem/UnblendedCost")),
    ):
        value = pick(raw, *names)
        if value is not None:
            return basis, decimal(value, basis)
    return "UNKNOWN", None


def normalize_v3(data):
    result = normalize(data)
    gaps = set(result["mapping_gaps"])
    # ContractedCost is not a native CUR column and is not required by this model.
    gaps.discard("CONTRACTED_COST_NOT_PROVIDED")
    gaps.discard("MISSING_ContractedCost")
    for row in result["records"]:
        basis, amount = native_cost(row["x_ProviderFields"])
        row["ContractedCost"] = None
        row["x_PricingBasis"] = basis
        row["x_NativeComputeCost"] = money(amount) if amount is not None else None
        row["x_MappingVersion"] = "aws-cur2-native-3"
        if amount is None:
            gaps.add("NATIVE_UNBLENDED_COST_MISSING")
    result["mapping_gaps"] = sorted(gaps)
    result["schema_version"] = "3"
    return result
