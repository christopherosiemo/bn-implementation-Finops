"""A versioned CUR 2.0 mapping with explicit gaps, not invented FOCUS values."""
from __future__ import annotations
from decimal import Decimal, localcontext
import hashlib
import json
from .model import EvidenceError, decimal, money


def pick(row: dict, *names: str, default=None):
    for name in names:
        value = row.get(name)
        if value is not None and value != "":
            return value
    return default


def normalize(data: dict) -> dict:
    rows = data.get("records")
    if not isinstance(rows, list) or len(rows) > 100000:
        raise EvidenceError("records must be a list of at most 100000 CUR records")
    source_id, version = data.get("source_id"), data.get("source_version")
    if not source_id or not version:
        raise EvidenceError("source_id and source_version are required")
    canonical, gaps, totals, seen = [], set(), {}, set()
    with localcontext() as ctx:
        ctx.prec = 60
        for row in rows:
            if not isinstance(row, dict):
                raise EvidenceError("billing record must be an object")
            record_id = str(pick(row, "identity_line_item_id", "identity/LineItemId", "source_record_id", default=""))
            if not record_id:
                record_id = hashlib.sha256(json.dumps(row, sort_keys=True, default=str).encode()).hexdigest()
            if record_id in seen:
                raise EvidenceError("duplicate billing record in source version")
            seen.add(record_id)
            currency = pick(row, "line_item_currency_code", "lineItem/CurrencyCode", "BillingCurrency")
            if not isinstance(currency, str) or len(currency) != 3:
                raise EvidenceError("billing record requires its native currency")
            kind = str(pick(row, "line_item_line_item_type", "lineItem/LineItemType", default="Usage"))
            billed_value = pick(row, "line_item_net_unblended_cost", "lineItem/NetUnblendedCost", "line_item_unblended_cost", "lineItem/UnblendedCost", "BilledCost")
            billed = decimal(str(billed_value), "BilledCost")
            # Credits/refunds preserve the source sign. We never negate blindly.
            if kind in ("Credit", "Refund") and billed > 0:
                gaps.add("POSITIVE_CREDIT_REQUIRES_SOURCE_REVIEW")
            effective_value = pick(row, "reservation_net_effective_cost", "reservation/NetEffectiveCost", "reservation_effective_cost", "reservation/EffectiveCost", "savings_plan_net_savings_plan_effective_cost", "savingsPlan/NetSavingsPlanEffectiveCost", "savings_plan_savings_plan_effective_cost", "savingsPlan/SavingsPlanEffectiveCost", "EffectiveCost")
            if kind in ("DiscountedUsage", "SavingsPlanCoveredUsage") and effective_value is None:
                effective = None
                gaps.add("COMMITMENT_EFFECTIVE_COST_MISSING")
            elif kind in ("SavingsPlanNegation", "RIFee", "SavingsPlanRecurringFee", "SavingsPlanUpfrontFee"):
                # Portfolio allocation needs provider amortisation data. Do not add
                # coverage + fee lines as though each were marginal compute cost.
                effective = None
                gaps.add("COMMITMENT_ALLOCATION_REQUIRED")
            else:
                effective = decimal(str(effective_value), "EffectiveCost") if effective_value is not None else billed
            list_value = pick(row, "pricing_public_on_demand_cost", "pricing/publicOnDemandCost", "ListCost")
            contracted_value = pick(row, "ContractedCost")
            if contracted_value is None:
                gaps.add("CONTRACTED_COST_NOT_PROVIDED")
            category = "Usage"
            if kind in ("Credit", "Refund"):
                category = "Credit"
            elif kind == "Tax":
                category = "Tax"
            elif kind in ("Fee", "RIFee", "SavingsPlanRecurringFee", "SavingsPlanUpfrontFee"):
                category = "Purchase"
            account = str(pick(row, "line_item_usage_account_id", "lineItem/UsageAccountId", "SubAccountId", default=""))
            resource = str(pick(row, "line_item_resource_id", "lineItem/ResourceId", "ResourceId", default=""))
            if not resource:
                gaps.add("RESOURCE_ALLOCATION_MISSING")
            canonical.append({
                "BillingCurrency": currency, "BilledCost": money(billed),
                "EffectiveCost": money(effective) if effective is not None else None,
                "ListCost": money(decimal(str(list_value))) if list_value is not None else None,
                "ContractedCost": money(decimal(str(contracted_value))) if contracted_value is not None else None,
                "BillingAccountId": str(pick(row, "bill_payer_account_id", "bill/PayerAccountId", "BillingAccountId", default="")),
                "SubAccountId": account, "ResourceId": resource,
                "ServiceProviderName": pick(row, "ServiceProviderName", default="Amazon Web Services" if pick(row,"bill_billing_entity","bill/BillingEntity",default="AWS") != "AWS Marketplace" else None),
                "HostProviderName": pick(row, "HostProviderName", default="Amazon Web Services" if pick(row,"bill_billing_entity","bill/BillingEntity",default="AWS") != "AWS Marketplace" else None),
                "InvoiceIssuerName": pick(row, "bill_invoicing_entity", "bill/InvoicingEntity", "InvoiceIssuerName"),
                "ServiceName": pick(row, "product_servicecode", "product/servicecode", "ServiceName", default="Unknown"),
                "RegionId": pick(row, "product_region_code", "product/regionCode", "RegionId"),
                "ChargeCategory": category, "ChargeClass": "Correction" if row.get("correction") is True else None,
                "ChargePeriodStart": pick(row, "line_item_usage_start_date", "lineItem/UsageStartDate", "ChargePeriodStart"),
                "ChargePeriodEnd": pick(row, "line_item_usage_end_date", "lineItem/UsageEndDate", "ChargePeriodEnd"),
                "BillingPeriodStart": pick(row, "bill_billing_period_start_date", "bill/BillingPeriodStartDate", "BillingPeriodStart"),
                "BillingPeriodEnd": pick(row, "bill_billing_period_end_date", "bill/BillingPeriodEndDate", "BillingPeriodEnd"),
                "Tags": pick(row, "resource_tags", "Tags", default={}),
                "x_SourceRecordId": record_id, "x_SourceId": source_id,
                "x_SourceVersion": version, "x_FocusVersion": "1.4",
                "x_MappingVersion": "aws-cur2-pilot-1", "x_ProviderFields": row,
            })
            # FOCUS 1.4 removed ProviderName/PublisherName. Unsupported values
            # stay null with a per-column gap; a version label is not certification.
            for name in ("BillingAccountId", "ServiceProviderName", "HostProviderName", "InvoiceIssuerName", "ChargePeriodStart", "ChargePeriodEnd", "BillingPeriodStart", "BillingPeriodEnd", "ListCost", "ContractedCost", "EffectiveCost"):
                if canonical[-1].get(name) is None or canonical[-1].get(name) == "":
                    gaps.add("MISSING_" + name)
            totals[currency] = totals.get(currency, Decimal("0")) + billed
        expected_totals = data.get("invoice_totals", {})
        reconciliations = {}
        for currency, total in totals.items():
            invoice = expected_totals.get(currency)
            if invoice is None:
                reconciliations[currency] = {"status": "PROVISIONAL", "ratio": None, "variance": None}
            else:
                invoice = decimal(invoice, "invoice_total")
                variance = total - invoice
                ratio = max(Decimal("0"), Decimal("1") - abs(variance) / abs(invoice)) if invoice else (Decimal("1") if not total else Decimal("0"))
                reconciliations[currency] = {"status": "RECONCILED" if ratio >= Decimal("0.995") else "VARIANCE", "ratio": money(ratio), "variance": money(variance)}
        return {"records": canonical, "totals": {c: money(v) for c, v in totals.items()}, "mapping_gaps": sorted(gaps), "reconciliation": reconciliations, "focus_version": "1.4", "conformance": "MAPPED_WITH_EXPLICIT_GAPS"}
