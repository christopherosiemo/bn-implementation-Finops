package commitmentportfolio

import (
	"regexp"
	"strconv"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

var unsignedInteger = regexp.MustCompile(`^(0|[1-9][0-9]{0,18})$`)

func reservedInstancePosition(ri model.Document, account string, nativeRef Ref) (Position, error) {
	p := Position{ID: account + ":ri:" + model.String(ri, "id"), AccountID: account, Class: "EC2_RI_UNCLASSIFIED", State: model.String(ri, "state"), Region: nullable(model.String(ri, "region")), End: date(model.String(ri, "end")), RecurringAmountUnit: "PROVIDER_FIELD_UNIT_UNVERIFIED", NativeRef: nativeRef, ReasonCodes: []string{"RI_CLASS_SCOPE_TERMS_CURRENCY_NOT_ISSUED"}}
	if model.String(ri, "native_projection") != "AWS_EC2_DESCRIBE_RESERVED_INSTANCES_V2" {
		return p, nil
	}
	text := func(key string) (*string, error) {
		v, ok := ri[key]
		if !ok || v == nil {
			return nil, nil
		}
		s, ok := v.(string)
		if !ok || s == "" || len(s) > 2048 {
			return nil, ErrEvidence
		}
		return &s, nil
	}
	terms := &ReservedInstanceTerms{}
	for key, target := range map[string]**string{"offering_class": &terms.OfferingClass, "offering_type": &terms.OfferingType, "scope": &terms.Scope, "duration_seconds": &terms.DurationSeconds, "currency_code": &terms.CurrencyCode, "fixed_price": &terms.FixedPrice, "usage_price": &terms.UsagePrice, "instance_count": &terms.InstanceCount, "instance_type": &terms.InstanceType, "instance_tenancy": &terms.InstanceTenancy, "product_description": &terms.ProductDescription, "availability_zone": &terms.AvailabilityZone, "availability_zone_id": &terms.AvailabilityZoneID} {
		value, e := text(key)
		if e != nil {
			return Position{}, e
		}
		*target = value
	}
	for _, value := range []*string{terms.FixedPrice, terms.UsagePrice} {
		if value != nil {
			if _, e := decimalValue(*value); e != nil {
				return Position{}, e
			}
		}
	}
	for _, value := range []*string{terms.DurationSeconds, terms.InstanceCount} {
		if value != nil {
			if !unsignedInteger.MatchString(*value) {
				return Position{}, ErrEvidence
			}
			n, e := strconv.ParseUint(*value, 10, 64)
			if e != nil || n == 0 {
				return Position{}, ErrEvidence
			}
		}
	}
	if terms.CurrencyCode != nil && !regexp.MustCompile(`^[A-Z]{3}$`).MatchString(*terms.CurrencyCode) {
		return Position{}, ErrEvidence
	}
	if container, exists := ri["recurring_charges"]; exists && container != nil {
		raw, e := jsonValue(container)
		if e != nil {
			return Position{}, ErrEvidence
		}
		if len(raw) > 64<<10 {
			return Position{}, ErrEvidence
		}
		charges, e := decodeRecurringCharges(raw)
		if e != nil || len(charges) > 32 {
			return Position{}, ErrEvidence
		}
		terms.RecurringCharges = charges
		for _, charge := range charges {
			if charge.Amount != nil {
				if _, e := decimalValue(*charge.Amount); e != nil {
					return Position{}, e
				}
			}
			if charge.Frequency != nil && (*charge.Frequency == "" || len(*charge.Frequency) > 128) {
				return Position{}, ErrEvidence
			}
		}
	}
	p.ReservedInstanceTerms = terms
	p.Currency = terms.CurrencyCode
	p.Start = date(model.String(ri, "start"))
	p.TermSeconds = terms.DurationSeconds
	if terms.OfferingClass != nil {
		switch *terms.OfferingClass {
		case "standard":
			p.Class = "EC2_STANDARD_RI"
		case "convertible":
			p.Class = "EC2_CONVERTIBLE_RI"
		}
	}
	p.ReasonCodes = []string{"RI_USAGE_ALLOCATION_AND_CASH_SCHEDULE_NOT_ISSUED"}
	if p.Class == "EC2_RI_UNCLASSIFIED" {
		p.ReasonCodes = append(p.ReasonCodes, "RI_OFFERING_CLASS_UNAVAILABLE")
	}
	return p, nil
}
