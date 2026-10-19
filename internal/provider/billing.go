package provider

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bcmdataexports"
	"github.com/aws/aws-sdk-go-v2/service/invoicing"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/savingsplans"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

type BillingObject struct {
	Key, VersionID, ETag string
	LastModified         time.Time
	Data                 []byte
}
type BillingAWS struct {
	*AWS
	ExpectedOwner string
	MemberReader  func(context.Context, string) (*BillingAWS, error)
}

func NewBillingAWS(ctx context.Context, region, role, external, owner string) (*BillingAWS, error) {
	a, e := NewAWS(ctx, region, role, external)
	if e != nil {
		return nil, e
	}
	a.cfg.HTTPClient = &http.Client{Timeout: 45 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &BillingAWS{AWS: a, ExpectedOwner: owner}, nil
}
func nativeDocument(v any) model.Document {
	b, _ := json.Marshal(v)
	var d model.Document
	_ = json.Unmarshal(b, &d)
	return d
}
func (a *BillingAWS) global() aws.Config { c := a.cfg; c.Region = "us-east-1"; return c }
func (a *BillingAWS) ListBillingExecutions(ctx context.Context, arn string) ([]model.Document, error) {
	c := bcmdataexports.NewFromConfig(a.global())
	out := []model.Document{}
	var token *string
	seen := map[string]bool{}
	for pages := 0; pages < 100; pages++ {
		r, e := c.ListExecutions(ctx, &bcmdataexports.ListExecutionsInput{ExportArn: aws.String(arn), NextToken: token, MaxResults: aws.Int32(100)})
		if e != nil {
			return nil, e
		}
		for _, x := range r.Executions {
			out = append(out, nativeDocument(x))
		}
		if r.NextToken == nil || *r.NextToken == "" {
			return out, nil
		}
		if seen[*r.NextToken] {
			return nil, errors.New("AWS_PAGINATION_CYCLE")
		}
		seen[*r.NextToken] = true
		token = r.NextToken
	}
	return nil, errors.New("AWS_EXECUTION_LIMIT")
}
func (a *BillingAWS) BillingExecution(ctx context.Context, arn, id string) (model.Document, error) {
	r, e := bcmdataexports.NewFromConfig(a.global()).GetExecution(ctx, &bcmdataexports.GetExecutionInput{ExportArn: aws.String(arn), ExecutionId: aws.String(id)})
	if e != nil {
		return nil, e
	}
	return model.Document{"ExecutionId": aws.ToString(r.ExecutionId), "ExecutionStatus": nativeDocument(r.ExecutionStatus), "Export": nativeDocument(r.Export)}, nil
}
func (a *BillingAWS) BillingManifestKeys(ctx context.Context, bucket, prefix, execution string) ([]string, error) {
	out := []string{}
	c := s3.NewFromConfig(a.cfg)
	var token *string
	seen := map[string]bool{}
	for pages := 0; pages < 100; pages++ {
		r, e := c.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: aws.String(bucket), ExpectedBucketOwner: aws.String(a.ExpectedOwner), Prefix: aws.String(prefix), ContinuationToken: token, MaxKeys: aws.Int32(1000)})
		if e != nil {
			return nil, e
		}
		for _, v := range r.Contents {
			key := aws.ToString(v.Key)
			if strings.HasSuffix(key, "Manifest.json") && strings.Contains(key, "-"+execution+"/") {
				out = append(out, key)
			}
		}
		if !aws.ToBool(r.IsTruncated) {
			return out, nil
		}
		if r.NextContinuationToken == nil || seen[*r.NextContinuationToken] {
			return nil, errors.New("AWS_PAGINATION_CYCLE")
		}
		seen[*r.NextContinuationToken] = true
		token = r.NextContinuationToken
	}
	return nil, errors.New("AWS_MANIFEST_LIST_LIMIT")
}
func (a *BillingAWS) BillingObject(ctx context.Context, bucket, key, version string) (BillingObject, error) {
	var out BillingObject
	in := &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key), ExpectedBucketOwner: aws.String(a.ExpectedOwner)}
	if version != "" {
		in.VersionId = aws.String(version)
	}
	r, e := s3.NewFromConfig(a.cfg).GetObject(ctx, in)
	if e != nil {
		return out, e
	}
	defer r.Body.Close()
	if r.VersionId == nil || *r.VersionId == "" || *r.VersionId == "null" {
		return out, errors.New("SOURCE_OBJECT_VERSION_REQUIRED")
	}
	if r.ContentLength != nil && *r.ContentLength > 64<<20 {
		return out, errors.New("SOURCE_OBJECT_LIMIT")
	}
	b, e := io.ReadAll(io.LimitReader(r.Body, (64<<20)+1))
	if e != nil {
		return out, e
	}
	if len(b) > 64<<20 {
		return out, errors.New("SOURCE_OBJECT_LIMIT")
	}
	return BillingObject{Key: key, VersionID: *r.VersionId, ETag: aws.ToString(r.ETag), LastModified: aws.ToTime(r.LastModified), Data: b}, nil
}
func (a *BillingAWS) BillingBucket(ctx context.Context, bucket string) (model.Document, error) {
	c := s3.NewFromConfig(a.cfg)
	v, e := c.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: aws.String(bucket), ExpectedBucketOwner: aws.String(a.ExpectedOwner)})
	if e != nil {
		return nil, e
	}
	p, e := c.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{Bucket: aws.String(bucket), ExpectedBucketOwner: aws.String(a.ExpectedOwner)})
	if e != nil {
		return nil, e
	}
	l, e := c.GetBucketLocation(ctx, &s3.GetBucketLocationInput{Bucket: aws.String(bucket), ExpectedBucketOwner: aws.String(a.ExpectedOwner)})
	if e != nil {
		return nil, e
	}
	policy := model.Document{}
	if e = json.Unmarshal([]byte(aws.ToString(p.Policy)), &policy); e != nil {
		return nil, errors.New("SOURCE_POLICY_INVALID")
	}
	region := string(l.LocationConstraint)
	if region == "EU" {
		region = "eu-west-1"
	}
	if region == "" {
		region = "us-east-1"
	}
	return model.Document{"versioning": string(v.Status), "policy": policy, "region": region, "bucket_owner": a.ExpectedOwner, "observed_at": model.Now()}, nil
}
func (a *BillingAWS) BillingInvoices(ctx context.Context, payer string, year, month int) ([]model.Document, error) {
	c := invoicing.NewFromConfig(a.global())
	var in invoicing.ListInvoiceSummariesInput
	raw, _ := json.Marshal(model.Document{"Selector": model.Document{"ResourceType": "ACCOUNT_ID", "Value": payer}, "Filter": model.Document{"BillingPeriod": model.Document{"Year": year, "Month": month}}, "MaxResults": 100})
	if e := json.Unmarshal(raw, &in); e != nil {
		return nil, e
	}
	out := []model.Document{}
	seen := map[string]bool{}
	for pages := 0; pages < 100; pages++ {
		r, e := c.ListInvoiceSummaries(ctx, &in)
		if e != nil {
			return nil, e
		}
		for _, v := range r.InvoiceSummaries {
			out = append(out, nativeDocument(v))
		}
		if r.NextToken == nil || *r.NextToken == "" {
			return out, nil
		}
		if seen[*r.NextToken] {
			return nil, errors.New("AWS_PAGINATION_CYCLE")
		}
		seen[*r.NextToken] = true
		in.NextToken = r.NextToken
	}
	return nil, errors.New("AWS_INVOICE_LIMIT")
}

// reservedInstanceNativeV2 is a projection of DescribeReservedInstances, not an
// offering, forecast or purchase authorization. Existing issued four-field RI
// records have no discriminator and retain their original limited meaning.
// https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_ReservedInstances.html
type reservedInstanceNativeV2 struct {
	ID                 string  `xml:"reservedInstancesId"`
	State              string  `xml:"state"`
	End                string  `xml:"end"`
	OfferingClass      *string `xml:"offeringClass"`
	OfferingType       *string `xml:"offeringType"`
	Scope              *string `xml:"scope"`
	Start              *string `xml:"start"`
	Duration           *string `xml:"duration"`
	CurrencyCode       *string `xml:"currencyCode"`
	FixedPrice         *string `xml:"fixedPrice"`
	UsagePrice         *string `xml:"usagePrice"`
	InstanceCount      *string `xml:"instanceCount"`
	InstanceType       *string `xml:"instanceType"`
	InstanceTenancy    *string `xml:"instanceTenancy"`
	ProductDescription *string `xml:"productDescription"`
	AvailabilityZone   *string `xml:"availabilityZone"`
	AvailabilityZoneID *string `xml:"availabilityZoneId"`
	RecurringCharges   *struct {
		Items []struct {
			Amount    *string `xml:"amount"`
			Frequency *string `xml:"frequency"`
		} `xml:"item"`
	} `xml:"recurringCharges"`
}

func nativeOptionalText(value *string) any {
	if value == nil {
		return nil
	}
	return *value
}

func (v reservedInstanceNativeV2) document(region string) model.Document {
	var recurring any
	if v.RecurringCharges != nil {
		items := []model.Document{}
		for _, charge := range v.RecurringCharges.Items {
			items = append(items, model.Document{"amount": nativeOptionalText(charge.Amount), "frequency": nativeOptionalText(charge.Frequency)})
		}
		recurring = items
	}
	// Preserve native lexical decimals/integers and presence, including explicit
	// zero. No float conversion, default currency, inferred monthly unit or
	// multiplication by instanceCount is applied. Consumers validate supported
	// class/scope/units before deriving amounts; future/unknown values stay raw.
	return model.Document{
		"id": v.ID, "state": v.State, "region": region, "end": v.End,
		"native_projection": "AWS_EC2_DESCRIBE_RESERVED_INSTANCES_V2",
		"offering_class":    nativeOptionalText(v.OfferingClass), "offering_type": nativeOptionalText(v.OfferingType),
		"scope": nativeOptionalText(v.Scope), "start": nativeOptionalText(v.Start), "duration_seconds": nativeOptionalText(v.Duration),
		"currency_code": nativeOptionalText(v.CurrencyCode), "fixed_price": nativeOptionalText(v.FixedPrice), "usage_price": nativeOptionalText(v.UsagePrice),
		"instance_count": nativeOptionalText(v.InstanceCount), "instance_type": nativeOptionalText(v.InstanceType), "instance_tenancy": nativeOptionalText(v.InstanceTenancy),
		"product_description": nativeOptionalText(v.ProductDescription), "availability_zone": nativeOptionalText(v.AvailabilityZone), "availability_zone_id": nativeOptionalText(v.AvailabilityZoneID),
		"recurring_charges": recurring,
	}
}

// ParseReservedInstancesResponse shares the collector's native Query response
// projection with local transport fixtures. Parsing is not authentication: only
// the signed, account-scoped collector and issued receipt establish provenance.
func ParseReservedInstancesResponse(raw []byte, region string) ([]model.Document, string, error) {
	if len(raw) == 0 || len(raw) > 16<<20 || !validRegion(region) {
		return nil, "", errors.New("COMMITMENT_RI_RESPONSE_INVALID")
	}
	var response struct {
		XMLName xml.Name                   `xml:"DescribeReservedInstancesResponse"`
		Items   []reservedInstanceNativeV2 `xml:"reservedInstancesSet>item"`
		Next    string                     `xml:"nextToken"`
	}
	decoder := xml.NewDecoder(strings.NewReader(string(raw)))
	if e := decoder.Decode(&response); e != nil {
		return nil, "", errors.New("COMMITMENT_RI_RESPONSE_INVALID")
	}
	for {
		token, e := decoder.Token()
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, "", errors.New("COMMITMENT_RI_RESPONSE_INVALID")
		}
		if text, ok := token.(xml.CharData); !ok || strings.TrimSpace(string(text)) != "" {
			return nil, "", errors.New("COMMITMENT_RI_RESPONSE_INVALID")
		}
	}
	rows := []model.Document{}
	for _, item := range response.Items {
		if item.State != "retired" {
			rows = append(rows, item.document(region))
		}
	}
	return rows, response.Next, nil
}

func (a *BillingAWS) accountCommitments(ctx context.Context) (model.Document, error) {
	var regions struct {
		Items []struct {
			Name string `xml:"regionName"`
		} `xml:"regionInfo>item"`
	}
	if e := a.query(ctx, a.cfg.Region, "DescribeRegions", url.Values{}, &regions); e != nil {
		return nil, e
	}
	if len(regions.Items) == 0 {
		return nil, errors.New("COMMITMENT_REGIONS_UNKNOWN")
	}
	ris := []model.Document{}
	for _, region := range regions.Items {
		var token string
		seen := map[string]bool{}
		for pages := 0; pages < 100; pages++ {
			values := url.Values{}
			if token != "" {
				values.Set("NextToken", token)
			}
			var r struct {
				XMLName xml.Name `xml:"DescribeReservedInstancesResponse"`
				Inner   string   `xml:",innerxml"`
			}
			if e := a.query(ctx, region.Name, "DescribeReservedInstances", values, &r); e != nil {
				return nil, e
			}
			rows, next, e := ParseReservedInstancesResponse([]byte("<DescribeReservedInstancesResponse>"+r.Inner+"</DescribeReservedInstancesResponse>"), region.Name)
			if e != nil {
				return nil, e
			}
			ris = append(ris, rows...)
			if next == "" {
				break
			}
			if seen[next] {
				return nil, errors.New("AWS_PAGINATION_CYCLE")
			}
			seen[next] = true
			token = next
			if pages == 99 {
				return nil, errors.New("AWS_COMMITMENT_LIMIT")
			}
		}
	}
	plans := []model.Document{}
	c := savingsplans.NewFromConfig(a.global())
	var token *string
	seen := map[string]bool{}
	for pages := 0; pages < 100; pages++ {
		r, e := c.DescribeSavingsPlans(ctx, &savingsplans.DescribeSavingsPlansInput{NextToken: token, MaxResults: aws.Int32(1000)})
		if e != nil {
			return nil, e
		}
		for _, v := range r.SavingsPlans {
			if string(v.State) != "retired" && string(v.State) != "returned" {
				plans = append(plans, nativeDocument(v))
			}
		}
		if r.NextToken == nil || *r.NextToken == "" {
			break
		}
		if seen[*r.NextToken] {
			return nil, errors.New("AWS_PAGINATION_CYCLE")
		}
		seen[*r.NextToken] = true
		token = r.NextToken
		if pages == 99 {
			return nil, errors.New("AWS_COMMITMENT_LIMIT")
		}
	}
	return model.Document{"reserved_instances": ris, "savings_plans": plans, "regions": regions.Items, "reserved_instance_count": len(ris), "savings_plan_count": len(plans)}, nil
}
func (a *BillingAWS) BillingCommitments(ctx context.Context, payer string) (model.Document, error) {
	now := model.Now()
	proof := model.Document{"payer_account_id": payer, "usage_account_ids": []string{}, "scope": "PAYER_ALL_LINKED_ACCOUNTS_ALL_REGIONS", "complete": false, "observed_at": now, "reason_code": "COMMITMENT_SCOPE_UNAVAILABLE"}
	identity, e := sts.NewFromConfig(a.cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if e != nil {
		return nil, e
	}
	if aws.ToString(identity.Account) != payer {
		return proof, nil
	}
	accounts := []string{payer}
	org := organizations.NewFromConfig(a.global())
	description, e := org.DescribeOrganization(ctx, &organizations.DescribeOrganizationInput{})
	if e != nil {
		var api smithy.APIError
		if !errors.As(e, &api) || api.ErrorCode() != "AWSOrganizationsNotInUseException" {
			return proof, nil
		}
	} else {
		if description.Organization == nil || aws.ToString(description.Organization.MasterAccountId) != payer {
			return proof, nil
		}
		accounts = []string{}
		var token *string
		seen := map[string]bool{}
		for pages := 0; pages < 100; pages++ {
			r, err := org.ListAccounts(ctx, &organizations.ListAccountsInput{NextToken: token, MaxResults: aws.Int32(20)})
			if err != nil {
				return proof, nil
			}
			for _, v := range r.Accounts {
				accounts = append(accounts, aws.ToString(v.Id))
			}
			if r.NextToken == nil || *r.NextToken == "" {
				break
			}
			if seen[*r.NextToken] {
				return proof, nil
			}
			seen[*r.NextToken] = true
			token = r.NextToken
			if pages == 99 {
				return proof, nil
			}
		}
	}
	if len(accounts) == 0 {
		return proof, nil
	}
	snapshots := []model.Document{}
	ri, sp := int64(0), int64(0)
	for _, account := range accounts {
		reader := a
		if account != payer {
			if a.MemberReader == nil {
				return proof, nil
			}
			reader, e = a.MemberReader(ctx, account)
			if e != nil {
				return proof, nil
			}
			actual, err := sts.NewFromConfig(reader.cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
			if err != nil || aws.ToString(actual.Account) != account {
				return proof, nil
			}
		}
		snapshot, err := reader.accountCommitments(ctx)
		if err != nil {
			return proof, nil
		}
		snapshot["account_id"] = account
		snapshots = append(snapshots, snapshot)
		ri += model.Number(snapshot, "reserved_instance_count")
		sp += model.Number(snapshot, "savings_plan_count")
	}
	proof["usage_account_ids"], proof["complete"], proof["reserved_instance_count"], proof["savings_plan_count"], proof["native_snapshots"], proof["reason_code"] = accounts, true, ri, sp, snapshots, "COMMITMENT_SCOPE_VERIFIED"
	return proof, nil
}
