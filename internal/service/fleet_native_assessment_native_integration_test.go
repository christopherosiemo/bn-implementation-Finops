package service

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleetassessment"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleetassessmentworker"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleetbilling"
	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/telemetry"
	"github.com/jackc/pgx/v5/pgconn"
)

const nativeAssessmentAccount = "111122223333"
const nativeAssessmentTemplate = "lt-0123456789abcdef0"
const nativeAssessmentImage = "ami-0123456789abcdef0"

type nativeAssessmentPage struct {
	selector url.Values
	body     string
}

func nativeAssessmentFrame(pages ...nativeAssessmentPage) []byte {
	var b bytes.Buffer
	for _, p := range pages {
		selector := p.selector.Encode()
		_ = binary.Write(&b, binary.BigEndian, uint32(len(selector)))
		b.WriteString(selector)
		_ = binary.Write(&b, binary.BigEndian, uint64(len(p.body)))
		b.WriteString(p.body)
	}
	return b.Bytes()
}

// These are explicit provider-shaped transport doubles. Each exact selector and
// XML response is archived and independently reparsed by the production decoder;
// no AWS account, historical membership or customer-native acceptance is claimed.
func nativeAssessmentHardware(t *testing.T, instance, kind string, now time.Time) (provider.HardwareEvidence, []byte) {
	t.Helper()
	raw := nativeAssessmentFrame(
		nativeAssessmentPage{url.Values{"Action": {"DescribeInstances"}, "Version": {"2016-11-15"}, "InstanceId.1": {instance}}, fmt.Sprintf(`<DescribeInstancesResponse><reservationSet><item><ownerId>%s</ownerId><instancesSet><item><instanceId>%s</instanceId><instanceType>%s</instanceType><imageId>%s</imageId><subnetId>subnet-0123456789abcdef0</subnetId><vpcId>vpc-0123456789abcdef0</vpcId><platformDetails>Linux/UNIX</platformDetails><usageOperation>RunInstances</usageOperation><placement><availabilityZone>eu-west-1a</availabilityZone><tenancy>default</tenancy></placement><blockDeviceMapping><item><deviceName>/dev/sda1</deviceName><ebs><volumeId>vol-0123456789abcdef0</volumeId></ebs></item></blockDeviceMapping></item></instancesSet></item></reservationSet></DescribeInstancesResponse>`, nativeAssessmentAccount, instance, kind, nativeAssessmentImage)},
		nativeAssessmentPage{url.Values{"Action": {"DescribeInstanceTypes"}, "Version": {"2016-11-15"}, "IncludeUnsupportedInRegion": {"false"}, "InstanceType.1": {kind}}, `<DescribeInstanceTypesResponse><instanceTypeSet><item><instanceType>` + kind + `</instanceType></item></instanceTypeSet></DescribeInstanceTypesResponse>`},
		nativeAssessmentPage{url.Values{"Action": {"DescribeInstanceTypeOfferings"}, "Version": {"2016-11-15"}, "LocationType": {"availability-zone"}, "Filter.1.Name": {"instance-type"}, "Filter.1.Value.1": {kind}, "Filter.2.Name": {"location"}, "Filter.2.Value.1": {"eu-west-1a"}, "MaxResults": {"1000"}}, `<DescribeInstanceTypeOfferingsResponse><instanceTypeOfferingSet><item><instanceType>` + kind + `</instanceType><locationType>availability-zone</locationType><location>eu-west-1a</location></item></instanceTypeOfferingSet></DescribeInstanceTypeOfferingsResponse>`},
		nativeAssessmentPage{url.Values{"Action": {"DescribeVolumes"}, "Version": {"2016-11-15"}, "VolumeId.1": {"vol-0123456789abcdef0"}}, `<DescribeVolumesResponse><volumeSet><item><volumeId>vol-0123456789abcdef0</volumeId><availabilityZone>eu-west-1a</availabilityZone><attachmentSet><item><instanceId>` + instance + `</instanceId><device>/dev/sda1</device><status>attached</status></item></attachmentSet></item></volumeSet></DescribeVolumesResponse>`},
		nativeAssessmentPage{url.Values{"Action": {"DescribeImages"}, "Version": {"2016-11-15"}, "ImageId.1": {nativeAssessmentImage}}, `<DescribeImagesResponse><imagesSet><item><imageId>` + nativeAssessmentImage + `</imageId><platformDetails>Linux/UNIX</platformDetails><usageOperation>RunInstances</usageOperation><productCodes/></item></imagesSet></DescribeImagesResponse>`},
	)
	native, e := provider.ParseHardwareEvidence(raw, nativeAssessmentAccount, "eu-west-1", instance, []string{kind}, now)
	if e != nil || provider.ValidateHardwareEvidence(native, instance, []string{kind}) != nil {
		t.Fatal("provider-shaped hardware failed exact native decoder", e)
	}
	return native, raw
}

func nativeAssessmentMembership(s g.Selection, instances []string, version int) (model.Document, []byte) {
	name := strings.SplitN(s.Target.ASGARN, ":autoScalingGroupName/", 2)[1]
	members := ""
	for _, id := range instances {
		members += fmt.Sprintf(`<member><InstanceId>%s</InstanceId><LaunchTemplate><LaunchTemplateId>%s</LaunchTemplateId><Version>%d</Version></LaunchTemplate></member>`, id, nativeAssessmentTemplate, version)
	}
	body := fmt.Sprintf(`<DescribeAutoScalingGroupsResponse><DescribeAutoScalingGroupsResult><AutoScalingGroups><member><AutoScalingGroupName>%s</AutoScalingGroupName><AutoScalingGroupARN>%s</AutoScalingGroupARN><VPCZoneIdentifier>subnet-0123456789abcdef0</VPCZoneIdentifier><DesiredCapacity>%d</DesiredCapacity><LaunchTemplate><LaunchTemplateId>%s</LaunchTemplateId><Version>%d</Version></LaunchTemplate><Instances>%s</Instances></member></AutoScalingGroups></DescribeAutoScalingGroupsResult></DescribeAutoScalingGroupsResponse>`, name, s.Target.ASGARN, len(instances), nativeAssessmentTemplate, version, members)
	raw := nativeAssessmentFrame(nativeAssessmentPage{url.Values{"Action": {"DescribeAutoScalingGroups"}, "Version": {"2011-01-01"}, "MaxRecords": {"100"}, "AutoScalingGroupNames.member.1": {name}}, body})
	var parsed struct {
		Groups []provider.FleetGroup `xml:"DescribeAutoScalingGroupsResult>AutoScalingGroups>member"`
	}
	_ = xml.Unmarshal([]byte(body), &parsed)
	for i := range parsed.Groups {
		if parsed.Groups[i].Members == nil {
			parsed.Groups[i].Members = []provider.FleetMember{}
		}
	}
	return model.Document{"history_registration_id": s.Registration.ID, "history_registration_version": s.Registration.Version, "history_registration_hash": s.Registration.SHA256, "binding": model.Document{"tenant_id": s.Target.TenantID, "workload_id": s.Target.WorkloadID, "provider": "AWS", "account_id": s.Target.AccountID, "region": s.Target.Region}, "groups": parsed.Groups}, raw
}

func nativeAssessmentTemplates() (model.Document, []byte) {
	body := `<DescribeLaunchTemplateVersionsResponse><launchTemplateVersionSet>`
	for n, kind := range []string{"m6i.xlarge", "m6i.large"} {
		body += fmt.Sprintf(`<item><launchTemplateId>%s</launchTemplateId><versionNumber>%d</versionNumber><launchTemplateData><instanceType>%s</instanceType><imageId>%s</imageId><placement><tenancy>default</tenancy></placement></launchTemplateData></item>`, nativeAssessmentTemplate, n+1, kind, nativeAssessmentImage)
	}
	body += `</launchTemplateVersionSet></DescribeLaunchTemplateVersionsResponse>`
	raw := nativeAssessmentFrame(nativeAssessmentPage{url.Values{"Action": {"DescribeLaunchTemplateVersions"}, "Version": {"2016-11-15"}, "MaxResults": {"100"}, "ResolveAlias": {"false"}, "LaunchTemplateId": {nativeAssessmentTemplate}, "LaunchTemplateVersion.1": {"1"}, "LaunchTemplateVersion.2": {"2"}}, body})
	var parsed struct {
		Items []provider.FleetTemplateVersion `xml:"launchTemplateVersionSet>item"`
	}
	_ = xml.Unmarshal([]byte(body), &parsed)
	return model.Document{"requests": []provider.FleetTemplateRequest{{ID: nativeAssessmentTemplate, Version: 1}, {ID: nativeAssessmentTemplate, Version: 2}}, "templates": parsed.Items}, raw
}

func nativeAssessmentUsage(instance, kind, sku, cost, rate string, start, end time.Time) model.Document {
	return model.Document{"identity_line_item_id": instance + ":" + start.Format(time.RFC3339Nano), "line_item_resource_id": instance, "line_item_usage_account_id": nativeAssessmentAccount, "bill_payer_account_id": nativeAssessmentAccount, "line_item_currency_code": "USD", "line_item_line_item_type": "Usage", "line_item_usage_start_date": start.Format(time.RFC3339Nano), "line_item_usage_end_date": end.Format(time.RFC3339Nano), "line_item_usage_amount": fmt.Sprint(end.Sub(start).Hours()), "line_item_unblended_cost": cost, "line_item_unblended_rate": rate, "line_item_net_unblended_cost": "", "line_item_net_unblended_rate": "", "line_item_operation": "RunInstances", "line_item_usage_type": "EUW1-BoxUsage:" + kind, "pricing_term": "OnDemand", "pricing_unit": "Hrs", "product_servicecode": "AmazonEC2", "product_product_family": "Compute Instance", "product_region_code": "eu-west-1", "product_instance_type": kind, "product_operating_system": "Linux", "product_tenancy": "Shared", "product_license_model": "No License required", "product_pre_installed_sw": "NA", "product_sku": sku}
}

// Retain the ordinary authenticated-export pipeline, including CSV/manifest,
// policy, revision, canonical-count and current-month-head checks. Only the
// provider transport and FOCUS projection are deterministic local doubles.
type nativeAssessmentBillingReader struct {
	*source.FixtureReader
	months []*source.FixtureReader
}

type nativeAssessmentRepository struct {
	db      *store.Store
	request string
}

func (r nativeAssessmentRepository) ResolveGroupNative(ctx context.Context, tenant, oldID, candidateID string) (fleetbilling.GroupNativeSnapshot, error) {
	var out fleetbilling.GroupNativeSnapshot
	e := r.db.Do(ctx, tenant, func(tx *store.Tx) error {
		d, e := tx.FleetNativeAssessmentSnapshot(ctx, r.request)
		if e != nil {
			return e
		}
		raw, e := json.Marshal(d)
		if e != nil {
			return e
		}
		if e = json.Unmarshal(raw, &out); e != nil {
			return e
		}
		if out.Selection.OldProposal.ID != oldID || out.Selection.CandidateProposal.ID != candidateID {
			return errors.New("fixture snapshot selector differs")
		}
		return nil
	})
	return out, e
}

func (r *nativeAssessmentBillingReader) ListBillingExecutions(context.Context, string) ([]model.Document, error) {
	out := []model.Document{}
	for _, m := range r.months {
		out = append(out, model.Clone(m.Execution))
	}
	return out, nil
}
func (r *nativeAssessmentBillingReader) BillingExecution(ctx context.Context, arn, id string) (model.Document, error) {
	for _, m := range r.months {
		if model.String(m.Execution, "ExecutionId") == id {
			return m.BillingExecution(ctx, arn, id)
		}
	}
	return nil, errors.New("fixture export execution unavailable")
}
func (r *nativeAssessmentBillingReader) BillingManifestKeys(ctx context.Context, bucket, prefix, id string) ([]string, error) {
	for _, m := range r.months {
		if model.String(m.Execution, "ExecutionId") == id {
			return m.BillingManifestKeys(ctx, bucket, prefix, id)
		}
	}
	return nil, errors.New("fixture manifest unavailable")
}
func (r *nativeAssessmentBillingReader) BillingObject(ctx context.Context, bucket, key, version string) (provider.BillingObject, error) {
	for _, m := range r.months {
		if _, ok := m.Objects[key]; ok {
			return m.BillingObject(ctx, bucket, key, version)
		}
	}
	return provider.BillingObject{}, errors.New("fixture object unavailable")
}
func (r *nativeAssessmentBillingReader) BillingInvoices(ctx context.Context, payer string, year, month int) ([]model.Document, error) {
	for _, m := range r.months {
		if strings.Contains(m.ManifestKeys[0], fmt.Sprintf("BILLING_PERIOD=%04d-%02d/", year, month)) {
			return m.BillingInvoices(ctx, payer, year, month)
		}
	}
	return nil, errors.New("fixture invoice unavailable")
}

func nativeAssessmentExport(t *testing.T, r source.Registration, period time.Time, records []model.Document, now time.Time) *source.FixtureReader {
	t.Helper()
	m, e := source.NewFixtureReader(r, records)
	if e != nil {
		t.Fatal(e)
	}
	end := period.AddDate(0, 1, 0)
	execution := "assessment-" + period.Format("200601")
	objects := map[string]provider.BillingObject{}
	keys := []string{}
	for key, o := range m.Objects {
		if strings.HasSuffix(key, "Manifest.json") {
			continue
		}
		gz, e := gzip.NewReader(bytes.NewReader(o.Data))
		if e != nil {
			t.Fatal(e)
		}
		rows, e := csv.NewReader(gz).ReadAll()
		_ = gz.Close()
		if e != nil {
			t.Fatal(e)
		}
		for column, name := range rows[0] {
			if name == "bill_billing_period_start_date" || name == "bill_billing_period_end_date" {
				v := period
				if name == "bill_billing_period_end_date" {
					v = end
				}
				for i := 1; i < len(rows); i++ {
					rows[i][column] = v.Format(time.RFC3339)
				}
			}
		}
		var b bytes.Buffer
		z := gzip.NewWriter(&b)
		w := csv.NewWriter(z)
		if e = w.WriteAll(rows); e != nil {
			t.Fatal(e)
		}
		if e = z.Close(); e != nil {
			t.Fatal(e)
		}
		key = strings.ReplaceAll(strings.ReplaceAll(key, "BILLING_PERIOD=2026-09/", "BILLING_PERIOD="+period.Format("2006-01")+"/"), "fixture-delivery", execution)
		o.Key, o.Data, o.LastModified = key, b.Bytes(), now.Add(-3*time.Second)
		o.VersionID = "fixture-native-" + source.BytesHash(o.Data)
		o.ETag = source.BytesHash(o.Data)
		objects[key] = o
		keys = append(keys, key)
	}
	sort.Strings(keys)
	oldManifest := m.Objects[m.ManifestKeys[0]]
	var manifest model.Document
	_ = json.Unmarshal(oldManifest.Data, &manifest)
	manifest["reportKeys"], manifest["billingPeriod"] = keys, model.Document{"start": period.Format(time.RFC3339), "end": end.Format(time.RFC3339)}
	manifestKey := strings.ReplaceAll(strings.ReplaceAll(m.ManifestKeys[0], "BILLING_PERIOD=2026-09/", "BILLING_PERIOD="+period.Format("2006-01")+"/"), "fixture-delivery", execution)
	body, _ := json.Marshal(manifest)
	objects[manifestKey] = provider.BillingObject{Key: manifestKey, Data: body, VersionID: "fixture-native-" + source.BytesHash(body), ETag: source.BytesHash(body), LastModified: now.Add(-2 * time.Second)}
	m.Objects, m.ManifestKeys = objects, []string{manifestKey}
	m.Execution["ExecutionId"] = execution
	m.Execution["ExecutionStatus"] = model.Document{"StatusCode": "DELIVERY_SUCCESS", "CreatedAt": now.Add(-time.Duration(1+period.Month()) * time.Second).Format(time.RFC3339Nano)}
	for _, invoice := range m.Invoices {
		invoice["BillingPeriod"] = model.Document{"Year": period.Year(), "Month": int(period.Month())}
		invoice["IssuedDate"] = now.Add(-time.Second).Format(time.RFC3339Nano)
		sourceObject(invoice["BaseCurrencyAmount"])["CurrencyCode"] = "USD"
		amount := sourceObject(invoice["BaseCurrencyAmount"])
		amount["CurrencyCode"] = "USD"
		invoice["BaseCurrencyAmount"] = amount
	}
	return m
}

func TestFleetNativeAssessmentProviderShapedExportFixture(t *testing.T) {
	now := time.Now().UTC()
	r, e := source.ParseRegistration(source.FixtureRegistration("unit-native-fixture", "assessment-native"))
	if e != nil {
		t.Fatal(e)
	}
	end := now.Truncate(24 * time.Hour)
	start := end.Add(-24 * time.Hour)
	period := time.Date(start.Year(), start.Month(), 1, 0, 0, 0, 0, time.UTC)
	reader := nativeAssessmentExport(t, r, period, []model.Document{nativeAssessmentUsage("i-0123456789abcdef0", "m6i.xlarge", "NATIVE-SKU", "4.8", "0.2", start, end)}, now)
	exportName := model.String(sourceObject(reader.Execution["Export"]), "Name")
	object := reader.Objects[reader.ManifestKeys[0]]
	manifest, e := source.ParseManifest(r, exportName, model.String(reader.Execution, "ExecutionId"), object.Key, object.Data)
	if e != nil {
		t.Fatal("provider-shaped manifest fixture invalid", e)
	}
	for _, key := range manifest.Keys {
		rows, e := source.ParseGzipCSV(reader.Objects[key].Data)
		if e != nil || source.ValidateRows(r, manifest, rows) != nil || len(rows) != 1 {
			t.Fatal("native export date/CSV closure invalid", e)
		}
		for _, column := range []string{"line_item_net_unblended_cost", "line_item_net_unblended_rate"} {
			if value, exists := rows[0][column]; !exists || value != "" {
				t.Fatal("explicit native net columns absent")
			}
		}
	}
	_, _ = nativeAssessmentHardware(t, "i-0123456789abcdef0", "m6i.xlarge", now)
}

func TestFleetNativeAssessmentActualVersionedRawIngestionAPIAndWorker(t *testing.T) {
	if os.Getenv("FLEET_NATIVE_ASSESSMENT_LAB") != "ISOLATED_VERSIONED_MINIO" {
		t.Skip("requires separately owned PostgreSQL/MinIO native-shaped fixture")
	}
	if os.Getenv("TEST_FLEET_HISTORY_S3_ENDPOINT") != "http://minio:9000" {
		t.Fatal("only owned private MinIO endpoint accepted")
	}
	writerAccess, writerSecret := os.Getenv("TEST_FLEET_HISTORY_S3_ACCESS_KEY"), os.Getenv("TEST_FLEET_HISTORY_S3_SECRET_KEY")
	readerAccess, readerSecret := os.Getenv("TEST_FLEET_ASSESSMENT_READ_ACCESS_KEY"), os.Getenv("TEST_FLEET_ASSESSMENT_READ_SECRET_KEY")
	if writerAccess == "" || writerSecret == "" || readerAccess == "" || readerSecret == "" || writerAccess == readerAccess || writerSecret == readerSecret {
		t.Fatal("separate private archive reader required")
	}
	f, _, assessor, proposals := newFleetNativeHTTPTest(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	now := time.Now().UTC()
	client := func(access, secret string) *s3.Client {
		return s3.NewFromConfig(aws.Config{Region: "eu-west-1", Credentials: credentials.NewStaticCredentialsProvider(access, secret, "")}, func(o *s3.Options) { o.BaseEndpoint = aws.String("http://minio:9000"); o.UsePathStyle = true })
	}
	archive, readClient := client(writerAccess, writerSecret), client(readerAccess, readerSecret)
	bucket := "native-assessment-" + strings.ReplaceAll(model.ID(), "-", "")
	owner := "owned-native-assessment:" + model.ID()
	if _, e := archive.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(bucket)}); e != nil {
		t.Fatal("owned archive create", e)
	}
	if _, e := archive.PutBucketTagging(ctx, &s3.PutBucketTaggingInput{Bucket: aws.String(bucket), Tagging: &types.Tagging{TagSet: []types.Tag{{Key: aws.String("finops-assessment-owner"), Value: aws.String(owner)}}}}); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		c, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		tags, e := archive.GetBucketTagging(c, &s3.GetBucketTaggingInput{Bucket: aws.String(bucket)})
		owned := false
		if e == nil {
			for _, v := range tags.TagSet {
				owned = owned || aws.ToString(v.Key) == "finops-assessment-owner" && aws.ToString(v.Value) == owner
			}
		}
		if !owned {
			t.Error("owned archive cleanup refused")
			return
		}
		pages := s3.NewListObjectVersionsPaginator(archive, &s3.ListObjectVersionsInput{Bucket: aws.String(bucket)})
		for pages.HasMorePages() {
			p, e := pages.NextPage(c)
			if e != nil || len(p.Versions)+len(p.DeleteMarkers) > 1000 {
				t.Error("owned archive enumeration failed")
				return
			}
			objects := []types.ObjectIdentifier{}
			for _, v := range p.Versions {
				objects = append(objects, types.ObjectIdentifier{Key: v.Key, VersionId: v.VersionId})
			}
			for _, v := range p.DeleteMarkers {
				objects = append(objects, types.ObjectIdentifier{Key: v.Key, VersionId: v.VersionId})
			}
			if len(objects) > 0 {
				out, e := archive.DeleteObjects(c, &s3.DeleteObjectsInput{Bucket: aws.String(bucket), Delete: &types.Delete{Objects: objects, Quiet: aws.Bool(true)}})
				if e != nil || len(out.Errors) > 0 {
					t.Error("owned archive version cleanup failed")
					return
				}
			}
		}
		if _, e := archive.DeleteBucket(c, &s3.DeleteBucketInput{Bucket: aws.String(bucket)}); e != nil {
			t.Error("owned archive cleanup failed")
		}
	})
	if _, e := archive.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{Bucket: aws.String(bucket), VersioningConfiguration: &types.VersioningConfiguration{Status: types.BucketVersioningStatusEnabled}}); e != nil {
		t.Fatal(e)
	}
	archived := 0
	put := func(key string, body []byte) model.Document {
		t.Helper()
		out, e := archive.PutObject(ctx, &s3.PutObjectInput{Bucket: aws.String(bucket), Key: aws.String(key), Body: bytes.NewReader(body)})
		if e != nil || out.VersionId == nil || aws.ToString(out.VersionId) == "null" {
			t.Fatal("versioned fixture archive failed", e)
		}
		back, e := archive.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key), VersionId: out.VersionId})
		if e != nil {
			t.Fatal(e)
		}
		got, e := io.ReadAll(io.LimitReader(back.Body, 32<<20))
		_ = back.Body.Close()
		if e != nil || !bytes.Equal(got, body) || aws.ToString(back.VersionId) != aws.ToString(out.VersionId) {
			t.Fatal("exact versioned raw readback failed")
		}
		archived++
		return model.Document{"bucket": bucket, "key": key, "version_id": aws.ToString(out.VersionId), "body_sha256": source.BytesHash(body)}
	}
	var registration model.Document
	if e := f.roles["ingester"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		var e error
		registration, e = tx.SourceGet(ctx, "assessment-native")
		return e
	}); e != nil {
		t.Fatal(e)
	}
	cfg := source.ConfigurationHash(registration)
	publish := func(kind string, d model.Document, raw []byte) {
		t.Helper()
		d = model.Clone(d)
		digest := source.BytesHash(raw)
		prefix := "group-native/"
		if kind == "AWS_EC2_HARDWARE" {
			prefix = "hardware/" + model.String(sourceObject(d["binding"]), "resource_id") + "/"
		}
		ref := put("tenant/"+f.tenant+"/"+prefix+digest+".bin", raw)
		id := "native-observation-" + source.Hash(model.Document{"kind": kind, "raw": digest, "binding": d["binding"]})
		revision := "native-revision-" + source.Hash(model.Document{"kind": kind, "raw": digest})
		d["id"], d["kind"], d["source_id"], d["revision_id"], d["registration_version"], d["config_hash"], d["read_role_binding_id"], d["collected_at"], d["raw_object"] = id, kind, "assessment-native", revision, model.Number(registration, "version"), cfg, registration["read_role_binding_id"], time.Now().UTC(), ref
		if kind == "AWS_EC2_HARDWARE" {
			d["collected_at"] = sourceObject(d["native"])["collected_at"]
		}
		if e := f.roles["ingester"].Do(ctx, f.tenant, func(tx *store.Tx) error {
			rev := model.Document{"id": revision, "source_id": "assessment-native", "kind": kind, "revision_hash": source.Hash(model.Document{"kind": kind, "raw": digest}), "config_hash": cfg, "registration_version": model.Number(registration, "version"), "raw_object": ref, "observed_at": d["collected_at"]}
			if kind == "AWS_EC2_HARDWARE" {
				rev["resource_snapshot_hash"] = d["resource_snapshot_hash"]
			}
			if _, e := tx.SourceRevisionCreate(ctx, rev); e != nil {
				return e
			}
			_, e := tx.SourceReceiptCreate(ctx, d)
			return e
		}); e != nil {
			t.Fatal("actual ingester native publication failed", kind, e)
		}
	}
	finance := f.token(f.tenant, "native-finance", "FINANCE")
	code, request, _ := f.request("workloads/fixture-workload/fleet-native-assessments", `"1"`, "actual-native-request", finance, model.Document{"old_configuration_proposal_id": proposals[0], "candidate_configuration_proposal_id": proposals[1]})
	if code != 202 {
		t.Fatal("IDs-only native request", code, request)
	}
	var selected struct {
		Groups struct {
			Binding g.Binding `json:"binding"`
		} `json:"groups"`
	}
	raw, _ := json.Marshal(request["selection"])
	if json.Unmarshal(raw, &selected) != nil {
		t.Fatal("server selection unavailable")
	}
	instanceID := func() string { return "i-" + strings.ReplaceAll(model.ID(), "-", "")[:17] }
	oldIDs := []string{instanceID(), instanceID()}
	candidateID := instanceID()
	for _, v := range []struct {
		s       g.Selection
		ids     []string
		version int
	}{{selected.Groups.Binding.Old, oldIDs, 1}, {selected.Groups.Binding.Candidate, []string{}, 2}} {
		d, raw := nativeAssessmentMembership(v.s, v.ids, v.version)
		publish("AWS_FLEET_MEMBERSHIP", d, raw)
	}
	templates, raw := nativeAssessmentTemplates()
	publish("AWS_FLEET_LAUNCH_TEMPLATES", templates, raw)
	for n, instance := range append(append([]string{}, oldIDs...), candidateID) {
		kind := "m6i.xlarge"
		if n == 2 {
			kind = "m6i.large"
		}
		resource := "actual-native-" + instance
		var inventory model.Document
		if e := f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
			var e error
			inventory, e = tx.Create(ctx, "resources", model.Document{"id": resource, "workload_id": "fixture-workload", "provider": "AWS", "provider_resource_id": instance, "account_id": nativeAssessmentAccount, "region": "eu-west-1", "instance_type": kind})
			return e
		}); e != nil {
			t.Fatal(e)
		}
		native, raw := nativeAssessmentHardware(t, instance, kind, time.Now().UTC())
		publish("AWS_EC2_HARDWARE", model.Document{"binding": telemetry.Binding{TenantID: f.tenant, ResourceID: resource, WorkloadID: "fixture-workload", Provider: "AWS", ProviderResourceID: instance, AccountID: nativeAssessmentAccount, Region: "eu-west-1"}, "resource_version": model.Number(inventory, "version"), "resource_snapshot_hash": telemetry.Hash(inventory), "inventory_snapshot": inventory, "candidate_types": []string{kind}, "native": source.Object(native), "execution_authorized": false}, raw)
	}
	end := now.Truncate(24 * time.Hour)
	periodRows := map[string][]model.Document{}
	for i := 14; i > 0; i-- {
		start := end.AddDate(0, 0, -i)
		for _, id := range oldIDs {
			periodRows[start.Format("2006-01")] = append(periodRows[start.Format("2006-01")], nativeAssessmentUsage(id, "m6i.xlarge", "ACTUAL-FIXTURE-OLD-SKU", "4.8", "0.2", start, start.Add(24*time.Hour)))
		}
	}
	start := end.Add(-24 * time.Hour)
	periodRows[start.Format("2006-01")] = append(periodRows[start.Format("2006-01")], nativeAssessmentUsage(candidateID, "m6i.large", "ACTUAL-FIXTURE-CANDIDATE-SKU", "2.88", "0.12", start, end))
	r, e := source.ParseRegistration(registration)
	if e != nil {
		t.Fatal(e)
	}
	reader := &nativeAssessmentBillingReader{}
	keys := []string{}
	for key := range periodRows {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		period, _ := time.Parse("2006-01", key)
		reader.months = append(reader.months, nativeAssessmentExport(t, r, period, periodRows[key], time.Now().UTC()))
	}
	reader.FixtureReader = reader.months[0]
	normalize := func(_ context.Context, raw model.Document) (model.Document, error) {
		rows := []model.Document{}
		for _, p := range source.Rows(raw["records"]) {
			cost := p["line_item_unblended_cost"]
			if model.String(p, "line_item_net_unblended_cost") != "" {
				cost = p["line_item_net_unblended_cost"]
			}
			rows = append(rows, model.Document{"x_SourceRecordId": p["identity_line_item_id"], "x_SourceId": raw["source_id"], "x_SourceVersion": raw["source_version"], "x_ProviderFields": p, "SubAccountId": p["line_item_usage_account_id"], "ResourceId": p["line_item_resource_id"], "RegionId": p["product_region_code"], "BillingCurrency": p["line_item_currency_code"], "BillingAccountId": p["bill_payer_account_id"], "ChargePeriodStart": p["line_item_usage_start_date"], "ChargePeriodEnd": p["line_item_usage_end_date"], "BilledCost": cost})
		}
		return model.Document{"records": rows}, nil
	}
	pipeline := source.Pipeline{Store: f.roles["ingester"], ProviderFactory: func(context.Context, source.Registration) (source.Reader, error) { return reader, nil }, Normalize: normalize, Persist: func(context.Context, string, string, model.Document, model.Document) error { return nil }, ArchiveObject: func(_ context.Context, tenant, src, key string, body []byte) error {
		_ = put("tenant/"+tenant+"/source/"+src+"/"+source.BytesHash([]byte(key))+".raw", body)
		return nil
	}}
	if e = pipeline.Sync(ctx, f.tenant, "assessment-native"); e != nil {
		t.Fatal("ordinary provider-shaped billing ingestion failed", e)
	}
	readback, e := fleetassessmentworker.NewPinnedReader(readClient, bucket, "")
	if e != nil {
		t.Fatal(e)
	}
	workerConfig := fleetNativeWorkerConfig(f.tenant)
	workerConfig.ArchiveEndpoint, workerConfig.ArchiveBucket = "http://minio:9000", bucket
	worker, e := fleetassessmentworker.New(ctx, workerConfig, assessor, readback)
	if e != nil {
		t.Fatal(e)
	}
	var snapshot model.Document
	if e = assessor.Do(ctx, f.tenant, func(tx *store.Tx) error {
		var e error
		snapshot, e = tx.FleetNativeAssessmentSnapshot(ctx, model.String(request, "id"))
		return e
	}); e != nil {
		t.Fatal("private native snapshot", e)
	}
	var typed fleetbilling.GroupNativeSnapshot
	encoded, _ := json.Marshal(snapshot)
	if json.Unmarshal(encoded, &typed) != nil {
		t.Fatal("typed native snapshot decode failed")
	}
	if fleetbilling.Hash(snapshot) != fleetbilling.Hash(typed) {
		different := []string{}
		roundtrip := source.Object(typed)
		for k, v := range snapshot {
			if fleetbilling.Hash(v) != fleetbilling.Hash(roundtrip[k]) {
				different = append(different, k)
			}
		}
		sort.Strings(different)
		t.Fatal("native snapshot typed/document hash differs", different)
	}
	broker := fleetbilling.GroupNativeBroker{Repository: nativeAssessmentRepository{assessor, model.String(request, "id")}, Archive: readback}
	prices, e := broker.Capture(ctx, f.tenant, proposals[0], proposals[1])
	if e != nil || prices.Status != "OBSERVED_CONDITIONAL" {
		t.Fatal("private native broker fixture did not close", prices.ReasonCodes, e)
	}
	var nativeSelection fleetassessment.Selection
	raw, _ = json.Marshal(request["selection"])
	if json.Unmarshal(raw, &nativeSelection) != nil {
		t.Fatal("native selection shape differs")
	}
	projection, e := fleetassessment.Build(nativeSelection, prices, nil, time.Now().UTC())
	if e != nil {
		t.Fatal("native projection unavailable", e)
	}
	rollbackProbe := errors.New("valid native publication probe rolled back")
	if e := assessor.Do(ctx, f.tenant, func(tx *store.Tx) error {
		if _, _, err := tx.FleetNativeAssessmentAppend(ctx, model.String(request, "id"), fleetbilling.Hash(snapshot), source.Object(projection)); err != nil {
			return err
		}
		return rollbackProbe
	}); !errors.Is(e, rollbackProbe) {
		t.Fatal("valid native publication guard probe failed", e)
	}
	// Start from the complete, independently decoded native projection so these
	// direct assessor SQL negatives reach the intended semantic guard rather
	// than failing an unrelated missing-evidence predicate. Each transaction
	// rolls back and no substitute projection is ever published.
	negativeMutations := []func(model.Document){
		func(d model.Document) {
			n := sourceObject(d["native_rates"])
			pins := source.Rows(n["source_pins"])
			n["source_pins"] = pins[1:]
			d["native_rates"] = n
		},
		func(d model.Document) {
			n := sourceObject(d["native_rates"])
			pins := source.Rows(n["source_pins"])
			pins[0]["receipt_sha256"] = strings.Repeat("0", 64)
			n["source_pins"] = pins
			d["native_rates"] = n
		},
		func(d model.Document) {
			n := sourceObject(d["native_rates"])
			n["observed_at"] = time.Now().UTC().Add(-10 * time.Minute).Format(time.RFC3339Nano)
			d["native_rates"] = n
		},
		func(d model.Document) {
			n := sourceObject(d["native_rates"])
			n["observed_at"] = time.Now().UTC().Add(10 * time.Minute).Format(time.RFC3339Nano)
			d["native_rates"] = n
		},
		func(d model.Document) {
			n := sourceObject(d["native_rates"])
			n["valid_until"] = "9999-01-01T00:00:00Z"
			d["native_rates"] = n
		},
		func(d model.Document) {
			s := sourceObject(d["scenario"])
			s["status"] = "UNAVAILABLE"
			d["scenario"] = s
		},
	}
	for index, mutate := range negativeMutations {
		d := source.Object(projection)
		d["id"] = model.ID()
		mutate(d)
		raw, _ := json.Marshal(d)
		cause := assessor.Do(ctx, f.tenant, func(tx *store.Tx) error {
			_, err := tx.Exec(ctx, `INSERT INTO public.fleet_native_assessments(tenant_id,id,request_id,content_hash,input_snapshot_hash,document,raw_document) VALUES($1,$2,$3,$4,$5,$6,$7)`, f.tenant, d["id"], request["id"], fleetbilling.Hash(d), fleetbilling.Hash(snapshot), raw, raw)
			if err != nil {
				return err
			}
			return errors.New("invalid native projection passed SQL guard; rolled back")
		})
		var pgError *pgconn.PgError
		if !errors.As(cause, &pgError) || pgError.Code != "P0001" {
			t.Fatal("native conditional SQL negative did not reach semantic rejection", index, cause)
		}
	}
	result, e := worker.Process(ctx, model.String(request, "id"))
	if e != nil || result.Existing {
		var selected fleetassessment.Selection
		raw, _ := json.Marshal(request["selection"])
		_ = json.Unmarshal(raw, &selected)
		projection, buildError := fleetassessment.Build(selected, prices, nil, time.Now().UTC())
		if buildError != nil {
			t.Fatal("actual native worker refused; independent domain projection", buildError)
		}
		// This diagnostic uses the same derived native projection and deliberately
		// rolls back, so a private guard error remains visible without publishing
		// a replacement result after the real worker has refused.
		diagnostic := assessor.Do(ctx, f.tenant, func(tx *store.Tx) error {
			_, _, cause := tx.FleetNativeAssessmentAppend(ctx, model.String(request, "id"), fleetbilling.Hash(snapshot), source.Object(projection))
			if cause != nil {
				return cause
			}
			return errors.New("diagnostic native publication would pass; rolled back")
		})
		t.Fatal("actual native worker publication failed", e, diagnostic)
	}
	code, stored := fleetNativeHTTPGet(t, f, "fleet-native-assessments/"+model.String(request, "id"), f.token(f.tenant, "native-auditor", "AUDITOR"))
	if code != 200 {
		t.Fatal("published native API readback unavailable", code)
	}
	assessment := sourceObject(stored["assessment"])
	scenario := sourceObject(assessment["scenario"])
	rates := sourceObject(assessment["native_rates"])
	capacity := sourceObject(assessment["capacity"])
	if model.String(scenario, "status") != "OBSERVED_CONDITIONAL" {
		t.Fatalf("provider-shaped conditional rate unavailable: rates=%s reasons=%v", model.String(rates, "status"), rates["reason_codes"])
	}
	if model.String(scenario, "old_hourly_compute") != "0.4" || model.String(scenario, "candidate_hourly_compute") != "0.24" || model.String(scenario, "hourly_compute_difference") != "0.16" || model.String(scenario, "currency") != "USD" || model.Number(scenario, "member_count") != 2 {
		t.Fatal("conditional exact native comparison differs")
	}
	if model.String(capacity, "status") != "UNAVAILABLE" || len(model.Strings(capacity, "missing_instance_ids")) != 2 || scenario["estimated_saving"] != nil || scenario["contracted_avoidable_cost"] != nil || assessment["verified_saving"] != nil || model.Bool(assessment, "execution_authorized") || assessment["change_plan_id"] != nil {
		t.Fatal("native observation invented group capacity, money or execution authority")
	}
	again, e := worker.Process(ctx, model.String(request, "id"))
	if e != nil || !again.Existing || again.AssessmentID != result.AssessmentID {
		t.Fatal("immutable worker replay changed native assessment", e)
	}
	if archived < 10 {
		t.Fatal("actual raw archive population incomplete")
	}
	if os.Getenv("FLEET_NATIVE_ASSESSMENT_WRITE_RESULT") == "1" {
		proof := model.Document{"schema_version": "1", "status": "PASS", "raw_transport": "PROVIDER_SHAPED_FIXTURE", "archived_readbacks": archived, "old_hourly_compute": scenario["old_hourly_compute"], "candidate_hourly_compute": scenario["candidate_hourly_compute"], "hourly_compute_difference": scenario["hourly_compute_difference"], "currency": scenario["currency"], "member_count": scenario["member_count"], "capacity_status": capacity["status"], "immutable_replay": true, "sql_guard_negatives": len(negativeMutations), "fixture": true, "customer_execution_authorized": false, "contracted_avoidable_cost": nil, "verified_saving": nil}
		raw, err := json.Marshal(proof)
		if err != nil || len(raw) > 4096 {
			t.Fatal("bounded native proof invalid")
		}
		file, err := os.OpenFile("/results/result.json", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Fatal("bounded native proof create failed")
		}
		if _, err = file.Write(raw); err == nil {
			err = file.Sync()
		}
		closeError := file.Close()
		if err != nil || closeError != nil {
			t.Fatal("bounded native proof persistence failed")
		}
	}
	t.Logf("provider-shaped fixture: native XML and authenticated-export pipeline -> versioned raw archive -> real JWT request -> restricted reader worker -> conditional observed estimate; %d archived readbacks; capacity/execution/savings unavailable", archived)
}
