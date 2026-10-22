package workflow

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/auth"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/native"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/network"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/service"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// This uses the existing owned PostgreSQL/MinIO/ClickHouse lab and the existing
// test transport pattern. Native AWS replies are explicitly provider-shaped
// COMPONENT evidence, not live AWS acceptance or a trusted complete traffic
// census. No customer AWS endpoint may be contacted.
func TestNetworkNativeCollectorRestrictedPersistenceAndStorage(t *testing.T) {
	networkNativeCollectorJourney(t, false)
}

// One coherent provider-shaped population reaches native collection, trusted
// billing, the restricted evaluator and ordinary OIDC. It is deterministic
// synthetic acceptance, never customer AWS or a verified savings claim.
func TestNetworkNativeCollectorPositiveGatewayThroughActualPython(t *testing.T) {
	networkNativeCollectorJourney(t, true)
}

func networkNativeCollectorJourney(t *testing.T, positive bool) {
	t.Helper()
	if os.Getenv("NETWORK_TEST_STORAGE_ENABLED") != "true" {
		t.Skip("existing owned PostgreSQL/versioned object/ClickHouse lab required")
	}
	admin, roles := schedulerTestDatabase(t)
	ctx, cancel := context.WithTimeout(context.Background(), 85*time.Second)
	defer cancel()
	tenant := "network-" + model.ID()
	if positive && os.Getenv("FINOPS_NETWORK_BROWSER") == "true" {
		tenant = "tenant-demo"
	}
	if positive && (os.Getenv("ECONOMICS_TEST_URL") == "" || os.Getenv("ECONOMICS_TEST_TOKEN") == "") {
		t.Fatal("actual private Python required")
	}
	login := "network_ingester_" + strings.ReplaceAll(model.ID(), "-", "")
	password := model.ID() + model.ID()
	marker := "owned-network-collector:" + login
	if _, e := admin.Pool.Exec(ctx, "CREATE ROLE "+pgx.Identifier{login}.Sanitize()+" LOGIN PASSWORD '"+password+"' IN ROLE finops_ingester"); e != nil {
		t.Fatal(e)
	}
	if _, e := admin.Pool.Exec(ctx, "COMMENT ON ROLE "+pgx.Identifier{login}.Sanitize()+" IS '"+marker+"'"); e != nil {
		t.Fatal(e)
	}
	var ingester *store.Store
	t.Cleanup(func() {
		if ingester != nil {
			ingester.Pool.Close()
		}
		var actual string
		if e := admin.Pool.QueryRow(context.Background(), "SELECT coalesce(shobj_description(oid,'pg_authid'),'') FROM pg_roles WHERE rolname=$1", login).Scan(&actual); e != nil || actual != marker {
			t.Error("owned collector login marker changed")
			return
		}
		if _, e := admin.Pool.Exec(context.Background(), "DROP ROLE "+pgx.Identifier{login}.Sanitize()); e != nil {
			t.Error(e)
		}
	})
	dsn, e := url.Parse(admin.Pool.Config().ConnConfig.ConnString())
	if e != nil {
		t.Fatal(e)
	}
	dsn.User = url.UserPassword(login, password)
	ingester, e = store.OpenRuntime(ctx, dsn.String(), "ingester")
	if e != nil {
		t.Fatal(e)
	}
	var current, session string
	if e = ingester.Pool.QueryRow(ctx, "SELECT current_user,session_user").Scan(&current, &session); e != nil || current != "finops_ingester" || session != login {
		t.Fatal("collector LOGIN/group identity differs", e)
	}
	const natID = "nat-0a100000000000001"
	const sourceENI = "eni-0a100000000000001"
	const natENI = "eni-0a100000000000002"
	const vpcID = "vpc-0a100000000000001"
	const subnetID = "subnet-0a100000000000001"
	resourceID := "component-network-resource"
	workloadID := "component-network-workload"
	r := network.Registration{ID: "source-" + model.ID(), TenantID: tenant, Kind: network.FlowKind, AccountID: "111122223333", Region: "eu-west-1", ReadRoleBindingID: "component-network-reader", FlowLogID: "fl-0a100000000000001", ResourceIDs: []string{vpcID}, ReportBucket: "component-network-reports", ReportOwner: "111122223333", ReportRegion: "eu-west-1", Prefix: "AWSLogs/111122223333/vpcflowlogs/eu-west-1/", Fields: strings.Fields("version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status region az-id vpc-id subnet-id pkt-srcaddr pkt-dstaddr pkt-src-aws-service pkt-dst-aws-service flow-direction traffic-path resource-id"), TrafficType: "ALL", MaxAggregationSeconds: 60, Version: 1, Enabled: true}
	if positive {
		// Native VPC Flow Logs are best-effort. Workload attribution is derived
		// from the independently collected ENI/subnet topology, not a synthetic
		// resource-id column or an assertion that absent records mean zero.
		r.Fields = r.Fields[:len(r.Fields)-1]
	}
	if e = roles["api"].Do(ctx, tenant, func(tx *store.Tx) error {
		if e := tx.Seed(ctx, true); e != nil {
			return e
		}
		if _, e := tx.Create(ctx, "workloads", model.Document{"id": workloadID, "name": "Component network workload", "owner": "declared-owner"}); e != nil {
			return e
		}
		if _, e := tx.Create(ctx, "resources", model.Document{"id": resourceID, "provider": "AWS", "resource_type": "NAT_GATEWAY", "account_id": r.AccountID, "region": r.Region, "provider_resource_id": natID, "owner": "declared-owner", "workload_id": workloadID, "configuration_authority": "TERRAFORM", "environment": "NON_PRODUCTION"}); e != nil {
			return e
		}
		raw, _ := json.Marshal(r)
		d := model.Document{}
		_ = json.Unmarshal(raw, &d)
		_, e := tx.SourceCreate(ctx, d)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_ = req.ParseForm()
		if req.Form.Get("Action") != "AssumeRole" {
			t.Error("unexpected STS operation")
			w.WriteHeader(400)
			return
		}
		fmt.Fprintf(w, `<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleResult><Credentials><AccessKeyId>component-network-read</AccessKeyId><SecretAccessKey>component-network-secret</SecretAccessKey><SessionToken>component-network-session</SessionToken><Expiration>%s</Expiration></Credentials><AssumedRoleUser><Arn>arn:aws:sts::111122223333:assumed-role/component-network-read/session</Arn><AssumedRoleId>COMPONENT:session</AssumedRoleId></AssumedRoleUser></AssumeRoleResult></AssumeRoleResponse>`, time.Now().UTC().Add(time.Hour).Format(time.RFC3339))
	}))
	defer sts.Close()
	for k, v := range map[string]string{"AWS_ACCESS_KEY_ID": "component-source", "AWS_SECRET_ACCESS_KEY": "component-source-secret", "AWS_SESSION_TOKEN": "", "AWS_ROLE_ARN": "", "AWS_WEB_IDENTITY_TOKEN_FILE": "", "AWS_PROFILE": "", "AWS_ENDPOINT_URL_STS": sts.URL, "AWS_EC2_METADATA_DISABLED": "true"} {
		t.Setenv(k, v)
	}
	storage, e := native.StorageFromEnvironment(ctx, true)
	if e != nil {
		t.Fatal(e)
	}
	allowed := map[string]bool{}
	for _, endpoint := range []string{os.Getenv("OBJECT_ENDPOINT"), os.Getenv("CLICKHOUSE_URL"), sts.URL} {
		u, e := url.Parse(endpoint)
		if e != nil || u.Host == "" {
			t.Fatal("owned storage endpoint missing")
		}
		allowed[u.Host] = true
	}
	end := time.Now().UTC().Truncate(24 * time.Hour)
	start := end.Add(-30 * 24 * time.Hour)
	if positive {
		networkPositiveBilling(t, ctx, roles["api"], ingester, storage, tenant, natID, start, end)
		u, e := url.Parse(os.Getenv("ECONOMICS_TEST_URL"))
		if e != nil || u.Host == "" {
			t.Fatal("actual economics endpoint missing")
		}
		allowed[u.Host] = true
	}
	format := []string{}
	for _, f := range r.Fields {
		format = append(format, "${"+f+"}")
	}
	var plain strings.Builder
	plain.WriteString(strings.Join(r.Fields, " ") + "\n")
	fmt.Fprintf(&plain, "7 %s %s 10.0.1.5 10.0.0.1 1234 443 6 10 100 %d %d ACCEPT OK eu-west-1 euw1-az1 %s %s 10.0.1.5 52.95.128.1 - S3 ingress - -\n", r.AccountID, natENI, start.Unix(), start.Add(time.Minute).Unix(), vpcID, subnetID)
	fmt.Fprintf(&plain, "7 %s %s 52.95.128.1 10.0.0.1 443 1234 6 5 50 %d %d ACCEPT OK eu-west-1 euw1-az1 %s %s 52.95.128.1 10.0.1.5 S3 - ingress - -\n", r.AccountID, natENI, start.Unix(), start.Add(time.Minute).Unix(), vpcID, subnetID)
	if positive {
		plain.Reset()
		plain.WriteString(strings.Join(r.Fields, " ") + "\n")
		for hour := start; hour.Before(end); hour = hour.Add(time.Hour) {
			from := hour.Add(59 * time.Minute)
			if hour.Equal(start) {
				from = start
			}
			until := from.Add(time.Minute)
			fmt.Fprintf(&plain, "7 %s %s 10.0.1.5 10.0.0.1 1234 443 6 1048576 1073741824 %d %d ACCEPT OK eu-west-1 euw1-az1 %s %s 10.0.1.5 52.95.128.1 - S3 ingress -\n", r.AccountID, natENI, from.Unix(), until.Unix(), vpcID, subnetID)
			fmt.Fprintf(&plain, "7 %s %s 52.95.128.1 10.0.0.1 443 1234 6 1048576 1073741824 %d %d ACCEPT OK eu-west-1 euw1-az1 %s %s 52.95.128.1 10.0.1.5 S3 - ingress -\n", r.AccountID, natENI, from.Unix(), until.Unix(), vpcID, subnetID)
		}
	}
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	_, _ = gz.Write([]byte(plain.String()))
	_ = gz.Close()
	payload := compressed.Bytes()
	objectKey := r.Prefix + "component.log.gz"
	page := func(action, collection, items string) string {
		return "<" + action + "Response><requestId>component-network</requestId><" + collection + ">" + items + "</" + collection + "></" + action + "Response>"
	}
	collections := map[string]string{"DescribeVpcs": "vpcSet", "DescribeSubnets": "subnetSet", "DescribeAvailabilityZones": "availabilityZoneInfo", "DescribeRouteTables": "routeTableSet", "DescribeNatGateways": "natGatewaySet", "DescribeAddresses": "addressesSet", "DescribeInternetGateways": "internetGatewaySet", "DescribeEgressOnlyInternetGateways": "egressOnlyInternetGatewaySet", "DescribeNetworkInterfaces": "networkInterfaceSet", "DescribeSecurityGroups": "securityGroupInfo", "DescribeVpcEndpoints": "vpcEndpointSet", "DescribeVpcEndpointServices": "serviceDetailSet", "DescribeVpcPeeringConnections": "vpcPeeringConnectionSet", "DescribeTransitGatewayAttachments": "transitGatewayAttachments", "DescribeFlowLogs": "flowLogSet", "DescribePrefixLists": "prefixListSet"}
	original := http.DefaultTransport
	http.DefaultTransport = databaseFixtureTransport(func(req *http.Request) (*http.Response, error) {
		host := req.URL.Host
		var raw []byte
		header := http.Header{}
		if allowed[host] {
			return original.RoundTrip(req)
		}
		if !strings.Contains(req.Header.Get("Authorization"), "AWS4-HMAC-SHA256") {
			return nil, errors.New("component native read unsigned")
		}
		if host == "sts.eu-west-1.amazonaws.com" {
			raw = []byte(`<GetCallerIdentityResponse><GetCallerIdentityResult><Account>111122223333</Account><Arn>arn:aws:sts::111122223333:assumed-role/component-network-read/session</Arn><UserId>COMPONENT:session</UserId></GetCallerIdentityResult></GetCallerIdentityResponse>`)
		} else if host == "ec2.eu-west-1.amazonaws.com" {
			body, _ := io.ReadAll(req.Body)
			v, _ := url.ParseQuery(string(body))
			action := v.Get("Action")
			collection, ok := collections[action]
			if !ok {
				return nil, errors.New("component network refuses mutation or unknown read")
			}
			items := ""
			switch action {
			case "DescribeVpcs":
				items = "<item><vpcId>" + vpcID + "</vpcId><ownerId>" + r.AccountID + "</ownerId></item>"
			case "DescribeSubnets":
				items = "<item><subnetId>" + subnetID + "</subnetId><vpcId>" + vpcID + "</vpcId><ownerId>" + r.AccountID + "</ownerId><availabilityZone>eu-west-1a</availabilityZone><availabilityZoneId>euw1-az1</availabilityZoneId></item>"
			case "DescribeNatGateways":
				items = "<item><natGatewayId>" + natID + "</natGatewayId><vpcId>" + vpcID + "</vpcId><subnetId>" + subnetID + "</subnetId><availabilityMode>zonal</availabilityMode><connectivityType>public</connectivityType><state>available</state><natGatewayAddressSet><item><networkInterfaceId>" + natENI + "</networkInterfaceId><publicIp>203.0.113.1</publicIp></item></natGatewayAddressSet></item>"
			case "DescribeNetworkInterfaces":
				items = "<item><networkInterfaceId>" + sourceENI + "</networkInterfaceId><subnetId>" + subnetID + "</subnetId><vpcId>" + vpcID + "</vpcId><ownerId>" + r.AccountID + "</ownerId><privateIpAddress>10.0.1.5</privateIpAddress><availabilityZone>eu-west-1a</availabilityZone></item><item><networkInterfaceId>" + natENI + "</networkInterfaceId><subnetId>" + subnetID + "</subnetId><vpcId>" + vpcID + "</vpcId><ownerId>" + r.AccountID + "</ownerId><privateIpAddress>10.0.0.1</privateIpAddress><availabilityZone>eu-west-1a</availabilityZone></item>"
			case "DescribeRouteTables":
				items = "<item><routeTableId>rtb-0a100000000000001</routeTableId><vpcId>" + vpcID + "</vpcId><routeSet><item><destinationCidrBlock>0.0.0.0/0</destinationCidrBlock><natGatewayId>" + natID + "</natGatewayId><state>active</state></item></routeSet><associationSet><item><subnetId>" + subnetID + "</subnetId><main>false</main></item></associationSet></item>"
			case "DescribeVpcEndpointServices":
				items = "<item><serviceName>com.amazonaws.eu-west-1.s3</serviceName><owner>amazon</owner><serviceType><item><serviceType>Gateway</serviceType></item></serviceType><availabilityZoneSet><item>eu-west-1a</item></availabilityZoneSet></item>"
			case "DescribePrefixLists":
				items = "<item><prefixListId>pl-0a100000000000001</prefixListId><prefixListName>com.amazonaws.eu-west-1.s3</prefixListName><cidrSet><item>52.95.128.0/24</item></cidrSet></item>"
			case "DescribeFlowLogs":
				items = "<item><flowLogId>" + r.FlowLogID + "</flowLogId><resourceId>" + vpcID + "</resourceId><flowLogStatus>ACTIVE</flowLogStatus><deliverLogsStatus>SUCCESS</deliverLogsStatus><trafficType>ALL</trafficType><maxAggregationInterval>60</maxAggregationInterval><logDestinationType>s3</logDestinationType><logDestination>arn:aws:s3:::" + r.ReportBucket + "</logDestination><logFormat>" + strings.Join(format, " ") + "</logFormat></item>"
			}
			raw = []byte(page(action, collection, items))
		} else if host == "elasticloadbalancing.eu-west-1.amazonaws.com" {
			raw = []byte("<DescribeLoadBalancersResponse><DescribeLoadBalancersResult><LoadBalancers/></DescribeLoadBalancersResult></DescribeLoadBalancersResponse>")
		} else if host == "monitoring.eu-west-1.amazonaws.com" {
			body, _ := io.ReadAll(req.Body)
			v, _ := url.ParseQuery(string(body))
			if v.Get("Action") != "GetMetricStatistics" {
				return nil, errors.New("component unexpected telemetry read")
			}
			from, _ := time.Parse(time.RFC3339, v.Get("StartTime"))
			to, _ := time.Parse(time.RFC3339, v.Get("EndTime"))
			stat := v.Get("Statistics.member.1")
			var points strings.Builder
			for at := from; at.Before(to); at = at.Add(time.Hour) {
				value := "0"
				if at.Equal(start) && v.Get("MetricName") == "BytesInFromSource" {
					value = "100"
				}
				if at.Equal(start) && v.Get("MetricName") == "BytesInFromDestination" {
					value = "50"
				}
				if positive {
					switch v.Get("MetricName") {
					case "BytesInFromSource", "BytesInFromDestination", "BytesOutToSource", "BytesOutToDestination":
						value = "1073741824"
					case "ActiveConnectionCount":
						value = "1"
					}
				}
				fmt.Fprintf(&points, "<member><Timestamp>%s</Timestamp><%s>%s</%s><SampleCount>60</SampleCount><Unit>%s</Unit></member>", at.Format(time.RFC3339), stat, value, stat, v.Get("Unit"))
			}
			raw = []byte("<GetMetricStatisticsResponse><GetMetricStatisticsResult><Datapoints>" + points.String() + "</Datapoints></GetMetricStatisticsResult></GetMetricStatisticsResponse>")
		} else if host == "api.pricing.us-east-1.amazonaws.com" && positive {
			body, e := io.ReadAll(req.Body)
			if e != nil {
				return nil, e
			}
			reply, e := networkPositivePriceReply(body, start)
			if e != nil {
				return nil, e
			}
			raw, e = json.Marshal(reply)
			if e != nil {
				return nil, e
			}
		} else if host == r.ReportBucket+".s3.eu-west-1.amazonaws.com" {
			if req.Header.Get("x-amz-expected-bucket-owner") != r.ReportOwner {
				return nil, errors.New("component destination owner omitted")
			}
			q := req.URL.Query()
			switch {
			case q.Has("versioning"):
				raw = []byte("<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>")
			case q.Has("location"):
				raw = []byte("<LocationConstraint>eu-west-1</LocationConstraint>")
			case q.Has("policy"):
				p := model.Document{"Version": "2012-10-17", "Statement": []model.Document{{"Effect": "Allow", "Principal": model.Document{"Service": "delivery.logs.amazonaws.com"}, "Action": "s3:PutObject", "Resource": "arn:aws:s3:::" + r.ReportBucket + "/AWSLogs/" + r.AccountID + "/*", "Condition": model.Document{"StringEquals": model.Document{"aws:SourceAccount": r.AccountID}, "ArnLike": model.Document{"aws:SourceArn": "arn:aws:logs:" + r.Region + ":" + r.AccountID + ":*"}}}}}
				raw, _ = json.Marshal(p)
			case positive && q.Get("list-type") == "2":
				raw = []byte("<ListBucketResult><Name>" + r.ReportBucket + "</Name><Prefix>" + r.Prefix + "</Prefix><IsTruncated>false</IsTruncated><Contents><Key>" + objectKey + "</Key><Size>" + strconv.Itoa(len(payload)) + "</Size></Contents></ListBucketResult>")
			case positive && req.Method == http.MethodHead:
				if strings.TrimPrefix(req.URL.Path, "/") != objectKey {
					return nil, errors.New("unregistered flow metadata")
				}
				header.Set("x-amz-version-id", "component-v1")
				header.Set("Content-Length", strconv.Itoa(len(payload)))
				raw = []byte{}
			default:
				if strings.TrimPrefix(req.URL.Path, "/") != objectKey || q.Get("versionId") != "component-v1" {
					return nil, errors.New("component unregistered flow payload request")
				}
				header.Set("x-amz-version-id", "component-v1")
				raw = payload
			}
		}
		if raw == nil {
			return nil, errors.New("component collector refused unregistered network endpoint")
		}
		length := int64(len(raw))
		if positive && req.Method == http.MethodHead {
			length = int64(len(payload))
		}
		return &http.Response{StatusCode: 200, Header: header, ContentLength: length, Body: io.NopCloser(bytes.NewReader(raw))}, nil
	})
	defer func() { http.DefaultTransport = original }()
	reader, e := provider.NewAWS(ctx, r.Region, "arn:aws:iam::111122223333:role/component-network-read", "component-network-external-id")
	if e != nil {
		t.Fatal(e)
	}
	discovery, e := reader.NetworkDiscover(ctx, network.Scope{TenantID: tenant, AccountID: r.AccountID, Region: r.Region})
	if e != nil || !discovery.Complete {
		t.Fatal("native topology collection", e)
	}
	var nat model.Document
	for _, d := range discovery.Resources {
		if d["provider_resource_id"] == natID {
			nat = d
		}
	}
	refs := []network.ObjectRef{{Key: objectKey, VersionID: "component-v1", SHA256: network.BytesHash(payload), Size: int64(len(payload))}}
	a := &Activities{Store: ingester}
	expectedRows := int64(2)
	if positive {
		expectedRows = int64(end.Sub(start)/time.Hour) * 2
		if e = SyncNetworkSource(ctx, a, r, func(context.Context, network.Registration) (*provider.AWS, error) { return reader, nil }, storage); e != nil {
			t.Fatal("registered native network sync", e)
		}
		refs, e = reader.FlowObjects(ctx, r)
		if e != nil || len(refs) != 1 {
			t.Fatal("native version-pinned flow selection", e)
		}
	} else {
		metrics, err := networkMetricSummary(ctx, storage, reader, discovery.Scope, nat)
		if err != nil {
			t.Fatal("native metrics/CH/archive", err)
		}
		if e = PublishNetworkDiscovery(ctx, ingester, storage, discovery, "", map[string]model.Document{natID: metrics}, model.Document{"status": "UNAVAILABLE", "dimensions": []model.Document{}}); e != nil {
			t.Fatal("native discovery publication", e)
		}
	}
	g, e := network.IngestFlow(ctx, r, refs, reader, networkArchiveAdapter{storage}, storage, networkCheckpoint{a, r})
	if e != nil || !g.Complete || g.Rows != expectedRows || g.Coverage["complete_traffic_census"] != false {
		t.Fatal("native flow storage", g, e)
	}
	if e = PublishNetworkGeneration(ctx, a, r, g, storage); e != nil {
		t.Fatal("native receipt/snapshot publication", e)
	}
	var snapshot, resource model.Document
	if e = roles["api"].Do(ctx, tenant, func(tx *store.Tx) error {
		var e error
		resource, e = tx.Get(ctx, "resources", resourceID)
		if e != nil {
			return e
		}
		snapshot, e = tx.NetworkEvidenceLatest(ctx, resourceID)
		if e != nil {
			return e
		}
		receipt, e := tx.SourceReceiptGet(ctx, "network-receipt-"+g.ID)
		if e != nil || receipt["complete_traffic_census"] != false {
			return errors.New("trusted delivery receipt overstated completeness")
		}
		if positive {
			source, e := tx.SourceGet(ctx, r.ID)
			if e != nil || source["status"] != "HEALTHY" || source["latest_receipt_id"] != receipt["id"] {
				return errors.New("registered native sync did not publish current authority")
			}
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	if resource["owner"] != "declared-owner" || resource["workload_id"] != workloadID || resource["configuration_authority"] != "TERRAFORM" {
		t.Fatal("native collection replaced declared authority/ownership")
	}
	raw, e := storage.Read(ctx, tenant, networkDoc(snapshot["archive"]))
	if e != nil || network.BytesHash(raw) != snapshot["content_hash"] {
		t.Fatal("stored snapshot readback", e)
	}
	var canonical model.Document
	if json.Unmarshal(raw, &canonical) != nil || networkDoc(canonical["flows"])["generation_id"] != g.ID || len(networkRows(networkDoc(canonical["flows"])["cohorts"])) != 2 {
		t.Fatal("stored flow cohort identity differs")
	}
	replay, e := network.IngestFlow(ctx, r, refs, reader, networkArchiveAdapter{storage}, storage, networkCheckpoint{a, r})
	if e != nil || replay.ID != g.ID || replay.PopulationHash != g.PopulationHash {
		t.Fatal("replay differs", e)
	}
	if e = PublishNetworkGeneration(ctx, a, r, replay, storage); e != nil {
		t.Fatal(e)
	}
	if e = storage.ValidateNetworkGeneration(ctx, g.Scope, g.ID, expectedRows); e != nil {
		t.Fatal("replay inflated analytics", e)
	}
	if e = roles["api"].Do(ctx, "other-"+model.ID(), func(tx *store.Tx) error {
		if _, e := tx.SourceReceiptGet(ctx, "network-receipt-"+g.ID); !errors.Is(e, pgx.ErrNoRows) {
			return errors.New("cross-tenant receipt readable")
		}
		if _, e := tx.NetworkEvidenceGet(ctx, model.String(snapshot, "id")); !errors.Is(e, pgx.ErrNoRows) {
			return errors.New("cross-tenant snapshot readable")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	if e = roles["api"].Do(ctx, tenant, func(tx *store.Tx) error {
		_, e := tx.NetworkEvidenceCreate(ctx, resourceID, "", canonical, networkDoc(snapshot["archive"]))
		return e
	}); e == nil {
		t.Fatal("console identity could manufacture native evidence")
	} else {
		var p *pgconn.PgError
		if !errors.As(e, &p) || p.Code != "42501" {
			t.Fatal("wrong evidence write rejection", e)
		}
	}
	if positive {
		networkPositiveAPI(t, ctx, admin, roles["api"], tenant, resource, snapshot, g, func(endpoint string) {
			u, e := url.Parse(endpoint)
			if e != nil || u.Host == "" {
				t.Fatal("owned API endpoint missing")
			}
			allowed[u.Host] = true
		})
	}
	if e = roles["api"].Do(ctx, tenant, func(tx *store.Tx) error {
		d, e := tx.SourceGet(ctx, r.ID)
		if e != nil {
			return e
		}
		d["enabled"], d["revoked"] = false, true
		_, e = tx.SourceUpdate(ctx, r.ID, 1, d)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if e = PublishNetworkGeneration(ctx, a, r, g, storage); e == nil {
		t.Fatal("revoked source could publish")
	}
}

// This handoff consumes only the native generation selected above. Neither the
// API nor the assessor receives caller-authored topology, traffic or prices.
func networkPositiveAPI(t *testing.T, ctx context.Context, admin, apiDB *store.Store, tenant string, resource, snapshot model.Document, generation network.Generation, allow func(string)) {
	t.Helper()
	analyst := lambdaComponentRuntime(t, ctx, admin, "network-assessor", "finops_network_analyst")
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	signer, e := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "network-native-component"))
	if e != nil {
		t.Fatal(e)
	}
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "network-native-component", Algorithm: "RS256", Use: "sig"}}})
	}))
	defer jwks.Close()
	allow(jwks.URL)
	const issuer = "https://component-network.invalid/realms/finops"
	validator, e := auth.New(ctx, issuer, "finops", jwks.URL)
	if e != nil {
		t.Fatal(e)
	}
	token := func(scope string) string {
		s, e := jwt.Signed(signer).Claims(map[string]any{"iss": issuer, "aud": "finops", "sub": "network-native-component-verifier", "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Add(-time.Minute).Unix(), "tenant_id": scope, "realm_access": model.Document{"roles": []string{"FINOPS_ADMIN"}}}).Serialize()
		if e != nil {
			t.Fatal(e)
		}
		return s
	}
	server := httptest.NewServer((&service.API{Store: apiDB, Auth: validator, Config: service.Config{Fixture: true}}).Handler())
	defer server.Close()
	allow(server.URL)
	request := func(method, path, access, key string, body model.Document) (int, model.Document) {
		var raw []byte
		if body != nil {
			raw, _ = json.Marshal(body)
		}
		r, e := http.NewRequestWithContext(ctx, method, server.URL+"/v1/"+path, bytes.NewReader(raw))
		if e != nil {
			t.Fatal(e)
		}
		if access != "" {
			r.Header.Set("Authorization", "Bearer "+access)
		}
		if method == http.MethodPost {
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("If-Match", `"0"`)
			r.Header.Set("Idempotency-Key", key)
		}
		response, e := server.Client().Do(r)
		if e != nil {
			t.Fatal(e)
		}
		defer response.Body.Close()
		out := model.Document{}
		if json.NewDecoder(io.LimitReader(response.Body, 8<<20)).Decode(&out) != nil {
			t.Fatal("bounded network API response invalid")
		}
		return response.StatusCode, out
	}
	access := token(tenant)
	if code, _ := request(http.MethodGet, "network-assessments", "", "", nil); code != 401 {
		t.Fatal("network unauthenticated API admitted", code)
	}
	if code, _ := request(http.MethodPost, "network-assessments", token("foreign-"+tenant), "network-native-foreign", model.Document{"resource_id": resource["id"]}); code != 404 {
		t.Fatal("network cross-tenant request admitted", code)
	}
	declared := model.Document{"owner": "declared-owner", "configuration_authority": "TERRAFORM", "criticality": "NON_PRODUCTION", "seasonal": false, "security_reviewed": true, "endpoint_policy_reviewed": true, "network_policy_known": true, "dependencies_known": true, "recovery_known": true, "resilience_known": true, "allow_topology_change": true, "required_azs": 1, "ha_required": true, "on_premises_required": false, "cross_vpc_required": false, "dns_change_approved": true, "traffic_purpose": "ACTIVE"}
	code, policy := request(http.MethodPost, "network-policies", access, "network-native-policy", model.Document{"resource_id": resource["id"], "name": "Synthetic native gateway requirements", "policy": declared})
	if code != 201 {
		t.Fatal("normal network policy API", code, policy)
	}
	body := model.Document{"resource_id": resource["id"], "policy_id": policy["id"]}
	code, queued := request(http.MethodPost, "network-assessments", access, "network-native-assessment", body)
	if code != 202 {
		t.Fatal("IDs-only network queue", code, queued)
	}
	if code, replay := request(http.MethodPost, "network-assessments", access, "network-native-assessment", body); code != 202 || replay["id"] != queued["id"] {
		t.Fatal("network queue replay changed")
	}
	if e = apiDB.Do(ctx, tenant, func(tx *store.Tx) error {
		var selected string
		if e := tx.QueryRow(ctx, "SELECT snapshot_id FROM network_assessments WHERE tenant_id=$1 AND id=$2", tenant, queued["id"]).Scan(&selected); e != nil {
			return e
		}
		if selected != snapshot["id"] {
			return errors.New("network API selected a replacement population")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	workerCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() {
		done <- service.RunNetworkAssessor(workerCtx, service.Config{Fixture: true, EconomicsURL: os.Getenv("ECONOMICS_TEST_URL"), EconomicsToken: os.Getenv("ECONOMICS_TEST_TOKEN")}, analyst)
	}()
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		cancel()
		select {
		case e := <-done:
			if e != nil {
				t.Error(e)
			}
		case <-time.After(5 * time.Second):
			t.Error("network analyst shutdown deadline")
		}
	}
	defer stop()
	var record model.Document
	for {
		code, record = request(http.MethodGet, "network-assessments/"+model.String(queued, "id"), access, "", nil)
		if code != 200 {
			t.Fatal("native network persisted read", code)
		}
		if record["status"] == "ASSESSED" || record["status"] == "BLOCKED" || record["status"] == "FAILED" {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("network native actual-Python original deadline")
		case <-time.After(100 * time.Millisecond):
		}
	}
	if record["status"] != "ASSESSED" || record["current"] != true {
		t.Fatal("native network assessment not current", record["status"], record["currentness_blockers"])
	}
	result := networkDoc(record["assessment"])
	networkPositiveGatewayResult(t, result)
	bound := false
	for _, b := range networkRows(result["source_bindings"]) {
		if b["receipt_id"] == "network-receipt-"+generation.ID {
			bound = true
		}
	}
	if !bound {
		t.Fatal("positive assessment detached from collected generation")
	}
	if e = apiDB.Do(ctx, tenant, func(tx *store.Tx) error {
		stored, e := tx.NetworkAssessmentGet(ctx, model.String(queued, "id"))
		if e != nil {
			return e
		}
		if network.Hash(stored["assessment"]) != network.Hash(result) {
			return errors.New("independent persisted network readback differs")
		}
		var count int
		if e := tx.QueryRow(ctx, "SELECT count(*) FROM network_recommendation_publications WHERE tenant_id=$1 AND assessment_id=$2", tenant, queued["id"]).Scan(&count); e != nil {
			return e
		}
		if count != 1 {
			return errors.New("network replay duplicated publication")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	if code, _ := request(http.MethodPost, "network-assessments", access, "network-native-price-injection", model.Document{"resource_id": resource["id"], "current_pricing": model.Document{"rate": "0"}}); code != 422 {
		t.Fatal("console price injection accepted")
	}
	stop()
	if os.Getenv("FINOPS_NETWORK_BROWSER") == "true" {
		networkPositiveBrowser(t, ctx, apiDB, analyst, tenant, resource, policy, model.String(queued, "id"), allow)
	}
}

func networkPositiveGatewayResult(t *testing.T, result model.Document) {
	t.Helper()
	if result["status"] != "RECOMMENDED" || result["read_only"] != true || result["execution_authorized"] != false || result["pre_execution_ready"] != false || result["verified_saving"] != nil || model.String(result, "model_assessment_hash") == "" || len(networkRows(result["source_refs"])) == 0 || len(networkRows(result["financial_references"])) == 0 {
		t.Fatal("native gateway result lost provenance or gained authority", result["status"], result["blockers"])
	}
	econ := networkDoc(result["economics"])
	if econ["currency"] != "GBP" || econ["detected_native_cost"] != "97.200000000000" || econ["estimated_monthly_saving"] != nil || econ["estimated_annual_saving"] != nil || econ["status"] != "INDEPENDENT_CANDIDATES_NEVER_SUMMED" {
		t.Fatal("network population economics differs or alternatives were summed", econ)
	}
	denominator := networkDoc(result["denominators"])
	if denominator["unattributed_bytes"] != "0.000000000000" || denominator["flow_complete"] != true || denominator["observation_complete"] != true || denominator["billing_complete"] != true || denominator["billing_scope_complete"] != true {
		t.Fatal("network byte/billing reconciliation is incomplete", denominator)
	}
	candidates := networkRows(result["candidates"])
	if len(candidates) != 2 {
		t.Fatal("native exclusive forward/reply cohorts changed", len(candidates))
	}
	for _, candidate := range candidates {
		if candidate["family"] != "A" || candidate["kind"] != "GATEWAY_ENDPOINT_REVIEW" || candidate["status"] != "RECOMMENDED" || len(model.Strings(candidate, "blockers")) != 0 {
			t.Fatal("same-region native gateway path not justified", candidate["blockers"])
		}
		c := networkDoc(candidate["economics"])
		if c["current_window_cost"] != "48.600000000000" || c["candidate_window_cost"] != "16.200000000000" || c["estimated_window_saving"] != "32.400000000000" || c["estimated_monthly_saving"] != "32.850000000000" || c["estimated_annual_saving"] != nil || c["nat_hourly_retained"] != true {
			t.Fatal("native gateway net economics differ", c)
		}
		retained := false
		for _, part := range networkRows(c["component_costs"]) {
			if part["component"] == "NAT_HOURLY" && part["current_window_cost"] == "16.200000000000" && part["candidate_window_cost"] == "16.200000000000" && part["avoided_window_cost"] == "0.000000000000" {
				retained = true
			}
		}
		if !retained {
			t.Fatal("continuing NAT hourly obligation lost")
		}
	}
}

// Existing normal-console handoff, now reading back the same native population.
func networkPositiveBrowser(t *testing.T, ctx context.Context, apiDB, analyst *store.Store, tenant string, resource, policy model.Document, componentID string, allow func(string)) {
	t.Helper()
	const binary = "/tmp/network-finops"
	info, e := os.Lstat(binary)
	if os.Getenv("FINOPS_NETWORK_ASSESSOR_BINARY") != binary || e != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode()&0111 == 0 {
		t.Fatal("actual compiled network analyst required")
	}
	log, e := os.OpenFile("/results/network-analyst.log", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		t.Fatal(e)
	}
	defer log.Close()
	cmd := exec.CommandContext(ctx, binary, "--mode", "network-assessor")
	cmd.Env = []string{"FIXTURE_MODE=true", "PORT=8098", "DATABASE_URL=" + analyst.Pool.Config().ConnConfig.ConnString(), "ECONOMICS_URL=" + os.Getenv("ECONOMICS_TEST_URL"), "ECONOMICS_TOKEN=" + os.Getenv("ECONOMICS_TEST_TOKEN")}
	for _, name := range []string{"OBJECT_REGION", "OBJECT_ENDPOINT", "OBJECT_BUCKET_RAW"} {
		if os.Getenv(name) == "" {
			t.Fatal("network archive binding incomplete")
		}
		cmd.Env = append(cmd.Env, name+"="+os.Getenv(name))
	}
	for _, pair := range [][2]string{{"OBJECT_ACCESS_KEY", "FINOPS_NETWORK_READER_ACCESS_KEY"}, {"OBJECT_SECRET_KEY", "FINOPS_NETWORK_READER_SECRET_KEY"}} {
		if os.Getenv(pair[1]) == "" {
			t.Fatal("version-only network evidence reader required")
		}
		cmd.Env = append(cmd.Env, pair[0]+"="+os.Getenv(pair[1]))
	}
	cmd.Stdout, cmd.Stderr = log, log
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	defer func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case e := <-done:
			if e != nil {
				t.Error("separate network analyst failed", e)
			}
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-done
			t.Error("network analyst shutdown deadline")
		}
	}()
	const jwks = "http://keycloak:8080/realms/finops/protocol/openid-connect/certs"
	allow(jwks)
	validator, e := auth.New(ctx, "http://localhost:8081/realms/finops", "finops", jwks)
	if e != nil {
		t.Fatal(e)
	}
	listener, e := net.Listen("tcp", ":8097")
	if e != nil {
		t.Fatal(e)
	}
	server := &http.Server{Handler: (&service.API{Store: apiDB, Auth: validator, Config: service.Config{Fixture: true}}).Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 40 * time.Second, WriteTimeout: 40 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	apiDone := make(chan error, 1)
	go func() { apiDone <- server.Serve(listener) }()
	defer func() {
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
		if e := <-apiDone; e != nil && !errors.Is(e, http.ErrServerClosed) {
			t.Error(e)
		}
	}()
	raw, _ := json.Marshal(model.Document{"schema_version": "1", "tenant_id": tenant, "resource_ids": []string{model.String(resource, "id")}, "policy_ids": []string{model.String(policy, "id")}})
	file, e := os.OpenFile("/results/network-native-ready.json", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = file.Write(raw); e != nil {
		t.Fatal(e)
	}
	_ = file.Close()
	for {
		body, e := os.ReadFile("/results/network-native-browser-done.json")
		if e == nil {
			proof := model.Document{}
			if json.Unmarshal(body, &proof) != nil {
				t.Fatal("network browser proof invalid")
			}
			ids := model.Strings(proof, "assessment_ids")
			if proof["schema_version"] != "1" || proof["tenant_id"] != tenant || proof["ready_sha256"] != network.BytesHash(raw) || len(ids) != 1 || ids[0] == componentID {
				t.Fatal("network browser proof target or issued ID differs")
			}
			if e = apiDB.Do(ctx, tenant, func(tx *store.Tx) error {
				record, e := tx.NetworkAssessmentGet(ctx, ids[0])
				if e != nil {
					return e
				}
				if record["resource_id"] != resource["id"] {
					return errors.New("browser selected another network resource")
				}
				networkPositiveGatewayResult(t, networkDoc(record["assessment"]))
				var actor string
				if e := tx.QueryRow(ctx, "SELECT created_by FROM network_assessments WHERE tenant_id=$1 AND id=$2", tenant, ids[0]).Scan(&actor); e != nil {
					return e
				}
				if actor == "" || actor == "network-native-component-verifier" {
					return errors.New("independent normal OIDC actor missing")
				}
				return nil
			}); e != nil {
				t.Fatal(e)
			}
			break
		}
		if !errors.Is(e, os.ErrNotExist) {
			t.Fatal(e)
		}
		select {
		case <-ctx.Done():
			t.Fatal("normal network browser original deadline")
		case <-time.After(100 * time.Millisecond):
		}
	}
}
