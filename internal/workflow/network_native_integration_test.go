package workflow

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/native"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/network"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// This uses the existing owned PostgreSQL/MinIO/ClickHouse lab and the existing
// test transport pattern. Native AWS replies are explicitly provider-shaped
// COMPONENT evidence, not live AWS acceptance or a trusted complete traffic
// census. No customer AWS endpoint may be contacted.
func TestNetworkNativeCollectorRestrictedPersistenceAndStorage(t *testing.T) {
	if os.Getenv("NETWORK_TEST_STORAGE_ENABLED") != "true" {
		t.Skip("existing owned PostgreSQL/versioned object/ClickHouse lab required")
	}
	admin, roles := schedulerTestDatabase(t)
	ctx, cancel := context.WithTimeout(context.Background(), 85*time.Second)
	defer cancel()
	tenant := "network-" + model.ID()
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
	format := []string{}
	for _, f := range r.Fields {
		format = append(format, "${"+f+"}")
	}
	var plain strings.Builder
	plain.WriteString(strings.Join(r.Fields, " ") + "\n")
	fmt.Fprintf(&plain, "7 %s %s 10.0.1.5 10.0.0.1 1234 443 6 10 100 %d %d ACCEPT OK eu-west-1 euw1-az1 %s %s 10.0.1.5 52.95.128.1 - S3 ingress - -\n", r.AccountID, natENI, start.Unix(), start.Add(time.Minute).Unix(), vpcID, subnetID)
	fmt.Fprintf(&plain, "7 %s %s 52.95.128.1 10.0.0.1 443 1234 6 5 50 %d %d ACCEPT OK eu-west-1 euw1-az1 %s %s 52.95.128.1 10.0.1.5 S3 - ingress - -\n", r.AccountID, natENI, start.Unix(), start.Add(time.Minute).Unix(), vpcID, subnetID)
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
				fmt.Fprintf(&points, "<member><Timestamp>%s</Timestamp><%s>%s</%s><SampleCount>60</SampleCount><Unit>%s</Unit></member>", at.Format(time.RFC3339), stat, value, stat, v.Get("Unit"))
			}
			raw = []byte("<GetMetricStatisticsResponse><GetMetricStatisticsResult><Datapoints>" + points.String() + "</Datapoints></GetMetricStatisticsResult></GetMetricStatisticsResponse>")
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
		return &http.Response{StatusCode: 200, Header: header, ContentLength: int64(len(raw)), Body: io.NopCloser(bytes.NewReader(raw))}, nil
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
	metrics, e := networkMetricSummary(ctx, storage, reader, discovery.Scope, nat)
	if e != nil {
		t.Fatal("native metrics/CH/archive", e)
	}
	if e = PublishNetworkDiscovery(ctx, ingester, storage, discovery, "", map[string]model.Document{natID: metrics}, model.Document{"status": "UNAVAILABLE", "dimensions": []model.Document{}}); e != nil {
		t.Fatal("native discovery publication", e)
	}
	refs := []network.ObjectRef{{Key: objectKey, VersionID: "component-v1", SHA256: network.BytesHash(payload), Size: int64(len(payload))}}
	a := &Activities{Store: ingester}
	g, e := network.IngestFlow(ctx, r, refs, reader, networkArchiveAdapter{storage}, storage, networkCheckpoint{a, r})
	if e != nil || !g.Complete || g.Rows != 2 || g.Coverage["complete_traffic_census"] != false {
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
	if e = storage.ValidateNetworkGeneration(ctx, g.Scope, g.ID, 2); e != nil {
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
