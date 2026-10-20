package provider

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/network"
)

func networkSourceRegistration() network.Registration {
	return network.Registration{ID: "source-network", TenantID: "tenant-network", Kind: network.FlowKind, AccountID: "111122223333", Region: "eu-west-1", ReadRoleBindingID: "read-network", FlowLogID: "fl-11111111", ResourceIDs: []string{"vpc-11111111"}, ReportBucket: "network-reports", ReportOwner: "111122223333", ReportRegion: "eu-west-1", Prefix: "AWSLogs/111122223333/vpcflowlogs/eu-west-1/", Fields: strings.Fields("version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status region"), TrafficType: "ALL", MaxAggregationSeconds: 60, Version: 1, Enabled: true}
}
func networkFlowPolicy(r network.Registration) model.Document {
	return model.Document{"Version": "2012-10-17", "Statement": []any{model.Document{"Effect": "Allow", "Principal": model.Document{"Service": "delivery.logs.amazonaws.com"}, "Action": "s3:PutObject", "Resource": "arn:aws:s3:::" + r.ReportBucket + "/AWSLogs/" + r.AccountID + "/*", "Condition": model.Document{"StringEquals": model.Document{"aws:SourceAccount": r.AccountID}, "ArnLike": model.Document{"aws:SourceArn": "arn:aws:logs:" + r.Region + ":" + r.AccountID + ":*"}}}}}
}
func TestNetworkFlowCommissionedBoundaryFences(t *testing.T) {
	for _, name := range []string{"valid", "wrong account", "wrong destination", "changed fields", "unversioned", "wrong region", "writer", "unsupported writer permission", "wrong scope", "non-native prefix", "parquet"} {
		t.Run(name, func(t *testing.T) {
			r := networkSourceRegistration()
			if name == "non-native prefix" {
				r.Prefix = "other/"
			}
			a := s3TestAWS(func(req *http.Request) (string, int) {
				if strings.HasPrefix(req.URL.Host, "sts.") {
					identity := rdsTestIdentity()
					if name == "wrong account" {
						identity = strings.ReplaceAll(identity, r.AccountID, "444455556666")
					}
					return identity, 200
				}
				if strings.HasPrefix(req.URL.Host, "ec2.") {
					format := []string{}
					for _, f := range r.Fields {
						format = append(format, "${"+f+"}")
					}
					dest := "arn:aws:s3:::" + r.ReportBucket
					resource := "vpc-11111111"
					if name == "wrong destination" {
						dest = "arn:aws:s3:::wrong-report"
					}
					if name == "wrong scope" {
						resource = "vpc-99999999"
					}
					if name == "changed fields" {
						format = append(format, "${az-id}")
					}
					options := ""
					if name == "parquet" {
						options = "<destinationOptions><fileFormat>parquet</fileFormat></destinationOptions>"
					}
					return ebsTestPage("DescribeFlowLogs", "flowLogSet", "<item><flowLogId>"+r.FlowLogID+"</flowLogId><resourceId>"+resource+"</resourceId><flowLogStatus>ACTIVE</flowLogStatus><deliverLogsStatus>SUCCESS</deliverLogsStatus><trafficType>ALL</trafficType><maxAggregationInterval>60</maxAggregationInterval><logDestinationType>s3</logDestinationType><logDestination>"+dest+"</logDestination><logFormat>"+strings.Join(format, " ")+"</logFormat>"+options+"</item>", ""), 200
				}
				if req.Header.Get("x-amz-expected-bucket-owner") != r.ReportOwner {
					t.Fatal("owner missing")
				}
				switch {
				case req.URL.Query().Has("versioning"):
					if name == "unversioned" {
						return "<VersioningConfiguration/>", 200
					}
					return "<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>", 200
				case req.URL.Query().Has("location"):
					if name == "wrong region" {
						return "<LocationConstraint>us-east-1</LocationConstraint>", 200
					}
					return "<LocationConstraint>eu-west-1</LocationConstraint>", 200
				case req.URL.Query().Has("policy"):
					p := networkFlowPolicy(r)
					if name == "unsupported writer permission" {
						p["Statement"].([]any)[0].(model.Document)["Action"] = []string{"s3:PutObject", "s3:DeleteObject"}
					}
					raw, _ := json.Marshal(p)
					if name == "writer" {
						raw = []byte(strings.ReplaceAll(string(raw), "delivery.logs.amazonaws.com", "ec2.amazonaws.com"))
					}
					return string(raw), 200
				}
				t.Fatal("unexpected read")
				return "", 500
			})
			out, e := a.FlowBoundary(context.Background(), r)
			if name == "valid" {
				if e != nil || len(model.String(out, "configuration_hash")) != 64 || len(model.String(out, "writer_policy_hash")) != 64 {
					t.Fatal(out, e)
				}
			} else if e == nil {
				t.Fatal("untrusted boundary accepted", out)
			}
		})
	}
}
func TestNetworkPricingDimensionsNeverSubstitutePublicPrice(t *testing.T) {
	const sku = "NATSKU"
	const rate = "NATSKU.TERM.RATE"
	for _, scenario := range []string{"valid", "wrong region", "reversed bracket", "unknown sku"} {
		t.Run(scenario, func(t *testing.T) {
			a := s3TestAWS(func(req *http.Request) (string, int) {
				if strings.HasPrefix(req.URL.Host, "sts.") {
					return rdsTestIdentity(), 200
				}
				if req.URL.Host != "api.pricing.us-east-1.amazonaws.com" || req.Header.Get("X-Amz-Target") != "AWSPriceListService.GetProducts" {
					t.Fatal("wrongpricingendpoint")
				}
				raw, _ := io.ReadAll(req.Body)
				q := model.Document{}
				_ = json.Unmarshal(raw, &q)
				products := []string{}
				if q["ServiceCode"] == "AmazonEC2" && scenario != "unknown sku" {
					region, begin := "eu-west-1", "0"
					if scenario == "wrong region" {
						region = "us-east-1"
					}
					if scenario == "reversed bracket" {
						begin = "100"
					}
					p := model.Document{"product": model.Document{"sku": sku, "attributes": model.Document{"regionCode": region, "servicecode": "AmazonEC2", "usagetype": "EU-NatGateway-Bytes", "operation": "NatGateway"}}, "publicationDate": "2026-10-01T00:00:00Z", "terms": model.Document{"OnDemand": model.Document{"term": model.Document{"effectiveDate": "2026-10-01T00:00:00Z", "priceDimensions": model.Document{rate: model.Document{"rateCode": rate, "beginRange": begin, "endRange": "10", "unit": "GB", "pricePerUnit": model.Document{"USD": "0.045"}}}}}}}
					b, _ := json.Marshal(p)
					products = append(products, string(b))
				}
				result, _ := json.Marshal(model.Document{"PriceList": products})
				return string(result), 200
			})
			out, e := a.NetworkPriceDimensions(context.Background(), networkTestScope, []string{sku})
			if scenario == "valid" {
				if e != nil {
					t.Fatal(e)
				}
				interpreted, _ := json.Marshal(out["dimensions"])
				if strings.Contains(string(interpreted), "0.045") || strings.Contains(string(interpreted), "pricePerUnit") {
					t.Fatal("publicpricesubstitution")
				}
			} else if e == nil {
				t.Fatal("invalid dimension accepted")
			}
		})
	}
}
