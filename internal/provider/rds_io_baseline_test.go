package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

func TestRDSDocumentedNonBurstIOBaselineAndArchivedSource(t *testing.T) {
	for _, tc := range []struct{ class, iops, throughput string }{
		{"db.r6i.8xlarge", "40000", "1250000000"},
		{"db.r6i.12xlarge", "60000", "1875000000"},
	} {
		row, err := RDSDocumentedIOBaseline(tc.class)
		if err != nil || row["class_id"] != tc.class || row["iops"] != tc.iops || row["throughput_bytes_per_second"] != tc.throughput || row["basis"] != "AWS_DOCUMENTED_NON_BURST_BASELINE_V1" || row["source_excerpt_sha256"] != rdsSHA(RDSDocumentedIOBaselineAsset()) {
			t.Fatalf("reviewed non-burst baseline changed: %v %+v", err, row)
		}
		for _, forbidden := range []string{"vcpu", "memory_bytes", "network_bytes_per_second", "price", "execution_authorized"} {
			if _, exists := row[forbidden]; exists {
				t.Fatal("documentation supplied unrelated authority")
			}
		}
		row["iops"] = "1"
		row["source_urls"].([]string)[0] = "https://foreign.invalid/"
		fresh, err := RDSDocumentedIOBaseline(tc.class)
		if err != nil || fresh["iops"] != tc.iops || strings.Contains(fresh["source_urls"].([]string)[0], "foreign") {
			t.Fatal("baseline caller can mutate the reviewed asset")
		}
	}
	for _, class := range []string{"db.r6i.large", "db.r6i.xlarge", "db.r6i.4xlarge", "db.r6g.large", "db.t3.large", "db.serverless", "db.r6i.16xlarge", "r6i.8xlarge", "db.r6i.8xlarge.tpc2.mem4x"} {
		row, err := RDSDocumentedIOBaseline(class)
		if err != nil || row != nil {
			t.Fatalf("unknown/burst class acquired baseline: %s %v", class, err)
		}
	}
	asset := RDSDocumentedIOBaselineAsset()
	asset[0] ^= 1
	if _, err := rdsDocumentedIOBaseline(asset, "db.r6i.8xlarge"); err == nil {
		t.Fatal("altered documentation accepted")
	}
	if rdsSHA(RDSDocumentedIOBaselineAsset()) != rdsDocumentedIOAssetSHA256 {
		t.Fatal("asset byte return aliases static data")
	}

	// Exercise the ordinary native orderable/Pricing reader: documentation does
	// not invent an orderable class or replace native processor/memory fields.
	a := rdsTestAWS(t, func(r *http.Request, body string) (string, int) {
		if r.Header.Get("X-Amz-Target") == "AWSPriceListService.GetProducts" {
			class, vcpu, memory, network := "db.r6i.8xlarge", "32", "256 GiB", "12.5 Gigabit"
			if strings.Contains(body, "db.r6i.12xlarge") {
				class, vcpu, memory, network = "db.r6i.12xlarge", "48", "384 GiB", "18.75 Gigabit"
			}
			p, _ := json.Marshal(model.Document{"product": model.Document{"sku": "fixture-" + class, "productFamily": "Database Instance", "attributes": map[string]string{"servicecode": "AmazonRDS", "instanceType": class, "regionCode": "eu-west-1", "vcpu": vcpu, "memory": memory, "physicalProcessor": "Intel Xeon", "processorArchitecture": "64-bit", "networkPerformance": network}}})
			response, _ := json.Marshal(model.Document{"PriceList": []string{string(p)}})
			return string(response), 200
		}
		v, _ := url.ParseQuery(body)
		if v.Get("Action") == "DescribeDBInstances" {
			return rdsTestPage("DescribeDBInstances", "DBInstances", strings.Replace(rdsTestInstance(""), "db.r6g.large", "db.r6i.12xlarge", 1), ""), 200
		}
		if v.Get("Action") == "DescribeOrderableDBInstanceOptions" {
			rows := ""
			for _, class := range []string{"db.r6i.8xlarge", "db.r6i.12xlarge"} {
				rows += "<OrderableDBInstanceOption><Engine>postgres</Engine><EngineVersion>16.4</EngineVersion><LicenseModel>postgresql-license</LicenseModel><DBInstanceClass>" + class + "</DBInstanceClass><StorageType>gp3</StorageType></OrderableDBInstanceOption>"
			}
			return rdsTestPage("DescribeOrderableDBInstanceOptions", "OrderableDBInstanceOptions", rows, ""), 200
		}
		return rdsTestDefault(t, r, body)
	})
	got, err := a.RDSCatalog(context.Background(), rdsTestScope, rdsTestARN)
	if err != nil || len(got.Capacities) != 2 {
		t.Fatalf("documented/native catalogue closure failed: %v", err)
	}
	for _, c := range got.Capacities {
		expected, err := RDSDocumentedIOBaseline(model.String(c, "class"))
		actual, _ := json.Marshal(c["ebs_baseline"])
		want, _ := json.Marshal(expected)
		if err != nil || !bytes.Equal(actual, want) || c["cpu_model"] != "Intel Xeon" {
			t.Fatal("native class and documented baseline were not bound")
		}
	}
	frames, err := RDSCaptureFrames(got.Raw)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, frame := range frames {
		if frame.Service == "aws_documentation" {
			count++
			if frame.Action != "ReviewedRDSNonBurstEBSBaselineV1" || frame.Selector != rdsDocumentedIOAssetSHA256 || frame.Region != "global" || !bytes.Equal(frame.Body, RDSDocumentedIOBaselineAsset()) {
				t.Fatal("exact documentation provenance lost")
			}
		}
	}
	if count != 1 {
		t.Fatal("documentation not archived exactly once per catalogue")
	}
}
