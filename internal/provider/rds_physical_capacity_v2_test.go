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

func rdsV2Classes() []string {
	return []string{
		"db.m8g.8xlarge", "db.m8g.12xlarge", "db.m8g.16xlarge",
		"db.r8g.8xlarge", "db.r8g.12xlarge", "db.r8g.16xlarge",
		"db.m8i.8xlarge", "db.m8i.12xlarge", "db.m8i.16xlarge",
		"db.r8i.8xlarge", "db.r8i.12xlarge", "db.r8i.16xlarge",
		"db.m7i.8xlarge", "db.m7i.12xlarge", "db.m7i.16xlarge",
		"db.r7i.8xlarge", "db.r7i.12xlarge", "db.r7i.16xlarge",
	}
}

func TestRDSPhysicalV2LiteralRowsAndImmutableVersionSelection(t *testing.T) {
	for _, class := range rdsV2Classes() {
		row, err := RDSDocumentedCapacity(class, rdsDocumentedPhysicalAssetSHA256)
		if err != nil || row == nil || row["class_id"] != class || row["basis"] != "AWS_DOCUMENTED_PHYSICAL_CAPACITY_V2" || row["source_excerpt_sha256"] != rdsSHA(RDSDocumentedPhysicalCapacityAssetV2()) {
			t.Fatal("reviewed class unavailable", class, row, err)
		}
		for _, field := range []string{"vcpu", "memory_bytes", "network_bytes_per_second", "iops", "throughput_bytes_per_second"} {
			if _, ok := rdsScaled(model.String(row, field), 1); !ok {
				t.Fatal("non-positive physical value", field)
			}
		}
		if _, ok := row["price"]; ok {
			t.Fatal("physical metadata acquired economic authority")
		}
		row["memory_bytes"] = "1"
		fresh, _ := RDSDocumentedCapacity(class, rdsDocumentedPhysicalAssetSHA256)
		if fresh["memory_bytes"] == "1" {
			t.Fatal("caller mutated immutable row")
		}
	}
	for _, class := range []string{"db.m8g.4xlarge", "db.r8i.24xlarge", "db.r7i.8xlarge.tpc2.mem3x", "db.m9g.8xlarge", "db.serverless", "db.r6i.8xlarge"} {
		row, err := RDSDocumentedCapacity(class, rdsDocumentedPhysicalAssetSHA256)
		if err != nil || row != nil {
			t.Fatal("unreviewed class inferred", class)
		}
	}
	v1, err := RDSDocumentedCapacity("db.r6i.8xlarge", rdsDocumentedIOAssetSHA256)
	if err != nil || v1["basis"] != "AWS_DOCUMENTED_NON_BURST_BASELINE_V1" {
		t.Fatal("historical revision changed")
	}
	for _, sha := range []string{rdsDocumentedIOAssetSHA256, rdsDocumentedPhysicalAssetSHA256} {
		raw, err := RDSDocumentedCapacityAsset(sha)
		if err != nil || rdsSHA(raw) != sha {
			t.Fatal("version/hash binding lost")
		}
		raw[0] ^= 1
		if _, err = rdsDocumentedPhysicalCapacity(raw, "db.m8g.8xlarge"); err == nil {
			t.Fatal("altered asset accepted")
		}
	}
	if _, err = RDSDocumentedCapacityAsset(strings.Repeat("a", 64)); err == nil {
		t.Fatal("unknown asset accepted")
	}
}

func TestRDSPhysicalV2NativeOrderabilityAndCapacityConflict(t *testing.T) {
	classes := rdsV2Classes()
	mode := "absent"
	reads := 0
	a := rdsTestAWS(t, func(r *http.Request, body string) (string, int) {
		if r.Header.Get("X-Amz-Target") == "AWSPriceListService.GetProducts" {
			reads++
			var request struct {
				Filters []struct{ Field, Value string }
			}
			if json.Unmarshal([]byte(body), &request) != nil {
				t.Fatal("invalid native selector")
			}
			class := ""
			for _, f := range request.Filters {
				if f.Field == "instanceType" {
					class = f.Value
				}
			}
			if mode == "absent" {
				return `{"PriceList":[]}`, 200
			}
			attrs := map[string]string{"servicecode": "AmazonRDS", "instanceType": class, "regionCode": "eu-west-1", "vcpu": "32", "memory": "128 GiB", "physicalProcessor": "AWS Graviton4", "processorArchitecture": "arm64", "networkPerformance": "15 Gigabit"}
			switch mode {
			case "cpu":
				attrs["vcpu"] = "64"
			case "memory":
				attrs["memory"] = "256 GiB"
			case "network":
				attrs["networkPerformance"] = "30 Gigabit"
			case "burst":
				attrs["networkPerformance"] = "Up to 15 Gigabit"
			case "architecture":
				attrs["processorArchitecture"] = "x86_64"
			}
			p, _ := json.Marshal(model.Document{"product": model.Document{"sku": "reviewed-" + class, "productFamily": "Database Instance", "attributes": attrs}})
			response, _ := json.Marshal(model.Document{"PriceList": []string{string(p)}})
			return string(response), 200
		}
		v, _ := url.ParseQuery(body)
		if v.Get("Action") == "DescribeOrderableDBInstanceOptions" {
			if v.Get("Engine") != "postgres" || v.Get("EngineVersion") != "16.4" || v.Get("LicenseModel") != "postgresql-license" {
				t.Fatal("exact engine/version/license selector lost")
			}
			rows := ""
			for _, class := range classes {
				rows += "<OrderableDBInstanceOption><Engine>postgres</Engine><EngineVersion>16.4</EngineVersion><LicenseModel>postgresql-license</LicenseModel><DBInstanceClass>" + class + "</DBInstanceClass><StorageType>gp3</StorageType></OrderableDBInstanceOption>"
			}
			return rdsTestPage("DescribeOrderableDBInstanceOptions", "OrderableDBInstanceOptions", rows, ""), 200
		}
		return rdsTestDefault(t, r, body)
	})
	out, err := a.RDSCatalog(context.Background(), rdsTestScope, rdsTestARN)
	if err != nil || len(out.Capacities) != 18 || reads != 18 {
		t.Fatal("native scoped literal coverage incomplete", err)
	}
	for _, c := range out.Capacities {
		if c["status"] != "OBSERVED_CATALOG_CAPACITY" || c["physical_capacity_asset_sha256"] != rdsDocumentedPhysicalAssetSHA256 || len(c["pricing_skus"].([]string)) != 0 {
			t.Fatal("documented hardware or missing native pricing misrepresented", c)
		}
	}
	frames, err := RDSCaptureFrames(out.Raw)
	if err != nil {
		t.Fatal(err)
	}
	v2count := 0
	for _, frame := range frames {
		if frame.Action == "ReviewedRDSPhysicalCapacityV2" {
			v2count++
			if frame.Selector != rdsDocumentedPhysicalAssetSHA256 || !bytes.Equal(frame.Body, RDSDocumentedPhysicalCapacityAssetV2()) {
				t.Fatal("exact V2 archive missing")
			}
		}
	}
	if v2count != 1 {
		t.Fatal("V2 asset not captured exactly once")
	}
	classes = []string{"db.m8g.8xlarge"}
	for _, value := range []string{"match", "cpu", "memory", "network", "burst", "architecture"} {
		mode = value
		out, err = a.RDSCatalog(context.Background(), rdsTestScope, rdsTestARN)
		if err != nil || len(out.Capacities) != 1 {
			t.Fatal("native catalogue unavailable", value, err)
		}
		c := out.Capacities[0]
		if value == "match" {
			if c["status"] != "OBSERVED_CATALOG_CAPACITY" {
				t.Fatal("matching native metadata rejected")
			}
			continue
		}
		if c["status"] != "UNAVAILABLE" || c["vcpu"] != nil || c["network_bytes_per_second"] != nil {
			t.Fatal("conflicting native metadata silently overridden", value, c)
		}
	}
	mode = "absent"
	classes = nil
	out, err = a.RDSCatalog(context.Background(), rdsTestScope, rdsTestARN)
	if err != nil || len(out.Capacities) != 0 {
		t.Fatal("documentation manufactured orderability", err)
	}
}

func TestRDSPhysicalV2OnlyIrelandScopeCanUseNewReviewedFallback(t *testing.T) {
	a := rdsTestAWS(t, func(r *http.Request, body string) (string, int) {
		if r.Header.Get("X-Amz-Target") == "AWSPriceListService.GetProducts" {
			return `{"PriceList":[]}`, 200
		}
		return rdsTestDefault(t, r, body)
	})
	scope := rdsTestScope
	scope.Region = "us-west-2"
	r, err := newRDSRead(a, scope)
	if err != nil {
		t.Fatal(err)
	}
	c, err := r.capacity(context.Background(), "db.m8g.8xlarge")
	if err != nil || c["ebs_baseline"] != nil || c["status"] != "UNAVAILABLE" {
		t.Fatal("Ireland-only source acquired other-region authority", c, err)
	}
}
