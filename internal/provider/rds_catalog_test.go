package provider

import (
	"context"
	"encoding/json"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestRDSCatalogUsesOrderableNativeClassAndCatalogCapacityOnly(t *testing.T) {
	priceReads := 0
	a := rdsTestAWS(t, func(r *http.Request, body string) (string, int) {
		if r.Header.Get("X-Amz-Target") == "AWSPriceListService.GetProducts" {
			priceReads++
			var request model.Document
			if json.Unmarshal([]byte(body), &request) != nil {
				t.Fatal("invalid pricing request")
			}
			if !strings.Contains(body, "db.r6g.large") || strings.Contains(body, "SavingsPlans") {
				t.Fatal("arbitrary names or purchase quote used as instance catalogue")
			}
			product := model.Document{"product": model.Document{"sku": "native-catalog-sku", "productFamily": "Database Instance", "attributes": map[string]string{"servicecode": "AmazonRDS", "instanceType": "db.r6g.large", "regionCode": "eu-west-1", "vcpu": "2", "memory": "16 GiB", "physicalProcessor": "AWS Graviton2", "processorArchitecture": "arm64", "networkPerformance": "Up to 10 Gigabit"}}, "terms": model.Document{"OnDemand": model.Document{"unrelated-public-price": "must-not-be-customer-economics"}}}
			raw, _ := json.Marshal(product)
			response, _ := json.Marshal(model.Document{"PriceList": []string{string(raw)}})
			return string(response), 200
		}
		v, _ := url.ParseQuery(body)
		if v.Get("Action") == "DescribeOrderableDBInstanceOptions" {
			if v.Get("Engine") != "postgres" || v.Get("EngineVersion") != "16.4" || v.Get("LicenseModel") != "postgresql-license" || v.Get("DBInstanceClass") != "" {
				t.Fatal("native compatibility selector lost")
			}
			row := "<OrderableDBInstanceOption><Engine>postgres</Engine><EngineVersion>16.4</EngineVersion><LicenseModel>postgresql-license</LicenseModel><DBInstanceClass>db.r6g.large</DBInstanceClass><StorageType>gp3</StorageType><Vpc>true</Vpc><MultiAZCapable>true</MultiAZCapable><AvailabilityZones><AvailabilityZone><Name>eu-west-1a</Name></AvailabilityZone></AvailabilityZones></OrderableDBInstanceOption>"
			return rdsTestPage("DescribeOrderableDBInstanceOptions", "OrderableDBInstanceOptions", row, ""), 200
		}
		return rdsTestDefault(t, r, body)
	})
	out, e := a.RDSCatalog(context.Background(), rdsTestScope, rdsTestARN)
	if e != nil || priceReads != 1 || len(out.Options) != 1 || len(out.Capacities) != 1 {
		t.Fatalf("catalogue read %v", e)
	}
	capacity := out.Capacities[0]
	if out.ModificationConstraintsStatus != "OBSERVED_NATIVE_CURRENT_INSTANCE_CONSTRAINTS" || model.String(out.ModificationConstraints, "resource_arn") != rdsTestARN || model.String(out.ModificationConstraints, "raw_page_sha256") == "" {
		t.Fatal("native modification constraints omitted")
	}
	if capacity["vcpu"] != int64(2) || capacity["memory_bytes"] != int64(16<<30) || capacity["network_bytes_per_second"] != nil {
		t.Fatal("native capacity/unsupported qualifier changed")
	}
	for _, key := range []string{"price", "hourly_cost", "estimated_saving"} {
		if _, exists := capacity[key]; exists {
			t.Fatal("public list price promoted")
		}
	}
}
func TestRDSReadScopeErrorsAndOptionalExposureFailClosed(t *testing.T) {
	calls := 0
	a := rdsTestAWS(t, func(r *http.Request, body string) (string, int) {
		calls++
		if strings.HasPrefix(r.URL.Host, "savingsplans.") || strings.HasPrefix(r.URL.Host, "compute-optimizer.") {
			return "{\"__type\":\"AccessDeniedException\",\"message\":\"private provider diagnostic\"}", 400
		}
		return rdsTestDefault(t, r, body)
	})
	if _, e := a.RDSDatabaseSavingsPlans(context.Background(), rdsTestScope); e == nil || strings.Contains(e.Error(), "private provider diagnostic") {
		t.Fatal("optional failure became empty authorized exposure or leaked body")
	}
	if _, e := a.RDSDiscover(context.Background(), rdsTestScope); e != nil {
		t.Fatal("optional refusal changed independent discovery", e)
	}
	if _, e := a.RDSCatalog(context.Background(), rdsTestScope, strings.Replace(rdsTestARN, "111122223333", "999988887777", 1)); e == nil {
		t.Fatal("foreign ARN accepted")
	}
	reader, e := newRDSRead(a, rdsTestScope)
	if e != nil {
		t.Fatal(e)
	}
	before := calls
	if _, e = reader.query(context.Background(), "rds", "ModifyDBInstance", url.Values{}); e == nil || calls != before {
		t.Fatal("mutation was dispatched")
	}
	for _, raw := range []string{"{\"x\":1,\"x\":2}", "{\"x\":{\"same\":1,\"same\":2}}"} {
		var out model.Document
		if rdsJSON([]byte(raw), &out) == nil {
			t.Fatal("ambiguous native JSON accepted")
		}
	}
	if _, e = RDSCaptureFrames([]byte("RDS_READ_V1\n\x00\x00\xff\xff")); e == nil {
		t.Fatal("unbounded raw frame accepted")
	}
}
