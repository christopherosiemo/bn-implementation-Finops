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

func rdsTestModifications(extra string) string {
	return rdsTestPage("DescribeValidDBInstanceModifications", "ValidDBInstanceModificationsMessage", `<Storage><ValidStorageOptions><StorageType>gp3</StorageType><StorageSize><Range><From>100</From><To>16384</To><Step>1</Step></Range><Range><From>20000</From><To>24000</To><Step>1000</Step></Range></StorageSize><ProvisionedIops><Range><From>1000</From><To>64000</To><Step>1000</Step></Range></ProvisionedIops><ProvisionedStorageThroughput><Range><From>125</From><To>1000</To><Step>125</Step></Range></ProvisionedStorageThroughput><IopsToStorageRatio><DoubleRange><From>0.5</From><To>500</To></DoubleRange></IopsToStorageRatio><StorageThroughputToIopsRatio><DoubleRange><From>0</From><To>0.25</To></DoubleRange></StorageThroughputToIopsRatio><SupportsStorageAutoscaling>true</SupportsStorageAutoscaling><UnprojectedRestriction>retained-native-value</UnprojectedRestriction></ValidStorageOptions></Storage><ValidProcessorFeatures><AvailableProcessorFeature><Name>coreCount</Name><DefaultValue>1</DefaultValue><AllowedValues>1,2</AllowedValues></AvailableProcessorFeature></ValidProcessorFeatures><SupportsDedicatedLogVolume>false</SupportsDedicatedLogVolume>`+extra, "")
}
func TestRDSModificationConstraintsPreserveStepsUnknownsAndUnsupported(t *testing.T) {
	raw := []byte(rdsTestModifications(""))
	constraints, e := rdsModificationConstraints(raw, rdsTestARN)
	if e != nil {
		t.Fatal(e)
	}
	storage := constraints["storage"].([]model.Document)
	ranges := storage[0]["storage_size"].([]model.Document)
	if len(storage) != 1 || len(ranges) != 2 || ranges[1]["step"] != int64(1000) || constraints["supports_dedicated_log_volume"] != false {
		t.Fatal("native range/step/false lost")
	}
	encoded, _ := json.Marshal(constraints["native_message"])
	if !strings.Contains(string(encoded), "retained-native-value") {
		t.Fatal("unprojected constraint lost from normalized native message")
	}
	for name, change := range map[string]func(string) string{
		"zero step":           func(s string) string { return strings.Replace(s, "<Step>1000</Step>", "<Step>0</Step>", 1) },
		"inverted range":      func(s string) string { return strings.Replace(s, "<To>16384</To>", "<To>99</To>", 1) },
		"non-native fraction": func(s string) string { return strings.Replace(s, "<From>0.5</From>", "<From>1/2</From>", 1) },
		"duplicate singleton": func(s string) string { return strings.Replace(s, "<Storage>", "<Storage/><Storage>", 1) },
	} {
		t.Run(name, func(t *testing.T) {
			if _, e := rdsModificationConstraints([]byte(change(string(raw))), rdsTestARN); e == nil {
				t.Fatal("invalid native constraint accepted")
			}
		})
	}
	missing := strings.Replace(string(raw), "<Step>1</Step>", "", 1)
	unknown, e := rdsModificationConstraints([]byte(missing), rdsTestARN)
	if e != nil || unknown["storage"].([]model.Document)[0]["storage_size"].([]model.Document)[0]["step"] != nil {
		t.Fatal("unknown step became invented default", e)
	}
	reads := 0
	a := rdsTestAWS(t, func(r *http.Request, b string) (string, int) {
		v, _ := url.ParseQuery(b)
		if v.Get("Action") == "DescribeDBInstances" {
			return rdsTestPage("DescribeDBInstances", "DBInstances", strings.Replace(rdsTestInstance(""), "<Engine>postgres</Engine>", "<Engine>custom-oracle-ee</Engine>", 1), ""), 200
		}
		if v.Get("Action") == "DescribeOrderableDBInstanceOptions" {
			return rdsTestPage("DescribeOrderableDBInstanceOptions", "OrderableDBInstanceOptions", "", ""), 200
		}
		if v.Get("Action") == "DescribeValidDBInstanceModifications" {
			reads++
		}
		return rdsTestDefault(t, r, b)
	})
	out, e := a.RDSCatalog(context.Background(), rdsTestScope, rdsTestARN)
	if e != nil || reads != 0 || out.ModificationConstraints != nil || out.ModificationConstraintsStatus != "UNSUPPORTED_NATIVE_MODIFICATION_CONSTRAINTS" {
		t.Fatal("RDS Custom acquired unsupported modification capability", e)
	}
}
