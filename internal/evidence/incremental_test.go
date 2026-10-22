package evidence

import (
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"testing"
)

func TestIncrementalReferencesCannotOmitUnknownCharges(t *testing.T) {
	row := model.Document{"x_SourceRecordId": "charge", "ResourceId": "i-target", "ServiceName": "Other", "EffectiveCost": "1.0", "ChargePeriodStart": "2026-09-01T00:00:00Z", "ChargePeriodEnd": "2026-09-01T01:00:00Z", "x_ProviderFields": model.Document{"finops_incremental_execution_id": "owned"}}
	ids, e := IncrementalReferences(nil, []model.Document{row}, []model.Document{{"execution_id": "owned"}})
	if e != nil || len(ids) != 1 {
		t.Fatal(e)
	}
	row["x_ProviderFields"] = model.Document{}
	if _, e = IncrementalReferences(nil, []model.Document{row}, nil); e == nil {
		t.Fatal("unknowncharge silentlyomitted")
	}
	row["x_ProviderFields"] = model.Document{"product_product_family": "Storage", "line_item_usage_type": "EBS:VolumeUsage"}
	if _, e = IncrementalReferences([]model.Document{row}, []model.Document{row}, nil); e != nil {
		t.Fatal("continuingretainedcost shouldnotbeavoided:", e)
	}
	changed := model.Clone(row)
	changed["EffectiveCost"] = "2.0"
	if _, e = IncrementalReferences([]model.Document{row}, []model.Document{changed}, nil); e == nil {
		t.Fatal("newstoragecost silentlyomitted")
	}
}
