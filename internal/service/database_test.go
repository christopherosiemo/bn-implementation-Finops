package service

import (
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"testing"
)

func TestDatabaseConfigurationIdentityIgnoresAcquisitionButPreservesAuthority(t *testing.T) {
	r := model.Document{"id": "db", "provider_resource_id": "arn:db", "account_id": "111122223333", "region": "eu-west-1", "resource_type": "RDS_INSTANCE", "database_configuration": model.Document{"class": "db.r6i.large", "raw_page_sha256": "one", "status": "available"}}
	before := DatabaseConfigurationHash(r)
	native := databaseObject(r["database_configuration"])
	native["raw_page_sha256"] = "two"
	native["status"] = "modifying"
	r["database_configuration"] = native
	if DatabaseConfigurationHash(r) != before {
		t.Fatal("acquisition invalidated stable configuration")
	}
	native["pending_modified_values"] = model.Document{"class": "db.r6i.small"}
	if DatabaseConfigurationHash(r) == before {
		t.Fatal("pending modification was ignored")
	}
	delete(native, "pending_modified_values")
	r["workload_id"] = "other"
	if DatabaseConfigurationHash(r) == before {
		t.Fatal("ownership change was ignored")
	}
}

func TestDatabaseResultCannotAcquireExecutionOrFloatMoney(t *testing.T) {
	input := model.Document{"binding": model.Document{"tenant_id": "t", "resource_id": "db"}, "current_pricing": model.Document{"currency": "GBP"}}
	result := model.Document{"schema_version": "1", "binding": input["binding"], "status": "RECOMMENDED", "proposal": model.Document{"executable": false, "execution_authorized": false, "risk_class": "R3"}, "verified_saving": nil, "economics": model.Document{"estimated_monthly_saving": "-12.000000000001", "currency": "GBP"}}
	if err := databaseValidateResult(result, input); err != nil {
		t.Fatal(err)
	}
	proposal := databaseObject(result["proposal"])
	proposal["executable"] = true
	result["proposal"] = proposal
	if databaseValidateResult(result, input) == nil {
		t.Fatal("executable database response accepted")
	}
	proposal["executable"] = false
	economics := databaseObject(result["economics"])
	economics["estimated_monthly_saving"] = 12.0
	result["economics"] = economics
	if databaseValidateResult(result, input) == nil {
		t.Fatal("floating money accepted")
	}
	economics["estimated_monthly_saving"] = "12"
	result["binding"] = model.Document{"tenant_id": "other", "resource_id": "db"}
	if databaseValidateResult(result, input) == nil {
		t.Fatal("cross tenant response accepted")
	}
}
