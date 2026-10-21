package workflow

import (
	"github.com/christopherosiemo/bn-implementation-Finops/internal/awsservice"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"testing"
)

func TestAWSServiceGenerationCannotHideEarlierPageDenial(t *testing.T) {
	earlier := model.Document{"reason_codes": []string{"ECS_TASK_DESCRIPTION_DENIED"}, "next_cursor": "page-two"}
	final := awsServiceGenerationCollection(earlier, awsservice.Collection{Complete: true, Reasons: []string{}})
	if final.Complete || len(final.Reasons) != 1 || final.Reasons[0] != "ECS_TASK_DESCRIPTION_DENIED" {
		t.Fatal("clean final page hid denied earlier source evidence")
	}
	fresh := awsServiceGenerationCollection(model.Document{}, awsservice.Collection{Complete: true})
	if !fresh.Complete || len(fresh.Reasons) != 0 {
		t.Fatal("new generation retained unrelated old debt")
	}
}
