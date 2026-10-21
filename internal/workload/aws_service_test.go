package workload

import (
	"encoding/json"
	"testing"
)

func TestAWSServiceRequirementsRejectMeasurementsAndInvalidFractions(t *testing.T) {
	if validateAWSServiceLimits(AWSServiceLimits{MemoryMaxFraction: "0.8", MaxSwapBytes: "0", Purpose: "FAILOVER"}) != nil {
		t.Fatal("explicit business constraints refused")
	}
	if validateAWSServiceLimits(AWSServiceLimits{MemoryMaxFraction: "1.1"}) == nil {
		t.Fatal("unbounded memory fraction accepted")
	}
	if validateAWSServiceLimits(AWSServiceLimits{MemoryHeadroomFraction: "1"}) == nil || validateAWSServiceLimits(AWSServiceLimits{ReadTargetUtilizationFraction: "0"}) == nil {
		t.Fatal("non-executable headroom/target requirement accepted")
	}
	var p Profile
	if json.Unmarshal([]byte(`{"aws_service":{"memory_max_fraction":"0.8"}}`), &p) != nil || p.AWSService == nil {
		t.Fatal("typed optional extension lost")
	}
	_, e := Decode([]byte(`{"aws_service":{"observed_memory_bytes":"0"}}`))
	if e == nil {
		t.Fatal("measurements accepted as customer policy")
	}
}
