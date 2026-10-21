package workflow

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestAWSBoundDiscoveryErrorsDoNotExposeProviderInputs(t *testing.T) {
	private := errors.New("provider reflected private external ID or credential input")
	for _, cause := range []error{private, fmt.Errorf("assume role failed: %w", private)} {
		safe := boundAccountDiscoveryError(true, cause)
		if safe == nil || safe.Error() != "AWS_BOUND_ACCOUNT_DISCOVERY_UNAVAILABLE" || strings.Contains(safe.Error(), private.Error()) || errors.Is(safe, private) {
			t.Fatal("bound discovery retained provider input or wrapped cause")
		}
		if boundAccountDiscoveryError(false, cause) != cause {
			t.Fatal("legacy error behavior changed")
		}
	}
	if boundAccountDiscoveryError(true, nil) != nil {
		t.Fatal("successful bound discovery became an error")
	}
}
