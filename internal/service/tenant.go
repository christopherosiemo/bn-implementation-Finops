package service

import (
	"crypto/subtle"
	"os"
)

// ValidateAWSTenant binds the one configured customer-role pair to exactly one
// authenticated tenant. A regional cell may store many tenants' fixture/evidence
// records, but it must never lend one customer's live cloud identity to another.
// A future multi-account role registry replaces this explicit pilot binding.
func ValidateAWSTenant(tenant string) error {
	expected := os.Getenv("AWS_TENANT_ID")
	if expected == "" || tenant == "" || subtle.ConstantTimeCompare([]byte(expected), []byte(tenant)) != 1 {
		return problem(403, "AWS_TENANT_NOT_CONFIGURED", "No live AWS identity is configured for this tenant")
	}
	return nil
}
