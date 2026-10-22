package store

import "testing"

func TestNonFixtureDatabaseCannotDowngradeOrSkipHostnameVerification(t *testing.T) {
	for _, mode := range []string{"disable", "allow", "prefer", "require", "verify-ca", "invalid"} {
		if err := ValidateDatabaseTransport("postgres://fixture:private-value@db.example.invalid/finops?sslmode=" + mode); err == nil || err.Error() != "DATABASE_VERIFIED_TLS_REQUIRED" {
			t.Fatalf("%s did not fail with a sanitized transport error", mode)
		}
	}
	if err := ValidateDatabaseTransport("postgres://fixture:private-value@db.example.invalid/finops?sslmode=verify-full"); err != nil {
		t.Fatal("hostname-verifying TLS was rejected")
	}
	if err := ValidateDatabaseTransport("host=db.example.invalid,standby.example.invalid user=fixture password=private-value dbname=finops sslmode=verify-full"); err != nil {
		t.Fatal("verified TLS failover hosts were rejected")
	}
	if err := ValidateDatabaseTransport("host=/tmp user=fixture password=private-value dbname=finops sslmode=verify-full"); err == nil {
		t.Fatal("a local socket bypassed the non-fixture TLS requirement")
	}
	if err := ValidateDatabaseTransport("postgres://invalid:private-value@["); err == nil || err.Error() != "DATABASE_VERIFIED_TLS_REQUIRED" {
		t.Fatal("invalid connection configuration leaked a parse error")
	}
}
