package service

import (
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"testing"
)

func TestLiveHealthRequiresHTTPS443AndAllowlist(t *testing.T) {
	cfg := Config{HealthAllowedHosts: "health.example.test"}
	for _, target := range []string{"http://health.example.test/health", "https://health.example.test:8443/health", "https://other.example.test/health", "https://user@health.example.test/health", "https://health.example.test/health#fragment"} {
		if validateHealthURL(target, cfg) == nil {
			t.Fatalf("unsafe live health accepted:%s", target)
		}
	}
	for _, target := range []string{"https://health.example.test/health", "https://health.example.test:443/health"} {
		if e := validateHealthURL(target, cfg); e != nil {
			t.Fatal(e)
		}
	}
}

func TestUploadedSourcesCannotAuthorizeLiveOrFixtureExecution(t *testing.T) {
	for _, fixture := range []bool{false, true} {
		for _, provenance := range []string{"CUSTOMER_IMPORT", "AWS_EXPORT", "", "true"} {
			if trustedSource(model.Document{"source_provenance": provenance}, fixture) == nil {
				t.Fatalf("untrustedsourceacceptedfixture=%v provenance=%s", fixture, provenance)
			}
		}
	}
	if trustedSource(model.Document{"source_provenance": "DETERMINISTIC_FIXTURE"}, false) == nil {
		t.Fatal("fixtureproducer authorized live mode")
	}
	if e := trustedSource(model.Document{"source_provenance": "DETERMINISTIC_FIXTURE"}, true); e != nil {
		t.Fatal(e)
	}
}
