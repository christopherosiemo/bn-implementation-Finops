package commitmentportfolio

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestPortfolioConfigurationKeepsDedicatedFilesAndPrivateEndpoints(t *testing.T) {
	c := Config{Enabled: true, TenantID: "tenant-a", DatabaseFile: databaseFile, DatabaseMode: "LOCAL_PRIVATE", ModelURL: "http://commitment-portfolio-model:8000", ModelTokenFile: "/run/secrets/commitment-portfolio-model-token"}
	if c.Validate() != nil {
		t.Fatal("fixed private configuration refused")
	}
	for _, change := range []func(*Config){func(c *Config) { c.DatabaseFile = "/tmp/database" }, func(c *Config) { c.ModelTokenFile = c.DatabaseFile }, func(c *Config) { c.ModelURL = "http://customer.example:8000" }, func(c *Config) { c.ModelURL += "/v5/commitment-portfolio" }, func(c *Config) { c.ModelURL = "http://commitment-portfolio-model:443" }, func(c *Config) { c.DatabaseMode = "DISABLE_TLS" }} {
		bad := c
		change(&bad)
		if bad.Validate() == nil {
			t.Fatal("unsafe config accepted")
		}
	}
	lookup := func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("10.1.2.3")}}, nil
	}
	calculator, e := newHTTPCalculator(context.Background(), c.ModelURL, c.DatabaseMode, "0123456789abcdef0123456789abcdef", lookup)
	if e != nil {
		t.Fatal(e)
	}
	client := calculator.Client.(*http.Client)
	transport := client.Transport.(*http.Transport)
	if client.Timeout != 35*time.Second || transport.Proxy != nil || client.CheckRedirect(&http.Request{}, nil) != http.ErrUseLastResponse {
		t.Fatal("HTTP timeout/proxy/redirect boundary changed")
	}
	if _, e = transport.DialContext(context.Background(), "tcp", "other-host:8000"); e == nil {
		t.Fatal("transport accepted a different destination")
	}
	public := func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}, nil
	}
	if _, e = newHTTPCalculator(context.Background(), c.ModelURL, c.DatabaseMode, "0123456789abcdef0123456789abcdef", public); e == nil {
		t.Fatal("public resolved endpoint accepted")
	}
}

func TestPortfolioModelTransportAndDatabaseRefuseAmbientIdentityOverrides(t *testing.T) {
	private := func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("10.2.3.4")}}, nil
	}
	for _, raw := range []string{"postgres://worker:secret@postgres:5432/finops?sslmode=disable&options=-crole%3Dpostgres", "postgres://postgres:secret@postgres:5432/finops?sslmode=disable", "postgres://worker:secret@public.example:5432/finops?sslmode=disable", "postgres://worker:secret@postgres:5432/finops?sslmode=allow"} {
		if _, e := databaseURL(context.Background(), []byte(raw), "LOCAL_PRIVATE", private); e == nil {
			t.Fatal("database boundary accepted unsafe selection")
		}
	}
	dsn, e := databaseURL(context.Background(), []byte("postgres://worker:secret@db.private.example:5432/finops?sslmode=verify-full&sslrootcert=/run/ca/commitment-portfolio-root.crt"), "HOSTED_TLS", private)
	if e != nil || dsn == "" {
		t.Fatal("hosted exact TLS hostname refused")
	}
}
