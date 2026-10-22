package fleetcapacityworker

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/native"
	"github.com/jackc/pgx/v5/pgxpool"
)

func tokenFile(t *testing.T, name, value string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if e := os.WriteFile(p, []byte(value), 0444); e != nil {
		t.Fatal(e)
	}
	return p
}
func TestPrivateDependenciesUseSeparateFixedMethodsPathsAndTokens(t *testing.T) {
	readerCalls, modelCalls := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Error("method changed")
		}
		switch r.URL.Path {
		case "/capacity-input":
			readerCalls++
			if r.Header.Get("Authorization") != "Bearer reader-private" {
				t.Error("reader credential changed")
			}
			var in native.CapacityInputRequest
			if json.NewDecoder(r.Body).Decode(&in) != nil || in.TenantID != "tenant" {
				t.Error("reader input changed")
			}
			_ = json.NewEncoder(w).Encode(native.CapacityPopulation{SchemaVersion: "1"})
		case "/v4/capacity":
			modelCalls++
			if r.Header.Get("Authorization") != "Bearer model-private" {
				t.Error("model credential changed")
			}
			_, _ = w.Write([]byte(`{"actual_model_response":true}`))
		default:
			t.Error("arbitrary path")
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	c := testConfig()
	c.ReaderURL, c.ModelURL = server.URL, server.URL
	c.ReaderTokenFile = tokenFile(t, "reader", "reader-private")
	c.ModelTokenFile = tokenFile(t, "model", "model-private")
	reader, model, close, e := OpenHTTPDependencies(context.Background(), c)
	if e != nil {
		t.Fatal(e)
	}
	defer close()
	if _, e = reader.Read(context.Background(), native.CapacityInputRequest{TenantID: "tenant"}); e != nil {
		t.Fatal(e)
	}
	if _, e = model.Calculate(context.Background(), native.CapacityModelRequest{}); e != nil {
		t.Fatal(e)
	}
	if readerCalls != 1 || modelCalls != 1 {
		t.Fatal("expected exact two bounded calls")
	}
}
func TestPrivateDependenciesRefuseCredentialConfusionAndRedirect(t *testing.T) {
	c := testConfig()
	c.ReaderTokenFile = tokenFile(t, "reader", "same-private")
	c.ModelTokenFile = tokenFile(t, "model", "same-private")
	if _, _, _, e := OpenHTTPDependencies(context.Background(), c); e == nil {
		t.Fatal("shared reader/model key accepted")
	}
	calls := 0
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(200) }))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 307) }))
	defer redirect.Close()
	c.ModelTokenFile = tokenFile(t, "model", "distinct-model")
	c.ReaderURL, c.ModelURL = redirect.URL, redirect.URL
	reader, _, close, e := OpenHTTPDependencies(context.Background(), c)
	if e != nil {
		t.Fatal(e)
	}
	defer close()
	if _, e = reader.Read(context.Background(), native.CapacityInputRequest{}); e == nil || calls != 0 {
		t.Fatal("redirect forwarded private token")
	}
	for _, raw := range []string{"http://8.8.8.8:8080", "http://127.0.0.1:80/path", "http://127.0.0.1:80?x=1", "http://user@127.0.0.1:80", "https://127.0.0.1:444"} {
		bad := testConfig()
		bad.ReaderURL = raw
		if bad.Validate() == nil {
			t.Fatal("invalid installed URL accepted", raw)
		}
	}
}
func TestPrivateDatabaseRetainsTLSNameAndRefusesOverrides(t *testing.T) {
	ctx := context.Background()
	dsn, e := databaseURL(ctx, []byte("postgres://capacity:private@localhost:5432/finops?sslmode=verify-full&sslrootcert=/etc/finops/rds/ca.pem"), true)
	if e != nil || dsn != "postgres://capacity:private@localhost:5432/finops?pool_max_conns=3&sslmode=verify-full&sslrootcert=%2Fetc%2Ffinops%2Frds%2Fca.pem" {
		t.Fatal("TLS DNS identity lost", e)
	}
	// Parse with system roots independently of a fixture CA file to verify pgx
	// still authenticates the DNS name, not the preflight numeric address.
	secure, e := databaseURL(ctx, []byte("postgres://capacity:private@localhost:5432/finops?sslmode=verify-full"), false)
	parsed, e := pgxpool.ParseConfig(secure)
	if e != nil || parsed.ConnConfig.Host != "localhost" || parsed.ConnConfig.TLSConfig == nil || parsed.ConnConfig.TLSConfig.ServerName != "localhost" || parsed.ConnConfig.TLSConfig.InsecureSkipVerify {
		t.Fatal("pgx TLS identity weakened")
	}
	for _, q := range []string{"sslmode=disable", "sslmode=verify-full&sslrootcert=/tmp/ca.pem", "sslmode=verify-full&sslrootcert=/etc/finops/rds/ca.pem&host=other", "sslmode=disable&sslmode=verify-full"} {
		if _, e := databaseURL(ctx, []byte("postgres://capacity:private@localhost:5432/finops?"+q), true); e == nil {
			t.Fatal("hosted DB boundary bypass")
		}
	}
}

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type countBody struct{ n int }

func (b *countBody) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	b.n += len(p)
	return len(p), nil
}
func (b *countBody) Close() error { return nil }
func TestPrivateResponseBoundsCountUnknownLengthAndRejectWrongStatus(t *testing.T) {
	for _, length := range []int64{-1, 1024} {
		body := &countBody{}
		client := privateClient{url: "http://127.0.0.1:1", path: "/capacity-input", maximum: 16, client: &http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, ContentLength: length, Body: body}, nil
		})}}
		if _, e := client.post(context.Background(), struct{}{}); e == nil || body.n > 17 || length > 16 && body.n != 0 {
			t.Fatal("response read exceeded cap+1", body.n)
		}
	}
	client := privateClient{url: "http://127.0.0.1:1", path: "/capacity-input", maximum: 16, client: &http.Client{Transport: transportFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 403, Body: io.NopCloser(strings.NewReader(`{"ignored":true}`))}, nil
	})}}
	if _, e := client.post(context.Background(), struct{}{}); e == nil {
		t.Fatal("error response admitted as population")
	}
}
func TestCapacityPrivateFilesRejectExecutableWritableSymlinkAndOversize(t *testing.T) {
	p := tokenFile(t, "credential", "private")
	if _, e := privateFile(p, 4); e == nil {
		t.Fatal("oversized private file accepted")
	}
	for _, mode := range []os.FileMode{0555, 0666} {
		if os.Chmod(p, mode) != nil {
			t.Fatal("chmod")
		}
		if _, e := privateFile(p, 256); e == nil {
			t.Fatal("unsafe projected credential accepted")
		}
	}
	_ = os.Chmod(p, 0444)
	link := filepath.Join(t.TempDir(), "link")
	if os.Symlink(p, link) != nil {
		t.Fatal("symlink")
	}
	if _, e := privateFile(link, 256); e == nil {
		t.Fatal("credential symlink followed")
	}
}
func TestCapacityConfigHasSeparateOptInAndFixedPrivateServiceMode(t *testing.T) {
	c := testConfig()
	values := map[string]string{"FLEET_CAPACITY_ENABLED": "true", "FLEET_CAPACITY_TENANT_ID": c.Archive.TenantID, "FLEET_CAPACITY_DATABASE_FILE": c.Archive.DatabaseFile, "FLEET_CAPACITY_ARCHIVE_MODE": c.Archive.ArchiveMode, "FLEET_CAPACITY_ARCHIVE_REGION": c.Archive.ArchiveRegion, "FLEET_CAPACITY_ARCHIVE_ENDPOINT": c.Archive.ArchiveEndpoint, "FLEET_CAPACITY_ARCHIVE_BUCKET": c.Archive.ArchiveBucket, "FLEET_CAPACITY_ARCHIVE_ACCESS_KEY_FILE": c.Archive.ArchiveAccessKeyFile, "FLEET_CAPACITY_ARCHIVE_SECRET_KEY_FILE": c.Archive.ArchiveSecretKeyFile, "FLEET_CAPACITY_SERVICE_MODE": c.ServiceMode, "FLEET_CAPACITY_READER_URL": c.ReaderURL, "FLEET_CAPACITY_READER_TOKEN_FILE": c.ReaderTokenFile, "FLEET_CAPACITY_MODEL_URL": c.ModelURL, "FLEET_CAPACITY_MODEL_TOKEN_FILE": c.ModelTokenFile}
	if got, e := ConfigFromEnvironment(func(k string) string { return values[k] }); e != nil || got != c {
		t.Fatal("deployment contract changed", e)
	}
	delete(values, "FLEET_CAPACITY_ENABLED")
	values["FLEET_ASSESSMENT_ENABLED"] = "true"
	if _, e := ConfigFromEnvironment(func(k string) string { return values[k] }); e == nil {
		t.Fatal("other worker opt-in enabled capacity")
	}
	for _, mutate := range []func(*Config){func(c *Config) { c.ModelTokenFile = c.ReaderTokenFile }, func(c *Config) { c.ServiceMode = "PUBLIC" }, func(c *Config) { c.Archive.DatabaseFile = "relative" }} {
		bad := c
		mutate(&bad)
		if bad.Validate() == nil {
			t.Fatal("ambiguous commissioning accepted")
		}
	}
}
