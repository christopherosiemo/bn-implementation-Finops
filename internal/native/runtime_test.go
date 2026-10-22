package native

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/telemetry"
)

func runtimeBinding() ReadBinding {
	return ReadBinding{Binding: telemetry.Binding{TenantID: "tenant", ResourceID: "resource", WorkloadID: "workload", Provider: "AWS", ProviderResourceID: "i-0123456789abcdef0", AccountID: "123456789012", Region: "eu-west-1"}, Endpoint: "https://metrics.example:443", AllowedCIDRs: []string{"10.20.0.0/16"}, RequiredLabels: map[string]string{"host_id": "i-0123456789abcdef0"}}
}
func TestBindingsRequireServerScopeAndForbidMetadata(t *testing.T) {
	b := runtimeBinding()
	raw, _ := json.Marshal(map[string]ReadBinding{"approved": b})
	if _, e := BindingsFromEnv(string(raw), false); e != nil {
		t.Fatal(e)
	}
	for _, mutate := range []func(*ReadBinding){func(b *ReadBinding) { b.Endpoint = "http://metrics.example" }, func(b *ReadBinding) {
		b.Endpoint = "https://169.254.169.254"
		b.AllowedCIDRs = []string{"169.254.0.0/16"}
	}, func(b *ReadBinding) { b.Endpoint = "https://127.0.0.1"; b.AllowedCIDRs = []string{"127.0.0.1/32"} }, func(b *ReadBinding) { b.AllowedCIDRs = []string{"0.0.0.0/0"} }, func(b *ReadBinding) { b.RequiredLabels = nil }, func(b *ReadBinding) { b.Endpoint = "https://metrics.example:8443" }, func(b *ReadBinding) { b.Binding.AccountID = "not-account" }} {
		b := runtimeBinding()
		mutate(&b)
		raw, _ := json.Marshal(map[string]ReadBinding{"approved": b})
		if _, e := BindingsFromEnv(string(raw), false); e == nil {
			t.Fatalf("invalid binding accepted: %+v", b)
		}
	}
	c := telemetry.Connection{Binding: runtimeBinding().Binding, Definitions: []telemetry.Definition{{Attributes: map[string]string{"host_id": "another-host"}}}}
	if runtimeBinding().connection(c) == nil {
		t.Fatal("server resource label did not bind selector")
	}
	c.Definitions[0].Attributes["host_id"] = c.Binding.ProviderResourceID
	if runtimeBinding().connection(c) != nil {
		t.Fatal("correct binding rejected")
	}
}
func TestBindingPinsDNSAndDoesNotForwardCredentialRedirect(t *testing.T) {
	var forwarded atomic.Int32
	receiver := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { forwarded.Add(1) }))
	defer receiver.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer token-one" {
			t.Error("credential unavailable")
		}
		http.Redirect(w, r, receiver.URL, http.StatusFound)
	}))
	defer source.Close()
	file := filepath.Join(t.TempDir(), "token")
	if e := os.WriteFile(file, []byte("token-one\n"), 0600); e != nil {
		t.Fatal(e)
	}
	b := runtimeBinding()
	b.Endpoint = source.URL
	b.AllowedCIDRs = []string{"127.0.0.1/32"}
	b.CredentialFile = file
	reader, e := b.Reader(true)
	if e != nil {
		t.Fatal(e)
	}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, source.URL, nil)
	response, e := reader.Client.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	response.Body.Close()
	if response.StatusCode != 302 || forwarded.Load() != 0 {
		t.Fatal("credential redirect followed")
	}
	b.AllowedCIDRs = []string{"10.20.0.0/16"}
	if _, e = b.Reader(true); e == nil {
		t.Fatal("configured endpoint outside approved CIDRs accepted")
	}
}
func TestNativeHTTPBoundaryRejectsBrowserAndUnauthenticatedReader(t *testing.T) {
	s := &Server{}
	for _, route := range []string{"/v1/metrics", "/evaluate"} {
		r := httptest.NewRequest(http.MethodPost, route, strings.NewReader(`{}`))
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if route == "/v1/metrics" && w.Code != 503 || route == "/evaluate" && w.Code != 401 {
			t.Fatalf("boundary %s %d", route, w.Code)
		}
	}
	r := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal("healthz unavailable")
	}
}
