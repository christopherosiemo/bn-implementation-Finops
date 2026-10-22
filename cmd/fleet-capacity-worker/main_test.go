package main

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type probeRoundTripper func(*http.Request) (*http.Response, error)

func (f probeRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestOnlyExactHealthcheckArgumentIsAccepted(t *testing.T) {
	if commandMode(nil) != serve || commandMode([]string{"--healthcheck"}) != probe {
		t.Fatal("worker or fixed readiness mode unavailable")
	}
	for _, args := range [][]string{{"--help"}, {"--healthcheck=http://example.invalid"}, {"--healthcheck", "http://127.0.0.1:8080/readyz"}, {"--healthcheck", "--healthcheck"}, {"--HEALTHCHECK"}, {""}} {
		if commandMode(args) != forbidden {
			t.Fatal("nonfixed arguments accepted")
		}
	}
}

func TestReadinessProbeUsesFixedGETAndTwoSecondDeadline(t *testing.T) {
	called := false
	if !readinessProbe(probeRoundTripper(func(r *http.Request) (*http.Response, error) {
		called = true
		deadline, ok := r.Context().Deadline()
		remaining := time.Until(deadline)
		if r.Method != http.MethodGet || r.URL.String() != "http://127.0.0.1:8080/readyz" || r.Body != nil || len(r.Header) != 0 || !ok || remaining <= 0 || remaining > 2*time.Second || readinessTimeout != 2*time.Second {
			t.Fatal("readiness request or deadline differs")
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("ready"))}, nil
	})) || !called {
		t.Fatal("successful fixed readiness response refused")
	}
}

func TestReadinessProbeRequires200AndRefusesRedirectOrTransportError(t *testing.T) {
	for _, status := range []int{http.StatusNoContent, http.StatusMovedPermanently, http.StatusTemporaryRedirect, http.StatusUnauthorized, http.StatusServiceUnavailable} {
		calls := 0
		if readinessProbe(probeRoundTripper(func(r *http.Request) (*http.Response, error) {
			calls++
			return &http.Response{StatusCode: status, Header: http.Header{"Location": []string{"http://elsewhere.invalid/readyz"}}, Body: io.NopCloser(strings.NewReader(""))}, nil
		})) || calls != 1 {
			t.Fatal("non200 response or redirect accepted")
		}
	}
	if readinessProbe(probeRoundTripper(func(*http.Request) (*http.Response, error) { return nil, errors.New("transport unavailable") })) {
		t.Fatal("transport failure accepted")
	}
}
