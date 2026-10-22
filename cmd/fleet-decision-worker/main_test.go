package main

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestHealthcheckUsesOnlyFixedReadinessWithoutConfiguration(t *testing.T) {
	t.Setenv("FLEET_DECISION_DATABASE_FILE", "/do-not-read")
	called := 0
	e := healthcheck(roundTrip(func(r *http.Request) (*http.Response, error) {
		called++
		if r.Method != "GET" || r.URL.String() != "http://127.0.0.1:8080/readyz" {
			t.Fatal("arbitrary target or method")
		}
		deadline, ok := r.Context().Deadline()
		remaining := time.Until(deadline)
		if !ok || remaining <= 0 || remaining > 2*time.Second {
			t.Fatal("health timeout differs")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{}}, nil
	}))
	if e != nil || called != 1 {
		t.Fatal("fixed readiness failed", e)
	}
	for _, status := range []int{301, 401, 503} {
		if healthcheck(roundTrip(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{}}, nil
		})) == nil {
			t.Fatal("non200 accepted")
		}
	}
}
func TestOnlyFixedHealthcheckArgumentAllowed(t *testing.T) {
	for _, args := range [][]string{{"--url", "http://foreign"}, {"--healthcheck", "http://foreign"}, {"--help"}, {"--tenant", "foreign"}} {
		if _, e := commandMode(args); e == nil {
			t.Fatal("arbitrary args accepted")
		}
	}
	if mode, e := commandMode([]string{"--healthcheck"}); e != nil || mode != "healthcheck" {
		t.Fatal("health argument refused")
	}
}
