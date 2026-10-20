//go:build commitment_decision_native_integration

package service

import (
	"bytes"
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"
)

// These diagnostics stay in the private native-lab log. Production errors remain
// opaque, and this transport does not alter requests, retries or write receipts.
type commitmentDecisionAnalyticsTransport struct {
	base http.RoundTripper
	logf func(string, ...any)
}

type commitmentDecisionAnalyticsBody struct {
	io.Reader
	io.Closer
}

var commitmentDecisionExceptionCode = regexp.MustCompile(`^[0-9]{1,6}$`)

func (d commitmentDecisionAnalyticsTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := d.base.RoundTrip(request)
	if err != nil || response == nil || response.Body == nil || response.StatusCode == http.StatusOK ||
		request.Method != http.MethodPost || request.URL.Scheme != "http" || request.URL.Host != "clickhouse:8123" ||
		request.URL.Query().Get("query") != "INSERT INTO native_metric_samples FORMAT JSONEachRow" {
		return response, err
	}
	const limit = 8192
	original := response.Body
	prefix, readErr := io.ReadAll(io.LimitReader(original, limit+1))
	response.Body = commitmentDecisionAnalyticsBody{Reader: io.MultiReader(bytes.NewReader(prefix), original), Closer: original}
	text := commitmentDecisionAnalyticsRedactedPrefix(prefix, request.Header, limit)
	code := response.Header.Get("X-ClickHouse-Exception-Code")
	if !commitmentDecisionExceptionCode.MatchString(code) {
		code = "UNAVAILABLE"
	}
	d.logf("native analytics rejection: status=%d exception_code=%s truncated=%t read_failed=%t response=%q", response.StatusCode, code, len(prefix) > limit, readErr != nil, text)
	return response, err
}

// Redact before bounding the log text, including a credential prefix cut by
// the bounded response read. The original response bytes are restored above.
func commitmentDecisionAnalyticsRedactedPrefix(prefix []byte, header http.Header, limit int) string {
	text := string(prefix)
	for _, name := range []string{"X-ClickHouse-Key", "X-ClickHouse-User", "Authorization"} {
		secret := header.Get(name)
		if secret == "" {
			continue
		}
		text = strings.ReplaceAll(text, secret, "[REDACTED]")
		if len(prefix) > limit {
			for n := min(len(secret)-1, len(text)); n > 0; n-- {
				if strings.HasSuffix(text, secret[:n]) {
					text = text[:len(text)-n] + "[REDACTED_TRUNCATED]"
					break
				}
			}
		}
	}
	return text[:min(len(text), limit)]
}

func commitmentDecisionAnalyticsClient(t *testing.T) *http.Client {
	t.Helper()
	client := &http.Client{
		Timeout:       45 * time.Second,
		Transport:     commitmentDecisionAnalyticsTransport{base: &http.Transport{Proxy: nil}, logf: t.Logf},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	t.Cleanup(func() {
		client.Transport.(commitmentDecisionAnalyticsTransport).base.(*http.Transport).CloseIdleConnections()
	})
	return client
}

type commitmentDecisionAnalyticsRoundTrip func(*http.Request) (*http.Response, error)

func (f commitmentDecisionAnalyticsRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

type commitmentDecisionAnalyticsTrackedBody struct {
	io.Reader
	closed int
}

func (b *commitmentDecisionAnalyticsTrackedBody) Close() error { b.closed++; return nil }

func TestCommitmentDecisionAnalyticsDiagnosticPreservesResponseAndRedactsCredentials(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusInternalServerError} {
		body := strings.Repeat("x", 8200) + "original-tail"
		body = "Code: 241 private-fixture-key " + body
		original := &commitmentDecisionAnalyticsTrackedBody{Reader: strings.NewReader(body)}
		calls, logs := 0, 0
		request, err := http.NewRequest(http.MethodPost, "http://clickhouse:8123/?query=INSERT%20INTO%20native_metric_samples%20FORMAT%20JSONEachRow", strings.NewReader("unchanged"))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("X-ClickHouse-Key", "private-fixture-key")
		transport := commitmentDecisionAnalyticsTransport{base: commitmentDecisionAnalyticsRoundTrip(func(got *http.Request) (*http.Response, error) {
			calls++
			if got != request {
				t.Fatal("request replaced")
			}
			return &http.Response{StatusCode: status, Header: http.Header{"X-Clickhouse-Exception-Code": {"241"}}, Body: original}, nil
		}), logf: func(format string, args ...any) {
			logs++
			if len(args) != 5 || args[0] != status || args[1] != "241" || args[2] != true || args[3] != false || strings.Contains(args[4].(string), "private-fixture-key") || !strings.Contains(args[4].(string), "[REDACTED]") {
				t.Fatal("private bounded diagnostic or credential redaction differs")
			}
		}}
		response, err := transport.RoundTrip(request)
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(response.Body)
		if err != nil || string(got) != body || calls != 1 || original.closed != 0 {
			t.Fatal("response was consumed or replaced", err)
		}
		if err := response.Body.Close(); err != nil || original.closed != 1 {
			t.Fatal("original response closer was lost")
		}
		if logs != map[bool]int{true: 0, false: 1}[status == http.StatusOK] {
			t.Fatal("success response logged or rejection missing")
		}
	}
}

func TestCommitmentDecisionAnalyticsDiagnosticBoundaries(t *testing.T) {
	const secret = "private-response-boundary-key"
	header := http.Header{"X-Clickhouse-Key": {secret}}
	for _, n := range []int{1, 3, len(secret) - 1, len(secret)} {
		prefix := []byte(strings.Repeat("x", 8193-n) + secret[:n])
		got := commitmentDecisionAnalyticsRedactedPrefix(prefix, header, 8192)
		if len(got) > 8192 || strings.Contains(strings.TrimLeft(got, "x"), secret[:n]) {
			t.Fatal("credential prefix survived response boundary redaction")
		}
	}
	for _, target := range []string{"http://other:8123/?query=INSERT%20INTO%20native_metric_samples%20FORMAT%20JSONEachRow", "http://clickhouse:8123/?query=SELECT%201", "https://clickhouse:8123/?query=INSERT%20INTO%20native_metric_samples%20FORMAT%20JSONEachRow"} {
		request, err := http.NewRequest(http.MethodPost, target, nil)
		if err != nil {
			t.Fatal(err)
		}
		original := &commitmentDecisionAnalyticsTrackedBody{Reader: strings.NewReader("untouched")}
		transport := commitmentDecisionAnalyticsTransport{base: commitmentDecisionAnalyticsRoundTrip(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 500, Body: original}, nil
		}), logf: func(string, ...any) { t.Fatal("unrelated endpoint/query was logged") }}
		response, err := transport.RoundTrip(request)
		if err != nil || response.Body != original {
			t.Fatal("unrelated response was changed")
		}
		body, err := io.ReadAll(response.Body)
		if err != nil || string(body) != "untouched" {
			t.Fatal("unrelated body was consumed")
		}
		response.Body.Close()
		if original.closed != 1 {
			t.Fatal("unrelated closer changed")
		}
	}
}
