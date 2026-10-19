package provider

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type archiveCountReader struct {
	remaining int
	read      int
}

func (r *archiveCountReader) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		return 0, io.EOF
	}
	n := len(p)
	if n > r.remaining {
		n = r.remaining
	}
	for i := 0; i < n; i++ {
		p[i] = 'x'
	}
	r.remaining -= n
	r.read += n
	return n, nil
}

func TestDecisionOwnershipNativeS3BoundedRead(t *testing.T) {
	for _, declared := range []bool{true, false} {
		t.Run(map[bool]string{true: "declared-too-large", false: "stream-too-large"}[declared], func(t *testing.T) {
			body := &archiveCountReader{remaining: 128 << 10}
			a := billingTestAWS(func(r *http.Request) (*http.Response, error) {
				if r.Header.Get("X-Amz-Expected-Bucket-Owner") != "111122223333" || r.URL.Query().Get("versionId") != "original-version" {
					t.Fatal("archive native read lost owner/version")
				}
				o := billingResponse("")
				o.Body = io.NopCloser(body)
				o.Header.Set("X-Amz-Version-Id", "original-version")
				o.Header.Set("Last-Modified", "Thu, 01 Oct 2026 00:00:00 GMT")
				if declared {
					o.Header.Set("Content-Length", "131072")
					o.ContentLength = 131072
				}
				return o, nil
			})
			if _, err := a.BillingObjectBounded(context.Background(), "archive-bucket", "tenant/test/hour.json", "original-version", 64<<10); err == nil {
				t.Fatal("oversized archive accepted")
			}
			if declared && body.read != 0 {
				t.Fatal("declared oversize was materialized")
			}
			if body.read > (64<<10)+1 {
				t.Fatal("archive transport read exceeded bound")
			}
		})
	}
	a := billingTestAWS(func(r *http.Request) (*http.Response, error) {
		o := billingResponse("exact original bytes")
		o.Header.Set("X-Amz-Version-Id", "original-version")
		o.Header.Set("Last-Modified", "Thu, 01 Oct 2026 00:00:00 GMT")
		return o, nil
	})
	got, err := a.BillingObjectBounded(context.Background(), "archive-bucket", "tenant/test/hour.json", "original-version", 64<<10)
	if err != nil || strings.TrimSpace(string(got.Data)) != "exact original bytes" {
		t.Fatal("bounded original archive unavailable", err)
	}
}
