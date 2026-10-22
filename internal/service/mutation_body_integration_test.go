package service

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
)

type mutationBodyCounter struct {
	reader io.Reader
	read   int64
}

func (b *mutationBodyCounter) Read(p []byte) (int, error) {
	n, err := b.reader.Read(p)
	b.read += int64(n)
	return n, err
}

// Genuine OIDC/JWKS validation and a dedicated restricted API login exercise the
// HTTP boundary. Only the helper's newly owned child PostgreSQL DB is mutated.
func TestMutationBodyLimitRejectsEntireOversizedRequestBeforeReplayOrSQL(t *testing.T) {
	f := newMutationReplayFixture(t)
	bearer := f.token(f.tenant, "body-operator", "PLATFORM_ADMIN")
	const prefix = `{"paused":true}`
	const supportedBodyBytes = 4 * 1024 * 1024
	capBody := prefix + strings.Repeat(" ", supportedBodyBytes-len(prefix))
	request := func(api *API, tenantToken, key, version, raw, framing string) (int, model.Document, int64) {
		t.Helper()
		counter := &mutationBodyCounter{reader: strings.NewReader(raw)}
		r := httptest.NewRequest(http.MethodPost, "/v1/control/pause", nil)
		r.Body = io.NopCloser(counter)
		defer r.Body.Close()
		switch framing {
		case "known":
			r.ContentLength = int64(len(raw))
		case "unknown":
			r.ContentLength = -1
		case "chunked":
			r.ContentLength = -1
			r.TransferEncoding = []string{"chunked"}
		case "misreported":
			r.ContentLength = 1
		default:
			t.Fatal("unknown test framing")
		}
		r.Header.Set("Authorization", "Bearer "+tenantToken)
		r.Header.Set("Idempotency-Key", key)
		r.Header.Set("If-Match", version)
		w := httptest.NewRecorder()
		api.ServeHTTP(w, r)
		out := model.Document{}
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal("body boundary returned non-JSON", w.Code)
		}
		return w.Code, out, counter.read
	}
	status, original, read := request(f.api, bearer, "full-body-original", `"1"`, capBody, "known")
	if status != 200 || read != supportedBodyBytes || model.Number(original, "version") != 2 || !model.Bool(original, "paused") {
		t.Fatal("exactly four MiB of valid JSON was not accepted", status, read, original)
	}
	audit, events := f.counts()
	var idempotency int
	if err := f.roles["api"].Do(context.Background(), f.tenant, func(tx *store.Tx) error {
		return tx.QueryRow(context.Background(), "SELECT count(*) FROM idempotency WHERE tenant_id=$1", f.tenant).Scan(&idempotency)
	}); err != nil {
		t.Fatal(err)
	}
	for _, framing := range []string{"known", "unknown", "chunked", "misreported"} {
		for _, test := range []struct{ name, body, key string }{
			{"one-extra-space-cached-prefix", capBody + " ", "full-body-original"},
			{"hidden-json-cached-prefix", capBody + `{"paused":false}`, "full-body-original"},
			{"hidden-invalid-suffix-fresh-key", capBody + `]invalid`, "full-body-rejected"},
			{"long-input-bounded", capBody + strings.Repeat(" ", supportedBodyBytes) + `unread`, "full-body-bounded"},
		} {
			t.Run(framing+"/"+test.name, func(t *testing.T) {
				status, out, read := request(f.api, bearer, test.key, `"1"`, test.body, framing)
				if status != 413 || model.String(out, "error") != "BODY_TOO_LARGE" || model.String(out, "message") != "request body exceeds 4 MiB" {
					t.Fatal("oversized full request borrowed a valid prefix or cached reply", status, out)
				}
				if read != supportedBodyBytes+1 {
					t.Fatal("oversized reader did not stop after one look-ahead byte", read)
				}
			})
		}
	}
	// An oversized request must stop before even touching the Store, including
	// seeding. The same real signed token is validated by the real JWKS verifier.
	withoutSQL := *f.api
	withoutSQL.Store = nil
	newTenant := f.tenant + "-unseeded"
	if code, out, read := request(&withoutSQL, f.token(newTenant, "body-operator", "PLATFORM_ADMIN"), "unseeded-oversize", `"1"`, capBody+" ", "chunked"); code != 413 || read != supportedBodyBytes+1 || model.String(out, "error") != "BODY_TOO_LARGE" {
		t.Fatal("oversized body reached SQL before rejection", code, out, read)
	}
	if err := f.roles["api"].Do(context.Background(), newTenant, func(tx *store.Tx) error {
		var entities, requests int
		if err := tx.QueryRow(context.Background(), "SELECT (SELECT count(*) FROM entities WHERE tenant_id=$1),(SELECT count(*) FROM idempotency WHERE tenant_id=$1)", newTenant).Scan(&entities, &requests); err != nil {
			return err
		}
		if entities != 0 || requests != 0 {
			return fmt.Errorf("oversized request seeded %d entities and %d keys", entities, requests)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.roles["api"].Do(context.Background(), f.tenant, func(tx *store.Tx) error {
		var requests int
		if err := tx.QueryRow(context.Background(), "SELECT count(*) FROM idempotency WHERE tenant_id=$1", f.tenant).Scan(&requests); err != nil {
			return err
		}
		org, err := tx.Get(context.Background(), "org", f.tenant)
		if err != nil {
			return err
		}
		if requests != idempotency || model.Number(org, "version") != 2 || !model.Bool(org, "paused") {
			return fmt.Errorf("oversized body changed idempotency or control state")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if gotAudit, gotEvents := f.counts(); gotAudit != audit || gotEvents != events {
		t.Fatal("oversized input appended audit or outbox records")
	}
	// Rejection never poisons either the original replay or a previously unused
	// key. A complete boundary-sized request still reconciles normally.
	for _, framing := range []string{"known", "unknown", "chunked"} {
		if code, out, read := request(f.api, bearer, "full-body-original", `"1"`, capBody, framing); code != 200 || read != supportedBodyBytes || model.Number(out, "version") != 2 {
			t.Fatal("exact-cap replay lost original full-body identity", code, out, read)
		}
	}
	if code, out, _ := request(f.api, bearer, "full-body-rejected", `"2"`, `{"paused":false}`, "unknown"); code != 200 || model.Number(out, "version") != 3 || model.Bool(out, "paused") {
		t.Fatal("oversized input reserved or poisoned an uncommitted key", code, out)
	}
}
