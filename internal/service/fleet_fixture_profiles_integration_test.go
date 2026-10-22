package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleetfixture"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
)

// Real restricted PG roles and signed JWT/JWKS exercise the public catalog.
// Installed toolchains here are explicit metadata doubles, not native proofs.
func TestFleetFixtureProfilesUseBoundedTenantCursorPages(t *testing.T) {
	f, producer := newFleetFixtureHTTPTest(t)
	ctx := context.Background()
	const count = 103
	ids := make([]string, 0, count)
	hashes := map[string]string{}
	if err := producer.Do(ctx, f.tenant, func(tx *store.Tx) error {
		for range count {
			p, err := tx.FleetFixtureProfileInstall(ctx, fleetfixture.Installation{TemplateID: "builtin-group-fixture-v1", ToolchainImageSHA256: strings.Repeat("a", 64), TerraformVersion: "1.16.0", ReceiptID: "pagination-installation-metadata-double", SourceSHA256: strings.Repeat("b", 64)})
			if err != nil {
				return err
			}
			raw, err := json.Marshal(p)
			if err != nil {
				return err
			}
			ids = append(ids, p.ID)
			hashes[p.ID] = fleetgroup.BytesDigest(raw)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	sort.Strings(ids)
	viewer := f.token(f.tenant, "catalog-viewer", "VIEWER")
	get := func(query, token string) (int, model.Document) {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, "/v1/fleet-fixture-profiles"+query, nil)
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		f.api.ServeHTTP(w, r)
		var out model.Document
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal("catalog response was not JSON", w.Code)
		}
		return w.Code, out
	}
	pageIDs := func(page model.Document) []string {
		t.Helper()
		items, ok := page["items"].([]any)
		if !ok {
			t.Fatal("catalog page did not contain items")
		}
		out := make([]string, 0, len(items))
		for _, item := range items {
			p, ok := item.(map[string]any)
			if !ok {
				t.Fatal("catalog item was not an object")
			}
			id, _ := p["id"].(string)
			if p["hash"] != hashes[id] || hashes[id] == "" {
				t.Fatal("immutable installed profile or hash changed")
			}
			out = append(out, id)
		}
		return out
	}
	if code, _ := get("", ""); code != http.StatusUnauthorized {
		t.Fatal("anonymous catalog read was accepted", code)
	}
	if code, page := get("", viewer); code != http.StatusOK || len(pageIDs(page)) != 50 || model.String(page, "next_cursor") == "" {
		t.Fatal("default catalog page was unbounded or lacked a continuation", code)
	}
	if code, page := get("?limit=100", viewer); code != http.StatusOK || !reflect.DeepEqual(pageIDs(page), ids[:100]) || model.String(page, "next_cursor") == "" {
		t.Fatal("maximum catalog page did not preserve its lookahead", code)
	}
	all := []string{}
	query, firstCursor := "?limit=17", ""
	for pages := 0; ; pages++ {
		if pages >= 7 {
			t.Fatal("catalog pagination did not terminate")
		}
		code, page := get(query, viewer)
		if code != http.StatusOK {
			t.Fatal("catalog page failed", code)
		}
		pageIDs := pageIDs(page)
		if len(pageIDs) > 17 {
			t.Fatal("catalog response exceeded requested limit")
		}
		all = append(all, pageIDs...)
		cursor := model.String(page, "next_cursor")
		if firstCursor == "" {
			firstCursor = cursor
		}
		if cursor == "" {
			if page["next_cursor"] != nil {
				t.Fatal("terminal cursor was not null")
			}
			break
		}
		query = "?limit=17&cursor=" + url.QueryEscape(cursor)
	}
	if !reflect.DeepEqual(all, ids) {
		t.Fatal("catalog traversal omitted, duplicated or reordered installed profiles")
	}
	code, replay := get("?limit=17&cursor="+url.QueryEscape(firstCursor), viewer)
	if code != http.StatusOK || !reflect.DeepEqual(pageIDs(replay), ids[17:34]) {
		t.Fatal("catalog cursor replay changed immutable page membership", code)
	}
	foreign := f.token(f.tenant+"-other", "catalog-viewer", "VIEWER")
	if code, _ := get("?limit=17&cursor="+url.QueryEscape(firstCursor), foreign); code != http.StatusUnprocessableEntity {
		t.Fatal("catalog cursor crossed tenant identity", code)
	}
	if code, page := get("?limit=1", foreign); code != http.StatusOK || !reflect.DeepEqual(pageIDs(page), ids[:1]) {
		t.Fatal("shared immutable catalog became tenant-owned", code)
	}
	raw, err := base64.RawURLEncoding.DecodeString(firstCursor)
	if err != nil {
		t.Fatal(err)
	}
	var cursor map[string]string
	if json.Unmarshal(raw, &cursor) != nil {
		t.Fatal("invalid issued catalog cursor")
	}
	cursor["Kind"] = "fleet-fixture-proposals"
	raw, _ = json.Marshal(cursor)
	for _, query := range []string{"?limit=0", "?limit=101", "?limit=-1", "?limit=bad", "?cursor=not-a-cursor", "?cursor=" + base64.RawURLEncoding.EncodeToString(raw)} {
		if code, _ := get(query, viewer); code != http.StatusUnprocessableEntity {
			t.Fatal("invalid or cross-query cursor was accepted", code)
		}
	}
	for _, limit := range []int{0, 102} {
		err := f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
			_, err := tx.FleetFixtureProfilePage(ctx, "", limit)
			return err
		})
		if !errors.Is(err, fleetfixture.ErrSelection) {
			t.Fatal("store accepted an unbounded profile read", limit, err)
		}
	}
	if err := f.roles["api"].Do(ctx, f.tenant, func(tx *store.Tx) error {
		rows, err := tx.FleetFixtureProfilePage(ctx, "", 101)
		if err == nil && len(rows) != 101 {
			t.Fatal("store did not bound the lookahead before JSON transport")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}
