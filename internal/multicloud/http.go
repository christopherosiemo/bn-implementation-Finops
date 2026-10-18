package multicloud

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

func (c Config) request(ctx context.Context, method, address, scope string, body any, headers map[string]string) (Object, Document, error) {
	u, e := url.Parse(address)
	if e != nil || u.Scheme != "https" || u.User != nil || u.Fragment != "" || u.Port() != "" || !(u.Host == "management.azure.com" || u.Host == "bigquery.googleapis.com" || u.Host == "cloudbilling.googleapis.com" || regexp.MustCompile(`^[a-z0-9]{3,24}\.blob\.core\.windows\.net$`).MatchString(u.Host)) {
		return Object{}, nil, errors.New("MULTICLOUD_ENDPOINT_NOT_APPROVED")
	}
	if method != http.MethodGet && !(method == http.MethodPost && u.Host == "bigquery.googleapis.com") {
		return Object{}, nil, errors.New("MULTICLOUD_METHOD_NOT_ALLOWED")
	}
	token, e := c.Tokens.Token(ctx, scope)
	if e != nil || token == "" || strings.ContainsAny(token, "\r\n") {
		return Object{}, nil, errors.New("MULTICLOUD_READ_IDENTITY_UNAVAILABLE")
	}
	var raw []byte
	if body != nil {
		raw, e = json.Marshal(body)
		if e != nil {
			return Object{}, nil, errors.New("MULTICLOUD_REQUEST_INVALID")
		}
	}
	req, e := http.NewRequestWithContext(ctx, method, address, bytes.NewReader(raw))
	if e != nil {
		return Object{}, nil, errors.New("MULTICLOUD_REQUEST_INVALID")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Encoding", "identity")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	client := *c.HTTP
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, e := client.Do(req)
	if e != nil {
		return Object{}, nil, errors.New("MULTICLOUD_READ_UNAVAILABLE")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return Object{}, nil, errors.New("MULTICLOUD_PROVIDER_REJECTED")
	}
	encoding := resp.Header.Get("Content-Encoding")
	blob := strings.HasSuffix(u.Host, ".blob.core.windows.net")
	if encoding != "" && encoding != "identity" && !(blob && strings.EqualFold(encoding, "gzip")) {
		return Object{}, nil, errors.New("MULTICLOUD_WIRE_ENCODING_UNSUPPORTED")
	}
	raw, e = io.ReadAll(io.LimitReader(resp.Body, MaxBodyBytes+1))
	if e != nil || len(raw) > MaxBodyBytes {
		return Object{}, nil, errors.New("MULTICLOUD_RESPONSE_LIMIT")
	}
	o := Object{Resource: address, SHA256: BytesHash(raw), Bytes: int64(len(raw)), Body: raw, ETag: resp.Header.Get("ETag"), Version: resp.Header.Get("x-ms-version-id")}
	o.LastModified, _ = http.ParseTime(resp.Header.Get("Last-Modified"))
	if blob {
		return o, nil, nil
	}
	d, e := decode(raw)
	return o, d, e
}
func decode(raw []byte) (Document, error) {
	var d Document
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&d) != nil || decoder.Decode(new(any)) != io.EOF || d == nil {
		return nil, errors.New("MULTICLOUD_NATIVE_JSON_INVALID")
	}
	return d, nil
}
func obj(v any) Document {
	switch x := v.(type) {
	case Document:
		return x
	case map[string]any:
		return Document(x)
	}
	return Document{}
}
func list(v any) []any                  { x, _ := v.([]any); return x }
func str(d Document, key string) string { x, _ := d[key].(string); return x }
func num(d Document, key string) (int64, bool) {
	n, ok := d[key].(json.Number)
	if !ok {
		return 0, false
	}
	v, e := n.Int64()
	return v, e == nil
}
func boolean(d Document, key string) bool { x, _ := d[key].(bool); return x }
func unique(in []string) []string {
	sort.Strings(in)
	out := []string{}
	for _, x := range in {
		if len(out) == 0 || out[len(out)-1] != x {
			out = append(out, x)
		}
	}
	return out
}

var decimalPattern = regexp.MustCompile(`^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?$`)
var currencyPattern = regexp.MustCompile(`^[A-Z]{3}$`)

func decimal(v any) (string, error) {
	var s string
	switch x := v.(type) {
	case string:
		s = x
	case json.Number:
		s = string(x)
	default:
		return "", errors.New("MULTICLOUD_MONEY_REQUIRED")
	}
	if len(s) > 200 || !decimalPattern.MatchString(s) {
		return "", errors.New("MULTICLOUD_MONEY_INVALID")
	}
	if i := strings.IndexAny(s, "eE"); i >= 0 {
		exponent, e := strconv.Atoi(s[i+1:])
		if e != nil || exponent < -60 || exponent > 60 {
			return "", errors.New("MULTICLOUD_MONEY_EXPONENT_LIMIT")
		}
	}
	n, ok := new(big.Rat).SetString(s)
	if !ok {
		return "", errors.New("MULTICLOUD_MONEY_INVALID")
	}
	return rat(n), nil
}
func rat(n *big.Rat) string {
	den := new(big.Int).Set(n.Denom())
	two, five := 0, 0
	for new(big.Int).Mod(den, big.NewInt(2)).Sign() == 0 {
		den.Div(den, big.NewInt(2))
		two++
	}
	for new(big.Int).Mod(den, big.NewInt(5)).Sign() == 0 {
		den.Div(den, big.NewInt(5))
		five++
	}
	if den.Cmp(big.NewInt(1)) != 0 {
		return ""
	}
	places := two
	if five > places {
		places = five
	}
	s := n.FloatString(places)
	if strings.Contains(s, ".") {
		s = strings.TrimRight(strings.TrimRight(s, "0"), ".")
	}
	if s == "-0" {
		return "0"
	}
	return s
}
func moneyPtr(v any) (*string, error) {
	if v == nil || v == "" {
		return nil, nil
	}
	s, e := decimal(v)
	if e != nil {
		return nil, e
	}
	return &s, nil
}
func addTotal(totals map[string]string, currency string, amount *string) {
	if amount == nil {
		return
	}
	a, _ := new(big.Rat).SetString(*amount)
	b := new(big.Rat)
	if old := totals[currency]; old != "" {
		b.SetString(old)
	}
	totals[currency] = rat(b.Add(b, a))
}
func instant(s string) (time.Time, error) { return time.Parse(time.RFC3339Nano, s) }
func periodValid(p Period, now time.Time) bool {
	return !p.Start.IsZero() && p.End.After(p.Start) && p.End.Sub(p.Start) <= 93*24*time.Hour && !p.End.After(now.Add(5*time.Second))
}
