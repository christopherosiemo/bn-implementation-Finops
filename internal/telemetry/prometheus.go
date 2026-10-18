package telemetry

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// PromReader is constructed only from a server-managed endpoint/credential
// binding. A caller cannot put an arbitrary URL or headers in a Connection.
// Client may supply an approved DNS-pinned transport. Redirects are disabled
// even when the injected client would normally follow them.
type PromReader struct {
	URL          string
	Client       *http.Client
	Headers      http.Header
	Now          func() time.Time
	AllowHTTP    bool
	AllowPrivate bool
}

func mergeLabels(maps ...map[string]string) map[string]string {
	m := map[string]string{}
	for _, a := range maps {
		for k, v := range a {
			m[k] = v
		}
	}
	return m
}
func forbiddenIP(ip netip.Addr, allowPrivate bool) bool {
	ip = ip.Unmap()
	// Metadata, multicast and unspecified destinations are never source bindings.
	if !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	return !allowPrivate && (ip.IsPrivate() || ip.IsLoopback())
}
func (p PromReader) endpoint() (*url.URL, error) {
	u, e := url.Parse(p.URL)
	if e != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "https" && !(p.AllowHTTP && u.Scheme == "http")) {
		return nil, errors.New("TELEMETRY_ENDPOINT_INVALID")
	}
	if ip, e := netip.ParseAddr(u.Hostname()); e == nil && forbiddenIP(ip, p.AllowPrivate) {
		return nil, errors.New("TELEMETRY_ENDPOINT_FORBIDDEN")
	}
	return u, nil
}
func (p PromReader) client() *http.Client {
	var c http.Client
	if p.Client != nil {
		c = *p.Client
	} else {
		dialer := &net.Dialer{Timeout: 10 * time.Second}
		transport := &http.Transport{TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 20 * time.Second}
		transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, e := net.SplitHostPort(address)
			if e != nil {
				return nil, e
			}
			ips, e := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
			if e != nil || len(ips) == 0 {
				return nil, errors.New("TELEMETRY_ENDPOINT_DNS_FAILED")
			}
			for _, ip := range ips {
				if forbiddenIP(ip, p.AllowPrivate) {
					return nil, errors.New("TELEMETRY_ENDPOINT_FORBIDDEN")
				}
			}
			// Dial the validated address itself, avoiding DNS rebinding between check and connect.
			return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
		}
		c.Transport = transport
	}
	if c.Timeout == 0 || c.Timeout > 45*time.Second {
		c.Timeout = 45 * time.Second
	}
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &c
}

type promEnvelope struct {
	Status   string          `json:"status"`
	Data     json.RawMessage `json:"data"`
	Warnings []string        `json:"warnings"`
	Infos    []string        `json:"infos"`
}
type promMatrix struct {
	ResultType string       `json:"resultType"`
	Result     []promSeries `json:"result"`
}
type promSeries struct {
	Metric     map[string]string   `json:"metric"`
	Values     [][]json.RawMessage `json:"values"`
	Histograms []json.RawMessage   `json:"histograms"`
}
type promPoint struct {
	at     time.Time
	value  string
	labels map[string]string
}

func selector(name string, attrs map[string]string) string {
	keys := make([]string, 0, len(attrs))
	for k := range attrs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := []string{}
	for _, k := range keys {
		parts = append(parts, k+"="+strconv.Quote(attrs[k]))
	}
	if len(parts) == 0 {
		return name
	}
	return name + "{" + strings.Join(parts, ",") + "}"
}
func frame(raw *bytes.Buffer, name string, body []byte) {
	_ = binary.Write(raw, binary.BigEndian, uint32(len(name)))
	raw.WriteString(name)
	_ = binary.Write(raw, binary.BigEndian, uint64(len(body)))
	raw.Write(body)
}
func (p PromReader) request(ctx context.Context, client *http.Client, base *url.URL, path string, form url.Values, raw *bytes.Buffer) (promEnvelope, error) {
	u := *base
	u.Path = strings.TrimRight(base.Path, "/") + path
	method := http.MethodPost
	var bodyReader io.Reader = strings.NewReader(form.Encode())
	if path == "/api/v1/metadata" {
		method = http.MethodGet
		u.RawQuery = form.Encode()
		bodyReader = nil
	}
	req, e := http.NewRequestWithContext(ctx, method, u.String(), bodyReader)
	if e != nil {
		return promEnvelope{}, errors.New("TELEMETRY_REQUEST_INVALID")
	}
	req.Header = p.Headers.Clone()
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Encoding", "identity")
	res, e := client.Do(req)
	if e != nil {
		return promEnvelope{}, errors.New("TELEMETRY_SOURCE_UNAVAILABLE")
	}
	defer res.Body.Close()
	if coding := res.Header.Get("Content-Encoding"); coding != "" && coding != "identity" {
		return promEnvelope{}, errors.New("TELEMETRY_RESPONSE_ENCODING_UNSUPPORTED")
	}
	body, e := io.ReadAll(io.LimitReader(res.Body, int64(MaxBodyBytes-raw.Len()+1)))
	if e != nil {
		return promEnvelope{}, errors.New("TELEMETRY_RESPONSE_UNREADABLE")
	}
	if raw.Len()+len(body) > MaxBodyBytes {
		return promEnvelope{}, errors.New("TELEMETRY_BODY_LIMIT")
	}
	frame(raw, path+"?"+form.Encode(), body)
	if raw.Len() > MaxBodyBytes {
		return promEnvelope{}, errors.New("TELEMETRY_BODY_LIMIT")
	}
	if res.StatusCode != http.StatusOK {
		return promEnvelope{}, errors.New("TELEMETRY_SOURCE_HTTP_REJECTED")
	}
	var env promEnvelope
	if json.Unmarshal(body, &env) != nil || env.Status != "success" {
		return env, errors.New("TELEMETRY_SOURCE_RESPONSE_INVALID")
	}
	return env, nil
}
func promTime(raw json.RawMessage) (time.Time, error) {
	r, ok := number(string(raw))
	if !ok {
		return time.Time{}, errors.New("TELEMETRY_TIMESTAMP_INVALID")
	}
	n := new(big.Rat).Mul(r, big.NewRat(1e9, 1))
	if !n.IsInt() || !n.Num().IsInt64() {
		return time.Time{}, errors.New("TELEMETRY_TIMESTAMP_INVALID")
	}
	return time.Unix(0, n.Num().Int64()).UTC(), nil
}
func promInteger(s string) (uint64, bool) {
	r, ok := number(s)
	if !ok || !r.IsInt() || r.Sign() < 0 || !r.Num().IsUint64() {
		return 0, false
	}
	n := r.Num().Uint64()
	// Prometheus transports IEEE754 values; larger counters cannot prove exact counts.
	return n, n <= 9007199254740991
}
func (p PromReader) query(ctx context.Context, client *http.Client, base *url.URL, name string, attrs map[string]string, start, end time.Time, raw *bytes.Buffer) ([]promPoint, []string, error) {
	duration := int64(end.Sub(start)/time.Second) + 1
	q := selector(name, attrs) + "[" + strconv.FormatInt(duration, 10) + "s]"
	env, e := p.request(ctx, client, base, "/api/v1/query", url.Values{"query": {q}, "time": {end.UTC().Format(time.RFC3339Nano)}}, raw)
	if e != nil {
		return nil, nil, e
	}
	var matrix promMatrix
	if json.Unmarshal(env.Data, &matrix) != nil || matrix.ResultType != "matrix" {
		return nil, nil, errors.New("TELEMETRY_RAW_MATRIX_REQUIRED")
	}
	out := []promPoint{}
	warnings := append(append([]string{}, env.Warnings...), env.Infos...)
	for _, series := range matrix.Result {
		if series.Metric["__name__"] != name || !matches(series.Metric, attrs) {
			return nil, nil, errors.New("TELEMETRY_STREAM_BINDING_MISMATCH")
		}
		if len(series.Histograms) > 0 {
			return nil, nil, errors.New("TELEMETRY_PROM_NATIVE_HISTOGRAM_UNSUPPORTED")
		}
		labels := mergeLabels(series.Metric)
		delete(labels, "__name__")
		for _, v := range series.Values {
			if len(v) != 2 {
				return nil, nil, errors.New("TELEMETRY_POINT_INVALID")
			}
			at, e := promTime(v[0])
			if e != nil {
				return nil, nil, e
			}
			var s string
			if json.Unmarshal(v[1], &s) != nil {
				return nil, nil, errors.New("TELEMETRY_VALUE_INVALID")
			}
			if _, ok := number(s); !ok {
				return nil, nil, errors.New("TELEMETRY_NONFINITE_VALUE")
			}
			if at.Before(start) || at.After(end) {
				return nil, nil, errors.New("TELEMETRY_TIMESTAMP_OUT_OF_RANGE")
			}
			out = append(out, promPoint{at, s, labels})
			if len(out) > MaxSamples {
				return nil, nil, errors.New("TELEMETRY_SAMPLE_LIMIT")
			}
		}
	}
	return out, warnings, nil
}
func (p PromReader) metadata(ctx context.Context, client *http.Client, base *url.URL, d Definition, raw *bytes.Buffer) error {
	// OpenMetrics counter metadata is keyed by family, while samples carry
	// the mandated _total suffix. This is a protocol rule, not fuzzy matching.
	family := d.Name
	if d.Type == "SUM" {
		family = strings.TrimSuffix(family, "_total")
	}
	env, e := p.request(ctx, client, base, "/api/v1/metadata", url.Values{"metric": {family}}, raw)
	if e != nil {
		return e
	}
	if len(env.Warnings)+len(env.Infos) > 0 {
		return errors.New("TELEMETRY_METADATA_WARNING")
	}
	var meta map[string][]struct {
		Type string `json:"type"`
		Unit string `json:"unit"`
	}
	if json.Unmarshal(env.Data, &meta) != nil || len(meta[family]) == 0 {
		return errors.New("TELEMETRY_METADATA_REQUIRED")
	}
	want := map[string]string{"GAUGE": "gauge", "SUM": "counter", "HISTOGRAM": "histogram"}[d.Type]
	for _, m := range meta[family] {
		if m.Type != want || m.Unit != d.Unit {
			return errors.New("TELEMETRY_METADATA_MISMATCH")
		}
	}
	return nil
}
func epochFor(points []promPoint, s promPoint, required map[string]string) (string, bool) {
	values := []string{}
	for _, p := range points {
		if !p.at.Equal(s.at) || !matches(p.labels, required) {
			continue
		}
		compatible := true
		for k, v := range p.labels {
			if w, ok := s.labels[k]; ok && w != v {
				compatible = false
				break
			}
		}
		if compatible {
			r, ok := number(p.value)
			if !ok || r.Sign() <= 0 || r.Cmp(big.NewRat(s.at.UnixNano(), 1e9)) > 0 {
				return "", false
			}
			values = append(values, p.value)
		}
	}
	if len(values) != 1 {
		return "", false
	}
	return values[0], true
}
func promSample(d Definition, p promPoint) Sample {
	a := mergeLabels(p.labels)
	delete(a, "le")
	s := Sample{DefinitionID: d.ID, Metric: d.Metric, Type: d.Type, Unit: d.Unit, Statistic: "SAMPLED_VALUE", Temporality: "INSTANT", Time: p.at, Attributes: a, ResourceAttributes: map[string]string{}, ScopeAttributes: map[string]string{}, OriginalAttributes: nil, Value: p.value, ReasonCodes: []string{}}
	s.StreamID = streamID(d, a, s.ResourceAttributes, s.ScopeAttributes, nil)
	return s
}

func (p PromReader) Read(ctx context.Context, c Connection, start, end time.Time) (Batch, error) {
	if e := ValidateConnection(c); e != nil {
		return Batch{}, e
	}
	if c.Kind != "PROMETHEUS" || !c.Enabled {
		return Batch{}, errors.New("TELEMETRY_CONNECTION_INACTIVE")
	}
	now := time.Now().UTC()
	if p.Now != nil {
		now = p.Now().UTC()
	}
	if start.IsZero() || !end.After(start) || end.Sub(start) > 92*24*time.Hour || end.After(now.Add(5*time.Second)) {
		return Batch{}, errors.New("TELEMETRY_RANGE_INVALID")
	}
	base, e := p.endpoint()
	if e != nil {
		return Batch{}, e
	}
	client := p.client()
	raw := &bytes.Buffer{}
	b := newBatch(c, nil, now)
	for _, d := range c.Definitions {
		if e = p.metadata(ctx, client, base, d, raw); e != nil {
			return Batch{}, e
		}
		queryStart := start.Add(-time.Duration(d.MaxGapSeconds) * time.Second)
		epochs := []promPoint{}
		epochAttrs := d.EpochAttributes
		if epochAttrs == nil {
			epochAttrs = d.Attributes
		}
		if d.Type != "GAUGE" {
			var warnings []string
			epochs, warnings, e = p.query(ctx, client, base, d.EpochMetric, epochAttrs, queryStart, end, raw)
			if e != nil {
				return Batch{}, e
			}
			b.Warnings = append(b.Warnings, warnings...)
		}
		name := d.Name
		if d.Type == "HISTOGRAM" {
			name += "_bucket"
		}
		points, warnings, e := p.query(ctx, client, base, name, d.Attributes, queryStart, end, raw)
		if e != nil {
			return Batch{}, e
		}
		b.Warnings = append(b.Warnings, warnings...)
		if d.Type == "HISTOGRAM" {
			counts, w, e := p.query(ctx, client, base, d.Name+"_count", d.Attributes, queryStart, end, raw)
			if e != nil {
				return Batch{}, e
			}
			b.Warnings = append(b.Warnings, w...)
			groups := map[string][]promPoint{}
			for _, x := range points {
				a := mergeLabels(x.labels)
				delete(a, "le")
				key := Hash(a) + x.at.Format(time.RFC3339Nano)
				groups[key] = append(groups[key], x)
			}
			keys := []string{}
			for k := range groups {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				group := groups[k]
				first := group[0]
				s := promSample(d, first)
				s.Value = ""
				s.Statistic = "EXPLICIT_BUCKET_POPULATION"
				s.Temporality = "CUMULATIVE"
				epoch, ok := epochFor(epochs, first, epochAttrs)
				if !ok {
					reject(&b, d, 1, "TELEMETRY_EPOCH_UNPROVEN")
					continue
				}
				s.Epoch = epoch
				h, ok := classicHistogram(group, counts)
				if !ok {
					reject(&b, d, 1, "TELEMETRY_HISTOGRAM_INCOMPLETE")
					continue
				}
				s.Histogram = h
				b.Samples = append(b.Samples, s)
			}
		} else {
			for _, x := range points {
				s := promSample(d, x)
				if d.Type == "SUM" {
					if _, ok := promInteger(x.value); !ok {
						reject(&b, d, 1, "TELEMETRY_COUNTER_NOT_EXACT")
						continue
					}
					epoch, ok := epochFor(epochs, x, epochAttrs)
					if !ok {
						reject(&b, d, 1, "TELEMETRY_EPOCH_UNPROVEN")
						continue
					}
					s.Epoch = epoch
					s.Temporality = "CUMULATIVE"
					s.Statistic = "MONOTONIC_COUNTER"
				}
				b.Samples = append(b.Samples, s)
			}
		}
		if len(b.Samples) > MaxSamples {
			return Batch{}, errors.New("TELEMETRY_SAMPLE_LIMIT")
		}
	}
	b.Raw = append([]byte{}, raw.Bytes()...)
	b.RawSHA256 = BytesHash(b.Raw)
	b.Warnings = unique(b.Warnings)
	finish(&b)
	return b, nil
}
func classicHistogram(points, counts []promPoint) (*Histogram, bool) {
	first := points[0]
	attrs := mergeLabels(first.labels)
	delete(attrs, "le")
	var expected uint64
	found := 0
	for _, p := range counts {
		if p.at.Equal(first.at) && Hash(p.labels) == Hash(attrs) {
			n, ok := promInteger(p.value)
			if !ok {
				return nil, false
			}
			expected = n
			found++
		}
	}
	if found != 1 {
		return nil, false
	}
	finite := map[string]uint64{}
	var inf uint64
	infCount := 0
	for _, p := range points {
		le, ok := p.labels["le"]
		if !ok {
			return nil, false
		}
		n, ok := promInteger(p.value)
		if !ok {
			return nil, false
		}
		if le == "+Inf" {
			inf = n
			infCount++
			continue
		}
		r, ok := number(le)
		if !ok || r.Sign() < 0 {
			return nil, false
		}
		key := r.RatString()
		if _, ok := finite[key]; ok {
			return nil, false
		}
		finite[key] = n
	}
	if infCount != 1 || inf != expected {
		return nil, false
	}
	keys := []string{}
	for k := range finite {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, _ := new(big.Rat).SetString(keys[i])
		b, _ := new(big.Rat).SetString(keys[j])
		return a.Cmp(b) < 0
	})
	h := &Histogram{Count: expected, Bounds: []string{}, BucketCounts: []uint64{}}
	last := uint64(0)
	for _, k := range keys {
		n := finite[k]
		if n < last || n > expected {
			return nil, false
		}
		r, _ := new(big.Rat).SetString(k)
		h.Bounds = append(h.Bounds, ratDecimal(r))
		h.BucketCounts = append(h.BucketCounts, n-last)
		last = n
	}
	h.BucketCounts = append(h.BucketCounts, inf-last)
	return h, validHistogram(h)
}
func ratDecimal(r *big.Rat) string {
	// Canonical finite decimal inputs remain exact; repeating rates disclose 18 digits.
	if r.IsInt() {
		return r.Num().String()
	}
	den := new(big.Int).Set(r.Denom())
	two, five := 0, 0
	for new(big.Int).Mod(den, big.NewInt(2)).Sign() == 0 {
		den.Quo(den, big.NewInt(2))
		two++
	}
	for new(big.Int).Mod(den, big.NewInt(5)).Sign() == 0 {
		den.Quo(den, big.NewInt(5))
		five++
	}
	digits := 18
	if den.Cmp(big.NewInt(1)) == 0 {
		digits = two
		if five > digits {
			digits = five
		}
	}
	s := r.FloatString(digits)
	s = strings.TrimRight(strings.TrimRight(s, "0"), ".")
	if s == "-0" {
		return "0"
	}
	return s
}
