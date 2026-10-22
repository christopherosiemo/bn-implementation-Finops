package native

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/telemetry"
)

type ReadBinding struct {
	Binding        telemetry.Binding `json:"binding"`
	Endpoint       string            `json:"endpoint"`
	CredentialFile string            `json:"credential_file,omitempty"`
	AllowedCIDRs   []string          `json:"allowed_cidrs,omitempty"`
	RequiredLabels map[string]string `json:"required_labels"`
}

func BindingsFromEnv(raw string, fixture bool) (map[string]ReadBinding, error) {
	out := map[string]ReadBinding{}
	if strings.TrimSpace(raw) == "" {
		return out, nil
	}
	if len(raw) > 128<<10 {
		return nil, errors.New("TELEMETRY_BINDINGS_LIMIT")
	}
	d := json.NewDecoder(strings.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&out) != nil || len(out) > 64 {
		return nil, errors.New("TELEMETRY_BINDINGS_INVALID")
	}
	if d.Decode(&struct{}{}) != io.EOF {
		return nil, errors.New("TELEMETRY_BINDINGS_INVALID")
	}
	for id, b := range out {
		if id == "" || b.validate(fixture) != nil {
			return nil, errors.New("TELEMETRY_READ_BINDING_INVALID")
		}
	}
	return out, nil
}
func (b ReadBinding) validate(fixture bool) error {
	u, e := url.Parse(b.Endpoint)
	if e != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Scheme != "https" && !(fixture && u.Scheme == "http") || !fixture && u.Port() != "" && u.Port() != "443" {
		return errors.New("TELEMETRY_ENDPOINT_INVALID")
	}
	c := telemetry.Connection{SchemaVersion: "1", ID: "binding-validation", Version: 1, Kind: "PROMETHEUS", ReadBindingID: "binding", Binding: b.Binding, Definitions: []telemetry.Definition{{ID: "d", Version: "1", Metric: "validation", Name: "validation", Type: "GAUGE", Unit: "ratio", CadenceSeconds: 15, MaxGapSeconds: 30}}}
	if telemetry.ValidateConnection(c) != nil || !fixture && (len(b.AllowedCIDRs) == 0 || len(b.RequiredLabels) == 0) {
		return errors.New("TELEMETRY_BINDING_SCOPE_REQUIRED")
	}
	for _, cidr := range b.AllowedCIDRs {
		p, e := netip.ParsePrefix(cidr)
		if e != nil || p.Bits() == 0 || p.Addr().IsUnspecified() {
			return errors.New("TELEMETRY_CIDR_INVALID")
		}
	}
	if ip, e := netip.ParseAddr(u.Hostname()); e == nil && !b.allowed(ip, fixture) {
		return errors.New("TELEMETRY_ENDPOINT_FORBIDDEN")
	}
	return nil
}
func (b ReadBinding) allowed(ip netip.Addr, fixture bool) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	if !fixture && ip.IsLoopback() {
		return false
	}
	if len(b.AllowedCIDRs) == 0 {
		return fixture
	}
	for _, cidr := range b.AllowedCIDRs {
		p, e := netip.ParsePrefix(cidr)
		if e == nil && p.Contains(ip) {
			return true
		}
	}
	return false
}
func (b ReadBinding) connection(c telemetry.Connection) error {
	if c.Binding != b.Binding {
		return errors.New("TELEMETRY_READ_BINDING_MISMATCH")
	}
	for _, d := range c.Definitions {
		for k, v := range b.RequiredLabels {
			if d.Attributes[k] != v {
				return errors.New("TELEMETRY_REQUIRED_LABEL_MISSING")
			}
		}
	}
	return nil
}

type credentialTransport struct {
	base http.RoundTripper
	file string
}

func (t credentialTransport) CloseIdleConnections() {
	if closer, ok := t.base.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

func (t credentialTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	copy := r.Clone(r.Context())
	copy.Header = r.Header.Clone()
	if t.file != "" {
		f, e := os.Open(t.file)
		if e != nil {
			return nil, errors.New("TELEMETRY_CREDENTIAL_UNAVAILABLE")
		}
		raw, e := io.ReadAll(io.LimitReader(f, 8193))
		f.Close()
		token := strings.TrimSpace(string(raw))
		if e != nil || len(raw) > 8192 || token == "" || strings.ContainsAny(token, "\r\n") {
			return nil, errors.New("TELEMETRY_CREDENTIAL_INVALID")
		}
		copy.Header.Set("Authorization", "Bearer "+token)
	}
	return t.base.RoundTrip(copy)
}
func (b ReadBinding) Reader(fixture bool) (telemetry.PromReader, error) {
	if e := b.validate(fixture); e != nil {
		return telemetry.PromReader{}, e
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 20 * time.Second, MaxConnsPerHost: 2, MaxIdleConnsPerHost: 2, IdleConnTimeout: time.Minute}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, e := net.SplitHostPort(address)
		if e != nil {
			return nil, errors.New("TELEMETRY_ENDPOINT_INVALID")
		}
		ips, e := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if e != nil || len(ips) == 0 {
			return nil, errors.New("TELEMETRY_ENDPOINT_DNS_FAILED")
		}
		for _, ip := range ips {
			if !b.allowed(ip, fixture) {
				return nil, errors.New("TELEMETRY_ENDPOINT_FORBIDDEN")
			}
		}
		return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
	}
	client := &http.Client{Transport: credentialTransport{transport, b.CredentialFile}, Timeout: 45 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return telemetry.PromReader{URL: b.Endpoint, Client: client, AllowHTTP: fixture, AllowPrivate: true}, nil
}
