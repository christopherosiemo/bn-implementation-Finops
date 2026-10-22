package commitmentportfolio

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

func modelServiceURL(raw, mode string) (*url.URL, error) {
	u, e := url.Parse(raw)
	if e != nil || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || u.Hostname() == "" {
		return nil, ErrConfiguration
	}
	switch mode {
	case "LOCAL_PRIVATE":
		if u.Scheme != "http" || u.Port() != "8000" || u.Hostname() != "commitment-portfolio-model" && net.ParseIP(u.Hostname()) == nil {
			return nil, ErrConfiguration
		}
	case "HOSTED_TLS":
		if u.Scheme != "https" || u.Port() != "443" || net.ParseIP(u.Hostname()) != nil || !hostPattern.MatchString(u.Hostname()) || !strings.Contains(u.Hostname(), ".") {
			return nil, ErrConfiguration
		}
	default:
		return nil, ErrConfiguration
	}
	return u, nil
}
func readModelToken(path string) ([]byte, error) {
	raw, e := readDatabaseFile(path)
	if e != nil {
		return nil, ErrConfiguration
	}
	token := []byte(strings.TrimSpace(string(raw)))
	clear(raw)
	if len(token) < 32 || len(token) > 4096 {
		return nil, ErrConfiguration
	}
	for _, c := range token {
		if c < 33 || c > 126 {
			return nil, ErrConfiguration
		}
	}
	return token, nil
}
func newHTTPCalculator(ctx context.Context, endpoint, mode, token string, lookup lookupIP) (*HTTPCalculator, error) {
	u, e := modelServiceURL(endpoint, mode)
	if e != nil || len(token) < 32 || len(token) > 4096 || lookup == nil {
		return nil, ErrConfiguration
	}
	for _, c := range []byte(token) {
		if c < 33 || c > 126 {
			return nil, ErrConfiguration
		}
	}
	addresses, e := lookup(ctx, u.Hostname())
	if e != nil || len(addresses) == 0 || len(addresses) > 16 {
		return nil, ErrConfiguration
	}
	for _, a := range addresses {
		if a.Zone != "" || a.IP == nil || !a.IP.IsPrivate() && (mode != "LOCAL_PRIVATE" || !a.IP.IsLoopback()) {
			return nil, ErrConfiguration
		}
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname()}
	if mode == "HOSTED_TLS" {
		roots, e := modelCertificateRoots()
		if e != nil {
			return nil, e
		}
		tlsConfig.RootCAs = roots
	}
	pinned := net.JoinHostPort(addresses[0].IP.String(), u.Port())
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	transport := &http.Transport{Proxy: nil, MaxIdleConns: 2, MaxIdleConnsPerHost: 2, IdleConnTimeout: 30 * time.Second, ResponseHeaderTimeout: 30 * time.Second, TLSClientConfig: tlsConfig, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != u.Host {
			return nil, ErrConfiguration
		}
		return dialer.DialContext(ctx, network, pinned)
	}}
	client := &http.Client{Transport: transport, Timeout: 35 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &HTTPCalculator{Client: client, Endpoint: u.String(), Token: token}, nil
}

// NewHTTPCalculator is the private worker/acceptance dependency constructor.
// Endpoint and token come from commissioned files/process configuration, never
// a public selection request. It retains DNS pinning and the fixed v5 route.
func NewHTTPCalculator(ctx context.Context, endpoint, mode, token string) (*HTTPCalculator, error) {
	return newHTTPCalculator(ctx, endpoint, mode, token, net.DefaultResolver.LookupIPAddr)
}

func modelCertificateRoots() (*x509.CertPool, error) {
	const path = "/run/ca/commitment-portfolio-model-root.crt"
	before, e := os.Lstat(path)
	if e != nil || !before.Mode().IsRegular() || before.Mode().Perm()&0133 != 0 || before.Size() < 1 || before.Size() > 64<<10 {
		return nil, ErrConfiguration
	}
	file, e := os.Open(path)
	if e != nil {
		return nil, ErrConfiguration
	}
	defer file.Close()
	actual, e := file.Stat()
	if e != nil || !os.SameFile(before, actual) {
		return nil, ErrConfiguration
	}
	raw, e := io.ReadAll(io.LimitReader(file, (64<<10)+1))
	if e != nil || int64(len(raw)) != before.Size() {
		return nil, ErrConfiguration
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(raw) {
		return nil, ErrConfiguration
	}
	return pool, nil
}
