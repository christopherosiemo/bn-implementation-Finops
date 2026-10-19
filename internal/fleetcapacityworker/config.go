// Package fleetcapacityworker runs a commissioned, resumable analytical queue.
// It has no discovery, signing, artifact-write or execution interface.
package fleetcapacityworker

import (
	"context"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	archive "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetassessmentworker"
)

var ErrConfiguration = errors.New("FLEET_CAPACITY_CONFIGURATION_INVALID")
var ErrJob = errors.New("FLEET_CAPACITY_JOB_REFUSED")
var ErrBusy = errors.New("FLEET_CAPACITY_JOB_BUSY")
var identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$`)

const PrivateServices = "PRIVATE_SERVICES"

type Config struct {
	Archive                                                           archive.Config
	ServiceMode, ReaderURL, ReaderTokenFile, ModelURL, ModelTokenFile string
}

func ConfigFromEnvironment(get func(string) string) (Config, error) {
	c := Config{Archive: archive.Config{Enabled: get("FLEET_CAPACITY_ENABLED") == "true", TenantID: get("FLEET_CAPACITY_TENANT_ID"), DatabaseFile: get("FLEET_CAPACITY_DATABASE_FILE"), ArchiveMode: get("FLEET_CAPACITY_ARCHIVE_MODE"), ArchiveRegion: get("FLEET_CAPACITY_ARCHIVE_REGION"), ArchiveEndpoint: get("FLEET_CAPACITY_ARCHIVE_ENDPOINT"), ArchiveBucket: get("FLEET_CAPACITY_ARCHIVE_BUCKET"), ArchiveBucketOwner: get("FLEET_CAPACITY_ARCHIVE_BUCKET_OWNER"), ArchiveAccessKeyFile: get("FLEET_CAPACITY_ARCHIVE_ACCESS_KEY_FILE"), ArchiveSecretKeyFile: get("FLEET_CAPACITY_ARCHIVE_SECRET_KEY_FILE"), RoleARN: get("AWS_ROLE_ARN"), WebIdentityTokenFile: get("AWS_WEB_IDENTITY_TOKEN_FILE")}, ServiceMode: get("FLEET_CAPACITY_SERVICE_MODE"), ReaderURL: get("FLEET_CAPACITY_READER_URL"), ReaderTokenFile: get("FLEET_CAPACITY_READER_TOKEN_FILE"), ModelURL: get("FLEET_CAPACITY_MODEL_URL"), ModelTokenFile: get("FLEET_CAPACITY_MODEL_TOKEN_FILE")}
	return c, c.Validate()
}
func privateName(h string) bool {
	if ip := net.ParseIP(h); ip != nil {
		return privateIP(ip)
	}
	return regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}(?:\.[a-z0-9-]{1,63})*$`).MatchString(h)
}
func privateIP(ip net.IP) bool {
	v := ip.To4()
	return ip.IsLoopback() || v != nil && (v[0] == 10 || v[0] == 172 && v[1] >= 16 && v[1] <= 31 || v[0] == 192 && v[1] == 168)
}
func serviceURL(raw string) (*url.URL, error) {
	u, e := url.Parse(raw)
	if e != nil || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || !privateName(u.Hostname()) || u.Port() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.Scheme == "https" && u.Port() != "443" {
		return nil, ErrConfiguration
	}
	return u, nil
}
func (c Config) Validate() error {
	if c.Archive.Validate() != nil || c.ServiceMode != PrivateServices {
		return ErrConfiguration
	}
	if _, e := serviceURL(c.ReaderURL); e != nil {
		return e
	}
	if _, e := serviceURL(c.ModelURL); e != nil {
		return e
	}
	seen := map[string]bool{}
	for _, p := range []string{c.Archive.DatabaseFile, c.ReaderTokenFile, c.ModelTokenFile, c.Archive.ArchiveAccessKeyFile, c.Archive.ArchiveSecretKeyFile, c.Archive.WebIdentityTokenFile} {
		if p == "" {
			continue
		}
		if !filepath.IsAbs(p) || filepath.Clean(p) != p || seen[p] {
			return ErrConfiguration
		}
		seen[p] = true
	}
	if c.ReaderTokenFile == "" || c.ModelTokenFile == "" {
		return ErrConfiguration
	}
	return nil
}
func privateFile(path string, max int64) ([]byte, error) {
	resolved, e := filepath.EvalSymlinks(path)
	if e != nil || resolved != filepath.Clean(path) {
		return nil, ErrConfiguration
	}
	s, e := os.Lstat(path)
	if e != nil || !s.Mode().IsRegular() || s.Mode().Perm()&0133 != 0 || s.Size() < 1 || s.Size() > max {
		return nil, ErrConfiguration
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, ErrConfiguration
	}
	defer f.Close()
	opened, e := f.Stat()
	if e != nil || !os.SameFile(s, opened) {
		return nil, ErrConfiguration
	}
	raw, e := io.ReadAll(io.LimitReader(f, max+1))
	if e != nil || int64(len(raw)) != s.Size() {
		return nil, ErrConfiguration
	}
	return raw, nil
}
func privateHost(ctx context.Context, host string) (string, error) {
	ips, e := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if e != nil || len(ips) == 0 {
		return "", ErrConfiguration
	}
	for _, ip := range ips {
		if !privateIP(ip) {
			return "", ErrConfiguration
		}
	}
	return ips[0].String(), nil
}
func databaseURL(ctx context.Context, raw []byte, hosted bool) (string, error) {
	u, e := url.Parse(strings.TrimSpace(string(raw)))
	if e != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || !privateName(u.Hostname()) || u.User == nil || u.User.Username() == "" || u.Path == "" || u.Path == "/" || u.Fragment != "" {
		return "", ErrConfiguration
	}
	password, ok := u.User.Password()
	if !ok || password == "" {
		return "", ErrConfiguration
	}
	q, e := url.ParseQuery(u.RawQuery)
	if e != nil {
		return "", ErrConfiguration
	}
	for k, v := range q {
		if len(v) != 1 || (k != "sslmode" && k != "sslrootcert") {
			return "", ErrConfiguration
		}
	}
	if q.Get("sslmode") != "disable" && q.Get("sslmode") != "verify-full" {
		return "", ErrConfiguration
	}
	if hosted {
		ca := q.Get("sslrootcert")
		if q.Get("sslmode") != "verify-full" || len(ca) > 512 || !filepath.IsAbs(ca) || filepath.Clean(ca) != ca || !strings.HasPrefix(ca, "/etc/finops/rds/") {
			return "", ErrConfiguration
		}
	}
	ip, e := privateHost(ctx, u.Hostname())
	if e != nil {
		return "", e
	}
	port := u.Port()
	if port == "" {
		port = "5432"
	}
	if q.Get("sslmode") == "disable" {
		u.Host = net.JoinHostPort(ip, port)
	}
	q.Set("pool_max_conns", "3")
	u.RawQuery = q.Encode()
	return u.String(), nil
}
