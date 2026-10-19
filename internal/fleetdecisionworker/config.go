package fleetdecisionworker

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
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
)

var ErrConfiguration = errors.New("FLEET_DECISION_CONFIGURATION_REFUSED")
var tenantPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
var namePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,62}$`)
var hostPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,251}[a-z0-9]$`)

const databaseFile = "/run/secrets/group-decision-database"

type Config struct {
	Enabled                              bool
	TenantID, DatabaseFile, DatabaseMode string
}

func ReadConfig() (Config, error) {
	c := Config{}
	switch os.Getenv("FLEET_DECISION_ENABLED") {
	case "", "false":
		return c, nil
	case "true":
		c.Enabled = true
	default:
		return c, ErrConfiguration
	}
	c.TenantID = os.Getenv("FLEET_DECISION_TENANT_ID")
	c.DatabaseFile = os.Getenv("FLEET_DECISION_DATABASE_FILE")
	c.DatabaseMode = os.Getenv("FLEET_DECISION_DATABASE_MODE")
	for _, line := range os.Environ() {
		key, value, _ := strings.Cut(line, "=")
		if value != "" && (strings.HasPrefix(key, "AWS_") || strings.HasPrefix(key, "AZURE_") || strings.HasPrefix(key, "GOOGLE_") || strings.HasPrefix(key, "ARM_") || strings.HasPrefix(key, "PG") || strings.HasPrefix(key, "DB_") || strings.HasPrefix(key, "DOCKER_") || key == "DATABASE_URL" || key == "ECONOMICS_TOKEN" || strings.Contains(key, "SIGNING_KEY")) {
			return c, ErrConfiguration
		}
	}
	return c, c.Validate()
}
func (c Config) Validate() error {
	if !c.Enabled {
		return nil
	}
	if !tenantPattern.MatchString(c.TenantID) || c.DatabaseFile != databaseFile || c.DatabaseMode != "LOCAL_PRIVATE" && c.DatabaseMode != "HOSTED_TLS" {
		return ErrConfiguration
	}
	return nil
}

func readDatabaseFile(path string) ([]byte, error) {
	info, e := os.Lstat(path)
	if e != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0111 != 0 || info.Mode().Perm()&0022 != 0 || info.Size() < 1 || info.Size() > 8192 {
		return nil, ErrConfiguration
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, ErrConfiguration
	}
	defer f.Close()
	actual, e := f.Stat()
	if e != nil || !os.SameFile(info, actual) {
		return nil, ErrConfiguration
	}
	raw, e := io.ReadAll(io.LimitReader(f, 8193))
	if e != nil || int64(len(raw)) != info.Size() {
		return nil, ErrConfiguration
	}
	return raw, nil
}

type lookupIP func(context.Context, string) ([]net.IPAddr, error)

func databaseURL(ctx context.Context, raw []byte, mode string, lookup lookupIP) (string, error) {
	text := strings.TrimSpace(string(raw))
	u, e := url.Parse(text)
	if e != nil || u.Scheme != "postgres" && u.Scheme != "postgresql" || u.User == nil || u.Fragment != "" || u.Opaque != "" || u.Hostname() == "" || u.Port() != "5432" || !namePattern.MatchString(strings.TrimPrefix(u.Path, "/")) || !namePattern.MatchString(u.User.Username()) || u.User.Username() == "postgres" || u.User.Username() == "root" {
		return "", ErrConfiguration
	}
	password, ok := u.User.Password()
	if !ok || password == "" || strings.ContainsAny(password, "\x00\r\n") {
		return "", ErrConfiguration
	}
	q, e := url.ParseQuery(u.RawQuery)
	if e != nil {
		return "", ErrConfiguration
	}
	host := u.Hostname()
	for _, v := range q {
		if len(v) != 1 {
			return "", ErrConfiguration
		}
	}
	switch mode {
	case "LOCAL_PRIVATE":
		if len(q) != 1 || q.Get("sslmode") != "disable" || host != "postgres" && net.ParseIP(host) == nil {
			return "", ErrConfiguration
		}
	case "HOSTED_TLS":
		if len(q) != 2 || q.Get("sslmode") != "verify-full" || q.Get("sslrootcert") != "/run/ca/group-decision-root.crt" || net.ParseIP(host) != nil || !hostPattern.MatchString(host) || !strings.Contains(host, ".") {
			return "", ErrConfiguration
		}
	default:
		return "", ErrConfiguration
	}
	if lookup == nil {
		return "", ErrConfiguration
	}
	addresses, e := lookup(ctx, host)
	if e != nil || len(addresses) == 0 || len(addresses) > 16 {
		return "", ErrConfiguration
	}
	for _, a := range addresses {
		if a.Zone != "" || a.IP == nil || !a.IP.IsPrivate() && (mode != "LOCAL_PRIVATE" || !a.IP.IsLoopback()) {
			return "", ErrConfiguration
		}
	}
	if mode == "LOCAL_PRIVATE" {
		u.Host = net.JoinHostPort(addresses[0].IP.String(), "5432")
	}
	// Hosted keeps exact DNS for pgx verify-full and TLS.ServerName. Deployment
	// additionally restricts egress to operator-approved private database CIDRs.
	return u.String(), nil
}

func Open(ctx context.Context, c Config) (*Worker, error) {
	if !c.Enabled || c.Validate() != nil {
		return nil, ErrConfiguration
	}
	setup, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	if filepath.Clean(c.DatabaseFile) != databaseFile {
		return nil, ErrConfiguration
	}
	raw, e := readDatabaseFile(c.DatabaseFile)
	if e != nil {
		return nil, e
	}
	defer clear(raw)
	dsn, e := databaseURL(setup, raw, c.DatabaseMode, net.DefaultResolver.LookupIPAddr)
	if e != nil {
		return nil, e
	}
	db, e := store.OpenRuntime(setup, dsn, "group-decision-reader")
	if e != nil {
		return nil, ErrConfiguration
	}
	worker := &Worker{Store: db, Tenant: c.TenantID}
	if !worker.Ready(setup) {
		db.Pool.Close()
		return nil, ErrConfiguration
	}
	return worker, nil
}
func (w *Worker) Close() {
	if w != nil && w.Store != nil {
		w.Store.Pool.Close()
	}
}
func (w *Worker) Ready(ctx context.Context) bool {
	if w == nil || w.Store == nil || !tenantPattern.MatchString(w.Tenant) {
		return false
	}
	var ready bool
	e := w.Store.Do(ctx, w.Tenant, func(tx *store.Tx) error {
		return tx.QueryRow(ctx, `SELECT public.fleet_decision_credential_scope($1)
		 AND to_regclass('public.fleet_joint_decision_requests') IS NOT NULL
		 AND to_regclass('public.fleet_joint_decisions') IS NOT NULL`, w.Tenant).Scan(&ready)
	})
	return e == nil && ready
}
