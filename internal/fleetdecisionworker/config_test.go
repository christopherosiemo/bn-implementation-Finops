package fleetdecisionworker

import (
	"context"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func privateLookup(context.Context, string) ([]net.IPAddr, error) {
	return []net.IPAddr{{IP: net.ParseIP("10.0.0.4")}}, nil
}
func TestDecisionConfigurationDisabledAndCredentialIsolation(t *testing.T) {
	t.Setenv("FLEET_DECISION_ENABLED", "false")
	t.Setenv("AWS_ACCESS_KEY_ID", "must-not-be-read-when-disabled")
	if c, e := ReadConfig(); e != nil || c.Enabled {
		t.Fatal("disabled process needs secrets", e)
	}
	t.Setenv("FLEET_DECISION_ENABLED", "true")
	t.Setenv("FLEET_DECISION_TENANT_ID", "tenant")
	t.Setenv("FLEET_DECISION_DATABASE_FILE", databaseFile)
	t.Setenv("FLEET_DECISION_DATABASE_MODE", "LOCAL_PRIVATE")
	if _, e := ReadConfig(); e == nil {
		t.Fatal("ambient provider credentials accepted")
	}
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	if c, e := ReadConfig(); e != nil || !c.Enabled {
		t.Fatal("fixed isolated configuration refused", e)
	}
	t.Setenv("FLEET_DECISION_DATABASE_FILE", "/arbitrary/database")
	if _, e := ReadConfig(); e == nil {
		t.Fatal("unfixed database path accepted")
	}
}
func TestDecisionDatabaseLocalPinAndHostedTLSName(t *testing.T) {
	local := []byte("postgres://group_decision_reader:fixture@postgres:5432/finops?sslmode=disable")
	got, e := databaseURL(context.Background(), local, "LOCAL_PRIVATE", privateLookup)
	if e != nil {
		t.Fatal(e)
	}
	u, _ := url.Parse(got)
	if u.Host != "10.0.0.4:5432" {
		t.Fatal("local address not pinned")
	}
	hosted := []byte("postgres://group_decision_reader:fixture@db.internal.example:5432/finops?sslmode=verify-full&sslrootcert=/run/ca/group-decision-root.crt")
	got, e = databaseURL(context.Background(), hosted, "HOSTED_TLS", privateLookup)
	if e != nil {
		t.Fatal(e)
	}
	// ParseConfig normally reads sslrootcert. A real fixture CA is intentionally
	// absent; inspect only the unchanged DNS value, then parse with system roots.
	u, _ = url.Parse(got)
	if u.Hostname() != "db.internal.example" {
		t.Fatal("TLS hostname replaced by IP")
	}
	q := u.Query()
	q.Del("sslrootcert")
	u.RawQuery = q.Encode()
	cfg, e := pgxpool.ParseConfig(u.String())
	if e != nil || cfg.ConnConfig.TLSConfig == nil || cfg.ConnConfig.TLSConfig.ServerName != "db.internal.example" || cfg.ConnConfig.TLSConfig.InsecureSkipVerify {
		t.Fatal("hosted verify-full identity lost", e)
	}
}
func TestDecisionDatabaseRejectsUnpinnedTargetsOverridesAndTLSFallback(t *testing.T) {
	for _, text := range []string{
		"postgres://postgres:fixture@postgres:5432/finops?sslmode=disable",
		"postgres://group_decision_reader:fixture@public.example:5432/finops?sslmode=disable",
		"postgres://group_decision_reader:fixture@postgres:5433/finops?sslmode=disable",
		"postgres://group_decision_reader:fixture@postgres:5432/finops?sslmode=disable&options=-crole=finops_api",
		"postgres://group_decision_reader:fixture@postgres:5432/finops?sslmode=disable&sslmode=prefer",
	} {
		if _, e := databaseURL(context.Background(), []byte(text), "LOCAL_PRIVATE", privateLookup); e == nil {
			t.Fatal("unsafe database target accepted")
		}
	}
	public := func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("203.0.113.8")}}, nil
	}
	if _, e := databaseURL(context.Background(), []byte("postgres://group_decision_reader:fixture@postgres:5432/finops?sslmode=disable"), "LOCAL_PRIVATE", public); e == nil {
		t.Fatal("public DNS answer accepted")
	}
	for _, mode := range []string{"prefer", "require", "verify-ca", "disable"} {
		if _, e := databaseURL(context.Background(), []byte("postgres://group_decision_reader:fixture@db.internal.example:5432/finops?sslmode="+mode+"&sslrootcert=/run/ca/group-decision-root.crt"), "HOSTED_TLS", privateLookup); e == nil {
			t.Fatal("hosted TLS fallback accepted")
		}
	}
}
func TestDecisionPrivateFileRejectsExecutableWritableSymlinkAndOversize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "database")
	if e := os.WriteFile(path, []byte("private"), 0444); e != nil {
		t.Fatal(e)
	}
	if _, e := readDatabaseFile(path); e != nil {
		t.Fatal(e)
	}
	for _, mode := range []os.FileMode{0555, 0666} {
		if e := os.Chmod(path, mode); e != nil {
			t.Fatal(e)
		}
		if _, e := readDatabaseFile(path); e == nil {
			t.Fatal("unsafe file permissions accepted")
		}
	}
	if e := os.Chmod(path, 0444); e != nil {
		t.Fatal(e)
	}
	link := filepath.Join(dir, "link")
	if e := os.Symlink(path, link); e != nil {
		t.Fatal(e)
	}
	if _, e := readDatabaseFile(link); e == nil {
		t.Fatal("symlink accepted")
	}
	if e := os.Chmod(path, 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(path, []byte(strings.Repeat("x", 8193)), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(path, 0444); e != nil {
		t.Fatal(e)
	}
	if _, e := readDatabaseFile(path); e == nil {
		t.Fatal("oversize database file accepted")
	}
}
