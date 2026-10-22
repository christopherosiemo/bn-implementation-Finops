package store

import (
	"crypto/tls"
	"errors"

	"github.com/jackc/pgx/v5"
)

// ValidateDatabaseTransport runs before any non-fixture process opens its
// database. Authentication must verify both the certificate chain and hostname;
// require/verify-ca and plaintext fallback are insufficient. Parsing failures
// never include the supplied DSN or credentials in the returned error.
func ValidateDatabaseTransport(dsn string) error {
	configuration, err := pgx.ParseConfig(dsn)
	if err != nil {
		return errors.New("DATABASE_VERIFIED_TLS_REQUIRED")
	}
	safe := func(config *tls.Config) bool {
		return config != nil && !config.InsecureSkipVerify && config.ServerName != "" &&
			(config.MinVersion == 0 || config.MinVersion >= tls.VersionTLS12)
	}
	if !safe(configuration.TLSConfig) {
		return errors.New("DATABASE_VERIFIED_TLS_REQUIRED")
	}
	for _, fallback := range configuration.Fallbacks {
		if !safe(fallback.TLSConfig) {
			return errors.New("DATABASE_VERIFIED_TLS_REQUIRED")
		}
	}
	return nil
}
