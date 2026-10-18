package configuration

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type ArtifactDatabaseOptions struct{ Fixture bool }
type ArtifactPostgresRepository struct{ Pool *pgxpool.Pool }

func OpenArtifactRepository(ctx context.Context, dsn string, options ...ArtifactDatabaseOptions) (*ArtifactPostgresRepository, error) {
	c, e := pgxpool.ParseConfig(dsn)
	if e != nil || len(options) > 1 {
		return nil, errors.New("CONFIGURATION_ARTIFACT_DATABASE_CONFIGURATION_INVALID")
	}
	for name := range c.ConnConfig.RuntimeParams {
		if strings.EqualFold(name, "role") || strings.EqualFold(name, "session_authorization") || strings.EqualFold(name, "options") {
			return nil, errors.New("CONFIGURATION_ARTIFACT_DATABASE_STARTUP_IDENTITY_FORBIDDEN")
		}
	}
	fixture := len(options) == 1 && options[0].Fixture
	if fixture {
		h := c.ConnConfig.Host
		if h != "postgres" && h != "localhost" && h != "127.0.0.1" && h != "::1" {
			return nil, errors.New("CONFIGURATION_ARTIFACT_FIXTURE_DATABASE_MUST_BE_LOCAL")
		}
	} else {
		safe := func(t *tls.Config) bool {
			return t != nil && !t.InsecureSkipVerify && t.ServerName != "" && (t.MinVersion == 0 || t.MinVersion >= tls.VersionTLS12)
		}
		if !safe(c.ConnConfig.TLSConfig) {
			return nil, errors.New("CONFIGURATION_ARTIFACT_DATABASE_VERIFIED_TLS_REQUIRED")
		}
		for _, f := range c.ConnConfig.Fallbacks {
			if !safe(f.TLSConfig) {
				return nil, errors.New("CONFIGURATION_ARTIFACT_DATABASE_VERIFIED_TLS_REQUIRED")
			}
		}
	}
	c.ConnConfig.RuntimeParams["search_path"] = "public,pg_temp"
	c.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		var safe bool
		e := conn.QueryRow(ctx, `SELECT current_user=session_user AND NOT(rolsuper OR rolcreaterole OR rolcreatedb OR rolbypassrls OR rolreplication) AND pg_has_role(session_user,'finops_configuration_attestor','MEMBER') AND NOT EXISTS(SELECT 1 FROM pg_roles r WHERE r.rolname NOT IN(session_user,'finops_configuration_attestor') AND pg_has_role(session_user,r.oid,'MEMBER')) FROM pg_roles WHERE rolname=session_user`).Scan(&safe)
		if e != nil || !safe {
			return errors.New("CONFIGURATION_ARTIFACT_DATABASE_IDENTITY_INVALID")
		}
		_, e = conn.Exec(ctx, "SET ROLE finops_configuration_attestor")
		return e
	}
	pool, e := pgxpool.NewWithConfig(ctx, c)
	if e != nil {
		return nil, errors.New("CONFIGURATION_ARTIFACT_DATABASE_CONFIGURATION_INVALID")
	}
	if e = pool.Ping(ctx); e != nil {
		pool.Close()
		return nil, e
	}
	return &ArtifactPostgresRepository{pool}, nil
}
func (r *ArtifactPostgresRepository) transaction(ctx context.Context, tenant string, fn func(pgx.Tx) error) error {
	if r == nil || r.Pool == nil || !artifactID.MatchString(tenant) {
		return errors.New("CONFIGURATION_ARTIFACT_TENANT_INVALID")
	}
	tx, e := r.Pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, "SELECT set_config('app.tenant_id',$1,true)", tenant); e != nil {
		return e
	}
	if e = fn(tx); e != nil {
		return e
	}
	return tx.Commit(ctx)
}
func artifactCurrent(ctx context.Context, tx pgx.Tx, tenant, id string) (ArtifactRegistration, error) {
	var r ArtifactRegistration
	var version int64
	e := tx.QueryRow(ctx, "SELECT version FROM configuration_artifact_registrations WHERE tenant_id=$1 AND id=$2 ORDER BY version DESC LIMIT 1", tenant, id).Scan(&version)
	if errors.Is(e, pgx.ErrNoRows) {
		return r, ErrArtifactInactive
	}
	if e != nil {
		return r, e
	}
	var raw []byte
	if e = tx.QueryRow(ctx, "SELECT configuration_artifact_current($1,$2,$3)", tenant, id, version).Scan(&raw); e != nil {
		var pg *pgconn.PgError
		if errors.As(e, &pg) && pg.Code == "P0001" {
			return r, ErrArtifactInactive
		}
		return r, e
	}
	if json.Unmarshal(raw, &r) != nil {
		return r, errors.New("CONFIGURATION_ARTIFACT_REGISTRATION_INVALID")
	}
	return r, ValidateArtifactRegistration(r)
}
func (r *ArtifactPostgresRepository) Register(ctx context.Context, in ArtifactRegistration) error {
	if e := ValidateArtifactRegistration(in); e != nil {
		return e
	}
	return r.transaction(ctx, in.Binding.TenantID, func(tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0)),pg_advisory_xact_lock(hashtextextended($2,0))", in.Binding.TenantID+":dependency-graph", in.Binding.TenantID+":configuration-artifact:"+in.ID); e != nil {
			return e
		}
		var old string
		e := tx.QueryRow(ctx, "SELECT content_hash FROM configuration_artifact_registrations WHERE tenant_id=$1 AND id=$2 AND version=$3", in.Binding.TenantID, in.ID, in.Version).Scan(&old)
		if e == nil {
			if old != artifactHash(in) {
				return ErrArtifactConflict
			}
			return nil
		}
		if !errors.Is(e, pgx.ErrNoRows) {
			return e
		}
		raw, _ := json.Marshal(in)
		if _, e = tx.Exec(ctx, "INSERT INTO configuration_artifact_registrations(tenant_id,id,version,resource_id,authority_id,document,content_hash) VALUES($1,$2,$3,$4,$5,$6,$7)", in.Binding.TenantID, in.ID, in.Version, in.Binding.ResourceID, in.AuthorityID, raw, artifactHash(in)); e != nil {
			return e
		}
		_, e = artifactCurrent(ctx, tx, in.Binding.TenantID, in.ID)
		return e
	})
}
func (r *ArtifactPostgresRepository) Current(ctx context.Context, tenant, id string) (out ArtifactRegistration, e error) {
	e = r.transaction(ctx, tenant, func(tx pgx.Tx) error { var err error; out, err = artifactCurrent(ctx, tx, tenant, id); return err })
	return
}
func artifactJob(ctx context.Context, tx pgx.Tx, tenant, registration, key string) (out ArtifactJob, e error) {
	var raw []byte
	e = tx.QueryRow(ctx, "SELECT id,idempotency_key,metadata,created_at FROM configuration_artifact_jobs WHERE tenant_id=$1 AND registration_id=$2 AND idempotency_key=$3", tenant, registration, key).Scan(&out.ID, &out.Key, &raw, &out.CreatedAt)
	if e == nil {
		e = json.Unmarshal(raw, &out.Metadata)
	}
	return
}
func (r *ArtifactPostgresRepository) JobByKey(ctx context.Context, tenant, registration, key string) (out ArtifactJob, e error) {
	e = r.transaction(ctx, tenant, func(tx pgx.Tx) error {
		var err error
		out, err = artifactJob(ctx, tx, tenant, registration, key)
		return err
	})
	return
}
func (r *ArtifactPostgresRepository) Prepare(ctx context.Context, reg ArtifactRegistration, key string, m ArtifactMetadata) (out ArtifactJob, replay bool, e error) {
	e = r.transaction(ctx, reg.Binding.TenantID, func(tx pgx.Tx) error {
		current, err := artifactCurrent(ctx, tx, reg.Binding.TenantID, reg.ID)
		if err != nil {
			return err
		}
		if artifactHash(current) != artifactHash(reg) || m.RegistrationHash != artifactHash(reg) {
			return ErrArtifactInactive
		}
		out, err = artifactJob(ctx, tx, reg.Binding.TenantID, reg.ID, key)
		if err == nil {
			if artifactHash(out.Metadata) != artifactHash(m) {
				return ErrArtifactConflict
			}
			replay = true
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		raw, _ := json.Marshal(m)
		out = ArtifactJob{ID: uuid.NewString(), Key: key, Metadata: m}
		return tx.QueryRow(ctx, "INSERT INTO configuration_artifact_jobs(tenant_id,id,registration_id,registration_version,idempotency_key,request_hash,metadata) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING created_at", reg.Binding.TenantID, out.ID, reg.ID, reg.Version, key, artifactHash(m), raw).Scan(&out.CreatedAt)
	})
	return
}
func (r *ArtifactPostgresRepository) Archive(ctx context.Context, tenant, job string) (out ArtifactArchiveRef, e error) {
	e = r.transaction(ctx, tenant, func(tx pgx.Tx) error {
		var raw []byte
		if err := tx.QueryRow(ctx, "SELECT document FROM configuration_artifact_archives WHERE tenant_id=$1 AND job_id=$2", tenant, job).Scan(&raw); err != nil {
			return err
		}
		return json.Unmarshal(raw, &out)
	})
	return
}
func (r *ArtifactPostgresRepository) Checkpoint(ctx context.Context, tenant, job string, in ArtifactArchiveRef) error {
	return r.transaction(ctx, tenant, func(tx pgx.Tx) error {
		var reg string
		if e := tx.QueryRow(ctx, "SELECT registration_id FROM configuration_artifact_jobs WHERE tenant_id=$1 AND id=$2", tenant, job).Scan(&reg); e != nil {
			return e
		}
		if _, e := artifactCurrent(ctx, tx, tenant, reg); e != nil {
			return e
		}
		var raw []byte
		e := tx.QueryRow(ctx, "SELECT document FROM configuration_artifact_archives WHERE tenant_id=$1 AND job_id=$2", tenant, job).Scan(&raw)
		if e == nil {
			var old ArtifactArchiveRef
			if json.Unmarshal(raw, &old) != nil || old != in {
				return ErrArtifactConflict
			}
			return nil
		}
		if !errors.Is(e, pgx.ErrNoRows) {
			return e
		}
		raw, _ = json.Marshal(in)
		_, e = tx.Exec(ctx, "INSERT INTO configuration_artifact_archives(tenant_id,job_id,document) VALUES($1,$2,$3)", tenant, job, raw)
		return e
	})
}
func (r *ArtifactPostgresRepository) Publish(ctx context.Context, tenant, job string) (out ArtifactReceipt, replay bool, e error) {
	e = r.transaction(ctx, tenant, func(tx pgx.Tx) error {
		var reg string
		var meta []byte
		if err := tx.QueryRow(ctx, "SELECT registration_id,metadata FROM configuration_artifact_jobs WHERE tenant_id=$1 AND id=$2", tenant, job).Scan(&reg, &meta); err != nil {
			return err
		}
		if _, err := artifactCurrent(ctx, tx, tenant, reg); err != nil {
			return err
		}
		var raw []byte
		err := tx.QueryRow(ctx, "SELECT document FROM configuration_artifact_receipts WHERE tenant_id=$1 AND job_id=$2", tenant, job).Scan(&raw)
		if err == nil {
			replay = true
			return json.Unmarshal(raw, &out)
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		var archive []byte
		if err = tx.QueryRow(ctx, "SELECT document FROM configuration_artifact_archives WHERE tenant_id=$1 AND job_id=$2", tenant, job).Scan(&archive); err != nil {
			return err
		}
		out = ArtifactReceipt{ID: uuid.NewString(), JobID: job}
		if json.Unmarshal(meta, &out.Metadata) != nil || json.Unmarshal(archive, &out.Archive) != nil {
			return errors.New("CONFIGURATION_ARTIFACT_METADATA_INVALID")
		}
		raw, _ = json.Marshal(out)
		if err = tx.QueryRow(ctx, "INSERT INTO configuration_artifact_receipts(tenant_id,id,job_id,document) VALUES($1,$2,$3,$4) RETURNING document", tenant, out.ID, job, raw).Scan(&raw); err != nil {
			return err
		}
		return json.Unmarshal(raw, &out)
	})
	return
}
func (r *ArtifactPostgresRepository) Revoke(ctx context.Context, tenant, id string, version int64, reason string) error {
	if !regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,119}$`).MatchString(reason) {
		return errors.New("CONFIGURATION_ARTIFACT_REVOCATION_INVALID")
	}
	return r.transaction(ctx, tenant, func(tx pgx.Tx) error {
		var old string
		e := tx.QueryRow(ctx, "SELECT reason_code FROM configuration_artifact_revocations WHERE tenant_id=$1 AND registration_id=$2 AND registration_version=$3", tenant, id, version).Scan(&old)
		if e == nil {
			if old != reason {
				return ErrArtifactConflict
			}
			return nil
		}
		if !errors.Is(e, pgx.ErrNoRows) {
			return e
		}
		_, e = tx.Exec(ctx, "INSERT INTO configuration_artifact_revocations(tenant_id,registration_id,registration_version,reason_code) VALUES($1,$2,$3,$4)", tenant, id, version, reason)
		return e
	})
}
