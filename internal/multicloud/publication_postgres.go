package multicloud

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresPublicationRepository is deliberately independent of store.Store and
// its application/financial roles. The supplied pool must run as the dedicated
// publication identity; a broad migration credential is rejected by Open.
type PostgresPublicationRepository struct{ Pool *pgxpool.Pool }
type PublicationDatabaseOptions struct{ Fixture bool }

func OpenPublicationRepository(ctx context.Context, dsn string, options ...PublicationDatabaseOptions) (*PostgresPublicationRepository, error) {
	c, e := pgxpool.ParseConfig(dsn)
	if e != nil {
		return nil, errors.New("MULTICLOUD_DATABASE_CONFIGURATION_INVALID")
	}
	if len(options) > 1 {
		return nil, errors.New("MULTICLOUD_DATABASE_CONFIGURATION_INVALID")
	}
	// This private component needs no backend command-line startup options.
	// Reject masks before authentication, including escaped -c/-- spellings in
	// options, rather than trying to maintain a partial PostgreSQL argv parser.
	for name, value := range c.ConnConfig.RuntimeParams {
		switch strings.ToLower(name) {
		case "role", "session_authorization":
			return nil, errors.New("MULTICLOUD_DATABASE_STARTUP_IDENTITY_OVERRIDE_FORBIDDEN")
		case "options":
			if value != "" {
				return nil, errors.New("MULTICLOUD_DATABASE_STARTUP_OPTIONS_FORBIDDEN")
			}
		}
	}
	fixture := len(options) == 1 && options[0].Fixture
	if fixture {
		if c.ConnConfig.Host != "postgres" && c.ConnConfig.Host != "localhost" && c.ConnConfig.Host != "127.0.0.1" && c.ConnConfig.Host != "::1" {
			return nil, errors.New("MULTICLOUD_FIXTURE_DATABASE_MUST_BE_LOCAL")
		}
	} else {
		safe := func(t *tls.Config) bool {
			return t != nil && !t.InsecureSkipVerify && t.ServerName != "" && (t.MinVersion == 0 || t.MinVersion >= tls.VersionTLS12)
		}
		if !safe(c.ConnConfig.TLSConfig) {
			return nil, errors.New("MULTICLOUD_DATABASE_VERIFIED_TLS_REQUIRED")
		}
		for _, fallback := range c.ConnConfig.Fallbacks {
			if !safe(fallback.TLSConfig) {
				return nil, errors.New("MULTICLOUD_DATABASE_VERIFIED_TLS_REQUIRED")
			}
		}
	}
	c.ConnConfig.RuntimeParams["search_path"] = "public,pg_temp"
	prior := c.AfterConnect
	c.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		if prior != nil {
			if e := prior(ctx, conn); e != nil {
				return e
			}
		}
		var safe bool
		var session string
		e := conn.QueryRow(ctx, `SELECT NOT(u.rolsuper OR u.rolcreaterole OR u.rolcreatedb OR u.rolbypassrls OR u.rolreplication) AND NOT(g.rolsuper OR g.rolcreaterole OR g.rolcreatedb OR g.rolbypassrls OR g.rolreplication) AND pg_has_role(session_user,'finops_multicloud_ingester','MEMBER') AND NOT EXISTS(SELECT 1 FROM pg_roles p WHERE p.rolname NOT IN(session_user,'finops_multicloud_ingester') AND pg_has_role(session_user,p.oid,'MEMBER')),session_user FROM pg_roles u CROSS JOIN pg_roles g WHERE u.rolname=session_user AND g.rolname='finops_multicloud_ingester'`).Scan(&safe, &session)
		if e != nil || !safe || session != c.ConnConfig.User {
			return errors.New("MULTICLOUD_DATABASE_IDENTITY_INVALID")
		}
		_, e = conn.Exec(ctx, "SET ROLE finops_multicloud_ingester")
		return e
	}
	pool, e := pgxpool.NewWithConfig(ctx, c)
	if e != nil {
		return nil, e
	}
	if e = pool.Ping(ctx); e != nil {
		pool.Close()
		return nil, e
	}
	return &PostgresPublicationRepository{Pool: pool}, nil
}
func (r *PostgresPublicationRepository) transaction(ctx context.Context, tenant string, fn func(pgx.Tx) error) error {
	if r == nil || r.Pool == nil || !safeID.MatchString(tenant) {
		return errors.New("MULTICLOUD_TENANT_INVALID")
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
func publicationLock(ctx context.Context, tx pgx.Tx, tenant, id string) error {
	_, e := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", tenant+":multicloud:"+id)
	return e
}
func currentPublication(ctx context.Context, tx pgx.Tx, tenant, id string) (RegistrationSnapshot, error) {
	var raw []byte
	var revoked bool
	e := tx.QueryRow(ctx, `SELECT r.document,EXISTS(SELECT 1 FROM multicloud_revocations v WHERE v.tenant_id=r.tenant_id AND v.registration_id=r.id AND v.registration_version=r.version) FROM multicloud_registrations r WHERE r.tenant_id=$1 AND r.id=$2 ORDER BY version DESC LIMIT 1`, tenant, id).Scan(&raw, &revoked)
	if errors.Is(e, pgx.ErrNoRows) || revoked {
		return RegistrationSnapshot{}, ErrPublicationInactive
	}
	if e != nil {
		return RegistrationSnapshot{}, e
	}
	var out RegistrationSnapshot
	if e = json.Unmarshal(raw, &out); e != nil {
		return out, e
	}
	if e = validatePrivateRegistration(out); e != nil {
		return out, e
	}
	return out, nil
}
func (r *PostgresPublicationRepository) Register(ctx context.Context, s RegistrationSnapshot) error {
	if e := validatePrivateRegistration(s); e != nil {
		return e
	}
	return r.transaction(ctx, s.Registration.TenantID, func(tx pgx.Tx) error {
		if e := publicationLock(ctx, tx, s.Registration.TenantID, s.Registration.ID); e != nil {
			return e
		}
		var existing []byte
		e := tx.QueryRow(ctx, "SELECT document FROM multicloud_registrations WHERE tenant_id=$1 AND id=$2 AND version=$3", s.Registration.TenantID, s.Registration.ID, s.Registration.Version).Scan(&existing)
		if e == nil {
			var old RegistrationSnapshot
			if e = json.Unmarshal(existing, &old); e != nil {
				return e
			}
			if Hash(old) != Hash(s) {
				return ErrPublicationConflict
			}
			return nil
		}
		if !errors.Is(e, pgx.ErrNoRows) {
			return e
		}
		raw, e := json.Marshal(s)
		if e != nil {
			return e
		}
		_, e = tx.Exec(ctx, `INSERT INTO multicloud_registrations(tenant_id,id,version,config_hash,scope_hash,binding_hash,document) VALUES($1,$2,$3,$4,$5,$6,$7)`, s.Registration.TenantID, s.Registration.ID, s.Registration.Version, s.ConfigHash, s.ScopeHash, s.BindingHash, raw)
		return e
	})
}
func (r *PostgresPublicationRepository) Current(ctx context.Context, tenant, id string) (out RegistrationSnapshot, e error) {
	e = r.transaction(ctx, tenant, func(tx pgx.Tx) error { var err error; out, err = currentPublication(ctx, tx, tenant, id); return err })
	return
}
func (r *PostgresPublicationRepository) Prepare(ctx context.Context, s RegistrationSnapshot, key string, m PublicationManifest) (out PublicationJob, replay bool, e error) {
	e = r.transaction(ctx, s.Registration.TenantID, func(tx pgx.Tx) error {
		if err := publicationLock(ctx, tx, s.Registration.TenantID, s.Registration.ID); err != nil {
			return err
		}
		current, err := currentPublication(ctx, tx, s.Registration.TenantID, s.Registration.ID)
		if err != nil {
			return err
		}
		if Hash(current) != Hash(s) {
			return ErrPublicationInactive
		}
		var raw []byte
		var requestHash string
		err = tx.QueryRow(ctx, `SELECT id,idempotency_key,manifest,created_at,request_hash FROM multicloud_jobs WHERE tenant_id=$1 AND registration_id=$2 AND idempotency_key=$3`, s.Registration.TenantID, s.Registration.ID, key).Scan(&out.ID, &out.Key, &raw, &out.CreatedAt, &requestHash)
		if err == nil {
			if requestHash != Hash(m) {
				return ErrPublicationConflict
			}
			if err = json.Unmarshal(raw, &out.Manifest); err != nil {
				return err
			}
			replay = true
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		out = PublicationJob{ID: uuid.NewString(), Key: key, Manifest: m}
		raw, err = json.Marshal(m)
		if err != nil {
			return err
		}
		return tx.QueryRow(ctx, `INSERT INTO multicloud_jobs(tenant_id,id,registration_id,registration_version,idempotency_key,request_hash,manifest) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING created_at`, s.Registration.TenantID, out.ID, s.Registration.ID, s.Registration.Version, key, Hash(m), raw).Scan(&out.CreatedAt)
	})
	return
}
func (r *PostgresPublicationRepository) Checkpoints(ctx context.Context, tenant, job string) (out []PublicationCheckpoint, e error) {
	out = []PublicationCheckpoint{}
	e = r.transaction(ctx, tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, "SELECT document FROM multicloud_checkpoints WHERE tenant_id=$1 AND job_id=$2 ORDER BY created_at,stage", tenant, job)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var raw []byte
			var c PublicationCheckpoint
			if err = rows.Scan(&raw); err != nil {
				return err
			}
			if err = json.Unmarshal(raw, &c); err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return
}
func (r *PostgresPublicationRepository) Job(ctx context.Context, tenant, id string) (out PublicationJob, e error) {
	e = r.transaction(ctx, tenant, func(tx pgx.Tx) error {
		var raw []byte
		if err := tx.QueryRow(ctx, "SELECT id,idempotency_key,manifest,created_at FROM multicloud_jobs WHERE tenant_id=$1 AND id=$2", tenant, id).Scan(&out.ID, &out.Key, &raw, &out.CreatedAt); err != nil {
			return err
		}
		return json.Unmarshal(raw, &out.Manifest)
	})
	return
}

// Pending exposes restart work only to the private publication runtime. It
// contains metadata/checkpoint IDs, not native billing rows or credentials.
func (r *PostgresPublicationRepository) Pending(ctx context.Context, tenant, registration string) (out []PublicationJob, e error) {
	out = []PublicationJob{}
	e = r.transaction(ctx, tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT j.id,j.idempotency_key,j.manifest,j.created_at FROM multicloud_jobs j WHERE j.tenant_id=$1 AND j.registration_id=$2 AND NOT EXISTS(SELECT 1 FROM multicloud_receipts r WHERE r.tenant_id=j.tenant_id AND r.job_id=j.id) ORDER BY j.created_at,j.id LIMIT 100`, tenant, registration)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var job PublicationJob
			var raw []byte
			if err = rows.Scan(&job.ID, &job.Key, &raw, &job.CreatedAt); err != nil {
				return err
			}
			if err = json.Unmarshal(raw, &job.Manifest); err != nil {
				return err
			}
			out = append(out, job)
		}
		return rows.Err()
	})
	return
}
func (r *PostgresPublicationRepository) Checkpoint(ctx context.Context, tenant, job string, c PublicationCheckpoint) error {
	return r.transaction(ctx, tenant, func(tx pgx.Tx) error {
		var registration string
		if e := tx.QueryRow(ctx, "SELECT registration_id FROM multicloud_jobs WHERE tenant_id=$1 AND id=$2", tenant, job).Scan(&registration); e != nil {
			return e
		}
		if e := publicationLock(ctx, tx, tenant, registration); e != nil {
			return e
		}
		var hash string
		e := tx.QueryRow(ctx, "SELECT content_hash FROM multicloud_checkpoints WHERE tenant_id=$1 AND job_id=$2 AND stage=$3", tenant, job, c.Stage).Scan(&hash)
		if e == nil {
			if hash != Hash(c) {
				return ErrPublicationConflict
			}
			return nil
		}
		if !errors.Is(e, pgx.ErrNoRows) {
			return e
		}
		raw, e := json.Marshal(c)
		if e != nil {
			return e
		}
		_, e = tx.Exec(ctx, "INSERT INTO multicloud_checkpoints(tenant_id,job_id,stage,content_hash,document) VALUES($1,$2,$3,$4,$5)", tenant, job, c.Stage, Hash(c), raw)
		return e
	})
}
func receiptProjection(ctx context.Context, tx pgx.Tx, tenant string, out *PublicationReceipt) error {
	var active, current, ambiguous bool
	e := tx.QueryRow(ctx, `WITH candidates AS(SELECT h.sequence,h.document->'manifest'->>'economic_hash' AS economic_hash,(h.document->'manifest'->>'native_observed_at')::timestamptz AS native_at FROM multicloud_receipts h WHERE h.tenant_id=$1 AND h.registration_id=$3 AND h.document->'manifest'->>'scope_hash'=$4 AND (h.document->'manifest'->'period'->>'start')::timestamptz=$5 AND (h.document->'manifest'->'period'->>'end')::timestamptz=$6),heads AS(SELECT * FROM candidates WHERE native_at=(SELECT max(native_at) FROM candidates)) SELECT r.registration_version=(SELECT max(version) FROM multicloud_registrations WHERE tenant_id=r.tenant_id AND id=r.registration_id) AND NOT EXISTS(SELECT 1 FROM multicloud_revocations v WHERE v.tenant_id=r.tenant_id AND v.registration_id=r.registration_id AND v.registration_version=r.registration_version),(SELECT count(DISTINCT economic_hash)=1 FROM heads) AND r.sequence=(SELECT max(sequence) FROM heads),(SELECT count(DISTINCT economic_hash)>1 FROM heads) FROM multicloud_receipts r WHERE tenant_id=$1 AND id=$2`, tenant, out.ID, out.Manifest.RegistrationID, out.Manifest.ScopeHash, out.Manifest.Period.Start, out.Manifest.Period.End).Scan(&active, &current, &ambiguous)
	out.ActiveSource = active
	out.IsCurrent = current
	out.HeadReasonCode = ""
	if ambiguous {
		out.HeadReasonCode = "NATIVE_OBSERVATION_ORDER_AMBIGUOUS"
	}
	return e
}
func (r *PostgresPublicationRepository) Publish(ctx context.Context, tenant, job string) (out PublicationReceipt, replay bool, e error) {
	e = r.transaction(ctx, tenant, func(tx pgx.Tx) error {
		var registration string
		var version int64
		var manifest []byte
		if err := tx.QueryRow(ctx, "SELECT registration_id,registration_version,manifest FROM multicloud_jobs WHERE tenant_id=$1 AND id=$2", tenant, job).Scan(&registration, &version, &manifest); err != nil {
			return err
		}
		if err := publicationLock(ctx, tx, tenant, registration); err != nil {
			return err
		}
		current, err := currentPublication(ctx, tx, tenant, registration)
		if err != nil {
			return err
		}
		if current.Registration.Version != version {
			return ErrPublicationInactive
		}
		var raw []byte
		err = tx.QueryRow(ctx, "SELECT document FROM multicloud_receipts WHERE tenant_id=$1 AND job_id=$2", tenant, job).Scan(&raw)
		if err == nil {
			if err = json.Unmarshal(raw, &out); err != nil {
				return err
			}
			replay = true
			return receiptProjection(ctx, tx, tenant, &out)
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		out = PublicationReceipt{ID: uuid.NewString(), JobID: job, CreatedAt: time.Time{}}
		if err = json.Unmarshal(manifest, &out.Manifest); err != nil {
			return err
		}
		if err = tx.QueryRow(ctx, "SELECT coalesce(max(sequence),0)+1 FROM multicloud_receipts WHERE tenant_id=$1 AND registration_id=$2", tenant, registration).Scan(&out.Sequence); err != nil {
			return err
		}
		raw, err = json.Marshal(out)
		if err != nil {
			return err
		}
		err = tx.QueryRow(ctx, `INSERT INTO multicloud_receipts(tenant_id,id,job_id,registration_id,registration_version,sequence,document) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING document`, tenant, out.ID, job, registration, version, out.Sequence, raw).Scan(&raw)
		if err != nil {
			return err
		}
		if err = json.Unmarshal(raw, &out); err != nil {
			return err
		}
		return receiptProjection(ctx, tx, tenant, &out)
	})
	return
}
func (r *PostgresPublicationRepository) Revoke(ctx context.Context, tenant, id string, version int64, reason string) error {
	if !publicationReason.MatchString(reason) {
		return errors.New("MULTICLOUD_REVOCATION_REASON_INVALID")
	}
	return r.transaction(ctx, tenant, func(tx pgx.Tx) error {
		if e := publicationLock(ctx, tx, tenant, id); e != nil {
			return e
		}
		var old string
		e := tx.QueryRow(ctx, "SELECT reason_code FROM multicloud_revocations WHERE tenant_id=$1 AND registration_id=$2 AND registration_version=$3", tenant, id, version).Scan(&old)
		if e == nil {
			if old != reason {
				return ErrPublicationConflict
			}
			return nil
		}
		if !errors.Is(e, pgx.ErrNoRows) {
			return e
		}
		_, e = tx.Exec(ctx, "INSERT INTO multicloud_revocations(tenant_id,registration_id,registration_version,reason_code) VALUES($1,$2,$3,$4)", tenant, id, version, reason)
		return e
	})
}

// Receipts returns immutable observation history with a current projection.
// Consumers must select IsCurrent, never sum receipts across repeated polls.
func (r *PostgresPublicationRepository) Receipts(ctx context.Context, tenant, registration string) (out []PublicationReceipt, e error) {
	out = []PublicationReceipt{}
	e = r.transaction(ctx, tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, "SELECT document FROM multicloud_receipts WHERE tenant_id=$1 AND registration_id=$2 ORDER BY sequence", tenant, registration)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var raw []byte
			var receipt PublicationReceipt
			if err = rows.Scan(&raw); err != nil {
				return err
			}
			if err = json.Unmarshal(raw, &receipt); err != nil {
				return err
			}
			out = append(out, receipt)
		}
		if err = rows.Err(); err != nil {
			return err
		}
		rows.Close()
		for i := range out {
			if err = receiptProjection(ctx, tx, tenant, &out[i]); err != nil {
				return err
			}
		}
		return nil
	})
	return
}
