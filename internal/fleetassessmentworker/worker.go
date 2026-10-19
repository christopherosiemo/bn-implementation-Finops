// Package fleetassessmentworker runs an explicitly commissioned analytical
// queue reader. It reads existing versioned native archives; it has no provider
// discovery, artifact write, signer, deployment or execution interface.
package fleetassessmentworker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	a "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetassessment"
	b "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetbilling"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
)

const LocalArchive = "LOCAL_VERSIONED_S3"
const IRSAArchive = "AWS_IRSA"
const pageLimit = 16
const maximumObjectBytes = 32 << 20

var ErrConfiguration = errors.New("FLEET_ASSESSMENT_CONFIGURATION_INVALID")
var ErrJob = errors.New("FLEET_ASSESSMENT_JOB_REFUSED")
var ErrBusy = errors.New("FLEET_ASSESSMENT_JOB_BUSY")
var ErrArchive = errors.New("FLEET_ASSESSMENT_ARCHIVE_UNAVAILABLE")
var identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$`)
var digest = regexp.MustCompile(`^[a-f0-9]{64}$`)
var bucketName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`)
var roleARN = regexp.MustCompile(`^arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]{1,512}$`)

// These are operator installation inputs, never browser request fields. The
// local credentials must be a separately commissioned archive read identity.
type Config struct {
	Enabled                                                                        bool
	TenantID, DatabaseFile                                                         string
	ArchiveMode, ArchiveRegion, ArchiveEndpoint, ArchiveBucket, ArchiveBucketOwner string
	ArchiveAccessKeyFile, ArchiveSecretKeyFile                                     string
	RoleARN, WebIdentityTokenFile                                                  string
}

func ConfigFromEnvironment(get func(string) string) (Config, error) {
	c := Config{Enabled: get("FLEET_ASSESSMENT_ENABLED") == "true", TenantID: get("FLEET_ASSESSMENT_TENANT_ID"), DatabaseFile: get("FLEET_ASSESSMENT_DATABASE_FILE"), ArchiveMode: get("FLEET_ASSESSMENT_ARCHIVE_MODE"), ArchiveRegion: get("FLEET_ASSESSMENT_ARCHIVE_REGION"), ArchiveEndpoint: get("FLEET_ASSESSMENT_ARCHIVE_ENDPOINT"), ArchiveBucket: get("FLEET_ASSESSMENT_ARCHIVE_BUCKET"), ArchiveBucketOwner: get("FLEET_ASSESSMENT_ARCHIVE_BUCKET_OWNER"), ArchiveAccessKeyFile: get("FLEET_ASSESSMENT_ARCHIVE_ACCESS_KEY_FILE"), ArchiveSecretKeyFile: get("FLEET_ASSESSMENT_ARCHIVE_SECRET_KEY_FILE"), RoleARN: get("AWS_ROLE_ARN"), WebIdentityTokenFile: get("AWS_WEB_IDENTITY_TOKEN_FILE")}
	return c, c.Validate()
}
func (c Config) Validate() error {
	if !c.Enabled || !identifier.MatchString(c.TenantID) || c.ArchiveRegion != "eu-west-1" || !bucketName.MatchString(c.ArchiveBucket) {
		return ErrConfiguration
	}
	paths := []string{c.DatabaseFile}
	switch c.ArchiveMode {
	case LocalArchive:
		u, e := url.Parse(c.ArchiveEndpoint)
		if e != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.Port() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || !privateName(u.Hostname()) || c.ArchiveBucketOwner != "" || c.RoleARN != "" || c.WebIdentityTokenFile != "" {
			return ErrConfiguration
		}
		paths = append(paths, c.ArchiveAccessKeyFile, c.ArchiveSecretKeyFile)
	case IRSAArchive:
		if c.ArchiveEndpoint != "" || c.ArchiveAccessKeyFile != "" || c.ArchiveSecretKeyFile != "" || !roleARN.MatchString(c.RoleARN) || !regexp.MustCompile(`^[0-9]{12}$`).MatchString(c.ArchiveBucketOwner) {
			return ErrConfiguration
		}
		paths = append(paths, c.WebIdentityTokenFile)
	default:
		return ErrConfiguration
	}
	seen := map[string]bool{}
	for _, p := range paths {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p || seen[p] {
			return ErrConfiguration
		}
		seen[p] = true
	}
	return nil
}
func checkEnvironment(entries []string, c Config) error {
	for _, entry := range entries {
		parts := strings.SplitN(entry, "=", 2)
		k := strings.ToUpper(parts[0])
		if strings.HasPrefix(k, "AWS_") {
			if c.ArchiveMode == IRSAArchive && (k == "AWS_ROLE_ARN" || k == "AWS_WEB_IDENTITY_TOKEN_FILE" || k == "AWS_REGION" || k == "AWS_DEFAULT_REGION" || k == "AWS_STS_REGIONAL_ENDPOINTS") {
				if len(parts) != 2 || k == "AWS_ROLE_ARN" && parts[1] != c.RoleARN || k == "AWS_WEB_IDENTITY_TOKEN_FILE" && parts[1] != c.WebIdentityTokenFile || (k == "AWS_REGION" || k == "AWS_DEFAULT_REGION") && parts[1] != "eu-west-1" || k == "AWS_STS_REGIONAL_ENDPOINTS" && parts[1] != "regional" {
					return ErrConfiguration
				}
				continue
			}
			return ErrConfiguration
		}
		for _, p := range []string{"TF_", "DOCKER_", "AZURE_", "GOOGLE_", "GCP_", "ARM_", "PG"} {
			if strings.HasPrefix(k, p) {
				return ErrConfiguration
			}
		}
		for _, p := range []string{"SIGNING_KEY", "SIGNING_KEY_FILE", "SIGNING_PRIVATE_KEY", "SIGNER_TOKEN", "EXECUTOR_TOKEN"} {
			if k == p {
				return ErrConfiguration
			}
		}
	}
	return nil
}
func secretFile(path string, max int64) ([]byte, error) {
	resolved, e := filepath.EvalSymlinks(path)
	if e != nil || resolved != filepath.Clean(path) {
		return nil, ErrConfiguration
	}
	s, e := os.Lstat(path)
	// Read-only mounted Secrets may be0400/0440/0444. No executable or
	// group/world-writable file is accepted, and no ambient file is searched.
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
func privateIP(ip net.IP) bool {
	v := ip.To4()
	return ip.IsLoopback() || v != nil && (v[0] == 10 || v[0] == 172 && v[1] >= 16 && v[1] <= 31 || v[0] == 192 && v[1] == 168)
}
func privateName(h string) bool {
	if ip := net.ParseIP(h); ip != nil {
		return privateIP(ip)
	}
	return regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}(?:\.[a-z0-9-]{1,63})*$`).MatchString(h)
}
func privateHost(ctx context.Context, h string) (string, error) {
	ips, e := net.DefaultResolver.LookupIP(ctx, "ip", h)
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
	// verify-full must retain the commissioned DNS name: pgx derives both
	// SNI and certificate hostname verification from it. The hosted deployment
	// additionally restricts actual RDS egress to its reviewed private CIDRs.
	q.Set("pool_max_conns", "3")
	u.RawQuery = q.Encode()
	return u.String(), nil
}

type getObject interface {
	GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error)
}
type archiveReader struct {
	client        getObject
	bucket, owner string
}

// NewPinnedReader wraps an already privately commissioned SDK transport. Its
// only operation is GetObject with an explicit VersionId. Open supplies the
// restricted local/IRSA transport; private integration callers may supply an
// independently commissioned MinIO reader without copying the readback logic.
func NewPinnedReader(client *s3.Client, bucket, owner string) (b.PinnedReader, error) {
	if client == nil || !bucketName.MatchString(bucket) || owner != "" && !regexp.MustCompile(`^[0-9]{12}$`).MatchString(owner) {
		return nil, ErrConfiguration
	}
	return archiveReader{client: client, bucket: bucket, owner: owner}, nil
}

func (r archiveReader) ReadPinned(ctx context.Context, tenant string, ref model.Document) (b.PinnedObject, error) {
	var empty b.PinnedObject
	key, version := model.String(ref, "key"), model.String(ref, "version_id")
	if !identifier.MatchString(tenant) || model.String(ref, "bucket") != r.bucket || !strings.HasPrefix(key, "tenant/"+tenant+"/") || strings.Contains(key, "..") || strings.ContainsAny(key, "\\\x00\r\n") || version == "" || version == "null" || len(version) > 1024 || !digest.MatchString(model.String(ref, "body_sha256")) {
		return empty, ErrArchive
	}
	in := &s3.GetObjectInput{Bucket: aws.String(r.bucket), Key: aws.String(key), VersionId: aws.String(version)}
	if r.owner != "" {
		in.ExpectedBucketOwner = aws.String(r.owner)
	}
	out, e := r.client.GetObject(ctx, in)
	if e != nil || out == nil || out.Body == nil {
		return empty, ErrArchive
	}
	defer out.Body.Close()
	if aws.ToString(out.VersionId) != version || out.ContentLength != nil && (*out.ContentLength < 1 || *out.ContentLength > maximumObjectBytes) {
		return empty, ErrArchive
	}
	raw, e := io.ReadAll(io.LimitReader(out.Body, maximumObjectBytes+1))
	if e != nil || len(raw) < 1 || len(raw) > maximumObjectBytes || out.ContentLength != nil && int64(len(raw)) != *out.ContentLength || b.BytesHash(raw) != model.String(ref, "body_sha256") {
		return empty, ErrArchive
	}
	// S3's response carries VersionId; bucket/key are the fixed target of
	// this authenticated request, not caller-supplied response metadata.
	return b.PinnedObject{Bucket: r.bucket, Key: key, VersionID: aws.ToString(out.VersionId), Body: raw}, nil
}

type repository interface {
	lock(context.Context, string, string) (func(), error)
	request(context.Context, string, string) (model.Document, error)
	pending(context.Context, string, string, int) ([]model.Document, error)
	snapshot(context.Context, string, string) (model.Document, error)
	members(context.Context, string, string, model.Document) ([]model.Document, error)
	append(context.Context, string, string, string, model.Document) (model.Document, bool, error)
}
type postgresRepository struct{ db *store.Store }

func (r postgresRepository) lock(ctx context.Context, tenant, id string) (func(), error) {
	conn, e := r.db.Pool.Acquire(ctx)
	if e != nil {
		return nil, ErrJob
	}
	key := tenant + ":fleet-native-assessment:" + id
	var held bool
	if e = conn.QueryRow(ctx, `SELECT pg_try_advisory_lock(hashtextextended($1,0))`, key).Scan(&held); e != nil || !held {
		conn.Release()
		return nil, ErrBusy
	}
	return func() {
		defer conn.Release()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var unlocked bool
		if conn.QueryRow(ctx, `SELECT pg_advisory_unlock(hashtextextended($1,0))`, key).Scan(&unlocked) != nil || !unlocked {
			_ = conn.Conn().Close(ctx)
		}
	}, nil
}
func (r postgresRepository) request(ctx context.Context, t, id string) (d model.Document, e error) {
	e = r.db.Do(ctx, t, func(tx *store.Tx) error { d, e = tx.FleetNativeAssessmentGet(ctx, id); return e })
	return
}
func (r postgresRepository) pending(ctx context.Context, t, after string, limit int) (d []model.Document, e error) {
	e = r.db.Do(ctx, t, func(tx *store.Tx) error { d, e = tx.FleetNativeAssessmentPending(ctx, after, limit); return e })
	return
}
func (r postgresRepository) snapshot(ctx context.Context, t, id string) (d model.Document, e error) {
	e = r.db.Do(ctx, t, func(tx *store.Tx) error { d, e = tx.FleetNativeAssessmentSnapshot(ctx, id); return e })
	return
}
func (r postgresRepository) members(ctx context.Context, t, id string, s model.Document) (d []model.Document, e error) {
	e = r.db.Do(ctx, t, func(tx *store.Tx) error { d, e = tx.FleetNativeAssessmentMembers(ctx, id, s); return e })
	return
}
func (r postgresRepository) append(ctx context.Context, t, id, hash string, in model.Document) (d model.Document, replay bool, e error) {
	e = r.db.Do(ctx, t, func(tx *store.Tx) error { d, replay, e = tx.FleetNativeAssessmentAppend(ctx, id, hash, in); return e })
	return
}
func decode(v any, out any) error {
	raw, e := json.Marshal(v)
	if e != nil || len(raw) > 32<<20 {
		return ErrJob
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	d.UseNumber()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return ErrJob
	}
	return nil
}

type nativeRepository struct {
	repository
	tenant, id string
	selection  a.Selection
	last       model.Document
	hash       string
}

func (r *nativeRepository) ResolveGroupNative(ctx context.Context, tenant, oldID, candidateID string) (b.GroupNativeSnapshot, error) {
	var s b.GroupNativeSnapshot
	if tenant != r.tenant || oldID != r.selection.Groups.OldProposal.ID || candidateID != r.selection.Groups.CandidateProposal.ID {
		return s, ErrJob
	}
	d, e := r.snapshot(ctx, tenant, r.id)
	if e != nil {
		return s, e
	}
	if decode(d, &s) != nil || b.Hash(s.Selection) != b.Hash(r.selection.Groups) || s.Selection.Binding.Old.Target.TenantID != tenant {
		return s, ErrJob
	}
	r.last = d
	r.hash = b.Hash(s)
	if r.hash != b.Hash(d) {
		return s, ErrJob
	}
	return s, nil
}

type Result struct {
	RequestID           string `json:"request_id"`
	AssessmentID        string `json:"assessment_id"`
	Existing            bool   `json:"existing"`
	ExecutionAuthorized bool   `json:"execution_authorized"`
}
type PollResult struct {
	Inspected int    `json:"inspected"`
	Completed int    `json:"completed"`
	Busy      int    `json:"busy"`
	Failed    int    `json:"failed"`
	Status    string `json:"status"`
}
type Worker struct {
	config     Config
	repository repository
	archive    b.PinnedReader
	close      func()
	ping       func(context.Context) error
	cursor     string
	retry      map[string]time.Time
}

func (w *Worker) Close() {
	if w != nil && w.close != nil {
		w.close()
	}
}
func (w *Worker) Ready(ctx context.Context) bool {
	return w != nil && w.ping != nil && w.ping(ctx) == nil
}

// New accepts only server-installed dependencies, not public evidence uploads.
// It repeats the commissioned database identity check even when a caller has
// already opened the pool through OpenRuntime. The archive is read-only.
func New(ctx context.Context, c Config, db *store.Store, archive b.PinnedReader) (*Worker, error) {
	if c.Validate() != nil || db == nil || db.Pool == nil || archive == nil {
		return nil, ErrConfiguration
	}
	var permitted bool
	e := db.Pool.QueryRow(ctx, `SELECT current_user='finops_group_assessor' AND session_user::text=$1 AND pg_has_role(session_user,'finops_group_assessor','MEMBER') AND NOT EXISTS(SELECT 1 FROM pg_roles r WHERE pg_has_role(session_user,r.oid,'MEMBER') AND (r.rolsuper OR r.rolcreaterole OR r.rolcreatedb OR r.rolbypassrls OR r.rolreplication OR r.rolname NOT IN(session_user,'finops_group_assessor')))`, db.Pool.Config().ConnConfig.User).Scan(&permitted)
	if e != nil || !permitted {
		return nil, ErrConfiguration
	}
	return &Worker{config: c, repository: postgresRepository{db}, archive: archive, ping: db.Pool.Ping}, nil
}

// Process is the same bounded job used by the daemon. The tenant is always
// commissioned configuration, never a per-job caller argument.
func (w *Worker) Process(ctx context.Context, id string) (Result, error) {
	if w == nil || w.repository == nil || w.archive == nil || w.config.Validate() != nil {
		return Result{}, ErrConfiguration
	}
	job, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	return w.process(job, id)
}

// One job holds the session lock across all object reads. Publication repeats
// source/selection/profile/member currentness in a fresh database transaction.
func (w *Worker) process(ctx context.Context, id string) (Result, error) {
	result := Result{RequestID: id}
	if !identifier.MatchString(id) {
		return result, ErrJob
	}
	release, e := w.repository.lock(ctx, w.config.TenantID, id)
	if e != nil {
		return result, e
	}
	defer release()
	d, e := w.repository.request(ctx, w.config.TenantID, id)
	if e != nil || model.String(d, "id") != id {
		return result, ErrJob
	}
	if d["assessment"] != nil {
		var old struct {
			ID string `json:"id"`
		}
		raw, _ := json.Marshal(d["assessment"])
		if json.Unmarshal(raw, &old) != nil || old.ID == "" {
			return result, ErrJob
		}
		result.AssessmentID, result.Existing = old.ID, true
		return result, nil
	}
	var selection a.Selection
	if decode(d["selection"], &selection) != nil || selection.Groups.Binding.Old.Target.TenantID != w.config.TenantID {
		return result, ErrJob
	}
	repo := &nativeRepository{repository: w.repository, tenant: w.config.TenantID, id: id, selection: selection}
	broker := b.GroupNativeBroker{Repository: repo, Archive: w.archive}
	prices, e := broker.Capture(ctx, w.config.TenantID, selection.Groups.OldProposal.ID, selection.Groups.CandidateProposal.ID)
	if e != nil || repo.last == nil || prices.SnapshotSHA256 != repo.hash {
		return result, ErrJob
	}
	docs, e := w.repository.members(ctx, w.config.TenantID, id, repo.last)
	if e != nil || len(docs) > 256 {
		return result, ErrJob
	}
	allowed := map[string]bool{}
	for _, id := range prices.CurrentMemberIDs {
		allowed[id] = true
	}
	members := []a.MemberAssessment{}
	for _, doc := range docs {
		var m a.MemberAssessment
		if decode(doc, &m) != nil {
			return result, ErrJob
		}
		if allowed[m.InstanceID] {
			members = append(members, m)
		}
	}
	assessment, e := a.Build(selection, prices, members, time.Now().UTC())
	if e != nil {
		return result, ErrJob
	}
	var body model.Document
	if decode(assessment, &body) != nil {
		return result, ErrJob
	}
	stored, replayed, e := w.repository.append(ctx, w.config.TenantID, id, repo.hash, body)
	if e != nil {
		return result, ErrJob
	}
	var accepted struct {
		ID string `json:"id"`
	}
	raw, _ := json.Marshal(stored["assessment"])
	if json.Unmarshal(raw, &accepted) != nil || accepted.ID == "" {
		return result, ErrJob
	}
	result.AssessmentID, result.Existing = accepted.ID, replayed
	return result, nil
}

// Poll advances a bounded keyset even over refused/busy jobs. Failed requests
// retain their queue row and receive a bounded in-memory retry delay; no
// failure is converted into an assessment or current source authority.
func (w *Worker) Poll(ctx context.Context) (PollResult, error) {
	out := PollResult{Status: "IDLE"}
	if w == nil || w.repository == nil || w.archive == nil {
		return out, ErrConfiguration
	}
	docs, e := w.repository.pending(ctx, w.config.TenantID, w.cursor, pageLimit)
	if e != nil {
		return out, ErrJob
	}
	if len(docs) > pageLimit {
		return out, ErrJob
	}
	if len(docs) == 0 {
		w.cursor = ""
		return out, nil
	}
	if w.retry == nil {
		w.retry = map[string]time.Time{}
	}
	for _, doc := range docs {
		id := model.String(doc, "id")
		if !identifier.MatchString(id) || id <= w.cursor {
			return out, ErrJob
		}
		w.cursor = id
		out.Inspected++
		if time.Now().Before(w.retry[id]) {
			continue
		}
		_, e = w.Process(ctx, id)
		if errors.Is(e, ErrBusy) {
			out.Busy++
			continue
		}
		if e != nil {
			out.Failed++
			out.Status = "REFUSED"
			if len(w.retry) >= 256 {
				clear(w.retry)
			}
			w.retry[id] = time.Now().Add(30 * time.Second)
			return out, ErrJob
		}
		delete(w.retry, id)
		out.Completed = 1
		out.Status = "ASSESSED"
		return out, nil
	}
	return out, nil
}
func (w *Worker) Run(ctx context.Context, report func(PollResult)) error {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for {
		p, e := w.Poll(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if e != nil && p.Status == "IDLE" {
			p.Status = "REFUSED"
		}
		if report != nil {
			report(p)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// Open never uses AWS's default credential chain. Local transport is pinned
// to private addresses; the IRSA branch reads only renewable web identity and
// the explicitly configured Ireland bucket under its dedicated read role.
func Open(ctx context.Context, c Config) (*Worker, error) {
	if c.Validate() != nil || checkEnvironment(os.Environ(), c) != nil {
		return nil, ErrConfiguration
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 10 * time.Second}).DialContext}
	httpClient := &http.Client{Timeout: 30 * time.Second, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	options := s3.Options{Region: c.ArchiveRegion, HTTPClient: httpClient, RetryMaxAttempts: 2}
	if c.ArchiveMode == LocalArchive {
		access, e := secretFile(c.ArchiveAccessKeyFile, 256)
		if e != nil {
			return nil, e
		}
		secret, e := secretFile(c.ArchiveSecretKeyFile, 256)
		if e != nil {
			return nil, e
		}
		accessText, secretText := strings.TrimSpace(string(access)), strings.TrimSpace(string(secret))
		clear(access)
		clear(secret)
		if accessText == "" || secretText == "" || strings.ContainsAny(accessText+secretText, "\x00\r\n\t ") || strings.HasPrefix(accessText, "AKIA") || strings.HasPrefix(accessText, "ASIA") {
			return nil, ErrConfiguration
		}
		u, _ := url.Parse(c.ArchiveEndpoint)
		ip, e := privateHost(ctx, u.Hostname())
		if e != nil {
			return nil, e
		}
		target, pinned := u.Host, net.JoinHostPort(ip, u.Port())
		transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			if address != target {
				return nil, ErrConfiguration
			}
			return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, pinned)
		}
		options.BaseEndpoint = aws.String(c.ArchiveEndpoint)
		options.UsePathStyle = true
		options.Credentials = credentials.NewStaticCredentialsProvider(accessText, secretText, "")
	} else {
		options.Credentials = aws.NewCredentialsCache(stscreds.NewWebIdentityRoleProvider(sts.New(sts.Options{Region: c.ArchiveRegion, HTTPClient: httpClient, RetryMaxAttempts: 2}), c.RoleARN, stscreds.IdentityTokenFile(c.WebIdentityTokenFile)))
	}
	client := s3.New(options)
	if c.ArchiveMode == IRSAArchive {
		location, e := client.GetBucketLocation(ctx, &s3.GetBucketLocationInput{Bucket: aws.String(c.ArchiveBucket), ExpectedBucketOwner: aws.String(c.ArchiveBucketOwner)})
		if e != nil || location == nil || string(location.LocationConstraint) != "eu-west-1" {
			transport.CloseIdleConnections()
			return nil, ErrConfiguration
		}
	}
	raw, e := secretFile(c.DatabaseFile, 8192)
	if e != nil {
		transport.CloseIdleConnections()
		return nil, e
	}
	dsn, e := databaseURL(ctx, raw, c.ArchiveMode == IRSAArchive)
	clear(raw)
	if e != nil {
		transport.CloseIdleConnections()
		return nil, e
	}
	db, e := store.OpenRuntime(ctx, dsn, "group-assessment-reader")
	if e != nil {
		transport.CloseIdleConnections()
		return nil, ErrConfiguration
	}
	w, e := New(ctx, c, db, archiveReader{client, c.ArchiveBucket, c.ArchiveBucketOwner})
	if e != nil {
		db.Pool.Close()
		transport.CloseIdleConnections()
		return nil, e
	}
	w.close = func() { db.Pool.Close(); transport.CloseIdleConnections() }
	return w, nil
}
