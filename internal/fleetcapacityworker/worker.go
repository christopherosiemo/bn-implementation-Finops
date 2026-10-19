package fleetcapacityworker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	a "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetassessment"
	archive "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetassessmentworker"
	b "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetbilling"
	c "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetcapacity"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/native"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/workload"
	"github.com/jackc/pgx/v5"
)

type repository interface {
	lock(context.Context, string, string) (func(), error)
	request(context.Context, string, string) (model.Document, error)
	pending(context.Context, string, string) ([]model.Document, error)
	resolve(context.Context, string, string) (model.Document, error)
	scope(context.Context, string, string) (model.Document, error)
	scopeAppend(context.Context, string, string, string, model.Document) (model.Document, error)
	evidence(context.Context, string, string) (model.Document, error)
	members(context.Context, string, string, string) ([]model.Document, error)
	inputs(context.Context, string, string, string) (model.Document, error)
	append(context.Context, string, string, string, model.Document) (model.Document, error)
	complete(context.Context, string, string, model.Document) (model.Document, bool, error)
}
type postgresRepository struct{ db *store.Store }

func (r postgresRepository) lock(ctx context.Context, t, id string) (func(), error) {
	conn, e := r.db.Pool.Acquire(ctx)
	if e != nil {
		return nil, ErrJob
	}
	key := t + ":fleet-native-capacity:" + id
	var held bool
	if conn.QueryRow(ctx, `SELECT pg_try_advisory_lock(hashtextextended($1,0))`, key).Scan(&held) != nil {
		conn.Release()
		return nil, ErrJob
	}
	if !held {
		conn.Release()
		return nil, ErrBusy
	}
	return func() {
		defer conn.Release()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var released bool
		if conn.QueryRow(ctx, `SELECT pg_advisory_unlock(hashtextextended($1,0))`, key).Scan(&released) != nil || !released {
			_ = conn.Conn().Close(ctx)
		}
	}, nil
}
func (r postgresRepository) request(ctx context.Context, t, id string) (d model.Document, e error) {
	e = r.db.Do(ctx, t, func(tx *store.Tx) error { d, e = tx.FleetCapacityBatchGet(ctx, id); return e })
	return
}
func (r postgresRepository) pending(ctx context.Context, t, after string) (d []model.Document, e error) {
	e = r.db.Do(ctx, t, func(tx *store.Tx) error { d, e = tx.FleetCapacityBatchPending(ctx, after, 16); return e })
	return
}
func (r postgresRepository) resolve(ctx context.Context, t, id string) (d model.Document, e error) {
	e = r.db.Do(ctx, t, func(tx *store.Tx) error { d, e = tx.FleetCapacityBatchResolve(ctx, id); return e })
	return
}
func (r postgresRepository) scope(ctx context.Context, t, id string) (d model.Document, e error) {
	e = r.db.Do(ctx, t, func(tx *store.Tx) error { d, e = tx.FleetCapacityBatchScopeGet(ctx, id); return e })
	return
}
func (r postgresRepository) scopeAppend(ctx context.Context, t, id, hash string, in model.Document) (d model.Document, e error) {
	e = r.db.Do(ctx, t, func(tx *store.Tx) error { d, _, e = tx.FleetCapacityBatchScopeAppend(ctx, id, hash, in); return e })
	return
}
func (r postgresRepository) evidence(ctx context.Context, t, id string) (d model.Document, e error) {
	e = r.db.Do(ctx, t, func(tx *store.Tx) error { d, e = tx.FleetCapacityBatchScopeEvidence(ctx, id); return e })
	return
}
func (r postgresRepository) members(ctx context.Context, t, id, after string) (d []model.Document, e error) {
	e = r.db.Do(ctx, t, func(tx *store.Tx) error { d, e = tx.FleetCapacityBatchMemberPage(ctx, id, after, 101); return e })
	return
}
func (r postgresRepository) inputs(ctx context.Context, t, id, instance string) (d model.Document, e error) {
	e = r.db.Do(ctx, t, func(tx *store.Tx) error { d, e = tx.FleetCapacityBatchMemberInputs(ctx, id, instance); return e })
	return
}
func (r postgresRepository) append(ctx context.Context, t, id, hash string, in model.Document) (d model.Document, e error) {
	e = r.db.Do(ctx, t, func(tx *store.Tx) error { d, _, e = tx.FleetCapacityBatchMemberAppend(ctx, id, hash, in); return e })
	return
}
func (r postgresRepository) complete(ctx context.Context, t, id string, in model.Document) (d model.Document, replay bool, e error) {
	e = r.db.Do(ctx, t, func(tx *store.Tx) error { d, replay, e = tx.FleetCapacityBatchComplete(ctx, id, in); return e })
	return
}

func decode(v any, out any) error {
	raw, e := json.Marshal(v)
	if e != nil || len(raw) > 32<<20 {
		return ErrJob
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return ErrJob
	}
	return nil
}
func document(v any) model.Document { out := model.Document{}; _ = decode(v, &out); return out }

// repositoryError preserves only the repository's explicit contention signal.
// Permission, integrity and other failures retain the normal refusal backoff.
func repositoryError(err error) error {
	if errors.Is(err, store.ErrFleetFixtureBusy) || errors.Is(err, ErrBusy) {
		return ErrBusy
	}
	return ErrJob
}

type pair struct {
	Receipt  model.Document `json:"receipt"`
	Revision model.Document `json:"revision"`
}
type selectionSnapshot struct {
	Selection              a.Selection               `json:"selection"`
	Profile                model.Document            `json:"profile"`
	Registrations          map[string]model.Document `json:"registrations"`
	Memberships            []pair                    `json:"memberships"`
	Templates              []pair                    `json:"templates"`
	Hardware               []pair                    `json:"hardware"`
	Resources, Connections []model.Document
}

type Result struct {
	RequestID           string `json:"request_id"`
	Members             int    `json:"members"`
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
	population PopulationReader
	calculator c.Calculator
	ping       func(context.Context) error
	close      func()
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
func New(ctx context.Context, config Config, db *store.Store, archiveReader b.PinnedReader, population PopulationReader, calculator c.Calculator) (*Worker, error) {
	if config.Validate() != nil || db == nil || db.Pool == nil || archiveReader == nil || population == nil || calculator == nil {
		return nil, ErrConfiguration
	}
	var allowed bool
	e := db.Pool.QueryRow(ctx, `SELECT current_user='finops_group_capacity' AND session_user::text=$1 AND pg_has_role(session_user,'finops_group_capacity','MEMBER') AND NOT EXISTS(SELECT 1 FROM pg_roles r WHERE pg_has_role(session_user,r.oid,'MEMBER') AND (r.rolsuper OR r.rolcreaterole OR r.rolcreatedb OR r.rolbypassrls OR r.rolreplication OR r.rolname NOT IN(session_user,'finops_group_capacity')))`, db.Pool.Config().ConnConfig.User).Scan(&allowed)
	if e != nil || !allowed {
		return nil, ErrConfiguration
	}
	return &Worker{config: config, repository: postgresRepository{db}, archive: archiveReader, population: population, calculator: calculator, ping: db.Pool.Ping}, nil
}
func (w *Worker) load(ctx context.Context, p pair, budget *int) (c.NativeEvidence, error) {
	e := c.NativeEvidence{Receipt: p.Receipt, Revision: p.Revision}
	for i, ref := range []model.Document{document(p.Receipt["raw_object"]), document(p.Revision["raw_object"])} {
		if i == 1 && b.Hash(ref) == b.Hash(p.Receipt["raw_object"]) {
			e.RevisionRaw = e.Raw
			continue
		}
		o, err := w.archive.ReadPinned(ctx, w.config.Archive.TenantID, ref)
		if err != nil || o.Bucket != model.String(ref, "bucket") || o.Key != model.String(ref, "key") || o.VersionID != model.String(ref, "version_id") || b.BytesHash(o.Body) != model.String(ref, "body_sha256") {
			return e, ErrJob
		}
		*budget += len(o.Body)
		if *budget > 64<<20 {
			return e, ErrJob
		}
		if i == 0 {
			e.Raw = o.Body
		} else {
			e.RevisionRaw = o.Body
		}
	}
	return e, nil
}
func (w *Worker) capture(ctx context.Context, id string, selection a.Selection) (c.ScopeCapture, error) {
	d, e := w.repository.resolve(ctx, w.config.Archive.TenantID, id)
	if e != nil {
		return c.ScopeCapture{}, repositoryError(e)
	}
	var s selectionSnapshot
	if decode(d, &s) != nil || b.Hash(s.Selection) != b.Hash(selection) || len(s.Memberships) > 2 || len(s.Templates) > 2 {
		return c.ScopeCapture{}, ErrJob
	}
	in := c.ScopeInput{RequestID: id, Selection: selection}
	budget := 0
	for _, p := range s.Memberships {
		native, e := w.load(ctx, p, &budget)
		if e != nil {
			return c.ScopeCapture{}, e
		}
		switch model.String(p.Receipt, "history_registration_id") {
		case selection.Groups.Binding.Old.Registration.ID:
			if in.OldMembership != nil {
				return c.ScopeCapture{}, ErrJob
			}
			in.OldMembership = &native
		case selection.Groups.Binding.Candidate.Registration.ID:
			if in.CandidateMembership != nil {
				return c.ScopeCapture{}, ErrJob
			}
			in.CandidateMembership = &native
		default:
			return c.ScopeCapture{}, ErrJob
		}
	}
	for _, p := range s.Templates {
		native, e := w.load(ctx, p, &budget)
		if e != nil {
			return c.ScopeCapture{}, e
		}
		in.Templates = append(in.Templates, native)
	}
	capture, e := c.CaptureScope(in, time.Now().UTC())
	if e != nil {
		return capture, e
	}
	issued, e := w.repository.scopeAppend(ctx, w.config.Archive.TenantID, id, b.Hash(d), document(capture))
	if e != nil {
		return c.ScopeCapture{}, repositoryError(e)
	}
	if decode(issued, &capture) != nil || c.ScopeHash(capture) != capture.Scope.SnapshotSHA256 {
		return c.ScopeCapture{}, ErrJob
	}
	return capture, nil
}

// candidate re-decodes the original selected immutable raw object on resume.
// Its historical collection time is used only for parsing that issued scope;
// MemberInputs/Append independently require actual current source/native pins.
func (w *Worker) candidate(ctx context.Context, id string, scope c.ScopeCapture) (*c.CandidateTemplate, error) {
	if scope.CandidateTemplate == nil {
		return nil, nil
	}
	d, e := w.repository.evidence(ctx, w.config.Archive.TenantID, id)
	if e != nil {
		return nil, repositoryError(e)
	}
	var body struct {
		Scope    c.ScopeCapture `json:"scope_record"`
		Evidence []pair         `json:"native_evidence"`
	}
	if decode(d, &body) != nil || b.Hash(body.Scope) != b.Hash(scope) || len(body.Evidence) > 4 {
		return nil, ErrJob
	}
	budget := 0
	for _, p := range body.Evidence {
		if model.String(p.Receipt, "id") != scope.CandidateTemplate.SourcePin.ReceiptID {
			continue
		}
		native, e := w.load(ctx, p, &budget)
		if e != nil {
			return nil, e
		}
		historical, e := time.Parse(time.RFC3339Nano, model.String(p.Receipt, "collected_at"))
		if e != nil {
			return nil, ErrJob
		}
		decoded, e := c.DecodeCandidateTemplate(native, scope.Scope.Selection.Groups.Binding.Candidate, provider.FleetLaunchTemplate{ID: scope.CandidateTemplate.ID, Version: scope.CandidateTemplate.Version}, historical)
		if e != nil || b.Hash(decoded) != b.Hash(scope.CandidateTemplate) {
			return nil, ErrJob
		}
		return decoded, nil
	}
	return nil, ErrJob
}
func memberRef(d model.Document) (c.MemberReference, error) {
	var out c.MemberReference
	out.InstanceID = model.String(d, "instance_id")
	out.ResultID = model.String(d, "id")
	out.SHA256 = model.String(d, "sha256")
	out.Status = model.String(d, "status")
	out.ModelEvaluated = model.Bool(d, "model_evaluated")
	if d["capacity_suitable"] != nil {
		v, ok := d["capacity_suitable"].(bool)
		if !ok {
			return out, ErrJob
		}
		out.CapacitySuitable = &v
	}
	return out, nil
}
func (w *Worker) member(ctx context.Context, id, instance string, scope c.ScopeCapture, loadCandidate func(context.Context) (*c.CandidateTemplate, error)) (c.MemberReference, error) {
	input, e := w.repository.inputs(ctx, w.config.Archive.TenantID, id, instance)
	if e != nil {
		return c.MemberReference{}, repositoryError(e)
	}
	if model.String(input, "instance_id") != instance || b.Hash(input["scope_record"]) != b.Hash(scope) {
		return c.MemberReference{}, ErrJob
	}
	now := time.Now().UTC()
	var result c.MemberResult
	if !model.Bool(input, "current") {
		reason := "FLEET_CAPACITY_SCOPE_NOT_CURRENT"
		if reasons := model.Strings(input, "reason_codes"); len(reasons) > 0 {
			reason = reasons[0]
		}
		result, e = c.Unavailable(scope.Scope, id, instance, reason, now)
	} else {
		candidate, err := loadCandidate(ctx)
		if err != nil {
			return c.MemberReference{}, err
		}
		if candidate == nil {
			result, e = c.Unavailable(scope.Scope, id, instance, "CAPACITY_CANDIDATE_NATIVE_TEMPLATE_UNAVAILABLE", now)
		} else {
			resource, connection, hardware := document(input["resource"]), document(input["connection"]), document(input["hardware"])
			var hp pair
			if decode(hardware, &hp) != nil {
				return c.MemberReference{}, ErrJob
			}
			budget := 0
			nativeHardware, err := w.load(ctx, hp, &budget)
			if err != nil {
				return c.MemberReference{}, err
			}
			profileDoc := document(input["profile"])
			for _, key := range []string{"tenant_id", "hash", "created_at", "writer_role"} {
				delete(profileDoc, key)
			}
			raw, err := json.Marshal(profileDoc)
			if err != nil {
				return c.MemberReference{}, ErrJob
			}
			profile, err := workload.Decode(raw)
			if err != nil {
				return c.MemberReference{}, ErrJob
			}
			population, err := w.population.Read(ctx, native.CapacityInputRequest{TenantID: w.config.Archive.TenantID, ConnectionID: model.String(connection, "id"), ConfigHash: model.String(connection, "config_hash"), SafetyProfileID: profile.ID, SafetyProfileVersion: profile.Version})
			if err != nil {
				result, e = c.Unavailable(scope.Scope, id, instance, "CAPACITY_MEMBER_TELEMETRY_POPULATION_UNAVAILABLE", time.Now().UTC())
			} else {
				plan, err := c.Prepare(c.MemberInput{BatchID: id, Scope: scope.Scope, InstanceID: instance, Resource: resource, Connection: connection, Profile: profile, Population: &population, Hardware: hp.Receipt, HardwareEvidence: &nativeHardware, Candidate: candidate}, time.Now().UTC())
				if err != nil {
					return c.MemberReference{}, err
				}
				result, e = c.Evaluate(ctx, plan, w.calculator, time.Now().UTC())
			}
		}
	}
	if e != nil {
		return c.MemberReference{}, e
	}
	stored, e := w.repository.append(ctx, w.config.Archive.TenantID, id, b.Hash(input), document(result))
	if e != nil {
		return c.MemberReference{}, repositoryError(e)
	}
	var accepted c.MemberResult
	if decode(stored["member"], &accepted) != nil || accepted.InstanceID != instance || b.Hash(accepted.Scope) != b.Hash(scope.Scope) || model.String(stored, "sha256") != b.Hash(accepted) {
		return c.MemberReference{}, ErrJob
	}
	return c.MemberReference{InstanceID: instance, ResultID: accepted.ID, SHA256: b.Hash(accepted), Status: accepted.Status, ModelEvaluated: accepted.ModelEvaluated, CapacitySuitable: accepted.CapacitySuitable}, nil
}
func (w *Worker) Process(ctx context.Context, id string) (Result, error) {
	result := Result{RequestID: id}
	if w == nil || w.repository == nil || w.archive == nil || w.population == nil || w.calculator == nil || w.config.Validate() != nil {
		return result, ErrConfiguration
	}
	if !identifier.MatchString(id) {
		return result, ErrJob
	}
	job, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	tenant := w.config.Archive.TenantID
	release, e := w.repository.lock(job, tenant, id)
	if e != nil {
		return result, repositoryError(e)
	}
	defer release()
	request, e := w.repository.request(job, tenant, id)
	if e != nil {
		return result, repositoryError(e)
	}
	if model.String(request, "id") != id {
		return result, ErrJob
	}
	if request["batch"] != nil {
		result.Existing = true
		return result, nil
	}
	var selection a.Selection
	if decode(request["selection"], &selection) != nil || selection.Groups.Binding.Old.Target.TenantID != tenant {
		return result, ErrJob
	}
	var scope c.ScopeCapture
	d, e := w.repository.scope(job, tenant, id)
	if errors.Is(e, pgx.ErrNoRows) {
		scope, e = w.capture(job, id, selection)
	} else if e == nil {
		e = decode(d, &scope)
	}
	if e != nil {
		return result, repositoryError(e)
	}
	if b.Hash(scope.Scope.Selection) != b.Hash(selection) || c.ScopeHash(scope) != scope.Scope.SnapshotSHA256 || scope.RequestID != id {
		return result, ErrJob
	}
	refs := map[string]c.MemberReference{}
	after := ""
	for {
		rows, e := w.repository.members(job, tenant, id, after)
		if e != nil {
			return result, repositoryError(e)
		}
		if len(rows) > 101 {
			return result, ErrJob
		}
		for _, d := range rows {
			ref, e := memberRef(d)
			if e != nil || ref.ResultID <= after || refs[ref.InstanceID].ResultID != "" {
				return result, ErrJob
			}
			after = ref.ResultID
			refs[ref.InstanceID] = ref
			if len(refs) > c.MaximumMembers {
				return result, ErrJob
			}
		}
		if len(rows) < 101 {
			break
		}
	}
	var candidate *c.CandidateTemplate
	loaded := false
	loadCandidate := func(ctx context.Context) (*c.CandidateTemplate, error) {
		if !loaded {
			var err error
			candidate, err = w.candidate(ctx, id, scope)
			if err != nil {
				return nil, err
			}
			loaded = true
		}
		return candidate, nil
	}
	for _, instance := range scope.Scope.CurrentMemberIDs {
		if refs[instance].ResultID != "" {
			continue
		}
		if job.Err() != nil {
			return result, ErrJob
		}
		ref, e := w.member(job, id, instance, scope, loadCandidate)
		if e != nil {
			return result, e
		}
		refs[instance] = ref
	}
	list := []c.MemberReference{}
	for _, ref := range refs {
		list = append(list, ref)
	}
	summary, e := c.SummarizeReferences(scope.Scope, list)
	if e != nil {
		return result, e
	}
	_, result.Existing, e = w.repository.complete(job, tenant, id, document(summary))
	result.Members = len(summary.Members)
	if e != nil {
		return result, repositoryError(e)
	}
	return result, nil
}
func (w *Worker) Poll(ctx context.Context) (PollResult, error) {
	out := PollResult{Status: "IDLE"}
	if w == nil || w.repository == nil {
		return out, ErrConfiguration
	}
	rows, e := w.repository.pending(ctx, w.config.Archive.TenantID, w.cursor)
	if e != nil {
		return out, repositoryError(e)
	}
	if w.retry == nil {
		w.retry = map[string]time.Time{}
	}
	for _, d := range rows {
		id := model.String(d, "id")
		if id <= w.cursor || !identifier.MatchString(id) {
			return out, ErrJob
		}
		w.cursor = id
		out.Inspected++
		if time.Now().Before(w.retry[id]) {
			continue
		}
		_, e := w.Process(ctx, id)
		switch {
		case e == nil:
			out.Completed++
			delete(w.retry, id)
		case errors.Is(e, ErrBusy):
			out.Busy++
		default:
			out.Failed++
			if len(w.retry) >= 1024 {
				w.retry = map[string]time.Time{}
			}
			w.retry[id] = time.Now().Add(time.Minute)
		}
	}
	if len(rows) < 16 {
		w.cursor = ""
	}
	if out.Completed > 0 {
		out.Status = "PROCESSED"
	} else if out.Failed > 0 {
		out.Status = "REFUSED"
	}
	return out, nil
}
func (w *Worker) Run(ctx context.Context, report func(PollResult)) error {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		out, e := w.Poll(ctx)
		if e != nil {
			out.Status = "REFUSED"
		}
		if report != nil {
			report(out)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
func Open(ctx context.Context, config Config) (*Worker, error) {
	if config.Validate() != nil {
		return nil, ErrConfiguration
	}
	setup, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	reader, closeArchive, e := archive.OpenReadOnlyArchive(setup, config.Archive)
	if e != nil {
		return nil, ErrConfiguration
	}
	population, calculator, closeHTTP, e := OpenHTTPDependencies(setup, config)
	if e != nil {
		closeArchive()
		return nil, e
	}
	raw, e := privateFile(config.Archive.DatabaseFile, 8192)
	if e != nil {
		closeArchive()
		closeHTTP()
		return nil, e
	}
	dsn, e := databaseURL(setup, raw, config.Archive.ArchiveMode == archive.IRSAArchive)
	clear(raw)
	if e != nil {
		closeArchive()
		closeHTTP()
		return nil, e
	}
	db, e := store.OpenRuntime(setup, dsn, "group-capacity-evaluator")
	if e != nil {
		closeArchive()
		closeHTTP()
		return nil, ErrConfiguration
	}
	worker, e := New(setup, config, db, reader, population, calculator)
	if e != nil {
		db.Pool.Close()
		closeArchive()
		closeHTTP()
		return nil, e
	}
	worker.close = func() { db.Pool.Close(); closeArchive(); closeHTTP() }
	return worker, nil
}
