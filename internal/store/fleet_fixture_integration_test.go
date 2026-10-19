package store

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleetfixture"
	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// These are explicit private producer dependency doubles, not actual native
// Git/toolchain/object acceptance. Source and selector rows are really issued
// by independently authenticated restricted database roles.
func newFleetFixtureTest(t *testing.T) (*fleetHistoryDBTest, SelectionPair) {
	t.Helper()
	f := newFleetConfigurationTest(t)
	dir := t.TempDir()
	raw, e := os.ReadFile(filepath.Join("..", "..", "migrations", "029_fleet_fixture_proposals.sql"))
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(dir, "029_fleet_fixture_proposals.sql"), raw, 0600); e != nil {
		t.Fatal(e)
	}
	if e = f.admin.Migrate(f.ctx, dir); e != nil {
		t.Fatal(e)
	}
	login := "fixture_" + strings.ReplaceAll(model.ID(), "-", "")
	password := model.ID()
	if _, e = f.admin.Pool.Exec(f.ctx, "CREATE ROLE "+pgx.Identifier{login}.Sanitize()+" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '"+password+"' IN ROLE finops_group_fixture"); e != nil {
		t.Fatal(e)
	}
	cfg := f.admin.Pool.Config().Copy()
	cfg.ConnConfig.User = login
	cfg.ConnConfig.Password = password
	cfg.ConnConfig.RuntimeParams = map[string]string{}
	cfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
		_, e := c.Exec(ctx, "SET ROLE finops_group_fixture")
		return e
	}
	pool, e := pgxpool.NewWithConfig(f.ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	f.roles["finops_group_fixture"] = &Store{Pool: pool}
	t.Cleanup(func() {
		pool.Close()
		if _, e := f.admin.Pool.Exec(context.Background(), "DROP ROLE "+pgx.Identifier{login}.Sanitize()); e != nil {
			t.Error(e)
		}
	})
	var profile fleetfixture.Profile
	f.must("finops_group_fixture", func(tx *Tx) error {
		var e error
		profile, e = tx.FleetFixtureProfileInstall(f.ctx, fleetfixture.Installation{TemplateID: "builtin-group-fixture-v1", ToolchainImageSHA256: strings.Repeat("a", 64), TerraformVersion: "1.16.0", ReceiptID: "explicit-unit-producer-installation", SourceSHA256: strings.Repeat("b", 64)})
		return e
	})
	r := f.registration
	r.ID = "candidate-registration"
	r.FleetID = "candidate-group"
	r.ASGARN = "arn:aws:autoscaling:eu-west-1:111122223333:autoScalingGroup:aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa:autoScalingGroupName/candidate"
	d := f.definition
	d.ID = "candidate-definition"
	f.must("finops_api", func(tx *Tx) error {
		if _, e := tx.FleetHistoryRegistrationAppend(f.ctx, 0, r); e != nil {
			return e
		}
		_, e := tx.FleetDemandDefinitionAppend(f.ctx, r.ID, 0, d)
		return e
	})
	ids := []string{f.registration.ID, r.ID}
	definitions := []string{f.definition.ID, d.ID}
	selected := []string{}
	for i, id := range ids {
		m := fleetConfigurationFixture(t, "refs/heads/finops")
		if i == 1 {
			m.Terraform.ASGAddress = "module.fleet.aws_autoscaling_group.candidate"
			m.Terraform.LaunchTemplateAddress = "module.fleet.aws_launch_template.candidate"
		}
		f.must("finops_api", func(tx *Tx) error {
			decl, e := tx.FleetConfigurationAppend(f.ctx, id, 0, "operator", m)
			if e != nil {
				return e
			}
			sc, e := tx.FleetHistoryScopeCapture(f.ctx, id, definitions[i])
			if e != nil {
				return e
			}
			p, e := tx.FleetConfigurationProposalCreate(f.ctx, id, model.String(decl, "id"), model.String(sc, "id"), 1, "operator")
			if e == nil {
				selected = append(selected, model.String(p, "id"))
			}
			return e
		})
	}
	return f, SelectionPair{Request: fleetfixture.SelectionRequest{OldConfigurationProposalID: selected[0], CandidateConfigurationProposalID: selected[1], FixtureProfileID: profile.ID}, Profile: profile}
}

type SelectionPair struct {
	Request fleetfixture.SelectionRequest
	Profile fleetfixture.Profile
}

func fixtureUnitGit(source, desired []byte, parent string, index int) (g.GitRevision, []byte, []byte) {
	hash := func(kind string, b []byte) string {
		h := sha1.Sum(append([]byte(fmt.Sprintf("%s %d\x00", kind, len(b))), b...))
		return hex.EncodeToString(h[:])
	}
	tree := []byte{}
	for _, file := range []struct {
		name string
		raw  []byte
	}{{g.GitDesiredPath, desired}, {g.GitMainPath, source}} {
		oid, _ := hex.DecodeString(hash("blob", file.raw))
		tree = append(tree, []byte("100644 "+file.name+"\x00")...)
		tree = append(tree, oid...)
	}
	head := "tree " + hash("tree", tree) + "\n"
	if parent != "" {
		head += "parent " + parent + "\n"
	}
	commit := []byte(head + fmt.Sprintf("author Unit <unit@example.invalid> 1792411200 +0000\ncommitter Unit <unit@example.invalid> 1792411200 +0000\n\nPrivate unit commit %d\n", index))
	return g.GitRevision{Commit: hash("commit", commit), Tree: hash("tree", tree), ConfigurationSHA256: g.BytesDigest(source), DesiredSHA256: g.BytesDigest(desired)}, commit, tree
}
func fleetFixtureUnitPreparation(t *testing.T, p fleetfixture.Proposal) fleetfixture.Preparation {
	t.Helper()
	now := time.Now().UTC()
	model := p.Profile.Model
	program := g.GitProgram{SchemaVersion: g.GitSchemaVersion, Kind: g.Kind, ID: "unit-program-" + p.ID, Binding: p.Binding, Realm: p.Realm, CreatorID: p.CreatorID, Environment: "NON_PRODUCTION", Policy: model.Policy, OldTemplate: model.OldTemplate, CandidateTemplate: model.CandidateTemplate, Budget: model.Budget, Stages: g.DefaultStages(20), CreatedAt: now, ExpiresAt: now.Add(8 * time.Hour), Nonce: "unit-parent-nonce-" + p.ID, ArtifactContext: g.ArtifactContext{Kind: g.BuiltinFixtureArtifact, ProviderSource: g.BuiltinProvider, RepositoryID: p.ID, ToolchainImageSHA256: p.Profile.Installation.ToolchainImageSHA256, TerraformVersion: "1.16.0", PipelineID: "fixture-pipeline-" + p.Profile.Generation, Workspace: "default", StateLineage: "11111111-2222-3333-4444-555555555555", Mapping: g.ModelMapping{OldDeclaredASG: "module.fleet.aws_autoscaling_group.old", CandidateDeclaredASG: "module.fleet.aws_autoscaling_group.candidate", DeclaredListenerRule: "module.fleet.aws_lb_listener_rule.app", OldModel: "terraform_data.old", CandidateModel: "terraform_data.candidate", TrafficModel: "terraform_data.traffic"}}}
	steps, e := g.GitStageSpecifications(program)
	if e != nil {
		t.Fatal(e)
	}
	source, e := g.GitFixtureConfiguration(program)
	if e != nil {
		t.Fatal(e)
	}
	desired, _ := g.GitFixtureDesired(program, steps[0].Before)
	base, commit, tree := fixtureUnitGit(source, desired, "", 0)
	program.ArtifactContext.ConfigurationSHA256 = base.ConfigurationSHA256
	program.ArtifactContext.GitCommit = base.Commit
	program.ArtifactContext.GitTree = base.Tree
	program.Manifest = g.GitManifest{SchemaVersion: "1", Ref: "refs/heads/private-unit", Base: base}
	proofs := []fleetfixture.GitProof{}
	previous := base
	for i, s := range steps {
		s.PredecessorCommit = previous.Commit
		if i == 0 {
			s.Revision = base
		} else {
			desired, _ = g.GitFixtureDesired(program, s.After)
			s.Revision, commit, tree = fixtureUnitGit(source, desired, previous.Commit, i)
		}
		proofs = append(proofs, fleetfixture.GitProof{Revision: s.Revision, CommitObject: commit, TreeObject: tree, Configuration: source, DesiredVariables: desired})
		program.Manifest.Entries = append(program.Manifest.Entries, s)
		previous = s.Revision
	}
	program.ManifestSHA256 = g.Digest(program.Manifest)
	for _, kind := range []string{"FIXTURE_HISTORY", "FIXTURE_DEMAND", "FIXTURE_CAPACITY", "FIXTURE_CONFIGURATION", "FIXTURE_DEPENDENCY", "FIXTURE_SLO", "FIXTURE_ECONOMICS"} {
		program.Evidence = append(program.Evidence, g.EvidenceRef{Kind: kind, ID: "explicit-unit-" + kind, SHA256: strings.Repeat("c", 64), BindingSHA256: g.Digest(p.Binding), RealmSHA256: g.Digest(p.Realm), ObservedAt: now, ValidUntil: program.ExpiresAt})
	}
	raw, _ := fleetfixture.ProofBytes(proofs)
	result := fleetfixture.Preparation{Program: program, GitProofs: proofs, Artifacts: []fleetfixture.ArtifactReference{{ID: "unit-encrypted-git-proof", Bucket: "unit-private-encrypted-bucket", Key: "tenant/" + p.Binding.Old.Target.TenantID + "/proof", VersionID: "unit-pinned-version", SHA256: g.BytesDigest(raw), SizeBytes: int64(len(raw))}}, JournalReview: fleetfixture.JournalReview{SchemaVersion: "1", Policy: program.Policy, Ref: program.Manifest.Ref, PipelineID: program.ArtifactContext.PipelineID, PipelineKeySHA256: strings.Repeat("d", 64), LedgerKeySHA256: strings.Repeat("e", 64), Base: g.JournalState{Revision: base, StateLineage: program.ArtifactContext.StateLineage, StateSerial: 0, StateSHA256: strings.Repeat("f", 64), Model: steps[0].Before}, MaxEffects: 32, MaxRecords: 512, ExpiresAt: program.ExpiresAt}}
	for _, e := range program.Evidence {
		result.Artifacts = append(result.Artifacts, fleetfixture.ArtifactReference{ID: e.ID, Bucket: "unit-private-encrypted-bucket", Key: "tenant/" + p.Binding.Old.Target.TenantID + "/" + e.ID, VersionID: "unit-pinned-version", SHA256: e.SHA256, SizeBytes: 64})
	}
	result.Artifacts = append(result.Artifacts, fleetfixture.ArtifactReference{ID: "unit-base-state", Bucket: "unit-private-encrypted-bucket", Key: "tenant/" + p.Binding.Old.Target.TenantID + "/base", VersionID: "unit-pinned-version", SHA256: result.JournalReview.Base.StateSHA256, SizeBytes: 64})
	return result
}

func TestFleetFixtureRealSelectorsPrivatePreparationIndependentApproval(t *testing.T) {
	f, pair := newFleetFixtureTest(t)
	var selected model.Document
	f.must("finops_api", func(tx *Tx) error {
		var e error
		selected, e = tx.FleetFixtureProposalCreate(f.ctx, "creator", pair.Request)
		return e
	})
	id := model.String(selected, "id")
	if model.String(selected, "status") != "WAITING_FOR_PROGRAM" || model.Number(selected, "version") != 1 || selected["prepared_program"] != nil || selected["approval"] != nil {
		t.Fatal("selection became prepared or approved")
	}
	p, e := FleetFixtureProposalDocument(selected)
	if e != nil {
		t.Fatal(e)
	}
	if p.Binding.Old.Target.FleetID == p.Binding.Candidate.Target.FleetID || p.Old.CustomerStatus != "BLOCKED" || p.CustomerExecutionAuthorized || p.EstimatedSaving != nil || p.VerifiedSaving != nil {
		t.Fatal("group selection promoted customer evidence")
	}
	if e = f.run("finops_api", func(tx *Tx) error { _, e := tx.FleetFixtureApprove(f.ctx, id, 1, "approver"); return e }); !errors.Is(e, fleetfixture.ErrProgram) {
		t.Fatal("approved without privately prepared actual program", e)
	}
	prepared := fleetFixtureUnitPreparation(t, p)
	f.must("finops_group_fixture", func(tx *Tx) error { _, e := tx.FleetFixturePreparedProgramAppend(f.ctx, id, prepared); return e })
	if e = f.run("finops_api", func(tx *Tx) error { _, e := tx.FleetFixtureApprove(f.ctx, id, 2, "creator"); return e }); !errors.Is(e, fleetfixture.ErrSelfApproval) {
		t.Fatal("creator approved own program", e)
	}
	if e = f.run("finops_api", func(tx *Tx) error { _, e := tx.FleetFixtureApprove(f.ctx, id, 1, "approver"); return e }); !errors.Is(e, ErrConflict) {
		t.Fatal("stale proposal version approved", e)
	}
	f.must("finops_api", func(tx *Tx) error {
		out, e := tx.FleetFixtureApprove(f.ctx, id, 2, "independent-approver")
		if e != nil {
			return e
		}
		if model.Number(out, "version") != 3 || model.String(out, "status") != "APPROVED" {
			return errors.New("immutable approval projection missing")
		}
		approval := fleetHistoryDocument(out["approval"])
		if model.String(approval, "program_hash") != g.Digest(prepared.Program) || model.String(approval, "manifest_hash") != prepared.Program.ManifestSHA256 || model.String(approval, "journal_review_hash") != g.Digest(prepared.JournalReview) {
			return errors.New("approval did not pin exact reviewed artifacts")
		}
		readiness := fleetHistoryDocument(out["readiness"])
		if model.Bool(readiness, "runtime_available") || model.Bool(readiness, "customer_execution_authorized") || readiness["verified_saving"] != nil {
			return errors.New("approval enabled runtime or money")
		}
		return nil
	})
	for _, role := range []string{"finops_api", "finops_ingester", "finops_worker", "finops_signer", "finops_executor", "finops_activity"} {
		f.denied(role, func(tx *Tx) error { _, e := tx.FleetFixturePreparedProgramAppend(f.ctx, id, prepared); return e })
	}
	for _, table := range []string{"fleet_fixture_proposals", "fleet_fixture_prepared_programs", "fleet_fixture_approvals"} {
		for _, sql := range []string{"UPDATE public." + table + " SET tenant_id=tenant_id", "DELETE FROM public." + table} {
			f.denied("finops_api", func(tx *Tx) error { _, e := tx.Exec(f.ctx, sql+" WHERE tenant_id=$1", f.tenant); return e })
		}
	}
	if e = f.roles["finops_api"].Do(f.ctx, f.tenant+"-foreign", func(tx *Tx) error {
		_, e := tx.FleetFixtureProposalGet(f.ctx, id)
		if !errors.Is(e, pgx.ErrNoRows) {
			return errors.New("foreign tenant read exposed proposal")
		}
		rows, e := tx.FleetFixtureProposalPage(f.ctx, p.WorkloadID, "", 100)
		if e == nil && len(rows) != 0 {
			return errors.New("foreign tenant page leaked")
		}
		return e
	}); e != nil {
		t.Fatal(e)
	}
}

func TestFleetFixtureCurrentnessSQLSealAndHistoricalRead(t *testing.T) {
	f, pair := newFleetFixtureTest(t)
	var first model.Document
	f.must("finops_api", func(tx *Tx) error {
		var e error
		first, e = tx.FleetFixtureProposalCreate(f.ctx, "creator", pair.Request)
		return e
	})
	id := model.String(first, "id")
	p, _ := FleetFixtureProposalDocument(first)
	// A direct SQL writer cannot replace the selected group or seal authority,
	// even after recomputing its own document bytes and hash.
	for _, field := range []string{"customer_execution_authorized", "verified_saving", "binding", "profile"} {
		bad := fleetHistoryDocument(p)
		bad["id"] = model.ID()
		if field == "customer_execution_authorized" {
			bad[field] = true
		} else {
			bad[field] = "forged"
		}
		raw, _ := json.Marshal(bad)
		f.denied("finops_api", func(tx *Tx) error {
			_, e := tx.Exec(f.ctx, `INSERT INTO public.fleet_fixture_proposals(tenant_id,id,workload_id,profile_id,profile_generation,old_configuration_proposal_id,candidate_configuration_proposal_id,content_hash,document,raw_document) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, f.tenant, bad["id"], p.WorkloadID, p.Profile.ID, p.Profile.Generation, pair.Request.OldConfigurationProposalID, pair.Request.CandidateConfigurationProposalID, g.BytesDigest(raw), raw, raw)
			return e
		})
	}
	// Refreshed source identity/config is checked at approval; old immutable
	// rows remain readable after revocation and never acquire current authority.
	f.must("finops_api", func(tx *Tx) error {
		s, e := tx.SourceGet(f.ctx, p.Binding.Old.SourceID)
		if e != nil {
			return e
		}
		s["enabled"] = false
		_, e = tx.SourceUpdate(f.ctx, p.Binding.Old.SourceID, model.Number(s, "version"), s)
		return e
	})
	if e := f.run("finops_api", func(tx *Tx) error { _, e := tx.FleetFixtureApprove(f.ctx, id, 1, "independent"); return e }); !errors.Is(e, fleetfixture.ErrCurrent) {
		t.Fatal("revoked selected source remained approvable", e)
	}
	f.must("finops_api", func(tx *Tx) error {
		out, e := tx.FleetFixtureProposalGet(f.ctx, id)
		if e == nil && model.String(out, "hash") != model.String(first, "hash") {
			return errors.New("revocation rewrote captured proposal")
		}
		return e
	})
}

func TestFleetFixturePrivateSQLPinsAndPreparationProofClosure(t *testing.T) {
	f, pair := newFleetFixtureTest(t)
	var row model.Document
	f.must("finops_api", func(tx *Tx) error {
		var e error
		row, e = tx.FleetFixtureProposalCreate(f.ctx, "creator", pair.Request)
		return e
	})
	p, _ := FleetFixtureProposalDocument(row)
	good := fleetFixtureUnitPreparation(t, p)
	copyPreparation := func() fleetfixture.Preparation {
		raw, _ := json.Marshal(good)
		var out fleetfixture.Preparation
		_ = json.Unmarshal(raw, &out)
		return out
	}
	for _, change := range []struct {
		name  string
		alter func(*fleetfixture.Preparation)
	}{
		{"missing evidence archive", func(v *fleetfixture.Preparation) { v.Artifacts = v.Artifacts[:1] }},
		{"tampered Git commit", func(v *fleetfixture.Preparation) {
			v.GitProofs[1].CommitObject = append(v.GitProofs[1].CommitObject, byte('x'))
		}},
		{"changed two-file desired source", func(v *fleetfixture.Preparation) { v.GitProofs[1].DesiredVariables = []byte(`{"old_count":0}`) }},
		{"wrong installed toolchain", func(v *fleetfixture.Preparation) {
			v.Program.ArtifactContext.ToolchainImageSHA256 = strings.Repeat("9", 64)
		}},
		{"same pipeline and ledger keys", func(v *fleetfixture.Preparation) { v.JournalReview.LedgerKeySHA256 = v.JournalReview.PipelineKeySHA256 }},
	} {
		v := copyPreparation()
		change.alter(&v)
		if e := fleetfixture.ValidatePreparation(p, v, time.Now().UTC()); e == nil {
			t.Fatal("private proof closure accepted", change.name)
		}
	}
	for _, kind := range []string{"missing base archive", "unbound evidence hash", "null pipeline key", "null effects bound", "mapping rewrite"} {
		program, _ := json.Marshal(good.Program)
		review := fleetHistoryDocument(good.JournalReview)
		refs := append([]fleetfixture.ArtifactReference{}, good.Artifacts...)
		switch kind {
		case "missing base archive":
			refs = refs[:len(refs)-1]
		case "unbound evidence hash":
			refs[1].SHA256 = strings.Repeat("8", 64)
		case "null pipeline key":
			review["pipeline_key_sha256"] = nil
		case "null effects bound":
			review["max_effects"] = nil
		case "mapping rewrite":
			d := fleetHistoryDocument(good.Program)
			ctx := fleetHistoryDocument(d["artifact_context"])
			mapping := fleetHistoryDocument(ctx["mapping"])
			mapping["old_declared_asg"] = "aws_autoscaling_group.unrelated"
			ctx["mapping"] = mapping
			d["artifact_context"] = ctx
			program, _ = json.Marshal(d)
		}
		rawReview, _ := json.Marshal(review)
		rawRefs, _ := json.Marshal(refs)
		proof, _ := fleetfixture.ProofBytes(good.GitProofs)
		f.denied("finops_group_fixture", func(tx *Tx) error {
			_, e := tx.Exec(f.ctx, `INSERT INTO public.fleet_fixture_prepared_programs(tenant_id,id,proposal_id,program_hash,manifest_hash,journal_review_hash,program,program_raw,journal_review,journal_review_raw,proof_hash,artifact_refs) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, f.tenant, model.ID(), p.ID, g.BytesDigest(program), good.Program.ManifestSHA256, g.BytesDigest(rawReview), program, program, rawReview, rawReview, g.BytesDigest(proof), rawRefs)
			return e
		})
	}
	// The template/profile installer cannot be reached by API, analytical,
	// signing or execution identities, even with valid installation metadata.
	for _, role := range []string{"finops_api", "finops_ingester", "finops_worker", "finops_signer", "finops_executor"} {
		f.denied(role, func(tx *Tx) error { _, e := tx.FleetFixtureProfileInstall(f.ctx, p.Profile.Installation); return e })
	}
	var forwardMember, financialMember bool
	if e := f.roles["finops_group_fixture"].Pool.QueryRow(f.ctx, `SELECT pg_has_role(current_user,'finops_executor','MEMBER') OR pg_has_role(current_user,'finops_signer','MEMBER'),has_table_privilege(current_user,'public.savings_ledger','INSERT')`).Scan(&forwardMember, &financialMember); e != nil || forwardMember || financialMember {
		t.Fatal("fixture producer acquired existing execution or ledger authority", e)
	}
}
