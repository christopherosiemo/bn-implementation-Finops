package fleetfixture

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
)

// JournalReview is readable preauthorization scope, NOT a signed journal
// authorization. The future repository must obtain approval of its exact
// server-derived authorization before reserving the first command.
type JournalReview struct {
	SchemaVersion     string                  `json:"schema_version"`
	Policy            fleetgroup.Policy       `json:"policy"`
	Ref               string                  `json:"ref"`
	PipelineID        string                  `json:"pipeline_id"`
	PipelineKeySHA256 string                  `json:"pipeline_key_sha256"`
	LedgerKeySHA256   string                  `json:"ledger_key_sha256"`
	Base              fleetgroup.JournalState `json:"base"`
	MaxEffects        uint64                  `json:"max_effects"`
	MaxRecords        uint64                  `json:"max_records"`
	ExpiresAt         time.Time               `json:"expires_at"`
}

// These references are private producer metadata after authenticated encrypted
// object readback. No HTTP endpoint accepts them. Public summaries expose only
// IDs/hashes; a reference by itself does not prove an artifact's authenticity.
type ArtifactReference struct {
	ID        string `json:"id"`
	Bucket    string `json:"bucket"`
	Key       string `json:"key"`
	VersionID string `json:"version_id"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
}
type GitProof struct {
	Revision         fleetgroup.GitRevision `json:"revision"`
	CommitObject     []byte                 `json:"commit_object"`
	TreeObject       []byte                 `json:"tree_object"`
	Configuration    []byte                 `json:"configuration"`
	DesiredVariables []byte                 `json:"desired_variables"`
}
type Preparation struct {
	Program       fleetgroup.GitProgram `json:"program"`
	JournalReview JournalReview         `json:"journal_review"`
	GitProofs     []GitProof            `json:"git_proofs"`
	Artifacts     []ArtifactReference   `json:"artifacts"`
}

func sha(v string) bool {
	if len(v) != 64 {
		return false
	}
	_, e := hex.DecodeString(v)
	return e == nil && strings.ToLower(v) == v
}
func gitHash(kind string, raw []byte, n int) string {
	framed := append([]byte(fmt.Sprintf("%s %d\x00", kind, len(raw))), raw...)
	if n == 40 {
		s := sha1.Sum(framed)
		return hex.EncodeToString(s[:])
	}
	s := sha256.Sum256(framed)
	return hex.EncodeToString(s[:])
}
func validateGitProof(g GitProof, previous string, base bool) error {
	if (len(g.Revision.Commit) != 40 && len(g.Revision.Commit) != 64) || len(g.CommitObject) > 65536 || len(g.TreeObject) > 4096 || len(g.Configuration) > 131072 || len(g.DesiredVariables) > 4096 || len(g.CommitObject) == 0 || gitHash("commit", g.CommitObject, len(g.Revision.Commit)) != g.Revision.Commit || gitHash("tree", g.TreeObject, len(g.Revision.Tree)) != g.Revision.Tree || fleetgroup.BytesDigest(g.Configuration) != g.Revision.ConfigurationSHA256 || fleetgroup.BytesDigest(g.DesiredVariables) != g.Revision.DesiredSHA256 {
		return ErrPreparation
	}
	head := strings.SplitN(string(g.CommitObject), "\n\n", 2)[0]
	var tree string
	parents := []string{}
	for _, line := range strings.Split(head, "\n") {
		if strings.HasPrefix(line, "tree ") {
			if tree != "" {
				return ErrPreparation
			}
			tree = strings.TrimPrefix(line, "tree ")
		}
		if strings.HasPrefix(line, "parent ") {
			parents = append(parents, strings.TrimPrefix(line, "parent "))
		}
	}
	if tree != g.Revision.Tree || (!base && (len(parents) != 1 || parents[0] != previous)) || len(parents) > 1 {
		return ErrPreparation
	}
	// Git tree records are binary and order-sensitive. Exactly two ordinary
	// committed files are allowed; no symlink, submodule or extra variable source.
	raw := g.TreeObject
	seen := map[string]bool{}
	width := len(g.Revision.Commit) / 2
	for len(raw) > 0 {
		nul := bytes.IndexByte(raw, 0)
		if nul < 0 || len(raw) < nul+1+width {
			return ErrPreparation
		}
		name := strings.TrimPrefix(string(raw[:nul]), "100644 ")
		if string(raw[:nul]) != "100644 "+name || seen[name] {
			return ErrPreparation
		}
		var content []byte
		switch name {
		case fleetgroup.GitMainPath:
			content = g.Configuration
		case fleetgroup.GitDesiredPath:
			content = g.DesiredVariables
		default:
			return ErrPreparation
		}
		if hex.EncodeToString(raw[nul+1:nul+1+width]) != gitHash("blob", content, len(g.Revision.Commit)) {
			return ErrPreparation
		}
		seen[name] = true
		raw = raw[nul+1+width:]
	}
	if len(seen) != 2 {
		return ErrPreparation
	}
	return nil
}

func ValidatePreparation(selected Proposal, p Preparation, now time.Time) error {
	program := p.Program
	if program.CreatorID != selected.CreatorID || program.Binding != selected.Binding || program.Realm != selected.Realm || program.OldTemplate != selected.Profile.Model.OldTemplate || program.CandidateTemplate != selected.Profile.Model.CandidateTemplate || program.Budget != selected.Profile.Model.Budget || program.Policy != selected.Profile.Model.Policy || len(p.GitProofs) != len(program.Manifest.Entries) || len(p.Artifacts) < 1 || len(p.Artifacts) > 128 {
		return ErrPreparation
	}
	if program.ArtifactContext.ToolchainImageSHA256 != selected.Profile.Installation.ToolchainImageSHA256 || program.ArtifactContext.TerraformVersion != selected.Profile.Installation.TerraformVersion {
		return ErrPreparation
	}
	if e := fleetgroup.ValidateGitProgram(program, fleetgroup.Expected{Binding: selected.Binding, Realm: selected.Realm}, now); e != nil {
		return e
	}
	r := p.JournalReview
	if r.SchemaVersion != "1" || r.Policy != program.Policy || r.Ref != program.Manifest.Ref || r.PipelineID != program.ArtifactContext.PipelineID || !sha(r.PipelineKeySHA256) || !sha(r.LedgerKeySHA256) || r.PipelineKeySHA256 == r.LedgerKeySHA256 || r.MaxEffects < 1 || r.MaxEffects > 32 || r.MaxRecords < 1 || r.MaxRecords > 512 || r.Base.Revision != program.Manifest.Base || r.Base.StateLineage != program.ArtifactContext.StateLineage || r.Base.StateSerial != program.ArtifactContext.InitialStateSerial || !sha(r.Base.StateSHA256) || r.Base.Model != program.Manifest.Entries[0].Before || !r.ExpiresAt.Equal(program.ExpiresAt) {
		return ErrPreparation
	}
	seen := map[string]bool{}
	for i, g := range p.GitProofs {
		entry := program.Manifest.Entries[i]
		if g.Revision != entry.Revision {
			return ErrPreparation
		}
		previous := entry.PredecessorCommit
		if e := validateGitProof(g, previous, i == 0); e != nil {
			return e
		}
		configuration, e := fleetgroup.GitFixtureConfiguration(program)
		if e != nil || !bytes.Equal(configuration, g.Configuration) {
			return ErrPreparation
		}
		desired, e := fleetgroup.GitFixtureDesired(program, entry.After)
		if e != nil || !bytes.Equal(desired, g.DesiredVariables) {
			return ErrPreparation
		}
	}
	proofs, e := ProofBytes(p.GitProofs)
	if e != nil {
		return e
	}
	proofHash := fleetgroup.BytesDigest(proofs)
	proofFound := false
	stateFound := false
	byID := map[string]ArtifactReference{}
	for _, ref := range p.Artifacts {
		if !ID(ref.ID) || ref.Bucket == "" || ref.Key == "" || ref.VersionID == "" || !sha(ref.SHA256) || ref.SizeBytes < 1 || ref.SizeBytes > 16<<20 || seen[ref.ID] {
			return ErrPreparation
		}
		seen[ref.ID] = true
		byID[ref.ID] = ref
		if ref.SHA256 == r.Base.StateSHA256 {
			stateFound = true
		}
		if ref.SHA256 == proofHash && ref.SizeBytes == int64(len(proofs)) {
			proofFound = true
		}
	}
	if !proofFound || !stateFound {
		return ErrPreparation
	}
	for _, e := range program.Evidence {
		ref, ok := byID[e.ID]
		if !ok || ref.SHA256 != e.SHA256 {
			return ErrPreparation
		}
	}
	return nil
}

func ProgramBytes(p fleetgroup.GitProgram) ([]byte, string, error) {
	b, e := json.Marshal(p)
	return b, fleetgroup.BytesDigest(b), e
}

// ProofBytes gives the private encrypted archive a deterministic payload. It
// contains sensitive state/Git provenance and is never a public API response.
func ProofBytes(p []GitProof) ([]byte, error) { return json.Marshal(p) }
