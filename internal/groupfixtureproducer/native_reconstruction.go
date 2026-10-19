package groupfixtureproducer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	ff "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetfixture"
	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
)

var ErrReconstruction = errors.New("GROUP_FIXTURE_RECONSTRUCTION_BINDING_INVALID")

const nativeTerminalDomain = "finops/group-fixture/native-terminal/v1\x00"
const nativeRetirementDomain = "finops/group-fixture/workspace-retirement/v1\x00"
const nativeReconstructionAlgorithm = "Ed25519/group-fixture-native/v1"

const ReconstructionOriginal = "ORIGINAL"
const ReconstructionRecoverySegment = "RECOVERY_SEGMENT"
const ReconstructionInitial = "INITIAL_PREPARED"
const ReconstructionTerminal = "CURRENT_APPLIED_TERMINAL"
const ReconstructionObservation = "OBSERVE_EXISTING_APPLIED_TERMINAL"

// NativeWorkspace is an operator/controller-installed runtime identity. It is
// not inferred from a PID, a lease, a current journal head or a request body.
// This first materializer supports explicitly isolated Docker fixtures only.
type NativeWorkspace struct {
	Generation  string `json:"generation"`
	RuntimeID   string `json:"runtime_id"`
	ImageSHA256 string `json:"image_sha256"`
}

// NativeWorkspaceRetirement is issued by an independently commissioned
// controller only after it observed removal of the exact owned old runtime.
// The native worker neither owns that key nor accesses the Docker socket.
// The current-generation registry must independently authenticate New.
type NativeWorkspaceRetirement struct {
	SchemaVersion string          `json:"schema_version"`
	ID            string          `json:"id"`
	TenantID      string          `json:"tenant_id"`
	ChainID       string          `json:"chain_id"`
	ProgramSHA256 string          `json:"program_sha256"`
	Method        string          `json:"method"`
	Old           NativeWorkspace `json:"old"`
	New           NativeWorkspace `json:"new"`
	ObservedAt    time.Time       `json:"observed_at"`
}
type NativeRetirementEnvelope struct {
	Retirement NativeWorkspaceRetirement `json:"retirement"`
	Algorithm  string                    `json:"algorithm"`
	Signature  string                    `json:"signature"`
}

type NativeReconstructionRefs struct {
	Review  ff.ArtifactReference `json:"review"`
	Capture ff.ArtifactReference `json:"capture"`
	After   ff.ArtifactReference `json:"after"`
}

// NativeTerminal is an immutable positive native inspection, made before the
// old workspace was lost. ObservedAt is the inspection time, not a fabricated
// Terraform completion time. It is never renewed during reconstruction.
// Encrypted objects and a pipeline-writer database role alone are insufficient:
// the independently pinned pipeline signature binds every selected version.
type NativeTerminal struct {
	SchemaVersion       string                   `json:"schema_version"`
	ID                  string                   `json:"id"`
	TenantID            string                   `json:"tenant_id"`
	ChainID             string                   `json:"chain_id"`
	ProgramSHA256       string                   `json:"program_sha256"`
	AuthorizationSHA256 string                   `json:"authorization_sha256"`
	CommandSHA256       string                   `json:"command_sha256"`
	OperationID         string                   `json:"operation_id"`
	Fence               uint64                   `json:"fence"`
	ArtifactSHA256      string                   `json:"artifact_sha256"`
	PreparationSHA256   string                   `json:"preparation_sha256"`
	Workspace           NativeWorkspace          `json:"workspace"`
	References          NativeReconstructionRefs `json:"references"`
	Before              g.JournalState           `json:"before"`
	After               g.JournalState           `json:"after"`
	Head                g.JournalHeadEnvelope    `json:"head"`
	ObservedAt          time.Time                `json:"observed_at"`
}
type NativeTerminalEnvelope struct {
	Terminal  NativeTerminal `json:"terminal"`
	Algorithm string         `json:"algorithm"`
	Signature string         `json:"signature"`
}

// NativeReconstructionSnapshot is supplied ONLY by the commissioned trusted
// repository/controller. Selected references must be immutable issued IDs,
// never "latest by label". Continuation duties cannot be adapted to JournalView.
type NativeReconstructionSnapshot struct {
	Kind              string
	Mode              string
	ChainID           string
	Selected          ff.Proposal
	Prepared          ff.Preparation
	View              g.JournalView
	Keys              g.JournalKeys
	ExpectedHead      g.JournalHeadRef
	CurrentHeadSHA256 string
	Workspace         NativeWorkspace
	RetirementKey     ed25519.PublicKey
	Retirement        *NativeRetirementEnvelope
	CommandID         string
	References        NativeReconstructionRefs
	TerminalRef       ff.ArtifactReference
	// Every non-manifest ancestor is selected from its exact issued command's
	// archived capture, in oldest-first order. Population is bounded by journal.
	Ancestors []NativeReconstructionAncestor
}
type NativeReconstructionAncestor struct {
	CommandID  string
	References NativeReconstructionRefs
}

// WithCurrentNativeFence must hold the actual graph/workload/current/outbox
// fences, independently resolve commissioned keys and selected refs, and
// authenticate the new workspace's exclusive installed generation. A current
// DB cursor cannot exclude an old in-flight worker. For a replacement runtime,
// independently issued exact removal evidence is additionally mandatory.
// Historical owned reconstruction does not renew forward source authority.
type NativeReconstructionAuthority interface {
	WithCurrentNativeFence(context.Context, string, func(NativeReconstructionSnapshot) error) error
}

func reconstructionMessage(domain string, body any) []byte {
	raw, _ := json.Marshal(body)
	return append([]byte(domain), raw...)
}
func nativeWorkspaceValid(w NativeWorkspace) bool {
	return archiveID.MatchString(w.Generation) && archiveSHA.MatchString(w.RuntimeID) && archiveSHA.MatchString(w.ImageSHA256)
}
func reconstructionRef(p ff.Proposal, kind string, r ff.ArtifactReference) bool {
	b, e := bindingFor(p, r.ID, kind, r.SHA256, r.SizeBytes)
	return e == nil && archiveID.MatchString(r.Bucket) && r.Key == archiveObjectKey(b) && r.VersionID != "" && r.VersionID != "null" && len(r.VersionID) <= 1024 && !strings.ContainsAny(r.VersionID, "\x00\r\n")
}
func reconstructionArtifact(c g.JournalCommand) (g.GitArtifact, bool) {
	if c.Forward != nil && c.Recovery == nil {
		return c.Forward.Child.Artifact, true
	}
	if c.Recovery != nil && c.Forward == nil {
		return c.Recovery.Recovery.Artifact, true
	}
	return g.GitArtifact{}, false
}

func verifyNativeRetirement(e NativeRetirementEnvelope, key ed25519.PublicKey, s NativeReconstructionSnapshot, terminal NativeTerminal, now time.Time) error {
	r := e.Retirement
	if len(key) != ed25519.PublicKeySize || bytes.Equal(key, s.Keys.Signer) || bytes.Equal(key, s.Keys.Pipeline) || bytes.Equal(key, s.Keys.Ledger) || e.Algorithm != nativeReconstructionAlgorithm || r.SchemaVersion != "1" || !archiveID.MatchString(r.ID) || r.TenantID != s.Selected.Binding.Old.Target.TenantID || r.ChainID != s.ChainID || r.ProgramSHA256 != g.Digest(s.View.Parent.Program) || r.Method != "OWNED_DOCKER_CONTAINER_REMOVAL_CONFIRMED" || !nativeWorkspaceValid(r.Old) || !nativeWorkspaceValid(r.New) || r.Old != terminal.Workspace || r.New != s.Workspace || r.Old.Generation == r.New.Generation || r.Old.RuntimeID == r.New.RuntimeID || r.Old.ImageSHA256 != r.New.ImageSHA256 || r.ObservedAt.Before(terminal.ObservedAt) || r.ObservedAt.After(now.Add(5*time.Second)) || r.ObservedAt.IsZero() {
		return ErrReconstruction
	}
	sig, e2 := base64.StdEncoding.DecodeString(e.Signature)
	if e2 != nil || !ed25519.Verify(key, reconstructionMessage(nativeRetirementDomain, r), sig) {
		return ErrReconstruction
	}
	return nil
}

// SignNativeRetirement belongs to the separately commissioned runtime-removal
// controller, never the native pipeline. The controller must verify actual
// exact-container removal before calling this pure signing primitive.
func SignNativeRetirement(r NativeWorkspaceRetirement, key ed25519.PrivateKey) (NativeRetirementEnvelope, error) {
	if len(key) != ed25519.PrivateKeySize || r.SchemaVersion != "1" || !nativeWorkspaceValid(r.Old) || !nativeWorkspaceValid(r.New) || r.Old == r.New || r.Method != "OWNED_DOCKER_CONTAINER_REMOVAL_CONFIRMED" || r.ObservedAt.IsZero() {
		return NativeRetirementEnvelope{}, ErrReconstruction
	}
	return NativeRetirementEnvelope{r, nativeReconstructionAlgorithm, base64.StdEncoding.EncodeToString(ed25519.Sign(key, reconstructionMessage(nativeRetirementDomain, r)))}, nil
}

func reconstructionSnapshot(s NativeReconstructionSnapshot, now time.Time) (g.JournalProjection, error) {
	if s.Kind != ReconstructionOriginal || !archiveID.MatchString(s.ChainID) || s.CurrentHeadSHA256 != g.Digest(s.View.Head) || s.ExpectedHead != s.View.Head.Head.Ref || !nativeWorkspaceValid(s.Workspace) || s.Workspace.ImageSHA256 != s.Selected.Profile.Installation.ToolchainImageSHA256 || s.Selected.CustomerExecutionAuthorized || s.Selected.EstimatedSaving != nil || s.Selected.VerifiedSaving != nil || g.Digest(s.Prepared.Program) != g.Digest(s.View.Parent.Program) || s.Selected.Binding != s.View.Parent.Program.Binding || s.Selected.Realm != s.View.Parent.Program.Realm {
		return g.JournalProjection{}, ErrReconstruction
	}
	if e := ff.ValidatePreparation(s.Selected, s.Prepared, s.Prepared.Program.CreatedAt); e != nil {
		return g.JournalProjection{}, e
	}
	p, e := g.VerifyJournal(s.View, s.Keys, s.ExpectedHead, now)
	if e != nil {
		return p, e
	}
	if s.Mode == ReconstructionInitial {
		if len(s.View.Records) != 0 || s.ExpectedHead.RecordCount != 0 || p.Pending != nil || len(p.Stack) != 0 || len(p.Consumed) != 0 || p.Current != s.Prepared.JournalReview.Base || s.CommandID != "" || s.TerminalRef.ID != "" || s.Retirement != nil || len(s.Ancestors) != 0 {
			return p, ErrReconstruction
		}
		return p, nil
	}
	if s.Mode == ReconstructionObservation {
		if p.Pending == nil || p.Pending.Command.ID != s.CommandID || !p.Pending.ApplyIntent || p.Pending.NoApply != nil || p.Pending.GitRepair != nil || s.TerminalRef.ID != "" || s.Retirement != nil {
			return p, ErrUncertain
		}
		return p, nil
	}
	if s.Mode != ReconstructionTerminal || s.TerminalRef.ID == "" {
		return p, ErrUncertain
	}
	if !reconstructionRef(s.Selected, "NATIVE_OPERATION_PROOF", s.TerminalRef) || s.CommandID == "" || s.Retirement == nil || len(s.Ancestors) > len(s.View.Records) {
		return p, ErrReconstruction
	}
	return p, nil
}

// Strict decoding rejects duplicate/unknown fields and trailing values. No
// public endpoint accepts these bodies. Bound before decoding archive bytes.
func decodeReconstruction(raw []byte, out any) error {
	if len(raw) == 0 || len(raw) > 16<<20 {
		return ErrReconstruction
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 64 {
			return ErrReconstruction
		}
		t, e := d.Token()
		if e != nil {
			return e
		}
		if x, ok := t.(json.Delim); ok {
			switch x {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					k, e := d.Token()
					if e != nil {
						return e
					}
					key, ok := k.(string)
					if !ok || seen[key] {
						return ErrReconstruction
					}
					seen[key] = true
					if e = walk(depth + 1); e != nil {
						return e
					}
				}
			case '[':
				for d.More() {
					if e = walk(depth + 1); e != nil {
						return e
					}
				}
			default:
				return ErrReconstruction
			}
			_, e = d.Token()
			return e
		}
		return nil
	}
	if e := walk(0); e != nil {
		return ErrReconstruction
	}
	if _, e := d.Token(); e != io.EOF {
		return ErrReconstruction
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return ErrReconstruction
	}
	return nil
}
