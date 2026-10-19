package groupfixtureproducer

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	ff "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetfixture"
	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
)

type reconstructionObject struct {
	kind string
	raw  []byte
}
type reconstructionMaterial struct {
	current  g.JournalState
	state    []byte
	objects  map[string]reconstructionObject
	terminal *NativeTerminalEnvelope
	command  g.JournalCommand
	capture  g.GitTerraformArtifactCapture
}

func reconstructionOID(kind string, raw []byte, width int) string {
	frame := append([]byte(fmt.Sprintf("%s %d\x00", kind, len(raw))), raw...)
	if width == 40 {
		h := sha1.Sum(frame)
		return hex.EncodeToString(h[:])
	}
	h := sha256.Sum256(frame)
	return hex.EncodeToString(h[:])
}
func (m *reconstructionMaterial) addProof(r g.GitRevision, commit, tree, configuration, desired []byte) error {
	// The installed native producer uses SHA1 Git repositories. Supporting
	// another repository format needs an independently reviewed Git boundary.
	if len(r.Commit) != 40 || len(r.Tree) != 40 || reconstructionOID("commit", commit, 40) != r.Commit || reconstructionOID("tree", tree, 40) != r.Tree || g.BytesDigest(configuration) != r.ConfigurationSHA256 || g.BytesDigest(desired) != r.DesiredSHA256 {
		return ErrReconstruction
	}
	for _, o := range []reconstructionObject{{"blob", configuration}, {"blob", desired}, {"tree", tree}, {"commit", commit}} {
		oid := reconstructionOID(o.kind, o.raw, 40)
		if old, ok := m.objects[oid]; ok && (old.kind != o.kind || !bytes.Equal(old.raw, o.raw)) {
			return ErrReconstruction
		}
		m.objects[oid] = o
	}
	return nil
}
func (m reconstructionMaterial) ancestry(base string) error {
	current := m.current.Revision.Commit
	seen := map[string]bool{}
	for i := 0; i <= len(m.objects); i++ {
		if current == base {
			return nil
		}
		if seen[current] {
			return ErrReconstruction
		}
		seen[current] = true
		o, ok := m.objects[current]
		if !ok || o.kind != "commit" {
			return ErrUncertain
		}
		head := strings.SplitN(string(o.raw), "\n\n", 2)
		if len(head) != 2 {
			return ErrReconstruction
		}
		parent := ""
		for _, line := range strings.Split(head[0], "\n") {
			if strings.HasPrefix(line, "parent ") {
				if parent != "" {
					return ErrReconstruction
				}
				parent = strings.TrimPrefix(line, "parent ")
			}
		}
		if len(parent) != 40 {
			return ErrReconstruction
		}
		current = parent
	}
	return ErrReconstruction
}

func reconstructionMaterializeInput(ctx context.Context, a ReadableArchive, s NativeReconstructionSnapshot, now time.Time) (reconstructionMaterial, error) {
	m := reconstructionMaterial{objects: map[string]reconstructionObject{}}
	p, e := reconstructionSnapshot(s, now)
	if e != nil {
		return m, e
	}
	if s.Mode != ReconstructionInitial && s.Mode != ReconstructionTerminal {
		return m, ErrReconstruction
	}
	// Bound the complete selected population before any object reads/decodes.
	// Duplicate references may reuse bytes, but an ID may never change body.
	selected := append([]ff.ArtifactReference{}, s.Prepared.Artifacts...)
	if s.Mode == ReconstructionTerminal {
		selected = append(selected, s.TerminalRef, s.References.Review, s.References.Capture, s.References.After)
	}
	for _, r := range s.Ancestors {
		selected = append(selected, r.References.Review, r.References.Capture)
	}
	var total int64
	references := map[string]ff.ArtifactReference{}
	for _, ref := range selected {
		if old, ok := references[ref.ID]; ok {
			if old != ref {
				return m, ErrReconstruction
			}
			continue
		}
		if ref.SizeBytes < 1 || ref.SizeBytes > 16<<20 {
			return m, ErrReconstruction
		}
		total += ref.SizeBytes
		if total > 32<<20 {
			return m, ErrReconstruction
		}
		references[ref.ID] = ref
	}
	proofBytes, e := ff.ProofBytes(s.Prepared.GitProofs)
	if e != nil {
		return m, e
	}
	seen := map[string]bool{}
	for _, ref := range s.Prepared.Artifacts {
		kind := ""
		for _, evidence := range s.Prepared.Program.Evidence {
			if evidence.ID == ref.ID && evidence.SHA256 == ref.SHA256 {
				kind = evidence.Kind
			}
		}
		if ref.SHA256 == g.BytesDigest(proofBytes) {
			kind = "GIT_PROOF_SET"
		}
		if ref.SHA256 == s.Prepared.JournalReview.Base.StateSHA256 {
			kind = "BASE_NATIVE_STATE"
		}
		if kind == "" || seen[kind] {
			return m, ErrReconstruction
		}
		seen[kind] = true
		raw, e := readReconstructionObject(ctx, a, s, kind, ref)
		if e != nil {
			return m, e
		}
		if kind == "GIT_PROOF_SET" && !bytes.Equal(raw, proofBytes) {
			return m, ErrReconstruction
		}
		if kind == "BASE_NATIVE_STATE" {
			base, e := baseState(raw, s.Prepared.Program, s.Prepared.JournalReview.Base.Model)
			if e != nil || base != s.Prepared.JournalReview.Base {
				return m, ErrReconstruction
			}
			m.state = raw
		}
	}
	if len(seen) != 9 || len(m.state) == 0 || !seen["GIT_PROOF_SET"] {
		return m, ErrReconstruction
	}
	for _, proof := range s.Prepared.GitProofs {
		if e = m.addProof(proof.Revision, proof.CommitObject, proof.TreeObject, proof.Configuration, proof.DesiredVariables); e != nil {
			return m, e
		}
	}
	m.current = p.Current
	if s.Mode == ReconstructionTerminal {
		raw, e := readReconstructionObject(ctx, a, s, "NATIVE_OPERATION_PROOF", s.TerminalRef)
		if e != nil {
			return m, e
		}
		terminal, e := decodeNativeTerminal(raw)
		if e != nil {
			return m, e
		}
		c, e := nativeTerminalFacts(s, terminal, p, now)
		if e != nil {
			return m, e
		}
		if e = verifyNativeRetirement(*s.Retirement, s.RetirementKey, s, terminal.Terminal, now); e != nil {
			return m, e
		}
		capture, e := readReconstructionCapture(ctx, a, s, c, s.References)
		if e != nil {
			return m, e
		}
		after, e := readReconstructionObject(ctx, a, s, "AFTER_NATIVE_STATE", s.References.After)
		if e != nil {
			return m, e
		}
		parsed, e := baseState(after, s.Prepared.Program, terminal.Terminal.After.Model)
		parsed.Revision = terminal.Terminal.After.Revision
		if e != nil || parsed != terminal.Terminal.After || !sameResourceIDs(capture.BeforeState, after) {
			return m, ErrReconstruction
		}
		m.state = after
		m.current = parsed
		m.terminal = &terminal
		m.command = c
		m.capture = capture
		if e = m.addProof(capture.Revision, capture.GitCommitObject, capture.GitTreeObject, capture.Configuration, capture.DesiredVariables); e != nil {
			return m, e
		}
	}
	commandIDs := map[string]bool{s.CommandID: true}
	for _, ancestor := range s.Ancestors {
		if commandIDs[ancestor.CommandID] {
			return m, ErrReconstruction
		}
		commandIDs[ancestor.CommandID] = true
		c, ok := nativeIssuedCommand(s.View, ancestor.CommandID)
		if !ok {
			return m, ErrReconstruction
		}
		capture, e := readReconstructionCapture(ctx, a, s, c, ancestor.References)
		if e != nil {
			return m, e
		}
		if e = m.addProof(capture.Revision, capture.GitCommitObject, capture.GitTreeObject, capture.Configuration, capture.DesiredVariables); e != nil {
			return m, e
		}
	}
	if e = m.ancestry(s.Prepared.Program.Manifest.Base.Commit); e != nil {
		return m, e
	}
	return m, nil
}

func writeReconstructionFile(name string, raw []byte) error {
	if e := privateFile(name, raw); e != nil {
		return e
	}
	dir, e := os.Open(filepath.Dir(name))
	if e != nil {
		return e
	}
	defer dir.Close()
	return dir.Sync()
}

// ReconstructNativeWorkspace materializes only a fresh empty owned workspace.
// No Terraform subprocess is invoked. A positive terminal is an authenticated
// observation of the old local fixture backend, not customer/cloud truth.
// Partial writes are never resumed as authority: use another fresh workspace.
func ReconstructNativeWorkspace(ctx context.Context, authority NativeReconstructionAuthority, chain string, archive ReadableArchive) (worker *NativeStage, err error) {
	if nativeBoundary() != nil || authority == nil || archive == nil {
		return nil, ErrBoundary
	}
	calls := 0
	err = authority.WithCurrentNativeFence(ctx, chain, func(s NativeReconstructionSnapshot) error {
		calls++
		if calls != 1 || s.ChainID != chain {
			return ErrReconstruction
		}
		entries, e := os.ReadDir(workspace)
		if e != nil || len(entries) != 0 {
			return ErrBoundary
		}
		m, e := reconstructionMaterializeInput(ctx, archive, s, time.Now().UTC())
		if e != nil {
			return e
		}
		// Recheck actual time/current issued-head validity after archive I/O,
		// while the same trusted repository/controller fence is still held.
		if _, e = reconstructionSnapshot(s, time.Now().UTC()); e != nil {
			return e
		}
		for _, dir := range []string{control, "/workspace/private", "/tmp/group-fixture-home"} {
			if e = os.MkdirAll(dir, 0700); e != nil {
				return e
			}
		}
		if _, e = gitCommand(ctx, control, nil, "init", "--bare", "--initial-branch=proposals"); e != nil {
			return e
		}
		for oid, o := range m.objects {
			actual, e := gitText(ctx, control, o.raw, "hash-object", "-w", "-t", o.kind, "--stdin")
			if e != nil || actual != oid {
				return ErrReconstruction
			}
		}
		zero := strings.Repeat("0", 40)
		if e = cas(ctx, proposalRef, s.Prepared.Program.Manifest.Entries[len(s.Prepared.Program.Manifest.Entries)-1].Revision.Commit, zero); e != nil {
			return e
		}
		if e = cas(ctx, executionRef, m.current.Revision.Commit, zero); e != nil {
			return e
		}
		if _, e = gitCommand(ctx, control, nil, "worktree", "add", repository, "approved"); e != nil {
			return e
		}
		if e = writeReconstructionFile(g.GitFixtureStatePath, m.state); e != nil {
			return e
		}
		worker, e = OpenNativeStage(ctx, s.Selected, s.Prepared, archive)
		if e != nil {
			return e
		}
		if m.terminal != nil {
			marker := struct{ Terminal, Retirement string }{g.Digest(*m.terminal), g.Digest(*s.Retirement)}
			if e = durableNativeFile(worker.operationFile(m.command, "APPLY"), marker); e != nil {
				return e
			}
			outcome := NativeOutcome{g.Digest(m.command), m.terminal.Terminal.Before, m.terminal.Terminal.After, m.terminal.Terminal.References.After}
			if e = durableNativeFile(worker.operationFile(m.command, "APPLY")+".terminal", outcome); e != nil {
				return e
			}
			// Existing APPLY marker prevents redispatch, even if someone presents
			// an old permit. UNKNOWN itself independently prohibits dispatch.
			if _, e = worker.Outcome(ctx, m.command); e != nil {
				return e
			}
		}
		actual, e := worker.Inspect(ctx, m.current.Revision, m.current.Model)
		if e != nil || actual != m.current {
			return ErrReconstruction
		}
		if _, e = reconstructionSnapshot(s, time.Now().UTC()); e != nil {
			return e
		}
		return nil
	})
	if err == nil && calls != 1 {
		err = ErrReconstruction
	}
	if err != nil {
		return nil, err
	}
	return worker, nil
}
