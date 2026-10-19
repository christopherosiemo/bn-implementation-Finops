package main

// This is a private Linux fixture adapter, not a commissioned journal service.
// A successful append fsyncs the canonical event before replacing the separately
// resolved head. A cut between those writes is rejected on reopen; no tail is
// truncated and no missing callback is interpreted as NOT_APPLIED.
import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
)

const journalDirectory = "/workspace/private/journal"
const maximumJournalBytes = 4 << 20

var errJournalWriterActive = errors.New("journal writer already active")

type journalBootstrap struct {
	View     g.JournalView     `json:"view"`
	Signer   ed25519.PublicKey `json:"signer"`
	Pipeline ed25519.PublicKey `json:"pipeline"`
	Ledger   ed25519.PublicKey `json:"ledger"`
}
type journalLine struct {
	Record g.JournalRecord       `json:"record"`
	Head   g.JournalHeadEnvelope `json:"head"`
}
type journalDisk struct {
	directory    string
	bootstrapSHA string
}

func canonicalDecode(raw []byte, value any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(value); err != nil {
		return fmt.Errorf("journal JSON rejected")
	}
	var extra any
	if d.Decode(&extra) != io.EOF || !bytes.Equal(exactJSON(value), raw) {
		return fmt.Errorf("journal noncanonical or trailing bytes rejected")
	}
	return nil
}
func boundedRegular(name string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() <= 0 || info.Size() > maximum {
		return nil, fmt.Errorf("journal private file boundary rejected")
	}
	raw, err := os.ReadFile(name)
	if err != nil || int64(len(raw)) != info.Size() {
		return nil, fmt.Errorf("journal read failed")
	}
	return raw, nil
}
func syncDirectory(directory string) error {
	f, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
func privateExclusive(name string, raw []byte) error {
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(raw); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
func (s journalDisk) lock() (*os.File, error) {
	if s.directory != journalDirectory && s.directory != "/workspace/private/journal-negative" {
		return nil, fmt.Errorf("fixed journal path required")
	}
	fd, err := syscall.Open(filepath.Join(s.directory, "writer.lock"), syscall.O_RDWR|syscall.O_CREAT|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "fixture-journal-writer-lock")
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		f.Close()
		return nil, fmt.Errorf("journal lock rejected")
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, errJournalWriterActive
		}
		return nil, err
	}
	return f, nil
}
func unlock(f *os.File) { must(syscall.Flock(int(f.Fd()), syscall.LOCK_UN)); must(f.Close()) }

func newJournalDisk(b journalBootstrap) journalDisk {
	must(os.Mkdir(journalDirectory, 0700))
	raw := exactJSON(b)
	must(privateExclusive(filepath.Join(journalDirectory, "bootstrap.json"), raw))
	must(privateExclusive(filepath.Join(journalDirectory, "head.json"), exactJSON(b.View.Head)))
	must(syncDirectory(journalDirectory))
	return journalDisk{journalDirectory, g.BytesDigest(raw)}
}
func (s journalDisk) load(now time.Time) (g.JournalView, g.JournalKeys, g.JournalProjection, error) {
	return s.loadSnapshot(now, false)
}
func (s journalDisk) loadSnapshot(now time.Time, issuerRefresh bool) (g.JournalView, g.JournalKeys, g.JournalProjection, error) {
	var b journalBootstrap
	raw, err := boundedRegular(filepath.Join(s.directory, "bootstrap.json"), 1<<20)
	if err != nil {
		return g.JournalView{}, g.JournalKeys{}, g.JournalProjection{}, err
	}
	if g.BytesDigest(raw) != s.bootstrapSHA || canonicalDecode(raw, &b) != nil {
		return g.JournalView{}, g.JournalKeys{}, g.JournalProjection{}, fmt.Errorf("journal bootstrap changed")
	}
	keys := g.JournalKeys{Signer: b.Signer, Pipeline: b.Pipeline, Ledger: b.Ledger}
	v := b.View
	checkpoints := []g.JournalHeadEnvelope{b.View.Head}
	if len(v.Records) != 0 {
		return v, keys, g.JournalProjection{}, fmt.Errorf("bootstrap records forbidden")
	}
	var log []byte
	info, err := os.Lstat(filepath.Join(s.directory, "records.jsonl"))
	if err != nil && !os.IsNotExist(err) {
		return v, keys, g.JournalProjection{}, err
	}
	if err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > maximumJournalBytes {
			return v, keys, g.JournalProjection{}, fmt.Errorf("journal log bound rejected")
		}
		log, err = os.ReadFile(filepath.Join(s.directory, "records.jsonl"))
		if err != nil || int64(len(log)) != info.Size() {
			return v, keys, g.JournalProjection{}, fmt.Errorf("journal log read rejected")
		}
	}
	if len(log) > 0 {
		if log[len(log)-1] != '\n' {
			return v, keys, g.JournalProjection{}, fmt.Errorf("torn journal tail rejected")
		}
		lines := bytes.Split(log[:len(log)-1], []byte{'\n'})
		if len(lines) > 512 {
			return v, keys, g.JournalProjection{}, fmt.Errorf("journal record bound rejected")
		}
		for _, line := range lines {
			var event journalLine
			if len(line) == 0 || canonicalDecode(line, &event) != nil {
				return v, keys, g.JournalProjection{}, fmt.Errorf("journal line rejected")
			}
			v.Records = append(v.Records, event.Record)
			v.Head = event.Head
			checkpoints = append(checkpoints, event.Head)
		}
	}
	anchor, err := boundedRegular(filepath.Join(s.directory, "head.json"), 1<<20)
	if err != nil {
		return v, keys, g.JournalProjection{}, err
	}
	var expected g.JournalHeadEnvelope
	if canonicalDecode(anchor, &expected) != nil || expected.Head.Ref != v.Head.Head.Ref || expected.Head.ProjectionSHA256 != v.Head.Head.ProjectionSHA256 {
		return v, keys, g.JournalProjection{}, fmt.Errorf("journal unresolved head publication rejected")
	}
	v.Head = expected
	at := now
	if issuerRefresh {
		at = expected.Head.ObservedAt
		if at.After(now.Add(5 * time.Second)) {
			return v, keys, g.JournalProjection{}, fmt.Errorf("future issuer head rejected")
		}
	}
	// One reducer pass verifies EVERY historical checkpoint at its event time,
	// then independently verifies the separately resolved current anchor now.
	// This preserves all checks without nesting a full replay for each prefix.
	projection, err := g.VerifyJournalCheckpoints(v, checkpoints, keys, expected.Head.Ref, at)
	return v, keys, projection, err
}

// Only the private fixture ledger issuer can renew a stale head. It reloads
// the complete original chain and separately persisted head under the same
// writer lock, then signs the identical ref/projection. New STOP/forward
// authority is still independently checked by the core; no duty is erased.
func (s journalDisk) refresh(key ed25519.PrivateKey, now time.Time) error {
	lock, err := s.lock()
	if err != nil {
		return err
	}
	defer unlock(lock)
	v, keys, p, err := s.loadSnapshot(now, true)
	if err != nil {
		return err
	}
	sealed, updated, err := g.SealJournalView(v.Parent, v.Authorization, v.Records, keys, key, now)
	if err != nil {
		return err
	}
	if sealed.Head.Head.Ref != v.Head.Head.Ref || g.Digest(updated) != g.Digest(p) {
		return fmt.Errorf("issuer refresh changed journal authority")
	}
	if err = privateExclusive(filepath.Join(s.directory, "head.next"), exactJSON(sealed.Head)); err != nil {
		return err
	}
	if err = os.Rename(filepath.Join(s.directory, "head.next"), filepath.Join(s.directory, "head.json")); err != nil {
		return err
	}
	return syncDirectory(s.directory)
}

// The event+sealed head are supplied by the private fixture ledger. The file
// adapter independently checks the current anchor and full chain under its
// nonblocking writer lock before append; a stale writer cannot publish a head.
func (s journalDisk) append(expected g.JournalHeadRef, record g.JournalRecord, head g.JournalHeadEnvelope, now time.Time) error {
	lock, err := s.lock()
	if err != nil {
		return err
	}
	defer unlock(lock)
	return s.appendLocked(expected, record, head, now)
}

// Call only while holding this journal's writer.lock. Native delivery keeps
// that same fence through intent validation, operation-state update and outcome.
func (s journalDisk) appendLocked(expected g.JournalHeadRef, record g.JournalRecord, head g.JournalHeadEnvelope, now time.Time) error {
	v, keys, _, err := s.load(now)
	if err != nil {
		return err
	}
	if v.Head.Head.Ref != expected {
		return fmt.Errorf("journal compare-and-swap failed")
	}
	v.Records = append(v.Records, record)
	v.Head = head
	if _, err = g.VerifyJournal(v, keys, head.Head.Ref, now); err != nil {
		return err
	}
	raw := append(exactJSON(journalLine{Record: record, Head: head}), '\n')
	info, err := os.Stat(filepath.Join(s.directory, "records.jsonl"))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if info != nil && info.Size()+int64(len(raw)) > maximumJournalBytes {
		return fmt.Errorf("journal append bound rejected")
	}
	f, err := os.OpenFile(filepath.Join(s.directory, "records.jsonl"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(raw); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = privateExclusive(filepath.Join(s.directory, "head.next"), exactJSON(head)); err != nil {
		return err
	}
	if err = os.Rename(filepath.Join(s.directory, "head.next"), filepath.Join(s.directory, "head.json")); err != nil {
		return err
	}
	return syncDirectory(s.directory)
}

type reopenResult struct {
	ProjectionSHA256 string `json:"projection_sha256"`
	RecordCount      int    `json:"record_count"`
	ApplyInvocations int    `json:"apply_invocations"`
	StateSHA256      string `json:"state_sha256"`
	GitCommit        string `json:"git_commit"`
	WriterBlocked    bool   `json:"writer_blocked"`
}

func nativeApplyCount() int {
	raw, err := boundedRegular("/workspace/private/terraform-invocations.jsonl", 1<<20)
	must(err)
	require(raw[len(raw)-1] == '\n', "torn invocation audit")
	count := 0
	for _, line := range bytes.Split(raw[:len(raw)-1], []byte{'\n'}) {
		var v struct {
			Arguments []string  `json:"arguments"`
			At        time.Time `json:"at"`
		}
		must(canonicalDecode(line, &v))
		require(len(v.Arguments) > 0, "missing actual invocation")
		if v.Arguments[0] == "apply" {
			count++
		}
	}
	return count
}
func reopenProcess(mode string) {
	require(mode == "--verify-journal" || mode == "--probe-writer-lock", "fixed subprocess mode required")
	s := journalDisk{directory: journalDirectory, bootstrapSHA: os.Getenv("FLEET_JOURNAL_BOOTSTRAP_SHA256")}
	require(len(s.bootstrapSHA) == 64, "private bootstrap pin required")
	if mode == "--probe-writer-lock" {
		f, err := s.lock()
		if err == nil {
			unlock(f)
		}
		require(errors.Is(err, errJournalWriterActive), "second writer did not observe actual held lock")
		fmt.Println(string(exactJSON(reopenResult{WriterBlocked: true})))
		return
	}
	lock, err := s.lock()
	must(err)
	defer unlock(lock)
	v, _, projection, err := s.load(time.Now().UTC())
	must(err)
	fmt.Println(string(exactJSON(reopenResult{ProjectionSHA256: g.Digest(projection), RecordCount: len(v.Records), ApplyInvocations: nativeApplyCount(), StateSHA256: g.BytesDigest(read("/workspace/private/current.tfstate")), GitCommit: git("rev-parse", executionRef)})))
}

func (s journalDisk) negativeStorageChecks(ledger ed25519.PrivateKey) int {
	// Each malformed-tail probe is an explicit owned copy. The authoritative
	// journal is never edited, truncated, repaired or rolled back by these tests.
	const clone = "/workspace/private/journal-negative"
	must(os.Mkdir(clone, 0700))
	defer func() { must(os.RemoveAll(clone)) }()
	for _, name := range []string{"bootstrap.json", "head.json", "records.jsonl"} {
		must(privateExclusive(filepath.Join(clone, name), read(filepath.Join(s.directory, name))))
	}
	copyStore := journalDisk{directory: clone, bootstrapSHA: s.bootstrapSHA}
	original := read(filepath.Join(clone, "records.jsonl"))
	probes := [][]byte{append(append([]byte(nil), original...), []byte("{\"record\":")...), append(append([]byte(nil), original...), []byte("\n")...), bytes.Replace(original, []byte("{\"record\":"), []byte("{ \"record\":"), 1)}
	count := 0
	for _, raw := range probes {
		write(filepath.Join(clone, "records.jsonl"), raw)
		_, _, _, err := copyStore.load(time.Now().UTC())
		require(err != nil, "malformed journal tail accepted")
		require(bytes.Equal(read(filepath.Join(clone, "records.jsonl")), raw), "reopen silently repaired journal")
		count++
	}
	write(filepath.Join(clone, "records.jsonl"), original)
	// The final current head and record hash chain remain authentic. Corrupt
	// only an intermediate checkpoint, with a valid fixture ledger signature:
	// a final-only verifier would miss this wrong historical projection.
	lineEnd := bytes.IndexByte(original, '\n')
	require(lineEnd > 0, "historical checkpoint missing")
	var checkpoint journalLine
	must(canonicalDecode(original[:lineEnd], &checkpoint))
	checkpoint.Head.Head.ProjectionSHA256 = g.BytesDigest([]byte("invalid historical projection"))
	message := append([]byte("finops/fleet-group/journal/v1/isolated-fixture/current-head\x00"), exactJSON(checkpoint.Head.Head)...)
	checkpoint.Head.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(ledger, message))
	altered := append(append(exactJSON(checkpoint), '\n'), original[lineEnd+1:]...)
	write(filepath.Join(clone, "records.jsonl"), altered)
	_, _, _, checkpointErr := copyStore.load(time.Now().UTC())
	require(checkpointErr != nil, "validly signed wrong historical projection accepted")
	write(filepath.Join(clone, "records.jsonl"), original)
	currentHead := read(filepath.Join(clone, "head.json"))
	first := bytes.IndexByte(original, '\n')
	require(first > 0, "journal prefix missing")
	write(filepath.Join(clone, "records.jsonl"), original[:first+1])
	_, _, _, err := copyStore.load(time.Now().UTC())
	require(err != nil, "valid old prefix borrowed the actual current head")
	require(bytes.Equal(read(filepath.Join(clone, "head.json")), currentHead), "old prefix silently resealed current head")
	write(filepath.Join(clone, "records.jsonl"), original)
	var b journalBootstrap
	must(canonicalDecode(read(filepath.Join(clone, "bootstrap.json")), &b))
	write(filepath.Join(clone, "head.json"), exactJSON(b.View.Head))
	_, _, _, err = copyStore.load(time.Now().UTC())
	require(err != nil, "log ahead of external head accepted")
	return count + 3
}
