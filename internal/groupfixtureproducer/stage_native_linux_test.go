package groupfixtureproducer

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	ff "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetfixture"
	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
)

func TestNativeStageDispatchRequiresExactUnexpiredBinding(t *testing.T) {
	now := time.Now().UTC()
	p := g.JournalDispatchPermit{JournalID: "journal", CommandID: "command", OperationID: "operation", Fence: 4, CommandSHA256: "command-hash", ArtifactSHA256: "artifact-hash", Head: g.JournalHeadRef{Version: 2, RecordCount: 5, LastRecordSHA256: "record-hash"}, ValidUntil: now.Add(time.Second)}
	if !permitMatches(p, p, now) {
		t.Fatal("exact fresh permit rejected")
	}
	for _, mutate := range []func(*g.JournalDispatchPermit){
		func(q *g.JournalDispatchPermit) { q.JournalID += "-other" },
		func(q *g.JournalDispatchPermit) { q.CommandID += "-other" },
		func(q *g.JournalDispatchPermit) { q.OperationID += "-other" },
		func(q *g.JournalDispatchPermit) { q.Fence++ },
		func(q *g.JournalDispatchPermit) { q.CommandSHA256 += "-other" },
		func(q *g.JournalDispatchPermit) { q.ArtifactSHA256 += "-other" },
		func(q *g.JournalDispatchPermit) { q.Head.Version++ },
		func(q *g.JournalDispatchPermit) { q.Head.RecordCount++ },
		func(q *g.JournalDispatchPermit) { q.ValidUntil = now },
		func(q *g.JournalDispatchPermit) { q.ValidUntil = p.ValidUntil.Add(time.Nanosecond) },
	} {
		q := p
		mutate(&q)
		if permitMatches(p, q, now) {
			t.Fatal("changed or expired permit admitted")
		}
	}
}

func TestNativeStageDurableDispatchMarkerCannotBeReused(t *testing.T) {
	name := filepath.Join(t.TempDir(), "dispatch.json")
	first := map[string]string{"operation": "original", "state": "DISPATCHING"}
	if err := durableNativeFile(name, first); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	if err = durableNativeFile(name, map[string]string{"operation": "retry"}); !errors.Is(err, ErrUncertain) {
		t.Fatal("existing dispatch was overwritten", err)
	}
	after, err := os.ReadFile(name)
	if err != nil || string(raw) != string(after) {
		t.Fatal("retry changed original durable evidence")
	}
}

func TestNativeStageResourceIdentityCannotChangeDuringModelUpdate(t *testing.T) {
	state := func(ids ...string) []byte {
		resources := []any{}
		for i, id := range ids {
			resources = append(resources, map[string]any{"name": []string{"old", "candidate", "traffic"}[i], "instances": []any{map[string]any{"attributes": map[string]any{"id": id}}}})
		}
		raw, _ := json.Marshal(map[string]any{"resources": resources})
		return raw
	}
	a := state("old-id", "candidate-id", "traffic-id")
	if !sameResourceIDs(a, a) {
		t.Fatal("unchanged identities rejected")
	}
	for _, b := range [][]byte{state("old-id", "replacement-id", "traffic-id"), state("old-id", "candidate-id"), state("old-id", "", "traffic-id"), []byte(`{"resources":[]}`), []byte("invalid")} {
		if sameResourceIDs(a, b) {
			t.Fatal("replacement or missing resource admitted")
		}
	}
}

func TestNativeStageRejectsUncommissionedOpenWithoutNativeIO(t *testing.T) {
	if _, err := OpenNativeStage(context.Background(), ff.Proposal{}, ff.Preparation{}, nil); !errors.Is(err, ErrBoundary) {
		t.Fatal("uncommissioned fixture opened", err)
	}
	var worker *NativeStage
	if _, err := worker.Inspect(context.Background(), g.GitRevision{}, g.ModelState{}); !errors.Is(err, ErrBoundary) {
		t.Fatal("uninitialized worker reached native tools", err)
	}
}
