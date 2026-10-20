package workflow

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/network"
)

func TestNetworkSnapshotBindsOriginalBytesAndPreservesNativeIntegers(t *testing.T) {
	// The deliberately non-sorted selection order is the production typed
	// MetricSelection layout; the native counter exceeds float64 exactness.
	raw := []byte(`{"resource_id":"resource","config_hash":"bound","metrics":{"selection":{"nat_gateway_id":"nat-test","start":"2026-09-01T00:00:00Z","end":"2026-10-01T00:00:00Z","period_seconds":3600},"native_counter":9007199254740993}}`)
	hash := network.BytesHash(raw)
	canonical, e := decodeNetworkSnapshot(raw, hash, "bound")
	if e != nil {
		t.Fatal("authentic archived JSON rejected", e)
	}
	counter := canonical["metrics"].(map[string]any)["native_counter"]
	number, ok := counter.(json.Number)
	if !ok || number.String() != "9007199254740993" {
		t.Fatal("native counter rounded", counter)
	}
	if network.Hash(canonical) == hash {
		t.Fatal("fixture must exercise original byte order differing from map serialization")
	}
	for name, change := range map[string]struct {
		raw          []byte
		hash, config string
	}{"changed bytes": {bytes.Replace(raw, []byte("nat-test"), []byte("nat-other"), 1), hash, "bound"}, "changed binding": {raw, hash, "other"}, "trailing JSON": {append(append([]byte{}, raw...), []byte(` {"extra":true}`)...), "", "bound"}} {
		t.Run(name, func(t *testing.T) {
			digest := change.hash
			if digest == "" {
				digest = network.BytesHash(change.raw)
			}
			if out, e := decodeNetworkSnapshot(change.raw, digest, change.config); e == nil || out != nil {
				t.Fatal("modified evidence accepted", model.String(out, "config_hash"), e)
			}
		})
	}
}
