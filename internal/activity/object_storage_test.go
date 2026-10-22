package activity

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/auth"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
)

func objectStorageObservation() store.ObjectStorageAccessInterval {
	return store.ObjectStorageAccessInterval{SchemaVersion: "1", SourceID: "synthetic-source", ResourceID: "synthetic-bucket", DatasetID: "synthetic-dataset", DatasetVersion: 1, Sequence: 1,
		IntervalStart: time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC), IntervalEnd: time.Date(2026, 10, 20, 12, 1, 0, 0, time.UTC),
		MetricDefinition: store.ActivityMetric{ID: "synthetic-all-app-gets", Version: "1", Unit: store.ObjectStorageAccessUnit}, GetRequests: "0", RetrievedBytes: "0", Heartbeat: true}
}

func TestObjectStorageAccessRequiresExplicitFactsAndExactJSON(t *testing.T) {
	in := objectStorageObservation()
	raw, _ := json.Marshal(in)
	got, err := DecodeObjectStorageAccess(raw)
	if err != nil || got != in {
		t.Fatalf("explicit zero observations rejected: %v", err)
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)
	for key := range fields {
		t.Run("missing-"+key, func(t *testing.T) {
			copy := map[string]json.RawMessage{}
			for k, v := range fields {
				copy[k] = v
			}
			delete(copy, key)
			body, _ := json.Marshal(copy)
			if _, err := DecodeObjectStorageAccess(body); err == nil {
				t.Fatal("missing source observation became an explicit zero")
			}
			copy[key] = json.RawMessage("null")
			body, _ = json.Marshal(copy)
			if _, err := DecodeObjectStorageAccess(body); err == nil {
				t.Fatal("null observation became a value")
			}
		})
	}
	for _, bad := range [][]byte{
		bytes.Replace(raw, []byte(`"heartbeat":true`), []byte(`"heartbeat":true,"heartbeat":false`), 1),
		bytes.Replace(raw, []byte(`"version":"1"`), []byte(`"version":"1","version":"2"`), 1),
		bytes.Replace(raw, []byte(`"get_requests":"0"`), []byte(`"get_requests":0`), 1),
		bytes.Replace(raw, []byte(`"get_requests":"0"`), []byte(`"get_requests":"0.1"`), 1),
		bytes.Replace(raw, []byte(`"get_requests":"0"`), []byte(`"get_requests":"-1"`), 1),
		append(append([]byte{}, raw...), raw...),
		[]byte(`[]`),
	} {
		if _, err := DecodeObjectStorageAccess(bad); err == nil {
			t.Fatalf("invalid or conflicting observation accepted: %s", bad)
		}
	}
}

func TestObjectStorageAccessMinuteBindingCannotUseWorkloadInterval(t *testing.T) {
	for name, mutate := range map[string]func(*store.ObjectStorageAccessInterval){
		"no-definition":   func(in *store.ObjectStorageAccessInterval) { in.MetricDefinition.Version = "" },
		"workload-unit":   func(in *store.ObjectStorageAccessInterval) { in.MetricDefinition.Unit = "order" },
		"dataset-version": func(in *store.ObjectStorageAccessInterval) { in.DatasetVersion = 0 },
		"partial-minute":  func(in *store.ObjectStorageAccessInterval) { in.IntervalEnd = in.IntervalEnd.Add(time.Second) },
		"unaligned-minute": func(in *store.ObjectStorageAccessInterval) {
			in.IntervalStart = in.IntervalStart.Add(time.Second)
			in.IntervalEnd = in.IntervalEnd.Add(time.Second)
		},
		"sequence-zero":     func(in *store.ObjectStorageAccessInterval) { in.Sequence = 0 },
		"bytes-without-get": func(in *store.ObjectStorageAccessInterval) { in.RetrievedBytes = "1" },
		"offset-time": func(in *store.ObjectStorageAccessInterval) {
			in.IntervalStart = in.IntervalStart.In(time.FixedZone("synthetic", 3600))
		},
	} {
		t.Run(name, func(t *testing.T) {
			in := objectStorageObservation()
			mutate(&in)
			if store.ValidateObjectStorageAccessInterval(in) == nil {
				t.Fatal("invalid source/metric/minute binding accepted")
			}
		})
	}
}

type objectStorageDeniedMachine struct{}

func (*objectStorageDeniedMachine) Validate(*http.Request) (auth.Identity, error) {
	return auth.Identity{}, errors.New("console audience is not accepted by machine validator")
}

func TestObjectStorageAccessRouteRequiresMachineIdentityBeforePersistence(t *testing.T) {
	handler := NewServer(nil, &objectStorageDeniedMachine{}, "https://machine.invalid").Handler()
	request := httptest.NewRequest(http.MethodPost, "/v1/object-storage-access/intervals", bytes.NewReader([]byte(`{}`)))
	request.Header.Set("Authorization", "Bearer synthetic-console-token")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("console identity reached persistence: %d", response.Code)
	}
	request = httptest.NewRequest(http.MethodGet, "/v1/object-storage-access/intervals", nil)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("observation route method accepted: %d", response.Code)
	}
}
