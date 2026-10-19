package provider

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

type controllerReplayFrame struct {
	selector string
	body     []byte
}
type controllerReplay struct {
	frames               []controllerReplayFrame
	position, generation int
	region               string
}

// Replay has no network fallback. Synthetic signing material is internal test
// machinery for reusing the exact acquisition parser, never AWS credentials or
// evidence of signing. Actual authenticity comes from the ingester's approved
// acquisition/STS transport and immutable raw version readback.
func (r *controllerReplay) Retrieve(context.Context) (aws.Credentials, error) {
	if r.position >= len(r.frames) {
		return aws.Credentials{}, errors.New("CONTROLLER_DISCOVERY_RAW_INVALID")
	}
	values, err := url.ParseQuery(r.frames[r.position].selector)
	if err != nil {
		return aws.Credentials{}, err
	}
	if values.Get("Action") == "GetCallerIdentity" {
		r.generation++
	}
	if r.generation == 0 {
		return aws.Credentials{}, errors.New("CONTROLLER_DISCOVERY_RAW_IDENTITY_REQUIRED")
	}
	return aws.Credentials{AccessKeyID: fmt.Sprintf("LOCAL_RAW_REPLAY_%d", r.generation), SecretAccessKey: "LOCAL_RAW_REPLAY_ONLY"}, nil
}

func (r *controllerReplay) RoundTrip(request *http.Request) (*http.Response, error) {
	if r.position >= len(r.frames) || request.Body == nil {
		return nil, errors.New("CONTROLLER_DISCOVERY_RAW_INVALID")
	}
	frame := r.frames[r.position]
	body, err := io.ReadAll(io.LimitReader(request.Body, (64<<10)+1))
	if err != nil || len(body) > 64<<10 || string(body) != frame.selector {
		return nil, errors.New("CONTROLLER_DISCOVERY_RAW_SELECTOR_MISMATCH")
	}
	values, err := url.ParseQuery(frame.selector)
	if err != nil {
		return nil, err
	}
	service := "autoscaling"
	if values.Get("Action") == "GetCallerIdentity" {
		service = "sts"
	}
	if request.Method != "POST" || request.URL.Scheme != "https" || request.URL.Host != service+"."+r.region+".amazonaws.com" || request.URL.Path != "/" {
		return nil, errors.New("CONTROLLER_DISCOVERY_RAW_SELECTOR_MISMATCH")
	}
	r.position++
	return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), ContentLength: int64(len(frame.body)), Body: io.NopCloser(bytes.NewReader(frame.body))}, nil
}

// ValidateControllerDiscoveryEvidence replays every framed selector, STS
// snapshot boundary, complete XML page and pagination transition through the
// SAME ControllerDiscovery implementation. It accepts no typed completeness
// flag and does not turn absent ASG membership into unmanaged classification.
func ValidateControllerDiscoveryEvidence(ctx context.Context, e ControllerDiscoveryEvidence, region, account string, instanceIDs []string) error {
	if len(e.Raw) == 0 || len(e.Raw) > controllerRawLimit || controllerSHA(e.Raw) != e.RawSHA256 || e.SchemaVersion != "1" || e.Provider != "AWS" || e.AccountID != account || e.Region != region || e.StartedAt.IsZero() || e.CollectedAt.Before(e.StartedAt) || e.CollectedAt.Sub(e.StartedAt) > 90*time.Second {
		return errors.New("CONTROLLER_DISCOVERY_RAW_INVALID")
	}
	for _, stamp := range []time.Time{e.StartedAt, e.CollectedAt} {
		_, offset := stamp.Zone()
		if offset != 0 {
			return errors.New("CONTROLLER_DISCOVERY_RAW_INVALID")
		}
	}
	replay := &controllerReplay{frames: []controllerReplayFrame{}, region: region}
	reader := bytes.NewReader(e.Raw)
	for reader.Len() > 0 {
		var selectorBytes uint32
		var bodyBytes uint64
		if binary.Read(reader, binary.BigEndian, &selectorBytes) != nil || selectorBytes == 0 || selectorBytes > 64<<10 || uint64(selectorBytes) > uint64(reader.Len()) {
			return errors.New("CONTROLLER_DISCOVERY_RAW_INVALID")
		}
		selector := make([]byte, int(selectorBytes))
		if _, err := io.ReadFull(reader, selector); err != nil {
			return errors.New("CONTROLLER_DISCOVERY_RAW_INVALID")
		}
		values, err := url.ParseQuery(string(selector))
		if err != nil || values.Encode() != string(selector) {
			return errors.New("CONTROLLER_DISCOVERY_RAW_SELECTOR_MISMATCH")
		}
		for _, values := range values {
			if len(values) != 1 {
				return errors.New("CONTROLLER_DISCOVERY_RAW_SELECTOR_MISMATCH")
			}
		}
		if binary.Read(reader, binary.BigEndian, &bodyBytes) != nil || bodyBytes == 0 || bodyBytes > controllerPageLimit || bodyBytes > uint64(reader.Len()) {
			return errors.New("CONTROLLER_DISCOVERY_RAW_INVALID")
		}
		body := make([]byte, int(bodyBytes))
		if _, err = io.ReadFull(reader, body); err != nil {
			return errors.New("CONTROLLER_DISCOVERY_RAW_INVALID")
		}
		replay.frames = append(replay.frames, controllerReplayFrame{string(selector), body})
		if len(replay.frames) > 2*controllerReadLimit {
			return errors.New("CONTROLLER_DISCOVERY_RAW_INVALID")
		}
	}
	local := &AWS{cfg: aws.Config{Region: region, Credentials: replay}, client: &http.Client{Transport: replay}}
	reconstructed, err := local.ControllerDiscovery(ctx, region, account, instanceIDs)
	if err != nil || replay.position != len(replay.frames) {
		return errors.New("CONTROLLER_DISCOVERY_RAW_REPARSE_FAILED")
	}
	reconstructed.StartedAt, reconstructed.CollectedAt = e.StartedAt, e.CollectedAt
	left, err := json.Marshal(e)
	if err != nil {
		return errors.New("CONTROLLER_DISCOVERY_RAW_INVALID")
	}
	right, err := json.Marshal(reconstructed)
	if err != nil || !bytes.Equal(left, right) || !bytes.Equal(e.Raw, reconstructed.Raw) {
		return errors.New("CONTROLLER_DISCOVERY_TYPED_RAW_MISMATCH")
	}
	return nil
}
