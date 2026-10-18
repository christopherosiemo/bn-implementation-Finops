package provider

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

type interruptedResponse struct{}

func (interruptedResponse) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
func (interruptedResponse) Close() error             { return nil }

func TestStopRejectionClassificationTracksActualDispatchPhase(t *testing.T) {
	for _, tc := range []struct {
		name                        string
		preflightCode               string
		preflightNetwork, protected bool
		stopStatus                  int
		stopCode                    string
		transport, readFailure      bool
		definite                    bool
		stopCalls                   int
	}{
		{name: "preflight authorization rejected", preflightCode: "UnauthorizedOperation", definite: true},
		{name: "preflight transport failed before mutation", preflightNetwork: true, definite: true},
		{name: "stop protection enabled", protected: true, definite: true},
		{name: "explicit unauthorized stop", stopStatus: 403, stopCode: "UnauthorizedOperation", definite: true, stopCalls: 1},
		{name: "explicit authentication rejection", stopStatus: 401, stopCode: "AuthFailure", definite: true, stopCalls: 1},
		{name: "transport response unknown", transport: true, stopCalls: 1},
		{name: "truncated denial response unknown", stopStatus: 403, readFailure: true, stopCalls: 1},
		{name: "server error remains uncertain", stopStatus: 503, stopCode: "UnauthorizedOperation", stopCalls: 1},
		{name: "unfamiliar client error remains uncertain", stopStatus: 400, stopCode: "UnknownProviderError", stopCalls: 1},
		{name: "timeout remains uncertain", stopStatus: 400, stopCode: "RequestTimeout", stopCalls: 1},
		{name: "successful dispatch is not rejection", stopStatus: 200, stopCalls: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			networkErr := errors.New("response lost after possible mutation")
			client := &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
				body, _ := io.ReadAll(r.Body)
				values, _ := url.ParseQuery(string(body))
				action := values.Get("Action")
				status := http.StatusOK
				response := "<StopInstancesResponse/>"
				if action == "DescribeInstanceAttribute" {
					if tc.preflightNetwork {
						return nil, networkErr
					}
					if tc.preflightCode != "" {
						status = 403
						response = fmt.Sprintf("<Response><Errors><Error><Code>%s</Code><Message>PRIVATE_AUTHORIZATION_DIAGNOSTIC</Message></Error></Errors></Response>", tc.preflightCode)
					} else {
						response = fmt.Sprintf("<DescribeInstanceAttributeResponse><disableApiStop><value>%t</value></disableApiStop></DescribeInstanceAttributeResponse>", tc.protected)
					}
				} else if action == "StopInstances" {
					calls++
					if tc.transport {
						return nil, networkErr
					}
					status = tc.stopStatus
					if tc.readFailure {
						return &http.Response{StatusCode: status, Body: interruptedResponse{}, Header: make(http.Header)}, nil
					}
					if status/100 != 2 {
						response = fmt.Sprintf("<Response><Errors><Error><Code>%s</Code><Message>PRIVATE_AUTHORIZATION_DIAGNOSTIC</Message></Error></Errors></Response>", tc.stopCode)
					}
				} else {
					t.Fatalf("unexpected provider action %s", action)
				}
				return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(response)), Header: make(http.Header)}, nil
			})}
			a := &AWS{cfg: aws.Config{Region: "eu-west-1", Credentials: aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider("fixture", "fixture-not-secret", ""))}, client: client}
			err := a.Stop(context.Background(), model.Operation{ProviderResourceID: "i-pilot", Region: "eu-west-1"})
			if got := StopDefinitelyRejected(err); got != tc.definite {
				t.Fatalf("definite=%v want %v error=%v", got, tc.definite, err)
			}
			if calls != tc.stopCalls {
				t.Fatalf("StopInstances calls=%d want %d", calls, tc.stopCalls)
			}
			if err != nil && strings.Contains(err.Error(), "PRIVATE_AUTHORIZATION_DIAGNOSTIC") {
				t.Fatal("provider message leaked")
			}
			if tc.stopCode != "" || tc.preflightCode != "" {
				var rejected *QueryRejection
				if !errors.As(fmt.Errorf("wrapped: %w", err), &rejected) {
					t.Fatalf("typed AWS rejection lost through wrapping: %v", err)
				}
				code := tc.stopCode
				action := "StopInstances"
				if tc.preflightCode != "" {
					code = tc.preflightCode
					action = "DescribeInstanceAttribute"
				}
				if rejected.Code != code || rejected.Action != action {
					t.Fatalf("typed rejection lost identity: %+v", rejected)
				}
			}
			if tc.preflightNetwork || tc.transport {
				if !errors.Is(err, networkErr) {
					t.Fatal("underlying transport error lost")
				}
			}
		})
	}
}

func TestOnlyExplicitStopDenialsCanConsumeFirstAttempt(t *testing.T) {
	for _, err := range []error{nil, errors.New("UnauthorizedOperation"), io.ErrUnexpectedEOF, &QueryRejection{Action: "DescribeInstances", Code: "UnauthorizedOperation", StatusCode: 403}, &QueryRejection{Action: "StopInstances", Code: "UnauthorizedOperation", StatusCode: 500}} {
		if StopDefinitelyRejected(err) {
			t.Fatalf("ambiguous or unrelated error was definitive: %v", err)
		}
	}
	err := fmt.Errorf("outer: %w", &QueryRejection{Action: "StopInstances", Code: "UnauthorizedOperation", StatusCode: 403})
	if !StopDefinitelyRejected(err) {
		t.Fatal("wrapper lost definitive denial")
	}
	if awsErrorCode("UnauthorizedOperation\nPRIVATE") != "ProviderError" {
		t.Fatal("invalid provider code not sanitized")
	}
}
