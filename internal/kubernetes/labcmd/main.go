// The local lab invokes the same read-only parser and proposal evaluator as
// product integrations. Mutating kubectl/Git actions stay in the labelled lab.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	k "github.com/christopherosiemo/bn-implementation-Finops/internal/kubernetes"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) != 2 {
		return fmt.Errorf("mode required: collect, assess, verify, hpa")
	}
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, 16*1024*1024+1))
	if err != nil || len(raw) > 16*1024*1024 {
		return fmt.Errorf("K8S_INPUT_LIMIT")
	}
	enc := json.NewEncoder(os.Stdout)
	switch os.Args[1] {
	case "collect":
		var b k.Binding
		if json.Unmarshal(raw, &b) != nil {
			return fmt.Errorf("K8S_BINDING_INVALID")
		}
		ca, err := os.ReadFile(os.Getenv("K8S_API_CA_FILE"))
		if err != nil {
			return fmt.Errorf("K8S_CA_UNAVAILABLE")
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(ca) {
			return fmt.Errorf("K8S_CA_INVALID")
		}
		token, err := os.ReadFile(os.Getenv("K8S_API_TOKEN_FILE"))
		if err != nil {
			return fmt.Errorf("K8S_TOKEN_UNAVAILABLE")
		}
		client := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, MaxConnsPerHost: 2}}
		r := k.Reader{URL: os.Getenv("K8S_API_URL"), Token: strings.TrimSpace(string(token)), Client: client}
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		s, err := r.Collect(ctx, b)
		if err != nil {
			return err
		}
		return enc.Encode(s)
	case "assess":
		var in k.Input
		if json.Unmarshal(raw, &in) != nil {
			return fmt.Errorf("K8S_INPUT_INVALID")
		}
		in.Now = time.Now().UTC()
		return enc.Encode(k.Assess(in))
	case "verify":
		var in struct {
			Plan     k.Plan     `json:"plan"`
			Snapshot k.Snapshot `json:"snapshot"`
			Revision string     `json:"revision"`
		}
		if json.Unmarshal(raw, &in) != nil {
			return fmt.Errorf("K8S_INPUT_INVALID")
		}
		if err := k.VerifySync(in.Plan, in.Snapshot, in.Revision, time.Now().UTC()); err != nil {
			return err
		}
		return enc.Encode(map[string]any{"status": "ACKNOWLEDGED", "revision": in.Revision, "deployment_spec_hash": in.Snapshot.Deployment.SpecHash})
	case "authorize":
		var in struct {
			Plan     k.Plan     `json:"plan"`
			Snapshot k.Snapshot `json:"snapshot"`
		}
		if json.Unmarshal(raw, &in) != nil {
			return fmt.Errorf("K8S_INPUT_INVALID")
		}
		if err := k.Revalidate(in.Plan, in.Snapshot, time.Now().UTC()); err != nil {
			return err
		}
		return enc.Encode(map[string]string{"status": "AUTHORIZED_FOR_GIT_RECONCILE"})
	case "hpa":
		var in k.HPAInput
		if json.Unmarshal(raw, &in) != nil {
			return fmt.Errorf("K8S_INPUT_INVALID")
		}
		r, err := k.SimulateHPA(in)
		if err != nil {
			return err
		}
		return enc.Encode(r)
	default:
		return fmt.Errorf("K8S_MODE_UNSUPPORTED")
	}
}
