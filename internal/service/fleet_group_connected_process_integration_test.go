package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/configuration"
	ff "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetfixture"
	g "github.com/christopherosiemo/bn-implementation-Finops/internal/fleetgroup"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/groupfixtureproducer"
)

const connectedDispatchFile = "/workspace/private/connected-dispatch.json"

type connectedProcessDispatch struct {
	Selected ff.Proposal
	Prepared ff.Preparation
	View     g.JournalView
	Keys     g.JournalKeys
	Permit   g.JournalDispatchPermit
	Capture  g.GitTerraformArtifactCapture
}

// This test-binary child has no caller-selected command, path, target or role.
// Its parent holds the committed current database/source fence throughout the
// short child lifetime. The actual native process exits after its fsynced
// positive terminal but before any PG pipeline receipt is published.
func TestFleetGroupConnectedNativeApplyProcess(t *testing.T) {
	if os.Getenv("FLEET_CONNECTED_CHILD") != "APPLY_TERMINAL_EXIT" {
		t.Skip("fixed owned subprocess only")
	}
	if os.Getuid() == 0 || os.Getenv("FLEET_CONNECTED_FIXTURE") != "ISOLATED_FIXTURE" || os.Getenv("FLEET_CONNECTED_S3_ENDPOINT") != "http://minio:9000" {
		t.Fatal("private subprocess boundary")
	}
	for _, key := range []string{"TEST_DATABASE_URL", "DATABASE_URL", "SIGNING_KEY", "SIGNER_TOKEN", "EXECUTOR_TOKEN"} {
		if os.Getenv(key) != "" {
			t.Fatal("native child inherited coordinator authority")
		}
	}
	raw, err := os.ReadFile(connectedDispatchFile)
	if err != nil || len(raw) > 32<<20 {
		t.Fatal("private dispatch record")
	}
	var d connectedProcessDispatch
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&d) != nil || decoder.Decode(new(any)) != io.EOF {
		t.Fatal("private dispatch decode")
	}
	master, err := os.ReadFile("/secrets/archive.key")
	if err != nil || len(master) != 32 {
		t.Fatal("private archive key")
	}
	keys, err := configuration.NewArtifactFixtureKeys(master)
	if err != nil {
		t.Fatal(err)
	}
	client := s3.New(s3.Options{Region: "eu-west-1", Credentials: credentials.NewStaticCredentialsProvider(os.Getenv("FLEET_CONNECTED_S3_USER"), os.Getenv("FLEET_CONNECTED_S3_SECRET"), ""), BaseEndpoint: &[]string{"http://minio:9000"}[0], UsePathStyle: true})
	archive := &groupfixtureproducer.EncryptedArchive{Client: client, Bucket: d.Prepared.Artifacts[0].Bucket, Keys: keys}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	native, err := groupfixtureproducer.OpenNativeStage(ctx, d.Selected, d.Prepared, archive)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = native.Apply(ctx, d.View, d.Keys, d.Permit, d.Capture); err != nil {
		t.Fatal("native subprocess apply", err)
	}
	os.Exit(73)
}

func connectedApplyProcess(ctx context.Context, d connectedProcessDispatch) error {
	raw, err := json.Marshal(d)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(connectedDispatchFile, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(raw); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	defer os.Remove(connectedDispatchFile)
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	command := exec.CommandContext(ctx, executable, "-test.run=^TestFleetGroupConnectedNativeApplyProcess$", "-test.timeout=30s")
	// The native child needs no database login or signing key. In particular
	// the coordinator's disposable-DB administrator is not inherited.
	command.Env = connectedNativeChildEnvironment(os.Environ())
	// Keep failure output bounded and generic; private records/keys are never
	// copied into a diagnostic command or returned error.
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output
	err = command.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 73 {
		return nil
	}
	return errors.New("fixed native subprocess did not reach its positive terminal cutpoint")
}

func connectedNativeChildEnvironment(entries []string) []string {
	allowed := map[string]bool{"PATH": true, "HOME": true, "LANG": true, "LC_ALL": true, "GOMAXPROCS": true, "GOMEMLIMIT": true, "FLEET_CONNECTED_FIXTURE": true, "FLEET_CONNECTED_S3_ENDPOINT": true, "FLEET_CONNECTED_S3_USER": true, "FLEET_CONNECTED_S3_SECRET": true, "FLEET_CONNECTED_IMAGE_SHA256": true}
	out := []string{}
	for _, entry := range entries {
		if allowed[strings.SplitN(entry, "=", 2)[0]] {
			out = append(out, entry)
		}
	}
	return append(out, "FLEET_CONNECTED_CHILD=APPLY_TERMINAL_EXIT")
}

func TestConnectedApplyChildEnvironmentDropsCoordinatorAuthority(t *testing.T) {
	actual := connectedNativeChildEnvironment([]string{"PATH=/usr/local/bin:/usr/bin", "FLEET_CONNECTED_FIXTURE=ISOLATED_FIXTURE", "TEST_DATABASE_URL=private-admin", "DATABASE_URL=private-login", "SIGNING_KEY=private-key", "AWS_ACCESS_KEY_ID=ambient", "DOCKER_HOST=ambient", "UNEXPECTED=private"})
	if strings.Join(actual, "\n") != "PATH=/usr/local/bin:/usr/bin\nFLEET_CONNECTED_FIXTURE=ISOLATED_FIXTURE\nFLEET_CONNECTED_CHILD=APPLY_TERMINAL_EXIT" {
		t.Fatal("unexpected native child authority environment")
	}
}
