package groupfixtureproducer

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"time"
)

const invocationAuditPath = "/workspace/private/native-invocations.jsonl"

type invocation struct {
	Operation string    `json:"operation"`
	StartedAt time.Time `json:"started_at"`
}

// This local diagnostic records only actual fixed-binary launch attempts. It
// carries no arguments, credentials, authority or provider success assertion.
// The isolated runner pins its bytes after producer exit for acceptance.
func recordTerraformInvocation(operation string) error {
	switch operation {
	case "version", "init", "apply", "plan", "show":
	default:
		return ErrBoundary
	}
	f, err := os.OpenFile(invocationAuditPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return ErrNative
	}
	defer f.Close()
	raw, err := json.Marshal(invocation{operation, time.Now().UTC()})
	if err != nil {
		return ErrNative
	}
	raw = append(raw, '\n')
	if size, err := f.Write(raw); err != nil || size != len(raw) {
		return ErrNative
	}
	if err = f.Sync(); err != nil {
		return ErrNative
	}
	return nil
}

type InvocationAudit struct {
	Counts map[string]uint64 `json:"counts"`
	Total  uint64            `json:"total"`
	SHA256 string            `json:"sha256"`
}

// TerraformInvocations is inspection only. Reconciliation and negative calls
// can prove that no additional fixed Terraform process was launched; a state
// equality check by itself does not establish this fact.
func TerraformInvocations() (InvocationAudit, error) {
	return readInvocationAudit(invocationAuditPath)
}

func readInvocationAudit(name string) (out InvocationAudit, err error) {
	out.Counts = map[string]uint64{}
	info, err := os.Lstat(name)
	if err != nil || !info.Mode().IsRegular() {
		return out, ErrNative
	}
	f, err := os.Open(name)
	if err != nil {
		return out, ErrNative
	}
	defer f.Close()
	digest := sha256.New()
	scanner := bufio.NewScanner(io.TeeReader(f, digest))
	scanner.Buffer(make([]byte, 1024), 4096)
	for scanner.Scan() {
		var entry invocation
		if json.Unmarshal(scanner.Bytes(), &entry) != nil || entry.StartedAt.IsZero() || entry.StartedAt.Location() != time.UTC {
			return out, ErrNative
		}
		switch entry.Operation {
		case "version", "init", "apply", "plan", "show":
		default:
			return out, ErrNative
		}
		out.Counts[entry.Operation]++
		out.Total++
	}
	if scanner.Err() != nil || info.Size() == 0 {
		return out, ErrNative
	}
	// A torn last frame is unknown, even if it happens to contain valid JSON.
	last := make([]byte, 1)
	if _, err = f.ReadAt(last, info.Size()-1); err != nil || last[0] != '\n' {
		return out, ErrNative
	}
	out.SHA256 = hex.EncodeToString(digest.Sum(nil))
	return out, nil
}
