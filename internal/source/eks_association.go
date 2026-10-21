package source

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/eksassociation"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/kubernetes"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

type EKSApprovedBinding struct {
	TenantID   string `json:"tenant_id"`
	AccountID  string `json:"account_id"`
	Region     string `json:"region"`
	ClusterARN string `json:"cluster_arn"`
}
type EKSReadBinding struct {
	TenantID      string `json:"tenant_id"`
	AccountID     string `json:"account_id"`
	Region        string `json:"region"`
	ClusterARN    string `json:"cluster_arn"`
	KubeSystemUID string `json:"kube_system_uid"`
	TokenFile     string `json:"token_file"`
}

func ValidateEKSApprovedBinding(encoded string, r eksassociation.Registration) error {
	bindings := map[string]EKSApprovedBinding{}
	d := json.NewDecoder(strings.NewReader(encoded))
	d.DisallowUnknownFields()
	if d.Decode(&bindings) != nil || d.Decode(new(any)) != io.EOF {
		return errors.New("EKS_APPROVED_BINDINGS_NOT_CONFIGURED")
	}
	b, ok := bindings[r.KubernetesReadBindingID]
	if !ok || b.TenantID != r.TenantID || b.AccountID != r.AccountID || b.Region != r.Region || b.ClusterARN != r.ClusterARN {
		return errors.New("EKS_APPROVED_BINDING_SCOPE_MISMATCH")
	}
	return nil
}

// Token files are operator-managed and re-read for each collection. Public
// registrations cannot supply a token, endpoint, CA, path or credential value.
func EKSIdentityReader(_ context.Context, encoded string, r eksassociation.Registration, cluster model.Document) (kubernetes.Reader, string, error) {
	bindings := map[string]EKSReadBinding{}
	d := json.NewDecoder(strings.NewReader(encoded))
	d.DisallowUnknownFields()
	if d.Decode(&bindings) != nil || d.Decode(new(any)) != io.EOF {
		return kubernetes.Reader{}, "", errors.New("EKS_READ_BINDINGS_NOT_CONFIGURED")
	}
	b, ok := bindings[r.KubernetesReadBindingID]
	if !ok || b.TenantID != r.TenantID || b.AccountID != r.AccountID || b.Region != r.Region || b.ClusterARN != r.ClusterARN || b.KubeSystemUID == "" || !filepath.IsAbs(b.TokenFile) {
		return kubernetes.Reader{}, "", eksassociation.ErrBinding
	}
	endpoint := model.String(cluster, "endpoint")
	u, e := url.Parse(endpoint)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || cluster["arn"] != r.ClusterARN {
		return kubernetes.Reader{}, "", errors.New("EKS_NATIVE_ENDPOINT_BINDING_INVALID")
	}
	pem, e := base64.StdEncoding.DecodeString(model.String(eksassociation.Document(cluster["certificateAuthority"]), "data"))
	if e != nil || len(pem) == 0 || len(pem) > 64<<10 {
		return kubernetes.Reader{}, "", errors.New("EKS_NATIVE_CA_REQUIRED")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return kubernetes.Reader{}, "", errors.New("EKS_NATIVE_CA_REQUIRED")
	}
	resolved, e := filepath.EvalSymlinks(b.TokenFile)
	if e != nil {
		return kubernetes.Reader{}, "", errors.New("EKS_READ_TOKEN_FILE_UNAVAILABLE")
	}
	relative, e := filepath.Rel(filepath.Dir(b.TokenFile), resolved)
	if e != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return kubernetes.Reader{}, "", errors.New("EKS_READ_TOKEN_FILE_UNAVAILABLE")
	}
	info, e := os.Stat(resolved)
	if e != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 16<<10 {
		return kubernetes.Reader{}, "", errors.New("EKS_READ_TOKEN_FILE_UNAVAILABLE")
	}
	raw, e := os.ReadFile(resolved)
	token := strings.TrimSpace(string(raw))
	if e != nil || token == "" || strings.ContainsAny(token, "\r\n\x00") {
		return kubernetes.Reader{}, "", errors.New("EKS_READ_TOKEN_FILE_UNAVAILABLE")
	}
	transport := &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	return kubernetes.Reader{URL: endpoint, Token: token, Client: &http.Client{Transport: transport, Timeout: 30 * time.Second}}, b.KubeSystemUID, nil
}
