package source

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/eksassociation"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func eksTestRegistration() eksassociation.Registration {
	return eksassociation.Registration{ID: "source", Kind: eksassociation.Kind, TenantID: "tenant", AccountID: "111122223333", Region: "eu-west-1", ClusterARN: "arn:aws:eks:eu-west-1:111122223333:cluster/pilot", ReadRoleBindingID: "aws", KubernetesReadBindingID: "kube", Version: 1, Enabled: true}
}
func TestEKSApprovedBindingIsTenantAccountRegionClusterBound(t *testing.T) {
	r := eksTestRegistration()
	raw, _ := json.Marshal(map[string]EKSApprovedBinding{"kube": {TenantID: r.TenantID, AccountID: r.AccountID, Region: r.Region, ClusterARN: r.ClusterARN}})
	if e := ValidateEKSApprovedBinding(string(raw), r); e != nil {
		t.Fatal(e)
	}
	for _, field := range []string{"tenant", "account", "region", "cluster"} {
		copy := r
		switch field {
		case "tenant":
			copy.TenantID = "foreign"
		case "account":
			copy.AccountID = "999900001111"
		case "region":
			copy.Region = "eu-west-2"
		case "cluster":
			copy.ClusterARN += "-replacement"
		}
		if ValidateEKSApprovedBinding(string(raw), copy) == nil {
			t.Fatalf("%s confusion accepted", field)
		}
	}
}
func TestEKSReaderPinsNativeTLSAndReloadsOperatorTokenWithoutPublicSecrets(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	r := eksTestRegistration()
	file := filepath.Join(t.TempDir(), "token")
	if e := os.WriteFile(file, []byte("first-read-token"), 0600); e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(map[string]EKSReadBinding{"kube": {TenantID: r.TenantID, AccountID: r.AccountID, Region: r.Region, ClusterARN: r.ClusterARN, KubeSystemUID: "observed-uid", TokenFile: file}})
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	cluster := model.Document{"arn": r.ClusterARN, "endpoint": server.URL, "certificateAuthority": model.Document{"data": base64.StdEncoding.EncodeToString(cert)}}
	reader, uid, e := EKSIdentityReader(context.Background(), string(raw), r, cluster)
	if e != nil || uid != "observed-uid" || reader.Token != "first-read-token" {
		t.Fatalf("reader binding unavailable %v", e)
	}
	if e = os.WriteFile(file, []byte("renewed-read-token"), 0600); e != nil {
		t.Fatal(e)
	}
	renewed, _, e := EKSIdentityReader(context.Background(), string(raw), r, cluster)
	if e != nil || renewed.Token != "renewed-read-token" {
		t.Fatal("rotated token not re-read")
	}
	cluster["endpoint"] = "http://localhost"
	if _, _, e = EKSIdentityReader(context.Background(), string(raw), r, cluster); e == nil {
		t.Fatal("HTTP native endpoint accepted")
	}
	cluster["endpoint"] = server.URL
	cluster["arn"] = r.ClusterARN + "-foreign"
	if _, _, e = EKSIdentityReader(context.Background(), string(raw), r, cluster); e == nil {
		t.Fatal("different native cluster accepted")
	}
}
