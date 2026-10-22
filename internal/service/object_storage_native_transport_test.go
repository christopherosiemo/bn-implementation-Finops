package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/objectstorage"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
)

type objectStorageNativeRoundTripper func(*http.Request) (*http.Response, error)

func (f objectStorageNativeRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

// This transport is an explicitly labelled AWS double. Product SDK signing,
// exact expected owners, report writer validation and versioned reads remain
// active; only external HTTPS is replaced, while local Compose services pass
// through the existing transport.
func objectStorageNativeTestReader(t *testing.T, ctx context.Context, tenant string) (*provider.ObjectStorageAWS, map[string][]byte) {
	t.Helper()
	const account = "111122223333"
	const collector = "arn:aws:iam::111122223333:role/object-access-collector"
	objects := map[string][]byte{}
	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if e := r.ParseForm(); e != nil || r.Form.Get("Action") != "AssumeRole" || r.Form.Get("RoleArn") != "arn:aws:iam::111122223333:role/object-storage-read" || len(r.Form.Get("ExternalId")) < 32 {
			http.Error(w, "unapproved identity", 403)
			return
		}
		w.Header().Set("Content-Type", "text/xml")
		fmt.Fprintf(w, `<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleResult><Credentials><AccessKeyId>synthetic-object-reader</AccessKeyId><SecretAccessKey>synthetic-object-secret</SecretAccessKey><SessionToken>synthetic-object-session</SessionToken><Expiration>%s</Expiration></Credentials><AssumedRoleUser><Arn>arn:aws:sts::111122223333:assumed-role/object-storage-read/finops-pilot</Arn><AssumedRoleId>SYNTHETIC:finops-pilot</AssumedRoleId></AssumedRoleUser></AssumeRoleResult></AssumeRoleResponse>`, time.Now().UTC().Add(time.Hour).Format(time.RFC3339))
	}))
	t.Cleanup(sts.Close)
	for k, v := range map[string]string{"AWS_ACCESS_KEY_ID": "synthetic-object-bootstrap", "AWS_SECRET_ACCESS_KEY": "synthetic-object-bootstrap-secret", "AWS_SESSION_TOKEN": "", "AWS_ROLE_ARN": "", "AWS_WEB_IDENTITY_TOKEN_FILE": "", "AWS_PROFILE": "", "AWS_EC2_METADATA_DISABLED": "true", "AWS_ENDPOINT_URL_STS": sts.URL} {
		t.Setenv(k, v)
	}
	original := http.DefaultTransport
	http.DefaultTransport = objectStorageNativeRoundTripper(func(r *http.Request) (*http.Response, error) {
		if !strings.HasSuffix(r.URL.Host, ".amazonaws.com") {
			return original.RoundTrip(r)
		}
		if !strings.Contains(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256") {
			return nil, fmt.Errorf("synthetic S3 unsigned native read")
		}
		raw := []byte{}
		status := 200
		contentType := "application/xml"
		version := ""
		q := r.URL.Query()
		switch {
		case strings.HasPrefix(r.URL.Host, "sts."):
			raw = []byte(`<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Arn>arn:aws:sts::111122223333:assumed-role/object-storage-read/finops-pilot</Arn><UserId>SYNTHETIC:finops-pilot</UserId><Account>111122223333</Account></GetCallerIdentityResult></GetCallerIdentityResponse>`)
		case r.URL.Host == "api.pricing.us-east-1.amazonaws.com":
			contentType = "application/x-amz-json-1.1"
			var input struct {
				Filters []struct{ Field, Value string }
			}
			body, _ := io.ReadAll(r.Body)
			if json.Unmarshal(body, &input) != nil {
				return nil, fmt.Errorf("synthetic pricing request")
			}
			sku := ""
			for _, f := range input.Filters {
				if f.Field == "sku" {
					sku = f.Value
				}
			}
			raw = objects["pricing/"+sku]
			if raw == nil {
				status = 404
				raw = []byte(`{"__type":"NotFoundException"}`)
			}
		default:
			if r.Method != "GET" {
				return nil, fmt.Errorf("synthetic S3 mutation rejected")
			}
			if r.Header.Get("x-amz-expected-bucket-owner") != account && !q.Has("max-buckets") {
				return nil, fmt.Errorf("synthetic S3 exact owner missing")
			}
			bucketName := ""
			key := ""
			if at := strings.Index(r.URL.Host, ".s3."); at > 0 {
				bucketName = r.URL.Host[:at]
				key = strings.TrimPrefix(r.URL.Path, "/")
			} else {
				parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/"), "/", 2)
				bucketName = parts[0]
				if len(parts) > 1 {
					key = parts[1]
				}
			}
			switch {
			case q.Has("location"):
				raw = []byte(`<LocationConstraint>eu-west-1</LocationConstraint>`)
			case q.Has("versioning"):
				raw = []byte(`<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>`)
			case q.Has("policy"):
				statements := []model.Document{}
				for _, prefix := range []string{"inventory/", "access/"} {
					resource := "arn:aws:s3:::synthetic-s3-reports/" + prefix + "*"
					allow := model.Document{"Effect": "Allow", "Action": "s3:PutObject", "Resource": resource}
					fences := map[string]string{}
					if prefix == "inventory/" {
						allow["Principal"] = model.Document{"Service": "s3.amazonaws.com"}
						allow["Condition"] = model.Document{"StringEquals": model.Document{"aws:SourceAccount": account}, "ArnLike": model.Document{"aws:SourceArn": "arn:aws:s3:::" + bucketName}}
						fences = map[string]string{"aws:PrincipalServiceName": "s3.amazonaws.com", "aws:SourceArn": "arn:aws:s3:::" + bucketName, "aws:SourceAccount": account}
					} else {
						allow["Principal"] = model.Document{"AWS": collector}
						fences = map[string]string{"aws:PrincipalArn": collector}
					}
					// A destination policy uses the workload bucket ARN, not its own ARN.
					if prefix == "inventory/" {
						sourceName := string(objects["fixture/source_bucket"])
						if sourceName == "" {
							sourceName = "data-bucket"
						}
						allow["Condition"] = model.Document{"StringEquals": model.Document{"aws:SourceAccount": account}, "ArnLike": model.Document{"aws:SourceArn": "arn:aws:s3:::" + sourceName}}
						fences["aws:SourceArn"] = "arn:aws:s3:::" + sourceName
					}
					statements = append(statements, allow)
					fields := []string{}
					for field := range fences {
						fields = append(fields, field)
					}
					sort.Strings(fields)
					for _, field := range fields {
						value := fences[field]
						statements = append(statements, model.Document{"Effect": "Deny", "Principal": "*", "Action": []string{"s3:PutObject", "s3:DeleteObject", "s3:DeleteObjectVersion"}, "Resource": resource, "Condition": model.Document{"StringNotEqualsIfExists": model.Document{field: value}}})
					}
				}
				raw, _ = json.Marshal(model.Document{"Version": "2012-10-17", "Statement": statements})
				contentType = "application/json"
			case q.Has("inventory") && q.Get("id") != "":
				raw = []byte(`<InventoryConfiguration><Id>native-config</Id><IsEnabled>true</IsEnabled><IncludedObjectVersions>All</IncludedObjectVersions><Schedule><Frequency>Daily</Frequency></Schedule><Destination><S3BucketDestination><AccountId>111122223333</AccountId><Bucket>arn:aws:s3:::synthetic-s3-reports</Bucket><Format>CSV</Format><Prefix>inventory</Prefix></S3BucketDestination></Destination><OptionalFields><Field>Size</Field><Field>LastModifiedDate</Field><Field>StorageClass</Field></OptionalFields></InventoryConfiguration>`)
			case q.Has("tagging"):
				raw = []byte(`<Tagging><TagSet/></Tagging>`)
			case q.Get("list-type") == "2":
				names := []string{}
				for name := range objects {
					if strings.HasPrefix(name, bucketName+"/"+q.Get("prefix")) {
						names = append(names, strings.TrimPrefix(name, bucketName+"/"))
					}
				}
				sort.Strings(names)
				var b strings.Builder
				b.WriteString(`<ListBucketResult><IsTruncated>false</IsTruncated>`)
				for _, name := range names {
					fmt.Fprintf(&b, "<Contents><Key>%s</Key><Size>%d</Size></Contents>", html.EscapeString(name), len(objects[bucketName+"/"+name]))
				}
				b.WriteString(`</ListBucketResult>`)
				raw = []byte(b.String())
			case key != "":
				raw = objects[bucketName+"/"+key]
				if raw == nil {
					status = 404
					raw = []byte(`<Error><Code>NoSuchKey</Code></Error>`)
				} else {
					version = "native-version"
					if v := q.Get("versionId"); v != "" && v != version {
						return nil, fmt.Errorf("synthetic pinned version mismatch")
					}
					contentType = "application/octet-stream"
				}
			default:
				status = 403
				raw = []byte(`<Error><Code>AccessDenied</Code></Error>`)
			}
		}
		h := http.Header{"Content-Type": []string{contentType}, "Content-Length": []string{strconv.Itoa(len(raw))}}
		if version != "" {
			h.Set("x-amz-version-id", version)
		}
		return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(bytes.NewReader(raw)), ContentLength: int64(len(raw)), Request: r}, nil
	})
	t.Cleanup(func() { http.DefaultTransport = original })
	encoded, _ := json.Marshal(model.Document{"synthetic-s3-read": model.Document{"tenant_id": tenant, "account_id": account, "role_arn": "arn:aws:iam::111122223333:role/object-storage-read", "external_id": strings.Repeat("synthetic-", 5), "region": "eu-west-1", "approved_writer_principal_arn": collector, "metric_definition_id": "synthetic-approved-access", "metric_definition_version": "1"}})
	factory, e := source.ObjectStorageAWSFactory(string(encoded))
	if e != nil {
		t.Fatal(e)
	}
	reader, e := factory(ctx, objectstorage.Registration{TenantID: tenant, AccountID: account, Region: "eu-west-1", ReadRoleBindingID: "synthetic-s3-read", ReportType: "APP_ACCESS"})
	if e != nil {
		t.Fatal(e)
	}
	return reader, objects
}
