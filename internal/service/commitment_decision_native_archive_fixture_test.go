//go:build commitment_decision_native_integration

package service

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/commitmentarchive"
	portfolio "github.com/christopherosiemo/bn-implementation-Finops/internal/commitmentportfolio"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/provider"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/source"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/store"
)

// These are *simulated original provider versions*. Only the separately owned
// actual MinIO app mirror is written now. Neither HTTP Last-Modified below nor
// these generated signatures establish genuine past customer/AWS ownership.
type commitmentDecisionOriginalArchive struct {
	Objects       map[string]provider.BillingObject
	Review        portfolio.DecisionOwnershipArchiveObjectPin
	HourlyObjects int
	EnvelopeBytes int64
}

func commitmentDecisionBuildOriginalArchive(reg portfolio.DecisionOwnershipArchiveRegistration, reviewer portfolio.DecisionOwnershipRegistration, query portfolio.DecisionOwnershipQuery, signer, reviewKey ed25519.PrivateKey, now time.Time) (commitmentDecisionOriginalArchive, error) {
	result := commitmentDecisionOriginalArchive{Objects: map[string]provider.BillingObject{}}
	if len(query.Scope.Resources) != 1 || len(reg.ExternalResources) != 1 || reg.ScopeSHA256 != portfolio.Hash(query.Scope) || reg.IssuedDocumentSHA256 == "" || len(signer) != ed25519.PrivateKeySize || len(reviewKey) != ed25519.PrivateKeySize || !signer.Public().(ed25519.PublicKey).Equal(ed25519.PublicKey(reg.SignerPublicKey)) || !reviewKey.Public().(ed25519.PublicKey).Equal(ed25519.PublicKey(reviewer.PublicKey)) || reviewer.ID == reg.SignerKeyID || reviewer.Subject == reg.SignerCustodianSubject || !query.Period.Start.Equal(query.Period.Start.Truncate(time.Hour)) || !query.Period.End.Equal(query.Period.End.Truncate(time.Hour)) || !query.Period.Start.Before(query.Period.End) {
		return result, errors.New("DECISION_NATIVE_ARCHIVE_SCOPE_DIFFERS")
	}
	external := reg.ExternalResources[0].ExternalResource
	configuration := portfolio.DecisionOwnershipArchiveConfiguration{ExternalResource: external, StateSerial: 1, ConfigurationBundleSHA256: external.ConfigurationSHA256}
	configRaw, err := json.Marshal(configuration)
	if err != nil {
		return result, err
	}
	deployment := portfolio.DecisionOwnershipArchiveDeployment{ExternalResource: external, StateSerial: 1, ConfigurationDocumentSHA256: source.BytesHash(configRaw), Revision: external.GitCommit, Result: "SUCCEEDED", CompletedAt: query.Period.Start}
	deploymentRaw, err := json.Marshal(deployment)
	if err != nil {
		return result, err
	}
	review := portfolio.DecisionOwnershipArchiveReview{SchemaVersion: "1", ID: "fixture-current-independent-archive-review", Query: query, SourceRegistrationSHA256: reg.IssuedDocumentSHA256, SignerPublicKeySHA256: source.BytesHash(reg.SignerPublicKey), Objects: []portfolio.DecisionOwnershipArchiveObjectPin{}, Heads: []portfolio.DecisionOwnershipHead{}, ReviewerRegistrationID: reviewer.ID, ReviewerRegistrationRevision: reviewer.Revision, SignedAt: now.UTC().Truncate(time.Second)}
	head := portfolio.DecisionOwnershipHead{ResourceID: query.Scope.Resources[0].ResourceID, FirstSequence: 1}
	previous := ""
	for at := query.Period.Start; at.Before(query.Period.End); at = at.Add(time.Hour) {
		sequence := uint64(result.HourlyObjects + 1)
		claim := portfolio.DecisionOwnershipArchiveClaim{SchemaVersion: "1", ID: fmt.Sprintf("external-hour-%06d", sequence), CustomerNamespace: reg.CustomerNamespace, SignerKeyID: reg.SignerKeyID, ExternalResource: external, Period: portfolio.Period{Start: at, End: at.Add(time.Hour)}, StateSerial: 1, Sequence: sequence, PreviousSHA256: previous, ConfigurationDocument: configRaw, DeploymentDocument: deploymentRaw, SignedAt: at.Add(time.Hour)}
		message, err := portfolio.DecisionOwnershipArchiveSigningBytes(claim)
		if err != nil {
			return result, err
		}
		envelope := portfolio.DecisionOwnershipArchiveEnvelope{Claim: claim, Algorithm: "Ed25519/commitment-ownership-archive/v1", Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(signer, message))}
		raw, err := json.Marshal(envelope)
		if err != nil {
			return result, err
		}
		if len(raw) > 64<<10 || result.EnvelopeBytes+int64(len(raw)) > 128<<20 || sequence > 100000 {
			return result, errors.New("DECISION_NATIVE_ARCHIVE_ORIGINAL_BOUND")
		}
		pin := portfolio.DecisionOwnershipArchiveObjectPin{Key: reg.Prefix + fmt.Sprintf("external/hour-%06d.json", sequence), VersionID: "original-fixture-" + source.BytesHash(raw), SHA256: source.BytesHash(raw), Bytes: int64(len(raw))}
		result.Objects[pin.Key+"\x00"+pin.VersionID] = provider.BillingObject{Key: pin.Key, VersionID: pin.VersionID, ETag: pin.SHA256, Data: raw, LastModified: claim.Period.End}
		if head.Count == 0 {
			head.FirstSHA256 = pin.SHA256
		}
		head.Count++
		head.LastSequence = sequence
		head.LastSHA256 = pin.SHA256
		previous = pin.SHA256
		result.HourlyObjects++
		result.EnvelopeBytes += int64(len(raw))
		review.Objects = append(review.Objects, pin)
	}
	review.Heads = append(review.Heads, head)
	message, err := portfolio.DecisionOwnershipArchiveReviewSigningBytes(review)
	if err != nil {
		return result, err
	}
	envelope := portfolio.DecisionOwnershipArchiveReviewEnvelope{Review: review, Algorithm: "Ed25519/commitment-ownership-archive-review/v1", Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(reviewKey, message))}
	raw, err := json.Marshal(envelope)
	if err != nil {
		return result, err
	}
	if len(raw) > 24<<20 {
		return result, errors.New("DECISION_NATIVE_ARCHIVE_REVIEW_BOUND")
	}
	result.Review = portfolio.DecisionOwnershipArchiveObjectPin{Key: reg.Prefix + "current-independent-review.json", VersionID: "review-fixture-" + source.BytesHash(raw), SHA256: source.BytesHash(raw), Bytes: int64(len(raw))}
	result.Objects[result.Review.Key+"\x00"+result.Review.VersionID] = provider.BillingObject{Key: result.Review.Key, VersionID: result.Review.VersionID, ETag: result.Review.SHA256, Data: raw, LastModified: review.SignedAt}
	return result, nil
}

type commitmentDecisionOriginalHTTP struct {
	Server               *httptest.Server
	AssumeRoleCalls      atomic.Int64
	VersionedObjectReads atomic.Int64
	RejectedRequests     atomic.Int64
}

// Reuse the UNCHANGED approved source.AWSFactory, STS AssumeRole credential
// path and bounded S3 SDK deserializer. SDK service endpoint configuration is
// test-only and selects this loopback server; no production seam/CLI is added.
// https://docs.aws.amazon.com/sdkref/latest/guide/feature-ss-endpoints.html
func commitmentDecisionOriginalHTTPServer(t *testing.T, bucket, account, role, external string, policy model.Document, objects map[string]provider.BillingObject) *commitmentDecisionOriginalHTTP {
	t.Helper()
	fixture := &commitmentDecisionOriginalHTTP{}
	policyRaw, err := json.Marshal(policy)
	if err != nil {
		t.Fatal("original provider policy fixture invalid")
	}
	reject := func(w http.ResponseWriter) {
		fixture.RejectedRequests.Add(1)
		http.Error(w, "FIXTURE_REQUEST_REFUSED", http.StatusForbidden)
	}
	fixture.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") || r.Header.Get("X-Amz-Date") == "" {
			reject(w)
			return
		}
		if strings.TrimSuffix(r.URL.Path, "/") == "/sts" && r.Method == http.MethodPost {
			r.Body = http.MaxBytesReader(w, r.Body, 8192)
			if r.ParseForm() != nil || r.PostForm.Get("Action") != "AssumeRole" || r.PostForm.Get("RoleArn") != role || r.PostForm.Get("ExternalId") != external || r.PostForm.Get("RoleSessionName") != "finops-pilot" {
				reject(w)
				return
			}
			fixture.AssumeRoleCalls.Add(1)
			w.Header().Set("Content-Type", "text/xml")
			fmt.Fprintf(w, `<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleResult><Credentials><AccessKeyId>fixture-approved-reader</AccessKeyId><SecretAccessKey>fixture-approved-reader-secret</SecretAccessKey><SessionToken>fixture-approved-reader-token</SessionToken><Expiration>%s</Expiration></Credentials><AssumedRoleUser><AssumedRoleId>fixture-role:finops-pilot</AssumedRoleId><Arn>arn:aws:sts::%s:assumed-role/FixtureOriginalArchiveRead/finops-pilot</Arn></AssumedRoleUser></AssumeRoleResult></AssumeRoleResponse>`, time.Now().UTC().Add(time.Hour).Format(time.RFC3339), account)
			return
		}
		prefix := "/s3/" + bucket
		if r.Method != http.MethodGet || !(r.URL.Path == prefix || strings.HasPrefix(r.URL.Path, prefix+"/")) || r.Header.Get("X-Amz-Expected-Bucket-Owner") != account || r.Header.Get("X-Amz-Security-Token") != "fixture-approved-reader-token" {
			reject(w)
			return
		}
		query := r.URL.Query()
		w.Header().Set("Content-Type", "application/xml")
		if values, ok := query["x-id"]; ok {
			expected := "GetObject"
			if r.URL.Path == prefix {
				switch {
				case query.Has("versioning"):
					expected = "GetBucketVersioning"
				case query.Has("location"):
					expected = "GetBucketLocation"
				case query.Has("policy"):
					expected = "GetBucketPolicy"
				default:
					reject(w)
					return
				}
			}
			if len(values) != 1 || values[0] != expected {
				reject(w)
				return
			}
			query.Del("x-id")
		}
		if r.URL.Path == prefix {
			if len(query) != 1 {
				reject(w)
				return
			}
			if query.Has("versioning") {
				io.WriteString(w, `<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>Enabled</Status></VersioningConfiguration>`)
				return
			}
			if query.Has("location") {
				io.WriteString(w, `<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/">eu-west-1</LocationConstraint>`)
				return
			}
			if query.Has("policy") {
				w.Header().Set("Content-Type", "application/json")
				w.Write(policyRaw)
				return
			}
			reject(w)
			return
		}
		if len(query) != 1 || query.Get("versionId") == "" {
			reject(w)
			return
		}
		key := strings.TrimPrefix(r.URL.Path, prefix+"/")
		object, ok := objects[key+"\x00"+query.Get("versionId")]
		if !ok || object.Key != key || object.VersionID != query.Get("versionId") {
			reject(w)
			return
		}
		fixture.VersionedObjectReads.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", strconv.Itoa(len(object.Data)))
		w.Header().Set("Last-Modified", object.LastModified.UTC().Format(http.TimeFormat))
		w.Header().Set("x-amz-version-id", object.VersionID)
		w.Header().Set("ETag", `"`+source.BytesHash(object.Data)+`"`)
		w.Write(object.Data)
	}))
	t.Cleanup(fixture.Server.Close)
	// Only dummy fixture credentials are introduced. NewAWS still assumes the
	// configured target role and external ID before any S3 operation is served.
	for key, value := range map[string]string{"AWS_ACCESS_KEY_ID": "fixture-bootstrap-reader", "AWS_SECRET_ACCESS_KEY": "fixture-bootstrap-reader-secret", "AWS_SESSION_TOKEN": "fixture-bootstrap-token", "AWS_EC2_METADATA_DISABLED": "true", "AWS_ENDPOINT_URL_STS": fixture.Server.URL + "/sts", "AWS_ENDPOINT_URL_S3": fixture.Server.URL + "/s3", "AWS_ENDPOINT_URL": "", "AWS_PROFILE": "", "AWS_SHARED_CREDENTIALS_FILE": "/nonexistent-fixture-credentials", "AWS_CONFIG_FILE": "/nonexistent-fixture-config"} {
		t.Setenv(key, value)
	}
	return fixture
}

// Registrations are commissioned by the operator using real selected artifact
// and current external mappings BEFORE this call. No witnesses/aggregates are
// inserted here: all those rows come from the actual ingestion Pipeline.
func commitmentDecisionCaptureOriginalArchive(ctx context.Context, ingester *store.Store, bindings string, storage *commitmentarchive.ImmutableArchive, target commitmentarchive.Target) (portfolio.DecisionOwnershipArchiveEvidence, error) {
	pipeline := commitmentarchive.Pipeline{Store: ingester, Bindings: bindings, Storage: storage}
	type attempt struct {
		Ordinal             int    `json:"ordinal"`
		Status              string `json:"status"`
		ElapsedMilliseconds int64  `json:"elapsed_milliseconds"`
	}
	attempts := []attempt{}
	defer func() {
		_, _ = fleetCapacityBrowserWrite("/results/decision-native-archive-attempts.json", struct {
			SchemaVersion     string    `json:"schema_version"`
			RunID             string    `json:"run_id"`
			BatchLimitSeconds int       `json:"batch_limit_seconds"`
			Attempts          []attempt `json:"attempts"`
			Fixture           bool      `json:"fixture"`
		}{"1", os.Getenv("COMMITMENT_PORTFOLIO_BROWSER_RUN_ID"), 180, attempts, true})
	}()
	for ordinal := 1; ordinal <= 5; ordinal++ {
		if ctx.Err() != nil {
			return portfolio.DecisionOwnershipArchiveEvidence{}, ctx.Err()
		}
		// The same production three-minute cap is retained. An outer child with
		// that exact deadline lets this fixture distinguish an elapsed batch from
		// an evidence failure without inspecting or reflecting private error text.
		batch, stop := context.WithTimeout(ctx, 3*time.Minute)
		started := time.Now()
		value, err := pipeline.Capture(batch, target)
		expired := errors.Is(batch.Err(), context.DeadlineExceeded)
		stop()
		status := "EVIDENCE_OR_TRANSPORT_FAILURE"
		if err == nil {
			status = "PASS"
		} else if expired {
			status = "BATCH_DEADLINE"
		}
		attempts = append(attempts, attempt{ordinal, status, time.Since(started).Milliseconds()})
		if err == nil {
			return value, nil
		}
		if !expired || ctx.Err() != nil {
			return portfolio.DecisionOwnershipArchiveEvidence{}, err
		}
		// Only an observed elapsed batch resumes ordinary immutable checkpoints.
		// Invalid evidence/authorization/native metadata is never retried here.
	}
	return portfolio.DecisionOwnershipArchiveEvidence{}, context.DeadlineExceeded
}

func TestCommitmentDecisionOriginalArchiveUsesApprovedFactory(t *testing.T) {
	const bucket = "fixture-original-archive"
	const account = "111122223333"
	const role = "arn:aws:iam::111122223333:role/FixtureOriginalArchiveRead"
	const external = "fixture-external-id-012345678901234567890123456789"
	body := []byte(`{"explicit":"synthetic-original-provider"}`)
	object := provider.BillingObject{Key: "external/history/hour.json", VersionID: "original-fixture-version", Data: body, LastModified: time.Date(2024, 1, 1, 1, 0, 0, 0, time.UTC)}
	fixture := commitmentDecisionOriginalHTTPServer(t, bucket, account, role, external, model.Document{"Version": "2012-10-17", "Statement": []any{}}, map[string]provider.BillingObject{object.Key + "\x00" + object.VersionID: object})
	bindings, _ := json.Marshal(map[string]source.AWSReadBinding{"original-archive-read": {TenantID: "fixture-tenant", PayerAccountID: account, AccountID: account, RoleARN: role, ExternalID: external, Region: "eu-west-1"}})
	factory, err := source.AWSFactory(string(bindings))
	if err != nil {
		t.Fatal("approved fixture source binding refused")
	}
	registration := source.Registration{ID: "original-history", TenantID: "fixture-tenant", PayerAccountID: account, Region: "eu-west-1", Bucket: bucket, BucketOwner: account, Prefix: "external/", ReadRoleBindingID: "original-archive-read"}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	reader, err := factory(ctx, registration)
	if err != nil {
		t.Fatal("actual approved factory construction failed")
	}
	if _, err = reader.BillingBucket(ctx, bucket); err != nil {
		t.Fatal("native-shaped bucket SDK projection failed", err)
	}
	bounded, ok := reader.(interface {
		BillingObjectBounded(context.Context, string, string, string, int64) (provider.BillingObject, error)
	})
	if !ok {
		t.Fatal("actual bounded original object SDK reader missing")
	}
	got, err := bounded.BillingObjectBounded(ctx, bucket, object.Key, object.VersionID, 64<<10)
	if err != nil || got.VersionID != object.VersionID || !got.LastModified.Equal(object.LastModified) || string(got.Data) != string(body) {
		t.Fatal("exact original version/body/metadata was not retained", err)
	}
	foreign := registration
	foreign.TenantID = "foreign-tenant"
	if _, err = factory(ctx, foreign); err == nil {
		t.Fatal("approved read binding crossed tenant")
	}
	if fixture.AssumeRoleCalls.Load() != 1 || fixture.VersionedObjectReads.Load() != 1 || fixture.RejectedRequests.Load() != 0 {
		t.Fatal("provider fixture selectors or approved role flow differ")
	}
}
