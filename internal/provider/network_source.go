package provider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/network"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/objectstorage"
)

// OpenFlowObject reads only the already commissioned destination prefix and
// exact immutable object version. Workload payload reads are never exposed.
func (a *AWS) OpenFlowObject(ctx context.Context, r network.Registration, key, version string) (network.Object, error) {
	out := network.Object{}
	if network.ValidateRegistration(r) != nil || !strings.HasPrefix(key, r.Prefix) || strings.Contains(key, "..") || !strings.HasSuffix(key, ".gz") || version == "" || version == "null" {
		return out, network.ErrEvidence
	}
	s := objectstorage.Scope{TenantID: r.TenantID, AccountID: r.AccountID, Region: r.ReportRegion}
	cfg, _, e := objectSDK(a, s)
	if e != nil {
		return out, e
	}
	if e = objectIdentity(ctx, cfg, s); e != nil {
		return out, e
	}
	h := a.client
	if h == nil {
		h = &http.Client{Timeout: 30 * time.Second}
	}
	safe := *h
	safe.Timeout = 0
	safe.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	cfg.HTTPClient = &safe
	p, e := objectClient(cfg).GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(r.ReportBucket), Key: aws.String(key), VersionId: aws.String(version), ExpectedBucketOwner: aws.String(r.ReportOwner)})
	if e != nil {
		return out, errors.New("FLOW_REPORT_OBJECT_UNAVAILABLE")
	}
	if aws.ToString(p.VersionId) != version {
		p.Body.Close()
		return out, errors.New("FLOW_REPORT_VERSION_CHANGED")
	}
	// GET length is optional transport metadata, not a measured zero. The
	// ingestion contract still requires a pinned HEAD size and verifies exact
	// streamed bytes and SHA256 before publishing any generation.
	length := int64(-1)
	if p.ContentLength != nil {
		length = *p.ContentLength
	}
	return network.Object{Bucket: r.ReportBucket, Key: key, VersionID: version, Length: length, LastModified: aws.ToTime(p.LastModified), Body: p.Body}, nil
}
func networkPolicyValues(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []any:
		out := []string{}
		for _, v := range x {
			s, ok := v.(string)
			if !ok {
				return nil
			}
			out = append(out, s)
		}
		return out
	}
	return nil
}
func networkPolicyDocument(v any) model.Document {
	b, _ := json.Marshal(v)
	d := model.Document{}
	_ = json.Unmarshal(b, &d)
	return d
}

// Only native delivery.logs.amazonaws.com writers, exact source account and
// regional log ARN conditions are supported. Customer administrators remain an
// explicit trust boundary; changes to this policy hash invalidate publication.
func validateFlowWriterPolicy(r network.Registration, p model.Document) error {
	values, ok := p["Statement"].([]any)
	if !ok {
		if d, ok := p["Statement"].(map[string]any); ok {
			values = []any{d}
		} else {
			return network.ErrEvidence
		}
	}
	found := false
	for _, value := range values {
		d := networkPolicyDocument(value)
		if d["Effect"] != "Allow" {
			continue
		}
		actions := networkPolicyValues(d["Action"])
		if len(actions) == 0 {
			return network.ErrEvidence
		}
		writer := false
		for _, action := range actions {
			a := strings.ToLower(action)
			if a == "s3:putobject" {
				writer = true
			} else if a == "*" || strings.Contains(a, "*") && (strings.HasPrefix(a, "s3:") || a == "*") || strings.HasPrefix(a, "s3:put") || strings.HasPrefix(a, "s3:delete") || strings.HasPrefix(a, "s3:replicate") {
				return errors.New("FLOW_REPORT_UNSUPPORTED_WRITER_PERMISSION")
			}
		}
		if !writer {
			continue
		}
		principal := networkPolicyDocument(d["Principal"])
		services := networkPolicyValues(principal["Service"])
		if len(principal) != 1 || len(services) != 1 || services[0] != "delivery.logs.amazonaws.com" {
			return errors.New("FLOW_REPORT_UNAPPROVED_WRITER")
		}
		condition := networkPolicyDocument(d["Condition"])
		equals := networkPolicyDocument(condition["StringEquals"])
		accounts := networkPolicyValues(equals["aws:SourceAccount"])
		if len(accounts) != 1 || accounts[0] != r.AccountID {
			return network.ErrEvidence
		}
		arns := networkPolicyValues(networkPolicyDocument(condition["ArnLike"])["aws:SourceArn"])
		if len(arns) == 0 {
			arns = networkPolicyValues(networkPolicyDocument(condition["ArnEquals"])["aws:SourceArn"])
		}
		if len(arns) != 1 || arns[0] != "arn:aws:logs:"+r.Region+":"+r.AccountID+":*" {
			return network.ErrEvidence
		}
		resources := networkPolicyValues(d["Resource"])
		if len(resources) != 1 || !strings.HasSuffix(resources[0], "*") || strings.Count(resources[0], "*") != 1 {
			return network.ErrEvidence
		}
		prefix := strings.TrimSuffix(resources[0], "*")
		minimum := "arn:aws:s3:::" + r.ReportBucket + "/"
		if !strings.HasPrefix(prefix, minimum) || prefix == minimum || !strings.HasPrefix(minimum+r.Prefix, prefix) {
			return network.ErrEvidence
		}
		found = true
	}
	if !found {
		return errors.New("FLOW_REPORT_WRITER_MISSING")
	}
	return nil
}
func (a *AWS) FlowBoundary(ctx context.Context, r network.Registration) (model.Document, error) {
	if network.ValidateRegistration(r) != nil {
		return nil, network.ErrEvidence
	}
	read, e := newNetworkRead(a, network.Scope{TenantID: r.TenantID, AccountID: r.AccountID, Region: r.Region})
	if e != nil {
		return nil, e
	}
	raw, e := read.query(ctx, "DescribeFlowLogs", url.Values{"FlowLogId.1": {r.FlowLogID}})
	if e != nil {
		return nil, e
	}
	root, e := ebsTree(raw, "DescribeFlowLogs")
	if e != nil || len(root.list("flowLogSet")) != 1 {
		return nil, network.ErrEvidence
	}
	n := root.list("flowLogSet")[0]
	if n.value("flowLogId") != r.FlowLogID || n.value("logDestinationType") != "s3" || n.value("flowLogStatus") != "ACTIVE" || n.value("deliverLogsStatus") != "SUCCESS" || n.value("trafficType") != r.TrafficType || n.value("maxAggregationInterval") != stringInt(r.MaxAggregationSeconds) || len(r.ResourceIDs) != 1 || n.value("resourceId") != r.ResourceIDs[0] {
		return nil, errors.New("FLOW_COMMISSIONED_CONFIGURATION_MISMATCH")
	}
	destination := strings.TrimSuffix(n.value("logDestination"), "/")
	expected := "arn:aws:s3:::" + r.ReportBucket
	prefix := strings.TrimSuffix(r.Prefix, "/")
	if destination != expected && destination != expected+"/"+prefix && !strings.HasPrefix(expected+"/"+prefix+"/", destination+"/") {
		return nil, network.ErrEvidence
	}
	fields := []string{}
	for _, field := range strings.Fields(n.value("logFormat")) {
		if !strings.HasPrefix(field, "${") || !strings.HasSuffix(field, "}") {
			return nil, network.ErrEvidence
		}
		fields = append(fields, strings.TrimSuffix(strings.TrimPrefix(field, "${"), "}"))
	}
	if network.Hash(fields) != network.Hash(r.Fields) {
		return nil, errors.New("FLOW_LOG_FORMAT_CHANGED")
	}
	if options := n.get("destinationOptions"); options != nil {
		if format := options.value("fileFormat"); format != "" && format != "plain-text" {
			return nil, errors.New("FLOW_REPORT_FORMAT_UNSUPPORTED")
		}
		if options.value("hiveCompatiblePartitions") == "true" {
			return nil, errors.New("FLOW_HIVE_LAYOUT_UNSUPPORTED")
		}
	}
	deliveryBase := strings.TrimPrefix(destination, expected)
	deliveryBase = strings.Trim(deliveryBase, "/")
	if deliveryBase != "" {
		deliveryBase += "/"
	}
	requiredPrefix := deliveryBase + "AWSLogs/" + r.AccountID + "/vpcflowlogs/" + r.Region + "/"
	if !strings.HasPrefix(r.Prefix, requiredPrefix) {
		return nil, errors.New("FLOW_NATIVE_DELIVERY_PREFIX_MISMATCH")
	}
	s := objectstorage.Scope{TenantID: r.TenantID, AccountID: r.AccountID, Region: r.ReportRegion}
	cfg, capture, e := objectSDK(a, s)
	if e != nil {
		return nil, e
	}
	if e = objectIdentity(ctx, cfg, s); e != nil {
		return nil, e
	}
	c := objectClient(cfg)
	version, e := c.GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: aws.String(r.ReportBucket), ExpectedBucketOwner: aws.String(r.ReportOwner)})
	if e != nil || string(version.Status) != "Enabled" {
		return nil, errors.New("FLOW_VERSIONED_DESTINATION_REQUIRED")
	}
	loc, e := c.GetBucketLocation(ctx, &s3.GetBucketLocationInput{Bucket: aws.String(r.ReportBucket), ExpectedBucketOwner: aws.String(r.ReportOwner)})
	if e != nil {
		return nil, e
	}
	region := string(loc.LocationConstraint)
	if region == "" {
		region = "us-east-1"
	}
	if region == "EU" {
		region = "eu-west-1"
	}
	if region != r.ReportRegion {
		return nil, errors.New("FLOW_DESTINATION_REGION_MISMATCH")
	}
	policy, e := c.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{Bucket: aws.String(r.ReportBucket), ExpectedBucketOwner: aws.String(r.ReportOwner)})
	if e != nil {
		return nil, e
	}
	p := model.Document{}
	if json.Unmarshal([]byte(aws.ToString(policy.Policy)), &p) != nil || validateFlowWriterPolicy(r, p) != nil {
		return nil, errors.New("FLOW_REPORT_WRITER_POLICY_UNAPPROVED")
	}
	configuration := model.Document{"native": rdsNormalizedNode(n), "scope": r.ResourceIDs, "fields": fields}
	evidence, _ := json.Marshal(model.Document{"scope": r, "network_frames": read.frames, "destination_frames": capture.frames})
	return model.Document{"versioning": "Enabled", "owner": r.ReportOwner, "region": region, "configuration": configuration, "configuration_hash": network.Hash(configuration), "writer_policy": p, "writer_policy_hash": network.Hash(p), "raw": evidence, "raw_sha256": network.BytesHash(evidence), "observed_at": time.Now().UTC()}, nil
}
func stringInt(v int) string { return strconv.Itoa(v) }

// FlowObjects lists only a registered commissioned log namespace. The file
// digest is calculated from the pinned streaming body before its use; native
// ETag is not treated as a SHA256 or as a multipart-object checksum.
func (a *AWS) FlowObjects(ctx context.Context, r network.Registration) ([]network.ObjectRef, error) {
	if network.ValidateRegistration(r) != nil {
		return nil, network.ErrEvidence
	}
	if _, e := a.FlowBoundary(ctx, r); e != nil {
		return nil, e
	}
	s := objectstorage.Scope{TenantID: r.TenantID, AccountID: r.AccountID, Region: r.ReportRegion}
	cfg, _, e := objectSDK(a, s)
	if e != nil {
		return nil, e
	}
	if e = objectIdentity(ctx, cfg, s); e != nil {
		return nil, e
	}
	c := objectClient(cfg)
	refs := []network.ObjectRef{}
	token := ""
	seen := map[string]bool{}
	for page := 0; page < 100; page++ {
		in := &s3.ListObjectsV2Input{Bucket: aws.String(r.ReportBucket), ExpectedBucketOwner: aws.String(r.ReportOwner), Prefix: aws.String(r.Prefix), MaxKeys: aws.Int32(1000)}
		if token != "" {
			in.ContinuationToken = aws.String(token)
		}
		out, e := c.ListObjectsV2(ctx, in)
		if e != nil {
			return nil, e
		}
		for _, object := range out.Contents {
			key := aws.ToString(object.Key)
			if !strings.HasPrefix(key, r.Prefix) {
				return nil, network.ErrEvidence
			}
			if !strings.HasSuffix(key, ".gz") {
				continue
			}
			head, e := c.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String(r.ReportBucket), ExpectedBucketOwner: aws.String(r.ReportOwner), Key: aws.String(key)})
			if e != nil {
				return nil, e
			}
			version := aws.ToString(head.VersionId)
			size := aws.ToInt64(head.ContentLength)
			if version == "" || version == "null" || size <= 0 || size > int64(4096*network.RawChunkBytes) {
				return nil, network.ErrEvidence
			}
			body, e := a.OpenFlowObject(ctx, r, key, version)
			if e != nil {
				return nil, e
			}
			digest := sha256.New()
			n, e := io.Copy(digest, io.LimitReader(body.Body, size+1))
			closed := body.Body.Close()
			if e != nil || closed != nil || n != size {
				return nil, errors.New("FLOW_OBJECT_HASH_INCOMPLETE")
			}
			refs = append(refs, network.ObjectRef{Key: key, VersionID: version, Size: size, SHA256: hex.EncodeToString(digest.Sum(nil))})
			if len(refs) > 10000 {
				return nil, errors.New("FLOW_OBJECT_SELECTION_LIMIT")
			}
		}
		if !aws.ToBool(out.IsTruncated) {
			return refs, nil
		}
		next := aws.ToString(out.NextContinuationToken)
		if next == "" || seen[next] {
			return nil, errors.New("FLOW_OBJECT_ENUMERATION_INCOMPLETE")
		}
		seen[next] = true
		token = next
	}
	return nil, errors.New("FLOW_OBJECT_ENUMERATION_INCOMPLETE")
}
