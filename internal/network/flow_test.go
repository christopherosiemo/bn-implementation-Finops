package network

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
)

func flowRegistration() Registration {
	return Registration{ID: "flow-source", TenantID: "tenant", Kind: FlowKind, AccountID: "111122223333", Region: "eu-west-1", ReadRoleBindingID: "network-read", FlowLogID: "fl-0123456789abcdef0", ResourceIDs: []string{"vpc-0123456789abcdef0"}, ReportBucket: "commissioned-reports", ReportOwner: "111122223333", ReportRegion: "eu-west-1", Prefix: "AWSLogs/111122223333/vpcflowlogs/eu-west-1/", Fields: strings.Fields("version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status region az-id vpc-id subnet-id pkt-srcaddr pkt-dstaddr pkt-src-aws-service pkt-dst-aws-service flow-direction traffic-path resource-id"), TrafficType: "ALL", MaxAggregationSeconds: 60, Version: 1, Enabled: true}
}
func flowLine(direction, sourceService, destService, status, byteCount string) string {
	return "7 111122223333 eni-0123456789abcdef0 10.0.0.1 52.95.128.1 1234 443 6 10 " + byteCount + " 1700000000 1700000060 ACCEPT " + status + " eu-west-1 euw1-az1 vpc-0123456789abcdef0 subnet-0123456789abcdef0 10.0.0.1 52.95.128.1 " + sourceService + " " + destService + " " + direction + " 8 -"
}
func TestNetworkFlowNativeDirectionServiceAndPath(t *testing.T) {
	r := flowRegistration()
	if ValidateRegistration(r) != nil {
		t.Fatal("registration")
	}
	egress, e := ParseFlow(r, flowLine("egress", "-", "S3", "OK", "0"))
	if e != nil || egress.Direction != "egress" || egress.DestinationService != "S3" || egress.SourceService != "" || egress.TrafficPath != "8" || egress.Bytes == nil || *egress.Bytes != 0 {
		t.Fatal(egress, e)
	}
	ingress, e := ParseFlow(r, flowLine("ingress", "S3", "-", "OK", "100"))
	if e != nil || ingress.DestinationService != "" || ingress.SourceService != "S3" || ingress.Direction != "ingress" {
		t.Fatal("direction was inverted", ingress, e)
	}
	unknown, e := ParseFlow(r, flowLine("-", "-", "-", "SKIPDATA", "-"))
	if e != nil || unknown.Bytes != nil || unknown.Direction != "" {
		t.Fatal("missing manufactured as zero", unknown, e)
	}
	for name, line := range map[string]string{"wrong account": strings.Replace(flowLine("egress", "-", "S3", "OK", "1"), r.AccountID, "444455556666", 1), "wrong region": strings.Replace(flowLine("egress", "-", "S3", "OK", "1"), "eu-west-1", "us-east-1", 1), "malformed": flowLine("outbound", "-", "S3", "OK", "1"), "overflow": flowLine("egress", "-", "S3", "OK", "18446744073709551616"), "field count": "7 short", "unsupported version": strings.Replace(flowLine("egress", "-", "S3", "OK", "1"), "7 ", "99 ", 1)} {
		t.Run(name, func(t *testing.T) {
			if _, e := ParseFlow(r, line); e == nil {
				t.Fatal("accepted")
			}
		})
	}
}

type flowFixture struct {
	data       []byte
	changed    bool
	calls      int
	badVersion bool
	analytics  map[string]string
	archived   map[string][]byte
	failBatch  bool
	largest    int
	length     *int64
}

func (f *flowFixture) FlowBoundary(context.Context, Registration) (model.Document, error) {
	f.calls++
	hash := "stable"
	if f.changed && f.calls > 1 {
		hash = "changed"
	}
	return model.Document{"configuration_hash": hash, "writer_policy_hash": "writer", "versioning": "Enabled"}, nil
}
func (f *flowFixture) OpenFlowObject(_ context.Context, r Registration, key, version string) (Object, error) {
	v := version
	if f.badVersion {
		v = "changed"
	}
	length := int64(len(f.data))
	if f.length != nil {
		length = *f.length
	}
	return Object{Bucket: r.ReportBucket, Key: key, VersionID: v, Length: length, Body: io.NopCloser(bytes.NewReader(f.data))}, nil
}
func (f *flowFixture) Archive(_ context.Context, tenant, kind, id string, b []byte) (model.Document, error) {
	if len(b) > f.largest {
		f.largest = len(b)
	}
	if f.archived == nil {
		f.archived = map[string][]byte{}
	}
	f.archived[id] = append([]byte{}, b...)
	return model.Document{"id": id, "tenant": tenant, "kind": kind}, nil
}
func (f *flowFixture) Read(_ context.Context, tenant string, d model.Document) ([]byte, error) {
	if d["tenant"] != tenant {
		return nil, ErrEvidence
	}
	return f.archived[model.String(d, "id")], nil
}
func (f *flowFixture) WriteNetworkRows(_ context.Context, _ Scope, generation, batch string, rows []FlowRow) (model.Document, error) {
	if len(rows) > FlowBatchRows {
		return nil, ErrEvidence
	}
	if f.failBatch {
		f.failBatch = false
		return nil, errors.New("interrupted")
	}
	if f.analytics == nil {
		f.analytics = map[string]string{}
	}
	digest := Hash(rows)
	if prior := f.analytics[batch]; prior != "" && prior != digest {
		return nil, ErrEvidence
	}
	f.analytics[batch] = digest
	return model.Document{"rows": len(rows), "row_digest": digest}, nil
}
func gzipFlow(lines string) []byte {
	var b bytes.Buffer
	g := gzip.NewWriter(&b)
	_, _ = g.Write([]byte(lines))
	_ = g.Close()
	return b.Bytes()
}
func flowRef(r Registration, b []byte) []ObjectRef {
	return []ObjectRef{{Key: r.Prefix + "report.log.gz", VersionID: "version-1", SHA256: BytesHash(b), Size: int64(len(b))}}
}
func TestNetworkFlowStreamReplayAndUnknownPopulation(t *testing.T) {
	r := flowRegistration()
	var body strings.Builder
	body.WriteString(strings.Join(r.Fields, " ") + "\n")
	for i := 0; i < 2101; i++ {
		line := strings.Replace(flowLine("egress", "-", "S3", "OK", "100"), "1234 443", fmt.Sprintf("%d 443", 1024+i), 1)
		body.WriteString(line + "\n")
	}
	data := gzipFlow(body.String())
	f := &flowFixture{data: data, failBatch: true}
	refs := flowRef(r, data)
	first, e := IngestFlow(context.Background(), r, refs, f, f, f, nil)
	if e == nil || first.Complete {
		t.Fatal("partial published")
	}
	f.calls = 0
	out, e := IngestFlow(context.Background(), r, refs, f, f, f, nil)
	if e != nil || !out.Complete || out.Rows != 2101 || len(out.Cohorts) != 1 || len(f.analytics) != 2 || f.largest > RawChunkBytes || out.Coverage["complete_traffic_census"] != false {
		t.Fatal(out, e, len(f.analytics))
	}
	f.calls = 0
	replay, e := IngestFlow(context.Background(), r, refs, f, f, f, nil)
	if e != nil || replay.ID != out.ID || replay.PopulationHash != out.PopulationHash || len(f.analytics) != 2 {
		t.Fatal("replay changed", replay, e)
	}
	if out.Cohorts[0]["bytes"] != "210100" {
		t.Fatal("cohort count")
	}
}
func TestNetworkFlowChangedMissingAndTamperedEvidence(t *testing.T) {
	r := flowRegistration()
	data := gzipFlow(flowLine("egress", "-", "S3", "OK", "1") + "\n")
	for name, configure := range map[string]func(*flowFixture, []ObjectRef){"changed version": func(f *flowFixture, _ []ObjectRef) { f.badVersion = true }, "changed boundary": func(f *flowFixture, _ []ObjectRef) { f.changed = true }, "tampered hash": func(_ *flowFixture, refs []ObjectRef) { refs[0].SHA256 = strings.Repeat("a", 64) }, "missing version": func(_ *flowFixture, refs []ObjectRef) { refs[0].VersionID = "" }, "malformed gzip": func(f *flowFixture, _ []ObjectRef) { f.data = []byte("not gzip") }} {
		t.Run(name, func(t *testing.T) {
			f := &flowFixture{data: data}
			refs := flowRef(r, data)
			configure(f, refs)
			out, e := IngestFlow(context.Background(), r, refs, f, f, f, nil)
			if e == nil || out.Complete {
				t.Fatal("untrusted generation", out, e)
			}
		})
	}
	f := &flowFixture{data: data}
	if out, e := IngestFlow(context.Background(), r, nil, f, f, f, nil); e == nil || out.Complete {
		t.Fatal("missing logs became zero")
	}
}

func TestNetworkFlowArchiveUsesFixedChunks(t *testing.T) {
	raw := bytes.Repeat([]byte{0x5a}, RawChunkBytes+37)
	fixture := &flowFixture{}
	r := &chunkReader{ctx: context.Background(), in: bytes.NewReader(raw), archive: fixture, tenant: "tenant", generation: "generation", key: "one.gz", chunk: make([]byte, 0, RawChunkBytes), hash: sha256.New()}
	if _, e := io.CopyBuffer(io.Discard, r, make([]byte, 32<<10)); e != nil {
		t.Fatal(e)
	}
	if e := r.flush(); e != nil {
		t.Fatal(e)
	}
	if len(r.refs) != 2 || fixture.largest != RawChunkBytes || r.refs[1]["size"] != 37 {
		t.Fatal("unbounded chunking", r.refs)
	}
}

func TestNetworkFlowUnknownGETLengthStillRequiresPinnedSizeAndHash(t *testing.T) {
	r := flowRegistration()
	data := gzipFlow(flowLine("egress", "-", "S3", "OK", "1") + "\n")
	for _, scenario := range []string{"unknown valid", "known wrong length", "known zero", "invalid negative", "unknown wrong size", "unknown wrong hash"} {
		t.Run(scenario, func(t *testing.T) {
			length := int64(-1)
			refs := flowRef(r, data)
			switch scenario {
			case "known wrong length":
				length = int64(len(data)) + 1
			case "known zero":
				length = 0
			case "invalid negative":
				length = -2
			case "unknown wrong size":
				refs[0].Size++
			case "unknown wrong hash":
				refs[0].SHA256 = strings.Repeat("a", 64)
			}
			fixture := &flowFixture{data: data, length: &length}
			out, e := IngestFlow(context.Background(), r, refs, fixture, fixture, fixture, nil)
			if scenario == "unknown valid" {
				if e != nil || !out.Complete || out.Rows != 1 {
					t.Fatal("exact pinned body with unknown GET length refused", out, e)
				}
			} else if e == nil || out.Complete {
				t.Fatal("size/hash integrity mismatch accepted", out, e)
			}
		})
	}
}
