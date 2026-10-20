package provider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"encoding/xml"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const ebsRawLimit = 64 << 20
const ebsPageLimit = 4 << 20
const ebsReadLimit = 2048

var ErrEBSRead = errors.New("EBS_READ_SCOPE_OR_EVIDENCE_UNAVAILABLE")

type EBSRawPage struct {
	Service  string `json:"service"`
	Region   string `json:"region"`
	Action   string `json:"action"`
	Selector string `json:"selector"`
	Body     []byte `json:"-"`
}
type ebsRead struct {
	a       *AWS
	scope   EBSScope
	raw     bytes.Buffer
	reads   int
	callers []model.Document
	bound   map[[32]byte]bool
	role    string
	started time.Time
	trailAt time.Time
}

func newEBSRead(a *AWS, s EBSScope) (*ebsRead, error) {
	if a == nil || a.cfg.Credentials == nil || !rdsPart.MatchString(s.TenantID) || !metricAccountID.MatchString(s.AccountID) || !validRegion(s.Region) || strings.HasPrefix(s.Region, "cn-") || strings.HasPrefix(s.Region, "us-gov-") {
		return nil, ErrEBSRead
	}
	r := &ebsRead{a: a, scope: s, bound: map[[32]byte]bool{}, callers: []model.Document{}, started: time.Now().UTC()}
	r.raw.WriteString("EBS_READ_V1\n")
	return r, nil
}
func (r *ebsRead) evidence() EBSReadEvidence {
	raw := append([]byte{}, r.raw.Bytes()...)
	return EBSReadEvidence{"1", r.scope, "BOUNDED_NON_ATOMIC_NATIVE_EBS_READ", r.started, time.Now().UTC(), r.callers, rdsSHA(raw), raw}
}
func (r *ebsRead) retain(service, action, selector string, body []byte) error {
	h, e := json.Marshal(EBSRawPage{Service: service, Region: r.scope.Region, Action: action, Selector: selector})
	if e != nil || len(h) > 64<<10 || len(body) > ebsPageLimit || r.raw.Len()+12+len(h)+len(body) > ebsRawLimit {
		return ErrEBSRead
	}
	_ = binary.Write(&r.raw, binary.BigEndian, uint32(len(h)))
	r.raw.Write(h)
	_ = binary.Write(&r.raw, binary.BigEndian, uint64(len(body)))
	r.raw.Write(body)
	return nil
}

// EBSCaptureFrames preserves exact selectors and native bytes. Scope and current
// registration must also be authenticated by the consuming publisher.
func EBSCaptureFrames(raw []byte) ([]EBSRawPage, error) {
	if len(raw) > ebsRawLimit || !bytes.HasPrefix(raw, []byte("EBS_READ_V1\n")) {
		return nil, ErrEBSRead
	}
	r := bytes.NewReader(raw[len("EBS_READ_V1\n"):])
	out := []EBSRawPage{}
	for r.Len() > 0 {
		var h uint32
		var n uint64
		if binary.Read(r, binary.BigEndian, &h) != nil || h == 0 || h > 64<<10 || int(h) > r.Len() {
			return nil, ErrEBSRead
		}
		b := make([]byte, h)
		_, _ = io.ReadFull(r, b)
		var p EBSRawPage
		d := json.NewDecoder(bytes.NewReader(b))
		d.DisallowUnknownFields()
		if d.Decode(&p) != nil || d.Decode(new(any)) != io.EOF || binary.Read(r, binary.BigEndian, &n) != nil || n > ebsPageLimit || n > uint64(r.Len()) {
			return nil, ErrEBSRead
		}
		p.Body = make([]byte, n)
		_, _ = io.ReadFull(r, p.Body)
		out = append(out, p)
		if len(out) > ebsReadLimit {
			return nil, ErrEBSRead
		}
	}
	return out, nil
}
func (r *ebsRead) signed(ctx context.Context, c aws.Credentials, service, action, body string) ([]byte, error) {
	return r.signedBody(ctx, c, service, action, body, "")
}
func (r *ebsRead) signedBody(ctx context.Context, c aws.Credentials, service, action, body, target string) ([]byte, error) {
	if service != "sts" && service != "ec2" && service != "monitoring" && service != "config" && service != "cloudtrail" {
		return nil, ErrEBSRead
	}
	client := r.a.client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	safe := *client
	safe.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	for attempt := 0; attempt < 3; attempt++ {
		// LookupEvents is limited to two requests/second/account/Region. Retries
		// use the same pacing, without increasing the existing retry/read budget.
		if service == "cloudtrail" {
			if delay := time.Until(r.trailAt.Add(550 * time.Millisecond)); delay > 0 {
				timer := time.NewTimer(delay)
				select {
				case <-ctx.Done():
					timer.Stop()
					return nil, ErrEBSRead
				case <-timer.C:
				}
			}
			r.trailAt = time.Now()
		}
		if ctx.Err() != nil || r.reads >= ebsReadLimit {
			return nil, ErrEBSRead
		}
		r.reads++
		req, e := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+service+"."+r.scope.Region+".amazonaws.com/", strings.NewReader(body))
		if e != nil {
			return nil, ErrEBSRead
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept-Encoding", "identity")
		if target != "" {
			req.Header.Set("Content-Type", "application/x-amz-json-1.1")
			req.Header.Set("X-Amz-Target", target)
		}
		if v4.NewSigner().SignHTTP(ctx, c, req, rdsSHA([]byte(body)), service, r.scope.Region, time.Now().UTC()) != nil {
			return nil, ErrEBSRead
		}
		res, e := safe.Do(req)
		if e != nil {
			return nil, ErrEBSRead
		}
		if enc := res.Header.Get("Content-Encoding"); enc != "" && enc != "identity" {
			res.Body.Close()
			return nil, ErrEBSRead
		}
		raw, e := io.ReadAll(io.LimitReader(res.Body, ebsPageLimit+1))
		res.Body.Close()
		if e != nil || len(raw) > ebsPageLimit {
			return nil, ErrEBSRead
		}
		if res.StatusCode == 200 {
			return raw, nil
		}
		var f struct {
			Errors []struct {
				Code string `xml:"Code"`
			} `xml:"Errors>Error"`
			Error struct {
				Code string `xml:"Code"`
			} `xml:"Error"`
		}
		_ = xml.Unmarshal(raw, &f)
		code := f.Error.Code
		if len(f.Errors) == 1 {
			code = f.Errors[0].Code
		}
		if code == "" {
			var j map[string]any
			_ = json.Unmarshal(raw, &j)
			code, _ = j["__type"].(string)
			if i := strings.LastIndexAny(code, "#:"); i >= 0 {
				code = code[i+1:]
			}
		}
		code = awsErrorCode(code)
		if attempt < 2 && (res.StatusCode == 429 || code == "Throttling" || code == "ThrottlingException" || code == "RequestLimitExceeded") {
			timer := time.NewTimer(time.Duration(attempt+1) * 100 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, ErrEBSRead
			case <-timer.C:
			}
			continue
		}
		return nil, &QueryRejection{Action: action, Code: code, StatusCode: res.StatusCode}
	}
	return nil, ErrEBSRead
}
func (r *ebsRead) identity(ctx context.Context, c aws.Credentials) error {
	key := sha256.Sum256([]byte(c.AccessKeyID + "\x00" + c.SecretAccessKey + "\x00" + c.SessionToken))
	if r.bound[key] {
		return nil
	}
	v := url.Values{"Action": {"GetCallerIdentity"}, "Version": {"2011-06-15"}}
	raw, e := r.signed(ctx, c, "sts", "GetCallerIdentity", v.Encode())
	if e != nil {
		return e
	}
	n, e := ebsTree(raw, "GetCallerIdentity")
	if e != nil {
		return e
	}
	n = n.get("GetCallerIdentityResult")
	if n == nil {
		return ErrEBSRead
	}
	account, arn, user := n.value("Account"), n.value("Arn"), n.value("UserId")
	prefix := "arn:aws:sts::" + r.scope.AccountID + ":assumed-role/"
	at := strings.LastIndexByte(arn, '/')
	if account != r.scope.AccountID || !strings.HasPrefix(arn, prefix) || at <= len(prefix) || at == len(arn)-1 || len(arn) > 2048 || user == "" || len(user) > 256 {
		return ErrEBSRead
	}
	role := arn[:at]
	if r.role != "" && r.role != role {
		return ErrEBSRead
	}
	r.role = role
	if e = r.retain("sts", "GetCallerIdentity", v.Encode(), raw); e != nil {
		return e
	}
	r.callers = append(r.callers, model.Document{"account_id": account, "arn": arn, "user_id": user, "raw_sha256": rdsSHA(raw)})
	r.bound[key] = true
	return nil
}
func (r *ebsRead) query(ctx context.Context, service, action string, v url.Values) ([]byte, error) {
	allowed := map[string]bool{"DescribeVolumes": true, "DescribeSnapshots": true, "DescribeImages": true, "DescribeFastSnapshotRestores": true, "DescribeSnapshotTierStatus": true, "DescribeLockedSnapshots": true, "DescribeSnapshotAttribute": true, "DescribeVolumesModifications": true, "DescribeVolumeStatus": true, "DescribeInstances": true, "DescribeInstanceTypes": true, "GetMetricStatistics": true}
	if !allowed[action] || service != "ec2" && service != "monitoring" || service == "monitoring" && action != "GetMetricStatistics" || service == "ec2" && action == "GetMetricStatistics" {
		return nil, ErrEBSRead
	}
	version := "2016-11-15"
	if service == "monitoring" {
		version = "2010-08-01"
	}
	v.Set("Action", action)
	v.Set("Version", version)
	c, e := r.a.cfg.Credentials.Retrieve(ctx)
	if e != nil || c.AccessKeyID == "" || c.SecretAccessKey == "" {
		return nil, ErrEBSRead
	}
	if e = r.identity(ctx, c); e != nil {
		return nil, e
	}
	body := v.Encode()
	raw, e := r.signed(ctx, c, service, action, body)
	if e != nil {
		return nil, e
	}
	if e = r.retain(service, action, body, raw); e != nil {
		return nil, e
	}
	return raw, nil
}

// Only collection item/member elements may repeat. Every singleton, including
// unknown native fields, is retained and duplicate singletons are rejected.
func ebsTree(raw []byte, action string) (*rdsNode, error) {
	d := xml.NewDecoder(bytes.NewReader(raw))
	stack := []*rdsNode{}
	var root *rdsNode
	nodes := 0
	for {
		tok, e := d.Token()
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, ErrEBSRead
		}
		switch x := tok.(type) {
		case xml.StartElement:
			nodes++
			if nodes > 200000 {
				return nil, ErrEBSRead
			}
			n := &rdsNode{name: x.Name.Local}
			if len(stack) == 0 {
				if root != nil || n.name != action+"Response" {
					return nil, ErrEBSRead
				}
				root = n
			} else {
				p := stack[len(stack)-1]
				if n.name != "item" && n.name != "member" && p.get(n.name) != nil {
					return nil, ErrEBSRead
				}
				p.children = append(p.children, n)
			}
			stack = append(stack, n)
			if len(stack) > 64 {
				return nil, ErrEBSRead
			}
		case xml.CharData:
			if len(stack) == 0 {
				if strings.TrimSpace(string(x)) != "" {
					return nil, ErrEBSRead
				}
			} else {
				stack[len(stack)-1].text += string(x)
			}
		case xml.EndElement:
			if len(stack) == 0 {
				return nil, ErrEBSRead
			}
			stack = stack[:len(stack)-1]
		case xml.Directive:
			return nil, ErrEBSRead
		}
	}
	if root == nil || len(raw) > ebsPageLimit {
		return nil, ErrEBSRead
	}
	return root, nil
}
