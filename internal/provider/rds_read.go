package provider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const rdsRawLimit = 32 << 20
const rdsPageLimit = 4 << 20
const rdsReadLimit = 256

var rdsPart = regexp.MustCompile("^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
var rdsIdentifier = regexp.MustCompile("^[A-Za-z][A-Za-z0-9-]{0,254}$")
var rdsClass = regexp.MustCompile("^db\\.[a-z0-9]+\\.[a-z0-9]+$")
var ErrRDSRead = errors.New("RDS_READ_SCOPE_OR_EVIDENCE_UNAVAILABLE")

func rdsSHA(b []byte) string { v := sha256.Sum256(b); return hex.EncodeToString(v[:]) }
func validateRDSScope(s RDSScope) error {
	if !rdsPart.MatchString(s.TenantID) || !metricAccountID.MatchString(s.AccountID) || !validRegion(s.Region) || strings.HasPrefix(s.Region, "cn-") || strings.HasPrefix(s.Region, "us-gov-") {
		return ErrRDSRead
	}
	return nil
}
func rdsARN(s RDSScope, arn, kind string) (string, error) {
	prefix := "arn:aws:rds:" + s.Region + ":" + s.AccountID + ":" + kind + ":"
	if !strings.HasPrefix(arn, prefix) {
		return "", ErrRDSRead
	}
	id := strings.TrimPrefix(arn, prefix)
	if kind == "ri" {
		if !rdsPart.MatchString(id) {
			return "", ErrRDSRead
		}
	} else if !rdsIdentifier.MatchString(id) {
		return "", ErrRDSRead
	}
	return id, nil
}

type RDSRawPage struct {
	Service  string `json:"service"`
	Region   string `json:"region"`
	Action   string `json:"action"`
	Selector string `json:"selector"`
	Body     []byte `json:"-"`
}
type rdsRead struct {
	a       *AWS
	scope   RDSScope
	raw     bytes.Buffer
	reads   int
	callers []model.Document
	bound   map[[32]byte]bool
	role    string
	started time.Time
}

func newRDSRead(a *AWS, s RDSScope) (*rdsRead, error) {
	if a == nil || a.cfg.Credentials == nil || validateRDSScope(s) != nil {
		return nil, ErrRDSRead
	}
	r := &rdsRead{a: a, scope: s, bound: map[[32]byte]bool{}, callers: []model.Document{}, started: time.Now().UTC()}
	r.raw.WriteString("RDS_READ_V1\n")
	return r, nil
}
func (r *rdsRead) evidence() RDSReadEvidence {
	raw := append([]byte{}, r.raw.Bytes()...)
	return RDSReadEvidence{"1", r.scope, "BOUNDED_NON_ATOMIC_NATIVE_RDS_READ", r.started, time.Now().UTC(), r.callers, rdsSHA(raw), raw}
}
func (r *rdsRead) retain(service, region, action, selector string, body []byte) error {
	h, e := json.Marshal(RDSRawPage{Service: service, Region: region, Action: action, Selector: selector})
	if e != nil || len(h) > 64<<10 || r.raw.Len()+12+len(h)+len(body) > rdsRawLimit {
		return ErrRDSRead
	}
	_ = binary.Write(&r.raw, binary.BigEndian, uint32(len(h)))
	r.raw.Write(h)
	_ = binary.Write(&r.raw, binary.BigEndian, uint64(len(body)))
	r.raw.Write(body)
	return nil
}

// RDSCaptureFrames reparses only bounded exact framed requests/responses. A
// database publisher must also repeat registered scope/currentness checks.
func RDSCaptureFrames(raw []byte) ([]RDSRawPage, error) {
	if len(raw) > rdsRawLimit || !bytes.HasPrefix(raw, []byte("RDS_READ_V1\n")) {
		return nil, ErrRDSRead
	}
	r := bytes.NewReader(raw[len("RDS_READ_V1\n"):])
	out := []RDSRawPage{}
	for r.Len() > 0 {
		var h uint32
		var n uint64
		if binary.Read(r, binary.BigEndian, &h) != nil || h == 0 || h > 64<<10 || int(h) > r.Len() {
			return nil, ErrRDSRead
		}
		b := make([]byte, h)
		_, _ = io.ReadFull(r, b)
		var p RDSRawPage
		d := json.NewDecoder(bytes.NewReader(b))
		d.DisallowUnknownFields()
		if d.Decode(&p) != nil || d.Decode(new(any)) != io.EOF || binary.Read(r, binary.BigEndian, &n) != nil || n > rdsPageLimit || n > uint64(r.Len()) {
			return nil, ErrRDSRead
		}
		p.Body = make([]byte, n)
		_, _ = io.ReadFull(r, p.Body)
		out = append(out, p)
		if len(out) > rdsReadLimit {
			return nil, ErrRDSRead
		}
	}
	return out, nil
}
func (r *rdsRead) identity(ctx context.Context, c aws.Credentials) error {
	key := sha256.Sum256([]byte(c.AccessKeyID + "\x00" + c.SecretAccessKey + "\x00" + c.SessionToken))
	if r.bound[key] {
		return nil
	}
	v := url.Values{"Action": {"GetCallerIdentity"}, "Version": {"2011-06-15"}}
	raw, e := r.signed(ctx, c, "sts", r.scope.Region, "GetCallerIdentity", "/", v.Encode(), "")
	if e != nil {
		return e
	}
	var x struct {
		Result struct {
			Account string `xml:"Account"`
			ARN     string `xml:"Arn"`
			UserID  string `xml:"UserId"`
		} `xml:"GetCallerIdentityResult"`
	}
	if rdsXML(raw, "GetCallerIdentityResponse", "GetCallerIdentityResult", "", &x) != nil || x.Result.Account != r.scope.AccountID || !strings.HasPrefix(x.Result.ARN, "arn:aws:sts::"+r.scope.AccountID+":assumed-role/") || x.Result.UserID == "" {
		return ErrRDSRead
	}
	at := strings.LastIndexByte(x.Result.ARN, '/')
	if at <= len("arn:aws:sts::"+r.scope.AccountID+":assumed-role/") || at == len(x.Result.ARN)-1 || len(x.Result.ARN) > 2048 || len(x.Result.UserID) > 256 {
		return ErrRDSRead
	}
	role := x.Result.ARN[:at]
	if r.role != "" && r.role != role {
		return ErrRDSRead
	}
	r.role = role
	if e = r.retain("sts", r.scope.Region, "GetCallerIdentity", v.Encode(), raw); e != nil {
		return e
	}
	r.callers = append(r.callers, model.Document{"account_id": x.Result.Account, "arn": x.Result.ARN, "user_id": x.Result.UserID, "raw_sha256": rdsSHA(raw)})
	r.bound[key] = true
	return nil
}
func (r *rdsRead) signed(ctx context.Context, c aws.Credentials, service, region, action, endpointPath, body, target string) ([]byte, error) {
	hosts := map[string]string{"sts": "sts." + region + ".amazonaws.com", "rds": "rds." + region + ".amazonaws.com", "monitoring": "monitoring." + region + ".amazonaws.com", "pricing": "api.pricing.us-east-1.amazonaws.com", "savingsplans": "savingsplans.us-east-1.amazonaws.com", "compute-optimizer": "compute-optimizer." + region + ".amazonaws.com"}
	host, ok := hosts[service]
	if !ok {
		return nil, ErrRDSRead
	}
	client := r.a.client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	safe := *client
	safe.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	for attempt := 0; attempt < 3; attempt++ {
		if ctx.Err() != nil || r.reads >= rdsReadLimit {
			return nil, ErrRDSRead
		}
		r.reads++
		req, e := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+host+endpointPath, strings.NewReader(body))
		if e != nil {
			return nil, ErrRDSRead
		}
		req.Header.Set("Accept-Encoding", "identity")
		if target == "" {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		} else {
			req.Header.Set("Content-Type", "application/x-amz-json-1.1")
			if target != "-" {
				req.Header.Set("X-Amz-Target", target)
			} else {
				req.Header.Set("Content-Type", "application/json")
			}
			if service == "compute-optimizer" {
				req.Header.Set("Content-Type", "application/x-amz-json-1.0")
			}
		}
		if e = v4.NewSigner().SignHTTP(ctx, c, req, rdsSHA([]byte(body)), service, region, time.Now().UTC()); e != nil {
			return nil, ErrRDSRead
		}
		response, e := safe.Do(req)
		if e != nil {
			return nil, ErrRDSRead
		}
		if response.Header.Get("Content-Encoding") != "" && response.Header.Get("Content-Encoding") != "identity" {
			response.Body.Close()
			return nil, ErrRDSRead
		}
		raw, e := io.ReadAll(io.LimitReader(response.Body, rdsPageLimit+1))
		response.Body.Close()
		if e != nil || len(raw) > rdsPageLimit {
			return nil, ErrRDSRead
		}
		if response.StatusCode == 200 {
			return raw, nil
		}
		var failure struct {
			Error struct {
				Code string `xml:"Code"`
			} `xml:"Error"`
		}
		_ = xml.Unmarshal(raw, &failure)
		code := failure.Error.Code
		if code == "" {
			var doc map[string]any
			_ = json.Unmarshal(raw, &doc)
			code, _ = doc["__type"].(string)
			if i := strings.LastIndexAny(code, "#:"); i >= 0 {
				code = code[i+1:]
			}
		}
		code = awsErrorCode(code)
		if attempt < 2 && (response.StatusCode == 429 || code == "Throttling" || code == "ThrottlingException" || code == "RequestLimitExceeded") {
			timer := time.NewTimer(time.Duration(attempt+1) * 100 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, ErrRDSRead
			case <-timer.C:
			}
			continue
		}
		return nil, &QueryRejection{Action: action, Code: code, StatusCode: response.StatusCode}
	}
	return nil, ErrRDSRead
}
func (r *rdsRead) query(ctx context.Context, service, action string, v url.Values) ([]byte, error) {
	version := "2014-10-31"
	if service == "monitoring" {
		version = "2010-08-01"
	} else if service != "rds" {
		return nil, ErrRDSRead
	}
	allowed := map[string]bool{"DescribeDBInstances": true, "DescribeDBClusters": true, "DescribeReservedDBInstances": true, "DescribeOrderableDBInstanceOptions": true, "DescribeDBParameters": true, "DescribeDBClusterParameters": true, "DescribeValidDBInstanceModifications": true, "GetMetricStatistics": true}
	if !allowed[action] || service == "monitoring" && action != "GetMetricStatistics" || service == "rds" && action == "GetMetricStatistics" {
		return nil, ErrRDSRead
	}
	v.Set("Action", action)
	v.Set("Version", version)
	c, e := r.a.cfg.Credentials.Retrieve(ctx)
	if e != nil || c.AccessKeyID == "" || c.SecretAccessKey == "" {
		return nil, ErrRDSRead
	}
	if e = r.identity(ctx, c); e != nil {
		return nil, e
	}
	body := v.Encode()
	raw, e := r.signed(ctx, c, service, r.scope.Region, action, "/", body, "")
	if e != nil {
		return nil, e
	}
	if e = r.retain(service, r.scope.Region, action, body, raw); e != nil {
		return nil, e
	}
	return raw, nil
}
func (r *rdsRead) jsonRead(ctx context.Context, service, action string, p model.Document) ([]byte, error) {
	target, region, endpointPath := "", "us-east-1", "/"
	switch service {
	case "pricing":
		if action != "GetProducts" {
			return nil, ErrRDSRead
		}
		target = "AWSPriceListService.GetProducts"
	case "savingsplans":
		if action != "DescribeSavingsPlans" {
			return nil, ErrRDSRead
		}
		target = "-"
		endpointPath = "/DescribeSavingsPlans"
	case "compute-optimizer":
		if action != "GetRDSDatabaseRecommendations" {
			return nil, ErrRDSRead
		}
		region = r.scope.Region
		target = "ComputeOptimizerService.GetRDSDatabaseRecommendations"
	default:
		return nil, ErrRDSRead
	}
	body, e := json.Marshal(p)
	if e != nil {
		return nil, ErrRDSRead
	}
	c, e := r.a.cfg.Credentials.Retrieve(ctx)
	if e != nil {
		return nil, ErrRDSRead
	}
	if e = r.identity(ctx, c); e != nil {
		return nil, e
	}
	raw, e := r.signed(ctx, c, service, region, action, endpointPath, string(body), target)
	if e != nil {
		return nil, e
	}
	if e = r.retain(service, region, action, string(body), raw); e != nil {
		return nil, e
	}
	return raw, nil
}

// Critical envelope and record singleton duplicates fail closed. Unknown native
// fields remain in raw bytes; they are never interpreted as capability flags.
func rdsXML(raw []byte, root, result, collection string, out any) error {
	d := xml.NewDecoder(bytes.NewReader(raw))
	stack := []string{}
	seen := map[string]bool{}
	recordFields := map[int]map[string]bool{}
	roots := 0
	results := 0
	collections := 0
	for {
		token, e := d.Token()
		if e == io.EOF {
			break
		}
		if e != nil {
			return ErrRDSRead
		}
		switch t := token.(type) {
		case xml.StartElement:
			stack = append(stack, t.Name.Local)
			if len(stack) > 64 {
				return ErrRDSRead
			}
			if len(stack) == 1 {
				roots++
				if roots != 1 || t.Name.Local != root {
					return ErrRDSRead
				}
			}
			p := strings.Join(stack, "/")
			if len(stack) == 2 && t.Name.Local == result {
				results++
			}
			if len(stack) == 3 && stack[1] == result && t.Name.Local == collection {
				collections++
			}
			if len(stack) <= 3 {
				if seen[p] {
					return ErrRDSRead
				}
				seen[p] = true
			}
			if len(stack) == 4 && stack[2] == collection {
				recordFields[4] = map[string]bool{}
			}
			if fields := recordFields[len(stack)-1]; fields != nil {
				if fields[t.Name.Local] {
					return ErrRDSRead
				}
				fields[t.Name.Local] = true
			}
		case xml.EndElement:
			delete(recordFields, len(stack))
			if len(stack) == 0 {
				return ErrRDSRead
			}
			stack = stack[:len(stack)-1]
		case xml.Directive:
			return ErrRDSRead
		case xml.CharData:
			if len(stack) == 0 && strings.TrimSpace(string(t)) != "" {
				return ErrRDSRead
			}
		}
	}
	if roots != 1 || results != 1 || collection != "" && collections != 1 {
		return ErrRDSRead
	}
	if xml.Unmarshal(raw, out) != nil {
		return ErrRDSRead
	}
	return nil
}
