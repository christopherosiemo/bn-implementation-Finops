package provider

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/lambdacost"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/model"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type lambdaRead struct {
	a            *AWS
	scope        lambdacost.Scope
	frames       []lambdacost.Frame
	reads, bytes int
	role         string
	bound        map[string]bool
}

func newLambdaRead(a *AWS, s lambdacost.Scope) (*lambdaRead, error) {
	if a == nil || a.cfg.Credentials == nil || a.cfg.Region != s.Region || lambdacost.ValidateScope(s) != nil {
		return nil, lambdacost.ErrEvidence
	}
	return &lambdaRead{a: a, scope: s, bound: map[string]bool{}}, nil
}
func (r *lambdaRead) evidence() lambdacost.Evidence {
	raw, _ := json.Marshal(model.Document{"schema_version": "LAMBDA_SANITIZED_NATIVE_V1", "scope": r.scope, "frames": r.frames})
	return lambdacost.Evidence{SchemaVersion: "1", Scope: r.scope, CollectedAt: time.Now().UTC(), RawSHA256: lambdacost.BytesHash(raw), Raw: raw, ObservationBasis: "SANITIZED_NATIVE_RESPONSE_NOT_SECRET_BEARING_WIRE"}
}
func (r *lambdaRead) retain(action, selector, requestID string, status int, raw []byte) error {
	if len(raw) > lambdacost.MaxPageBytes || r.bytes+len(raw)+len(selector) > lambdacost.MaxCaptureBytes {
		return lambdacost.ErrEvidence
	}
	r.bytes += len(raw) + len(selector)
	r.frames = append(r.frames, lambdacost.Frame{Action: action, Selector: selector, RequestID: requestID, StatusCode: status, Body: json.RawMessage(append([]byte{}, raw...)), SanitizerVersion: "LAMBDA_SECRET_MINIMIZATION_V1"})
	return nil
}

// Never retain Environment values, provider diagnostic messages or presigned
// code URLs. Sanitization happens before a native response enters evidence.
func lambdaSanitize(v any) any {
	switch d := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, x := range d {
			switch k {
			case "Environment":
				env, _ := x.(map[string]any)
				vars, _ := env["Variables"].(map[string]any)
				err, _ := env["Error"].(map[string]any)
				out[k] = model.Document{"present": x != nil, "variable_count": len(vars), "values_redacted": true, "error_code": err["ErrorCode"]}
			case "Location", "RepositoryType", "ResolvedImageUri", "CodeSigningConfigArn":
				if k == "CodeSigningConfigArn" {
					out[k] = x
				}
			case "Message", "message", "StateReason", "LastUpdateStatusReason", "Description": // Free-form strings may contain customer data; structured codes remain.
			default:
				out[k] = lambdaSanitize(x)
			}
		}
		return out
	case []any:
		out := make([]any, len(d))
		for i, x := range d {
			out[i] = lambdaSanitize(x)
		}
		return out
	default:
		return v
	}
}
func (r *lambdaRead) signed(ctx context.Context, method, service, path, query, body, target string) ([]byte, error) {
	c, e := r.a.cfg.Credentials.Retrieve(ctx)
	if e != nil || c.AccessKeyID == "" || c.SecretAccessKey == "" {
		return nil, lambdacost.ErrEvidence
	}
	if e = r.identity(ctx, c); e != nil {
		return nil, e
	}
	return r.dispatch(ctx, c, method, service, path, query, body, target)
}
func (r *lambdaRead) identity(ctx context.Context, c aws.Credentials) error {
	key := lambdacost.BytesHash([]byte(c.AccessKeyID + "\x00" + c.SecretAccessKey + "\x00" + c.SessionToken))
	if r.bound[key] {
		return nil
	}
	raw, e := r.dispatch(ctx, c, "POST", "sts", "/", "", "Action=GetCallerIdentity&Version=2011-06-15", "")
	if e != nil {
		return e
	}
	var out struct {
		Result struct{ Account, Arn, UserId string } `xml:"GetCallerIdentityResult"`
	}
	if xml.Unmarshal(raw, &out) != nil || out.Result.Account != r.scope.AccountID || !strings.HasPrefix(out.Result.Arn, "arn:aws:sts::"+r.scope.AccountID+":assumed-role/") || out.Result.UserId == "" {
		return lambdacost.ErrEvidence
	}
	at := strings.LastIndexByte(out.Result.Arn, '/')
	if at <= len("arn:aws:sts::"+r.scope.AccountID+":assumed-role/") {
		return lambdacost.ErrEvidence
	}
	role := out.Result.Arn[:at]
	if r.role != "" && r.role != role {
		return lambdacost.ErrEvidence
	}
	r.role = role
	r.bound[key] = true
	safe, _ := json.Marshal(model.Document{"account_id": out.Result.Account, "arn": out.Result.Arn, "user_id": out.Result.UserId})
	return r.retain("GetCallerIdentity", "", "", 200, safe)
}
func (r *lambdaRead) dispatch(ctx context.Context, c aws.Credentials, method, service, path, query, body, target string) ([]byte, error) {
	allowed := map[string]bool{"lambda": true, "sts": true, "monitoring": true, "logs": true, "compute-optimizer": true}
	if !allowed[service] || !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "\r\n") {
		return nil, lambdacost.ErrEvidence
	}
	h := r.a.client
	if h == nil {
		h = &http.Client{Timeout: 30 * time.Second}
	}
	safe := *h
	safe.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	for attempt := 0; attempt < 3; attempt++ {
		if ctx.Err() != nil || r.reads >= 2048 {
			return nil, lambdacost.ErrEvidence
		}
		r.reads++
		endpoint := "https://" + service + "." + r.scope.Region + ".amazonaws.com" + path
		if query != "" {
			endpoint += "?" + query
		}
		req, e := http.NewRequestWithContext(ctx, method, endpoint, strings.NewReader(body))
		if e != nil {
			return nil, lambdacost.ErrEvidence
		}
		req.Header.Set("Accept-Encoding", "identity")
		req.Header.Set("Content-Type", "application/json")
		if service == "sts" || service == "monitoring" {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		if target != "" {
			req.Header.Set("X-Amz-Target", target)
			req.Header.Set("Content-Type", "application/x-amz-json-1.1")
		}
		if service == "compute-optimizer" {
			req.Header.Set("Content-Type", "application/x-amz-json-1.0")
		}
		if v4.NewSigner().SignHTTP(ctx, c, req, lambdacost.BytesHash([]byte(body)), service, r.scope.Region, time.Now().UTC()) != nil {
			return nil, lambdacost.ErrEvidence
		}
		res, e := safe.Do(req)
		if e != nil {
			return nil, lambdacost.ErrEvidence
		}
		raw, e := io.ReadAll(io.LimitReader(res.Body, lambdacost.MaxPageBytes+1))
		res.Body.Close()
		if e != nil || len(raw) > lambdacost.MaxPageBytes || res.Header.Get("Content-Encoding") != "" && res.Header.Get("Content-Encoding") != "identity" {
			return nil, lambdacost.ErrEvidence
		}
		if res.StatusCode == 200 {
			return raw, nil
		}
		code := res.Header.Get("x-amzn-ErrorType")
		var doc model.Document
		if json.Unmarshal(raw, &doc) == nil && code == "" {
			code = model.String(doc, "__type")
		}
		if at := strings.LastIndexAny(code, "#:"); at >= 0 {
			code = code[at+1:]
		}
		code = awsErrorCode(code)
		if attempt < 2 && (res.StatusCode == 429 || code == "ThrottlingException" || code == "TooManyRequestsException") {
			timer := time.NewTimer(time.Duration(attempt+1) * 100 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, lambdacost.ErrEvidence
			case <-timer.C:
			}
			continue
		}
		return nil, &QueryRejection{Action: path, Code: code, StatusCode: res.StatusCode}
	}
	return nil, lambdacost.ErrEvidence
}
func (r *lambdaRead) get(ctx context.Context, action, path string, q url.Values) (model.Document, error) {
	raw, e := r.signed(ctx, "GET", "lambda", path, q.Encode(), "", "")
	if e != nil {
		return nil, e
	}
	var doc map[string]any
	if lambdacost.DecodeJSON(raw, &doc) != nil {
		return nil, lambdacost.ErrEvidence
	}
	sanitized := lambdaSanitize(doc)
	safe, e := json.Marshal(sanitized)
	if e != nil {
		return nil, lambdacost.ErrEvidence
	}
	if e = r.retain(action, path+"?"+q.Encode(), "", 200, safe); e != nil {
		return nil, e
	}
	return lambdacost.Document(sanitized), nil
}
func (r *lambdaRead) list(ctx context.Context, action, path, key string, q url.Values) ([]model.Document, error) {
	rows := []model.Document{}
	tokens := map[string]bool{}
	for page := 0; page < 128; page++ {
		d, e := r.get(ctx, action, path, q)
		if e != nil {
			return nil, e
		}
		v, ok := d[key]
		if !ok {
			return nil, lambdacost.ErrEvidence
		}
		list, ok := v.([]any)
		if !ok {
			return nil, lambdacost.ErrEvidence
		}
		for _, v := range list {
			row := lambdacost.Document(v)
			if len(row) == 0 {
				return nil, lambdacost.ErrEvidence
			}
			rows = append(rows, row)
			if len(rows) > lambdacost.MaxRows {
				return nil, lambdacost.ErrEvidence
			}
		}
		next := model.String(d, "NextMarker")
		if next == "" {
			return rows, nil
		}
		if len(next) > 4096 || tokens[next] {
			return nil, lambdacost.ErrEvidence
		}
		tokens[next] = true
		q.Set("Marker", next)
	}
	return nil, lambdacost.ErrEvidence
}
