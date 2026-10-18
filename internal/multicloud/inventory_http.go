package multicloud

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

const computeScope = "https://www.googleapis.com/auth/compute.readonly"
const monitoringScope = "https://www.googleapis.com/auth/monitoring.read"
const computeAPI = "https://compute.googleapis.com/compute/v1"
const monitoringAPI = "https://monitoring.googleapis.com/v3"

var membershipReadPath = regexp.MustCompile(`^/compute/v1/projects/[a-z][a-z0-9-]+/(?:zones|regions)/[a-z0-9-]+/instanceGroupManagers/[a-z][a-z0-9-]*/listManagedInstances$`)

// nativeRead has one narrowly documented read-only POST exception: Google's
// listManagedInstances method. It contains no start/stop/update/delete verbs.
func (c Config) nativeRead(ctx context.Context, method, address, scope string) (Object, Document, error) {
	u, e := url.Parse(address)
	if e != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" || u.Fragment != "" || !(u.Host == "management.azure.com" || u.Host == "compute.googleapis.com" || u.Host == "monitoring.googleapis.com") {
		return Object{}, nil, errors.New("INVENTORY_ENDPOINT_NOT_APPROVED")
	}
	if method != http.MethodGet && !(method == http.MethodPost && u.Host == "compute.googleapis.com" && membershipReadPath.MatchString(u.Path)) {
		return Object{}, nil, errors.New("INVENTORY_METHOD_NOT_ALLOWED")
	}
	token, e := c.Tokens.Token(ctx, scope)
	if e != nil || token == "" || strings.ContainsAny(token, "\r\n") {
		return Object{}, nil, errors.New("INVENTORY_READ_IDENTITY_UNAVAILABLE")
	}
	req, e := http.NewRequestWithContext(ctx, method, address, nil)
	if e != nil {
		return Object{}, nil, errors.New("INVENTORY_REQUEST_INVALID")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Encoding", "identity")
	client := *c.HTTP
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, e := client.Do(req)
	if e != nil {
		return Object{}, nil, errors.New("INVENTORY_READ_UNAVAILABLE")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return Object{}, nil, errors.New("INVENTORY_PROVIDER_REJECTED")
	}
	if encoding := resp.Header.Get("Content-Encoding"); encoding != "" && encoding != "identity" {
		return Object{}, nil, errors.New("INVENTORY_ENCODING_UNSUPPORTED")
	}
	raw, e := io.ReadAll(io.LimitReader(resp.Body, MaxBodyBytes+1))
	if e != nil || len(raw) > MaxBodyBytes {
		return Object{}, nil, errors.New("INVENTORY_RESPONSE_LIMIT")
	}
	d, e := decode(raw)
	return Object{Resource: address, Body: raw, Bytes: int64(len(raw)), SHA256: BytesHash(raw), ETag: resp.Header.Get("ETag")}, d, e
}
func nextNativeLink(next, host, path string) error {
	u, e := url.Parse(next)
	if e != nil || u.Scheme != "https" || u.Host != host || u.User != nil || u.Fragment != "" || !strings.EqualFold(u.Path, path) {
		return errors.New("INVENTORY_NEXT_LINK_INVALID")
	}
	return nil
}
func googleLink(raw, project, kind, scope, collection, name string) bool {
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "https" || (u.Host != "www.googleapis.com" && u.Host != "compute.googleapis.com") || u.User != nil || u.Port() != "" || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	return u.Path == "/compute/v1/projects/"+project+"/"+kind+"/"+scope+"/"+collection+"/"+name
}
