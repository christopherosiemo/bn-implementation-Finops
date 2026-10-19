package fleetcapacityworker

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/christopherosiemo/bn-implementation-Finops/internal/fleetcapacity"
	"github.com/christopherosiemo/bn-implementation-Finops/internal/native"
)

type PopulationReader interface {
	Read(context.Context, native.CapacityInputRequest) (native.CapacityPopulation, error)
}
type privateClient struct {
	url, token, path string
	client           *http.Client
	maximum          int64
}

func (c privateClient) post(ctx context.Context, value any) ([]byte, error) {
	raw, e := json.Marshal(value)
	if e != nil || len(raw) > 64<<20 {
		return nil, ErrJob
	}
	r, e := http.NewRequestWithContext(ctx, http.MethodPost, c.url+c.path, bytes.NewReader(raw))
	if e != nil {
		return nil, ErrJob
	}
	r.Header.Set("Authorization", "Bearer "+c.token)
	r.Header.Set("Content-Type", "application/json")
	response, e := c.client.Do(r)
	if e != nil {
		return nil, ErrJob
	}
	defer response.Body.Close()
	if response.StatusCode != 200 || response.ContentLength > c.maximum {
		return nil, ErrJob
	}
	body, e := io.ReadAll(io.LimitReader(response.Body, c.maximum+1))
	if e != nil || int64(len(body)) > c.maximum {
		return nil, ErrJob
	}
	return body, nil
}

type populationClient struct{ privateClient }

func (c populationClient) Read(ctx context.Context, in native.CapacityInputRequest) (native.CapacityPopulation, error) {
	var p native.CapacityPopulation
	raw, e := c.post(ctx, in)
	if e != nil {
		return p, e
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil || d.Decode(new(any)) != io.EOF {
		return p, ErrJob
	}
	return p, nil
}

type modelClient struct{ privateClient }

func (c modelClient) Calculate(ctx context.Context, in native.CapacityModelRequest) ([]byte, error) {
	return c.post(ctx, in)
}

// OpenHTTPDependencies reads only two commissioned private token files and
// pins both exact installed private service destinations. Paths and methods are
// fixed; tokens are never returned. TLS retains normal certificate/DNS checks.
func OpenHTTPDependencies(ctx context.Context, c Config) (PopulationReader, fleetcapacity.Calculator, func(), error) {
	if c.Validate() != nil {
		return nil, nil, nil, ErrConfiguration
	}
	r, e := privateFile(c.ReaderTokenFile, 4096)
	if e != nil {
		return nil, nil, nil, e
	}
	m, e := privateFile(c.ModelTokenFile, 4096)
	if e != nil {
		clear(r)
		return nil, nil, nil, e
	}
	rt, mt := strings.TrimSpace(string(r)), strings.TrimSpace(string(m))
	clear(r)
	clear(m)
	if rt == "" || mt == "" || strings.ContainsAny(rt+mt, "\x00\r\n\t ") || subtle.ConstantTimeCompare([]byte(rt), []byte(mt)) == 1 {
		return nil, nil, nil, ErrConfiguration
	}
	transports := []*http.Transport{}
	close := func() {
		for _, t := range transports {
			t.CloseIdleConnections()
		}
	}
	makeClient := func(raw, token, path string, max int64) (privateClient, error) {
		u, e := serviceURL(raw)
		if e != nil {
			return privateClient{}, e
		}
		ip, e := privateHost(ctx, u.Hostname())
		if e != nil {
			return privateClient{}, e
		}
		target, pinned := u.Host, net.JoinHostPort(ip, u.Port())
		transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if address != target {
				return nil, ErrConfiguration
			}
			return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, pinned)
		}, ResponseHeaderTimeout: 2 * time.Minute}
		transports = append(transports, transport)
		client := &http.Client{Timeout: 2 * time.Minute, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		return privateClient{url: raw, token: token, path: path, client: client, maximum: max}, nil
	}
	reader, e := makeClient(c.ReaderURL, rt, "/capacity-input", 64<<20)
	if e != nil {
		close()
		return nil, nil, nil, e
	}
	model, e := makeClient(c.ModelURL, mt, "/v4/capacity", 1<<20)
	if e != nil {
		close()
		return nil, nil, nil, e
	}
	return populationClient{reader}, modelClient{model}, close, nil
}
