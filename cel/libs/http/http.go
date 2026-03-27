package http

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

type ClientInterface interface {
	Do(*http.Request) (*http.Response, error)
}

type contextImpl struct {
	client      ClientInterface
	timeout     time.Duration
	maxBodySize int64
}

func NewHTTP(client ClientInterface, timeout time.Duration, maxBodySize int64) ContextInterface {
	if client == nil {
		client = newClient(nil, timeout)
	}
	return &contextImpl{
		client:      client,
		timeout:     timeout,
		maxBodySize: maxBodySize,
	}
}

func (r *contextImpl) Get(url string, headers map[string]string) (any, error) {
	req, err := http.NewRequestWithContext(context.TODO(), "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	for h, v := range headers {
		req.Header.Add(h, v)
	}
	return r.executeRequest(r.client, req)
}

func (r *contextImpl) Post(url string, data any, headers map[string]string) (any, error) {
	body, err := buildRequestData(data)
	if err != nil {
		return nil, fmt.Errorf("failed to encode request data: %w", err)
	}
	req, err := http.NewRequestWithContext(context.TODO(), "POST", url, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	for h, v := range headers {
		req.Header.Add(h, v)
	}
	return r.executeRequest(r.client, req)
}

func (r *contextImpl) executeRequest(client ClientInterface, req *http.Request) (any, error) {
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var body any
	var w http.ResponseWriter

	resp.Body = http.MaxBytesReader(w, resp.Body, r.maxBodySize)
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		if _, ok := err.(*http.MaxBytesError); ok {
			return nil, fmt.Errorf("response length must be less than max allowed response length of %d", r.maxBodySize)
		}

		return nil, fmt.Errorf("unable to decode JSON body: %w", err)
	}

	if bodyMap, ok := body.(map[string]any); ok {
		bodyMap["statusCode"] = resp.StatusCode
		return bodyMap, nil
	}

	return map[string]any{
		"body":       body,
		"statusCode": resp.StatusCode,
	}, nil
}

func (r *contextImpl) Client(caBundle string) (ContextInterface, error) {
	if caBundle == "" {
		return r, nil
	}
	caCertPool := x509.NewCertPool()
	if ok := caCertPool.AppendCertsFromPEM([]byte(caBundle)); !ok {
		return nil, fmt.Errorf("failed to parse PEM CA bundle for APICall")
	}
	return &contextImpl{
		client: newClient(caCertPool, r.timeout),
	}, nil
}

func buildRequestData(data any) (io.Reader, error) {
	buffer := new(bytes.Buffer)
	if err := json.NewEncoder(buffer).Encode(data); err != nil {
		return nil, fmt.Errorf("failed to encode HTTP POST data %v: %w", data, err)
	}
	return buffer, nil
}

func newClient(certPool *x509.CertPool, timeout time.Duration) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 60 * time.Second,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			Proxy:                 http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{
				RootCAs:    certPool,
				MinVersion: tls.VersionTLS12,
			},
		},
		Timeout: timeout,
	}
}
