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
	"net/url"
	"strings"
	"time"
)

// normalizeHost lowercases a DNS hostname and strips any trailing dot.
// DNS hostnames are case-insensitive and the trailing-dot (FQDN) form is equivalent.
func normalizeHost(h string) string {
	return strings.ToLower(strings.TrimRight(h, "."))
}

// effectivePort returns the port for a URL, falling back to the scheme's default
// when the URL omits an explicit port.
func effectivePort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	switch u.Scheme {
	case "https":
		return "443"
	case "http":
		return "80"
	}
	return ""
}

// secureDialContext returns a DialContext function that validates resolved IPs
// against the given blocked CIDRs before establishing a connection. It resolves
// the hostname itself and dials the validated IP directly, closing the
// DNS-rebinding window that arises when validation and dialing use separate
// DNS lookups.
func secureDialContext(blockedCIDRs []*net.IPNet) func(ctx context.Context, network, addr string) (net.Conn, error) {
	base := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		// Literal IP: validate and dial directly.
		if ip := net.ParseIP(host); ip != nil {
			for _, cidr := range blockedCIDRs {
				if cidr.Contains(ip) {
					return nil, fmt.Errorf("connection to %s blocked: IP %s falls in blocked range %s", addr, ip, cidr)
				}
			}
			return base.DialContext(ctx, network, addr)
		}
		// Hostname: resolve, validate ALL IPs, then dial the first one directly
		// to prevent DNS-rebinding. Validating all IPs (not just the one we dial)
		// ensures a hostname is fully blocked if any of its resolved addresses
		// falls in a blocked CIDR range.
		ips, err := net.DefaultResolver.LookupHost(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve %s: %w", host, err)
		}
		// First pass: reject if ANY resolved IP is in a blocked range.
		for _, ipStr := range ips {
			ip := net.ParseIP(ipStr)
			if ip == nil {
				continue
			}
			for _, cidr := range blockedCIDRs {
				if cidr.Contains(ip) {
					return nil, fmt.Errorf("connection to %s blocked: resolved IP %s falls in blocked range %s", addr, ip, cidr)
				}
			}
		}
		// Second pass: dial the first parseable address.
		// Connect directly to the validated IP. Go's http.Transport derives
		// the TLS ServerName from the original request URL's hostname rather
		// than from the address given to DialContext, so TLS SNI and
		// certificate validation remain correct when dialling by IP.
		for _, ipStr := range ips {
			if net.ParseIP(ipStr) == nil {
				continue
			}
			return base.DialContext(ctx, network, net.JoinHostPort(ipStr, port))
		}
		return nil, fmt.Errorf("no usable addresses resolved for %s", host)
	}
}

// DefaultBlockedCIDRs is the default set of CIDR ranges blocked to prevent SSRF attacks.
// It covers loopback, link-local (cloud metadata), RFC-1918 private, and shared address space.
var DefaultBlockedCIDRs = []string{
	"127.0.0.0/8",    // loopback
	"::1/128",        // IPv6 loopback
	"169.254.0.0/16", // link-local — covers AWS (169.254.169.254), GCP, Azure, DO, Alibaba metadata IPs
	"fe80::/10",      // IPv6 link-local
	"10.0.0.0/8",     // RFC-1918 private
	"172.16.0.0/12",  // RFC-1918 private
	"192.168.0.0/16", // RFC-1918 private
	"fc00::/7",       // IPv6 unique local address (ULA)
	"100.64.0.0/10",  // shared address space (RFC 6598, used by some cloud NAT/VPCs)
}

// DefaultBlockedHosts is the default set of hostnames blocked to prevent SSRF attacks.
// These are cloud provider metadata endpoints whose IPs may not always fall in DefaultBlockedCIDRs.
var DefaultBlockedHosts = []string{
	"metadata.google.internal", // GCP metadata server
	"metadata.internal",        // Oracle Cloud metadata server
}

// httpDoer is the internal interface for making HTTP requests.
type httpDoer interface {
	Do(*http.Request) (*http.Response, error)
}

type contextImpl struct {
	client             httpDoer
	blockedCIDRs       []*net.IPNet
	blockedHosts       map[string]struct{}
	allowedURLPrefixes []*url.URL
}

// NewHTTP creates a ContextInterface with no URL restrictions. Intended for testing and internal use.
// For production admission controllers use NewHTTPWithDefaultBlocklist or NewHTTPWithBlocklist.
func NewHTTP() ContextInterface {
	return &contextImpl{client: http.DefaultClient}
}

// NewHTTPWithDefaultBlocklist creates a ContextInterface with the default SSRF blocklist applied.
// It panics if the default blocklist contains an invalid entry, which indicates a programming error.
func NewHTTPWithDefaultBlocklist() ContextInterface {
	ctx, err := NewHTTPWithBlocklist(append(DefaultBlockedCIDRs, DefaultBlockedHosts...), nil)
	if err != nil {
		panic(fmt.Sprintf("kyverno.http: default blocklist is invalid: %v", err))
	}
	return ctx
}

// NewHTTPWithBlocklist creates a ContextInterface with configurable URL validation.
//
// blocklist entries may be:
//   - CIDR ranges (e.g. "10.0.0.0/8"): the resolved IP of any requested host is checked against these.
//   - Hostnames (e.g. "metadata.google.internal"): matched against the exact request hostname.
//
// allowlist entries are URL prefixes (scheme + host, optionally + path prefix).
// When the allowlist is non-empty, a request URL must match at least one entry — scheme and host
// must be identical and the request path must start with the entry's path. The blocklist is
// still enforced on top of the allowlist for defence in depth.
func NewHTTPWithBlocklist(blocklist, allowlist []string) (ContextInterface, error) {
	var blockedCIDRs []*net.IPNet
	blockedHosts := make(map[string]struct{})
	for _, entry := range blocklist {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			_, ipNet, err := net.ParseCIDR(entry)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %q in blocklist: %w", entry, err)
			}
			blockedCIDRs = append(blockedCIDRs, ipNet)
		} else {
			blockedHosts[normalizeHost(entry)] = struct{}{}
		}
	}

	var allowedURLPrefixes []*url.URL
	for _, entry := range allowlist {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		u, err := url.Parse(entry)
		if err != nil {
			return nil, fmt.Errorf("invalid allowlist URL %q: %w", entry, err)
		}
		if u.Scheme == "" || u.Host == "" {
			return nil, fmt.Errorf("allowlist entry %q must include scheme and host (e.g. https://api.example.com)", entry)
		}
		allowedURLPrefixes = append(allowedURLPrefixes, u)
	}

	// When blocked CIDRs are configured, install secureDialContext in the
	// client's transport regardless of whether a custom client was supplied.
	// This closes the DNS-rebinding window for both default and caller-supplied
	// clients by enforcing CIDR checks at connection time.
	var client httpDoer
	if len(blockedCIDRs) > 0 {
		client = wrapClientWithSecureDial(blockedCIDRs)
	} else {
		client = http.DefaultClient
	}

	return &contextImpl{
		client:             client,
		blockedCIDRs:       blockedCIDRs,
		blockedHosts:       blockedHosts,
		allowedURLPrefixes: allowedURLPrefixes,
	}, nil
}

// wrapClientWithSecureDial builds an *http.Client cloned from http.DefaultTransport
// with secureDialContext installed, so CIDR validation is enforced at connection
// time and DNS-rebinding is prevented.
func wrapClientWithSecureDial(blockedCIDRs []*net.IPNet) *http.Client {
	baseTransport, ok := http.DefaultTransport.(*http.Transport)
	if !ok || baseTransport == nil {
		baseTransport = &http.Transport{}
	}
	t := baseTransport.Clone()
	t.DialContext = secureDialContext(blockedCIDRs)
	return &http.Client{Transport: t}
}

// validateURL enforces allowlist and hostname-blocklist rules before a request is
// sent. CIDR blocking is fully delegated to secureDialContext at connection time,
// so no pre-flight DNS resolution is needed here.
func (r *contextImpl) validateURL(rawURL string) error {
	if len(r.blockedHosts) == 0 && len(r.allowedURLPrefixes) == 0 {
		return nil
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	host := u.Hostname()
	// Allowlist check: if configured, the URL must match at least one entry.
	if len(r.allowedURLPrefixes) > 0 && !r.matchesAllowlist(u) {
		return fmt.Errorf("URL %q is not permitted: no matching allowlist entry", rawURL)
	}
	// Hostname blocklist check. Normalize to handle case differences and
	// trailing dots (e.g. "METADATA.GOOGLE.INTERNAL" and "metadata.google.internal."
	// both match "metadata.google.internal").
	if _, blocked := r.blockedHosts[normalizeHost(host)]; blocked {
		return fmt.Errorf("URL %q is blocked: hostname %q is on the blocklist", rawURL, host)
	}
	return nil
}

func (r *contextImpl) matchesAllowlist(reqURL *url.URL) bool {
	reqHost := normalizeHost(reqURL.Hostname())
	reqPort := effectivePort(reqURL)
	for _, entry := range r.allowedURLPrefixes {
		if reqURL.Scheme != entry.Scheme {
			continue
		}
		// Compare canonicalized hostnames (case-insensitive, no trailing dot)
		// and effective ports (defaulting from scheme when omitted), so that
		// e.g. https://api.example.com matches https://api.example.com:443.
		if normalizeHost(entry.Hostname()) != reqHost || effectivePort(entry) != reqPort {
			continue
		}
		entryPath := entry.Path
		if entryPath == "" || entryPath == "/" {
			return true
		}
		// Require either an exact path match, or a prefix match that aligns with
		// a path-segment boundary. This avoids matching "/v10/..." when the
		// allowlist entry is "/v1".
		if reqURL.Path == entryPath {
			return true
		}
		if strings.HasPrefix(reqURL.Path, entryPath) {
			// If the allowlist path ends with "/", treat it as a directory prefix.
			if entryPath[len(entryPath)-1] == '/' {
				return true
			}
			// Otherwise, require the next character after the prefix to be "/".
			if len(reqURL.Path) > len(entryPath) && reqURL.Path[len(entryPath)] == '/' {
				return true
			}
		}
	}
	return false
}

func (r *contextImpl) Get(url string, headers map[string]string) (any, error) {
	if err := r.validateURL(url); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(context.TODO(), "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	for h, v := range headers {
		req.Header.Add(h, v)
	}
	return r.executeRequest(req)
}

func (r *contextImpl) Post(url string, data any, headers map[string]string) (any, error) {
	if err := r.validateURL(url); err != nil {
		return nil, err
	}
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
	return r.executeRequest(req)
}

func (r *contextImpl) Put(url string, data any, headers map[string]string) (any, error) {
	if err := r.validateURL(url); err != nil {
		return nil, err
	}
	body, err := buildRequestData(data)
	if err != nil {
		return nil, fmt.Errorf("failed to encode request data: %w", err)
	}
	req, err := http.NewRequestWithContext(context.TODO(), "PUT", url, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	for h, v := range headers {
		req.Header.Add(h, v)
	}
	return r.executeRequest(req)
}

func (r *contextImpl) executeRequest(req *http.Request) (any, error) {
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var body any
	if resp.Body != nil {
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			body = nil
		}
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
	baseTransport, ok := http.DefaultTransport.(*http.Transport)
	if !ok || baseTransport == nil {
		baseTransport = &http.Transport{}
	}
	transport := baseTransport.Clone()
	if transport.TLSClientConfig != nil {
		transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	} else {
		transport.TLSClientConfig = &tls.Config{}
	}
	transport.TLSClientConfig.RootCAs = caCertPool
	if transport.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		transport.TLSClientConfig.MinVersion = tls.VersionTLS12
	}
	if len(r.blockedCIDRs) > 0 {
		transport.DialContext = secureDialContext(r.blockedCIDRs)
	}
	return &contextImpl{
		client:             &http.Client{Transport: transport},
		blockedCIDRs:       r.blockedCIDRs,
		blockedHosts:       r.blockedHosts,
		allowedURLPrefixes: r.allowedURLPrefixes,
	}, nil
}

func buildRequestData(data any) (io.Reader, error) {
	buffer := new(bytes.Buffer)
	if err := json.NewEncoder(buffer).Encode(data); err != nil {
		return nil, fmt.Errorf("failed to encode HTTP POST data %v: %w", data, err)
	}
	return buffer, nil
}
