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
	"path"
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

// lookupHost resolves a hostname. It is a variable so that tests can force a specific
// answer, since resolution of any real name is neither offline-safe nor deterministic.
var lookupHost = net.DefaultResolver.LookupHost

// blockedCIDR returns the blocked range containing ip, or nil if there is none.
//
// net.IPNet.Contains normalizes IPv4-mapped IPv6 addresses itself, so an IPv4 range such
// as 169.254.0.0/16 already contains ::ffff:169.254.169.254. Other IPv6 encodings embed
// an IPv4 address in a form Contains does not recognise, so the embedded address is
// checked as well.
func blockedCIDR(blockedCIDRs []*net.IPNet, ip net.IP) *net.IPNet {
	for _, candidate := range [2]net.IP{ip, embeddedIPv4(ip)} {
		if candidate == nil {
			continue
		}
		for _, cidr := range blockedCIDRs {
			if cidr.Contains(candidate) {
				return cidr
			}
		}
	}
	return nil
}

// embeddedIPv4 extracts the IPv4 address carried by an IPv6 address in a form that
// net.IP.To4 does not recognise. Each is a different spelling of an address that an IPv4
// CIDR in the blocklist is meant to cover: without this, [2002:a9fe:a9fe::] reaches the
// cloud metadata service even though 169.254.0.0/16 is blocked. Returns nil when there is
// no embedded address, or when To4 already handles it.
func embeddedIPv4(ip net.IP) net.IP {
	if ip.To4() != nil || len(ip.To16()) != net.IPv6len {
		return nil
	}
	ip = ip.To16()
	isZero := func(b []byte) bool {
		for _, c := range b {
			if c != 0 {
				return false
			}
		}
		return true
	}
	switch {
	// ::a.b.c.d — IPv4-compatible IPv6.
	case isZero(ip[:12]):
		return net.IPv4(ip[12], ip[13], ip[14], ip[15])
	// 64:ff9b::a.b.c.d — the NAT64 well-known prefix, standard in IPv6-only clusters.
	case ip[0] == 0x00 && ip[1] == 0x64 && ip[2] == 0xff && ip[3] == 0x9b && isZero(ip[4:12]):
		return net.IPv4(ip[12], ip[13], ip[14], ip[15])
	// 2002:aabb:ccdd::/48 — 6to4, which carries the IPv4 address in bytes 2-5.
	case ip[0] == 0x20 && ip[1] == 0x02:
		return net.IPv4(ip[2], ip[3], ip[4], ip[5])
	}
	return nil
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
			if cidr := blockedCIDR(blockedCIDRs, ip); cidr != nil {
				return nil, fmt.Errorf("connection to %s blocked: IP %s falls in blocked range %s", addr, ip, cidr)
			}
			return base.DialContext(ctx, network, addr)
		}
		// Hostname: resolve, validate ALL IPs, then dial the first one directly
		// to prevent DNS-rebinding. Validating all IPs (not just the one we dial)
		// ensures a hostname is fully blocked if any of its resolved addresses
		// falls in a blocked CIDR range.
		ips, err := lookupHost(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve %s: %w", host, err)
		}
		// First pass: reject if ANY resolved IP is in a blocked range.
		for _, ipStr := range ips {
			ip := net.ParseIP(ipStr)
			if ip == nil {
				continue
			}
			if cidr := blockedCIDR(blockedCIDRs, ip); cidr != nil {
				return nil, fmt.Errorf("connection to %s blocked: resolved IP %s falls in blocked range %s", addr, ip, cidr)
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

	r := &contextImpl{
		client:             http.DefaultClient,
		blockedCIDRs:       blockedCIDRs,
		blockedHosts:       blockedHosts,
		allowedURLPrefixes: allowedURLPrefixes,
	}
	// Build a guarded client whenever any rule is configured. A CIDR-only test would
	// miss the allowlist and hostname rules, which are enforced on the client rather
	// than on the transport.
	if r.filtered() {
		r.client = r.newClient(cloneDefaultTransport())
	}
	return r, nil
}

// filtered reports whether any rule is configured. With none, the context imposes no
// restrictions at all, which is what NewHTTP documents.
func (r *contextImpl) filtered() bool {
	return len(r.blockedCIDRs) > 0 || len(r.blockedHosts) > 0 || len(r.allowedURLPrefixes) > 0
}

// cloneDefaultTransport returns a private copy of http.DefaultTransport, safe to mutate.
func cloneDefaultTransport() *http.Transport {
	baseTransport, ok := http.DefaultTransport.(*http.Transport)
	if !ok || baseTransport == nil {
		baseTransport = &http.Transport{}
	}
	return baseTransport.Clone()
}

// newClient installs the SSRF guard on transport and returns a client using it. The
// transport must not be shared: both of its hooks are replaced.
func (r *contextImpl) newClient(transport *http.Transport) *http.Client {
	if len(r.blockedCIDRs) > 0 {
		transport.DialContext = secureDialContext(r.blockedCIDRs)
		transport.Proxy = r.guardedProxy(transport.Proxy)
	}
	return &http.Client{Transport: transport, CheckRedirect: r.checkRedirect}
}

// maxRedirects mirrors the limit net/http applies when CheckRedirect is nil. Setting
// CheckRedirect replaces that default wholesale, so the limit has to be restated or a
// redirect loop would be followed forever.
const maxRedirects = 10

// checkRedirect re-applies validateURL to every redirect hop.
//
// Redirects are still followed. Refusing them outright would close the same gap but would
// break policies that work today: an endpoint that legitimately redirects — http to https,
// a bare path to a versioned one, anything behind an ingress that normalizes URLs — would
// start failing on upgrade.
//
// Following them is safe because secureDialContext sits in the transport and so already
// re-checks the address of every hop. The checks it cannot make are the ones that need the
// URL rather than the address — the allowlist and the hostname blocklist — which were
// otherwise applied only to the URL the caller passed. Without this, a redirect returned
// the body of an off-allowlist host to the caller.
func (r *contextImpl) checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return fmt.Errorf("stopped after %d redirects", maxRedirects)
	}
	return r.validateURL(req.URL.String())
}

// guardedProxy wraps a transport's proxy resolver so that the CIDR blocklist is applied
// to the request target.
//
// When a proxy is in use Go dials the PROXY, so secureDialContext is handed the proxy's
// address and never sees the real target — a cloned http.DefaultTransport keeps
// ProxyFromEnvironment, so merely setting HTTP_PROXY disabled the CIDR check entirely.
// Checking here, at the point where we learn a proxy will be used, restores it.
//
// This leaves a rebinding window the direct path does not have, since the proxy resolves
// the target itself. That is inherent to proxying and cannot be closed from this side.
func (r *contextImpl) guardedProxy(base func(*http.Request) (*url.URL, error)) func(*http.Request) (*url.URL, error) {
	if base == nil {
		return nil
	}
	return func(req *http.Request) (*url.URL, error) {
		proxyURL, err := base(req)
		if err != nil || proxyURL == nil {
			return proxyURL, err
		}
		if err := r.validateProxiedHost(req.Context(), req.URL.Hostname()); err != nil {
			return nil, fmt.Errorf("request to %q is blocked: %w", req.URL.Redacted(), err)
		}
		return proxyURL, nil
	}
}

// validateProxiedHost applies the CIDR blocklist to a host that will be reached through a
// proxy, resolving it when it is not already a literal address. The hostname blocklist and
// the allowlist are not repeated here: validateURL has already applied both.
func (r *contextImpl) validateProxiedHost(ctx context.Context, host string) error {
	if ip := net.ParseIP(host); ip != nil {
		if cidr := blockedCIDR(r.blockedCIDRs, ip); cidr != nil {
			return fmt.Errorf("IP %s falls in blocked range %s", ip, cidr)
		}
		return nil
	}
	ips, err := lookupHost(ctx, host)
	if err != nil {
		// A cluster that egresses through a proxy commonly cannot resolve external names
		// itself — the proxy does that — so refusing every unresolvable name would break
		// calls that work today. But permitting them unconditionally leaves the CIDR
		// blocklist unenforced for exactly the hosts we cannot see.
		//
		// The allowlist settles it. When one is configured, validateURL has already
		// required this URL to match an entry an operator wrote by hand, so the target is
		// explicitly sanctioned and an in-pod resolution failure says nothing about it.
		// With no allowlist, nothing else has vetted the host, so refuse.
		if len(r.allowedURLPrefixes) > 0 {
			return nil
		}
		return fmt.Errorf("%q cannot be resolved to verify it is not in a blocked range; add it to the allowlist to permit it", host)
	}
	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		if cidr := blockedCIDR(r.blockedCIDRs, ip); cidr != nil {
			return fmt.Errorf("%s resolves into blocked range %s", host, cidr)
		}
	}
	return nil
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

// cleanPath canonicalizes a URL path for comparison: rooted, with "." and ".."
// segments and duplicate slashes resolved, and any trailing slash removed.
func cleanPath(p string) string {
	return path.Clean("/" + strings.TrimPrefix(p, "/"))
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
		// Compare canonical paths. url.Parse leaves "/v1/../admin" — and the
		// percent-encoded "/v1/%2e%2e/admin", which it decodes to the same thing —
		// intact in Path, so a raw prefix test admits either for an entry of "/v1"
		// while the server resolves both to "/admin". path.Clean collapses the
		// traversal before the comparison.
		reqPath := cleanPath(reqURL.Path)
		cleanEntry := cleanPath(entryPath)
		if reqPath == cleanEntry {
			return true
		}
		// Require the prefix to align with a path-segment boundary, so an entry of
		// "/v1" does not admit "/v10". Clean has already stripped any trailing slash
		// from cleanEntry, so this one rule covers both the "/v1" and "/v1/" forms.
		if strings.HasPrefix(reqPath, cleanEntry) && len(reqPath) > len(cleanEntry) && reqPath[len(cleanEntry)] == '/' {
			return true
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
	transport := cloneDefaultTransport()
	if transport.TLSClientConfig != nil {
		transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	} else {
		transport.TLSClientConfig = &tls.Config{}
	}
	transport.TLSClientConfig.RootCAs = caCertPool
	if transport.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		transport.TLSClientConfig.MinVersion = tls.VersionTLS12
	}
	derived := &contextImpl{
		blockedCIDRs:       r.blockedCIDRs,
		blockedHosts:       r.blockedHosts,
		allowedURLPrefixes: r.allowedURLPrefixes,
	}
	derived.client = derived.newClient(transport)
	return derived, nil
}

func buildRequestData(data any) (io.Reader, error) {
	buffer := new(bytes.Buffer)
	if err := json.NewEncoder(buffer).Encode(data); err != nil {
		return nil, fmt.Errorf("failed to encode HTTP POST data %v: %w", data, err)
	}
	return buffer, nil
}
