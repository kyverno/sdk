package imagedataloader

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type azureRoundTripper func(*http.Request) (*http.Response, error)

func (f azureRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func azureManagedIdentity(t *testing.T, handler http.HandlerFunc) *atomic.Int32 {
	t.Helper()
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		assert.Equal(t, "test-identity-header", r.Header.Get("X-IDENTITY-HEADER"))
		if handler != nil {
			handler(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "managed-identity-access-token",
			"expires_on":   strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10),
			"resource":     r.URL.Query().Get("resource"),
			"token_type":   "Bearer",
		})
	}))
	t.Cleanup(server.Close)
	t.Setenv("AZURE_TOKEN_CREDENTIALS", "ManagedIdentityCredential")
	t.Setenv("IDENTITY_ENDPOINT", server.URL)
	t.Setenv("IDENTITY_HEADER", "test-identity-header")
	t.Setenv("IDENTITY_SERVER_THUMBPRINT", "")
	t.Setenv("AZURE_CLIENT_ID", t.Name())
	return &calls
}

func azureRefreshToken(t *testing.T, label ...string) string {
	t.Helper()
	claims, err := json.Marshal(map[string]any{"exp": time.Now().Add(time.Hour).Unix(), "label": label})
	require.NoError(t, err)
	return base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`)) + "." +
		base64.RawURLEncoding.EncodeToString(claims) + ".signature"
}

func azureExchangeResponse(t *testing.T, req *http.Request, token string) *http.Response {
	t.Helper()
	assert.Equal(t, http.MethodPost, req.Method)
	assert.Equal(t, "/oauth2/exchange", req.URL.Path)
	require.NoError(t, req.ParseForm())
	assert.Equal(t, "managed-identity-access-token", req.Form.Get("access_token"))
	assert.Equal(t, "access_token", req.Form.Get("grant_type"))
	assert.Equal(t, req.URL.Hostname(), req.Form.Get("service"))
	body, err := json.Marshal(map[string]string{"refresh_token": token})
	require.NoError(t, err)
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}},
		Body: io.NopCloser(strings.NewReader(string(body))), Request: req}
}

func azureContext() context.Context {
	return policy.WithRetryOptions(context.Background(), policy.RetryOptions{MaxRetries: -1})
}

func TestAzureRegistryHTTPClientAndManagedIdentity(t *testing.T) {
	identityCalls := azureManagedIdentity(t, nil)
	token := azureRefreshToken(t)
	var exchangeCalls atomic.Int32
	type contextKey struct{}
	ctx := context.WithValue(azureContext(), contextKey{}, "caller-context")
	hosts := []string{"registry.azurecr.io", "registry.azurecr.io:443", "registry.azurecr.io:8443", "Registry.AZURECR.IO.:443"}
	for _, host := range hosts {
		t.Run(host, func(t *testing.T) {
			client := &http.Client{Transport: azureRoundTripper(func(req *http.Request) (*http.Response, error) {
				exchangeCalls.Add(1)
				assert.Equal(t, host, req.URL.Host)
				assert.Equal(t, "caller-context", req.Context().Value(contextKey{}))
				return azureExchangeResponse(t, req, token), nil
			})}
			keychain := NewAzureKeychain(WithAzureRegistryHTTPClient(client))
			resource, err := name.NewTag(host + "/repository:latest")
			require.NoError(t, err)
			authenticator, err := authn.Resolve(ctx, keychain, resource)
			require.NoError(t, err)
			cfg, err := authenticator.Authorization()
			require.NoError(t, err)
			assert.Equal(t, "00000000-0000-0000-0000-000000000000", cfg.Username)
			assert.Equal(t, token, cfg.Password)
		})
	}
	assert.Positive(t, identityCalls.Load(), "identity must keep its own transport")
	assert.EqualValues(t, len(hosts), exchangeCalls.Load())
}

func TestAzureRegistryHTTPClientErrorDoesNotFallBack(t *testing.T) {
	azureManagedIdentity(t, nil)
	blocked := errors.New("registry egress denied")
	client := &http.Client{Transport: azureRoundTripper(func(*http.Request) (*http.Response, error) {
		return nil, blocked
	})}
	keychain := authn.NewMultiKeychain(NewAzureKeychain(WithAzureRegistryHTTPClient(client)), AnonymousKeychain)
	resource, err := name.NewTag("registry.azurecr.io/repository:latest")
	require.NoError(t, err)
	authenticator, err := authn.Resolve(azureContext(), keychain, resource)
	require.ErrorIs(t, err, blocked)
	assert.Nil(t, authenticator, "an explicit transport denial must not become anonymous auth")
}

func TestAzureRegistryHTTPClientCancellation(t *testing.T) {
	identityCalls := azureManagedIdentity(t, nil)
	resource, err := name.NewTag("registry.azurecr.io/repository:latest")
	require.NoError(t, err)
	var exchangeCalls atomic.Int32
	client := &http.Client{Transport: azureRoundTripper(func(req *http.Request) (*http.Response, error) {
		exchangeCalls.Add(1)
		<-req.Context().Done()
		return nil, req.Context().Err()
	})}
	keychain := NewAzureKeychain(WithAzureRegistryHTTPClient(client))
	ctx, cancel := context.WithCancel(azureContext())
	cancel()
	_, err = authn.Resolve(ctx, keychain, resource)
	require.ErrorIs(t, err, context.Canceled)
	assert.Zero(t, identityCalls.Load())
	assert.Zero(t, exchangeCalls.Load())

	ctx, cancel = context.WithTimeout(azureContext(), 250*time.Millisecond)
	defer cancel()
	_, err = authn.Resolve(ctx, keychain, resource)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.EqualValues(t, 1, identityCalls.Load())
	assert.EqualValues(t, 1, exchangeCalls.Load())
}

func TestAzureIdentityFailurePreservesAnonymousFallback(t *testing.T) {
	azureManagedIdentity(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":"identity unavailable"}`)
	})
	var exchangeCalls atomic.Int32
	client := &http.Client{Transport: azureRoundTripper(func(*http.Request) (*http.Response, error) {
		exchangeCalls.Add(1)
		return nil, errors.New("unexpected exchange")
	})}
	resource, err := name.NewTag("registry.azurecr.io/repository:latest")
	require.NoError(t, err)
	for _, keychain := range []authn.Keychain{AzureKeychain, NewAzureKeychain(WithAzureRegistryHTTPClient(client))} {
		authenticator, err := authn.Resolve(azureContext(), keychain, resource)
		require.NoError(t, err)
		assert.Equal(t, authn.Anonymous, authenticator)
	}
	assert.Zero(t, exchangeCalls.Load())
}

func TestAzureIdentityCancellationDoesNotFallBack(t *testing.T) {
	azureManagedIdentity(t, func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
	resource, err := name.NewTag("registry.azurecr.io/repository:latest")
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(azureContext(), 100*time.Millisecond)
	defer cancel()
	authenticator, err := authn.Resolve(ctx, AzureKeychain, resource)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Nil(t, authenticator)
}

func TestAzureProviderOptionsKeepInstancesSeparate(t *testing.T) {
	azureManagedIdentity(t, nil)
	resource, err := name.NewTag("registry.azurecr.io/repository:latest")
	require.NoError(t, err)
	type resolvedCase struct {
		token    string
		keychain authn.Keychain
	}
	var cases []resolvedCase
	for _, label := range []string{"first", "second"} {
		token := azureRefreshToken(t, label)
		client := &http.Client{Transport: azureRoundTripper(func(req *http.Request) (*http.Response, error) {
			return azureExchangeResponse(t, req, token), nil
		})}
		keychains := KeychainsForProvidersWithOptions([]string{"azure"}, WithAzureRegistryHTTPClient(client))
		require.Len(t, keychains, 1)
		cases = append(cases, resolvedCase{token: token, keychain: keychains[0]})
	}
	for _, tc := range cases {
		authenticator, err := authn.Resolve(azureContext(), tc.keychain, resource)
		require.NoError(t, err)
		cfg, err := authenticator.Authorization()
		require.NoError(t, err)
		assert.Equal(t, tc.token, cfg.Password)
	}
	defaults := KeychainsForProviders("azure")
	require.Len(t, defaults, 1)
	assert.Equal(t, AzureKeychain, defaults[0])
	nilOptions := KeychainsForProvidersWithOptions([]string{"azure"}, WithAzureRegistryHTTPClient(nil))
	require.Len(t, nilOptions, 1)
	assert.Equal(t, AzureKeychain, nilOptions[0])
}

func TestAzureResourceManagerScopeCompatibility(t *testing.T) {
	for host, expected := range map[string]string{
		"registry.azurecr.io":     "https://management.azure.com/.default",
		"registry.azurecr.cn":     "https://management.chinacloudapi.cn/.default",
		"registry.azurecr.us":     "https://management.usgovcloudapi.net/.default",
		"registry.azurecr.de":     "https://management.azure.com/.default",
		"registry.azurecr.cn:443": "https://management.azure.com/.default",
		"REGISTRY.AZURECR.US.":    "https://management.azure.com/.default",
	} {
		t.Run(host, func(t *testing.T) { assert.Equal(t, expected, azureResourceManagerScope(host)) })
	}
}

func TestImageDataLoaderAzureRegistryHTTPClient(t *testing.T) {
	azureManagedIdentity(t, nil)
	server := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	t.Cleanup(server.Close)
	endpoint, err := url.Parse(server.URL)
	require.NoError(t, err)
	localRef, err := name.NewTag(endpoint.Host+"/repository:latest", name.Insecure)
	require.NoError(t, err)
	img, err := random.Image(32, 1)
	require.NoError(t, err)
	require.NoError(t, remote.Write(localRef, img))
	token := azureRefreshToken(t)
	var defaultCalls, overrideCalls atomic.Int32
	client := &http.Client{Transport: azureRoundTripper(func(req *http.Request) (*http.Response, error) {
		defaultCalls.Add(1)
		return azureExchangeResponse(t, req, token), nil
	})}
	override := &http.Client{Transport: azureRoundTripper(func(req *http.Request) (*http.Response, error) {
		overrideCalls.Add(1)
		return azureExchangeResponse(t, req, token), nil
	})}
	fetcher, err := New(nil, WithAzureRegistryHTTPClient(client), WithTransport(func(http.RoundTripper) http.RoundTripper {
		return azureRoundTripper(func(req *http.Request) (*http.Response, error) {
			if req.URL.Host != "registry.azurecr.io" {
				return nil, fmt.Errorf("unexpected registry host %s", req.URL.Host)
			}
			clone := req.Clone(req.Context())
			clone.URL.Scheme = endpoint.Scheme
			clone.URL.Host = endpoint.Host
			return server.Client().Transport.RoundTrip(clone)
		})
	}))
	require.NoError(t, err)
	_, err = fetcher.FetchImageData(azureContext(), "registry.azurecr.io/repository:latest", WithCredentialProviders("azure"))
	require.NoError(t, err)
	require.Positive(t, defaultCalls.Load(), "constructor exchange client must reach per-fetch providers")
	before := defaultCalls.Load()
	_, err = fetcher.FetchImageData(azureContext(), "registry.azurecr.io/repository:latest", WithCredentialProviders("azure"), WithAzureRegistryHTTPClient(override))
	require.NoError(t, err)
	assert.Equal(t, before, defaultCalls.Load())
	assert.Positive(t, overrideCalls.Load(), "per-fetch exchange client must override the constructor client")
}

func TestAzureDefaultExchangeFailurePreservesAnonymousFallback(t *testing.T) {
	identityCalls := azureManagedIdentity(t, nil)
	var exchangeCalls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		exchangeCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":{"code":"UNAUTHORIZED","message":"denied"}}`)
	}))
	t.Cleanup(server.Close)
	endpoint, err := url.Parse(server.URL)
	require.NoError(t, err)
	transport := server.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig.ServerName = endpoint.Hostname()
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address == "registry.azurecr.io:443" {
			address = endpoint.Host
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	previous := http.DefaultTransport
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = previous; transport.CloseIdleConnections() })
	resource, err := name.NewTag("registry.azurecr.io/repository:latest")
	require.NoError(t, err)
	for _, keychain := range []authn.Keychain{AzureKeychain, NewAzureKeychain(WithAzureRegistryHTTPClient(nil))} {
		authenticator, err := authn.Resolve(azureContext(), keychain, resource)
		require.NoError(t, err)
		assert.Equal(t, authn.Anonymous, authenticator)
	}
	assert.Positive(t, identityCalls.Load())
	assert.EqualValues(t, 2, exchangeCalls.Load())
}

func TestAzureRegistryHTTPClientRejectsRedirect(t *testing.T) {
	azureManagedIdentity(t, nil)
	var targetCalls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { targetCalls.Add(1) }))
	t.Cleanup(target.Close)
	blocked := errors.New("redirect denied")
	client := &http.Client{
		Transport: azureRoundTripper(func(req *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusTemporaryRedirect,
				Header: http.Header{"Location": []string{target.URL}}, Body: http.NoBody, Request: req}, nil
		}),
		CheckRedirect: func(*http.Request, []*http.Request) error { return blocked },
	}
	resource, err := name.NewTag("registry.azurecr.io/repository:latest")
	require.NoError(t, err)
	authenticator, err := authn.Resolve(azureContext(), NewAzureKeychain(WithAzureRegistryHTTPClient(client)), resource)
	require.ErrorIs(t, err, blocked)
	assert.Nil(t, authenticator)
	assert.Zero(t, targetCalls.Load())
}

func TestAzureConfiguredClientRejectsNonACRBeforeIdentity(t *testing.T) {
	identityCalls := azureManagedIdentity(t, nil)
	var exchangeCalls atomic.Int32
	client := &http.Client{Transport: azureRoundTripper(func(*http.Request) (*http.Response, error) {
		exchangeCalls.Add(1)
		return nil, errors.New("unexpected exchange")
	})}
	resource := &acrGuardResource{host: "registry.azurecr.io.attacker.example"}
	authenticator, err := authn.Resolve(azureContext(), NewAzureKeychain(WithAzureRegistryHTTPClient(client)), resource)
	require.NoError(t, err)
	assert.Equal(t, authn.Anonymous, authenticator)
	assert.Zero(t, resource.stringCalls)
	assert.Zero(t, identityCalls.Load())
	assert.Zero(t, exchangeCalls.Load())
}
