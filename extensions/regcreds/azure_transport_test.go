package regcreds

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/go-logr/logr"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/kyverno/api/api/policies.kyverno.io/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type azureRoundTripper func(*http.Request) (*http.Response, error)

func (f azureRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// Exercise the real default Azure credential chain through its App Service
// managed identity protocol. Every identity request stays on this local server.
func managedIdentityServer(t *testing.T, handler http.HandlerFunc) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != server.Listener.Addr().String() {
			return nil, fmt.Errorf("unexpected default transport connection to %s", address)
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	old := http.DefaultTransport
	http.DefaultTransport = transport
	t.Cleanup(func() {
		http.DefaultTransport = old
		transport.CloseIdleConnections()
	})
	t.Setenv("AZURE_TOKEN_CREDENTIALS", "ManagedIdentityCredential")
	t.Setenv("AZURE_CLIENT_ID", t.Name())
	t.Setenv("IDENTITY_ENDPOINT", server.URL)
	t.Setenv("IDENTITY_HEADER", "test-identity-header")
	t.Setenv("IDENTITY_SERVER_THUMBPRINT", "")
	t.Setenv("IMDS_ENDPOINT", "")
	t.Setenv("MSI_ENDPOINT", "")
	t.Setenv("MSI_SECRET", "")
}

func writeIdentityToken(t *testing.T, w http.ResponseWriter, r *http.Request) {
	t.Helper()
	assert.Equal(t, "test-identity-header", r.Header.Get("X-IDENTITY-HEADER"))
	w.Header().Set("Content-Type", "application/json")
	assert.NoError(t, json.NewEncoder(w).Encode(map[string]any{
		"access_token": "identity-access-token",
		"expires_on":   time.Now().Add(time.Hour).Unix(),
		"resource":     r.URL.Query().Get("resource"),
		"token_type":   "Bearer",
	}))
}

func acrRefreshToken() string {
	claims := fmt.Sprintf(`{"exp":%d}`, time.Now().Add(time.Hour).Unix())
	return "eyJhbGciOiJub25lIn0." + base64.RawURLEncoding.EncodeToString([]byte(claims)) + "."
}

func exchangeResponse(r *http.Request, token string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(fmt.Sprintf(`{"refresh_token":%q}`, token))),
		Request:    r,
	}
}

func TestAzureRegistryClientUsesCallerTransportAndContext(t *testing.T) {
	var identityCalls atomic.Int32
	managedIdentityServer(t, func(w http.ResponseWriter, r *http.Request) {
		identityCalls.Add(1)
		assert.Equal(t, "https://management.azure.com", r.URL.Query().Get("resource"))
		writeIdentityToken(t, w, r)
	})

	type contextKey struct{}
	ctx := context.WithValue(context.Background(), contextKey{}, "request-marker")
	token := acrRefreshToken()
	var exchangeCalls atomic.Int32
	client := &http.Client{Transport: azureRoundTripper(func(r *http.Request) (*http.Response, error) {
		exchangeCalls.Add(1)
		require.Equal(t, "request-marker", r.Context().Value(contextKey{}))
		require.Equal(t, "registry.azurecr.io", r.URL.Host)
		require.Equal(t, "/oauth2/exchange", r.URL.Path)
		require.Equal(t, http.MethodPost, r.Method)
		require.NoError(t, r.ParseForm())
		require.Equal(t, "identity-access-token", r.Form.Get("access_token"))
		require.Equal(t, "registry.azurecr.io", r.Form.Get("service"))
		require.Equal(t, "access_token", r.Form.Get("grant_type"))
		return exchangeResponse(r, token), nil
	})}

	for _, keychain := range []authn.Keychain{
		NewAzureKeychain(WithAzureRegistryHTTPClient(client)),
		KeychainsForProvidersWithOptions([]string{"azure"}, WithAzureRegistryHTTPClient(client))[0],
	} {
		ref := name.MustParseReference("registry.azurecr.io/image:latest")
		resolved, err := authn.Resolve(ctx, keychain, ref.Context())
		require.NoError(t, err)
		config, err := resolved.Authorization()
		require.NoError(t, err)
		require.Equal(t, "00000000-0000-0000-0000-000000000000", config.Username)
		require.Equal(t, token, config.Password)
	}
	require.Positive(t, identityCalls.Load(), "registry client must not intercept identity requests")
	require.EqualValues(t, 2, exchangeCalls.Load())
}

func TestAzureRegistryClientsAreIsolated(t *testing.T) {
	managedIdentityServer(t, func(w http.ResponseWriter, r *http.Request) { writeIdentityToken(t, w, r) })
	ref := name.MustParseReference("registry.azurecr.io/image:latest")
	firstToken, secondToken := acrRefreshToken(), acrRefreshToken()+"second"
	// Signature contents do not affect Flux's extraction of the expiry claim.
	first := NewAzureKeychain(WithAzureRegistryHTTPClient(&http.Client{Transport: azureRoundTripper(func(r *http.Request) (*http.Response, error) {
		return exchangeResponse(r, firstToken), nil
	})}))
	second := NewAzureKeychain(WithAzureRegistryHTTPClient(&http.Client{Transport: azureRoundTripper(func(r *http.Request) (*http.Response, error) {
		return exchangeResponse(r, secondToken), nil
	})}))
	for _, test := range []struct {
		keychain authn.Keychain
		token    string
	}{{first, firstToken}, {second, secondToken}, {first, firstToken}} {
		resolved, err := test.keychain.Resolve(ref.Context())
		require.NoError(t, err)
		config, err := resolved.Authorization()
		require.NoError(t, err)
		require.Equal(t, test.token, config.Password)
	}
}

func TestAzureRegistryClientCancellation(t *testing.T) {
	managedIdentityServer(t, func(w http.ResponseWriter, r *http.Request) { writeIdentityToken(t, w, r) })
	started := make(chan struct{})
	client := &http.Client{Transport: azureRoundTripper(func(r *http.Request) (*http.Response, error) {
		close(started)
		<-r.Context().Done()
		return nil, r.Context().Err()
	})}
	keychain := NewAzureKeychain(WithAzureRegistryHTTPClient(client))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resolved := make(chan error, 1)
	go func() {
		_, err := authn.Resolve(ctx, keychain, name.MustParseReference("registry.azurecr.io/image:latest").Context())
		resolved <- err
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("registry exchange did not start")
	}
	cancel()
	select {
	case err := <-resolved:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(5 * time.Second):
		t.Fatal("registry exchange ignored cancellation")
	}
}

func TestAzureIdentityCancellation(t *testing.T) {
	started := make(chan struct{})
	managedIdentityServer(t, func(_ http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
	})
	var exchangeCalls atomic.Int32
	client := &http.Client{Transport: azureRoundTripper(func(*http.Request) (*http.Response, error) {
		exchangeCalls.Add(1)
		return nil, errors.New("unexpected registry exchange")
	})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resolved := make(chan error, 1)
	go func() {
		_, err := authn.Resolve(ctx, NewAzureKeychain(WithAzureRegistryHTTPClient(client)), name.MustParseReference("registry.azurecr.io/image:latest").Context())
		resolved <- err
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("identity acquisition did not start")
	}
	cancel()
	select {
	case err := <-resolved:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(5 * time.Second):
		t.Fatal("identity acquisition ignored cancellation")
	}
	require.Zero(t, exchangeCalls.Load())
}

func TestAzureRegistryClientPreCanceledAndNonACR(t *testing.T) {
	var identityCalls, exchangeCalls atomic.Int32
	managedIdentityServer(t, func(w http.ResponseWriter, r *http.Request) {
		identityCalls.Add(1)
		writeIdentityToken(t, w, r)
	})
	keychain := NewAzureKeychain(WithAzureRegistryHTTPClient(&http.Client{Transport: azureRoundTripper(func(*http.Request) (*http.Response, error) {
		exchangeCalls.Add(1)
		return nil, errors.New("unexpected registry exchange")
	})}))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := authn.Resolve(ctx, keychain, name.MustParseReference("registry.azurecr.io/image:latest").Context())
	require.ErrorIs(t, err, context.Canceled)
	for _, host := range []string{"ghcr.io", "registry.azurecr.io.attacker.example"} {
		ref, err := name.ParseReference(host + "/image:latest")
		require.NoError(t, err)
		resolved, err := authn.Resolve(ctx, keychain, ref.Context())
		require.NoError(t, err)
		require.Equal(t, authn.Anonymous, resolved)
	}
	require.Zero(t, identityCalls.Load())
	require.Zero(t, exchangeCalls.Load())
}

func TestAzureRegistryClientErrorIsPreserved(t *testing.T) {
	managedIdentityServer(t, func(w http.ResponseWriter, r *http.Request) { writeIdentityToken(t, w, r) })
	denied := errors.New("registry egress denied")
	client := &http.Client{Transport: azureRoundTripper(func(*http.Request) (*http.Response, error) {
		return nil, denied
	})}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ctx = policy.WithRetryOptions(ctx, policy.RetryOptions{MaxRetries: -1})
	_, err := authn.Resolve(ctx, NewAzureKeychain(WithAzureRegistryHTTPClient(client)), name.MustParseReference("registry.azurecr.io/image:latest").Context())
	require.ErrorIs(t, err, denied)
}

func TestAzureRegistryDefaultAndNilClients(t *testing.T) {
	managedIdentityServer(t, func(w http.ResponseWriter, r *http.Request) { writeIdentityToken(t, w, r) })
	token := acrRefreshToken()
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		assert.Equal(t, "registry.azurecr.io", r.Host)
		assert.Equal(t, "/oauth2/exchange", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		assert.NoError(t, json.NewEncoder(w).Encode(map[string]string{"refresh_token": token}))
	}))
	defer server.Close()
	transport := server.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig.ServerName = "example.com"
	identityTransport := http.DefaultTransport
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address == "registry.azurecr.io:443" {
			return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
		}
		return identityTransport.(*http.Transport).DialContext(ctx, network, address)
	}
	old := http.DefaultTransport
	http.DefaultTransport = transport
	t.Cleanup(func() {
		http.DefaultTransport = old
		transport.CloseIdleConnections()
	})
	for _, keychain := range []authn.Keychain{AzureKeychain, NewAzureKeychain(), NewAzureKeychain(WithAzureRegistryHTTPClient(nil))} {
		resolved, err := keychain.Resolve(name.MustParseReference("registry.azurecr.io/image:latest").Context())
		require.NoError(t, err)
		config, err := resolved.Authorization()
		require.NoError(t, err)
		require.Equal(t, token, config.Password)
	}
	require.EqualValues(t, 3, requests.Load())
}

func TestAzureRegistryCloudScopes(t *testing.T) {
	for _, test := range []struct{ host, resource string }{
		{"registry.azurecr.io", "https://management.azure.com"},
		{"registry.azurecr.cn", "https://management.chinacloudapi.cn"},
		{"registry.azurecr.us", "https://management.usgovcloudapi.net"},
		{"registry.azurecr.de", "https://management.azure.com"},
		{"registry.azurecr.cn:443", "https://management.azure.com"},
		{"registry.azurecr.io:8443", "https://management.azure.com"},
		{"REGISTRY.AZURECR.US.", "https://management.azure.com"},
	} {
		t.Run(test.host, func(t *testing.T) {
			managedIdentityServer(t, func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, test.resource, r.URL.Query().Get("resource"))
				writeIdentityToken(t, w, r)
			})
			client := &http.Client{Transport: azureRoundTripper(func(r *http.Request) (*http.Response, error) {
				require.Equal(t, test.host, r.URL.Host)
				require.NoError(t, r.ParseForm())
				endpoint, err := url.Parse("https://" + test.host)
				require.NoError(t, err)
				require.Equal(t, endpoint.Hostname(), r.Form.Get("service"))
				return exchangeResponse(r, acrRefreshToken()), nil
			})}
			ref, err := name.ParseReference(test.host + "/image:latest")
			require.NoError(t, err)
			_, err = NewAzureKeychain(WithAzureRegistryHTTPClient(client)).Resolve(ref.Context())
			require.NoError(t, err)
		})
	}
}

func TestIVPOLCredentialsForwardAzureClient(t *testing.T) {
	managedIdentityServer(t, func(w http.ResponseWriter, r *http.Request) { writeIdentityToken(t, w, r) })
	var exchangeCalls atomic.Int32
	client := &http.Client{Transport: azureRoundTripper(func(r *http.Request) (*http.Response, error) {
		exchangeCalls.Add(1)
		return exchangeResponse(r, acrRefreshToken()), nil
	})}
	opts, _ := RemoteOptsFromIvpolCredentialsWithOptions(nil, v1alpha1.Credentials{
		Providers: []v1alpha1.CredentialsProvidersType{"azure"},
	}, "", logr.Discard(), WithAzureRegistryHTTPClient(client))
	finished := errors.New("registry request reached")
	opts = append(opts, remote.WithTransport(azureRoundTripper(func(*http.Request) (*http.Response, error) {
		return nil, finished
	})))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	opts = append(opts, remote.WithContext(ctx))
	_, err := remote.Head(name.MustParseReference("registry.azurecr.io/image:latest"), opts...)
	require.ErrorIs(t, err, finished)
	require.EqualValues(t, 1, exchangeCalls.Load())
}

func TestAzureRegistryClientTimeout(t *testing.T) {
	managedIdentityServer(t, func(w http.ResponseWriter, r *http.Request) { writeIdentityToken(t, w, r) })
	client := &http.Client{
		Timeout: 10 * time.Millisecond,
		Transport: azureRoundTripper(func(r *http.Request) (*http.Response, error) {
			<-r.Context().Done()
			return nil, r.Context().Err()
		}),
	}
	ctx := policy.WithRetryOptions(context.Background(), policy.RetryOptions{MaxRetries: -1})
	_, err := authn.Resolve(ctx, NewAzureKeychain(WithAzureRegistryHTTPClient(client)), name.MustParseReference("registry.azurecr.io/image:latest").Context())
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestAzureProviderOptionsPreserveOtherProviders(t *testing.T) {
	t.Parallel()
	providers := []string{"default", "google", "github"}
	client := &http.Client{}
	require.Equal(t, KeychainsForProviders(providers...), KeychainsForProvidersWithOptions(providers, WithAzureRegistryHTTPClient(client)))
	require.Equal(t, []authn.Keychain{AzureKeychain}, KeychainsForProvidersWithOptions([]string{"azure"}, nil, WithAzureRegistryHTTPClient(nil)))
}
