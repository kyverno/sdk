package registryclient

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type azureRoundTripper func(*http.Request) (*http.Response, error)

func (f azureRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestAzureRegistryHTTPClientOption(t *testing.T) {
	var identityRequests atomic.Int32
	identity := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identityRequests.Add(1)
		assert.Equal(t, "identity-header", r.Header.Get("X-IDENTITY-HEADER"))
		w.Header().Set("Content-Type", "application/json")
		assert.NoError(t, json.NewEncoder(w).Encode(map[string]any{
			"access_token": "identity-token", "expires_on": time.Now().Add(time.Hour).Unix(),
			"resource": r.URL.Query().Get("resource"), "token_type": "Bearer",
		}))
	}))
	defer identity.Close()
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != identity.Listener.Addr().String() {
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
	t.Setenv("IDENTITY_ENDPOINT", identity.URL)
	t.Setenv("IDENTITY_HEADER", "identity-header")
	t.Setenv("IDENTITY_SERVER_THUMBPRINT", "")
	t.Setenv("IMDS_ENDPOINT", "")
	t.Setenv("MSI_ENDPOINT", "")
	t.Setenv("MSI_SECRET", "")
	type contextKey struct{}
	ctx := context.WithValue(context.Background(), contextKey{}, "registry-client")
	refreshToken := "eyJhbGciOiJub25lIn0." + base64.RawURLEncoding.EncodeToString(fmt.Appendf(nil, `{"exp":%d}`, time.Now().Add(time.Hour).Unix())) + "."
	var exchangeRequests atomic.Int32
	azureHTTPClient := &http.Client{Transport: azureRoundTripper(func(r *http.Request) (*http.Response, error) {
		exchangeRequests.Add(1)
		assert.Equal(t, "registry-client", r.Context().Value(contextKey{}))
		assert.Equal(t, "registry.azurecr.io", r.URL.Host)
		assert.Equal(t, "/oauth2/exchange", r.URL.Path)
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Body:       io.NopCloser(strings.NewReader(fmt.Sprintf(`{"refresh_token":%q}`, refreshToken))),
			Request:    r,
		}, nil
	})}
	client := New(WithCredentialHelpers("azure"), WithAzureRegistryHTTPClient(azureHTTPClient))
	resolved, err := authn.Resolve(ctx, client.Keychain(), name.MustParseReference("registry.azurecr.io/image:latest").Context())
	require.NoError(t, err)
	config, err := resolved.Authorization()
	require.NoError(t, err)
	require.Equal(t, refreshToken, config.Password)
	require.EqualValues(t, 1, identityRequests.Load())
	require.EqualValues(t, 1, exchangeRequests.Load())
}
