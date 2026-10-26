package registryclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/kyverno/sdk/extensions/regcreds"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1listers "k8s.io/client-go/listers/core/v1"
)

type requestTransportFunc func(*http.Request) (*http.Response, error)

func (f requestTransportFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type requestKeychainFunc func(context.Context, authn.Resource) (authn.Authenticator, error)

func (f requestKeychainFunc) Resolve(target authn.Resource) (authn.Authenticator, error) {
	return f(context.Background(), target)
}

func (f requestKeychainFunc) ResolveContext(ctx context.Context, target authn.Resource) (authn.Authenticator, error) {
	return f(ctx, target)
}

type requestContextKey struct{}

func requestResponse(req *http.Request, status int, body string, headers map[string]string) *http.Response {
	header := make(http.Header)
	for key, value := range headers {
		header.Set(key, value)
	}
	return &http.Response{
		StatusCode:    status,
		Status:        fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Header:        header,
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       req,
	}
}

// Exercise the actual remote.Get authentication and redirect machinery: every
// request, including requests to hosts introduced by a server response, must
// pass through the caller's transport and retain the request context.
func TestWithTransport_RegistryTokenAndRedirectRequests(t *testing.T) {
	t.Parallel()
	manifest, err := empty.Image.RawManifest()
	require.NoError(t, err)
	mediaType, err := empty.Image.MediaType()
	require.NoError(t, err)

	for _, blockedHost := range []string{"", "registry.example.test", "auth.example.test", "cdn.example.test"} {
		label := blockedHost
		if label == "" {
			label = "allowed"
		}
		t.Run(label, func(t *testing.T) {
			t.Parallel()
			denied := errors.New("request denied by caller transport")
			var hosts []string
			ctx := context.WithValue(context.Background(), requestContextKey{}, "request")
			transport := requestTransportFunc(func(req *http.Request) (*http.Response, error) {
				hosts = append(hosts, req.URL.Host)
				assert.Equal(t, "request", req.Context().Value(requestContextKey{}))
				assert.Contains(t, req.UserAgent(), regcreds.KyvernoUserAgent)
				if req.URL.Host == blockedHost {
					return nil, denied
				}
				switch req.URL.Host + req.URL.Path {
				case "registry.example.test/v2/":
					return requestResponse(req, http.StatusUnauthorized, "", map[string]string{
						"WWW-Authenticate": `Bearer realm="https://auth.example.test/token",service="registry.example.test"`,
					}), nil
				case "auth.example.test/token":
					username, password, ok := req.BasicAuth()
					assert.True(t, ok)
					assert.Equal(t, "reader", username)
					assert.Equal(t, "password", password)
					return requestResponse(req, http.StatusOK, `{"token":"test-token","expires_in":3600}`, nil), nil
				case "registry.example.test/v2/repo/manifests/latest":
					assert.Equal(t, "Bearer test-token", req.Header.Get("Authorization"))
					return requestResponse(req, http.StatusTemporaryRedirect, "", map[string]string{
						"Location": "https://cdn.example.test/manifest",
					}), nil
				case "cdn.example.test/manifest":
					return requestResponse(req, http.StatusOK, string(manifest), map[string]string{
						"Content-Type": string(mediaType),
					}), nil
				default:
					return nil, fmt.Errorf("unexpected request: %s", req.URL)
				}
			})
			client := New(WithTransport(transport), WithKeychain(fixedKeychain{
				auth: &authn.Basic{Username: "reader", Password: "password"},
			}))
			descriptor, err := client.FetchImageDescriptor(ctx, "registry.example.test/repo:latest")
			if blockedHost != "" {
				require.ErrorIs(t, err, denied)
				require.NotEmpty(t, hosts)
				assert.Equal(t, blockedHost, hosts[len(hosts)-1])
				return
			}
			require.NoError(t, err)
			assert.Equal(t, manifest, descriptor.Manifest)
			assert.Equal(t, []string{
				"registry.example.test", "auth.example.test", "registry.example.test", "cdn.example.test",
			}, hosts)
		})
	}
}

type requestSecretLister struct {
	corev1listers.SecretLister
	lookups int
}

func (l *requestSecretLister) Secrets(string) corev1listers.SecretNamespaceLister {
	l.lookups++
	return notFoundSecretNamespaceLister{}
}

func TestWithKeychainWrapper_GatesComposedCredentials(t *testing.T) {
	t.Parallel()
	for _, source := range []string{"keychain", "secret", "both"} {
		for _, wrapperFirst := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/wrapper-first=%t", source, wrapperFirst), func(t *testing.T) {
				t.Parallel()
				denied := errors.New("registry rejected before credentials")
				credentialCalls, transportCalls := 0, 0
				lister := &requestSecretLister{}
				opts := []Option{WithTransport(requestTransportFunc(func(*http.Request) (*http.Response, error) {
					transportCalls++
					return nil, errors.New("unexpected HTTP request")
				}))}
				if source != "secret" {
					opts = append(opts, WithKeychain(requestKeychainFunc(func(context.Context, authn.Resource) (authn.Authenticator, error) {
						credentialCalls++
						return authn.Anonymous, nil
					})))
				}
				if source != "keychain" {
					opts = append(opts, WithSecretLister(lister, "tenant"), WithImagePullSecrets("pull-secret"))
				}
				guard := WithKeychainWrapper(func(authn.Keychain) authn.Keychain {
					return requestKeychainFunc(func(ctx context.Context, target authn.Resource) (authn.Authenticator, error) {
						assert.Equal(t, "tenant", ctx.Value(requestContextKey{}))
						assert.Equal(t, "blocked.example.test", target.RegistryStr())
						return nil, denied
					})
				})
				if wrapperFirst {
					opts = append([]Option{guard}, opts...)
				} else {
					opts = append(opts, guard)
				}
				ctx := context.WithValue(context.Background(), requestContextKey{}, "tenant")
				_, err := New(opts...).FetchImageDescriptor(ctx, "blocked.example.test/repo:latest")
				require.ErrorIs(t, err, denied)
				assert.Zero(t, credentialCalls)
				assert.Zero(t, lister.lookups)
				assert.Zero(t, transportCalls)
			})
		}
	}
}

func TestWithKeychainWrapper_OrderAndContext(t *testing.T) {
	t.Parallel()
	var events []string
	ctx := context.WithValue(context.Background(), requestContextKey{}, "caller")
	wrap := func(label string) func(authn.Keychain) authn.Keychain {
		return func(next authn.Keychain) authn.Keychain {
			events = append(events, "wrap "+label)
			return requestKeychainFunc(func(ctx context.Context, target authn.Resource) (authn.Authenticator, error) {
				events = append(events, "resolve "+label)
				assert.Equal(t, "caller", ctx.Value(requestContextKey{}))
				return authn.Resolve(ctx, next, target)
			})
		}
	}
	wantAuth := &authn.Basic{Username: "reader", Password: "password"}
	client := New(
		WithKeychainWrapper(wrap("first")),
		WithKeychain(requestKeychainFunc(func(ctx context.Context, _ authn.Resource) (authn.Authenticator, error) {
			events = append(events, "credential")
			assert.Equal(t, "caller", ctx.Value(requestContextKey{}))
			return wantAuth, nil
		})),
		WithKeychainWrapper(nil),
		WithKeychainWrapper(wrap("second")),
		WithKeychain(requestKeychainFunc(func(ctx context.Context, _ authn.Resource) (authn.Authenticator, error) {
			events = append(events, "anonymous")
			assert.Equal(t, "caller", ctx.Value(requestContextKey{}))
			return authn.Anonymous, nil
		})),
	)
	gotAuth, err := authn.Resolve(ctx, client.Keychain(), testResource("registry.example.test/repo"))
	require.NoError(t, err)
	assert.Equal(t, wantAuth, gotAuth)
	assert.Equal(t, []string{"wrap first", "wrap second", "resolve second", "resolve first", "anonymous", "credential"}, events)
}

// A retained option slice must resolve current credentials for each request.
// Reusing a puller would retain the first authenticator for this repository.
func TestNewRemoteOptions_RefreshesCredentialsAndRequestContext(t *testing.T) {
	t.Parallel()
	manifest, err := empty.Image.RawManifest()
	require.NoError(t, err)
	mediaType, err := empty.Image.MediaType()
	require.NoError(t, err)
	var resolved, received []string
	password := "first-password"
	opts, nameOpts := NewRemoteOptions(
		nil,
		WithKeychainWrapper(nil),
		WithKeychain(requestKeychainFunc(func(ctx context.Context, _ authn.Resource) (authn.Authenticator, error) {
			username, ok := ctx.Value(requestContextKey{}).(string)
			require.True(t, ok, "credential resolution must use the current request context")
			require.NoError(t, ctx.Err())
			resolved = append(resolved, username)
			return &authn.Basic{Username: username, Password: password}, nil
		})),
		WithTransport(requestTransportFunc(func(req *http.Request) (*http.Response, error) {
			require.NoError(t, req.Context().Err())
			assert.Equal(t, "https", req.URL.Scheme)
			if req.URL.Path == "/v2/" {
				return requestResponse(req, http.StatusUnauthorized, "", map[string]string{
					"WWW-Authenticate": `Basic realm="registry"`,
				}), nil
			}
			username, secret, ok := req.BasicAuth()
			assert.True(t, ok)
			assert.Equal(t, req.Context().Value(requestContextKey{}), username)
			assert.Equal(t, password, secret)
			received = append(received, username)
			return requestResponse(req, http.StatusOK, string(manifest), map[string]string{
				"Content-Type": string(mediaType),
			}), nil
		})),
	)
	assert.Empty(t, nameOpts, "HTTPS remains the default")
	ref, err := name.ParseReference("registry.example.test/repo:latest", nameOpts...)
	require.NoError(t, err)
	for _, caller := range []string{"first-caller", "second-caller"} {
		ctx, cancel := context.WithCancel(context.WithValue(context.Background(), requestContextKey{}, caller))
		requestOpts := append(append([]remote.Option(nil), opts...), remote.WithContext(ctx))
		descriptor, err := remote.Get(ref, requestOpts...)
		cancel()
		require.NoError(t, err)
		assert.Equal(t, manifest, descriptor.Manifest)
		password = "rotated-password"
	}
	assert.Equal(t, []string{"first-caller", "second-caller"}, resolved)
	assert.Equal(t, resolved, received)

	_, insecureNameOpts := NewRemoteOptions(WithAllowInsecureRegistry(true))
	insecureRef, err := name.ParseReference("registry.example.test/repo:latest", insecureNameOpts...)
	require.NoError(t, err)
	assert.Equal(t, "http", insecureRef.Context().Scheme())
}
