package regcreds

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	corev1listers "k8s.io/client-go/listers/core/v1"
)

type secretLookupLister struct {
	corev1listers.SecretLister
	namespace func(string) corev1listers.SecretNamespaceLister
}

func (l secretLookupLister) Secrets(namespace string) corev1listers.SecretNamespaceLister {
	return l.namespace(namespace)
}

type contextualSecretLookup struct {
	corev1listers.SecretNamespaceLister
	get func(context.Context, string) (*corev1.Secret, error)
}

func (l contextualSecretLookup) GetWithContext(ctx context.Context, name string) (*corev1.Secret, error) {
	return l.get(ctx, name)
}

type cachedSecretLookup struct {
	corev1listers.SecretNamespaceLister
	get func(string) (*corev1.Secret, error)
}

func (l cachedSecretLookup) Get(name string) (*corev1.Secret, error) {
	return l.get(name)
}

type fallbackCredentials struct{ calls int }

func (k *fallbackCredentials) Resolve(authn.Resource) (authn.Authenticator, error) {
	k.calls++
	return authn.Anonymous, nil
}

func pullSecret(password string) *corev1.Secret {
	return &corev1.Secret{
		Type: corev1.SecretTypeDockerConfigJson,
		Data: map[string][]byte{
			corev1.DockerConfigJsonKey: []byte(fmt.Sprintf(`{"auths":{"registry.example":{"username":"user","password":%q}}}`, password)),
		},
	}
}

func TestSecretsKeychainLiveLookupContext(t *testing.T) {
	t.Parallel()
	type requestKey struct{}
	ctx, cancel := context.WithTimeout(context.WithValue(context.Background(), requestKey{}, "request value"), time.Minute)
	defer cancel()
	entered := make(chan context.Context, 1)
	release := make(chan struct{})
	defer close(release)
	lister := secretLookupLister{namespace: func(string) corev1listers.SecretNamespaceLister {
		return contextualSecretLookup{get: func(ctx context.Context, _ string) (*corev1.Secret, error) {
			entered <- ctx
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-release:
				return nil, errors.New("Secret lookup outlived the request")
			}
		}}
	}}
	fallback := &fallbackCredentials{}
	keychain := authn.NewMultiKeychain(NewSecretsKeychain(lister, "tenant", logr.Discard(), "creds"), fallback)
	result := make(chan error, 1)
	go func() {
		_, err := authn.Resolve(ctx, keychain, name.MustParseReference("registry.example/image:tag").Context())
		result <- err
	}()
	select {
	case lookupContext := <-entered:
		deadline, ok := lookupContext.Deadline()
		require.True(t, ok)
		expected, _ := ctx.Deadline()
		require.Equal(t, expected, deadline)
		require.Equal(t, "request value", lookupContext.Value(requestKey{}))
	case <-time.After(5 * time.Second):
		t.Fatal("Secret lookup did not start")
	}
	cancel()
	select {
	case err := <-result:
		require.ErrorIs(t, err, context.Canceled)
		require.Zero(t, fallback.calls)
	case <-time.After(5 * time.Second):
		t.Fatal("Secret lookup ignored request cancellation")
	}
}

func TestSecretsKeychainLookupErrors(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name     string
		err      error
		fallback bool
	}{
		{"missing permits fallback", k8serrors.NewNotFound(schema.GroupResource{Resource: "secrets"}, "creds"), true},
		{"forbidden stops fallback", k8serrors.NewForbidden(schema.GroupResource{Resource: "secrets"}, "creds", errors.New("denied")), false},
		{"unavailable stops fallback", k8serrors.NewServiceUnavailable("unavailable"), false},
		{"canceled stops fallback", context.Canceled, false},
		{"deadline stops fallback", context.DeadlineExceeded, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			lister := secretLookupLister{namespace: func(string) corev1listers.SecretNamespaceLister {
				return contextualSecretLookup{get: func(context.Context, string) (*corev1.Secret, error) {
					return nil, test.err
				}}
			}}
			fallback := &fallbackCredentials{}
			keychain := authn.NewMultiKeychain(NewSecretsKeychain(lister, "tenant", logr.Discard(), "creds"), fallback)
			_, err := authn.Resolve(context.Background(), keychain, name.MustParseReference("registry.example/image:tag").Context())
			if test.fallback {
				require.NoError(t, err)
				require.Equal(t, 1, fallback.calls)
			} else {
				require.ErrorIs(t, err, test.err)
				require.Zero(t, fallback.calls)
			}
		})
	}
}

func TestSecretsKeychainCachedLookupAndRefresh(t *testing.T) {
	t.Parallel()
	for _, reference := range []string{"creds", "tenant/creds", "/tenant/creds"} {
		t.Run(reference, func(t *testing.T) {
			t.Parallel()
			password := "first"
			var namespace, secretName string
			lister := secretLookupLister{namespace: func(value string) corev1listers.SecretNamespaceLister {
				namespace = value
				return cachedSecretLookup{get: func(value string) (*corev1.Secret, error) {
					secretName = value
					return pullSecret(password), nil
				}}
			}}
			keychain := NewSecretsKeychain(lister, "tenant", logr.Discard(), reference)
			resource := name.MustParseReference("registry.example/image:tag").Context()
			for _, expected := range []string{"first", "rotated"} {
				password = expected
				authenticator, err := keychain.Resolve(resource)
				require.NoError(t, err)
				auth, err := authenticator.Authorization()
				require.NoError(t, err)
				require.Equal(t, "user", auth.Username)
				require.Equal(t, expected, auth.Password)
				require.Equal(t, "tenant", namespace)
				require.Equal(t, "creds", secretName)
			}
		})
	}
}

func TestSecretsKeychainNilBackend(t *testing.T) {
	t.Parallel()
	resource := name.MustParseReference("registry.example/image:tag").Context()
	authenticator, err := NewSecretsKeychain(nil, "tenant", logr.Discard()).Resolve(resource)
	require.NoError(t, err)
	require.Equal(t, authn.Anonymous, authenticator)
	for _, reference := range []string{"creds", "tenant/creds"} {
		t.Run(reference, func(t *testing.T) {
			t.Parallel()
			fallback := &fallbackCredentials{}
			keychain := authn.NewMultiKeychain(NewSecretsKeychain(nil, "tenant", logr.Discard(), reference), fallback)
			_, err := authn.Resolve(context.Background(), keychain, resource)
			require.ErrorContains(t, err, "secret lister is not configured")
			require.Zero(t, fallback.calls)
		})
	}
}

func TestSecretsKeychainCanceledBeforeLookup(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// A canceled request must be rejected before even consulting the backend.
	keychain := NewSecretsKeychain(nil, "tenant", logr.Discard(), "creds")
	_, err := authn.Resolve(ctx, keychain, name.MustParseReference("registry.example/image:tag").Context())
	require.ErrorIs(t, err, context.Canceled)
}

func TestSecretsKeychainCanceledDuringCachedLookup(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	lister := secretLookupLister{namespace: func(string) corev1listers.SecretNamespaceLister {
		return cachedSecretLookup{get: func(string) (*corev1.Secret, error) {
			cancel()
			return pullSecret("unused"), nil
		}}
	}}
	fallback := &fallbackCredentials{}
	keychain := authn.NewMultiKeychain(NewSecretsKeychain(lister, "tenant", logr.Discard(), "creds"), fallback)
	_, err := authn.Resolve(ctx, keychain, name.MustParseReference("registry.example/image:tag").Context())
	require.ErrorIs(t, err, context.Canceled)
	require.Zero(t, fallback.calls)
}
