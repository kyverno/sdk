package regcreds

import (
	"testing"

	"github.com/go-logr/logr/funcr"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	corev1listers "k8s.io/client-go/listers/core/v1"
)

// notFoundLister is a SecretLister whose Get always reports the secret as
// missing, which is the branch that emits the debug log we care about.
type notFoundLister struct{}

func (l notFoundLister) List(labels.Selector) ([]*corev1.Secret, error) { return nil, nil }

func (l notFoundLister) Secrets(namespace string) corev1listers.SecretNamespaceLister {
	return notFoundNamespaceLister{namespace: namespace}
}

type notFoundNamespaceLister struct{ namespace string }

func (l notFoundNamespaceLister) List(labels.Selector) ([]*corev1.Secret, error) { return nil, nil }

func (l notFoundNamespaceLister) Get(name string) (*corev1.Secret, error) {
	return nil, k8serrors.NewNotFound(schema.GroupResource{Resource: "secrets"}, name)
}

type testResource string

func (r testResource) String() string      { return string(r) }
func (r testResource) RegistryStr() string { return string(r) }

// A missing pull secret is not an error, it is skipped. The skip is only
// visible through the logger the caller supplies, so the caller has to be able
// to supply one.
func TestNewSecretsKeychain_LogsSkippedSecretToSuppliedLogger(t *testing.T) {
	var logged []string
	logger := funcr.New(
		func(prefix, args string) { logged = append(logged, args) },
		funcr.Options{Verbosity: 4},
	)

	kc := NewSecretsKeychain(notFoundLister{}, "kyverno", logger, "missing-secret")

	auth, err := kc.Resolve(testResource("ghcr.io"))
	require.NoError(t, err)
	assert.NotNil(t, auth)

	require.Len(t, logged, 1, "the skipped secret should be logged exactly once")
	assert.Contains(t, logged[0], "secret not found, skipping")
	assert.Contains(t, logged[0], "missing-secret")
	assert.Contains(t, logged[0], "kyverno")
}

// The logger must not be consulted when there is nothing to skip.
func TestNewSecretsKeychain_NoSecretsLogsNothing(t *testing.T) {
	var logged []string
	logger := funcr.New(
		func(prefix, args string) { logged = append(logged, args) },
		funcr.Options{Verbosity: 4},
	)

	kc := NewSecretsKeychain(notFoundLister{}, "kyverno", logger)

	_, err := kc.Resolve(testResource("ghcr.io"))
	require.NoError(t, err)
	assert.Empty(t, logged)
}

var _ authn.Keychain = (*autoRefreshSecrets)(nil)

func TestKeychainsForProviders(t *testing.T) {
	tests := []struct {
		name      string
		providers []string
		want      int
	}{
		{name: "no providers", providers: nil, want: 0},
		{name: "default", providers: []string{"default"}, want: 1},
		{name: "google", providers: []string{"google"}, want: 1},
		{name: "amazon", providers: []string{"amazon"}, want: 1},
		{name: "azure", providers: []string{"azure"}, want: 1},
		{name: "github", providers: []string{"github"}, want: 1},
		{name: "alibabacloud", providers: []string{"alibabacloud"}, want: 1},
		{name: "all providers", providers: []string{"default", "google", "amazon", "azure", "github", "alibabacloud"}, want: 6},
		{name: "unknown provider", providers: []string{"unknown"}, want: 0},
		{name: "duplicate providers are counted once", providers: []string{"alibabacloud", "alibabacloud"}, want: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Len(t, KeychainsForProviders(tt.providers...), tt.want)
		})
	}
}

// The alibabacloud helper only authenticates against ACR registries; for any other
// registry it must fall back to anonymous instead of failing the keychain, otherwise
// enabling the helper would break verification of images hosted elsewhere.
func TestKeychainsForProviders_AlibabacloudFallsBackToAnonymousForNonACRRegistry(t *testing.T) {
	// Force the non-EE code path of the ACR helper so it rejects the domain
	// without reaching out to the instance metadata service.
	t.Setenv("DOCKER_CREDENTIAL_ACR_HELPER_INSTANCE_ID", "")

	chains := KeychainsForProviders("alibabacloud")
	require.Len(t, chains, 1)

	auth, err := chains[0].Resolve(testResource("ghcr.io"))
	require.NoError(t, err)
	assert.Equal(t, authn.Anonymous, auth)
}
