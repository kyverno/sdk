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
