package registryclient

import (
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fixedKeychain always resolves to the same authenticator, regardless of target.
type fixedKeychain struct {
	auth authn.Authenticator
}

func (k fixedKeychain) Resolve(_ authn.Resource) (authn.Authenticator, error) {
	return k.auth, nil
}

// testResource is a minimal authn.Resource implementation for exercising keychains in tests.
type testResource string

func (r testResource) String() string      { return string(r) }
func (r testResource) RegistryStr() string { return string(r) }

func TestNew_NoOptions(t *testing.T) {
	c := New()

	require.NotNil(t, c)
	require.NotNil(t, c.Keychain())
	assert.Empty(t, c.NameOptions())
}

func TestNew_WithAllowInsecureRegistry(t *testing.T) {
	c := New(WithAllowInsecureRegistry(true))

	// name.Option values aren't comparable, so just check one was added.
	assert.Len(t, c.NameOptions(), 1)
}

func TestWithKeychain_TakesPrecedenceOverConfiguredCredentials(t *testing.T) {
	globalAuth := &authn.Basic{Username: "global-user", Password: "global-pass"}

	// WithCredentialHelpers("default") makes New build a non-empty fallback keychain
	// (authn.DefaultKeychain), so this also verifies that WithKeychain is tried before it.
	c := New(WithCredentialHelpers("default"), WithKeychain(fixedKeychain{auth: globalAuth}))

	resolved, err := c.Keychain().Resolve(testResource("example.com/repo"))
	require.NoError(t, err)
	assert.Equal(t, authn.Authenticator(globalAuth), resolved)
}

func TestWithKeychain_FallsBackWhenAnonymous(t *testing.T) {
	c := New(WithKeychain(fixedKeychain{auth: authn.Anonymous}))

	// with no other credentials configured, New falls back to authn.DefaultKeychain; composing
	// an anonymous keychain in front of it must not error out and must still resolve.
	resolved, err := c.Keychain().Resolve(testResource("example.com/repo"))
	require.NoError(t, err)
	require.NotNil(t, resolved)
}

func TestWithKeychain_LaterOptionTakesPrecedence(t *testing.T) {
	firstAuth := &authn.Basic{Username: "first-user", Password: "first-pass"}
	secondAuth := &authn.Basic{Username: "second-user", Password: "second-pass"}

	// Each WithKeychain wraps the result of the previous ones, so when applied multiple times,
	// the last one is tried first.
	c := New(
		WithKeychain(fixedKeychain{auth: firstAuth}),
		WithKeychain(fixedKeychain{auth: secondAuth}),
	)

	resolved, err := c.Keychain().Resolve(testResource("example.com/repo"))
	require.NoError(t, err)
	assert.Equal(t, authn.Authenticator(secondAuth), resolved)
}

func TestWithKeychain_NilIsNoop(t *testing.T) {
	c := New(WithKeychain(nil))

	require.NotNil(t, c.Keychain())
}

func TestNew_WithImagePullSecretsWithoutSecretLister(t *testing.T) {
	// no WithSecretLister: the client should still build without error, secrets are just
	// unresolvable (a nil lister) until looked up.
	c := New(WithImagePullSecrets("my-secret"))

	require.NotNil(t, c)
	require.NotNil(t, c.Keychain())
}
