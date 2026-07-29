package registryclient

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	gcrremote "github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/kyverno/kyverno/pkg/tracing"
	"github.com/kyverno/sdk/extensions/regcreds"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	corev1listers "k8s.io/client-go/listers/core/v1"
)

var (
	registryClient Client

	once sync.Once
)

// GlobalOptsOrDefault returns the global registry client's options if it has been initialized,
// otherwise it returns sane defaults. The context is used to initialize remote.WithContext,
// so callers should pass the request context (or a derived one) for remote registry calls.
func GlobalOptsOrDefault(ctx context.Context) ([]gcrremote.Option, []name.Option) {
	if registryClient != nil {
		rc := registryClient.(*client)
		opts, nameOpts := rc.optionsWithoutPuller(ctx)
		return opts, nameOpts
	}

	// there's no registry client, instantiate defaults
	ret := regcreds.DefaultOpts()
	opts := append(ret[:], gcrremote.WithContext(ctx))
	return opts, []name.Option{}
}

func GetRegistryClient() (Client, error) {
	if registryClient == nil {
		return nil, fmt.Errorf("registry client wasn't initialized")
	}
	return registryClient, nil
}

func MustRegistryClient() Client {
	if registryClient == nil {
		panic("registry client wasn't initialized. please call registryclient.SetupGlobalRegistryClient")
	}
	return registryClient
}

// SetupGlobalRegistryClient initializes the package-level global Client. imagePullSecrets and
// regCredHelpers are comma-separated lists, as passed on the command line. Only the first call
// has any effect; later calls return the client built by the first one.
func SetupGlobalRegistryClient(secretLister corev1listers.SecretLister, defaultNamespace string,
	imagePullSecrets string, regCredHelpers string, allowInsecure bool) Client {
	once.Do(func() {
		opts := []Option{WithSecretLister(secretLister, defaultNamespace)}
		if imagePullSecrets != "" {
			opts = append(opts, WithImagePullSecrets(buildSecretList(imagePullSecrets, ",")...))
		}
		if regCredHelpers != "" {
			opts = append(opts, WithCredentialHelpers(buildSecretList(regCredHelpers, ",")...))
		}
		if allowInsecure {
			opts = append(opts, WithAllowInsecureRegistry(true))
		}
		registryClient = New(opts...)
	})
	return registryClient
}

// options accumulates the configuration collected from the Option values passed to New.
type options struct {
	secretLister      corev1listers.SecretLister
	defaultNamespace  string
	imagePullSecrets  []string
	credentialHelpers []string
	allowInsecure     bool
	keychain          authn.Keychain
}

// Option configures a Client built by New.
type Option func(*options)

// WithSecretLister configures the lister (and the namespace unqualified secret names are
// resolved in) used to look up the image pull secrets passed to WithImagePullSecrets.
func WithSecretLister(lister corev1listers.SecretLister, defaultNamespace string) Option {
	return func(o *options) {
		o.secretLister = lister
		o.defaultNamespace = defaultNamespace
	}
}

// WithImagePullSecrets configures the client to also resolve credentials from the given image
// pull secrets. Each secret can be specified as a name (resolved in the namespace configured via
// WithSecretLister) or as namespace/name.
func WithImagePullSecrets(secrets ...string) Option {
	return func(o *options) {
		o.imagePullSecrets = append(o.imagePullSecrets, secrets...)
	}
}

// WithCredentialHelpers configures the client to also authenticate using the given registry
// credential providers/helpers (one or more of: default, google, amazon, azure, github).
func WithCredentialHelpers(providers ...string) Option {
	return func(o *options) {
		o.credentialHelpers = append(o.credentialHelpers, providers...)
	}
}

// WithAllowInsecureRegistry allows the client to talk to registries over plain HTTP.
func WithAllowInsecureRegistry(allow bool) Option {
	return func(o *options) {
		o.allowInsecure = allow
	}
}

// WithKeychain puts kc first in line to authenticate, falling back to the keychain built
// from WithImagePullSecrets/WithCredentialHelpers. Useful for layering per-request
// credentials on top of an existing keychain without losing it.
//
// If applied more than once, the last WithKeychain wins, falling back to earlier ones.
func WithKeychain(kc authn.Keychain) Option {
	return func(o *options) {
		if kc == nil {
			return
		}
		if o.keychain == nil {
			o.keychain = kc
			return
		}
		// authn.NewMultiKeychain tries each keychain in order and returns the first non-anonymous authenticator.
		o.keychain = authn.NewMultiKeychain(kc, o.keychain)
	}
}

// New builds a Client. With no options, it authenticates using authn.DefaultKeychain
// (local Docker/Podman config, or anonymous). Use WithImagePullSecrets/WithCredentialHelpers
// for Kubernetes-based credentials, and WithKeychain to layer an existing keychain on top.
func New(opts ...Option) Client {
	var o options
	for _, opt := range opts {
		if opt != nil {
			opt(&o)
		}
	}

	// create an array of key chains
	kcs := []authn.Keychain{}
	if len(o.imagePullSecrets) > 0 && o.secretLister != nil {
		kcs = append(kcs, regcreds.NewSecretsKeychain(o.secretLister, o.defaultNamespace, o.imagePullSecrets...))
	}
	if len(o.credentialHelpers) > 0 {
		kcs = append(kcs, regcreds.KeychainsForProviders(o.credentialHelpers...)...)
	}

	var authnKc authn.Keychain
	if len(kcs) > 0 {
		authnKc = authn.NewMultiKeychain(kcs...)
	} else {
		authnKc = authn.DefaultKeychain
	}

	if o.keychain != nil {
		authnKc = authn.NewMultiKeychain(o.keychain, authnKc)
	}

	return &client{
		allowInsecureRegistry: o.allowInsecure,
		keychain:              authnKc,
		transport:             tracing.Transport(regcreds.DefaultTransport, otelhttp.WithFilter(tracing.RequestFilterIsInSpan)),
	}
}

// In some scenarios, we don't want to rely on the puller and pusher that have been created by the registry
// client and want to instantiate our own from the credentials we have.
func (c *client) optionsWithoutPuller(ctx context.Context) ([]gcrremote.Option, []name.Option) {
	opts := []gcrremote.Option{
		gcrremote.WithAuthFromKeychain(c.keychain),
		gcrremote.WithTransport(c.transport),
		gcrremote.WithContext(ctx),
		gcrremote.WithUserAgent(regcreds.KyvernoUserAgent),
	}

	nameOpts := []name.Option{}
	if c.allowInsecureRegistry {
		nameOpts = append(nameOpts, name.Insecure)
	}
	return opts, nameOpts
}

// Options returns remote.Option config parameters for the client these options get passed to remote.Get
func (c *client) Options(ctx context.Context) ([]gcrremote.Option, []name.Option, error) {
	opts, nameOpts := c.optionsWithoutPuller(ctx)

	pusher, err := gcrremote.NewPusher(opts...)
	if err != nil {
		return nil, nil, err
	}
	opts = append(opts, gcrremote.Reuse(pusher))

	puller, err := gcrremote.NewPuller(opts...)
	if err != nil {
		return nil, nil, err
	}
	opts = append(opts, gcrremote.Reuse(puller))

	return opts, nameOpts, nil
}

// NameOptions returns name.Option config parameters for the client
func (c *client) NameOptions() []name.Option {
	nameOpts := []name.Option{}

	if c.allowInsecureRegistry {
		nameOpts = append(nameOpts, name.Insecure)
	}

	return nameOpts
}

// FetchImageDescriptor fetches Descriptor from registry with given imageRef
// and provides access to metadata about remote artifact.
func (c *client) FetchImageDescriptor(ctx context.Context, imageRef string) (*gcrremote.Descriptor, error) {
	nameOpts := c.NameOptions()
	parsedRef, err := name.ParseReference(imageRef, nameOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to parse image reference: %s, error: %w", imageRef, err)
	}
	remoteOpts, _, err := c.Options(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get gcr remote opts: %s, error: %w", imageRef, err)
	}
	desc, err := gcrremote.Get(parsedRef, remoteOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch image reference: %s, error: %w", imageRef, err)
	}
	if _, ok := parsedRef.(name.Digest); ok && parsedRef.Identifier() != desc.Digest.String() {
		return nil, fmt.Errorf("digest mismatch, expected: %s, received: %s", parsedRef.Identifier(), desc.Digest.String())
	}
	return desc, nil
}

func (c *client) Keychain() authn.Keychain {
	return c.keychain
}

// buildSecretList splits a comma-separated list of secrets into a slice of strings, trimming whitespace and ignoring empty entries.
func buildSecretList(in string, sep string) []string {
	parts := strings.Split(in, sep)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
