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

func SetupGlobalRegistryClient(secretLister corev1listers.SecretLister, defaultNamespace string,
	imagePullSecrets string, regCredHelpers string, allowInsecure bool) Client {
	once.Do(func() {
		registryClient = New(secretLister, defaultNamespace, imagePullSecrets, regCredHelpers, allowInsecure)
	})
	return registryClient
}

func New(secretLister corev1listers.SecretLister, defaultNamespace string,
	imagePullSecrets string, regCredHelpers string, allowInsecure bool) Client {
	// create an array of key chains
	kcs := []authn.Keychain{}
	if imagePullSecrets != "" {
		secrets := strings.Split(imagePullSecrets, ",")
		kc := regcreds.NewSecretsKeychain(secretLister, defaultNamespace, secrets...)
		kcs = append(kcs, kc)
	}

	credHelpers := strings.Split(regCredHelpers, ",")
	if len(credHelpers) > 0 && regCredHelpers != "" {
		regkc := regcreds.KeychainsForProviders(credHelpers...)
		kcs = append(kcs, regkc...)
	}

	var authnKc authn.Keychain
	if len(kcs) > 0 {
		authnKc = authn.NewMultiKeychain(kcs...)
	} else {
		authnKc = authn.DefaultKeychain
	}

	c := &client{
		allowInsecureRegistry: allowInsecure,
		keychain:              authnKc,
		transport:             tracing.Transport(regcreds.DefaultTransport, otelhttp.WithFilter(tracing.RequestFilterIsInSpan)),
	}
	return c
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
