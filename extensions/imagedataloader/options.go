package imagedataloader

import (
	"fmt"
	"net"
	"net/http"
	"runtime"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/kyverno/sdk/extensions/regcreds"
	"github.com/kyverno/sdk/extensions/registryclient"
	"sigs.k8s.io/release-utils/version"

	corev1listers "k8s.io/client-go/listers/core/v1"
)

var (
	DefaultTransport = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			// By default we wrap the transport in retries, so reduce the
			// default dial timeout to 5s to avoid 5x 30s of connection
			// timeouts when doing the "ping" on certain http registries.
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	UserAgent = fmt.Sprintf("Kyverno/%s (%s; %s)", version.GetVersionInfo().GitVersion, runtime.GOOS, runtime.GOARCH)
)

type Option func(*options)

type options struct {
	insecure            bool
	secrets             []string
	credentialProviders []string
	localCredentials    bool
	transport           func(http.RoundTripper) http.RoundTripper
}

func WithInsecure(v bool) Option {
	return func(o *options) {
		o.insecure = v
	}
}

// this never gets called anyways
func WithTransport(transport func(http.RoundTripper) http.RoundTripper) Option {
	return func(o *options) {
		o.transport = transport
	}
}

func WithPullSecret(secrets []string) Option {
	return func(o *options) {
		o.secrets = secrets
	}
}

func WithCredentialProviders(providers ...string) Option {
	return func(o *options) {
		o.credentialProviders = providers
	}
}

func WithLocalCredentials(v bool) Option {
	return func(o *options) {
		o.localCredentials = v
	}
}

// this function gets called only by .New
func makeDefaultOpts(lister corev1listers.SecretLister, opts ...Option) ([]remote.Option, error) {
	// create an array of remote options
	remoteOpts := make([]remote.Option, 0)

	// replacing make base opts
	remoteOpts = append(remoteOpts,
		remote.WithTransport(registryclient.DefaultTransport),
		remote.WithUserAgent(UserAgent),
	)

	// and this.. doesn't it just lead to the same group of opts as the ones the registry client produces ?
	authOpts, err := makeAuthOptions(lister, opts...)
	if err != nil {
		return nil, err
	}

	remoteOpts = append(remoteOpts, authOpts...)
	return remoteOpts, nil
}

// is there any scenario where we may create the imagee data loader but not have initialzied the registry client ?
func makeAuthOptions(lister corev1listers.SecretLister, opts ...Option) ([]remote.Option, error) {
	// wait lol we already have those two damn opts in the other function
	// its needed because this function may be called without makeDefaultOptions being called before it
	remoteOpts := make([]remote.Option, 0)
	remoteOpts = append(remoteOpts,
		remote.WithTransport(registryclient.DefaultTransport),
		remote.WithUserAgent(UserAgent),
	)

	opt := options{}
	for _, o := range opts {
		o(&opt)
	}

	// if the secrets (the imagePullSecerts argument) has non zero length, which in the case of the ivpol
	// where we get credential references from the policy directly then the length will indeed be non zero
	// so realistically this function needs an argument for secrets rather than relying on the opt
	keychains := make([]authn.Keychain, 0)
	if len(opt.secrets) > 0 {
		if lister == nil {
			return nil, fmt.Errorf("secret lister is nil, cannot create image pull secrets")
		}
		kc, err := regcreds.NewAutoRefreshSecretsKeychain(lister, "kyverno", opt.secrets...)
		if err != nil {
			return nil, err
		}
		keychains = append(keychains, kc)
	}

	// same bs as the registry client
	if len(opt.credentialProviders) > 0 {
		keychains = append(keychains, regcreds.KeychainsForProviders(opt.credentialProviders...)...)
	}

	// what sets this option ?
	if opt.localCredentials {
		// we place though, not append. so its either this or anonymous
		keychains = []authn.Keychain{authn.DefaultKeychain} // only in kyverno CLI
	}

	// if there werent key chains
	if len(keychains) == 0 {
		keychains = []authn.Keychain{regcreds.AnonymousKeychain}
	}
	// if there were no credential helpers or secrets create a key chain with anonymous

	remoteOpts = append(remoteOpts,
		// do we append this option in the client as well ?
		remote.WithAuthFromKeychain(authn.NewMultiKeychain(keychains...)),
	)
	return remoteOpts, nil
}

func nameOptions(opts ...Option) []name.Option {
	nameOpts := make([]name.Option, 0)
	opt := options{}
	for _, o := range opts {
		o(&opt)
	}
	if opt.insecure {
		nameOpts = append(nameOpts, name.Insecure)
	}
	return nameOpts
}
