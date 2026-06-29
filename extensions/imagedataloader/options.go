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

func makeAuthOptions(lister corev1listers.SecretLister,
	secrets []string,
	credentialProviders []string,
	localRegistry bool,
) ([]remote.Option, error) {
	remoteOpts := make([]remote.Option, 0)
	remoteOpts = append(remoteOpts,
		remote.WithUserAgent(UserAgent),
	)

	keychains := make([]authn.Keychain, 0)
	if len(secrets) > 0 {
		if lister == nil {
			return nil, fmt.Errorf("secret lister is nil, cannot create image pull secrets")
		}
		kc := regcreds.NewAutoRefreshSecretsKeychain(lister, "kyverno", secrets...)
		keychains = append(keychains, kc)
	}

	// same bs as the registry client
	if len(credentialProviders) > 0 {
		keychains = append(keychains, regcreds.KeychainsForProviders(credentialProviders...)...)
	}

	if localRegistry {
		keychains = []authn.Keychain{authn.DefaultKeychain} // only in kyverno CLI
	}

	// if there werent key chains (localRegistry false, secrets and credentials providers are empty)
	if len(keychains) == 0 {
		keychains = []authn.Keychain{regcreds.AnonymousKeychain}
	}

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
