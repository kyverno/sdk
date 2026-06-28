package registryclient

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	gcrremote "github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/kyverno/kyverno/pkg/tracing"
	"github.com/kyverno/sdk/extensions/regcreds"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/cache"
	"sigs.k8s.io/release-utils/version"

	kubernetes "k8s.io/client-go/kubernetes"
)

var (
	registryClient Client

	once             sync.Once
	initErr          error
	userAgent        = fmt.Sprintf("Kyverno/%s (%s; %s)", version.GetVersionInfo().GitVersion, runtime.GOOS, runtime.GOARCH)
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
)

func GetRegistryClient() (Client, error) {
	if registryClient == nil {
		return nil, fmt.Errorf("registry client wasn't initialized")
	}
	return registryClient, nil
}

func MustRegistryClient() (Client, error) {
	if registryClient == nil {
		panic("registry client wasn't initialized")
	}
	return registryClient, nil
}

func SetupGlobalRegistryClient(ctx context.Context,
	kclient kubernetes.Interface,
	resyncPeriod time.Duration,
	imagePullSecrets string, regCredHelpers string, allowInsecure bool) error {
	once.Do(func() {
		factory := informers.NewSharedInformerFactory(kclient, 10*time.Minute)
		secretInformer := factory.Core().V1().Secrets()
		factory.Start(ctx.Done())

		if !cache.WaitForCacheSync(ctx.Done(), secretInformer.Informer().HasSynced) {
			initErr = fmt.Errorf("timed out waiting for cache sync")
			return
		}
		secretLister := secretInformer.Lister()

		// create an array of key chains
		kcs := []authn.Keychain{}
		// if we have an image pull secrets passed, create a chain that gets auto refreshed on secret updated
		if imagePullSecrets != "" && len(strings.Split(imagePullSecrets, ",")) > 0 {
			kc, err := regcreds.NewAutoRefreshSecretsKeychain(secretLister, "kyverno")
			if err != nil {
				initErr = err
				return
			}
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
			authnKc = authn.NewMultiKeychain(regcreds.AnonymousKeychain)
		}

		c := &client{
			keychain:              authnKc,
			transport:             tracing.Transport(DefaultTransport, otelhttp.WithFilter(tracing.RequestFilterIsInSpan)),
			allowInsecureRegistry: allowInsecure,
		}
		registryClient = c
	})
	return initErr
}

// Options returns remote.Option config parameters for the client
// these options get passed to remote.Get
func (c *client) Options(ctx context.Context) ([]gcrremote.Option, error) {
	opts := []gcrremote.Option{
		gcrremote.WithAuthFromKeychain(c.keychain),
		gcrremote.WithTransport(c.transport),
		gcrremote.WithContext(ctx),
		gcrremote.WithUserAgent(userAgent),
	}

	pusher, err := gcrremote.NewPusher(opts...)
	if err != nil {
		return nil, err
	}
	opts = append(opts, gcrremote.Reuse(pusher))

	puller, err := gcrremote.NewPuller(opts...)
	if err != nil {
		return nil, err
	}
	opts = append(opts, gcrremote.Reuse(puller))

	return opts, nil
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
	remoteOpts, err := c.Options(ctx)
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
