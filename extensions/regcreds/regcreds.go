package regcreds

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"time"

	"github.com/awslabs/amazon-ecr-credential-helper/ecr-login"
	"github.com/fluxcd/pkg/oci/auth/azure"
	"github.com/go-logr/logr"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/authn/github"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/google"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/kyverno/api/api/policies.kyverno.io/v1alpha1"
	"k8s.io/apimachinery/pkg/util/sets"

	corev1listers "k8s.io/client-go/listers/core/v1"
	"sigs.k8s.io/release-utils/version"

	kauth "github.com/google/go-containerregistry/pkg/authn/kubernetes"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
)

var (
	AzureKeychain authn.Keychain = azureKeyChain{}

	KyvernoUserAgent = fmt.Sprintf("Kyverno/%s (%s; %s)", version.GetVersionInfo().GitVersion, runtime.GOOS, runtime.GOARCH)
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

type autoRefreshSecrets struct {
	lister           corev1listers.SecretLister
	defaultNamespace string
	logger           logr.Logger
	imagePullSecrets []string
}

// ContextSecretNamespaceLister is optionally implemented by the namespace lister
// returned by a SecretLister. It allows live Secret reads to use the registry
// request's cancellation, deadline, and values. Informer-backed listers can keep
// implementing only SecretNamespaceLister; their Get method is used as before.
type ContextSecretNamespaceLister interface {
	GetWithContext(context.Context, string) (*corev1.Secret, error)
}

var _ authn.ContextKeychain = (*autoRefreshSecrets)(nil)

func RemoteOptsFromIvpolCredentials(lister corev1listers.SecretLister, ivpolCreds v1alpha1.Credentials, defaultNamespace string, logger logr.Logger) ([]remote.Option, []name.Option) {
	providers := make([]string, 0, len(ivpolCreds.Providers))
	for _, p := range ivpolCreds.Providers {
		providers = append(providers, string(p))
	}

	authOpts := remoteOptsFromParams(lister, defaultNamespace, ivpolCreds.Secrets, providers, logger)

	nameOpts := []name.Option{}
	if ivpolCreds.AllowInsecureRegistry {
		nameOpts = append(nameOpts, name.Insecure)
	}

	return authOpts[:], nameOpts
}

func DefaultOpts() [3]remote.Option {
	remoteOpts := [3]remote.Option{}

	remoteOpts[0] = remote.WithTransport(DefaultTransport)
	remoteOpts[1] = remote.WithUserAgent(KyvernoUserAgent)
	// look for credential helpers in ~/.docker/config.json on the filesystem, or fall back to anonymous
	remoteOpts[2] = remote.WithAuthFromKeychain(authn.DefaultKeychain)

	return remoteOpts
}

func KeychainsForProviders(credentialProviders ...string) []authn.Keychain {
	var chains []authn.Keychain
	helpers := sets.New(credentialProviders...)
	if helpers.Has("default") {
		chains = append(chains, authn.DefaultKeychain)
	}
	if helpers.Has("google") {
		chains = append(chains, google.Keychain)
	}
	if helpers.Has("amazon") {
		chains = append(chains, authn.NewKeychainFromHelper(ecr.NewECRHelper(ecr.WithLogger(io.Discard))))
	}
	if helpers.Has("azure") {
		chains = append(chains, AzureKeychain)
	}
	if helpers.Has("github") {
		chains = append(chains, github.Keychain)
	}
	return chains
}

// NewSecretsKeychain refreshes pull secrets on each credential resolution. When
// a namespace lister implements ContextSecretNamespaceLister, authn.Resolve
// forwards the request context to its Secret reads. Only missing Secrets allow
// fallback to another credential source; other lookup failures are returned to
// the caller.
func NewSecretsKeychain(lister corev1listers.SecretLister, defaultNamespace string, logger logr.Logger, imagePullSecrets ...string) authn.Keychain {
	return &autoRefreshSecrets{
		lister:           lister,
		defaultNamespace: defaultNamespace,
		logger:           logger,
		imagePullSecrets: imagePullSecrets,
	}
}

func (kc *autoRefreshSecrets) Resolve(resource authn.Resource) (authn.Authenticator, error) {
	return kc.ResolveContext(context.Background(), resource)
}

func (kc *autoRefreshSecrets) ResolveContext(ctx context.Context, resource authn.Resource) (authn.Authenticator, error) {
	inner, err := generateKeychainForPullSecrets(ctx, kc.lister, kc.defaultNamespace, kc.logger, kc.imagePullSecrets...)
	if err != nil {
		return nil, err
	}
	return authn.Resolve(ctx, inner, resource)
}

func remoteOptsFromParams(lister corev1listers.SecretLister, defaultNamespace string, secrets, credentialProviders []string, logger logr.Logger) [3]remote.Option {
	ret := DefaultOpts()

	kcs := []authn.Keychain{}
	if len(secrets) > 0 {
		kc := NewSecretsKeychain(lister, defaultNamespace, logger, secrets...)
		kcs = append(kcs, kc)
	}

	if len(credentialProviders) > 0 {
		regKcs := KeychainsForProviders(credentialProviders...)
		kcs = append(kcs, regKcs...)
	}

	if len(kcs) > 0 {
		multiKc := authn.NewMultiKeychain(kcs...)
		ret[2] = remote.WithAuthFromKeychain(multiKc)
	}

	return ret
}

// generateKeychainForPullSecrets generates keychain by fetching secrets data from imagePullSecrets.
// Supports namespace/name notation for secrets in any namespace.
func generateKeychainForPullSecrets(ctx context.Context, lister corev1listers.SecretLister, defaultNamespace string, logger logr.Logger, imagePullSecrets ...string) (authn.Keychain, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var secrets []corev1.Secret
	// for each secret
	for _, imagePullSecret := range imagePullSecrets {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if lister == nil {
			return nil, fmt.Errorf("cannot resolve registry credentials: secret lister is not configured")
		}
		namespace, name := parseSecretReference(imagePullSecret, defaultNamespace)
		namespaceLister := lister.Secrets(namespace)
		var secret *corev1.Secret
		var err error
		if contextual, ok := namespaceLister.(ContextSecretNamespaceLister); ok {
			secret, err = contextual.GetWithContext(ctx, name)
		} else {
			secret, err = namespaceLister.Get(name)
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err == nil {
			secrets = append(secrets, *secret)
		} else if !k8serrors.IsNotFound(err) {
			return nil, err
		} else {
			logger.V(4).Info("secret not found, skipping", "namespace", namespace, "name", name)
		}
	}

	return kauth.NewFromPullSecrets(ctx, secrets)
}

func parseSecretReference(secretRef string, defaultNamespace string) (namespace string, name string) {
	secretRef = strings.TrimPrefix(secretRef, "/")

	parts := strings.SplitN(secretRef, "/", 2)
	// if the secret ref has two parts return 1 and 2 (name and namespace)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	// otherwise return the default namespace and the secret ref with the leading slash removed
	return defaultNamespace, secretRef
}

type azureKeyChain struct{}

func (azureKeyChain) Resolve(resource authn.Resource) (authn.Authenticator, error) {
	if !isACRRegistry(resource.RegistryStr()) {
		return authn.Anonymous, nil
	}

	ref, err := name.ParseReference(resource.String())
	if err != nil {
		return authn.Anonymous, err
	}

	azClient := azure.NewClient()
	auth, err := azClient.Login(context.TODO(), true, resource.String(), ref)
	if err != nil {
		return authn.Anonymous, err
	}
	return auth, nil
}

func isACRRegistry(input string) bool {
	serverURL, err := url.Parse("https://" + input)
	if err != nil {
		return false
	}

	host := strings.ToLower(strings.TrimSuffix(serverURL.Hostname(), "."))
	return azure.ValidHost(host)
}
