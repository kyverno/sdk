package regcreds

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"

	"github.com/awslabs/amazon-ecr-credential-helper/ecr-login"
	"github.com/fluxcd/pkg/oci/auth/azure"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/authn/github"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/google"
	"github.com/kyverno/kyverno/pkg/logging"
	"k8s.io/apimachinery/pkg/util/sets"
	corev1listers "k8s.io/client-go/listers/core/v1"

	kauth "github.com/google/go-containerregistry/pkg/authn/kubernetes"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
)

var (
	AnonymousKeychain authn.Keychain = anonymousKeyChain{}
	azureKeychain     authn.Keychain = azureKeyChain{}
)

type autoRefreshSecrets struct {
	lister           corev1listers.SecretLister
	defaultNamespace string
	imagePullSecrets []string
}

// i probably need to move this to a separate module. it would be more clean
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
		chains = append(chains, azureKeychain)
	}
	if helpers.Has("github") {
		chains = append(chains, github.Keychain)
	}
	return chains
}

// where exactly is the auto refresh in this ?
func NewAutoRefreshSecretsKeychain(lister corev1listers.SecretLister, defaultNamespace string, imagePullSecrets ...string) (authn.Keychain, error) {
	return &autoRefreshSecrets{
		lister:           lister,
		defaultNamespace: defaultNamespace,
		imagePullSecrets: imagePullSecrets,
	}, nil
}

func (kc *autoRefreshSecrets) Resolve(resource authn.Resource) (authn.Authenticator, error) {
	inner, err := generateKeychainForPullSecrets(kc.lister, kc.defaultNamespace, kc.imagePullSecrets...)
	if err != nil {
		return nil, err
	}
	return inner.Resolve(resource)
}

// generateKeychainForPullSecrets generates keychain by fetching secrets data from imagePullSecrets.
// Supports namespace/name notation for secrets in any namespace.
func generateKeychainForPullSecrets(lister corev1listers.SecretLister, defaultNamespace string, imagePullSecrets ...string) (authn.Keychain, error) {
	var secrets []corev1.Secret
	// for each secret
	for _, imagePullSecret := range imagePullSecrets {
		namespace, name := parseSecretReference(imagePullSecret, defaultNamespace)
		secret, err := lister.Secrets(namespace).Get(name)
		if err == nil {
			secrets = append(secrets, *secret)
		} else if !k8serrors.IsNotFound(err) {
			return nil, err
		} else {
			logging.V(4).Info("secret not found, skipping", "namespace", namespace, "name", name)
		}
	}

	// context.TODO is not a problem here. the kauth.NewFromPullSecrets doesn't use the context parameter
	return kauth.NewFromPullSecrets(context.TODO(), secrets)
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

type anonymousKeyChain struct{}

func (anonymousKeyChain) Resolve(_ authn.Resource) (authn.Authenticator, error) {
	return authn.Anonymous, nil
}

type azureKeyChain struct{}

func (azureKeyChain) Resolve(resource authn.Resource) (authn.Authenticator, error) {
	if !isACRRegistry(resource.RegistryStr()) {
		return authn.Anonymous, fmt.Errorf("expected an azure registry")
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

	acrRE := regexp.MustCompile(`.*\.azurecr\.io|.*\.azurecr\.cn|.*\.azurecr\.de|.*\.azurecr\.us`)
	matches := acrRE.FindStringSubmatch(serverURL.Hostname())
	return len(matches) != 0
}
