package imagedataloader

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"

	_ "github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/awslabs/amazon-ecr-credential-helper/ecr-login"
	fluxauth "github.com/fluxcd/pkg/auth"
	"github.com/fluxcd/pkg/auth/azure"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/authn/github"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/google"
	"k8s.io/apimachinery/pkg/util/sets"
)

var (
	AnonymousKeychain authn.Keychain = anonymousKeyChain{}
	AzureKeychain     authn.Keychain = azureKeyChain{}
)

func KeychainsForProviders(credentialProviders ...string) []authn.Keychain {
	return KeychainsForProvidersWithOptions(credentialProviders)
}

// KeychainsForProvidersWithOptions creates provider keychains with per-client
// authentication options. Without an Azure HTTP client, it uses AzureKeychain.
func KeychainsForProvidersWithOptions(credentialProviders []string, opts ...Option) []authn.Keychain {
	var opt options
	for _, o := range opts {
		o(&opt)
	}
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
		azureKeychain := AzureKeychain
		if opt.azureRegistryHTTPClient != nil {
			azureKeychain = NewAzureKeychain(opts...)
		}
		chains = append(chains, azureKeychain)
	}
	if helpers.Has("github") {
		chains = append(chains, github.Keychain)
	}
	return chains
}

type autoRefreshSecrets struct {
	lister           SecretInterface
	imagePullSecrets []string
}

func NewAutoRefreshSecretsKeychain(lister SecretInterface, imagePullSecrets ...string) (authn.Keychain, error) {
	return &autoRefreshSecrets{
		lister:           lister,
		imagePullSecrets: imagePullSecrets,
	}, nil
}

func (kc *autoRefreshSecrets) Resolve(resource authn.Resource) (authn.Authenticator, error) {
	inner, err := generateKeychainForPullSecrets(context.TODO(), kc.lister, kc.imagePullSecrets...)
	if err != nil {
		return nil, err
	}
	return inner.Resolve(resource)
}

type anonymousKeyChain struct{}

func (anonymousKeyChain) Resolve(_ authn.Resource) (authn.Authenticator, error) {
	return authn.Anonymous, nil
}

// NewAzureKeychain creates an Azure keychain with per-client authentication
// options. The registry HTTP client is used only for the ACR token exchange;
// Azure identity acquisition retains the default credential chain and transport.
func NewAzureKeychain(opts ...Option) authn.Keychain {
	var opt options
	for _, o := range opts {
		o(&opt)
	}
	return azureKeyChain{registryHTTPClient: opt.azureRegistryHTTPClient}
}

type azureKeyChain struct {
	registryHTTPClient *http.Client
}

var _ authn.ContextKeychain = azureKeyChain{}

func (kc azureKeyChain) Resolve(resource authn.Resource) (authn.Authenticator, error) {
	return kc.ResolveContext(context.Background(), resource)
}

func (kc azureKeyChain) ResolveContext(ctx context.Context, resource authn.Resource) (authn.Authenticator, error) {
	if !isACRRegistry(resource.RegistryStr()) {
		return authn.Anonymous, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if _, err := name.ParseReference(resource.String()); err != nil {
		return authn.Anonymous, nil
	}

	// Keep identity acquisition separate from registry egress controls. The
	// default chain may legitimately contact the managed identity endpoint.
	credential, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return authn.Anonymous, nil
	}
	accessToken, err := credential.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{azureResourceManagerScope(resource.RegistryStr())},
	})
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return authn.Anonymous, nil
	}

	registryClient := kc.registryHTTPClient
	if registryClient == nil {
		// Preserve the previous exchange client's timeout and default transport.
		registryClient = &http.Client{}
	}
	credentials, err := (azure.Provider{}).NewArtifactRegistryCredentials(ctx,
		resource.RegistryStr(), &azure.Token{AccessToken: accessToken},
		fluxauth.WithArtifactRegistryHTTPClient(registryClient),
	)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// Preserve compatibility fallback for ordinary authentication failures,
		// but never hide a failure from an explicitly configured exchange client.
		if kc.registryHTTPClient != nil {
			return nil, err
		}
		return authn.Anonymous, nil
	}
	return credentials.Authenticator, nil
}

// Preserve the Resource Manager scope selection of the previous Azure client.
func azureResourceManagerScope(registry string) string {
	configuration := cloud.AzurePublic
	switch {
	case strings.HasSuffix(registry, ".azurecr.cn"):
		configuration = cloud.AzureChina
	case strings.HasSuffix(registry, ".azurecr.us"):
		configuration = cloud.AzureGovernment
	}
	return configuration.Services[cloud.ResourceManager].Endpoint + "/.default"
}

func isACRRegistry(input string) bool {
	serverURL, err := url.Parse("https://" + input)
	if err != nil {
		return false
	}
	host := strings.ToLower(strings.TrimSuffix(serverURL.Hostname(), "."))
	for _, suffix := range []string{".azurecr.io", ".azurecr.cn", ".azurecr.de", ".azurecr.us"} {
		if strings.HasSuffix(host, suffix) {
			return true
		}
	}
	return false
}
