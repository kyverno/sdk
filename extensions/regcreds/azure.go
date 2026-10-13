package regcreds

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	_ "github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	fluxauth "github.com/fluxcd/pkg/auth"
	"github.com/fluxcd/pkg/auth/azure"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
)

type providerOptions struct {
	azureRegistryHTTPClient *http.Client
}

// ProviderOption configures registry credential providers.
type ProviderOption func(*providerOptions)

// WithAzureRegistryHTTPClient configures the HTTP client used to exchange Azure
// identity tokens for ACR registry credentials. The client is used as supplied,
// including its transport, redirect policy, and timeout. It does not change
// Azure identity token acquisition, which may require managed identity endpoints.
// A nil client preserves the default registry transport.
func WithAzureRegistryHTTPClient(client *http.Client) ProviderOption {
	return func(o *providerOptions) {
		o.azureRegistryHTTPClient = client
	}
}

func newProviderOptions(opts ...ProviderOption) providerOptions {
	var o providerOptions
	for _, opt := range opts {
		if opt != nil {
			opt(&o)
		}
	}
	return o
}

type azureKeyChain struct {
	registryHTTPClient *http.Client
}

var _ authn.ContextKeychain = azureKeyChain{}

// NewAzureKeychain constructs an Azure credential provider with per-instance
// configuration. Use authn.Resolve(ctx, keychain, resource) to pass a context
// through identity token acquisition and the ACR token exchange.
func NewAzureKeychain(opts ...ProviderOption) authn.Keychain {
	o := newProviderOptions(opts...)
	return azureKeyChain{registryHTTPClient: o.azureRegistryHTTPClient}
}

func (a azureKeyChain) Resolve(resource authn.Resource) (authn.Authenticator, error) {
	return a.ResolveContext(context.Background(), resource)
}

func (a azureKeyChain) ResolveContext(ctx context.Context, resource authn.Resource) (authn.Authenticator, error) {
	if !isACRRegistry(resource.RegistryStr()) {
		return authn.Anonymous, nil
	}
	if _, err := name.ParseReference(resource.String()); err != nil {
		return authn.Anonymous, err
	}
	if err := ctx.Err(); err != nil {
		return authn.Anonymous, err
	}

	// Keep the existing Azure credential chain, including workload identity,
	// managed identity, and local CLI credentials. A registry-specific client
	// must not restrict the identity endpoints required by that chain.
	credential, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return authn.Anonymous, err
	}

	// Preserve the Resource Manager scope used by the previous Azure client.
	configuration := cloud.AzurePublic
	switch registry := resource.RegistryStr(); {
	case strings.HasSuffix(registry, ".azurecr.cn"):
		configuration = cloud.AzureChina
	case strings.HasSuffix(registry, ".azurecr.us"):
		configuration = cloud.AzureGovernment
	}
	token, err := credential.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{configuration.Services[cloud.ResourceManager].Endpoint + "/.default"},
	})
	if err != nil {
		// DefaultAzureCredential combines credential errors without retaining
		// their error chains. Preserve cancellation for context-aware callers.
		if ctx.Err() != nil {
			return authn.Anonymous, ctx.Err()
		}
		return authn.Anonymous, err
	}

	client := a.registryHTTPClient
	if client == nil {
		// Keep the previous client's default transport and zero timeout when
		// the caller has not selected a registry-specific HTTP client.
		client = &http.Client{}
	}
	credentials, err := (azure.Provider{}).NewArtifactRegistryCredentials(ctx, resource.RegistryStr(), &azure.Token{AccessToken: token},
		fluxauth.WithArtifactRegistryHTTPClient(client))
	if err != nil {
		return authn.Anonymous, err
	}
	return credentials.Authenticator, nil
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
