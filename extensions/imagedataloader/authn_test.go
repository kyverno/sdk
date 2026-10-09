package imagedataloader

import (
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsACRRegistry(t *testing.T) {
	for _, host := range []string{
		"registry.azurecr.io",
		"registry.azurecr.cn",
		"registry.azurecr.de",
		"registry.azurecr.us",
		"registry.azurecr.io:443",
		"registry.azurecr.cn:8443",
		"Registry.AZURECR.IO",
		"registry.azurecr.io.",
		"Registry.AZURECR.US.:443",
	} {
		t.Run(host, func(t *testing.T) {
			assert.True(t, isACRRegistry(host))
		})
	}

	for _, host := range []string{
		"registry.azurecr.io.attacker.example",
		"registry.azurecr.cn.attacker.example",
		"registry.azurecr.de.attacker.example",
		"registry.azurecr.us.attacker.example",
		"registry.azurecr.io.attacker.example:443",
		"registry.azurecr.io-attacker.example",
		"registry.azurecr.ioattacker.example",
		"registry.azurecr.io.attacker.example.",
		"azurecr.io",
		"registryazurecr.io",
		"registry.example",
		"localhost:5000",
		"127.0.0.1:5000",
		"[::1]:5000",
		"",
		"registry.azurecr.io:invalid",
		"[registry.azurecr.io",
		"registry%2eazurecr.io",
		"registry.azurecr.io..",
	} {
		t.Run(host, func(t *testing.T) {
			assert.False(t, isACRRegistry(host))
		})
	}
}

// String returns an invalid image to prevent any login or network request even
// if the registry guard accidentally allows a non-ACR host through.
type acrGuardResource struct {
	host        string
	stringCalls int
}

func (r *acrGuardResource) RegistryStr() string { return r.host }

func (r *acrGuardResource) String() string {
	r.stringCalls++
	return "invalid image reference"
}

func TestAzureKeychainRejectsNonACRBeforeLogin(t *testing.T) {
	for _, host := range []string{
		"registry.azurecr.io.attacker.example",
		"registry.azurecr.cn.attacker.example",
		"registry.azurecr.de.attacker.example",
		"registry.azurecr.us.attacker.example",
		"registry.azurecr.io.attacker.example:443",
		"registry.example",
	} {
		t.Run(host, func(t *testing.T) {
			resource := &acrGuardResource{host: host}
			chains := KeychainsForProviders("azure")
			require.Len(t, chains, 1)
			got, err := chains[0].Resolve(resource)
			require.NoError(t, err)
			assert.Equal(t, authn.Anonymous, got)
			assert.Zero(t, resource.stringCalls, "non-ACR hosts must be rejected before parsing or login")
		})
	}
}

func TestAzureKeychainAcceptsACRBeforeParsing(t *testing.T) {
	providers := KeychainsForProviders("azure")
	require.Len(t, providers, 1)
	for source, keychain := range map[string]authn.Keychain{
		"exported keychain": AzureKeychain,
		"provider list":     providers[0],
	} {
		t.Run(source, func(t *testing.T) {
			for _, suffix := range []string{"io", "cn", "de", "us"} {
				for _, host := range []string{"registry.azurecr." + suffix, "REGISTRY.AZURECR." + suffix + ".:443"} {
					resource := &acrGuardResource{host: host}
					got, err := keychain.Resolve(resource)
					// This compatibility branch preserves anonymous fallback on
					// invalid image references after selecting the Azure provider.
					require.NoError(t, err)
					assert.Equal(t, authn.Anonymous, got)
					assert.Equal(t, 1, resource.stringCalls, "ACR hosts must reach reference parsing: %s", host)
				}
			}
		})
	}
}
