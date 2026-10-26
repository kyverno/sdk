package regcreds

import (
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/stretchr/testify/require"
)

func TestIsACRRegistry(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		host string
		want bool
	}{
		{"registry.azurecr.io", true},
		{"registry.azurecr.cn", true},
		{"registry.azurecr.de", true},
		{"registry.azurecr.us", true},
		{"registry.azurecr.io:443", true},
		{"registry.azurecr.cn:5000", true},
		{"REGISTRY.AZURECR.IO", true},
		{"registry.azurecr.io.", true},
		{"REGISTRY.AZURECR.US.:443", true},
		{"registry.azurecr.io.attacker.example", false},
		{"registry.azurecr.cn.attacker.example", false},
		{"registry.azurecr.de.attacker.example", false},
		{"registry.azurecr.us.attacker.example", false},
		{"registry.azurecr.ioevil", false},
		{"registryazurecr.io", false},
		{"azurecr.io", false},
		{"registry.azurecr.io..", false},
		{"ghcr.io", false},
		{"localhost", false},
		{"127.0.0.1", false},
		{"[::1]:443", false},
		{"registry.azurecr.io:bad-port", false},
		{"%invalid", false},
		{"", false},
	} {
		t.Run(test.host, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, test.want, isACRRegistry(test.host))
		})
	}
}

// An invalid image reference stops accepted hosts before any Azure login. A
// rejected host must not read the reference at all, even through the exported
// provider list used by SDK consumers.
type azureSelectionResource struct {
	host           string
	referenceReads int
}

func (r *azureSelectionResource) RegistryStr() string { return r.host }

func (r *azureSelectionResource) String() string {
	r.referenceReads++
	return "%invalid-reference"
}

func TestAzureProviderHostSelection(t *testing.T) {
	t.Parallel()
	providers := KeychainsForProviders("azure")
	require.Len(t, providers, 1)
	for source, keychain := range map[string]authn.Keychain{
		"exported keychain": AzureKeychain,
		"provider list":     providers[0],
	} {
		t.Run(source, func(t *testing.T) {
			t.Parallel()
			for _, suffix := range []string{"io", "cn", "de", "us"} {
				for _, host := range []string{"registry.azurecr." + suffix, "REGISTRY.AZURECR." + suffix + ".:443"} {
					resource := &azureSelectionResource{host: host}
					_, err := keychain.Resolve(resource)
					require.Error(t, err, "accepted host must reach reference parsing: %s", host)
					require.Positive(t, resource.referenceReads)
				}
				for _, host := range []string{"registry.azurecr." + suffix + ".attacker.example", "registry.azurecr." + suffix + "evil"} {
					resource := &azureSelectionResource{host: host}
					authenticator, err := keychain.Resolve(resource)
					require.NoError(t, err, host)
					require.Equal(t, authn.Anonymous, authenticator)
					require.Zero(t, resource.referenceReads, "rejected host reached reference parsing: %s", host)
				}
			}
		})
	}
}
