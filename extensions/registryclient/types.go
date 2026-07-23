package registryclient

import (
	"context"
	"net/http"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	gcrremote "github.com/google/go-containerregistry/pkg/v1/remote"
)

type client struct {
	keychain              authn.Keychain
	transport             http.RoundTripper
	allowInsecureRegistry bool
}

// Client provides registry related objects.
type Client interface {
	// Keychain provides the configured credentials
	Keychain() authn.Keychain

	// FetchImageDescriptor fetches Descriptor from registry with given imageRef
	// and provides access to metadata about remote artifact.
	FetchImageDescriptor(context.Context, string) (*gcrremote.Descriptor, error)

	// Options returns remote.Option configuration for the client.
	Options(context.Context) ([]gcrremote.Option, []name.Option, error)

	// NameOptions returns name.Option configuration for the client.
	NameOptions() []name.Option
}
