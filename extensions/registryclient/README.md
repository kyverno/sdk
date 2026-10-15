# Registry client configuration

`New` owns registry credential composition, reference parsing, tracing and
go-containerregistry puller/pusher construction. Existing callers can continue
using it without additional options.

`WithTransport` supplies the `http.RoundTripper` used for registry traffic,
including registry authentication-token requests and redirects. The SDK keeps
its tracing wrapper. A nil transport retains the default transport. This option
does not configure separate HTTP clients owned by cloud credential helpers.

`WithKeychainWrapper` decorates the completed credential chain, after pull
Secrets, providers and `WithKeychain` sources have been composed. This allows a
consumer to apply request-specific checks before any source resolves credentials
without reconstructing the SDK's provider list. Wrappers run in option order,
with the last wrapper outermost; nil wrappers are ignored. A wrapper must return
a non-nil keychain. Context-aware wrappers should implement
`authn.ContextKeychain` and delegate with `authn.Resolve(ctx, inner, resource)`.

Pull Secret resolution forwards the request context to namespace listers that
implement `regcreds.ContextSecretNamespaceLister`. Ordinary informer listers keep
using `Get`. Secrets are read again on subsequent resolutions; only NotFound
permits fallback to another credential source. Namespace authorization is the
consumer's responsibility.

For a request, use `client.Options(ctx)` or `client.FetchImageDescriptor(ctx, ref)`.
For a reusable image data loader, use `NewRemoteOptions` with the same constructor
options and append `remote.WithContext(ctx)` for each operation:

```go
opts, nameOpts := registryclient.NewRemoteOptions(
    registryclient.WithSecretLister(lister, namespace),
    registryclient.WithImagePullSecrets("registry-credentials"),
    registryclient.WithTransport(transport),
)

// Each operation supplies its own context. Do not cache Options(firstRequest):
// those options include a puller and pusher configured for that request.
ref, err := name.ParseReference(image, nameOpts...)
if err != nil {
    return err
}
requestOpts := append(append([]remote.Option(nil), opts...), remote.WithContext(ctx))
_, err = remote.Get(ref, requestOpts...)
return err
```

Reusable options contain neither a request context nor a cached puller/pusher,
so a later request receives its own cancellation, deadline and current
credentials while the configured HTTP transport can share connections.
