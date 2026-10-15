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

Pull Secret keychains retain the supplied lister and reference names, then read
the current Secrets and rebuild their inner credential keychain on every
resolution. Informer reads reflect updates after the cache receives them; this
refresh behavior does not imply live API reads. The concrete object returned by
the caller's `SecretLister.Secrets(namespace)` selects whether the SDK uses
`GetWithContext` or ordinary `Get`. The SDK creates no Kubernetes client or
namespace authorization rules. See [registry credentials](../regcreds/README.md)
for the optional interface and error handling.

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

## Kyverno consumers

The migration drafts [kyverno/kyverno#17917](https://github.com/kyverno/kyverno/pull/17917)
and [#17922](https://github.com/kyverno/kyverno/pull/17922) use both
`WithKeychainWrapper` and `NewRemoteOptions` in Kyverno's guarded registry client
([release source](https://github.com/kyverno/kyverno/blob/334f61a2069aaafcc04c614a0bd0809d7c146a9c/pkg/registryclient/client.go#L166-L174),
[main source](https://github.com/kyverno/kyverno/blob/7e983b618140f52ea07fd6aae3e7c51da49f7db3/pkg/registryclient/client.go#L166-L174)).
At these revisions, their [setup still supplies informer-backed listers](https://github.com/kyverno/kyverno/blob/7e983b618140f52ea07fd6aae3e7c51da49f7db3/cmd/internal/registry.go#L23-L47).

The separate open PRs [#17923](https://github.com/kyverno/kyverno/pull/17923) and
[#17919](https://github.com/kyverno/kyverno/pull/17919) implement a
[policy-scoped getter](https://github.com/kyverno/kyverno/blob/516118f08d46577dba26f2f97ec7116ee24e0cb1/pkg/utils/kube/secret_client.go#L105-L118)
that tries the cache, then performs a live Secret GET on NotFound using the
request context. They currently use a [local context-aware keychain bridge](https://github.com/kyverno/kyverno/blob/516118f08d46577dba26f2f97ec7116ee24e0cb1/pkg/image/verification/credentials/secrets.go#L39-L77).
The SDK hook is intended to replace that duplicate bridge when integrating those
changes; this live-read path is not yet integrated into the migration drafts.
