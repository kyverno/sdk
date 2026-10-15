# Registry credentials

`NewSecretsKeychain` retains the supplied lister and Secret reference names.
Each `Resolve` or `ResolveContext` call reads those Secrets and builds a fresh
inner credential keychain for that resolution. This preserves the existing
refresh behavior without rebuilding the caller's keychain or retaining resolved
credentials between calls. With informer-backed listers, reads use the local
cache: updated credentials become visible after the informer updates that cache.
Refresh does not itself imply a network request.

Secret references retain their existing formats: `name` uses the default
namespace, while `namespace/name` selects an explicit namespace.

Use `authn.Resolve(ctx, keychain, resource)` to carry the request context through
credential resolution. `remote.WithContext(ctx)` does this automatically for
go-containerregistry requests, including keychains combined with
`authn.NewMultiKeychain`. Calling `keychain.Resolve(resource)` remains supported
and uses a background context.

The SDK calls the supplied `SecretLister.Secrets(namespace)` and checks the
concrete namespace lister it returns. If that object implements
`ContextSecretNamespaceLister`, the SDK uses `GetWithContext(ctx, name)`;
otherwise it uses the standard `Get(name)`. Informer listers need no changes.
The caller chooses and wires the implementation, for example with these methods
on types that also implement the standard lister methods:

```go
func (l liveSecretLister) Secrets(ns string) corev1listers.SecretNamespaceLister {
    return &liveNamespaceLister{client: l.client.Secrets(ns)}
}

func (l liveNamespaceLister) GetWithContext(ctx context.Context, name string) (*corev1.Secret, error) {
    return l.client.Get(ctx, name, metav1.GetOptions{})
}
```

The keychain passes the request's cancellation, deadline, and values to this
method. The SDK does not create namespace listers or Kubernetes API clients,
enable live reads based on a namespace string, or authorize Secret access; those
decisions remain with the caller.

A missing Secret is skipped, allowing later credential sources to run.
Authorization failures, cancellation, and other lookup errors stop credential
resolution. Explicit Secret references require a configured lister; an empty
Secret list remains anonymous without one.
