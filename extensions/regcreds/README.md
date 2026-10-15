# Registry credentials

`NewSecretsKeychain` resolves Kubernetes image pull secrets on every credential
lookup, so updated credentials are used without rebuilding the keychain. Secret
references retain their existing formats: `name` uses the default namespace,
while `namespace/name` selects an explicit namespace.

Use `authn.Resolve(ctx, keychain, resource)` to carry the request context through
credential resolution. `remote.WithContext(ctx)` does this automatically for
go-containerregistry requests, including keychains combined with
`authn.NewMultiKeychain`. Calling `keychain.Resolve(resource)` remains supported
and uses a background context.

Informer-backed Secret listers continue to use `Get(name)`. A namespace lister
that performs live reads can additionally implement `ContextSecretNamespaceLister`:

```go
func (l liveNamespaceLister) GetWithContext(ctx context.Context, name string) (*corev1.Secret, error) {
    return l.client.Get(ctx, name, metav1.GetOptions{})
}
```

The keychain passes the request's cancellation, deadline, and values to this
method. A missing Secret is skipped, allowing later credential sources to run.
Authorization failures, cancellation, and other lookup errors stop credential
resolution. Explicit Secret references require a configured lister; an empty
Secret list remains anonymous without one.
