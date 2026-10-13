# Registry credential providers

Azure registry token exchanges can use a caller-owned HTTP client. Configure its
transport, proxy, redirect policy, and timeout before creating the keychain:

```go
keychain := regcreds.NewAzureKeychain(
    regcreds.WithAzureRegistryHTTPClient(registryHTTPClient),
)
credentials, err := authn.Resolve(ctx, keychain, reference.Context())
```

Use `authn.Resolve` with the request context to propagate cancellation and
deadlines through Azure identity token acquisition and the ACR exchange. The
legacy `keychain.Resolve` method remains available and uses a background context.

The supplied client handles the registry exchange only. Identity token
acquisition keeps the existing Azure default credential chain and its transport,
including workload identity, managed identity endpoints, and local Azure CLI
credentials. Only recognized ACR hosts trigger Azure authentication. Omitting the
option, or supplying `nil`, keeps the existing default transport and timeout.

The same option is available when composing providers or policy credentials:

```go
keychains := regcreds.KeychainsForProvidersWithOptions(
    []string{"azure", "amazon"},
    regcreds.WithAzureRegistryHTTPClient(registryHTTPClient),
)
remoteOpts, nameOpts := regcreds.RemoteOptsFromIvpolCredentialsWithOptions(
    secretLister, policyCredentials, namespace, logger,
    regcreds.WithAzureRegistryHTTPClient(registryHTTPClient),
)
```

`registryclient.New` also accepts
`registryclient.WithAzureRegistryHTTPClient(registryHTTPClient)` together with
`registryclient.WithCredentialHelpers("azure")`. Each configured keychain retains
its own client. Configuring one keychain does not modify other providers or the
exported `regcreds.AzureKeychain` default.
