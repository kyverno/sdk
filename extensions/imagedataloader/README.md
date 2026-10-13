# Image data authentication

Azure registry token exchanges can use a caller-owned HTTP client:

```go
fetcher, err := imagedataloader.New(secretLister,
    imagedataloader.WithAzureRegistryHTTPClient(registryHTTPClient),
)
if err != nil {
    return err
}
image, err := fetcher.FetchImageData(ctx, "example.azurecr.io/app:latest",
    imagedataloader.WithCredentialProviders("azure"),
)
```

A `WithAzureRegistryHTTPClient` option passed to `FetchImageData` overrides the
constructor's client for that fetch. The client retains its transport, proxy,
redirect, and timeout settings. A nil client selects the default exchange client.
Azure identity acquisition continues to use the default Azure credential chain,
including workload identity, managed identity, and developer credentials, with
its own transport. The supplied registry client only handles the ACR token
exchange.

For direct keychain use, construct `NewAzureKeychain` or
`KeychainsForProvidersWithOptions` with the same option and resolve through
`authn.Resolve(ctx, keychain, resource)` to pass cancellation and deadlines.
`AzureKeychain` and `KeychainsForProviders` remain available with their defaults.

This compatibility branch retains anonymous fallback when Azure identity is
unavailable. Cancellation and errors from a configured registry exchange client
are returned to the caller instead of falling back to anonymous authentication.
