package regcreds

import (
	"container/list"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrhelper "github.com/awslabs/amazon-ecr-credential-helper/ecr-login"
	ecrapi "github.com/awslabs/amazon-ecr-credential-helper/ecr-login/api"
	"github.com/google/go-containerregistry/pkg/authn"
	"golang.org/x/sync/singleflight"
)

const (
	defaultAmazonTokenCacheSize = 128
	defaultAmazonResolveTimeout = 15 * time.Second
	amazonTokenExpiryWindow     = 5 * time.Minute
)

type ecrClient interface {
	GetAuthorizationToken(context.Context, *ecr.GetAuthorizationTokenInput, ...func(*ecr.Options)) (*ecr.GetAuthorizationTokenOutput, error)
}

type amazonClientFactory func(context.Context, string, bool) (ecrClient, error)

type amazonCacheKey struct {
	account string
	region  string
}

func (k amazonCacheKey) String() string {
	return k.account + "/" + k.region
}

type amazonToken struct {
	auth      authn.Authenticator
	expiresAt time.Time
}

type amazonTokenCacheEntry struct {
	key   amazonCacheKey
	token amazonToken
}

type amazonTokenCache struct {
	maxEntries int
	entries    map[amazonCacheKey]*list.Element
	lru        *list.List
}

func newAmazonTokenCache(maxEntries int) *amazonTokenCache {
	if maxEntries < 1 {
		maxEntries = 1
	}
	return &amazonTokenCache{
		maxEntries: maxEntries,
		entries:    map[amazonCacheKey]*list.Element{},
		lru:        list.New(),
	}
}

func (c *amazonTokenCache) get(key amazonCacheKey, now time.Time) (amazonToken, bool) {
	element, ok := c.entries[key]
	if !ok {
		return amazonToken{}, false
	}
	entry := element.Value.(amazonTokenCacheEntry)
	if !now.Before(entry.token.expiresAt.Add(-amazonTokenExpiryWindow)) {
		c.lru.Remove(element)
		delete(c.entries, key)
		return amazonToken{}, false
	}
	c.lru.MoveToFront(element)
	return entry.token, true
}

func (c *amazonTokenCache) put(key amazonCacheKey, token amazonToken) {
	if element, ok := c.entries[key]; ok {
		element.Value = amazonTokenCacheEntry{key: key, token: token}
		c.lru.MoveToFront(element)
		return
	}
	element := c.lru.PushFront(amazonTokenCacheEntry{key: key, token: token})
	c.entries[key] = element
	for c.lru.Len() > c.maxEntries {
		oldest := c.lru.Back()
		entry := oldest.Value.(amazonTokenCacheEntry)
		delete(c.entries, entry.key)
		c.lru.Remove(oldest)
	}
}

type amazonKeychain struct {
	mu             sync.Mutex
	clients        map[string]ecrClient
	tokens         *amazonTokenCache
	clientFactory  amazonClientFactory
	now            func() time.Time
	resolveTimeout time.Duration
	clientGroup    singleflight.Group
	tokenGroup     singleflight.Group
	fallback       authn.Keychain
}

// NewAmazonKeychain returns a process-local keychain for private ECR registries.
// Public ECR authentication continues to use the upstream credential helper.
func NewAmazonKeychain() authn.Keychain {
	return newAmazonKeychain(defaultAmazonTokenCacheSize, defaultAmazonResolveTimeout, newAmazonClient)
}

func newAmazonKeychain(maxEntries int, resolveTimeout time.Duration, clientFactory amazonClientFactory) *amazonKeychain {
	return &amazonKeychain{
		clients:        map[string]ecrClient{},
		tokens:         newAmazonTokenCache(maxEntries),
		clientFactory:  clientFactory,
		now:            time.Now,
		resolveTimeout: resolveTimeout,
		fallback: authn.NewKeychainFromHelper(ecrhelper.NewECRHelper(
			ecrhelper.WithLogger(io.Discard),
		)),
	}
}

func newAmazonClient(ctx context.Context, region string, fips bool) (ecrClient, error) {
	config, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, err
	}
	return ecr.NewFromConfig(config, func(options *ecr.Options) {
		if fips {
			options.EndpointOptions.UseFIPSEndpoint = aws.FIPSEndpointStateEnabled
		}
	}), nil
}

func (k *amazonKeychain) Resolve(resource authn.Resource) (authn.Authenticator, error) {
	ctx, cancel := context.WithTimeout(context.Background(), k.resolveTimeout)
	defer cancel()
	return k.resolve(ctx, resource)
}

func (k *amazonKeychain) resolve(ctx context.Context, resource authn.Resource) (authn.Authenticator, error) {
	registry, err := ecrapi.ExtractRegistry(resource.RegistryStr())
	if err != nil || registry.Service != ecrapi.ServiceECR {
		return k.fallback.Resolve(resource)
	}

	key := amazonCacheKey{account: registry.ID, region: registry.Region}
	if token, ok := k.cachedToken(key); ok {
		return token.auth, nil
	}

	result := k.tokenGroup.DoChan(key.String(), func() (any, error) {
		if token, ok := k.cachedToken(key); ok {
			return token.auth, nil
		}

		refreshCtx, cancel := context.WithTimeout(context.Background(), k.resolveTimeout)
		defer cancel()
		client, err := k.client(refreshCtx, registry.Region, registry.FIPS)
		if err != nil {
			return nil, err
		}
		output, err := client.GetAuthorizationToken(refreshCtx, &ecr.GetAuthorizationTokenInput{
			RegistryIds: []string{registry.ID},
		})
		if err != nil {
			return nil, err
		}
		token, err := authorizationToken(output)
		if err != nil {
			return nil, err
		}
		k.mu.Lock()
		k.tokens.put(key, token)
		k.mu.Unlock()
		return token.auth, nil
	})

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case resolved := <-result:
		if resolved.Err != nil {
			return nil, resolved.Err
		}
		return resolved.Val.(authn.Authenticator), nil
	}
}

func (k *amazonKeychain) cachedToken(key amazonCacheKey) (amazonToken, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.tokens.get(key, k.now())
}

func (k *amazonKeychain) client(ctx context.Context, region string, fips bool) (ecrClient, error) {
	key := fmt.Sprintf("%s/%t", region, fips)
	k.mu.Lock()
	client := k.clients[key]
	k.mu.Unlock()
	if client != nil {
		return client, nil
	}

	value, err, _ := k.clientGroup.Do(key, func() (any, error) {
		k.mu.Lock()
		client := k.clients[key]
		k.mu.Unlock()
		if client != nil {
			return client, nil
		}
		client, err := k.clientFactory(ctx, region, fips)
		if err != nil {
			return nil, err
		}
		k.mu.Lock()
		k.clients[key] = client
		k.mu.Unlock()
		return client, nil
	})
	if err != nil {
		return nil, err
	}
	return value.(ecrClient), nil
}

func authorizationToken(output *ecr.GetAuthorizationTokenOutput) (amazonToken, error) {
	if output == nil || len(output.AuthorizationData) == 0 {
		return amazonToken{}, fmt.Errorf("ecr returned no authorization data")
	}
	data := output.AuthorizationData[0]
	if data.AuthorizationToken == nil || data.ExpiresAt == nil {
		return amazonToken{}, fmt.Errorf("ecr returned incomplete authorization data")
	}
	decoded, err := base64.StdEncoding.DecodeString(*data.AuthorizationToken)
	if err != nil {
		return amazonToken{}, fmt.Errorf("decoding ecr authorization token: %w", err)
	}
	username, password, ok := strings.Cut(string(decoded), ":")
	if !ok {
		return amazonToken{}, fmt.Errorf("ecr returned malformed authorization token")
	}
	return amazonToken{
		auth: authn.FromConfig(authn.AuthConfig{
			Username: username,
			Password: password,
		}),
		expiresAt: *data.ExpiresAt,
	}, nil
}
