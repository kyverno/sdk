package regcreds

import (
	"context"
	"encoding/base64"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type amazonTestResource string

func (r amazonTestResource) String() string      { return string(r) }
func (r amazonTestResource) RegistryStr() string { return string(r) }

type fakeECRClient struct {
	calls     atomic.Int64
	expiresAt func() time.Time
	started   chan struct{}
	release   chan struct{}
	once      sync.Once
}

func (f *fakeECRClient) GetAuthorizationToken(
	ctx context.Context,
	_ *ecr.GetAuthorizationTokenInput,
	_ ...func(*ecr.Options),
) (*ecr.GetAuthorizationTokenOutput, error) {
	f.calls.Add(1)
	if f.started != nil {
		f.once.Do(func() { close(f.started) })
	}
	if f.release != nil {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-f.release:
		}
	}
	token := base64.StdEncoding.EncodeToString([]byte("AWS:password"))
	return &ecr.GetAuthorizationTokenOutput{
		AuthorizationData: []ecrtypes.AuthorizationData{{
			AuthorizationToken: aws.String(token),
			ExpiresAt:          aws.Time(f.expiresAt()),
		}},
	}, nil
}

func TestAmazonKeychainCoalescesTokenRefreshAndReusesClient(t *testing.T) {
	now := time.Now()
	client := &fakeECRClient{
		expiresAt: func() time.Time { return now.Add(12 * time.Hour) },
		started:   make(chan struct{}),
		release:   make(chan struct{}),
	}
	var factoryCalls atomic.Int64
	keychain := newAmazonKeychain(8, time.Second, func(_ context.Context, region string, fips bool) (ecrClient, error) {
		factoryCalls.Add(1)
		assert.Equal(t, "us-west-2", region)
		assert.False(t, fips)
		return client, nil
	})
	keychain.now = func() time.Time { return now }

	resource := amazonTestResource("123456789012.dkr.ecr.us-west-2.amazonaws.com")
	const workers = 50
	results := make(chan error, workers)
	for range workers {
		go func() {
			authenticator, err := keychain.Resolve(resource)
			if err == nil {
				config, authErr := authenticator.Authorization()
				if authErr != nil {
					err = authErr
				} else if config.Username != "AWS" || config.Password != "password" {
					err = fmt.Errorf("unexpected credentials: %#v", config)
				}
			}
			results <- err
		}()
	}

	<-client.started
	close(client.release)
	for range workers {
		require.NoError(t, <-results)
	}

	assert.Equal(t, int64(1), factoryCalls.Load())
	assert.Equal(t, int64(1), client.calls.Load())

	_, err := keychain.Resolve(resource)
	require.NoError(t, err)
	assert.Equal(t, int64(1), factoryCalls.Load())
	assert.Equal(t, int64(1), client.calls.Load())
}

func TestAmazonKeychainRefreshesNearExpiry(t *testing.T) {
	now := time.Now()
	client := &fakeECRClient{expiresAt: func() time.Time { return now.Add(12 * time.Hour) }}
	keychain := newAmazonKeychain(8, time.Second, func(context.Context, string, bool) (ecrClient, error) {
		return client, nil
	})
	keychain.now = func() time.Time { return now }
	resource := amazonTestResource("123456789012.dkr.ecr.us-west-2.amazonaws.com")

	_, err := keychain.Resolve(resource)
	require.NoError(t, err)
	assert.Equal(t, int64(1), client.calls.Load())

	now = now.Add(11*time.Hour + 56*time.Minute)
	_, err = keychain.Resolve(resource)
	require.NoError(t, err)
	assert.Equal(t, int64(2), client.calls.Load())
}

func TestAmazonKeychainReusesRegionalClientAcrossAccounts(t *testing.T) {
	now := time.Now()
	client := &fakeECRClient{expiresAt: func() time.Time { return now.Add(12 * time.Hour) }}
	var factoryCalls atomic.Int64
	keychain := newAmazonKeychain(8, time.Second, func(context.Context, string, bool) (ecrClient, error) {
		factoryCalls.Add(1)
		return client, nil
	})
	keychain.now = func() time.Time { return now }

	_, err := keychain.Resolve(amazonTestResource("123456789012.dkr.ecr.us-west-2.amazonaws.com"))
	require.NoError(t, err)
	_, err = keychain.Resolve(amazonTestResource("210987654321.dkr.ecr.us-west-2.amazonaws.com"))
	require.NoError(t, err)

	assert.Equal(t, int64(1), factoryCalls.Load())
	assert.Equal(t, int64(2), client.calls.Load())
}

func TestAmazonTokenCacheIsBounded(t *testing.T) {
	now := time.Now()
	cache := newAmazonTokenCache(2)
	token := amazonToken{auth: authn.Anonymous, expiresAt: now.Add(time.Hour)}
	first := amazonCacheKey{account: "1", region: "us-west-2"}
	second := amazonCacheKey{account: "2", region: "us-west-2"}
	third := amazonCacheKey{account: "3", region: "us-west-2"}

	cache.put(first, token)
	cache.put(second, token)
	cache.put(third, token)

	_, found := cache.get(first, now)
	assert.False(t, found)
	_, found = cache.get(second, now)
	assert.True(t, found)
	_, found = cache.get(third, now)
	assert.True(t, found)
	assert.Len(t, cache.entries, 2)
}

func TestAuthorizationTokenRejectsMalformedResponse(t *testing.T) {
	_, err := authorizationToken(&ecr.GetAuthorizationTokenOutput{})
	assert.ErrorContains(t, err, "no authorization data")

	expiresAt := time.Now().Add(time.Hour)
	malformed := base64.StdEncoding.EncodeToString([]byte("missing-separator"))
	_, err = authorizationToken(&ecr.GetAuthorizationTokenOutput{
		AuthorizationData: []ecrtypes.AuthorizationData{{
			AuthorizationToken: aws.String(malformed),
			ExpiresAt:          &expiresAt,
		}},
	})
	assert.ErrorContains(t, err, "malformed authorization token")
}
