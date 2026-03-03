package sources

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/kyverno/sdk/core"
	"github.com/stretchr/testify/assert"
)

func TestNewCache_TransformsAndCaches(t *testing.T) {
	ctx := context.Background()
	inner := core.MakeSource("a", "b", "c")
	keyFunc := func(_ context.Context, s string) (string, error) { return s, nil }
	cacheFunc := func(_ context.Context, k string, _ string) (string, error) {
		return fmt.Sprintf("cached:%s", k), nil
	}

	src := NewCache(inner, keyFunc, cacheFunc)
	data, err := src.Load(ctx)
	assert.NoError(t, err)
	assert.Equal(t, []string{"cached:a", "cached:b", "cached:c"}, data)
}

func TestNewCache_SecondLoadReusesCachedItems(t *testing.T) {
	ctx := context.Background()
	inner := core.MakeSource(1, 2)
	var callCount int
	cacheFunc := func(_ context.Context, k int, _ int) (int, error) {
		callCount++
		return k * 10, nil
	}

	src := NewCache(inner, func(_ context.Context, n int) (int, error) { return n, nil }, cacheFunc)

	data1, err1 := src.Load(ctx)
	assert.NoError(t, err1)
	assert.Equal(t, []int{10, 20}, data1)
	assert.Equal(t, 2, callCount, "cacheFunc called once per item on first Load")

	data2, err2 := src.Load(ctx)
	assert.NoError(t, err2)
	assert.Equal(t, []int{10, 20}, data2)
	assert.Equal(t, 2, callCount, "second Load reuses read buffer so cacheFunc not called again")
}

func TestNewCache_KeyErrorAggregated(t *testing.T) {
	ctx := context.Background()
	inner := core.MakeSource(1, 2, 3)
	keyFunc := func(_ context.Context, n int) (int, error) {
		if n == 2 {
			return 0, errors.New("key error for 2")
		}
		return n, nil
	}
	cacheFunc := func(_ context.Context, k int, _ int) (int, error) { return k, nil }

	src := NewCache(inner, keyFunc, cacheFunc)
	data, err := src.Load(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "key error")
	assert.Equal(t, []int{1, 3}, data)
}

func TestNewCache_CacheFuncErrorAggregated(t *testing.T) {
	ctx := context.Background()
	inner := core.MakeSource(1, 2)
	cacheFunc := func(_ context.Context, k int, _ int) (int, error) {
		if k == 2 {
			return 0, errors.New("cache error")
		}
		return k, nil
	}

	src := NewCache(inner, func(_ context.Context, n int) (int, error) { return n, nil }, cacheFunc)
	data, err := src.Load(ctx)
	assert.Error(t, err)
	assert.Equal(t, []int{1}, data)
}
