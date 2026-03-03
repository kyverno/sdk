package sources

import (
	"context"
	"errors"
	"testing"

	"github.com/kyverno/sdk/core"
	"github.com/stretchr/testify/assert"
)

func TestNewOnce_ReturnsNonNil(t *testing.T) {
	src := core.MakeSource(1, 2)
	once := NewOnce(src)
	assert.NotNil(t, once)
}

func TestOnce_Load_CallsInnerOnce(t *testing.T) {
	ctx := context.Background()
	var loadCount int
	inner := core.MakeSourceFunc(func(context.Context) ([]int, error) {
		loadCount++
		return []int{1, 2}, nil
	})
	once := NewOnce(inner)

	data1, err1 := once.Load(ctx)
	assert.NoError(t, err1)
	assert.Equal(t, []int{1, 2}, data1)
	assert.Equal(t, 1, loadCount)

	data2, err2 := once.Load(ctx)
	assert.NoError(t, err2)
	assert.Equal(t, []int{1, 2}, data2)
	assert.Equal(t, 1, loadCount, "inner Load not called again")
}

func TestOnce_Load_CachesError(t *testing.T) {
	ctx := context.Background()
	loadErr := errors.New("load failed")
	var loadCount int
	inner := core.MakeSourceFunc(func(context.Context) ([]string, error) {
		loadCount++
		return nil, loadErr
	})
	once := NewOnce(inner)

	_, err1 := once.Load(ctx)
	assert.Equal(t, loadErr, err1)
	_, err2 := once.Load(ctx)
	assert.Equal(t, loadErr, err2)
	assert.Equal(t, 1, loadCount)
}
