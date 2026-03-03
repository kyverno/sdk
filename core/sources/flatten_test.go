package sources

import (
	"context"
	"errors"
	"testing"

	"github.com/kyverno/sdk/core"
	"github.com/stretchr/testify/assert"
)

func TestNewFlatten_FlattensInnerSlices(t *testing.T) {
	ctx := context.Background()
	inner := core.MakeSource([]int{1, 2}, []int{3, 4, 5})
	src := NewFlatten(inner)

	data, err := src.Load(ctx)
	assert.NoError(t, err)
	assert.Equal(t, []int{1, 2, 3, 4, 5}, data)
}

func TestNewFlatten_EmptyInner(t *testing.T) {
	ctx := context.Background()
	inner := core.MakeSource([]int{}, []int{})
	src := NewFlatten(inner)

	data, err := src.Load(ctx)
	assert.NoError(t, err)
	assert.Empty(t, data)
}

func TestNewFlatten_PropagatesError(t *testing.T) {
	ctx := context.Background()
	loadErr := errors.New("load failed")
	inner := core.MakeSourceFunc(func(context.Context) ([][]int, error) {
		return [][]int{{1}, {2}}, loadErr
	})
	src := NewFlatten(inner)

	data, err := src.Load(ctx)
	assert.Equal(t, loadErr, err)
	assert.Equal(t, []int{1, 2}, data, "flatten still returns available data when inner errors")
}
