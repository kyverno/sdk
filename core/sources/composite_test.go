package sources

import (
	"context"
	"errors"
	"testing"

	"github.com/kyverno/sdk/core"
	"github.com/stretchr/testify/assert"
)

func TestNewComposite_MergesSourcesInOrder(t *testing.T) {
	ctx := context.Background()
	src1 := core.MakeSource(1, 2)
	src2 := core.MakeSource(3, 4)

	comp := NewComposite(src1, src2)
	data, err := comp.Load(ctx)

	assert.NoError(t, err)
	assert.Equal(t, []int{1, 2, 3, 4}, data)
}

func TestNewComposite_SingleSource(t *testing.T) {
	ctx := context.Background()
	src := core.MakeSource("a", "b")
	comp := NewComposite(src)

	data, err := comp.Load(ctx)
	assert.NoError(t, err)
	assert.Equal(t, []string{"a", "b"}, data)
}

func TestNewComposite_AggregatesErrors(t *testing.T) {
	ctx := context.Background()
	err1 := errors.New("source1 failed")
	err2 := errors.New("source2 failed")
	src1 := core.MakeSourceFunc(func(context.Context) ([]int, error) { return []int{1}, err1 })
	src2 := core.MakeSourceFunc(func(context.Context) ([]int, error) { return []int{2}, err2 })

	comp := NewComposite(src1, src2)
	data, err := comp.Load(ctx)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "source1")
	assert.Contains(t, err.Error(), "source2")
	assert.Empty(t, data, "both sources error so no items appended")
}

func TestNewComposite_PartialSuccess(t *testing.T) {
	ctx := context.Background()
	err2 := errors.New("second failed")
	src1 := core.MakeSource(1, 2)
	src2 := core.MakeSourceFunc(func(context.Context) ([]int, error) { return []int{3}, err2 })
	src3 := core.MakeSource(4, 5)

	comp := NewComposite(src1, src2, src3)
	data, err := comp.Load(ctx)

	assert.Error(t, err)
	assert.Equal(t, []int{1, 2, 4, 5}, data, "items from successful sources are merged")
}
