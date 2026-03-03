package sources

import (
	"context"
	"errors"
	"strconv"
	"testing"

	"github.com/kyverno/sdk/core"
	"github.com/stretchr/testify/assert"
)

func TestNewTransform_AppliesTransformToEachElement(t *testing.T) {
	ctx := context.Background()
	inner := core.MakeSource(1, 2, 3)
	src := NewTransform(inner, func(n int) string {
		return strconv.Itoa(n * 10)
	})

	data, err := src.Load(ctx)
	assert.NoError(t, err)
	assert.Equal(t, []string{"10", "20", "30"}, data)
}

func TestNewTransform_PropagatesInnerError(t *testing.T) {
	ctx := context.Background()
	loadErr := errors.New("load failed")
	inner := core.MakeSourceFunc(func(context.Context) ([]int, error) {
		return nil, loadErr
	})
	src := NewTransform(inner, func(n int) string { return strconv.Itoa(n) })

	_, err := src.Load(ctx)
	assert.Equal(t, loadErr, err)
}

func TestNewTransformErr_AppliesTransformAndAggregatesErrors(t *testing.T) {
	ctx := context.Background()
	inner := core.MakeSource("1", "2", "x", "4")
	src := NewTransformErr(inner, func(s string) (int, error) {
		return strconv.Atoi(s)
	})

	data, err := src.Load(ctx)
	assert.Error(t, err)
	assert.Equal(t, []int{1, 2, 4}, data)
}

func TestNewTransformErr_AllSucceed(t *testing.T) {
	ctx := context.Background()
	inner := core.MakeSource("1", "2", "3")
	src := NewTransformErr(inner, strconv.Atoi)

	data, err := src.Load(ctx)
	assert.NoError(t, err)
	assert.Equal(t, []int{1, 2, 3}, data)
}
