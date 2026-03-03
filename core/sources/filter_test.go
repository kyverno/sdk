package sources

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/kyverno/sdk/core"
	"github.com/stretchr/testify/assert"
)

func TestNewFilter_KeepsMatchingElements(t *testing.T) {
	ctx := context.Background()
	inner := core.MakeSource(1, 2, 3, 4, 5)
	src := NewFilter(inner, func(n int) bool { return n%2 == 0 })

	data, err := src.Load(ctx)
	assert.NoError(t, err)
	assert.Equal(t, []int{2, 4}, data)
}

func TestNewFilter_NoneMatch(t *testing.T) {
	ctx := context.Background()
	inner := core.MakeSource(1, 3, 5)
	src := NewFilter(inner, func(n int) bool { return n > 10 })

	data, err := src.Load(ctx)
	assert.NoError(t, err)
	assert.Empty(t, data)
}

func TestNewFilter_PropagatesInnerError(t *testing.T) {
	ctx := context.Background()
	loadErr := errors.New("load failed")
	inner := core.MakeSourceFunc(func(context.Context) ([]int, error) { return nil, loadErr })
	src := NewFilter(inner, func(int) bool { return true })

	_, err := src.Load(ctx)
	assert.Equal(t, loadErr, err)
}

func TestNewFilterErr_KeepsMatchingAndAggregatesErrors(t *testing.T) {
	ctx := context.Background()
	inner := core.MakeSource("1", "2", "x", "4")
	src := NewFilterErr(inner, func(s string) (bool, error) {
		if s == "x" {
			return false, fmt.Errorf("invalid: %q", s)
		}
		return true, nil
	})

	data, err := src.Load(ctx)
	assert.Error(t, err)
	assert.Equal(t, []string{"1", "2", "4"}, data)
}

func TestNewFilterErr_AllPass(t *testing.T) {
	ctx := context.Background()
	inner := core.MakeSource("a", "b", "c")
	src := NewFilterErr(inner, func(s string) (bool, error) { return len(s) > 0, nil })

	data, err := src.Load(ctx)
	assert.NoError(t, err)
	assert.Equal(t, []string{"a", "b", "c"}, data)
}
