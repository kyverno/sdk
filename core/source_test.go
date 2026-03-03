package core

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSourceFunc_Load_DelegatesToFunction(t *testing.T) {
	ctx := context.Background()
	want := []string{"a", "b"}
	src := MakeSourceFunc(func(context.Context) ([]string, error) {
		return want, nil
	})
	data, err := src.Load(ctx)
	assert.NoError(t, err)
	assert.Equal(t, want, data)
}

func TestSourceFunc_Load_PropagatesError(t *testing.T) {
	ctx := context.Background()
	loadErr := errors.New("load failed")
	src := MakeSourceFunc(func(context.Context) ([]int, error) {
		return nil, loadErr
	})
	data, err := src.Load(ctx)
	assert.Equal(t, loadErr, err)
	assert.Nil(t, data)
}

func TestMakeSource_ReturnsDataAndNilError(t *testing.T) {
	ctx := context.Background()
	src := MakeSource(1, 2, 3)
	data, err := src.Load(ctx)
	assert.NoError(t, err)
	assert.Equal(t, []int{1, 2, 3}, data)
}

func TestMakeSource_EmptyVariadic_ReturnsNilSliceAndNoError(t *testing.T) {
	ctx := context.Background()
	src := MakeSource[int]()
	data, err := src.Load(ctx)
	assert.NoError(t, err)
	assert.Empty(t, data)
}
