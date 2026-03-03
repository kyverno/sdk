package utils

import (
	"testing"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/stretchr/testify/assert"
)

func TestGetArg_Success(t *testing.T) {
	t.Run("int", func(t *testing.T) {
		args := []ref.Val{types.Int(42)}
		got, errVal := GetArg[int](args, 0)
		assert.Nil(t, errVal)
		assert.Equal(t, 42, got)
	})
	t.Run("string", func(t *testing.T) {
		args := []ref.Val{types.String("hello")}
		got, errVal := GetArg[string](args, 0)
		assert.Nil(t, errVal)
		assert.Equal(t, "hello", got)
	})
	t.Run("bool", func(t *testing.T) {
		args := []ref.Val{types.True}
		got, errVal := GetArg[bool](args, 0)
		assert.Nil(t, errVal)
		assert.True(t, got)
	})
	t.Run("second_arg", func(t *testing.T) {
		args := []ref.Val{types.Int(1), types.Int(2), types.Int(3)}
		got, errVal := GetArg[int](args, 1)
		assert.Nil(t, errVal)
		assert.Equal(t, 2, got)
	})
}

func TestGetArg_ConversionError(t *testing.T) {
	args := []ref.Val{types.String("not-an-int")}
	got, errVal := GetArg[int](args, 0)
	assert.NotNil(t, errVal)
	assert.True(t, types.IsError(errVal))
	assert.Equal(t, 0, got)
}

func TestGetArg_ErrorContainsIndexAndMessage(t *testing.T) {
	args := []ref.Val{types.Bool(false)}
	_, errVal := GetArg[string](args, 0)
	assert.True(t, types.IsError(errVal))
	err, ok := errVal.(error)
	assert.True(t, ok)
	assert.Contains(t, err.Error(), "invalid arg")
	assert.Contains(t, err.Error(), "0")
}
