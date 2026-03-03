package defaults

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMakeSourceResult(t *testing.T) {
	t.Run("with_data_and_nil_error", func(t *testing.T) {
		data := []string{"a", "b"}
		got := MakeSourceResult(data, nil)
		assert.Equal(t, data, got.Data)
		assert.Nil(t, got.Error)
	})

	t.Run("with_nil_data_and_error", func(t *testing.T) {
		err := errors.New("load failed")
		got := MakeSourceResult[string](nil, err)
		assert.Nil(t, got.Data)
		assert.Equal(t, err, got.Error)
	})

	t.Run("with_empty_slice", func(t *testing.T) {
		got := MakeSourceResult([]int{}, nil)
		assert.Empty(t, got.Data)
		assert.Nil(t, got.Error)
	})
}

func TestMakePolicyResult(t *testing.T) {
	policy := "policy-1"
	input := 42
	out := true

	got := MakePolicyResult(policy, input, out)
	assert.Equal(t, policy, got.Policy)
	assert.Equal(t, input, got.Input)
	assert.Equal(t, out, got.Out)
}

func TestMakeResult(t *testing.T) {
	source := MakeSourceResult([]string{"p1"}, nil)
	input := 100
	data := "config"
	policies := []PolicyResult[string, int, bool]{
		MakePolicyResult("p1", 100, true),
	}

	got := MakeResult(source, input, data, policies)
	assert.Equal(t, source, got.Source)
	assert.Equal(t, input, got.Input)
	assert.Equal(t, data, got.Data)
	assert.Len(t, got.Policies, 1)
	assert.Equal(t, "p1", got.Policies[0].Policy)
	assert.Equal(t, 100, got.Policies[0].Input)
	assert.True(t, got.Policies[0].Out)
}
