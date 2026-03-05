package policy

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPolicyFunc_Evaluate_DelegatesToFunction(t *testing.T) {
	ctx := context.Background()
	p := PolicyFunc[map[string]bool, string, bool](func(_ context.Context, data map[string]bool, in string) (bool, error) {
		allowed, ok := data[in]
		if !ok {
			return false, errors.New("user not found")
		}
		return allowed, nil
	})

	allowed, err := p.Evaluate(ctx, map[string]bool{"read": true, "write": false}, "read")
	assert.NoError(t, err)
	assert.True(t, allowed)

	allowed, err = p.Evaluate(ctx, map[string]bool{"read": true, "write": false}, "write")
	assert.NoError(t, err)
	assert.False(t, allowed)

	_, err = p.Evaluate(ctx, map[string]bool{}, "missing")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestMakePolicyFunc_ReturnsPolicyFunc(t *testing.T) {
	ctx := context.Background()
	called := false
	f := func(context.Context, struct{}, int) (int, error) {
		called = true
		return 42, nil
	}
	p := MakePolicyFunc(f)

	result, err := p.Evaluate(ctx, struct{}{}, 0)
	assert.NoError(t, err)
	assert.Equal(t, 42, result)
	assert.True(t, called)
}
