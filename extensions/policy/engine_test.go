package policy

import (
	"context"
	"testing"

	"github.com/kyverno/sdk/core"
	"github.com/kyverno/sdk/core/defaults"
	"github.com/stretchr/testify/assert"
)

func TestNewEngine_ReturnsNonNil(t *testing.T) {
	src := core.MakeSource(accessPolicy{})
	eng := NewEngine(src)
	assert.NotNil(t, eng)
}

func TestNewEngine_Handle_ReturnsResultWithPolicyEvaluations(t *testing.T) {
	ctx := context.Background()
	src := core.MakeSource(accessPolicy{})
	eng := NewEngine(src)

	data := map[string]bool{"read": true, "write": false}
	result := eng.Handle(ctx, data, "read")

	// result is defaults.Result[accessPolicy, map[string]bool, string, Evaluation[bool]]
	assert.Equal(t, data, result.Data)
	assert.Equal(t, "read", result.Input)
	assert.Len(t, result.Policies, 1)
	assert.Equal(t, "read", result.Policies[0].Input)
	assert.True(t, result.Policies[0].Out.Result)
	assert.Nil(t, result.Policies[0].Out.Error)
}

func TestNewEngine_Handle_MultiplePolicies(t *testing.T) {
	ctx := context.Background()
	// Two policy instances - engine will evaluate both
	src := core.MakeSource(accessPolicy{}, accessPolicy{})
	eng := NewEngine(src)

	result := eng.Handle(ctx, map[string]bool{"a": true}, "a")

	assert.Len(t, result.Policies, 2)
	for i := range result.Policies {
		assert.True(t, result.Policies[i].Out.Result)
		assert.Nil(t, result.Policies[i].Out.Error)
	}
}

func TestNewEngine_Handle_PropagatesEvaluationError(t *testing.T) {
	ctx := context.Background()
	src := core.MakeSource(accessPolicy{})
	eng := NewEngine(src)

	result := eng.Handle(ctx, map[string]bool{}, "nonexistent")

	assert.Len(t, result.Policies, 1)
	assert.Error(t, result.Policies[0].Out.Error)
	assert.False(t, result.Policies[0].Out.Result)
}

// ensureEngineResultType compiles only if the engine has the expected result type.
func ensureEngineResultType(_ core.Engine[map[string]bool, string, defaults.Result[accessPolicy, map[string]bool, string, Evaluation[bool]]]) {
}

func TestNewEngine_ResultTypeMatchesDefaults(t *testing.T) {
	src := core.MakeSource(accessPolicy{})
	eng := NewEngine(src)
	ensureEngineResultType(eng)
}
