package policy

import (
	"context"
	"errors"
	"testing"

	"github.com/kyverno/sdk/core"
	"github.com/stretchr/testify/assert"
)

// accessPolicy implements Policy[map[string]bool, string, bool].
type accessPolicy struct{}

func (p accessPolicy) Evaluate(_ context.Context, data map[string]bool, in string) (bool, error) {
	allowed, ok := data[in]
	if !ok {
		return false, errors.New("user not found")
	}
	return allowed, nil
}

func TestEvaluatorFactory_ReturnsNonNilFactory(t *testing.T) {
	factory := EvaluatorFactory[accessPolicy]()
	assert.NotNil(t, factory)
}

func TestEvaluatorFactory_ProducesEvaluatorThatWrapsInEvaluation(t *testing.T) {
	ctx := context.Background()
	srcCtx := core.MakeSourceContext([]accessPolicy{{}}, nil)
	fctx := core.MakeFactoryContext(srcCtx, map[string]bool{"alice": true, "bob": false}, "")

	factory := EvaluatorFactory[accessPolicy]()
	evaluator := factory(ctx, fctx)
	assert.NotNil(t, evaluator)

	// Evaluate policy with input "alice" -> data has alice: true
	eval := evaluator.Evaluate(ctx, accessPolicy{}, "alice")
	assert.Nil(t, eval.Error)
	assert.True(t, eval.Result)

	// Evaluate with "bob" -> false
	eval = evaluator.Evaluate(ctx, accessPolicy{}, "bob")
	assert.Nil(t, eval.Error)
	assert.False(t, eval.Result)

	// Evaluate with "unknown" -> error
	eval = evaluator.Evaluate(ctx, accessPolicy{}, "unknown")
	assert.Error(t, eval.Error)
	assert.Contains(t, eval.Error.Error(), "not found")
}
