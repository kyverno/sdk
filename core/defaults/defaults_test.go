package defaults

import (
	"context"
	"errors"
	"testing"

	"github.com/kyverno/sdk/core"
	"github.com/stretchr/testify/assert"
)

func TestResulter_ReturnsResulterFactory(t *testing.T) {
	factory := Resulter[string, string, int, bool]()
	assert.NotNil(t, factory)
}

func TestResulter_CollectAndResult_ProducesExpectedResult(t *testing.T) {
	ctx := context.Background()
	srcCtx := core.MakeSourceContext([]string{"p1", "p2"}, nil)
	fctx := core.MakeFactoryContext(srcCtx, "data", 99)

	factory := Resulter[string, string, int, bool]()
	resulter := factory(ctx, fctx)
	assert.NotNil(t, resulter)

	resulter.Collect(ctx, "p1", 99, true)
	resulter.Collect(ctx, "p2", 99, false)

	result := resulter.Result()
	assert.Equal(t, fctx.Source.Data, result.Source.Data)
	assert.Equal(t, fctx.Source.Error, result.Source.Error)
	assert.Equal(t, 99, result.Input)
	assert.Equal(t, "data", result.Data)
	assert.Len(t, result.Policies, 2)
	assert.Equal(t, "p1", result.Policies[0].Policy)
	assert.Equal(t, 99, result.Policies[0].Input)
	assert.True(t, result.Policies[0].Out)
	assert.Equal(t, "p2", result.Policies[1].Policy)
	assert.False(t, result.Policies[1].Out)
}

func TestResulter_ResultWithSourceError_PreservesError(t *testing.T) {
	ctx := context.Background()
	err := errors.New("source error")
	srcCtx := core.MakeSourceContext([]string(nil), err)
	fctx := core.MakeFactoryContext(srcCtx, "data", 0)

	factory := Resulter[string, string, int, bool]()
	resulter := factory(ctx, fctx)
	result := resulter.Result()

	assert.Equal(t, err, result.Source.Error)
	assert.Nil(t, result.Source.Data)
}

func TestDispatcher_ReturnsNonNilFactory(t *testing.T) {
	evaluator := func(context.Context, core.FactoryContext[string, string, int]) core.Evaluator[string, int, bool] {
		return core.MakeEvaluatorFunc(func(_ context.Context, _ string, _ int) bool { return true })
	}
	factory := Dispatcher(evaluator)
	assert.NotNil(t, factory)
}

type countCollector struct {
	n *int
}

func (c countCollector) Collect(_ context.Context, _ string, _ int, _ bool) {
	*c.n++
}

func TestDispatcher_InvokedReturnsDispatcherThatDispatches(t *testing.T) {
	ctx := context.Background()
	srcCtx := core.MakeSourceContext([]string{"p1", "p2"}, nil)
	fctx := core.MakeFactoryContext(srcCtx, "config", 0)

	var collected int
	collector := countCollector{n: &collected}

	evaluator := func(context.Context, core.FactoryContext[string, string, int]) core.Evaluator[string, int, bool] {
		return core.MakeEvaluatorFunc(func(_ context.Context, _ string, in int) bool { return in > 0 })
	}
	dispatcherFactory := Dispatcher(evaluator)
	dispatcher := dispatcherFactory(ctx, fctx, collector)
	assert.NotNil(t, dispatcher)

	dispatcher.Dispatch(ctx, 1)
	assert.Equal(t, 2, collected, "should collect once per policy")
}

func TestHandler_ReturnsNonNilFactory(t *testing.T) {
	evaluator := func(context.Context, core.FactoryContext[string, string, int]) core.Evaluator[string, int, bool] {
		return core.MakeEvaluatorFunc(func(_ context.Context, _ string, in int) bool { return in > 0 })
	}
	factory := Handler(evaluator)
	assert.NotNil(t, factory)
}

func TestHandler_Handle_ReturnsResultFromResulter(t *testing.T) {
	ctx := context.Background()
	srcCtx := core.MakeSourceContext([]string{"p1", "p2"}, nil)
	fctx := core.MakeFactoryContext(srcCtx, "config", 0)

	evaluator := func(context.Context, core.FactoryContext[string, string, int]) core.Evaluator[string, int, bool] {
		return core.MakeEvaluatorFunc(func(_ context.Context, policy string, in int) bool {
			return policy == "p1" && in == 42
		})
	}
	handlerFactory := Handler(evaluator)
	handler := handlerFactory(ctx, fctx)
	assert.NotNil(t, handler)

	result := handler.Handle(ctx, 42)
	// Result.Input comes from fctx.Input (set at factory build time), not the Handle() argument
	assert.Equal(t, 0, result.Input)
	assert.Equal(t, "config", result.Data)
	assert.Len(t, result.Policies, 2)
	assert.True(t, result.Policies[0].Out, "p1 with input 42 should evaluate true")
	assert.False(t, result.Policies[1].Out, "p2 should evaluate false")
}
