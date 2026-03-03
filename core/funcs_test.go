package core

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBreakerFunc_Break_DelegatesToFunction(t *testing.T) {
	ctx := context.Background()
	b := MakeBreakerFunc(func(_ context.Context, _ string, _ int, out bool) bool {
		return out
	})
	assert.True(t, b.Break(ctx, "p", 0, true))
	assert.False(t, b.Break(ctx, "p", 0, false))
}

func TestDispatcherFunc_Dispatch_InvokesFunction(t *testing.T) {
	ctx := context.Background()
	var received int
	d := MakeDispatcherFunc(func(_ context.Context, in int) {
		received = in
	})
	d.Dispatch(ctx, 99)
	assert.Equal(t, 99, received)
}

func TestHandlerFunc_Handle_ReturnsFunctionResult(t *testing.T) {
	ctx := context.Background()
	h := MakeHandlerFunc(func(_ context.Context, in int) string {
		return "ok"
	})
	got := h.Handle(ctx, 42)
	assert.Equal(t, "ok", got)
}

func TestEvaluatorFunc_Evaluate_DelegatesToFunction(t *testing.T) {
	ctx := context.Background()
	e := MakeEvaluatorFunc(func(_ context.Context, policy string, in int) bool {
		return policy == "allow" && in > 0
	})
	assert.True(t, e.Evaluate(ctx, "allow", 1))
	assert.False(t, e.Evaluate(ctx, "deny", 1))
	assert.False(t, e.Evaluate(ctx, "allow", 0))
}
