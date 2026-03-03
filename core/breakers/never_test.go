package breakers

import (
	"context"
	"testing"

	"github.com/kyverno/sdk/core"
	"github.com/stretchr/testify/assert"
)

func TestNever_ReturnsBreaker(t *testing.T) {
	b := Never[string, int, bool]()
	assert.NotNil(t, b)
}

func TestNever_Break_AlwaysReturnsFalse(t *testing.T) {
	b := Never[string, int, bool]()

	t.Run("with_todo_context", func(t *testing.T) {
		got := b.Break(context.TODO(), "policy", 42, true)
		assert.False(t, got)
	})

	t.Run("with_context", func(t *testing.T) {
		ctx := context.Background()
		got := b.Break(ctx, "policy", 0, false)
		assert.False(t, got)
	})

	t.Run("with_various_inputs", func(t *testing.T) {
		ctx := context.Background()
		assert.False(t, b.Break(ctx, "", 0, false))
		assert.False(t, b.Break(ctx, "any", 100, true))
	})
}

func TestNeverFactory_ReturnsNonNilFactory(t *testing.T) {
	factory := NeverFactory[string, struct{}, int, bool]()
	assert.NotNil(t, factory)
}

func TestNeverFactory_InvokedReturnsBreakerThatNeverBreaks(t *testing.T) {
	factory := NeverFactory[string, string, int, bool]()
	ctx := context.Background()
	srcCtx := core.MakeSourceContext([]string{"p1"}, nil)
	fctx := core.MakeFactoryContext(srcCtx, "data", 99)

	breaker := factory(ctx, fctx)
	assert.NotNil(t, breaker)

	got := breaker.Break(ctx, "policy", 1, true)
	assert.False(t, got)
}
