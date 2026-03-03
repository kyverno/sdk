package core

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewEngine_ReturnsNonNil(t *testing.T) {
	src := MakeSource("p1")
	handler := func(context.Context, FactoryContext[string, string, int]) Handler[int, string] {
		return MakeHandlerFunc(func(context.Context, int) string { return "ok" })
	}
	eng := NewEngine(src, handler)
	assert.NotNil(t, eng)
}

func TestEngine_Handle_LoadsSourceBuildsHandlerAndReturnsResult(t *testing.T) {
	ctx := context.Background()
	src := MakeSource("p1", "p2")
	var seenInput int
	handlerFactory := func(_ context.Context, fctx FactoryContext[string, []string, int]) Handler[int, string] {
		return MakeHandlerFunc(func(_ context.Context, in int) string {
			seenInput = in
			return "result"
		})
	}
	eng := NewEngine(src, handlerFactory)

	got := eng.Handle(ctx, []string{"data"}, 42)
	assert.Equal(t, "result", got)
	assert.Equal(t, 42, seenInput)
}

func TestEngine_Handle_SourceErrorStillBuildsContextAndCallsHandler(t *testing.T) {
	ctx := context.Background()
	loadErr := errors.New("load failed")
	src := MakeSourceFunc(func(context.Context) ([]string, error) {
		return nil, loadErr
	})
	handlerFactory := func(_ context.Context, fctx FactoryContext[string, string, int]) Handler[int, string] {
		assert.NotNil(t, fctx.Source.Error)
		return MakeHandlerFunc(func(context.Context, int) string { return "ok" })
	}
	eng := NewEngine(src, handlerFactory)

	got := eng.Handle(ctx, "data", 0)
	assert.Equal(t, "ok", got)
}
