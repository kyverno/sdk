package resulters

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewFirst_ReturnsNonNil(t *testing.T) {
	r := NewFirst[string, int, bool](func(bool) bool { return true })
	assert.NotNil(t, r)
}

func TestFirst_Result_NoMatch_ReturnsZeroValue(t *testing.T) {
	ctx := context.Background()
	r := NewFirst[string, int, int](func(out int) bool { return out > 10 })

	r.Collect(ctx, "p1", 0, 5)
	r.Collect(ctx, "p2", 0, 8)

	got := r.Result()
	assert.Equal(t, 0, got)
}

func TestFirst_Result_FirstMatchReturned(t *testing.T) {
	ctx := context.Background()
	r := NewFirst[string, int, int](func(out int) bool { return out > 5 })

	r.Collect(ctx, "p1", 0, 2)
	r.Collect(ctx, "p2", 0, 7)
	r.Collect(ctx, "p3", 0, 9)

	got := r.Result()
	assert.Equal(t, 7, got)
}

func TestFirst_Result_OnlyFirstMatchStored(t *testing.T) {
	ctx := context.Background()
	r := NewFirst[string, int, bool](func(out bool) bool { return out })

	r.Collect(ctx, "p1", 0, false)
	r.Collect(ctx, "p2", 0, true)
	r.Collect(ctx, "p3", 0, true)

	got := r.Result()
	assert.True(t, got)
}

func TestFirst_Result_FirstItemMatches(t *testing.T) {
	ctx := context.Background()
	r := NewFirst[string, int, string](func(out string) bool { return len(out) > 0 })

	r.Collect(ctx, "p1", 0, "first")

	got := r.Result()
	assert.Equal(t, "first", got)
}
