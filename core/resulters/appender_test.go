package resulters

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewAppender_ReturnsNonNil(t *testing.T) {
	r := NewAppender[string, int, bool]()
	assert.NotNil(t, r)
}

func TestAppender_Result_InitiallyEmpty(t *testing.T) {
	r := NewAppender[string, int, bool]()
	got := r.Result()
	assert.Nil(t, got)
	assert.Len(t, got, 0)
}

func TestAppender_Collect_AppendsToResult(t *testing.T) {
	ctx := context.Background()
	r := NewAppender[string, int, bool]()

	r.Collect(ctx, "p1", 1, true)
	r.Collect(ctx, "p2", 2, false)

	got := r.Result()
	assert.Len(t, got, 2)
	assert.True(t, got[0])
	assert.False(t, got[1])
}

func TestAppender_Collect_OrderPreserved(t *testing.T) {
	ctx := context.Background()
	r := NewAppender[string, int, int]()

	r.Collect(ctx, "a", 0, 10)
	r.Collect(ctx, "b", 0, 20)
	r.Collect(ctx, "c", 0, 30)

	got := r.Result()
	assert.Equal(t, []int{10, 20, 30}, got)
}
