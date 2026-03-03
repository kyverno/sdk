package resulters

import (
	"context"
	"testing"

	"github.com/kyverno/sdk/core"
	"github.com/stretchr/testify/assert"
)

func TestNewTransformer_ReturnsNonNil(t *testing.T) {
	collect := func(_ string, _ int, out bool) int {
		if out {
			return 1
		}
		return 0
	}
	result := func(x []int) int {
		sum := 0
		for _, v := range x {
			sum += v
		}
		return sum
	}
	inner := NewAppender[string, int, int]()
	r := NewTransformer(collect, result, inner)
	assert.NotNil(t, r)
}

func TestTransformer_Collect_TransformsAndDelegatesToInner(t *testing.T) {
	ctx := context.Background()
	// Transform (policy, in, out) -> policy + out value for collection
	collect := func(policy string, _ int, out bool) string {
		if out {
			return policy + ":true"
		}
		return policy + ":false"
	}
	result := func(items []string) []string {
		return items
	}
	inner := NewAppender[string, int, string]()

	r := NewTransformer(collect, result, inner)
	r.Collect(ctx, "p1", 10, true)
	r.Collect(ctx, "p2", 10, false)

	got := r.Result()
	assert.Equal(t, []string{"p1:true", "p2:false"}, got)
}

func TestTransformer_Result_TransformsInnerResult(t *testing.T) {
	ctx := context.Background()
	collect := func(_ string, _ int, out int) int {
		return out
	}
	result := func(items []int) int {
		sum := 0
		for _, v := range items {
			sum += v
		}
		return sum
	}
	inner := NewAppender[string, int, int]()

	r := NewTransformer(collect, result, inner)
	r.Collect(ctx, "p1", 0, 1)
	r.Collect(ctx, "p2", 0, 2)
	r.Collect(ctx, "p3", 0, 3)

	got := r.Result()
	assert.Equal(t, 6, got)
}

func TestTransformer_ImplementsResulter(t *testing.T) {
	ctx := context.Background()
	collect := func(policy string, in int, out bool) struct{ P string; I int; O bool } {
		return struct{ P string; I int; O bool }{policy, in, out}
	}
	result := func(s []struct{ P string; I int; O bool }) int { return len(s) }
	inner := NewAppender[string, int, struct{ P string; I int; O bool }]()

	var _ core.Resulter[string, int, bool, int] = NewTransformer(collect, result, inner)

	r := NewTransformer(collect, result, inner)
	r.Collect(ctx, "a", 1, true)
	r.Collect(ctx, "b", 2, false)

	got := r.Result()
	assert.Equal(t, 2, got)
}
