package core

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMakeSourceContext_SetsDataAndError(t *testing.T) {
	data := []string{"p1", "p2"}
	ctx := MakeSourceContext(data, nil)
	assert.Equal(t, data, ctx.Data)
	assert.Nil(t, ctx.Error)
}

func TestMakeSourceContext_WithError(t *testing.T) {
	err := errors.New("load failed")
	ctx := MakeSourceContext[string](nil, err)
	assert.Nil(t, ctx.Data)
	assert.Equal(t, err, ctx.Error)
}

func TestMakeFactoryContext_SetsSourceDataAndInput(t *testing.T) {
	src := MakeSourceContext([]int{1, 2}, nil)
	fctx := MakeFactoryContext(src, "config", 42)
	assert.Equal(t, src, fctx.Source)
	assert.Equal(t, "config", fctx.Data)
	assert.Equal(t, 42, fctx.Input)
}
