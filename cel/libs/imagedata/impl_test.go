package imagedata

import (
	"strings"
	"testing"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/kyverno/sdk/cel/compiler"
	"github.com/stretchr/testify/assert"
)

func Test_impl_get_imagedata_string(t *testing.T) {
	base, err := compiler.NewBaseEnv()
	assert.NoError(t, err)
	assert.NotNil(t, base)

	ctx := Context{&ContextMock{
		GetImageDataFunc: func(image string) (map[string]any, error) {
			return map[string]any{
				"resolvedImage": "ghcr.io/kyverno/kyverno:latest@sha256:",
			}, nil
		},
	}}

	env, err := base.Extend(
		Lib(&ctx, nil),
	)
	assert.NoError(t, err)
	assert.NotNil(t, env)
	ast, issues := env.Compile(`image.GetMetadata("ghcr.io/kyverno/kyverno:latest").resolvedImage`)
	assert.Nil(t, issues)
	assert.NotNil(t, ast)
	prog, err := env.Program(ast)
	assert.NoError(t, err)
	assert.NotNil(t, prog)

	out, _, err := prog.Eval(map[string]any{})
	assert.NoError(t, err)
	resolvedImg := out.Value().(string)
	assert.True(t, strings.HasPrefix(resolvedImg, "ghcr.io/kyverno/kyverno:latest@sha256:"))
}

func Test_impl_get_imagedata_string_error(t *testing.T) {
	base, err := compiler.NewBaseEnv()
	assert.NoError(t, err)
	assert.NotNil(t, base)

	env, err := base.Extend(
		Lib(nil, nil),
	)
	assert.NoError(t, err)
	assert.NotNil(t, env)
	tests := []struct {
		name string
		args []ref.Val
		want ref.Val
	}{{
		name: "not enough args",
		args: nil,
		want: types.NewErr("expected 2 arguments, got %d", 0),
	}, {
		name: "bad arg 1",
		args: []ref.Val{types.String("foo"), types.String("foo")},
		want: types.NewErr("unsupported native conversion from string to 'imagedata.Context'"),
	}, {
		name: "bad arg 2",
		args: []ref.Val{env.CELTypeAdapter().NativeToValue(Context{}), types.Bool(false)},
		want: types.NewErr("type conversion error from bool to 'string'"),
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &impl{}
			got := c.get_imagedata_string(tt.args...)
			assert.Equal(t, tt.want, got)
		})
	}
}
