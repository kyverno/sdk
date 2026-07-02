package generator

import (
	"testing"

	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/kyverno/sdk/extensions/cel/compiler"
	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/util/version"
)

func Test_apply_generator_string_list(t *testing.T) {
	base, err := compiler.NewBaseEnv()
	assert.NoError(t, err)
	assert.NotNil(t, base)

	ctx := Context{&ContextMock{
		GenerateResourcesFunc: func(namespace string, dataList []map[string]any) error {
			assert.Equal(t, "default", namespace)
			assert.Len(t, dataList, 1)
			assert.Equal(t, dataList[0]["apiVersion"].(string), "apps/v1")
			assert.Equal(t, dataList[0]["kind"].(string), "Deployment")
			assert.Equal(t, dataList[0]["metadata"].(map[string]any)["name"], "name")
			assert.Equal(t, dataList[0]["metadata"].(map[string]any)["namespace"], "namespace")
			return nil
		},
	}}

	env, err := base.Extend(
		Lib(&ctx, "", version.MajorMinor(1, 18)),
	)
	assert.NoError(t, err)
	assert.NotNil(t, env)
	ast, issues := env.Compile(`
generator.apply(
	"default",
	[
		{
			"apiVersion": dyn("apps/v1"),
			"kind":       dyn("Deployment"),
			"metadata": dyn({
				"name":      "name",
				"namespace": "namespace",
			}),
		},
	]
)`)
	assert.Nil(t, issues)
	assert.NotNil(t, ast)
	prog, err := env.Program(ast)
	assert.NoError(t, err)
	assert.NotNil(t, prog)

	_, _, err = prog.Eval(map[string]any{})
	assert.NoError(t, err)
}

func Test_apply_namespaced_no_namespace_arg(t *testing.T) {
	base, err := compiler.NewBaseEnv()
	assert.NoError(t, err)

	called := false
	var capturedNS string
	ctx := Context{&ContextMock{
		GenerateResourcesFunc: func(namespace string, dataList []map[string]any) error {
			called = true
			capturedNS = namespace
			return nil
		},
	}}

	env, err := base.Extend(
		Lib(&ctx, "tenant-ns", version.MajorMinor(1, 18)),
	)
	assert.NoError(t, err)

	// cross-namespace call must not compile — namespace arg not accepted in namespaced policies
	_, issues := env.Compile(`generator.apply("kube-system", [{"apiVersion": dyn("v1"), "kind": dyn("ConfigMap")}])`)
	assert.NotNil(t, issues, "namespace arg must not be accepted in a namespaced policy")

	// correct call: no namespace arg — policy namespace is used automatically
	ast, issues := env.Compile(`generator.apply([{"apiVersion": dyn("v1"), "kind": dyn("ConfigMap")}])`)
	assert.Nil(t, issues)
	prog, err := env.Program(ast)
	assert.NoError(t, err)
	_, _, err = prog.Eval(map[string]any{})
	assert.NoError(t, err)
	assert.True(t, called)
	assert.Equal(t, "tenant-ns", capturedNS, "GenerateResources must receive the policy's own namespace")
}

func Test_apply_generator_string_list_error(t *testing.T) {
	base, err := compiler.NewBaseEnv()
	assert.NoError(t, err)
	assert.NotNil(t, base)

	env, err := base.Extend(
		Lib(nil, "", Latest()),
	)
	assert.NoError(t, err)
	assert.NotNil(t, env)
	tests := []struct {
		name string
		args []ref.Val
		want ref.Val
	}{{
		name: "bad arg 1",
		args: []ref.Val{types.String("foo"), types.String("default"), types.NewListType(types.NewMapType(types.StringType, types.AnyType))},
		want: types.NewErr("invalid arg 0: unsupported native conversion from string to 'generator.Context'"),
	}, {
		name: "bad arg 2",
		args: []ref.Val{env.CELTypeAdapter().NativeToValue(Context{}), types.Bool(false), types.NewListType(types.NewMapType(types.StringType, types.AnyType))},
		want: types.NewErr("invalid arg 1: type conversion error from bool to 'string'"),
	}, {
		name: "bad arg 3",
		args: []ref.Val{env.CELTypeAdapter().NativeToValue(Context{}), types.String("default"), types.Bool(false), types.String("ns"), types.NewMapType(types.StringType, types.AnyType)},
		want: types.NewErr("invalid arg 2: type conversion error from bool to '[]*structpb.Struct'"),
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &impl{}
			got := c.apply_generator_string_list(tt.args...)
			assert.Equal(t, tt.want, got)
		})
	}
}
