package resource

import (
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/kyverno/sdk/extensions/cel/compiler"
	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/util/version"
)

// why do we need to specify a version here ?
func TestLib(t *testing.T) {
	base, err := compiler.NewBaseEnv()
	assert.NoError(t, err)
	assert.NotNil(t, base)
	options := []cel.EnvOption{
		cel.Variable("resource", ContextType),
		Lib(nil, "", version.MajorMinor(1, 18)),
	}
	env, err := base.Extend(options...)
	assert.NoError(t, err)
	assert.NotNil(t, env)
}

func TestNamespaceLib(t *testing.T) {
	base, err := compiler.NewBaseEnv()
	assert.NoError(t, err)
	assert.NotNil(t, base)
	options := []cel.EnvOption{
		cel.Variable("resource", ContextType),
		Lib(nil, "default", version.MajorMinor(1, 18)),
	}
	env, err := base.Extend(options...)
	assert.NoError(t, err)
	assert.NotNil(t, env)
}

func Test_lib_LibraryName(t *testing.T) {
	var l lib
	assert.Equal(t, libraryName, l.LibraryName())
}

// ToGVR hands a *schema.GroupVersionResource to NativeToValue, which since
// cel-go v0.31.0 only converts registered native types. This checks the
// registration directly, so it also fails on older cel-go versions, which
// convert unregistered structs anyway.
func TestLib_RegistersGroupVersionResource(t *testing.T) {
	for _, namespace := range []string{"", "default"} {
		base, err := compiler.NewBaseEnv()
		assert.NoError(t, err)
		env, err := base.Extend(Lib(nil, namespace, version.MajorMinor(1, 18)))
		assert.NoError(t, err)
		_, found := env.CELTypeProvider().FindStructType("schema.GroupVersionResource")
		assert.True(t, found, "namespace %q", namespace)
	}
}
