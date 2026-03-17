package resource

import (
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/kyverno/sdk/cel/compiler"
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
