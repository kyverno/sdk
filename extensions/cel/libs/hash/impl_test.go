package hash

import (
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/kyverno/sdk/extensions/cel/compiler"
	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/util/version"
)

func Test_hashing(t *testing.T) {
	base, err := compiler.NewBaseEnv()
	assert.NoError(t, err)
	assert.NotNil(t, base)
	options := []cel.EnvOption{
		Lib(version.MajorMinor(1, 18)),
	}
	env, err := base.Extend(options...)
	assert.NoError(t, err)
	assert.NotNil(t, env)

	t.Run("sha1_string", func(t *testing.T) {
		ast, issues := env.Compile(`hash.sha1("ghcr.io/kyverno/kyverno:latest")`)
		assert.Nil(t, issues)
		assert.NotNil(t, ast)
		prog, err := env.Program(ast)
		assert.NoError(t, err)
		assert.NotNil(t, prog)
		out, _, err := prog.Eval(map[string]any{})
		assert.NoError(t, err)
		value := out.Value().(string)
		assert.Equal(t, value, "98f68a84cd3ada3a25bc42bf69ed8e0297e13022")
	})

	t.Run("sha256_string", func(t *testing.T) {
		ast, issues := env.Compile(`hash.sha256("ghcr.io/kyverno/kyverno:latest")`)
		assert.Nil(t, issues)
		assert.NotNil(t, ast)
		prog, err := env.Program(ast)
		assert.NoError(t, err)
		assert.NotNil(t, prog)
		out, _, err := prog.Eval(map[string]any{})
		assert.NoError(t, err)
		value := out.Value().(string)
		assert.Equal(t, value, "e98de8e3a54bcb921de9cc72741522823cb30ef9dda17cfd228416ead4ce3760")
	})

	t.Run("md5_string", func(t *testing.T) {
		ast, issues := env.Compile(`hash.md5("ghcr.io/kyverno/kyverno:latest")`)
		assert.Nil(t, issues)
		assert.NotNil(t, ast)
		prog, err := env.Program(ast)
		assert.NoError(t, err)
		assert.NotNil(t, prog)
		out, _, err := prog.Eval(map[string]any{})
		assert.NoError(t, err)
		value := out.Value().(string)
		assert.Equal(t, value, "16dc16f633974d1015cad2ffe81e7365")
	})
}
