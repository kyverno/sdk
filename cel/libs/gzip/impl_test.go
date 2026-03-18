package gzip

import (
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/kyverno/sdk/cel/compiler"
	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/util/version"
)

func Test_gzip(t *testing.T) {
	base, err := compiler.NewBaseEnv()
	assert.NoError(t, err)
	assert.NotNil(t, base)
	options := []cel.EnvOption{
		Lib(version.MajorMinor(1, 18)),
	}
	env, err := base.Extend(options...)
	assert.NoError(t, err)
	assert.NotNil(t, env)

	t.Run("decompress_base64", func(t *testing.T) {
		ast, issues := env.Compile(`gzip.decompress(base64.decode("H4sIADP4umkAA8uuLEstyssHAOgPnDMHAAAA"))`)
		assert.Nil(t, issues)
		assert.NotNil(t, ast)
		prog, err := env.Program(ast)
		assert.NoError(t, err)
		assert.NotNil(t, prog)
		out, _, err := prog.Eval(map[string]any{})
		assert.NoError(t, err)
		value := out.Value().(string)
		assert.Equal(t, value, "kyverno")
	})

	t.Run("compress_base64", func(t *testing.T) {
		ast, issues := env.Compile(`base64.encode(gzip.compress("kyverno"))`)
		assert.Nil(t, issues)
		assert.NotNil(t, ast)
		prog, err := env.Program(ast)
		assert.NoError(t, err)
		assert.NotNil(t, prog)
		out, _, err := prog.Eval(map[string]any{})
		assert.NoError(t, err)
		value := out.Value().(string)
		assert.Equal(t, value, "H4sIAAAAAAAA/8quLEstyssHBAAA///oD5wzBwAAAA==")
	})
}
