package transform

import (
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/kyverno/sdk/extensions/cel/compiler"
	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/util/version"
)

func Test_list_of_object_to_map(t *testing.T) {
	base, err := compiler.NewBaseEnv()
	assert.NoError(t, err)
	assert.NotNil(t, base)
	options := []cel.EnvOption{
		Lib(version.MajorMinor(1, 18)),
	}
	env, err := base.Extend(options...)
	assert.NoError(t, err)
	assert.NotNil(t, env)

	t.Run("list_of_object_to_map", func(t *testing.T) {
		desiredMap := map[string]any{
			"kyverno":    "security",
			"kubernetes": "orchestration",
		}
		ast, issues := env.Compile(
			`transform.listObjToMap(
        [
            {"name": "kyverno", "lfx": "mentorship"},
            {"name": "kubernetes", "lfx": "something"}
        ],
        [
            {"domain": "security"},
            {"domain": "orchestration"}
        ],
        "name",
        "domain")`)

		assert.Nil(t, issues)
		assert.NotNil(t, ast)
		prog, err := env.Program(ast)
		assert.NoError(t, err)

		out, _, err := prog.Eval(map[string]any{})
		assert.NoError(t, err)
		value := out.Value().(map[string]any)

		// verify the output matches the desired map
		assert.Equal(t, value, desiredMap)
	})
}
