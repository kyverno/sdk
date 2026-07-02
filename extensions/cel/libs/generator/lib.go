package generator

import (
	"fmt"
	"reflect"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/ext"
	"github.com/kyverno/sdk/extensions/cel/libs/versions"
	"k8s.io/apimachinery/pkg/util/version"
)

const libraryName = "kyverno.generator"

type lib struct {
	generatorIface ContextInterface
	namespace      string
	version        *version.Version
}

func Lib(generatorCtx ContextInterface, namespace string, v *version.Version) cel.EnvOption {
	if v == nil {
		panic(libraryName + ": library version must not be nil")
	}
	// create the cel lib env option
	return cel.Lib(&lib{generatorIface: generatorCtx, namespace: namespace, version: v})
}

func Latest() *version.Version {
	return versions.KyvernoLatest
}

func (*lib) LibraryName() string {
	return libraryName
}

func (c *lib) CompileOptions() []cel.EnvOption {
	return []cel.EnvOption{
		cel.Variable("generator", ContextType),
		ext.NativeTypes(reflect.TypeFor[Context]()),
		c.extendEnv,
	}
}

func (l *lib) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{
		cel.Globals(
			map[string]any{
				"generator": l.generatorIface,
			},
		),
	}
}

func (c *lib) extendEnv(env *cel.Env) (*cel.Env, error) {
	var binding func(args ...ref.Val) ref.Val
	if c.namespace != "" {
		ni := namespacedImpl{namespace: c.namespace, Adapter: env.CELTypeAdapter()}
		binding = ni.apply_generator_string_list
	} else {
		ci := impl{Adapter: env.CELTypeAdapter()}
		binding = ci.apply_generator_string_list
	}

	buildApplyOverloads := func(suffix string) []cel.FunctionOpt {
		return []cel.FunctionOpt{
			cel.MemberOverload(
				fmt.Sprintf("generator_apply_string_list_%s", suffix),
				[]*cel.Type{ContextType, types.StringType, types.NewListType(types.NewMapType(types.StringType, types.AnyType))},
				types.BoolType,
				cel.FunctionBinding(binding),
			),
		}
	}
	libraryDecls := map[string][]cel.FunctionOpt{
		"Apply": buildApplyOverloads("pascal"),
	}
	if c.version.AtLeast(version.MajorMinor(1, 18)) {
		libraryDecls["apply"] = buildApplyOverloads("camel")
	}
	options := []cel.EnvOption{}
	for name, overloads := range libraryDecls {
		options = append(options, cel.Function(name, overloads...))
	}
	return env.Extend(options...)
}
