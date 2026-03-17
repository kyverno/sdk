package random

import (
	"fmt"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/kyverno/sdk/cel/libs/versions"
	"k8s.io/apimachinery/pkg/util/version"
)

const libraryName = "kyverno.random"

type lib struct {
	version *version.Version
}

func Lib(v *version.Version) cel.EnvOption {
	if v == nil {
		panic(libraryName + ": library version must not be nil")
	}
	// create the cel lib env option
	return cel.Lib(&lib{version: v})
}

func Latest() *version.Version {
	return versions.KyvernoLatest
}

func (*lib) LibraryName() string {
	return libraryName
}

func (c *lib) CompileOptions() []cel.EnvOption {
	return []cel.EnvOption{
		c.extendEnv,
	}
}

func (*lib) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{}
}

func (c *lib) extendEnv(env *cel.Env) (*cel.Env, error) {
	impl := impl{
		Adapter: env.CELTypeAdapter(),
	}

	buildRandomOverloads := func(suffix string) []cel.FunctionOpt {
		return []cel.FunctionOpt{
			cel.Overload(
				fmt.Sprintf("random_string_%s", suffix),
				[]*cel.Type{types.StringType},
				types.StringType,
				cel.UnaryBinding(impl.random),
			),
			cel.Overload(
				fmt.Sprintf("random_string_default_expr_%s", suffix),
				[]*cel.Type{},
				types.StringType,
				cel.FunctionBinding(impl.random_default_expr),
			),
		}
	}
	// build our function overloads
	options := []cel.EnvOption{
		cel.Function("random", buildRandomOverloads("non_prefixed")...),
	}
	if c.version.AtLeast(version.MajorMinor(1, 18)) {
		options = append(options,
			cel.Function("random.random", buildRandomOverloads("prefixed")...),
		)
	}
	// extend environment with our function overloads
	return env.Extend(options...)
}
