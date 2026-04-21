package transform

import (
	"fmt"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/kyverno/sdk/extensions/cel/libs/versions"
	"k8s.io/apimachinery/pkg/util/version"
)

const libraryName = "kyverno.transform"

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

	buildOverload := func(suffix string) cel.FunctionOpt {
		return cel.Overload(
			fmt.Sprintf("list_of_object_to_map_%s", suffix),
			[]*cel.Type{types.ListType, types.ListType, types.StringType, types.StringType},
			types.MapType,
			cel.FunctionBinding(impl.list_of_objects_to_map),
		)
	}

	env, err := env.Extend(cel.Function("listObjToMap", buildOverload("non_prefixed")))
	if err != nil {
		return nil, err
	}

	if c.version.AtLeast(version.MajorMinor(1, 18)) {
		env, err = env.Extend(cel.Function("transform.listObjToMap", buildOverload("prefixed")))
		if err != nil {
			return nil, err
		}
	}

	return env, nil
}
