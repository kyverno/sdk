package user

import (
	"fmt"
	"reflect"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/ext"
	"github.com/kyverno/sdk/cel/libs/versions"
	"k8s.io/apimachinery/pkg/util/version"
)

const libraryName = "kyverno.user"

type lib struct {
	version *version.Version
}

func Latest() *version.Version {
	return versions.KyvernoLatest
}

func Lib(v *version.Version) cel.EnvOption {
	if v == nil {
		panic(libraryName + ": library version must not be nil")
	}
	// create the cel lib env option
	return cel.Lib(&lib{version: v})
}

func (*lib) LibraryName() string {
	return libraryName
}

func (c *lib) CompileOptions() []cel.EnvOption {
	return []cel.EnvOption{
		ext.NativeTypes(reflect.TypeFor[ServiceAccount]()),
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

	buildParseServiceAccountOverload := func(suffix string) cel.FunctionOpt {
		return cel.Overload(
			fmt.Sprintf("parse_service_account_string_%s", suffix),
			[]*cel.Type{types.StringType},
			ServiceAccountType,
			cel.UnaryBinding(impl.parse_service_account_string),
		)
	}
	// build our function overloads
	options := []cel.EnvOption{
		cel.Function("parseServiceAccount", buildParseServiceAccountOverload("non_prefixed")),
	}
	if c.version.AtLeast(version.MajorMinor(1, 18)) {
		options = append(options,
			cel.Function("user.parseServiceAccount", buildParseServiceAccountOverload("prefixed")),
		)
	}
	// extend environment with our function overloads
	return env.Extend(options...)
}
