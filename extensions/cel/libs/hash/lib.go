package hash

import (
	"fmt"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/kyverno/sdk/extensions/cel/libs/versions"
	"k8s.io/apimachinery/pkg/util/version"
)

const libraryName = "kyverno.hash"

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
		cel.Constant("mylib_version", types.StringType, types.String("")),
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

	buildSha1Overload := func(suffix string) cel.FunctionOpt {
		return cel.Overload(
			fmt.Sprintf("sha1_string_%s", suffix),
			[]*cel.Type{types.StringType},
			types.StringType,
			cel.UnaryBinding(impl.sha1_string),
		)
	}
	buildSha256Overload := func(suffix string) cel.FunctionOpt {
		return cel.Overload(
			fmt.Sprintf("sha256_string_%s", suffix),
			[]*cel.Type{types.StringType},
			types.StringType,
			cel.UnaryBinding(impl.sha256_string),
		)
	}
	buildMd5Overload := func(suffix string) cel.FunctionOpt {
		return cel.Overload(
			fmt.Sprintf("md5_string_%s", suffix),
			[]*cel.Type{types.StringType},
			types.StringType,
			cel.UnaryBinding(impl.md5_string),
		)
	}
	// build our function overloads
	options := []cel.EnvOption{
		cel.Function("sha1", buildSha1Overload("non_prefixed")),
		cel.Function("sha256", buildSha256Overload("non_prefixed")),
		cel.Function("md5", buildMd5Overload("non_prefixed")),
	}
	if c.version.AtLeast(version.MajorMinor(1, 18)) {
		options = append(options,
			cel.Function("hash.sha1", buildSha1Overload("prefixed")),
			cel.Function("hash.sha256", buildSha256Overload("prefixed")),
			cel.Function("hash.md5", buildMd5Overload("prefixed")),
		)
	}
	// extend environment with our function overloads
	return env.Extend(options...)
}
