package gzip

import (
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/kyverno/sdk/extensions/cel/libs/versions"
	"k8s.io/apimachinery/pkg/util/version"
)

const libraryName = "kyverno.gzip"

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
	return cel.Lib(&lib{
		version: v,
	})
}

func (*lib) LibraryName() string {
	return libraryName
}

func (l *lib) CompileOptions() []cel.EnvOption {
	return []cel.EnvOption{
		// extend environment with function overloads
		l.extendEnv,
	}
}

func (l *lib) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{}
}

func (*lib) extendEnv(env *cel.Env) (*cel.Env, error) {
	adapter := env.CELTypeAdapter()
	impl := impl{adapter}

	return env.Extend(
		cel.Function("gzip.decompress", cel.Overload("decompress_bytes_string", []*cel.Type{types.BytesType}, types.StringType, cel.UnaryBinding(impl.decompress_string))),
		cel.Function("gzip.compress", cel.Overload("compress_any_bytes", []*cel.Type{types.DynType}, types.BytesType, cel.UnaryBinding(impl.compress))),
	)
}
