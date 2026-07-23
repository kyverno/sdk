package imagedata

import (
	"fmt"
	"reflect"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/ext"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/kyverno/sdk/extensions/cel/libs/versions"
	"k8s.io/apimachinery/pkg/util/version"
)

const libraryName = "kyverno.imagedata"

type lib struct {
	imagedataIface ContextInterface
	version        *version.Version
	authOpts       []remote.Option // remote authentication options to pass during calls to external registries that require auth
}

// Initialize the imagedata library. imagedataCtx argument is whatever implements the methods for interacting with
// an externl image registry. authOpts is the custom authentication options (secret references, allow insecure)
// that get passed during making a call to that remote which is an image validating policy only feature.
func Lib(imagedataCtx ContextInterface, v *version.Version, authOpts []remote.Option) cel.EnvOption {
	if v == nil {
		panic(libraryName + ": library version must not be nil")
	}
	// create the cel lib env option
	return cel.Lib(&lib{imagedataIface: imagedataCtx, version: v, authOpts: authOpts})
}

func Latest() *version.Version {
	return versions.KyvernoLatest
}

func (*lib) LibraryName() string {
	return libraryName
}

func (c *lib) CompileOptions() []cel.EnvOption {
	return []cel.EnvOption{
		cel.Variable("image", ContextType),
		ext.NativeTypes(reflect.TypeFor[Context]()),
		c.extendEnv,
	}
}

func (l *lib) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{
		cel.Globals(
			map[string]any{
				"image": l.imagedataIface,
			},
		),
	}
}

func (c *lib) extendEnv(env *cel.Env) (*cel.Env, error) {
	impl := impl{
		Adapter:  env.CELTypeAdapter(),
		authOpts: c.authOpts,
	}
	buildGetMetadataOverloads := func(suffix string) []cel.FunctionOpt {
		return []cel.FunctionOpt{
			cel.MemberOverload(
				fmt.Sprintf("imagedata_get_string_%s", suffix),
				[]*cel.Type{ContextType, types.StringType},
				types.DynType,
				cel.FunctionBinding(impl.get_imagedata_string),
			),
		}
	}
	// build our function overloads
	libraryDecls := map[string][]cel.FunctionOpt{
		"GetMetadata": buildGetMetadataOverloads("pascal"),
	}
	if c.version.AtLeast(version.MajorMinor(1, 18)) {
		libraryDecls["getMetadata"] = buildGetMetadataOverloads("camel")
	}
	// create env options corresponding to our function overloads
	options := []cel.EnvOption{}
	for name, overloads := range libraryDecls {
		options = append(options, cel.Function(name, overloads...))
	}
	// extend environment with our function overloads
	return env.Extend(options...)
}
